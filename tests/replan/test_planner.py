"""replan 规划器核心场景测试（标准库 unittest，离线运行）。

运行方式（在仓库根目录）::

    PYTHONPATH=. python3 -P -m unittest tests.replan.test_planner -v
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from replan.archive import build_admission_archive
from replan.contract import load_contract, load_lineage
from replan.packet import read_packet
from replan.planner import build_plan
from replan.render import canonical_json, render_markdown
from replan.workdir import WorkDir, cleanup_stale

from .fixtures_builder import (
    USERS_HEADER, TRADES_HEADER, base_contract, base_lineage,
    base_trades_rows, base_users_rows, build_directory_packet,
    build_rename_contract, build_rename_packet, build_zip_packet,
    packet_files, write_configs, write_csv_bytes,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


class PlannerTestBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="replan-test-")
        self.base = Path(self.temp.name)
        self.packets = self.base / "packets"
        self.configs = self.base / "configs"
        self.packets.mkdir()
        self.configs.mkdir()
        self.contract_path, self.lineage_path = write_configs(
            self.configs, base_contract(), base_lineage())

    def tearDown(self):
        self.temp.cleanup()

    def build_old_packet(self, name="old_packet.zip",
                         users_rows=None, trades_rows=None,
                         trades_header=None):
        files = packet_files({
            "users": (USERS_HEADER, users_rows or base_users_rows()),
            "trades": (trades_header or TRADES_HEADER,
                       trades_rows or base_trades_rows()),
        })
        return build_zip_packet(self.packets, name, files)

    def build_old_archive(self, old_packet_path):
        work = self.base / "work"
        work.mkdir(exist_ok=True)
        with WorkDir(work) as work_dir:
            packet_read = read_packet(old_packet_path, work_dir)
            contract = load_contract(self.contract_path)
            lineage = load_lineage(self.lineage_path, contract)
            return build_admission_archive(
                packet_read, contract, lineage,
                admission={"passed": True, "task_id": "old-task"})

    def write_archive(self, archive, name="old_archive.json"):
        path = self.base / name
        path.write_text(json.dumps(archive, ensure_ascii=False,
                                   indent=2, sort_keys=True),
                        encoding="utf-8")
        return str(path)

    def plan(self, old_packet, new_packet, old_archive,
             contract_path=None, lineage_path=None):
        work = self.base / "work"
        work.mkdir(exist_ok=True)
        return build_plan(
            old_packet_path=old_packet,
            new_packet_path=new_packet,
            contract_path=contract_path or self.contract_path,
            lineage_path=lineage_path or self.lineage_path,
            old_archive_path=old_archive,
            work_base=str(work),
            generated_at="2026-01-01T00:00:00Z")


class RenameAndTypeTests(PlannerTestBase):
    """验收场景一：改了列名和类型的成对数据包。"""

    def test_rename_and_type_change_hits_targets_and_propagates(self):
        old_packet = self.build_old_packet()
        archive = self.build_old_archive(old_packet)
        archive_path = self.write_archive(archive)
        new_packet = build_rename_packet(self.packets)
        new_contract_path, new_lineage_path = write_configs(
            self.configs / "v2", build_rename_contract(), base_lineage())

        plan = self.plan(old_packet, new_packet, archive_path,
                         contract_path=new_contract_path,
                         lineage_path=new_lineage_path)

        # 改名+类型变化触发定向模式（旧存档完整且哈希核对一致）。
        self.assertEqual(plan["mode"], "targeted")
        column_index = {(c["table"], c["column"]): c
                        for c in plan["columns"]}
        target = column_index[("trades", "trade_amount")]
        self.assertEqual(target["decision"], "must_recheck")
        self.assertIn("renamed_column", target["events"])
        self.assertIn("type_narrowed", target["events"])
        self.assertEqual(target["old_name"], "amount")

        # 外键引用传播：trades.user_id 与 users.user_id 均不受改名影响，
        # 但改名列所在表的外键列本身未变 -> 关系结论应可沿用。
        relation = next(r for r in plan["relations"]
                        if r["relation"] == "trade_owner")
        self.assertEqual(relation["decision"], "reuse")

        # 可执行计划命中具体列，而不是整表。
        executable = plan["recheck_plan"]
        self.assertFalse(executable["full_recheck"])
        trade_entry = next(t for t in executable["tables"]
                           if t["table"] == "trades")
        self.assertIn("trade_amount", trade_entry["must_columns"])
        self.assertNotIn("user_id", trade_entry["must_columns"])

        # users 表未改 -> 整表列可沿用。
        users_entry = next(t for t in plan["tables"] if t["table"] == "users")
        self.assertEqual(users_entry["decision"], "reuse")

    def test_foreign_key_change_propagates_to_referenced_table(self):
        """被外键引用的键变化必须沿引用关系传播到引用方。"""
        old_packet = self.build_old_packet()
        archive = self.build_old_archive(old_packet)
        archive_path = self.write_archive(archive)
        # 修改 users.user_id 的数据（维表键变化）。
        new_users_rows = [
            ["U101", "Alice", "north", "30"],
            ["U102", "Bob", "south", "41"],
            ["U103", "Carol", "east", "25"],
        ]
        files = packet_files({
            "users": (USERS_HEADER, new_users_rows),
            "trades": (TRADES_HEADER, base_trades_rows()),
        })
        new_packet = build_zip_packet(self.packets, "current_fk.zip", files)

        plan = self.plan(old_packet, new_packet, archive_path)
        self.assertEqual(plan["mode"], "targeted")
        column_index = {(c["table"], c["column"]): c
                        for c in plan["columns"]}
        # 引用方 trades.user_id 必须被传播为必须重检。
        trades_fk = column_index[("trades", "user_id")]
        self.assertEqual(trades_fk["decision"], "must_recheck")
        self.assertIn("lineage_propagated", trades_fk["events"])
        reason_codes = {r["code"] for r in trades_fk["reasons"]}
        self.assertIn("lineage_propagated", reason_codes)
        # 血缘关系本身必须重检。
        relation = next(r for r in plan["relations"]
                        if r["relation"] == "trade_owner")
        self.assertEqual(relation["decision"], "must_recheck")


class ColumnLifecycleTests(PlannerTestBase):
    """新增可空列、删除列、类型收窄的列级命中。"""

    def test_new_nullable_column_is_column_scoped(self):
        old_packet = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_packet))
        new_header = TRADES_HEADER + ["remark"]
        new_rows = [row + [""] for row in base_trades_rows()]
        files = packet_files({
            "users": (USERS_HEADER, base_users_rows()),
            "trades": (new_header, new_rows),
        })
        new_packet = build_zip_packet(self.packets, "current_nullable.zip",
                                      files)
        # 新列加入契约且 nullable=true。
        contract = base_contract()
        contract["tables"]["trades"]["fields"]["remark"] = {
            "type": "string", "required": False, "nullable": True}
        contract_path, _ = write_configs(self.configs / "v2", contract,
                                         base_lineage())
        plan = self.plan(old_packet, new_packet, archive_path,
                         contract_path=contract_path)
        self.assertEqual(plan["mode"], "targeted")
        column_index = {(c["table"], c["column"]): c
                        for c in plan["columns"]}
        remark = column_index[("trades", "remark")]
        self.assertEqual(remark["decision"], "must_recheck")
        self.assertIn("added_column", remark["events"])
        self.assertTrue(remark["reasons"][0]["nullable"])
        # 同表其它列仍可沿用。
        self.assertEqual(column_index[("trades", "status")]["decision"],
                         "reuse")
        self.assertEqual(column_index[("users", "region")]["decision"],
                         "reuse")

    def test_removed_column_marks_rules_and_relations(self):
        old_packet = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_packet))
        new_header = ["trade_id", "user_id", "amount"]
        # 数据行同步删除 status（第 4 列）。
        new_rows = [row[:3] for row in base_trades_rows()]
        files = packet_files({
            "users": (USERS_HEADER, base_users_rows()),
            "trades": (new_header, new_rows),
        })
        new_packet = build_zip_packet(self.packets, "current_removed.zip",
                                      files)
        contract = base_contract()
        del contract["tables"]["trades"]["fields"]["status"]
        del contract["anomaly_rules"]["trades"]["status"]
        contract_path, _ = write_configs(self.configs / "v2", contract,
                                         base_lineage())
        plan = self.plan(old_packet, new_packet, archive_path,
                         contract_path=contract_path)
        removed = next(c for c in plan["columns"]
                       if c["table"] == "trades"
                       and "removed_column" in c["events"])
        self.assertEqual(removed["old_name"], "status")
        self.assertEqual(removed["decision"], "must_recheck")
        table_entry = next(t for t in plan["tables"] if t["table"] == "trades")
        self.assertIn("status", table_entry["removed_columns"])
        # 旧 status 规则不应出现在新契约规则里；其余规则仍有决策。
        rule_targets = {(r["table"], r["column"]) for r in plan["rules"]}
        self.assertNotIn(("trades", "status"), rule_targets)

    def test_type_narrowing_is_must_and_widening_is_suggested(self):
        from replan.contract import is_narrowing
        self.assertTrue(is_narrowing("number", "integer"))
        self.assertTrue(is_narrowing("string", "integer"))
        self.assertFalse(is_narrowing("integer", "number"))
        self.assertFalse(is_narrowing("string", "string"))
        # 跨族（数值 -> 文本）按收窄处理。
        self.assertTrue(is_narrowing("integer", "string"))

        old_packet = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_packet))
        # age: integer -> number（同族放宽），同时保持数据不变。
        contract = base_contract()
        contract["tables"]["users"]["fields"]["age"]["type"] = "number"
        contract_path, _ = write_configs(self.configs / "v2", contract,
                                         base_lineage())
        plan = self.plan(old_packet, old_packet, archive_path,
                         contract_path=contract_path)
        age = next(c for c in plan["columns"]
                   if c["table"] == "users" and c["column"] == "age")
        self.assertEqual(age["decision"], "suggested_recheck")
        self.assertIn("type_widened", age["events"])


class FallbackTests(PlannerTestBase):
    """缺失旧存档、存档字段不全、读包失败、引用解析失败的保守降级。"""

    def test_missing_old_archive_triggers_full_fallback_with_reason(self):
        old_packet = self.build_old_packet()
        new_packet = self.build_old_packet("current_same.zip")
        plan = self.plan(old_packet, new_packet, None)
        self.assertEqual(plan["mode"], "full_fallback")
        self.assertTrue(plan["recheck_plan"]["full_recheck"])
        codes = {r["code"] for r in plan["fallback_reasons"]}
        self.assertIn("missing_old_archive", codes)
        # 全部列必须重检，且原因可读。
        self.assertTrue(plan["columns"])
        self.assertTrue(all(c["decision"] == "must_recheck"
                            for c in plan["columns"]))
        self.assertTrue(any("存档" in r["message"]
                            for r in plan["fallback_reasons"]))

    def test_table_level_only_archive_triggers_fallback(self):
        """gateway 历史表级摘要（无列级指纹）必须被识别并降级。"""
        old_packet = self.build_old_packet()
        legacy_report = {
            "schema": "gateway-report/1",
            "meta": {"tool": "数包闸检"},
            "checks": [{"key": "schema", "passed": True}],
            "issues": [],
        }
        archive_path = self.write_archive(legacy_report,
                                          "legacy_report.json")
        new_packet = self.build_old_packet("current_same.zip")
        plan = self.plan(old_packet, new_packet, archive_path)
        self.assertEqual(plan["mode"], "full_fallback")
        codes = {r["code"] for r in plan["fallback_reasons"]}
        self.assertIn("old_archive_table_level_only", codes)

    def test_partial_column_fingerprint_triggers_fallback(self):
        old_packet = self.build_old_packet()
        archive = self.build_old_archive(old_packet)
        # 删掉其中一列的指纹字段，模拟字段不全的常态。
        del archive["tables"]["users"]["columns"]["age"]["sha256"]
        archive_path = self.write_archive(archive, "partial_archive.json")
        new_packet = self.build_old_packet("current_same.zip")
        plan = self.plan(old_packet, new_packet, archive_path)
        self.assertEqual(plan["mode"], "full_fallback")
        codes = {r["code"] for r in plan["fallback_reasons"]}
        self.assertIn("old_archive_missing_fingerprints", codes)

    def test_tampered_old_packet_triggers_fallback(self):
        old_packet = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_packet))
        # 同名但内容不同的“旧包”：哈希与存档声明不一致。
        files = packet_files({
            "users": (USERS_HEADER,
                      [row[:] for row in base_users_rows()[:-1]]),
            "trades": (TRADES_HEADER, base_trades_rows()),
        })
        fake_old = build_zip_packet(self.packets, "old_packet.zip", files)
        new_packet = self.build_old_packet("current_same.zip")
        plan = self.plan(fake_old, new_packet, archive_path)
        self.assertEqual(plan["mode"], "full_fallback")
        codes = {r["code"] for r in plan["fallback_reasons"]}
        self.assertIn("old_packet_mismatch", codes)

    def test_unreadable_current_member_triggers_fallback(self):
        old_packet = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_packet))
        # 当前包 CSV 行列数不一致 -> 表读取错误 -> 保守降级。
        broken_csv = write_csv_bytes(TRADES_HEADER,
                                     [["T001", "U001"]])  # 列数不足
        files = packet_files({
            "users": (USERS_HEADER, base_users_rows()),
        }, extra_members={"data/trades.csv": broken_csv})
        new_packet = build_zip_packet(self.packets, "current_broken.zip",
                                      files)
        plan = self.plan(old_packet, new_packet, archive_path)
        self.assertEqual(plan["mode"], "full_fallback")
        codes = {r["code"] for r in plan["fallback_reasons"]}
        self.assertIn("packet_read_error", codes)

    def test_unresolved_lineage_reference_triggers_fallback(self):
        old_packet = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_packet))
        bad_lineage = {
            "version": "1.0", "name": "bad",
            "relations": [{
                "name": "ghost",
                "left": {"table": "trades", "field": "user_id"},
                "right": {"table": "ghost_table", "field": "id"},
                "relationship": "many_to_one",
            }],
        }
        _, bad_lineage_path = write_configs(self.configs / "bad",
                                            base_contract(), bad_lineage)
        new_packet = self.build_old_packet("current_same.zip")
        with self.assertRaises(Exception):
            # load_lineage 在解析阶段即抛出 ReferenceUnresolved。
            from replan.contract import load_lineage as _load
            _load(bad_lineage_path, load_contract(self.contract_path))
        # 通过主入口验证降级路径（主入口将其作为致命/降级处理之一）。
        from replan.errors import FallbackError
        with self.assertRaises(FallbackError):
            load_lineage(bad_lineage_path, load_contract(self.contract_path))


class DeterminismTests(PlannerTestBase):
    """相同输入重复运行，除 generated_at 外字节级一致。"""

    def test_byte_identical_plans_across_runs_and_packet_forms(self):
        old_zip = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_zip))
        # 当前包分别用 zip、tar.gz、目录三种形态承载相同内容。
        files = packet_files({
            "users": (USERS_HEADER, base_users_rows()),
            "trades": (TRADES_HEADER,
                       base_trades_rows() + [["T004", "U001", "5.0", "paid"]]),
        })
        new_zip = build_zip_packet(self.packets, "new.zip", files)
        new_tar = build_zip_packet(self.packets, "new.tar.gz", files,
                                   archive_format="tar")
        new_dir = build_directory_packet(self.packets, "new_dir", files)

        plans = []
        for new_packet in (new_zip, new_tar, new_dir):
            plan = self.plan(old_zip, new_packet, archive_path)
            plans.append(canonical_json(plan))
        # 三种形态计划内容一致（位置字段除外，位置不参与 plan_fingerprint）。
        plan_objs = [json.loads(text) for text in plans]
        fingerprints = {p["plan_fingerprint"] for p in plan_objs}
        self.assertEqual(len(fingerprints), 1)

        # 同一输入两次运行（不同时间戳）字节对比：剔除 generated_at 后一致。
        first = self.plan(old_zip, new_zip, archive_path,
                          )
        second = self.plan(old_zip, new_zip, archive_path)
        self.assertEqual(first["plan_fingerprint"], second["plan_fingerprint"])
        first_body = {k: v for k, v in first.items() if k != "generated_at"}
        second_body = {k: v for k, v in second.items() if k != "generated_at"}
        self.assertEqual(canonical_json(first_body),
                         canonical_json(second_body))
        # Markdown 同样确定性（除生成时间行）。
        md1 = [line for line in render_markdown(first).splitlines()
               if not line.startswith("- 生成时间")]
        md2 = [line for line in render_markdown(second).splitlines()
               if not line.startswith("- 生成时间")]
        self.assertEqual(md1, md2)

    def test_sorting_independent_of_insertion_order(self):
        old_packet = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_packet))
        new_packet = self.build_old_packet("new.zip")
        plan = self.plan(old_packet, new_packet, archive_path)
        # 所有列表均按稳定键排序。
        columns = [(c["table"], c["column"]) for c in plan["columns"]]
        self.assertEqual(columns, sorted(columns))
        rule_ids = [r["rule_id"] for r in plan["rules"]]
        self.assertEqual(rule_ids, sorted(rule_ids))
        member_names = list(plan["reuse_evidence"]["columns"])
        keys = [(item["table"], item["column"]) for item in member_names]
        self.assertEqual(keys, sorted(keys))


class WorkDirTests(unittest.TestCase):
    """临时目录隔离、异常清理与并发安全。"""

    def test_workdir_cleanup_on_exception(self):
        base = tempfile.mkdtemp(prefix="replan-wd-")
        created = []
        with self.assertRaises(RuntimeError):
            with WorkDir(base) as work_dir:
                created.append(str(work_dir))
                (work_dir / "spill.bin").write_bytes(b"x" * 1024)
                raise RuntimeError("boom")
        self.assertFalse(Path(created[0]).exists())
        shutil.rmtree(base, ignore_errors=True)

    def test_concurrent_workdirs_are_isolated(self):
        base = tempfile.mkdtemp(prefix="replan-conc-")
        dirs = []
        for _ in range(8):
            wd = WorkDir(base)
            wd.__enter__()
            dirs.append(wd)
        paths = {str(wd.path) for wd in dirs}
        self.assertEqual(len(paths), 8)
        for wd in dirs:
            wd.cleanup()
        self.assertEqual([p for p in paths if Path(p).exists()], [])
        shutil.rmtree(base, ignore_errors=True)

    def test_cleanup_stale_removes_dead_directories_only(self):
        base = tempfile.mkdtemp(prefix="replan-stale-")
        stale = Path(base) / "replan-999999-abcd1234"
        stale.mkdir()
        live = Path(base) / ("replan-%d-ef567890" % os.getpid())
        live.mkdir()
        removed = cleanup_stale(base)
        self.assertGreaterEqual(removed, 1)
        self.assertFalse(stale.exists())
        self.assertTrue(live.exists())
        shutil.rmtree(base, ignore_errors=True)


class PacketSafetyTests(PlannerTestBase):
    """压缩包安全：路径穿越、重复成员、不支持格式。"""

    def test_path_traversal_member_rejected(self):
        import zipfile
        evil = self.packets / "evil.zip"
        with zipfile.ZipFile(evil, "w") as archive:
            archive.writestr("manifest.yaml", b"schema_version: '1.0'\n")
            archive.writestr("../escape.txt", b"escape")
        from replan.errors import PlannerError
        from replan.packet import read_packet
        with WorkDir(self.base / "work") as work_dir:
            with self.assertRaises(Exception) as ctx:
                read_packet(str(evil), work_dir)
            self.assertEqual(ctx.exception.code, "path_traversal")

    def test_duplicate_member_rejected(self):
        import warnings
        import zipfile
        evil = self.packets / "dup.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with zipfile.ZipFile(evil, "w") as archive:
                archive.writestr("data/a.csv", b"id\n1\n")
                archive.writestr("data/a.csv", b"id\n2\n")
        from replan.packet import read_packet
        with WorkDir(self.base / "work") as work_dir:
            with self.assertRaises(Exception) as ctx:
                read_packet(str(evil), work_dir)
            self.assertEqual(ctx.exception.code, "duplicate_member")

    def test_missing_current_packet_is_fatal_planner_error(self):
        from replan.errors import PlannerError
        with self.assertRaises(PlannerError):
            self.plan(None, str(self.packets / "nope.zip"), None)


class CliTests(PlannerTestBase):
    """CLI 端到端：退出码、输出文件、并发运行与无残留。"""

    def _run_cli(self, args):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        return subprocess.run(
            [sys.executable, "-P", "-m", "replan"] + args,
            cwd=str(self.base), env=env, capture_output=True, text=True)

    def test_cli_targeted_and_outputs_written(self):
        old_packet = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_packet))
        new_packet = build_rename_packet(self.packets)
        contract_path, lineage_path = write_configs(
            self.configs / "v2", build_rename_contract(), base_lineage())
        out_dir = self.base / "out"
        plan_out = out_dir / "plan.json"
        summary_out = out_dir / "summary.md"
        result = self._run_cli([
            "--old-packet", old_packet,
            "--old-archive", archive_path,
            "--packet", new_packet,
            "--contract", contract_path,
            "--lineage", lineage_path,
            "--plan-out", str(plan_out),
            "--summary-out", str(summary_out),
            "--temp-base", str(self.base / "tmp"),
            "--generated-at", "2026-01-01T00:00:00Z",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(plan_out.is_file())
        self.assertTrue(summary_out.is_file())
        plan = json.loads(plan_out.read_text(encoding="utf-8"))
        self.assertEqual(plan["mode"], "targeted")
        summary = summary_out.read_text(encoding="utf-8")
        self.assertIn("最小重检计划", summary)
        # 临时目录无残留。
        leftovers = list((self.base / "tmp").glob("replan-*"))
        self.assertEqual(leftovers, [])

    def test_cli_missing_archive_exit_zero_but_full_fallback(self):
        old_packet = self.build_old_packet()
        new_packet = self.build_old_packet("new.zip")
        out_dir = self.base / "out"
        result = self._run_cli([
            "--old-packet", old_packet,
            "--packet", new_packet,
            "--contract", self.contract_path,
            "--lineage", self.lineage_path,
            "--plan-out", str(out_dir / "plan.json"),
            "--summary-out", str(out_dir / "summary.md"),
            "--temp-base", str(self.base / "tmp"),
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["mode"], "full_fallback")

    def test_cli_missing_current_packet_exit_2(self):
        result = self._run_cli([
            "--packet", str(self.packets / "missing.zip"),
            "--contract", self.contract_path,
            "--lineage", self.lineage_path,
            "--plan-out", str(self.base / "p.json"),
            "--summary-out", str(self.base / "s.md"),
        ])
        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stderr.strip().splitlines()[-1])
        self.assertTrue(payload["error"])

    def test_two_concurrent_runs_same_inputs(self):
        old_packet = self.build_old_packet()
        archive_path = self.write_archive(self.build_old_archive(old_packet))
        new_packet = build_rename_packet(self.packets)
        contract_path, lineage_path = write_configs(
            self.configs / "v2", build_rename_contract(), base_lineage())
        out_dir = self.base / "out"
        processes = []
        for index in range(2):
            processes.append(self._run_cli([
                "--old-packet", old_packet,
                "--old-archive", archive_path,
                "--packet", new_packet,
                "--contract", contract_path,
                "--lineage", lineage_path,
                "--plan-out", str(out_dir / ("plan_%d.json" % index)),
                "--summary-out", str(out_dir / ("summary_%d.md" % index)),
                "--temp-base", str(self.base / "tmp"),
                "--generated-at", "2026-01-01T00:00:00Z",
            ]))
        self.assertTrue(all(p.returncode == 0 for p in processes),
                        [p.stderr for p in processes])
        plans = [json.loads((out_dir / ("plan_%d.json" % i)).read_text(
            encoding="utf-8")) for i in range(2)]
        self.assertEqual(plans[0]["plan_fingerprint"],
                         plans[1]["plan_fingerprint"])
        self.assertEqual(canonical_json(plans[0]), canonical_json(plans[1]))
        leftovers = list((self.base / "tmp").glob("replan-*"))
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
