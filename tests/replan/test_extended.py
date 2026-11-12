"""补充场景：启发式改名、表增删、规则变化、多格式与编码、规则指纹复用。"""

import json
from pathlib import Path
import tempfile
import unittest

from replan.archive import build_admission_archive
from replan.contract import load_contract, load_lineage
from replan.packet import read_packet
from replan.planner import build_plan
from replan.workdir import WorkDir

from .fixtures_builder import (
    TRADES_HEADER, USERS_HEADER, base_contract, base_lineage,
    base_trades_rows, base_users_rows, build_zip_packet, packet_files,
    write_configs, write_csv_bytes, write_jsonl_bytes, write_sqlite_bytes,
)


class ExtendedPlannerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="replan-ext-")
        self.base = Path(self.temp.name)
        (self.base / "packets").mkdir()
        (self.base / "configs").mkdir()
        self.cpath, self.lpath = write_configs(
            self.base / "configs", base_contract(), base_lineage())

    def tearDown(self):
        self.temp.cleanup()

    def _archive(self, packet):
        with WorkDir(self.base / "w") as work_dir:
            read = read_packet(packet, work_dir)
            contract = load_contract(self.cpath)
            lineage = load_lineage(self.lpath, contract)
            return build_admission_archive(read, contract, lineage)

    def _plan(self, old, new, archive, contract=None, lineage=None):
        return build_plan(old, new, contract or self.cpath,
                          lineage or self.lpath, self._write(archive),
                          work_base=str(self.base / "work"),
                          generated_at="2026-01-02T00:00:00Z")

    def _write(self, obj, name="archive.json"):
        path = self.base / name
        path.write_text(json.dumps(obj, sort_keys=True), encoding="utf-8")
        return str(path)

    def test_heuristic_rename_by_identical_fingerprint(self):
        old = build_zip_packet(self.base / "packets", "old.zip",
                               packet_files({
                                   "users": (USERS_HEADER, base_users_rows()),
                                   "trades": (TRADES_HEADER,
                                              base_trades_rows())}))
        archive = self._archive(old)
        # 物理改名 status -> trade_status，数据完全一致，且无契约显式映射。
        new_header = ["trade_id", "user_id", "amount", "trade_status"]
        new_rows = [row[:] for row in base_trades_rows()]
        contract = base_contract()
        field = contract["tables"]["trades"]["fields"].pop("status")
        contract["tables"]["trades"]["fields"]["trade_status"] = field
        # 规则仍登记在新列名上（模拟业务方手工改契约）。
        contract["anomaly_rules"]["trades"]["trade_status"] = \
            contract["anomaly_rules"]["trades"].pop("status")
        cpath, _ = write_configs(self.base / "configs" / "v2",
                                 contract, base_lineage())
        new = build_zip_packet(self.base / "packets", "new.zip",
                               packet_files({
                                   "users": (USERS_HEADER,
                                             base_users_rows()),
                                   "trades": (new_header, new_rows)}))
        plan = self._plan(old, new, archive, contract=cpath)
        self.assertEqual(plan["mode"], "targeted")
        renamed = next(c for c in plan["columns"]
                       if c["table"] == "trades"
                       and c["column"] == "trade_status")
        self.assertEqual(renamed["decision"], "suggested_recheck")
        self.assertEqual(renamed["old_name"], "status")
        mapping = plan["table_changes"]["renames"]["trades"]
        self.assertEqual(mapping[0]["confidence"], "heuristic")

    def test_added_and_removed_tables(self):
        old_files = packet_files({
            "users": (USERS_HEADER, base_users_rows())})
        old = build_zip_packet(self.base / "packets", "old.zip", old_files)
        archive = self._archive(old)
        new_files = packet_files({
            "users": (USERS_HEADER, base_users_rows()),
            "trades": (TRADES_HEADER, base_trades_rows())})
        new = build_zip_packet(self.base / "packets", "new.zip", new_files)
        # 新表需要在契约中声明。
        plan = self._plan(old, new, archive)
        self.assertEqual(plan["mode"], "targeted")
        self.assertIn("trades", plan["table_changes"]["added"])
        trades = next(t for t in plan["tables"] if t["table"] == "trades")
        self.assertEqual(trades["decision"], "must_recheck")
        # 新增表 trades 通过外键引用 users.user_id，被引用键端必须连带重检。
        users = next(t for t in plan["tables"] if t["table"] == "users")
        self.assertEqual(users["decision"], "must_recheck")
        user_id = next(c for c in plan["columns"]
                       if c["table"] == "users" and c["column"] == "user_id")
        self.assertIn("lineage_propagated", user_id["events"])

        # 反向：删除表。
        plan2 = self._plan(new, old, self._archive(new))
        self.assertIn("trades", plan2["table_changes"]["removed"])
        removed_table = next(t for t in plan2["tables"]
                             if t["table"] == "trades")
        self.assertEqual(removed_table["decision"], "must_recheck")

    def test_rule_definition_change_forces_rule_recheck(self):
        old = build_zip_packet(self.base / "packets", "old.zip",
                               packet_files({
                                   "users": (USERS_HEADER,
                                             base_users_rows()),
                                   "trades": (TRADES_HEADER,
                                              base_trades_rows())}))
        archive = self._archive(old)
        contract = base_contract()
        # 收紧 amount range 上限：规则指纹变化，数据未变。
        contract["anomaly_rules"]["trades"]["amount"] = [
            {"rule": "range", "min": 0, "max": 50}]
        cpath, _ = write_configs(self.base / "configs" / "v2",
                                 contract, base_lineage())
        plan = self._plan(old, old, archive, contract=cpath)
        amount_rule = next(r for r in plan["rules"]
                           if r["column"] == "amount")
        self.assertEqual(amount_rule["decision"], "must_recheck")
        self.assertEqual(amount_rule["reasons"][0]["code"],
                         "rule_definition_changed")
        # 同表未受影响的规则仍可沿用。
        tid_rule = next(r for r in plan["rules"]
                        if r["column"] == "trade_id")
        self.assertEqual(tid_rule["decision"], "reuse")

    def test_jsonl_and_sqlite_tables_are_fingerprinted(self):
        users_csv = write_csv_bytes(USERS_HEADER, base_users_rows())
        trades_jsonl = write_jsonl_bytes([
            dict(zip(TRADES_HEADER, row)) for row in base_trades_rows()])
        files = {
            "data/users.csv": users_csv,
            "data/trades.jsonl": trades_jsonl,
        }
        packet = build_zip_packet(self.base / "packets", "mix.zip", files)
        with WorkDir(self.base / "w") as work_dir:
            read = read_packet(packet, work_dir)
        self.assertEqual(set(read.tables), {"users", "trades"})
        self.assertEqual(read.tables["trades"].format, "jsonl")
        self.assertEqual(read.tables["trades"].row_count, 3)
        # 列级指纹全部存在且为 64 位 sha256。
        for column in TRADES_HEADER:
            fp = read.tables["trades"].fingerprints[column]
            self.assertEqual(len(fp.sha256), 64)

        sqlite_bytes = write_sqlite_bytes(
            "users", USERS_HEADER, base_users_rows())
        sqlite_packet = build_zip_packet(
            self.base / "packets", "sqlite.zip",
            {"data/users.sqlite": sqlite_bytes})
        with WorkDir(self.base / "w2") as work_dir:
            read2 = read_packet(sqlite_packet, work_dir)
        self.assertEqual(read2.tables["users"].format, "sqlite")
        self.assertEqual(read2.tables["users"].columns, USERS_HEADER)

    def test_gbk_encoded_csv_is_read(self):
        gbk_csv = write_csv_bytes(
            ["user_id", "user_name"],
            [["U001", "张三"], ["U002", "李四"]], encoding="gbk")
        packet = build_zip_packet(
            self.base / "packets", "gbk.zip",
            {"data/users.csv": gbk_csv})
        with WorkDir(self.base / "w") as work_dir:
            read = read_packet(packet, work_dir)
        self.assertEqual(read.tables["users"].encoding, "gbk")
        self.assertEqual(read.tables["users"].row_count, 2)

    def test_identical_packets_reuse_everything(self):
        old = build_zip_packet(self.base / "packets", "old.zip",
                               packet_files({
                                   "users": (USERS_HEADER,
                                             base_users_rows()),
                                   "trades": (TRADES_HEADER,
                                              base_trades_rows())}))
        archive = self._archive(old)
        plan = self._plan(old, old, archive)
        self.assertEqual(plan["mode"], "targeted")
        self.assertTrue(plan["columns"])
        self.assertTrue(all(c["decision"] == "reuse"
                            for c in plan["columns"]))
        self.assertTrue(all(r["decision"] == "reuse"
                            for r in plan["rules"]))
        self.assertTrue(all(r["decision"] == "reuse"
                            for r in plan["relations"]))
        self.assertEqual(plan["scope_summary"]["reuse_ratio"], 1.0)
        # 可执行重检范围为空。
        self.assertEqual(plan["recheck_plan"]["tables"], [])
        self.assertEqual(plan["recheck_plan"]["rule_ids"], [])

    def test_null_count_is_tracked_for_nullable_column(self):
        rows = [
            ["T001", "U001", "100.5", "paid"],
            ["T002", "U002", "", "pending"],
        ]
        packet = build_zip_packet(
            self.base / "packets", "nulls.zip",
            packet_files({"trades": (TRADES_HEADER, rows)}))
        with WorkDir(self.base / "w") as work_dir:
            read = read_packet(packet, work_dir)
        amount_fp = read.tables["trades"].fingerprints["amount"]
        self.assertEqual(amount_fp.null_count, 1)
        self.assertEqual(amount_fp.row_count, 2)


if __name__ == "__main__":
    unittest.main()
