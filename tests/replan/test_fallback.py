"""降级触发条件与文本解析的边界测试。"""

import json
from pathlib import Path
import tempfile
import unittest

from replan.archive import build_admission_archive
from replan.contract import load_contract, load_lineage
from replan.errors import FallbackError, PlannerError
from replan.packet import read_packet
from replan.planner import build_plan
from replan.textio import parse_yaml_subset
from replan.workdir import WorkDir

from .fixtures_builder import (
    TRADES_HEADER, USERS_HEADER, base_contract, base_lineage,
    base_trades_rows, base_users_rows, build_zip_packet, packet_files,
    write_configs,
)


class FallbackConditionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="replan-fb-")
        self.base = Path(self.temp.name)
        (self.base / "packets").mkdir()
        (self.base / "configs").mkdir()
        self.cpath, self.lpath = write_configs(
            self.base / "configs", base_contract(), base_lineage())

    def tearDown(self):
        self.temp.cleanup()

    def _packet(self, name="p.zip"):
        return build_zip_packet(self.base / "packets", name, packet_files({
            "users": (USERS_HEADER, base_users_rows()),
            "trades": (TRADES_HEADER, base_trades_rows())}))

    def _archive(self, packet):
        with WorkDir(self.base / "w") as work_dir:
            read = read_packet(packet, work_dir)
            return build_admission_archive(
                read, load_contract(self.cpath),
                load_lineage(self.lpath, load_contract(self.cpath)))

    def test_contract_changed_without_snapshot_forces_fallback(self):
        old = self._packet("old.zip")
        archive = self._archive(old)
        # 人为移除契约快照，再修改契约。
        del archive["contract"]
        archive_path = self.base / "no_snapshot.json"
        archive_path.write_text(json.dumps(archive, sort_keys=True))
        contract = base_contract()
        contract["tables"]["users"]["fields"]["age"]["minimum"] = 21
        cpath2, _ = write_configs(self.base / "configs" / "v2",
                                  contract, base_lineage())
        plan = build_plan(old, old, cpath2, self.lpath, str(archive_path),
                          work_base=str(self.base / "work"),
                          generated_at="2026-03-01T00:00:00Z")
        self.assertEqual(plan["mode"], "full_fallback")
        codes = {r["code"] for r in plan["fallback_reasons"]}
        self.assertIn("old_archive_missing_contract_snapshot", codes)

    def test_unparseable_archive_forces_fallback(self):
        old = self._packet("old.zip")
        bad = self.base / "bad_archive.json"
        bad.write_text("{ this is not valid json", encoding="utf-8")
        plan = build_plan(old, old, self.cpath, self.lpath, str(bad),
                          work_base=str(self.base / "work"),
                          generated_at="2026-03-01T00:00:00Z")
        self.assertEqual(plan["mode"], "full_fallback")
        codes = {r["code"] for r in plan["fallback_reasons"]}
        self.assertIn("old_archive_unreadable", codes)

    def test_packet_with_no_recognized_tables(self):
        # 只有 manifest，没有任何业务表。
        packet = build_zip_packet(
            self.base / "packets", "empty.zip",
            {"manifest.yaml": b"schema_version: '1.0'\ntables: {}\nfiles: {}\n"})
        with WorkDir(self.base / "w2") as work_dir:
            read = read_packet(str(packet), work_dir)
        self.assertEqual(read.tables, {})

    def test_contract_file_missing_is_fatal(self):
        old = self._packet("old.zip")
        with self.assertRaises(PlannerError) as ctx:
            build_plan(old, old, str(self.base / "nope.json"),
                       self.lpath, None,
                       work_base=str(self.base / "work"))
        self.assertEqual(ctx.exception.code, "contract_not_found")

    def test_lineage_unresolvable_raises_fallback_error(self):
        bad_lineage = {
            "version": "1.0", "name": "bad",
            "relations": [{
                "name": "x",
                "left": {"table": "trades", "field": "user_id"},
                "right": {"table": "users", "field": "nonexistent"},
            }],
        }
        _, lpath2 = write_configs(self.base / "configs" / "bad",
                                  base_contract(), bad_lineage)
        with self.assertRaises(FallbackError) as ctx:
            load_lineage(lpath2, load_contract(self.cpath))
        self.assertEqual(ctx.exception.code, "rule_reference_unresolved")

    def test_unresolvable_lineage_via_build_plan_is_full_fallback(self):
        old = self._packet("old.zip")
        bad_lineage = {
            "version": "1.0", "name": "bad",
            "relations": [{
                "name": "x",
                "left": {"table": "trades", "field": "user_id"},
                "right": {"table": "ghost", "field": "id"},
            }],
        }
        _, lpath2 = write_configs(self.base / "configs" / "bad2",
                                  base_contract(), bad_lineage)
        plan = build_plan(old, old, self.cpath, lpath2, None,
                          work_base=str(self.base / "work"),
                          generated_at="2026-03-01T00:00:00Z")
        self.assertEqual(plan["mode"], "full_fallback")
        codes = {r["code"] for r in plan["fallback_reasons"]}
        self.assertIn("rule_reference_unresolved", codes)
        self.assertTrue(all(c["decision"] == "must_recheck"
                            for c in plan["columns"]))

    def test_unparseable_contract_via_build_plan_is_full_fallback(self):
        old = self._packet("old.zip")
        bad_contract = self.base / "bad_contract.yaml"
        bad_contract.write_text("tables:\n bad_indent: 1\n  x: 2\n",
                                encoding="utf-8")
        plan = build_plan(old, old, str(bad_contract), self.lpath, None,
                          work_base=str(self.base / "work"),
                          generated_at="2026-03-01T00:00:00Z")
        self.assertEqual(plan["mode"], "full_fallback")
        codes = {r["code"] for r in plan["fallback_reasons"]}
        self.assertTrue({"contract_unparseable", "missing_old_archive"}
                        & codes)

    def test_malformed_yaml_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_yaml_subset("a:\n  b: 1\n c: 2\n")  # 非法缩进

    def test_inline_list_and_quoted_scalars(self):
        result = parse_yaml_subset(
            "name: 'hello world'\ntags: [a, b, c]\nflag: true\nempty: null\n")
        self.assertEqual(result["name"], "hello world")
        self.assertEqual(result["tags"], ["a", "b", "c"])
        self.assertIs(result["flag"], True)
        self.assertIsNone(result["empty"])


if __name__ == "__main__":
    unittest.main()
