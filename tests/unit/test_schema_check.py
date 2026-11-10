"""数据契约 Schema 校验单元测试。"""

from pathlib import Path

import pandas as pd
import pytest

from gateway.parser.archive_loader import load_archive
from gateway.parser.table_reader import TableData, read_manifest_table
from gateway.validator.schema_check import (ContractError, load_contract,
                                            validate_schema)

CONTRACT = Path(__file__).resolve().parents[2] / "fixtures" / "mock_contract" / "user_trade_contract.yaml"


def _table(name, rows, offset=2):
    frame = pd.DataFrame(rows)
    return TableData(name=name, frame=frame, source_format="csv",
                     total_rows=len(frame), sampled_rows=len(frame),
                     sample_ratio=1.0, row_offset=offset)


def _contract(fields, table_extra=None, allow_extra=False):
    table = {"fields": fields}
    table.update(table_extra or {})
    return {"allow_extra_fields": allow_extra, "tables": {"t": table}}


def test_load_contract_and_errors(tmp_path):
    contract = load_contract(CONTRACT)
    assert "users" in contract["tables"]
    with pytest.raises(ContractError, match="不存在"):
        load_contract(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("tables: []", encoding="utf-8")
    with pytest.raises(ContractError, match="tables"):
        load_contract(bad)
    syntax = tmp_path / "syntax.yaml"
    syntax.write_text("tables: [", encoding="utf-8")
    with pytest.raises(ContractError, match="解析"):
        load_contract(syntax)
    huge = tmp_path / "huge.yaml"
    huge.write_text("x" * (2 * 1024 * 1024 + 1), encoding="utf-8")
    with pytest.raises(ContractError, match="体积"):
        load_contract(huge)
    fields_bad = tmp_path / "fields.yaml"
    fields_bad.write_text("tables:\n  t: {fields: []}\n", encoding="utf-8")
    with pytest.raises(ContractError, match="fields"):
        load_contract(fields_bad)


def test_full_valid_packet_schema(config):
    with load_archive(Path("fixtures/valid_packets/retail_valid_a.zip"), config) as extracted:
        tables = {name: read_manifest_table(extracted, name, config, sample=False)
                  for name in ("users", "trades", "products", "orders")}
    result = validate_schema(tables, load_contract(CONTRACT))
    assert result["passed"]
    assert result["rows_checked"] == 152
    assert all(item["passed"] for item in result["tables"])


def test_type_enum_length_and_row_number():
    fields = {
        "id": {"type": "integer", "required": True},
        "kind": {"type": "string", "enum": ["a", "b"]},
        "name": {"type": "string", "maxLength": 3},
    }
    table = _table("t", [{"id": "bad", "kind": "z", "name": "long"}])
    result = validate_schema({"t": table}, _contract(fields))
    assert not result["passed"]
    codes = {item["code"] for item in result["errors"]}
    assert {"type", "enum", "maxLength"} <= codes
    assert result["samples"][0]["row"] == 2


def test_required_column_missing_and_extra_field():
    fields = {"id": {"type": "integer", "required": True},
              "name": {"type": "string"}}
    table = _table("t", [{"other": 1}])
    result = validate_schema({"t": table}, _contract(fields))
    assert not result["passed"]
    codes = {item["code"] for item in result["errors"]}
    assert "required" in codes
    assert "unexpected_field" in codes
    assert result["tables"][0]["missing_fields"] == ["id", "name"]


def test_allow_extra_fields():
    fields = {"id": {"type": "integer", "required": True}}
    table = _table("t", [{"id": 1, "other": 2}])
    result = validate_schema({"t": table}, _contract(fields, allow_extra=True))
    assert result["passed"]


def test_alias_mapping_and_conflicts():
    fields = {"user_name": {"type": "string", "required": True}}
    aliased = _table("t", [{"name": "Mock"}])
    contract = _contract(fields, {"aliases": {"user_name": ["name"]}})
    assert validate_schema({"t": aliased}, contract)["passed"]
    both = _table("t", [{"user_name": "A", "name": "B"}])
    result = validate_schema({"t": both}, contract)
    assert not result["passed"]
    assert any(item["code"] == "alias_conflict" for item in result["errors"])
    multi_contract = _contract(fields, {"aliases": {"user_name": ["a", "b"]}})
    multi = _table("t", [{"a": "A", "b": "B"}])
    assert not validate_schema({"t": multi}, multi_contract)["passed"]


def test_required_nullable_and_date_format():
    fields = {
        "id": {"type": "string", "required": True, "nullable": True},
        "when": {"type": "string", "required": True, "format": "date"},
    }
    table = _table("t", [{"id": None, "when": "not-a-date"}])
    result = validate_schema({"t": table}, _contract(fields))
    assert not result["passed"]
    codes = {item["code"] for item in result["errors"]}
    assert "required" in codes
    assert "format" in codes


def test_table_missing_and_invalid_rule():
    missing = validate_schema({}, _contract({"id": {"type": "string"}}))
    assert not missing["passed"]
    assert missing["errors"][0]["code"] == "table_missing"
    table = _table("t", [{"id": "x"}])
    unsupported = _contract({"id": {"type": "uuid"}})
    result = validate_schema({"t": table}, unsupported)
    assert not result["passed"]
    assert result["errors"][0]["code"] == "contract_error"
    non_map = {"tables": {"t": {"fields": {"id": "string"}}}}
    result2 = validate_schema({"t": table}, non_map)
    assert not result2["passed"]


def test_sample_limits_to_top_ten():
    fields = {"id": {"type": "integer", "required": True}}
    rows = [{"id": "x"} for _ in range(20)]
    result = validate_schema({"t": _table("t", rows)}, _contract(fields))
    assert not result["passed"]
    assert len(result["samples"]) == 10
    assert result["tables"][0]["error_rows"] == 20


def test_empty_table_is_valid():
    fields = {"id": {"type": "integer", "required": True}}
    table = _table("t", [])
    table.frame = pd.DataFrame(columns=["id"])
    result = validate_schema({"t": table}, _contract(fields))
    assert result["passed"]


def test_value_helpers_cover_serialization_and_errors(monkeypatch):
    from datetime import date
    from gateway.validator import schema_check as module

    class BadItem:
        def item(self):
            raise ValueError("no item")

    class BadNa:
        pass

    assert module._is_null(None) is True
    assert module._is_null("  ") is True
    assert module._is_null(1) is False
    monkeypatch.setattr(module.pd, "isna", lambda value: (_ for _ in ()).throw(TypeError("x")))
    assert module._is_null(BadNa()) is False
    assert module._to_python(date(2024, 1, 2)) == "2024-01-02"
    assert module._to_python([date(2024, 1, 2), None]) == ["2024-01-02", None]
    assert module._to_python({"a": 1}) == {"a": 1}
    assert module._to_python(BadItem()).__class__ is BadItem
    assert module._truncate("x" * 100).endswith("...")


def test_type_less_rule_and_alias_error_paths():
    no_type = {"allow_extra_fields": True, "tables": {"t": {
        "fields": {"value": {"enum": ["a"]}}}}}
    result = validate_schema({"t": _table("t", [{"value": "a"}])}, no_type)
    assert result["passed"]
    alias_bad = {"tables": {"t": {"fields": {"id": {}}, "aliases": ["bad"]}}}
    result_bad = validate_schema({"t": _table("t", [{"id": 1}])}, alias_bad)
    assert not result_bad["passed"]
    assert result_bad["errors"][0]["code"] == "contract_error"
    alias_none = {"tables": {"t": {"fields": {"id": {}}, "aliases": {"id": None}}}}
    assert validate_schema({"t": _table("t", [{"id": 1}])}, alias_none)["passed"]


def test_long_value_is_truncated_in_error_sample():
    fields = {"id": {"type": "integer", "required": True}}
    result = validate_schema({"t": _table("t", [{"id": "x" * 100}])}, _contract(fields))
    assert result["errors"][0]["value"].endswith("...")
