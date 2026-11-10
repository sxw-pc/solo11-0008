"""跨表血缘一致性校验单元测试。"""

from pathlib import Path

import pytest

from gateway.validator.lineage_check import (LineageRuleError, load_lineage_rules,
                                             validate_lineage)


def _relation(left_table="trades", left_field="user_id",
              right_table="users", right_field="user_id",
              relationship="many_to_one", **extra):
    relation = {
        "name": "rel", "left_table": left_table, "left_field": left_field,
        "right_table": right_table, "right_field": right_field,
        "relationship": relationship,
    }
    relation.update(extra)
    return {"relations": [relation]}


def test_valid_relations_and_graph(valid_users, valid_trades):
    result = validate_lineage({"users": valid_users, "trades": valid_trades},
                              _relation())
    assert result["passed"]
    assert result["graph"]["relation_count"] == 1
    assert "trades.user_id" in result["graph"]["text"]
    assert "graph LR" in result["graph"]["mermaid"]
    assert result["orphan_count"] == 0


def test_orphan_and_null_handling(make_table):
    users = make_table("users", [{"user_id": "U0001"}])
    trades = make_table("trades", [
        {"user_id": "U0002"}, {"user_id": None}, {"user_id": "U0001"},
    ])
    result = validate_lineage({"users": users, "trades": trades}, _relation())
    assert not result["passed"]
    relation = result["relations"][0]
    assert relation["orphan_count"] == 1
    assert relation["missing_reference_count"] == 1
    codes = {item["code"] for item in relation["errors"]}
    assert {"orphan_record", "reference_missing"} <= codes
    allow_null = validate_lineage(
        {"users": users, "trades": trades},
        _relation(allow_null=True))
    assert allow_null["missing_reference_count"] == 0


def test_cardinality_rules(make_table):
    left = make_table("trades", [{"key": "a"}, {"key": "a"}])
    right = make_table("users", [{"key": "a"}, {"key": "a"}])
    one_to_one = validate_lineage({"trades": left, "users": right},
                                  _relation("trades", "key", "users", "key",
                                            "one_to_one"))
    assert one_to_one["cardinality_errors"] == 2
    many_to_one = validate_lineage({"trades": left, "users": right},
                                   _relation("trades", "key", "users", "key",
                                             "many_to_one"))
    assert many_to_one["cardinality_errors"] == 1
    one_to_many = validate_lineage({"trades": left, "users": right},
                                   _relation("trades", "key", "users", "key",
                                             "one_to_many"))
    assert one_to_many["cardinality_errors"] == 1


def test_missing_table_and_field(valid_users, valid_trades):
    missing_table = validate_lineage({"users": valid_users}, _relation())
    assert not missing_table["passed"]
    assert missing_table["relations"][0]["errors"][0]["code"] == "table_missing"
    missing_field = validate_lineage(
        {"users": valid_users, "trades": valid_trades},
        _relation(left_field="missing"))
    assert not missing_field["passed"]
    assert missing_field["relations"][0]["errors"][0]["code"] == "field_missing"


def test_invalid_relationship_and_endpoint(valid_users, valid_trades):
    invalid = validate_lineage({"users": valid_users, "trades": valid_trades},
                               _relation(relationship="bad"))
    assert not invalid["passed"]
    assert invalid["relations"][0]["errors"][0]["code"] == "rule_invalid"
    broken_endpoint = {"relations": [{"name": "broken", "left": {"table": "trades"}}]}
    result = validate_lineage({"users": valid_users, "trades": valid_trades},
                              broken_endpoint)
    assert not result["passed"]
    assert result["relations"][0]["errors"][0]["code"] == "rule_invalid"
    assert result["graph"]["relation_count"] == 1


def test_cross_format_numeric_key_normalization(make_table):
    left = make_table("orders", [{"trade_id": 1}, {"trade_id": 2.0}],
                      source_format="sqlite", offset=1)
    right = make_table("trades", [{"trade_id": "1"}, {"trade_id": "2"}],
                       source_format="csv", offset=2)
    result = validate_lineage(
        {"orders": left, "trades": right},
        _relation("orders", "trade_id", "trades", "trade_id", "many_to_one"))
    assert result["passed"]


def test_broken_graph_marks_nodes(make_table):
    users = make_table("users", [{"user_id": "U1"}])
    trades = make_table("trades", [{"user_id": "U2"}])
    result = validate_lineage({"users": users, "trades": trades}, _relation())
    assert result["graph"]["broken_nodes"] == ["trades", "users"]
    assert "classDef broken" in result["graph"]["mermaid"]


def test_nested_relation_config(valid_users, valid_trades):
    rules = {"relations": [{
        "name": "nested",
        "left": {"table": "trades", "field": "user_id"},
        "right": {"table": "users", "field": "user_id"},
        "relationship": "many_to_one",
    }]}
    assert validate_lineage({"users": valid_users, "trades": valid_trades},
                            rules)["passed"]


def test_load_rules_errors(tmp_path):
    rules = load_lineage_rules(Path("fixtures/mock_lineage/trade_lineage_rule.yaml"))
    assert len(rules["relations"]) == 4
    with pytest.raises(LineageRuleError, match="不存在"):
        load_lineage_rules(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("relations: {}", encoding="utf-8")
    with pytest.raises(LineageRuleError, match="relations"):
        load_lineage_rules(bad)
    syntax = tmp_path / "syntax.yaml"
    syntax.write_text("relations: [", encoding="utf-8")
    with pytest.raises(LineageRuleError, match="解析"):
        load_lineage_rules(syntax)


def test_non_mapping_rule_and_row_samples(make_table):
    users = make_table("users", [{"user_id": "U1"}])
    trades = make_table("trades", [{"user_id": "U2"}])
    rules = {"relations": ["bad", {"name": "ok",
                                   "left_table": "trades", "left_field": "user_id",
                                   "right_table": "users", "right_field": "user_id"}]}
    result = validate_lineage({"users": users, "trades": trades}, rules)
    assert not result["passed"]
    assert result["samples"][0]["row"] == 2


def test_key_normalization_edges():
    from datetime import date
    from gateway.validator.lineage_check import _normalize_key

    class BadItem:
        def item(self):
            raise ValueError("bad")

    assert _normalize_key(None) is None
    assert _normalize_key("  ") is None
    assert _normalize_key(date(2024, 1, 2)) == "2024-01-02"
    assert _normalize_key(float("nan")) is None
    assert _normalize_key(2.0) == "2"
    assert _normalize_key(2.5) == "2.5"
    import pandas as pd
    assert _normalize_key(pd.NA) is None
    assert _normalize_key(["unhashable"]) == "['unhashable']"
    assert _normalize_key(pd.Series([1, 2])).startswith("0")
    assert _normalize_key(BadItem()).startswith("<")
    assert _normalize_key(7) == "7"


def test_right_field_missing_branch(make_table):
    left = make_table("trades", [{"user_id": "U1"}])
    right = make_table("users", [{"other": "U1"}])
    result = validate_lineage({"trades": left, "users": right}, _relation())
    assert result["relations"][0]["errors"][0]["code"] == "field_missing"
    assert "users.user_id" in result["relations"][0]["errors"][0]["message"]
