"""异常值抽检规则引擎单元测试。"""

from datetime import date

import pytest

from gateway.validator.anomaly_check import validate_anomalies
from gateway.validator.custom_rules import get_custom_rule


def _rules(table, field, rules):
    return {"anomaly_rules": {table: {field: rules}}}


def test_all_builtin_rules_pass(make_table):
    table = make_table("t", [
        {"id": "a", "num": 5, "status": "paid", "day": "2024-02-01"},
        {"id": "b", "num": 6, "status": "pending", "day": "2024-02-02"},
    ])
    rules = _rules("t", "id", [
        {"rule": "null_rate", "max": 0.0},
        {"rule": "duplicate_rate", "max": 0.0},
        {"rule": "regex", "pattern": "^[a-z]$", "full_match": True},
    ])
    rules["anomaly_rules"]["t"]["num"] = [{"rule": "range", "min": 0, "max": 10}]
    rules["anomaly_rules"]["t"]["day"] = [{"rule": "date", "format": "%Y-%m-%d"}]
    result = validate_anomalies({"t": table}, rules)
    assert result["passed"]
    assert "全部通过" in result["summary"]


def test_range_regex_date_failures(make_table):
    table = make_table("t", [{"num": 50, "status": "x", "day": "bad"}])
    rules = _rules("t", "num", [{"rule": "range", "min": 0, "max": 10}])
    rules["anomaly_rules"]["t"]["status"] = [
        {"rule": "regex", "pattern": "^paid$", "full_match": True}]
    rules["anomaly_rules"]["t"]["day"] = [{"rule": "date", "format": "%Y-%m-%d"}]
    result = validate_anomalies({"t": table}, rules)
    assert not result["passed"]
    assert result["failed_rules"] == 3
    assert len(result["samples"]) == 3


def test_range_nonnumeric_and_threshold(make_table):
    table = make_table("t", [{"num": "x"}, {"num": 5}])
    failed = validate_anomalies({"t": table},
                                _rules("t", "num", [{"rule": "range", "min": 0, "max": 10}]))
    assert failed["fields"][0]["rules"][0]["violations"] == 1
    allowed = validate_anomalies(
        {"t": table},
        _rules("t", "num", [{"rule": "range", "min": 0, "max": 10, "max_rate": 0.5}]))
    assert allowed["passed"]


def test_null_and_duplicate_rates(make_table):
    table = make_table("t", [{"value": None}, {"value": "a"},
                             {"value": "a"}, {"value": "b"}])
    null = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "null_rate", "max": 0.1}]))
    assert null["fields"][0]["null_rate"] == 0.25
    assert not null["passed"]
    duplicate = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "duplicate_rate", "max": 0.1}]))
    assert duplicate["fields"][0]["duplicate_rate"] == 0.3333
    assert not duplicate["passed"]


def test_custom_rule_pass_fail_and_missing(make_table):
    table = make_table("t", [{"num": -1}, {"num": 2}])
    negative = validate_anomalies(
        {"t": table}, _rules("t", "num", [{"rule": "custom", "function": "no_negative"}]))
    assert not negative["passed"]
    assert negative["samples"][0]["value"] == -1
    missing = validate_anomalies(
        {"t": table}, _rules("t", "num", [{"rule": "custom", "function": "missing"}]))
    assert not missing["passed"]
    assert "执行失败" in missing["fields"][0]["rules"][0]["error"]
    with pytest.raises(KeyError):
        get_custom_rule("missing")


def test_invalid_rule_shapes_and_regex(make_table):
    table = make_table("t", [{"value": "x"}])
    invalid_regex = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "regex", "pattern": "["}]))
    assert "执行失败" in invalid_regex["fields"][0]["rules"][0]["error"]
    unknown = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "unknown"}]))
    assert "未知" in unknown["fields"][0]["rules"][0]["error"]
    no_rule_key = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"threshold": 1}]))
    assert "rule" in no_rule_key["fields"][0]["rules"][0]["error"]
    no_range = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "range"}]))
    assert "执行失败" in no_range["fields"][0]["rules"][0]["error"]


def test_missing_table_field_and_malformed_rules(make_table):
    table = make_table("t", [{"value": "x"}])
    result = validate_anomalies({"t": table}, {"anomaly_rules": {
        "missing": {"field": [{"rule": "null_rate", "max": 0}]},
        "t": {"missing": [{"rule": "null_rate", "max": 0}]},
    }})
    assert not result["passed"]
    assert {item["code"] for item in result["errors"]} == {"table_missing", "field_missing"}
    malformed = validate_anomalies({"t": table}, {"anomaly_rules": {"t": ["bad"]}})
    assert malformed["errors"][0]["code"] == "rule_invalid"
    not_mapping = validate_anomalies({"t": table}, {"anomaly_rules": []})
    assert not_mapping["passed"]


def test_sample_cap_and_value_truncation(make_table):
    rows = [{"num": -1} for _ in range(30)]
    rows[0]["num"] = -1
    table = make_table("t", rows)
    result = validate_anomalies(
        {"t": table}, _rules("t", "num", [{"rule": "custom", "function": "no_negative"}]))
    assert len(result["samples"]) == 20
    assert result["fields"][0]["anomaly_rate"] == 1.0
    long_table = make_table("t", [{"value": "x" * 100}])
    truncated = validate_anomalies(
        {"t": long_table}, _rules("t", "value", [{"rule": "regex", "pattern": "^a"}]))
    assert truncated["samples"][0]["value"].endswith("...")


def test_date_formats_string_and_datetime(make_table):
    table = make_table("t", [{"day": "2024/02/01"}])
    string_format = validate_anomalies(
        {"t": table}, _rules("t", "day", [{"rule": "date", "formats": "%Y/%m/%d"}]))
    assert string_format["passed"]


def test_helper_edges(monkeypatch):
    from datetime import date
    from gateway.validator import anomaly_check as module

    class BadItem:
        def item(self):
            raise ValueError("bad")

    class BadNa:
        pass

    assert module._is_null(None) is True
    assert module._is_null(" ") is True
    assert module._is_null(0) is False
    monkeypatch.setattr(module.pd, "isna", lambda value: (_ for _ in ()).throw(ValueError("x")))
    assert module._is_null(BadNa()) is False
    assert module._safe_value(None) is None
    assert module._safe_value(date(2024, 1, 1)) == "2024-01-01"
    assert module._safe_value(BadItem()).startswith("<")
    assert module._safe_value({"x": 1}) == "{'x': 1}"
    assert module._row_number("bad", 2) is None
    assert module._row_number(3, 2) == 5


def test_null_skip_missing_patterns_and_datetime(make_table):
    table = make_table("t", [{"value": None}, {"value": "2024-01-01"}])
    regex = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "regex", "pattern": "^x$"}]))
    assert regex["fields"][0]["rules"][0]["violations"] == 1
    ranged = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "range", "min": 0}]))
    assert ranged["fields"][0]["rules"][0]["violations"] == 1
    missing_pattern = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "regex"}]))
    assert "缺少 pattern" in missing_pattern["fields"][0]["rules"][0]["error"]
    date_table = make_table("t", [{"day": None}, {"day": date(2024, 1, 1)}])
    date_result = validate_anomalies(
        {"t": date_table}, _rules("t", "day", [{"rule": "date", "format": "%Y-%m-%d"}]))
    assert date_result["passed"]


def test_null_rate_sample_cap_and_single_rule(make_table):
    table = make_table("t", [{"value": None} for _ in range(25)])
    result = validate_anomalies(
        {"t": table}, _rules("t", "value", {"rule": "null_rate", "max": 0.0}))
    assert not result["passed"]
    assert len(result["samples"]) == 20


def test_non_callable_custom_and_empty_series(make_table, monkeypatch):
    from gateway.validator import custom_rules
    monkeypatch.setitem(custom_rules.CUSTOM_RULES, "broken", None)
    table = make_table("t", [{"value": 1}])
    result = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "custom", "function": "broken"}]))
    assert "执行失败" in result["fields"][0]["rules"][0]["error"]
    empty = make_table("t", [])
    empty.frame = empty.frame.reindex(columns=["value"])
    empty_result = validate_anomalies(
        {"t": empty}, _rules("t", "value", [{"rule": "range", "min": 0}]))
    assert empty_result["passed"]


def test_non_empty_custom_rule(make_table):
    table = make_table("t", [{"value": " "}, {"value": "ok"}])
    result = validate_anomalies(
        {"t": table}, _rules("t", "value", [{"rule": "custom", "function": "non_empty"}]))
    assert result["fields"][0]["rules"][0]["violations"] == 1


def test_alias_field_participates_in_anomaly_rules(make_table):
    """异常规则字段名应经别名映射后匹配规范字段，且不报 field_missing。"""
    table = make_table("t", [
        {"uid": "U0001", "status": "paid"},
        {"uid": "U0002", "status": "bad"},
    ])
    contract = {
        "tables": {"t": {"aliases": {"user_id": ["uid"],
                                      "status": ["state"]},
                          "fields": {}}},
        "anomaly_rules": {"t": {
            "user_id": [{"rule": "duplicate_rate", "max": 0.0}],
            "status": [{"rule": "regex", "pattern": "^(paid|pending)$"}],
        }},
    }
    result = validate_anomalies({"t": table}, contract)
    assert not result["passed"]
    assert result["errors"] == []
    status = next(item for item in result["fields"] if item["field"] == "status")
    assert not status["passed"]
    assert status["rules"][0]["violations"] == 1
    user = next(item for item in result["fields"] if item["field"] == "user_id")
    assert user["passed"]
    assert user["checked"] == 2


def test_alias_contract_missing_nonexistent_canonical_still_reported(make_table):
    table = make_table("t", [{"value": "x"}])
    contract = {
        "tables": {"t": {"aliases": {"uid": ["user_id"]}, "fields": {}}},
        "anomaly_rules": {"t": {"user_id": [{"rule": "null_rate", "max": 0.0}]}},
    }
    result = validate_anomalies({"t": table}, contract)
    codes = {item["code"] for item in result["errors"]}
    assert "field_missing" in codes
