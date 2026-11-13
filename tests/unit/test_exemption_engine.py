"""豁免引擎的结果适配、标记、结论重算、资源释放与业务域解析测试。"""

from datetime import datetime
from pathlib import Path

import pytest

from gateway.exemption.engine import (EXEMPTION_KEY, ExemptionEngine,
                                      build_engine, resolve_business_domain)
from gateway.exemption.rules import ExemptionRule, RuleSet

NOW = datetime(2025, 6, 1, 12, 0, 0)


def _rule(rule_id, action="exempt", **overrides):
    base = dict(
        rule_id=rule_id, business_domain="trade", anomaly_types=("*",),
        action=action, grade="L2",
        effective_from=datetime(2024, 1, 1), effective_to=datetime(2099, 12, 31),
        approvers=("治理部",), reason="历史遗留")
    base.update(overrides)
    return ExemptionRule(**base)


def _ruleset(*rules):
    return RuleSet(rules=tuple(rules), ruleset_hash="hash")


@pytest.fixture(autouse=True)
def reset_registry():
    ExemptionEngine.reset_registry()
    yield
    ExemptionEngine.reset_registry()


def _engine(tmp_path, ruleset, domain="trade"):
    return ExemptionEngine(ruleset, "task-1", domain, Path(tmp_path) / "audit", now=NOW)


def test_empty_ruleset_is_noop_and_writes_nothing(tmp_path):
    engine = _engine(tmp_path, RuleSet())
    results = [{"key": "anomaly", "name": "x", "passed": False,
                "fields": [], "errors": [], "samples": []}]
    summary = engine.apply(results)
    assert summary["exempted"] == 0 and summary["ruleset_hash"] == ""
    assert not Path(tmp_path, "audit").exists()


def test_schema_exemption_marks_and_recomputes_passed(tmp_path):
    error = {"code": "type", "table": "trades", "field": "amount", "message": "类型错误"}
    results = [{"key": "schema", "name": "Schema", "passed": False,
                "tables": [{"table": "trades", "errors": [error]}],
                "errors": [error], "samples": []}]
    engine = _engine(tmp_path, _ruleset(_rule("R1", anomaly_types=("type",))))
    with engine:
        summary = engine.apply(results)
    assert summary["exempted"] == 1
    assert error[EXEMPTION_KEY]["status"] == "exempted"
    assert error[EXEMPTION_KEY]["rule_id"] == "R1"
    assert results[0]["passed"] is True


def test_schema_unmatched_error_keeps_blocked(tmp_path):
    error = {"code": "type", "table": "trades", "field": "amount", "message": "x"}
    results = [{"key": "schema", "name": "Schema", "passed": False,
                "tables": [{"table": "trades", "errors": [error]}],
                "errors": [error], "samples": []}]
    engine = _engine(tmp_path, _ruleset(_rule("R1", anomaly_types=("enum",))))
    summary = engine.apply(results)
    assert summary["blocked"] == 1 and summary["exempted"] == 0
    assert EXEMPTION_KEY not in error
    assert results[0]["passed"] is False


def test_lineage_deny_rule_keeps_relation_blocked(tmp_path):
    err = {"code": "orphan_record", "message": "孤立记录"}
    results = [{"key": "lineage", "name": "血缘", "passed": False,
                "relations": [{"name": "rel", "left_table": "trades",
                               "left_field": "user_id", "passed": False,
                               "errors": [err]}],
                "errors": [], "samples": []}]
    engine = _engine(tmp_path,
                     _ruleset(_rule("D1", "deny", anomaly_types=("orphan_record",))))
    summary = engine.apply(results)
    assert summary["denied"] == 1
    assert err[EXEMPTION_KEY]["status"] == "blocked_by_rule"
    assert results[0]["passed"] is False


def test_lineage_exempt_all_errors_flips_passed(tmp_path):
    err = {"code": "orphan_record", "message": "孤立"}
    results = [{"key": "lineage", "name": "血缘", "passed": False,
                "relations": [{"name": "rel", "left_table": "trades",
                               "left_field": "user_id", "passed": False,
                               "errors": [err]}],
                "errors": [], "samples": []}]
    engine = _engine(tmp_path,
                     _ruleset(_rule("E1", anomaly_types=("orphan_record",))))
    engine.apply(results)
    assert err[EXEMPTION_KEY]["status"] == "exempted"
    assert results[0]["passed"] is True


def test_anomaly_rule_level_exemption(tmp_path):
    rule_obj = {"rule": "null_rate", "passed": False, "rate": 0.5}
    results = [{"key": "anomaly", "name": "异常", "passed": False,
                "fields": [{"table": "trades", "field": "note", "rules": [rule_obj]}],
                "errors": [], "samples": []}]
    engine = _engine(tmp_path,
                     _ruleset(_rule("A1", anomaly_types=("null_rate",))))
    summary = engine.apply(results)
    assert summary["exempted"] == 1
    assert rule_obj[EXEMPTION_KEY]["rule_id"] == "A1"
    assert results[0]["passed"] is True


def test_anomaly_partial_block_still_fails(tmp_path):
    bad = {"rule": "range", "passed": False}
    good = {"rule": "regex", "passed": True}
    results = [{"key": "anomaly", "name": "异常", "passed": False,
                "fields": [{"table": "trades", "field": "amount",
                            "rules": [bad, good]}],
                "errors": [], "samples": []}]
    engine = _engine(tmp_path,
                     _ruleset(_rule("A1", anomaly_types=("null_rate",))))
    engine.apply(results)
    assert EXEMPTION_KEY not in bad
    assert results[0]["passed"] is False


def test_hash_banned_codes_never_exempted(tmp_path):
    danger = {"code": "dangerous_file", "path": "payload.exe", "message": "高危"}
    results = [{"key": "hash", "name": "哈希", "passed": False,
                "errors": [danger], "samples": []}]
    engine = _engine(tmp_path, _ruleset(_rule("W", anomaly_types=("*",))))
    summary = engine.apply(results)
    assert summary["blocked"] == 1 and summary["exempted"] == 0
    assert EXEMPTION_KEY not in danger
    assert results[0]["passed"] is False


def test_hash_normal_error_can_be_exempted(tmp_path):
    redundancy = {"code": "redundant_file", "path": "extra.txt", "message": "冗余"}
    results = [{"key": "hash", "name": "哈希", "passed": False,
                "errors": [redundancy], "samples": []}]
    engine = _engine(tmp_path, _ruleset(_rule("H1", anomaly_types=("*",))))
    engine.apply(results)
    assert redundancy[EXEMPTION_KEY]["status"] == "exempted"
    assert results[0]["passed"] is True


def test_conflict_is_recorded_in_summary(tmp_path):
    err = {"code": "type", "table": "trades", "field": "amount", "message": "x"}
    results = [{"key": "schema", "name": "Schema", "passed": False,
                "tables": [{"table": "trades", "errors": [err]}],
                "errors": [err], "samples": []}]
    ruleset = _ruleset(
        _rule("BROAD", "exempt", anomaly_types=("type",)),
        _rule("DENY", "deny", anomaly_types=("type",), tables=("trades",)))
    engine = _engine(tmp_path, ruleset)
    summary = engine.apply(results)
    assert summary["conflict_count"] == 1
    assert summary["conflicts"][0]["chosen_rule_id"] == "DENY"
    assert err[EXEMPTION_KEY]["status"] == "blocked_by_rule"
    assert err[EXEMPTION_KEY]["conflicted"] is True


def test_expired_rule_blocks_and_is_audited(tmp_path):
    err = {"code": "type", "table": "trades", "field": "amount", "message": "x"}
    results = [{"key": "schema", "name": "Schema", "passed": False,
                "tables": [{"table": "trades", "errors": [err]}],
                "errors": [err], "samples": []}]
    expired = _rule("OLD", anomaly_types=("type",),
                    effective_from=datetime(2020, 1, 1),
                    effective_to=datetime(2024, 12, 31))
    engine = _engine(tmp_path, _ruleset(expired))
    summary = engine.apply(results)
    assert summary["expired_blocked"] == 1
    assert EXEMPTION_KEY not in err


def test_engine_released_after_apply_and_audit_verifiable(tmp_path):
    engine = _engine(tmp_path, _ruleset(_rule("R1")))
    assert ExemptionEngine.live_count() == 1
    engine.apply([{"key": "hash", "name": "h", "passed": True,
                   "errors": [], "samples": []}])
    assert ExemptionEngine.live_count() == 0
    assert engine._released is True
    audit_files = list(Path(tmp_path, "audit").glob("*.jsonl"))
    assert audit_files and audit_files[0].stat().st_mode & 0o777 in (0o600, 0o644, 0o666)


def test_context_manager_closes_engine(tmp_path):
    engine = _engine(tmp_path, _ruleset(_rule("R1")))
    with engine:
        assert ExemptionEngine.live_count() == 1
    assert ExemptionEngine.live_count() == 0
    assert engine._released is True


def test_audit_chain_written_for_decisions(tmp_path):
    redundancy = {"code": "redundant_file", "path": "x", "message": "y"}
    engine = _engine(tmp_path, _ruleset(_rule("R1", anomaly_types=("*",))))
    with engine:
        engine.apply([{"key": "hash", "name": "h", "passed": False,
                       "errors": [redundancy], "samples": []}])
    audit = engine._audit.audit_path
    import json
    events = [json.loads(line)["event"] for line in audit.read_text(
        encoding="utf-8").splitlines()]
    assert events == ["chain_open", "decision", "chain_close"]


def test_resolve_business_domain_variants():
    assert resolve_business_domain(
        {"packet": {"business_domain": "trade"}}) == "trade"
    assert resolve_business_domain({"business_domain": "finance"}) == "finance"
    assert resolve_business_domain({"packet": {}}) == ""
    assert resolve_business_domain(None) == ""
    assert resolve_business_domain({"packet": {"business_domain": "  "}}) == ""


def test_wildcard_rule_matches_packet_without_domain(tmp_path):
    err = {"code": "type", "table": "t", "field": "f", "message": "x"}
    results = [{"key": "schema", "name": "S", "passed": False,
                "tables": [{"table": "t", "errors": [err]}],
                "errors": [err], "samples": []}]
    engine = _engine(tmp_path,
                     _ruleset(_rule("W", business_domain="*")), domain="")
    engine.apply(results)
    assert err[EXEMPTION_KEY]["status"] == "exempted"


def test_specific_domain_rule_does_not_match_domainless_packet(tmp_path):
    err = {"code": "type", "table": "t", "field": "f", "message": "x"}
    results = [{"key": "schema", "name": "S", "passed": False,
                "tables": [{"table": "t", "errors": [err]}],
                "errors": [err], "samples": []}]
    engine = _engine(tmp_path,
                     _ruleset(_rule("T", business_domain="trade")), domain="")
    summary = engine.apply(results)
    assert summary["blocked"] == 1
    assert EXEMPTION_KEY not in err


def test_adapters_skip_malformed_non_dict_entries(tmp_path):
    # 混入非字典元素，适配器应跳过而不是抛异常，剩余有效异常按规则处理。
    good_err = {"code": "type", "table": "t", "field": "f", "message": "x"}
    results = [
        {"key": "schema", "name": "S", "passed": False,
         "tables": ["not-a-dict", {"table": "t", "errors": [good_err]}],
         "errors": [good_err], "samples": []},
        {"key": "lineage", "name": "L", "passed": True,
         "relations": ["not-a-dict"], "samples": []},
        {"key": "anomaly", "name": "A", "passed": True,
         "fields": ["not-a-dict"], "errors": [], "samples": []},
    ]
    engine = _engine(tmp_path, _ruleset(_rule("R1", anomaly_types=("type",))))
    summary = engine.apply(results)
    assert summary["exempted"] == 1
    assert good_err[EXEMPTION_KEY]["status"] == "exempted"


def test_anomaly_config_error_in_errors_list_is_processed(tmp_path):
    config_err = {"code": "table_missing", "table": "ghost",
                  "field": None, "message": "表不存在"}
    results = [{"key": "anomaly", "name": "A", "passed": False,
                "fields": [], "errors": [config_err], "samples": []}]
    engine = _engine(tmp_path,
                     _ruleset(_rule("R1", anomaly_types=("table_missing",))))
    summary = engine.apply(results)
    assert summary["exempted"] == 1
    assert config_err[EXEMPTION_KEY]["rule_id"] == "R1"
    assert results[0]["passed"] is True


def test_build_engine_returns_none_without_rules(tmp_path):
    assert build_engine(None, "t1", "trade", Path(tmp_path)) is None
    assert build_engine(Path(tmp_path) / "missing.yaml", "t1",
                        "trade", Path(tmp_path)) is None


def test_build_engine_returns_engine_with_rules(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - id: R1\n    business_domain: trade\n"
        "    anomaly_types: [type]\n    action: exempt\n"
        '    effective_from: "2024-01-01"\n    effective_to: "2099-12-31"\n'
        '    approvers: ["a"]\n', encoding="utf-8")
    engine = build_engine(rules_path, "t1", "trade", Path(tmp_path) / "audit")
    assert isinstance(engine, ExemptionEngine)
    assert engine.ruleset.rules[0].rule_id == "R1"
    engine.close()
    assert ExemptionEngine.live_count() == 0


def test_checks_outside_exemptible_set_are_ignored(tmp_path):
    # archive / internal / table_read 等校验项不参与豁免，原样保留。
    results = [{"key": "archive", "name": "压缩包", "passed": False,
                "errors": [{"code": "path_traversal", "message": "穿越"}],
                "samples": []}]
    engine = _engine(tmp_path, _ruleset(_rule("R1", anomaly_types=("*",))))
    summary = engine.apply(results)
    assert summary["exempted"] == 0 and summary["blocked"] == 0
    assert "exemption" not in results[0]["errors"][0]
    assert results[0]["passed"] is False


def test_schema_top_level_only_error_is_separately_processed(tmp_path):
    # 顶层 errors 含一个表级 errors 中不存在的独立错误（如表缺失）
    table_err = {"code": "type", "table": "t", "field": "f", "message": "a"}
    top_err = {"code": "table_missing", "table": "ghost", "field": None,
               "message": "契约表不存在"}
    results = [{"key": "schema", "name": "S", "passed": False,
                "tables": [{"table": "t", "errors": [table_err]}],
                "errors": [table_err, top_err], "samples": []}]
    engine = _engine(tmp_path, _ruleset(
        _rule("R1", anomaly_types=("type", "table_missing"))))
    summary = engine.apply(results)
    assert summary["exempted"] == 2
    assert top_err[EXEMPTION_KEY]["status"] == "exempted"
    assert results[0]["passed"] is True
