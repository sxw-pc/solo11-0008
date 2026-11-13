"""分级豁免规则模型、本地加载与最严格冲突仲裁的单元测试。"""

from datetime import datetime
from pathlib import Path

import pytest

from gateway.exemption.rules import (AnomalyUnit, ExemptionRule,
                                     ExemptionRuleError, RuleSet,
                                     compute_ruleset_hash, load_exemption_rules,
                                     parse_datetime)

NOW = datetime(2025, 6, 1, 12, 0, 0)


def _rule(rule_id="R1", action="exempt", **overrides):
    base = dict(
        rule_id=rule_id, business_domain="trade", anomaly_types=("null_rate",),
        action=action, grade="L2",
        effective_from=datetime(2024, 1, 1), effective_to=datetime(2099, 12, 31),
        approvers=("治理部",), reason="历史遗留",
    )
    base.update(overrides)
    return ExemptionRule(**base)


def _unit(**overrides):
    base = dict(check="anomaly", anomaly_type="null_rate", domain="trade",
                table="trades", field="note", path="", message="空值率超标")
    base.update(overrides)
    return AnomalyUnit(**base)


def test_parse_datetime_accepts_multiple_formats():
    assert parse_datetime("2025-06-01") == datetime(2025, 6, 1)
    assert parse_datetime("2025-06-01T12:00:00") == datetime(2025, 6, 1, 12)
    assert parse_datetime(datetime(2025, 6, 1)) == datetime(2025, 6, 1)
    with pytest.raises(ExemptionRuleError):
        parse_datetime("not-a-date")
    with pytest.raises(ExemptionRuleError):
        parse_datetime("", "生效时间")


def test_rule_active_window_and_scope():
    rule = _rule(tables=("trades",), fields=("note",))
    assert rule.is_active(NOW)
    assert rule.matches(_unit(), NOW)
    # 超出有效期
    expired = _rule(effective_to=datetime(2024, 12, 31))
    assert not expired.matches(_unit(), NOW)
    # 尚未生效
    future = _rule(effective_from=datetime(2099, 1, 1))
    assert not future.matches(_unit(), NOW)
    # 停用规则不匹配
    assert not _rule(enabled=False).matches(_unit(), NOW)
    # 影响范围不匹配
    assert not _rule(tables=("orders",)).matches(_unit(), NOW)
    assert not _rule(fields=("amount",)).matches(_unit(), NOW)
    # 通配范围放行
    assert _rule(tables=("*",)).matches(_unit(), NOW)
    # 业务域与异常类型不匹配
    assert not _rule(business_domain="finance").matches(_unit(), NOW)
    assert not _rule(anomaly_types=("type",)).matches(_unit(), NOW)
    assert _rule(business_domain="*").matches(_unit(), NOW)
    assert _rule(anomaly_types=("*",)).matches(_unit(), NOW)


def test_ruleset_decide_deny_wins_conflict():
    ruleset = RuleSet(rules=(
        _rule("BROAD", "exempt"),
        _rule("SPECIFIC", "deny", tables=("trades",), fields=("note",)),
    ), ruleset_hash="hash")
    decision = ruleset.decide(_unit(), NOW)
    assert decision is not None
    assert decision.conflicted is True
    assert decision.chosen.rule_id == "SPECIFIC"
    assert decision.chosen.action == "deny"
    assert decision.exempted is False
    assert [rule.rule_id for rule in decision.candidates] == ["SPECIFIC", "BROAD"]


def test_ruleset_decide_specificity_orders_exempt_rules():
    ruleset = RuleSet(rules=(
        _rule("GENERIC", "exempt"),
        _rule("NARROW", "exempt", tables=("trades",), fields=("note",)),
    ), ruleset_hash="hash")
    decision = ruleset.decide(_unit(), NOW)
    assert decision.chosen.rule_id == "NARROW"
    assert decision.exempted is True


def test_ruleset_no_match_and_expired_detection():
    ruleset = RuleSet(rules=(_rule("OTHER", "exempt",
                                   business_domain="finance"),),
                      ruleset_hash="hash")
    assert ruleset.decide(_unit(), NOW) is None
    expired = _rule("OLD", "exempt",
                    effective_from=datetime(2020, 1, 1),
                    effective_to=datetime(2024, 12, 31))
    ruleset_exp = RuleSet(rules=(expired,), ruleset_hash="hash")
    assert ruleset_exp.decide(_unit(), NOW) is None
    assert ruleset_exp.expired_matches(_unit(), NOW) == ["OLD"]
    assert ruleset_exp.active_rule_ids(NOW) == []
    assert RuleSet().active_rule_ids(NOW) == []
    assert not RuleSet()


def test_specificity_score_ordering():
    broad = _rule("B", "exempt", business_domain="*", anomaly_types=("*",))
    narrow = _rule("N", "exempt", tables=("trades",), fields=("note",))
    assert narrow.specificity(_unit()) > broad.specificity(_unit())


def _write_yaml(tmp_path, payload):
    path = Path(tmp_path) / "rules.yaml"
    path.write_text(payload, encoding="utf-8")
    return path


def test_load_rules_success_and_hash_stable(tmp_path):
    path = _write_yaml(tmp_path, """
version: "1.0"
rules:
  - id: EXM-1
    business_domain: trade
    anomaly_types: [null_rate]
    scope: {tables: [trades], fields: [note]}
    action: exempt
    grade: L1
    effective_from: "2024-01-01"
    effective_to: "2099-12-31"
    approvers: ["治理部", "安全部"]
    reason: "备案"
""")
    ruleset = load_exemption_rules(path)
    assert len(ruleset.rules) == 1
    rule = ruleset.rules[0]
    assert rule.rule_id == "EXM-1"
    assert rule.tables == ("trades",)
    assert ruleset.ruleset_hash == compute_ruleset_hash(ruleset.rules)


def test_load_missing_or_empty_returns_empty_ruleset(tmp_path):
    assert not load_exemption_rules(None)
    assert not load_exemption_rules(Path(tmp_path) / "absent.yaml")
    empty = _write_yaml(tmp_path, 'version: "1"\nrules: []\n')
    assert not load_exemption_rules(empty)


@pytest.mark.parametrize("payload,marker", [
    ("not: : valid: yaml: :", "YAML"),
    ("version: '1'\nother: []\n", "rules 列表"),
    ("rules:\n  - not-a-mapping\n", "映射"),
    ("rules:\n  - business_domain: trade\n", "id"),
    ("rules:\n  - id: 'bad id'\n    business_domain: trade\n", "非法字符"),
    ("rules:\n  - id: R1\n    business_domain: trade\n", "anomaly_types"),
    ("rules:\n  - id: R1\n    business_domain: trade\n    anomaly_types: [x]\n"
     "    action: nope\n", "action"),
    ("rules:\n  - id: R1\n    business_domain: trade\n    anomaly_types: [x]\n"
     "    action: exempt\n    grade: L9\n", "grade"),
    ("rules:\n  - id: R1\n    business_domain: trade\n    anomaly_types: [x]\n"
     "    action: exempt\n"
     '    effective_from: "2099-01-01"\n    effective_to: "2024-01-01"\n', "晚于"),
    ("rules:\n  - id: R1\n    business_domain: trade\n    anomaly_types: [x]\n"
     "    action: exempt\n"
     '    effective_from: "2024-01-01"\n    effective_to: "2099-01-01"\n', "approvers"),
])
def test_load_invalid_rules_raises(tmp_path, payload, marker):
    path = _write_yaml(tmp_path, payload)
    with pytest.raises(ExemptionRuleError) as exc:
        load_exemption_rules(path)
    assert marker in str(exc.value)


def test_duplicate_rule_id_rejected(tmp_path):
    path = _write_yaml(tmp_path, """
rules:
  - id: DUP
    business_domain: trade
    anomaly_types: [null_rate]
    action: exempt
    effective_from: "2024-01-01"
    effective_to: "2099-12-31"
    approvers: ["a"]
  - id: DUP
    business_domain: trade
    anomaly_types: [type]
    action: exempt
    effective_from: "2024-01-01"
    effective_to: "2099-12-31"
    approvers: ["a"]
""")
    with pytest.raises(ExemptionRuleError, match="重复"):
        load_exemption_rules(path)


def test_scope_validation_rejects_bad_types(tmp_path):
    path = _write_yaml(tmp_path, """
rules:
  - id: R1
    business_domain: trade
    anomaly_types: [null_rate]
    action: exempt
    scope: "not-a-dict"
    effective_from: "2024-01-01"
    effective_to: "2099-12-31"
    approvers: ["a"]
""")
    with pytest.raises(ExemptionRuleError, match="scope"):
        load_exemption_rules(path)


def test_audit_dict_is_serializable():
    data = _rule().to_audit_dict()
    assert data["id"] == "R1"
    assert isinstance(data["anomaly_types"], list)
    unit_dict = _unit().to_dict()
    assert unit_dict["anomaly_type"] == "null_rate"
    assert len(_unit().key()) == 6


def test_ensure_str_list_validation_edges(tmp_path):
    # 字符串形式可自动包裹为列表
    path = _write_yaml(tmp_path, """
rules:
  - id: R1
    business_domain: trade
    anomaly_types: null_rate
    action: exempt
    scope:
      tables: trades
    effective_from: "2024-01-01"
    effective_to: "2099-12-31"
    approvers: ["a"]
""")
    rule = load_exemption_rules(path).rules[0]
    assert rule.anomaly_types == ("null_rate",)
    assert rule.tables == ("trades",)


def test_invalid_scope_list_and_string_fields(tmp_path):
    head = ('rules:\n  - id: R1\n    business_domain: trade\n'
            '    anomaly_types: [x]\n    action: exempt\n')
    window = '    effective_from: "2024-01-01"\n    effective_to: "2099-12-31"\n'
    # 空列表
    with pytest.raises(ExemptionRuleError):
        load_exemption_rules(_write_yaml(
            tmp_path, head + "    scope: {tables: []}\n" + window +
            '    approvers: ["a"]\n'))
    # 非字符串元素
    with pytest.raises(ExemptionRuleError):
        load_exemption_rules(_write_yaml(
            tmp_path, head + "    scope: {tables: [123]}\n" + window +
            '    approvers: ["a"]\n'))
    # approvers 不允许通配符（scope 中的通配是合法的）
    with pytest.raises(ExemptionRuleError, match="approvers"):
        load_exemption_rules(_write_yaml(
            tmp_path, head + "    scope: {tables: ['*']}\n" + window +
            '    approvers: ["*"]\n'))


def test_reason_and_enabled_type_validation(tmp_path):
    base = ('rules:\n  - id: R1\n    business_domain: trade\n'
            '    anomaly_types: [x]\n    action: exempt\n'
            '    effective_from: "2024-01-01"\n    effective_to: "2099-12-31"\n'
            '    approvers: ["a"]\n')
    with pytest.raises(ExemptionRuleError, match="reason"):
        load_exemption_rules(_write_yaml(tmp_path, base + "    reason: 123\n"))
    with pytest.raises(ExemptionRuleError, match="enabled"):
        load_exemption_rules(_write_yaml(tmp_path, base + "    enabled: 'yes'\n"))


def test_disabled_rule_is_loaded_but_never_matches(tmp_path):
    path = _write_yaml(tmp_path, """
rules:
  - id: R1
    business_domain: trade
    anomaly_types: [null_rate]
    action: exempt
    enabled: false
    effective_from: "2024-01-01"
    effective_to: "2099-12-31"
    approvers: ["a"]
""")
    ruleset = load_exemption_rules(path)
    assert ruleset.decide(_unit(), NOW) is None


def test_path_scope_specificity():
    rule_with_path = _rule("P", "exempt", paths=("data/a.csv",))
    assert rule_with_path.specificity(_unit()) >= 1
    assert rule_with_path.matches(_unit(path="data/b.csv"), NOW) is False
    assert rule_with_path.matches(_unit(path="data/a.csv"), NOW) is True


def test_missing_domain_and_anomaly_types(tmp_path):
    head = ('rules:\n  - id: R1\n    action: exempt\n'
            '    effective_from: "2024-01-01"\n    effective_to: "2099-12-31"\n'
            '    approvers: ["a"]\n')
    with pytest.raises(ExemptionRuleError, match="business_domain"):
        load_exemption_rules(_write_yaml(tmp_path, head))
    with pytest.raises(ExemptionRuleError, match="anomaly_types"):
        load_exemption_rules(_write_yaml(
            tmp_path, "rules:\n  - id: R1\n    business_domain: trade\n"
            "    action: exempt\n"
            '    effective_from: "2024-01-01"\n    effective_to: "2099-12-31"\n'
            '    approvers: ["a"]\n'))


def test_iter_units_helper():
    from gateway.exemption.rules import iter_units
    units = [_unit()]
    assert list(iter_units(units)) == units
