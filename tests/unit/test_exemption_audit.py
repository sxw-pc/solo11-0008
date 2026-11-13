"""豁免审计哈希链的写入、连续性校验与篡改检测单元测试。"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from gateway.exemption.audit import (GENESIS_HASH, AuditError,
                                     ExemptionAuditTrail, record_hash,
                                     verify_audit_chain)
from gateway.exemption.rules import AnomalyUnit, ExemptionRule

NOW = datetime(2025, 6, 1, 12, 0, 0)


def _rule(rule_id="R1", action="exempt"):
    return ExemptionRule(
        rule_id=rule_id, business_domain="trade", anomaly_types=("null_rate",),
        action=action, grade="L2",
        effective_from=datetime(2024, 1, 1), effective_to=datetime(2099, 12, 31),
        approvers=("治理部",), reason="历史遗留")


def _unit():
    return AnomalyUnit(check="anomaly", anomaly_type="null_rate",
                       domain="trade", table="trades", field="note")


def _trail(tmp_path, task_id="task1"):
    return ExemptionAuditTrail(Path(tmp_path) / (task_id + ".jsonl"),
                               task_id, "ruleset-hash", "trade", now=NOW)


def test_audit_chain_lifecycle_and_linking(tmp_path):
    trail = _trail(tmp_path)
    trail.open_chain(["R1"])
    rule = _rule()
    trail.log_decision(_unit(), rule, ["R1"], False, "exempted",
                       "2024-01-01T00:00:00", "2099-12-31T00:00:00")
    trail.log_unmatched(_unit())
    trail.log_expired(_unit(), ["OLD"])
    summary = {"exempted": 1, "blocked": 1, "expired_blocked": 1}
    trail.close_chain(summary)
    assert len(trail.records) == 5
    result = verify_audit_chain(trail.audit_path)
    assert result["valid"] is True
    assert result["task_id"] == "task1"
    # 链头前序哈希必须是创世哈希
    assert trail.records[0]["prev_hash"] == GENESIS_HASH
    # 每条记录的 prev_hash 指向前一条 hash
    for previous, current in zip(trail.records, trail.records[1:]):
        assert current["prev_hash"] == previous["hash"]


def test_append_only_each_line_is_valid_json(tmp_path):
    trail = _trail(tmp_path)
    trail.open_chain([])
    trail.close_chain({})
    lines = trail.audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        record = json.loads(line)
        assert record["hash"] == record_hash(record)


def test_verify_detects_content_tampering(tmp_path):
    trail = _trail(tmp_path)
    trail.open_chain(["R1"])
    trail.log_unmatched(_unit())
    trail.close_chain({})
    lines = trail.audit_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["detail"]["reason"] = "TAMPERED"
    lines[1] = json.dumps(record, ensure_ascii=False, sort_keys=True)
    tampered = Path(tmp_path) / "tampered.jsonl"
    tampered.write_text("\n".join(lines), encoding="utf-8")
    result = verify_audit_chain(tampered)
    assert result["valid"] is False
    assert "篡改" in result["error"]


def test_verify_detects_broken_link(tmp_path):
    trail = _trail(tmp_path)
    trail.open_chain([])
    trail.close_chain({})
    lines = trail.audit_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["prev_hash"] = "f" * 64
    record["hash"] = record_hash(record)
    lines[1] = json.dumps(record, ensure_ascii=False, sort_keys=True)
    broken = Path(tmp_path) / "broken.jsonl"
    broken.write_text("\n".join(lines), encoding="utf-8")
    result = verify_audit_chain(broken)
    assert result["valid"] is False
    assert "断裂" in result["error"]


def test_verify_detects_missing_close(tmp_path):
    trail = _trail(tmp_path)
    trail.open_chain([])
    result = verify_audit_chain(trail.audit_path)
    assert result["valid"] is False
    assert "关闭" in result["error"]


def test_verify_handles_missing_file_and_empty_and_corrupt(tmp_path):
    missing = verify_audit_chain(Path(tmp_path) / "nope.jsonl")
    assert missing["valid"] is False and "不存在" in missing["error"]
    empty = Path(tmp_path) / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert verify_audit_chain(empty)["valid"] is False
    corrupt = Path(tmp_path) / "corrupt.jsonl"
    corrupt.write_text("{not valid json}\n", encoding="utf-8")
    result = verify_audit_chain(corrupt)
    assert result["valid"] is False and "JSON" in result["error"]


def test_cannot_append_after_close(tmp_path):
    trail = _trail(tmp_path)
    trail.open_chain([])
    trail.close_chain({})
    with pytest.raises(AuditError):
        trail.log_unmatched(_unit())


def test_double_close_is_safe(tmp_path):
    trail = _trail(tmp_path)
    trail.open_chain([])
    trail.close_chain({})
    record_count = len(trail.records)
    trail.close_chain({})  # 不应重复追加或报错
    assert len(trail.records) == record_count
    assert verify_audit_chain(trail.audit_path)["valid"] is True


def test_deny_decision_is_logged(tmp_path):
    trail = _trail(tmp_path, task_id="deny-task")
    trail.open_chain(["R1"])
    trail.log_decision(_unit(), _rule("R1", "deny"), ["R1"], True,
                       "denied", "2024-01-01T00:00:00", "2099-12-31T00:00:00")
    trail.close_chain({})
    decision = trail.records[1]
    assert decision["detail"]["decision"] == "denied"
    assert decision["detail"]["conflict"] is True
    assert verify_audit_chain(trail.audit_path)["valid"] is True


def test_callable_now_factory_is_used(tmp_path):
    fixed = datetime(2030, 1, 2, 3, 4, 5)
    trail = ExemptionAuditTrail(Path(tmp_path) / "factory.jsonl", "t9",
                                "hash", "trade", now=lambda: fixed)
    trail.open_chain([])
    assert trail.records[0]["timestamp"] == "2030-01-02T03:04:05"
    trail.close_chain({})


def test_blank_lines_are_ignored_when_reading(tmp_path):
    trail = _trail(tmp_path)
    trail.open_chain([])
    trail.close_chain({})
    with trail.audit_path.open("a", encoding="utf-8") as handle:
        handle.write("\n   \n")  # 追加空白行不应影响校验
    assert verify_audit_chain(trail.audit_path)["valid"] is True


def test_sequence_gap_is_detected(tmp_path):
    trail = _trail(tmp_path)
    trail.open_chain([])
    trail.log_unmatched(_unit())
    trail.close_chain({})
    lines = trail.audit_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["seq"] = 99  # 制造序列号断裂
    record["hash"] = record_hash(record)
    lines[1] = json.dumps(record, ensure_ascii=False, sort_keys=True)
    gapped = Path(tmp_path) / "gapped.jsonl"
    gapped.write_text("\n".join(lines), encoding="utf-8")
    result = verify_audit_chain(gapped)
    assert result["valid"] is False
    assert "序列号" in result["error"]


def test_close_chain_idempotent_returns_last_record(tmp_path):
    trail = ExemptionAuditTrail(Path(tmp_path) / "idempotent.jsonl",
                                "t", "h", "trade", now=NOW)
    trail.open_chain([])
    record = trail.close_chain({})
    assert record["event"] == "chain_close"
    # 再次关闭返回同一条记录，不追加新行
    again = trail.close_chain({"other": True})
    assert again is record
    lines = trail.audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2


def test_chmod_failure_is_tolerated(tmp_path, monkeypatch):
    def raise_oserror(path, mode):
        raise OSError("platform does not support chmod")

    monkeypatch.setattr("gateway.exemption.audit.os.chmod", raise_oserror)
    trail = _trail(tmp_path)
    trail.open_chain([])
    record = trail.close_chain({})  # 不应因 chmod 失败而抛异常
    assert record["event"] == "chain_close"
    assert verify_audit_chain(trail.audit_path)["valid"] is True
