"""分级豁免复核的端到端集成测试。

覆盖：真实异常包的豁免放行与拦截、规则快照隔离、审计链落盘与校验、
报告/任务历史中的豁免留痕、历史任务兼容、高危异常不可豁免与离线约束。
"""

import json
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from gateway.app import create_app
from gateway.config import AppConfig
from gateway.exemption import verify_audit_chain
from gateway.exemption.engine import ExemptionEngine
from gateway.pipeline import run_validation
from gateway.store.sqlite_store import SQLiteStore

ROOT = Path(__file__).resolve().parents[2]
INVALID = ROOT / "fixtures" / "invalid_packets"


def _write_rules(folder: Path, rules, name="exemption_rules.yaml") -> Path:
    path = Path(folder) / name
    path.write_text(yaml.safe_dump({"version": "1.0", "rules": rules},
                                   allow_unicode=True, sort_keys=False),
                    encoding="utf-8")
    return path


def _null_rate_rule(action="exempt", rule_id="EXM-NULL-1", domain="trade",
                    effective_to="2099-12-31"):
    return {
        "id": rule_id, "business_domain": domain,
        "anomaly_types": ["null_rate"],
        "scope": {"tables": ["trades"], "fields": ["note"]},
        "action": action, "grade": "L2",
        "effective_from": "2024-01-01", "effective_to": effective_to,
        "approvers": ["数据治理部", "安全合规部"],
        "reason": "历史遗留空值率问题，经多部门备案限期豁免",
    }


def _domain_packet(tmp_path, source_zip: Path, domain: str) -> Path:
    """复制异常包并在 manifest 注入业务域，返回新压缩包路径。"""
    import zipfile
    target = Path(tmp_path) / source_zip.name
    with zipfile.ZipFile(source_zip) as zin, \
            zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.namelist():
            data = zin.read(item)
            if item.endswith("manifest.yaml"):
                manifest = yaml.safe_load(data)
                manifest.setdefault("packet", {})["business_domain"] = domain
                data = yaml.safe_dump(manifest, allow_unicode=True,
                                      sort_keys=False).encode("utf-8")
            zout.writestr(item, data)
    return target


def _by_key(results, key):
    return next(item for item in results if item["key"] == key)


@pytest.fixture(autouse=True)
def reset_engine_registry():
    ExemptionEngine.reset_registry()
    yield
    ExemptionEngine.reset_registry()


def test_matching_rule_exempts_anomaly_and_passes_task(tmp_path):
    rules_path = _write_rules(tmp_path, [_null_rate_rule()])
    workspace = tmp_path / "ws"
    config = AppConfig(workspace_dir=workspace, exemption_rules_path=rules_path)
    store = SQLiteStore(config.db_path)
    packet = _domain_packet(tmp_path,
                            INVALID / "null_rate_over" / "null_rate_over.zip",
                            "trade")
    outcome = run_validation(packet, packet.name, config, store)
    task = outcome["task"]
    assert task["status"] == "passed"
    exemption = task["exemption"]
    assert exemption["exempted"] == 1
    assert exemption["exemption_records"][0]["rule_id"] == "EXM-NULL-1"
    assert exemption["ruleset_hash"]
    # 异常对象确实带上了规则唯一标识与有效期
    anomaly = _by_key(outcome["results"], "anomaly")
    note = next(f for f in anomaly["fields"]
                if f["table"] == "trades" and f["field"] == "note")
    marker = next(r["exemption"] for r in note["rules"] if not r["passed"])
    assert marker["status"] == "exempted"
    assert marker["rule_id"] == "EXM-NULL-1"
    assert marker["valid_from"] and marker["valid_to"]
    # 审计文件落盘且哈希链完整
    audit_rel = exemption["audit_path"]
    audit_path = workspace / audit_rel
    verified = verify_audit_chain(audit_path)
    assert verified["valid"] is True
    events = [rec["event"] for rec in verified["records"]]
    assert events == ["chain_open", "decision", "chain_close"]
    # 引擎实例已释放，无资源泄漏
    assert ExemptionEngine.live_count() == 0


def test_unmatched_anomaly_remains_blocked(tmp_path):
    # 规则面向 finance 域，数据包是 trade 域，无法命中
    rules_path = _write_rules(tmp_path, [_null_rate_rule(domain="finance")])
    config = AppConfig(workspace_dir=tmp_path / "ws",
                       exemption_rules_path=rules_path)
    store = SQLiteStore(config.db_path)
    packet = _domain_packet(tmp_path,
                            INVALID / "null_rate_over" / "null_rate_over.zip",
                            "trade")
    outcome = run_validation(packet, packet.name, config, store)
    assert outcome["task"]["status"] == "failed"
    exemption = outcome["task"]["exemption"]
    assert exemption["exempted"] == 0
    assert exemption["blocked"] >= 1
    anomaly = _by_key(outcome["results"], "anomaly")
    assert all("exemption" not in rule
               for field in anomaly["fields"] for rule in field["rules"]
               if not rule.get("passed"))


def test_expired_rule_keeps_anomaly_blocked(tmp_path):
    rules_path = _write_rules(
        tmp_path, [_null_rate_rule(effective_to="2024-12-31")])
    config = AppConfig(workspace_dir=tmp_path / "ws",
                       exemption_rules_path=rules_path)
    store = SQLiteStore(config.db_path)
    packet = _domain_packet(tmp_path,
                            INVALID / "null_rate_over" / "null_rate_over.zip",
                            "trade")
    outcome = run_validation(packet, packet.name, config, store)
    assert outcome["task"]["status"] == "failed"
    assert outcome["task"]["exemption"]["expired_blocked"] >= 1
    assert outcome["task"]["exemption"]["exempted"] == 0


def test_deny_rule_overrides_exempt_in_conflict(tmp_path):
    rules_path = _write_rules(tmp_path, [
        _null_rate_rule(action="exempt", rule_id="EXM-ALLOW"),
        _null_rate_rule(action="deny", rule_id="EXM-DENY"),
    ])
    config = AppConfig(workspace_dir=tmp_path / "ws",
                       exemption_rules_path=rules_path)
    store = SQLiteStore(config.db_path)
    packet = _domain_packet(tmp_path,
                            INVALID / "null_rate_over" / "null_rate_over.zip",
                            "trade")
    outcome = run_validation(packet, packet.name, config, store)
    exemption = outcome["task"]["exemption"]
    assert exemption["conflict_count"] >= 1
    # 最严格 deny 生效，任务维持失败
    assert outcome["task"]["status"] == "failed"
    conflict = exemption["conflicts"][0]
    assert conflict["chosen_rule_id"] == "EXM-DENY"
    assert set(conflict["candidate_rule_ids"]) == {"EXM-ALLOW", "EXM-DENY"}


def test_dangerous_file_never_exempted_even_with_wildcard(tmp_path):
    wildcard = {
        "id": "WILD", "business_domain": "*", "anomaly_types": ["*"],
        "action": "exempt", "grade": "L3",
        "effective_from": "2020-01-01", "effective_to": "2099-12-31",
        "approvers": ["x"], "reason": "越权尝试",
    }
    rules_path = _write_rules(tmp_path, [wildcard])
    config = AppConfig(workspace_dir=tmp_path / "ws",
                       exemption_rules_path=rules_path)
    store = SQLiteStore(config.db_path)
    packet = INVALID / "redundant_file" / "redundant_file.zip"
    outcome = run_validation(packet, packet.name, config, store)
    assert outcome["task"]["status"] == "failed"
    hash_result = _by_key(outcome["results"], "hash")
    dangerous = [e for e in hash_result["errors"]
                 if e.get("code") == "dangerous_file"]
    assert dangerous and all("exemption" not in e for e in dangerous)


def test_snapshot_isolation_against_mid_task_rule_change(tmp_path):
    from gateway.exemption.rules import load_exemption_rules
    rules_path = _write_rules(tmp_path, [_null_rate_rule()])

    # 第一个任务启动时固化旧规则快照（可豁免 null_rate）
    snapshot_before = load_exemption_rules(rules_path)
    assert [r.rule_id for r in snapshot_before.rules] == ["EXM-NULL-1"]

    # 任务启动后改写规则文件：新规则面向 finance 域，无法再命中 trade 数据包
    _write_rules(tmp_path, [{
        "id": "CHANGED", "business_domain": "finance",
        "anomaly_types": ["type"], "action": "deny", "grade": "L1",
        "effective_from": "2024-01-01", "effective_to": "2099-12-31",
        "approvers": ["y"], "reason": "changed"}])
    snapshot_after = load_exemption_rules(rules_path)
    assert [r.rule_id for r in snapshot_after.rules] == ["CHANGED"]
    assert snapshot_before.ruleset_hash != snapshot_after.ruleset_hash

    # 关键：持有旧快照的在跑任务，其豁免判定不受文件变更影响
    from gateway.exemption.engine import ExemptionEngine
    from gateway.exemption.rules import AnomalyUnit
    unit = AnomalyUnit(check="anomaly", anomaly_type="null_rate",
                       domain="trade", table="trades", field="note")
    decision = snapshot_before.decide(unit, datetime(2025, 6, 1))
    assert decision is not None and decision.chosen.rule_id == "EXM-NULL-1"

    # 变更后启动的新任务加载新快照，相同异常不再被豁免
    config = AppConfig(workspace_dir=tmp_path / "ws",
                       exemption_rules_path=rules_path)
    store = SQLiteStore(config.db_path)
    packet = _domain_packet(tmp_path,
                            INVALID / "null_rate_over" / "null_rate_over.zip",
                            "trade")
    outcome = run_validation(packet, packet.name, config, store)
    assert outcome["task"]["status"] == "failed"
    assert outcome["task"]["exemption"]["exempted"] == 0
    assert ExemptionEngine.live_count() == 0


def test_exemption_persisted_in_history_and_archived_report(tmp_path):
    rules_path = _write_rules(tmp_path, [_null_rate_rule()])
    workspace = tmp_path / "ws"
    config = AppConfig(workspace_dir=workspace, exemption_rules_path=rules_path)
    store = SQLiteStore(config.db_path)
    packet = _domain_packet(tmp_path,
                            INVALID / "null_rate_over" / "null_rate_over.zip",
                            "trade")
    outcome = run_validation(packet, packet.name, config, store)
    task_id = outcome["task"]["task_id"]
    # 任务历史中可读出豁免留痕
    stored = store.get_task(task_id)
    assert stored["result"]["exemption"]["exempted"] == 1
    assert stored["result"]["exemption"]["exemption_records"][0]["rule_id"]
    # 归档 JSON 报告包含豁免章节
    report_json = json.loads((workspace / stored["report_json"]).read_text(
        encoding="utf-8"))
    assert report_json["exemption"]["exempted"] == 1
    # HTML / Markdown 报告包含豁免标识
    html = (workspace / stored["report_html"]).read_text(encoding="utf-8")
    md = (workspace / stored["report_md"]).read_text(encoding="utf-8")
    assert "分级豁免复核" in html and "EXM-NULL-1" in html
    assert "已豁免" in md and "EXM-NULL-1" in md


def test_legacy_task_without_exemption_loads_as_all_blocked(tmp_path):
    workspace = tmp_path / "ws"
    config = AppConfig(workspace_dir=workspace)
    store = SQLiteStore(config.db_path)
    err = {"code": "type", "table": "t", "field": "amount", "message": "坏"}
    legacy_results = [{"key": "schema", "name": "Schema", "passed": False,
                       "tables": [{"table": "t", "errors": [err]}],
                       "errors": [err], "samples": []}]
    task = {
        "task_id": "legacy1", "packet_name": "old.zip", "packet_size": 1,
        "packet_sha256": "", "archive_type": "zip",
        "uploaded_at": "2024-01-01T00:00:00", "finished_at": "2024-01-01T00:01:00",
        "status": "failed", "passed": False, "contract_name": "c",
        "lineage_name": "l", "duration_seconds": 1.0, "config_hash": "h",
        "tool_version": "1.0.0", "error_summary": "x",
        "report_md": "", "report_html": "", "report_json": "", "log_path": "",
    }
    store.create_task(task)
    store.update_task("legacy1", result_json={"results": legacy_results})
    app = create_app(config)
    client = app.test_client()
    response = client.get("/tasks/legacy1")
    assert response.status_code == 200
    loaded = store.get_task("legacy1")
    assert "exemption" not in loaded["result"]
    text = response.get_data(as_text=True)
    assert "分级豁免复核" not in text  # 无豁免数据时章节隐藏


def test_invalid_rule_file_fails_closed(tmp_path):
    rules_path = tmp_path / "bad.yaml"
    rules_path.write_text("rules:\n  - id: 'bad id'\n    business_domain: trade\n",
                          encoding="utf-8")
    config = AppConfig(workspace_dir=tmp_path / "ws",
                       exemption_rules_path=rules_path)
    store = SQLiteStore(config.db_path)
    packet = INVALID / "null_rate_over" / "null_rate_over.zip"
    outcome = run_validation(packet, packet.name, config, store)
    assert outcome["task"]["status"] == "failed"
    assert "exemption" not in outcome["task"]
    assert not list(config.exemption_audit_dir.glob("*.jsonl"))


def test_no_rules_configuration_keeps_original_flow_identical(tmp_path):
    config = AppConfig(workspace_dir=tmp_path / "ws")  # 未配置豁免
    store = SQLiteStore(config.db_path)
    packet = INVALID / "null_rate_over" / "null_rate_over.zip"
    outcome = run_validation(packet, packet.name, config, store)
    assert outcome["task"]["status"] == "failed"
    assert "exemption" not in outcome["task"]
    assert not list(config.exemption_audit_dir.glob("*.jsonl"))
    assert ExemptionEngine.live_count() == 0


def test_engine_internal_error_falls_back_to_strict_block(tmp_path, monkeypatch):
    rules_path = _write_rules(tmp_path, [_null_rate_rule()])
    config = AppConfig(workspace_dir=tmp_path / "ws",
                       exemption_rules_path=rules_path)
    store = SQLiteStore(config.db_path)
    packet = _domain_packet(tmp_path,
                            INVALID / "null_rate_over" / "null_rate_over.zip",
                            "trade")

    def boom(self, results):
        raise RuntimeError("exemption engine exploded")

    monkeypatch.setattr(ExemptionEngine, "apply", boom)
    outcome = run_validation(packet, packet.name, config, store)
    # 豁免子系统异常绝不能放行：任务维持失败且无豁免留痕
    assert outcome["task"]["status"] == "failed"
    assert "exemption" not in outcome["task"]
    assert ExemptionEngine.live_count() == 0
    log_file = config.logs_dir / (outcome["task"]["task_id"] + ".log")
    assert "回退严格拦截" in log_file.read_text(encoding="utf-8")
