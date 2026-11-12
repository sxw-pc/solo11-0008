"""跨批次质量趋势对比单元测试。"""

import pytest

from gateway.config import AppConfig
from gateway.validator.trend_check import (
    contract_fingerprint, contract_fingerprint_from_file, detect_deviations,
    extract_metrics, metric_key, run_trend_stage,
)


def _metric(fingerprint, table, column, rule, value):
    """构造测试用指标记录。"""
    return {
        "contract_fingerprint": fingerprint,
        "metric_key": metric_key(fingerprint, table, column, rule),
        "table_name": table,
        "column_name": column,
        "rule": rule,
        "metric_value": float(value),
    }


def _baseline_row(task_id, table, column, rule, value):
    """构造测试用基线指标行。"""
    return {
        "task_id": task_id, "table_name": table, "column_name": column,
        "rule": rule, "metric_value": float(value),
        "uploaded_at": "2026-01-01T00:00:00",
    }


def test_contract_fingerprint_stable_and_sensitive(tmp_path):
    contract_a = {"version": "1.0", "tables": {"users": {"fields": {"id": {"type": "string"}}}}}
    contract_b = {"tables": {"users": {"fields": {"id": {"type": "string"}}}}, "version": "1.0"}
    contract_c = {"version": "1.0", "tables": {"users": {"fields": {"id": {"type": "integer"}}}}}
    assert contract_fingerprint(contract_a) == contract_fingerprint(contract_b)
    assert contract_fingerprint(contract_a) != contract_fingerprint(contract_c)
    path = tmp_path / "contract.yaml"
    path.write_text("version: '1.0'\ntables: {}\n", encoding="utf-8")
    from_file = contract_fingerprint_from_file(path)
    assert from_file == contract_fingerprint({"version": "1.0", "tables": {}})
    path.write_text("version: '1.1'\ntables: {}\n", encoding="utf-8")
    assert contract_fingerprint_from_file(path) != from_file


def test_contract_fingerprint_fallback_for_broken_file(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_bytes(b"\xff\xfe\x00bad:\x00")
    first = contract_fingerprint_from_file(path)
    assert isinstance(first, str) and len(first) == 16
    missing = contract_fingerprint_from_file(tmp_path / "missing.yaml")
    assert isinstance(missing, str) and len(missing) == 16
    assert first != missing


def test_extract_metrics_from_tables_and_anomaly(make_table):
    tables = {
        "users": make_table("users", [{"a": 1}, {"a": 2}]),
        "trades": make_table("trades", [{"b": 1}]),
    }
    anomaly = {
        "fields": [
            {"table": "users", "field": "email", "null_rate": 0.5,
             "duplicate_rate": 0.0, "anomaly_rate": 0.5},
            {"table": "users", "field": "age", "null_rate": 0.0,
             "duplicate_rate": 0.25, "anomaly_rate": 0.0},
        ]
    }
    metrics = extract_metrics("fp123", tables, anomaly)
    by_key = {item["metric_key"]: item["metric_value"] for item in metrics}
    assert by_key["fp123:users::row_count"] == 2.0
    assert by_key["fp123:trades::row_count"] == 1.0
    assert by_key["fp123:users:email:null_rate"] == 0.5
    assert by_key["fp123:users:age:duplicate_rate"] == 0.25
    assert by_key["fp123:users:email:anomaly_rate"] == 0.5
    assert len(metrics) == 2 + 2 * 3
    # 异常结果缺失时仍保留行数指标。
    only_rows = extract_metrics("fp123", tables, None)
    assert {item["rule"] for item in only_rows} == {"row_count"}


def test_detect_row_count_deviation_both_directions():
    current = [_metric("fp", "users", "", "row_count", 30)]
    baseline = [_baseline_row("t1", "users", "", "row_count", 100)]
    deviations = detect_deviations(current, baseline, 0.5, 0.05)
    assert len(deviations) == 1
    item = deviations[0]
    assert item["rule"] == "row_count"
    assert item["baseline"] == 100.0
    assert item["current"] == 30.0
    assert item["change"] == pytest.approx(-0.7)
    assert "users" in item["message"] and "波动" in item["message"]
    # 增长方向同样触发。
    current_up = [_metric("fp", "users", "", "row_count", 160)]
    assert len(detect_deviations(current_up, baseline, 0.5, 0.05)) == 1
    # 阈值内不触发。
    current_ok = [_metric("fp", "users", "", "row_count", 140)]
    assert detect_deviations(current_ok, baseline, 0.5, 0.05) == []


def test_detect_rate_increment_only_on_rise():
    baseline = [_baseline_row("t1", "trades", "note", "null_rate", 0.05)]
    rise = [_metric("fp", "trades", "note", "null_rate", 0.12)]
    deviations = detect_deviations(rise, baseline, 0.5, 0.05)
    assert len(deviations) == 1
    assert deviations[0]["change"] == pytest.approx(0.07)
    assert deviations[0]["change_text"].endswith("pp")
    # 下降属于质量改善，不触发。
    drop = [_metric("fp", "trades", "note", "null_rate", 0.0)]
    assert detect_deviations(drop, baseline, 0.5, 0.05) == []
    # 增量未超阈值不触发。
    small = [_metric("fp", "trades", "note", "null_rate", 0.09)]
    assert detect_deviations(small, baseline, 0.5, 0.05) == []


def test_detect_deviation_edge_cases():
    # 基线行数为 0、本次非 0 视为突变。
    current = [_metric("fp", "users", "", "row_count", 10)]
    baseline = [_baseline_row("t1", "users", "", "row_count", 0)]
    deviations = detect_deviations(current, baseline, 0.5, 0.05)
    assert len(deviations) == 1 and deviations[0]["change"] is None
    # 基线不存在的指标键直接跳过，不做跨键对齐。
    orphan = [_metric("fp", "new_table", "", "row_count", 999)]
    assert detect_deviations(orphan, baseline, 0.5, 0.05) == []
    # 多次基线任务取均值。
    current_avg = [_metric("fp", "users", "", "row_count", 50)]
    baseline_avg = [_baseline_row("t1", "users", "", "row_count", 100),
                    _baseline_row("t2", "users", "", "row_count", 110)]
    deviations_avg = detect_deviations(current_avg, baseline_avg, 0.5, 0.05)
    assert deviations_avg[0]["baseline"] == pytest.approx(105.0)
    assert deviations_avg[0]["baseline_tasks"] == 2


def test_run_trend_stage_disabled(config, store):
    result, metrics = run_trend_stage(
        AppConfig(workspace_dir=config.workspace_dir, trend_enabled=False),
        store, config.builtin_contract, "taskx", {}, None)
    assert result is None and metrics is None


def test_run_trend_stage_first_task_degrades(config, store, make_table):
    tables = {"users": make_table("users", [{"a": 1}])}
    result, metrics = run_trend_stage(
        config, store, config.builtin_contract, "task1", tables, None)
    assert result["status"] == "no_baseline"
    assert result["passed"] is True
    assert "基线" in result["summary"]
    assert metrics and metrics[0]["rule"] == "row_count"


def test_run_trend_stage_internal_error_degrades(config, store, make_table):
    class BrokenStore:
        def baseline_metrics(self, *args, **kwargs):
            raise RuntimeError("db gone")

    result, metrics = run_trend_stage(
        config, BrokenStore(), config.builtin_contract, "task1",
        {"users": make_table("users", [{"a": 1}])}, None)
    assert result["status"] == "degraded"
    assert result["passed"] is True
    assert metrics is None


def test_trend_config_validation(tmp_path):
    with pytest.raises(ValueError, match="trend_baseline_tasks"):
        AppConfig(workspace_dir=tmp_path / "a", trend_baseline_tasks=0)
    with pytest.raises(ValueError, match="trend_row_change_ratio"):
        AppConfig(workspace_dir=tmp_path / "b", trend_row_change_ratio=-0.1)
    with pytest.raises(ValueError, match="trend_rate_increase"):
        AppConfig(workspace_dir=tmp_path / "c", trend_rate_increase=-1)
    config = AppConfig(workspace_dir=tmp_path / "d", trend_baseline_tasks=3,
                       trend_row_change_ratio=0.2, trend_rate_increase=0.1)
    public = config.public_dict()
    assert public["trend_baseline_tasks"] == 3
    assert public["trend_rate_increase"] == 0.1
