"""跨批次质量趋势对比集成测试。

使用 fixtures 生成脚本构造同契约多批数据，连续跑多个任务，核对：
趋势小节内容、突变警示触发、首任务降级、删除任务后基线变化、
契约指纹变化断代、失败任务不污染基线与老库平滑迁移。
"""

import json
import sqlite3
from pathlib import Path

import pytest

from gateway.app import create_app
from gateway.config import AppConfig
from gateway.pipeline import run_validation
from gateway.store.sqlite_store import SQLiteStore

from fixtures.generate_fixtures import generate_trend_series

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
CONTRACT = FIXTURES / "mock_contract" / "user_trade_contract.yaml"
PRODUCT_CONTRACT = FIXTURES / "mock_contract" / "product_contract.yaml"
LINEAGE = FIXTURES / "mock_lineage" / "trade_lineage_rule.yaml"
PRODUCT_LINEAGE = FIXTURES / "mock_lineage" / "product_lineage_rule.yaml"
NULL_RATE_OVER = FIXTURES / "invalid_packets" / "null_rate_over" / "null_rate_over.zip"
PATH_TRAVERSAL = FIXTURES / "invalid_packets" / "path_traversal" / "path_traversal.zip"


@pytest.fixture(scope="module")
def trend_packets(tmp_path_factory):
    """生成同契约三批数据：两批正常基线 + 一批行数骤降、空值率抬升。"""
    return generate_trend_series(tmp_path_factory.mktemp("trend_packets"))


@pytest.fixture
def trend_config(tmp_path):
    """全量数据参与抽检，保证指标数值确定可断言。"""
    return AppConfig(workspace_dir=tmp_path / "workspace", sample_ratio=1.0)


@pytest.fixture
def trend_store(trend_config):
    return SQLiteStore(trend_config.db_path)


def _run(packet, config, store, **kwargs):
    return run_validation(packet, packet.name, config, store, **kwargs)


def _trend_result(outcome):
    return next(item for item in outcome["results"] if item["key"] == "trend")


def test_first_task_degrades_without_baseline(trend_config, trend_store, trend_packets):
    """首个没有基线的任务优雅降级，并在报告中说明。"""
    outcome = _run(trend_packets[0], trend_config, trend_store)
    task = outcome["task"]
    assert task["status"] == "passed"
    trend = _trend_result(outcome)
    assert trend["status"] == "no_baseline"
    assert trend["passed"] is True
    assert trend["deviations"] == []
    # 三种报告都包含趋势小节与降级说明。
    md = Path(outcome["report_paths"]["md"]).read_text(encoding="utf-8")
    html = Path(outcome["report_paths"]["html"]).read_text(encoding="utf-8")
    report_json = json.loads(Path(outcome["report_paths"]["json"]).read_text(encoding="utf-8"))
    assert "跨批次质量趋势" in md
    assert "暂无历史成功任务" in md
    assert "不影响准入结论" in md
    assert "跨批次质量趋势" in html and "暂无历史成功任务" in html
    assert report_json["trend"]["status"] == "no_baseline"
    # 首任务指标已正常落库，供后续任务做基线。
    metrics = trend_store.task_metrics(task["task_id"])
    assert metrics
    assert {row["task_status"] for row in metrics} == {"passed"}
    keys = {row["metric_key"] for row in metrics}
    assert any(key.endswith(":users::row_count") for key in keys)
    assert any(key.endswith(":trades:note:null_rate") for key in keys)


def test_deviation_warning_and_report_section(trend_config, trend_store, trend_packets):
    """行数骤降与空值率抬升触发突变警示，但只警示不阻断准入。"""
    first = _run(trend_packets[0], trend_config, trend_store)
    second = _run(trend_packets[1], trend_config, trend_store)
    assert _trend_result(second)["status"] == "ok"
    assert _trend_result(second)["deviations"] == []
    third = _run(trend_packets[2], trend_config, trend_store)
    task = third["task"]
    assert task["status"] == "passed", task["error_summary"]
    trend = _trend_result(third)
    assert trend["status"] == "ok"
    assert trend["baseline_tasks"] == 2
    assert trend["passed"] is True
    triggered = {(item["table"], item["column"], item["rule"]): item
                 for item in trend["deviations"]}
    # users 表 120 -> 40 行，触发行数波动警示。
    users_rows = triggered[("users", "", "row_count")]
    assert users_rows["baseline"] == 120.0
    assert users_rows["current"] == 40.0
    assert users_rows["change"] == pytest.approx(-2 / 3, abs=0.01)
    # trades.note 空值率 5% -> 13.75%，触发增量警示。
    note_null = triggered[("trades", "note", "null_rate")]
    assert note_null["baseline"] == pytest.approx(0.05)
    assert note_null["current"] == pytest.approx(0.1375)
    # trades/orders 行数与 note 异常命中率同样突变。
    assert ("trades", "", "row_count") in triggered
    assert ("orders", "", "row_count") in triggered
    assert ("trades", "note", "anomaly_rate") in triggered
    # 未突变的指标不警示。
    assert ("products", "", "row_count") not in triggered
    # 报告趋势小节包含突变指标、基线值与本次值。
    md = Path(third["report_paths"]["md"]).read_text(encoding="utf-8")
    assert "跨批次质量趋势" in md
    assert "表行数" in md and "空值率" in md
    assert "120" in md and "40" in md
    assert "仅作警示" in md
    html = Path(third["report_paths"]["html"]).read_text(encoding="utf-8")
    assert "跨批次质量趋势" in html and "表行数" in html
    report_json = json.loads(Path(third["report_paths"]["json"]).read_text(encoding="utf-8"))
    json_trend = report_json["trend"]
    assert json_trend["status"] == "ok"
    assert len(json_trend["deviations"]) == len(trend["deviations"])
    # 总体结论不受趋势警示影响。
    assert third["report"]["overall_passed"] is True
    # 详情页也能渲染趋势卡片。
    app = create_app(trend_config)
    client = app.test_client()
    detail = client.get("/tasks/%s" % task["task_id"])
    assert detail.status_code == 200
    assert "跨批次质量趋势" in detail.get_data(as_text=True)


def test_baseline_excludes_deleted_tasks(trend_config, trend_store, trend_packets):
    """被删除的历史任务不再参与基线计算。"""
    batch1 = _run(trend_packets[0], trend_config, trend_store)["task"]
    batch2 = _run(trend_packets[1], trend_config, trend_store)["task"]
    batch3 = _run(trend_packets[2], trend_config, trend_store)["task"]
    assert trend_store.delete_task(batch2["task_id"])
    assert trend_store.task_metrics(batch2["task_id"]) == []
    # 再跑一批正常数据：基线应只剩 batch3 与 batch1。
    outcome = _run(trend_packets[0], trend_config, trend_store)
    trend = _trend_result(outcome)
    assert trend["status"] == "ok"
    assert trend["baseline_tasks"] == 2
    assert set(trend["baseline_task_ids"]) == {batch1["task_id"], batch3["task_id"]}
    # 基线均值被 batch3 拉低后，本批指标不再被视为突变。
    assert trend["deviations"] == []
    rows = trend_store.baseline_metrics(
        trend["contract_fingerprint"], exclude_task_id=outcome["task"]["task_id"])
    assert {row["task_id"] for row in rows} == {batch1["task_id"], batch3["task_id"]}


def test_contract_change_breaks_trend_lineage(trend_config, trend_store, trend_packets):
    """契约内容变化导致指纹变化，新旧契约指标自然断代。"""
    first = _run(trend_packets[0], trend_config, trend_store,
                 contract_path=CONTRACT, lineage_path=LINEAGE)
    assert _trend_result(first)["status"] == "no_baseline"
    second = _run(trend_packets[1], trend_config, trend_store,
                  contract_path=PRODUCT_CONTRACT, lineage_path=PRODUCT_LINEAGE)
    trend = _trend_result(second)
    assert trend["status"] == "no_baseline"
    assert trend["contract_fingerprint"] != _trend_result(first)["contract_fingerprint"]
    # 换回 trade 契约，基线仍然连续。
    third = _run(trend_packets[1], trend_config, trend_store,
                 contract_path=CONTRACT, lineage_path=LINEAGE)
    trend_third = _trend_result(third)
    assert trend_third["status"] == "ok"
    assert trend_third["baseline_task_ids"] == [first["task"]["task_id"]]


def test_failed_tasks_do_not_pollute_baseline(trend_config, trend_store, trend_packets):
    """失败任务的指标不参与基线；中途失败的阶段不留半截指标。"""
    batch1 = _run(trend_packets[0], trend_config, trend_store)["task"]
    # 单次校验失败的任务：指标落库但标记 failed，不进基线。
    failed = _run(NULL_RATE_OVER, trend_config, trend_store)["task"]
    assert failed["status"] == "failed"
    failed_metrics = trend_store.task_metrics(failed["task_id"])
    assert failed_metrics
    assert {row["task_status"] for row in failed_metrics} == {"failed"}
    # 压缩包安全阶段失败：趋势阶段不执行，无任何指标残留。
    broken = _run(PATH_TRAVERSAL, trend_config, trend_store)["task"]
    assert broken["status"] == "failed"
    assert trend_store.task_metrics(broken["task_id"]) == []
    # 后续任务的基线只包含成功任务。
    outcome = _run(trend_packets[1], trend_config, trend_store)
    trend = _trend_result(outcome)
    assert trend["status"] == "ok"
    assert trend["baseline_task_ids"] == [batch1["task_id"]]
    assert trend["deviations"] == []


def test_legacy_database_migrates_smoothly(tmp_path, trend_packets):
    """仅含 tasks 表的老库打开不报错，新任务指标正常写入。"""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    connection = sqlite3.connect(str(workspace / "gateway.db"))
    with connection:
        connection.execute("""
            CREATE TABLE tasks (
                task_id TEXT PRIMARY KEY, packet_name TEXT NOT NULL,
                packet_size INTEGER NOT NULL DEFAULT 0,
                packet_sha256 TEXT NOT NULL DEFAULT '',
                archive_type TEXT NOT NULL DEFAULT '',
                uploaded_at TEXT NOT NULL, finished_at TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                passed INTEGER NOT NULL DEFAULT 0,
                contract_name TEXT NOT NULL DEFAULT '',
                lineage_name TEXT NOT NULL DEFAULT '',
                duration_seconds REAL NOT NULL DEFAULT 0,
                config_hash TEXT NOT NULL DEFAULT '',
                tool_version TEXT NOT NULL DEFAULT '',
                error_summary TEXT NOT NULL DEFAULT '',
                report_md TEXT NOT NULL DEFAULT '',
                report_html TEXT NOT NULL DEFAULT '',
                report_json TEXT NOT NULL DEFAULT '',
                log_path TEXT NOT NULL DEFAULT '',
                result_json TEXT NOT NULL DEFAULT '{}'
            )
        """)
        connection.execute(
            "INSERT INTO tasks (task_id, packet_name, uploaded_at, status, passed) "
            "VALUES ('legacy1', 'old.zip', '2023-01-01T00:00:00', 'passed', 1)")
    connection.close()
    config = AppConfig(workspace_dir=workspace, sample_ratio=1.0)
    store = SQLiteStore(config.db_path)
    assert store.get_task("legacy1")["packet_name"] == "old.zip"
    outcome = _run(trend_packets[0], config, store)
    assert outcome["task"]["status"] == "passed"
    assert _trend_result(outcome)["status"] == "no_baseline"
    assert store.task_metrics(outcome["task"]["task_id"])
    # 老记录无指标，删除不影响新数据。
    assert store.delete_task("legacy1")
    assert store.task_metrics(outcome["task"]["task_id"])
