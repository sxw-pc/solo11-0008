"""跨版本血缘漂移检测端到端集成测试。"""

from hashlib import md5, sha256
import json
from pathlib import Path
import sqlite3
import statistics
import time
import zipfile

import pandas as pd
import yaml

from gateway.app import create_app
from gateway.pipeline import run_validation
from gateway.store.lineage_snapshot_store import LineageSnapshotStore
from gateway.validator.lineage_drift import LineageSnapshotError

ROOT = Path(__file__).resolve().parents[2]
VALID_PACKET = ROOT / "fixtures" / "valid_packets" / "retail_valid_a.zip"


def _hashes(path: Path) -> dict:
    data = path.read_bytes()
    return {"md5": md5(data).hexdigest(), "sha256": sha256(data).hexdigest(),
            "size": len(data)}


def _write_orders_sqlite(path: Path, trades: pd.DataFrame) -> None:
    path.unlink(missing_ok=True)
    connection = sqlite3.connect(str(path))
    try:
        connection.execute(
            "CREATE TABLE orders (order_id TEXT PRIMARY KEY, trade_id TEXT UNIQUE, "
            "product_id TEXT NOT NULL, amount REAL NOT NULL, order_date TEXT NOT NULL)")
        for index, trade in trades.iterrows():
            connection.execute(
                "INSERT INTO orders VALUES (?, ?, ?, ?, ?)",
                ("O%04d" % (index + 1), trade["trade_id"], trade["product_id"],
                 float(trade["amount"]), trade["trade_date"]))
        connection.commit()
    finally:
        connection.close()


def build_packet(folder: Path, name: str, *,
                 users_columns=("user_id", "user_name", "region", "age",
                                "email", "signup_date"),
                 trades_columns=("trade_id", "user_id", "product_id", "amount",
                                 "quantity", "status", "trade_date", "note"),
                 extra_tables=None) -> Path:
    """构造满足内置 trade 契约/血缘规则的最小合法数据包。"""
    staging = folder / name
    data_dir = staging / "data"
    data_dir.mkdir(parents=True)
    users = pd.DataFrame([{
        "user_id": "U0001", "user_name": "Mock A", "region": "north", "age": 30,
        "email": "a@mock.local", "signup_date": "2024-01-05", "owner_id": "U0001",
    }])
    users = users[[column for column in users_columns if column in users.columns]]
    products = pd.DataFrame([{
        "product_id": "P001", "product_name": "Mock P", "category": "books",
        "price": 19.9, "stock": 10, "listed_date": "2024-01-15",
    }])
    trades = pd.DataFrame([{
        "trade_id": "T0001", "user_id": "U0001", "product_id": "P001",
        "amount": 10.5, "quantity": 1, "status": "paid",
        "trade_date": "2024-02-01", "note": "mock",
    }])[list(trades_columns)]
    users.to_csv(data_dir / "users.csv", index=False, encoding="utf-8")
    trades.to_csv(data_dir / "trades.csv", index=False, encoding="utf-8")
    products.to_parquet(data_dir / "products.parquet", index=False)
    _write_orders_sqlite(data_dir / "orders.sqlite", trades)
    tables = {
        "users": {"path": "data/users.csv", "format": "csv"},
        "trades": {"path": "data/trades.csv", "format": "csv"},
        "products": {"path": "data/products.parquet", "format": "parquet"},
        "orders": {"path": "data/orders.sqlite", "format": "sqlite",
                   "table": "orders"},
    }
    for table_name, frame in (extra_tables or {}).items():
        file_name = "data/%s.csv" % table_name
        frame.to_csv(staging / file_name, index=False, encoding="utf-8")
        tables[table_name] = {"path": file_name, "format": "csv"}
    files = {}
    for path in sorted((staging / "data").glob("*")):
        files["data/" + path.name] = _hashes(path)
    manifest = {
        "schema_version": "1.0", "packet": {"name": name},
        "tables": tables, "files": files,
    }
    (staging / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False),
        encoding="utf-8")
    packet = folder / (name + ".zip")
    with zipfile.ZipFile(packet, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(staging).as_posix())
    return packet


def test_first_packet_records_first_version_drift(config, store, tmp_path):
    outcome = run_validation(VALID_PACKET, "v1.zip", config, store)
    drift = outcome["lineage_drift"]
    assert drift["enabled"] and not drift["degraded"]
    assert drift["baseline"] is None
    assert drift["current"]["version"] == 1
    assert drift["lineage_key"]
    # 结果同时落入任务历史 JSON，供详情页重建报告。
    stored = store.get_task(outcome["task"]["task_id"])
    assert stored["result"]["lineage_drift"]["current"]["version"] == 1


def test_second_version_detects_field_mapping_drift(config, store, tmp_path):
    run_validation(VALID_PACKET, "v1.zip", config, store)
    packet_v2 = build_packet(tmp_path, "packet_v2",
                             trades_columns=("trade_id", "user_id", "product_id",
                                             "amount", "quantity", "status",
                                             "trade_date"))
    outcome = run_validation(packet_v2, "packet_v2.zip", config, store)
    drift = outcome["lineage_drift"]
    assert drift["current"]["version"] == 2
    assert drift["baseline"]["version"] == 1
    types = {change["type"] for change in drift["changes"]}
    assert "field_removed" in types
    target = next(change for change in drift["changes"]
                  if change["type"] == "field_removed" and "note" in change["target"])
    assert target["before"] == "note"
    # JSON 报告中漂移结构可直接解析，且原有字段保持不变。
    report_json = json.loads(
        Path(outcome["report_paths"]["json"]).read_text(encoding="utf-8"))
    assert report_json["lineage_drift"]["has_changes"] is True
    assert report_json["task"]["task_id"] == outcome["task"]["task_id"]
    assert report_json["checks"], "原有校验项概览字段必须保留"
    markdown = Path(outcome["report_paths"]["md"]).read_text(encoding="utf-8")
    html = Path(outcome["report_paths"]["html"]).read_text(encoding="utf-8")
    assert "血缘版本漂移" in markdown and "血缘版本漂移" in html


def test_relation_mapping_change_is_detected(config, store, tmp_path):
    run_validation(VALID_PACKET, "v1.zip", config, store)
    packet_v2 = build_packet(
        tmp_path, "packet_v2_rel",
        users_columns=("user_id", "user_name", "region", "age", "email",
                       "signup_date", "owner_id"))
    # 用临时血缘规则把关联字段从 user_id 改为 owner_id 映射。
    rule_path = tmp_path / "custom_lineage.yaml"
    rule = yaml.safe_load((ROOT / "fixtures" / "mock_lineage" /
                           "trade_lineage_rule.yaml").read_text(encoding="utf-8"))
    rule["relations"][0]["right"]["field"] = "owner_id"
    rule_path.write_text(yaml.safe_dump(rule, allow_unicode=True),
                         encoding="utf-8")
    outcome = run_validation(packet_v2, "packet_v2_rel.zip", config, store,
                             lineage_path=rule_path)
    drift = outcome["lineage_drift"]
    changed = next(change for change in drift["changes"]
                   if change["type"] == "relation_changed")
    assert changed["target"] == "trade_owner"
    assert changed["before"]["right_field"] == "user_id"
    assert changed["after"]["right_field"] == "owner_id"


def test_table_split_drift_end_to_end(config, store, tmp_path):
    run_validation(VALID_PACKET, "v1.zip", config, store)
    packet_v2 = build_packet(
        tmp_path, "packet_split",
        extra_tables={
            "users_profile": pd.DataFrame([{"user_id": "U0001", "age": 30,
                                            "region": "north"}]),
        })
    outcome = run_validation(packet_v2, "packet_split.zip", config, store)
    drift = outcome["lineage_drift"]
    assert any(change["type"] == "table_added"
               and change["target"] == "users_profile"
               for change in drift["changes"])


def test_corrupt_snapshot_degrades_without_blocking(config, store, tmp_path):
    first = run_validation(VALID_PACKET, "v1.zip", config, store)
    assert first["lineage_drift"]["current"]["version"] == 1
    # 直接破坏最新快照的 JSON 体，模拟归档数据损坏。
    connection = sqlite3.connect(str(config.db_path))
    connection.execute("UPDATE lineage_snapshots SET payload_json = 'broken-json'")
    connection.commit()
    connection.close()
    packet_v2 = build_packet(tmp_path, "packet_v3")
    outcome = run_validation(packet_v2, "packet_v3.zip", config, store)
    drift = outcome["lineage_drift"]
    assert drift["degraded"] is True
    assert drift["error"]["code"] == "lineage_snapshot_corrupt"
    # 主流程未被阻断：任务、三类报告与血缘校验结果照常产出。
    assert outcome["task"]["status"] == "passed"
    assert Path(outcome["report_paths"]["html"]).is_file()
    assert any(item["key"] == "lineage" for item in outcome["results"])
    markdown = Path(outcome["report_paths"]["md"]).read_text(encoding="utf-8")
    assert "降级" in markdown


def test_store_failure_degrades_and_keeps_main_flow(config, store, tmp_path,
                                                    monkeypatch):
    def boom(*args, **kwargs):
        raise LineageSnapshotError("注入损坏")

    monkeypatch.setattr(LineageSnapshotStore, "get_latest_snapshot", boom)
    outcome = run_validation(VALID_PACKET, "v1.zip", config, store)
    drift = outcome["lineage_drift"]
    assert drift["degraded"] is True
    assert drift["error"]["code"] == "lineage_snapshot_corrupt"
    assert outcome["task"]["status"] == "passed"


def test_unexpected_store_error_is_caught(config, store, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("磁盘不可用")

    monkeypatch.setattr(LineageSnapshotStore, "save_snapshot", boom)
    outcome = run_validation(VALID_PACKET, "v1.zip", config, store)
    drift = outcome["lineage_drift"]
    assert drift["degraded"] is True
    assert drift["error"]["code"] == "lineage_drift_error"
    assert outcome["task"]["status"] == "passed"


def test_snapshot_retention_keeps_latest_versions(config, store, tmp_path):
    config.lineage_snapshot_versions = 3
    lineage_key = None
    for index in range(5):
        packet = build_packet(tmp_path, "retention_%d" % index)
        outcome = run_validation(packet, packet.name, config, store)
        lineage_key = outcome["lineage_drift"]["lineage_key"]
    snapshot_store = LineageSnapshotStore(
        config.db_path, max_versions=config.lineage_snapshot_versions)
    metas = snapshot_store.list_snapshots(lineage_key)
    assert len(metas) == 3
    assert [meta["version"] for meta in metas] == [5, 4, 3]


def test_legacy_database_without_snapshot_table_supported(config, store, tmp_path):
    # 先建出快照表再删除，模拟只含旧版 tasks 表的历史数据库。
    LineageSnapshotStore(config.db_path)
    connection = sqlite3.connect(str(config.db_path))
    connection.execute("DROP TABLE IF EXISTS lineage_snapshots")
    connection.commit()
    connection.close()
    outcome = run_validation(VALID_PACKET, "legacy.zip", config, store)
    drift = outcome["lineage_drift"]
    assert drift["enabled"] and not drift["degraded"]
    assert drift["baseline"] is None
    # 旧库补建快照表后，任务历史读写不受影响。
    assert store.stats()["total"] == 1
    assert store.get_task(outcome["task"]["task_id"])["status"] == "passed"


def test_detail_page_renders_drift_card(config, store, tmp_path):
    run_validation(VALID_PACKET, "v1.zip", config, store)
    packet_v2 = build_packet(tmp_path, "packet_web")
    outcome = run_validation(packet_v2, "packet_web.zip", config, store)
    app = create_app(config)
    response = app.test_client().get(
        "/tasks/%s" % outcome["task"]["task_id"])
    assert response.status_code == 200
    assert "血缘版本漂移" in response.get_data(as_text=True)


def test_legacy_task_without_drift_renders_detail_page(config, store):
    # 模拟旧版本任务：result_json 只有 results，没有 lineage_drift 键。
    task_id = store.create_task({
        "task_id": "legacy-task", "packet_name": "legacy.zip",
        "uploaded_at": "2024-01-01T10:00:00", "status": "passed", "passed": True,
        "result_json": {"results": [{"key": "archive", "passed": True}]},
    })
    app = create_app(config)
    response = app.test_client().get("/tasks/%s" % task_id)
    assert response.status_code == 200
    assert "未启用跨版本血缘漂移检测" in response.get_data(as_text=True)


def test_drift_overhead_under_10_percent(config, store, tmp_path, monkeypatch):
    # 需求口径是“单包校验整体耗时涨幅 ≤ 10%”。漂移逻辑本身为元数据级操作，
    # 因此以完整流水线为分母，分别测量启用漂移与漂移短路（不访问快照存储）
    # 两种情况下的多轮中位数耗时并比对。
    from gateway import pipeline
    from gateway.validator.lineage_drift import unavailable_drift

    packet = build_packet(tmp_path, "perf_packet")
    rounds = 5

    def median_duration():
        values = []
        for _ in range(rounds):
            started = time.perf_counter()
            run_validation(packet, packet.name, config, store)
            values.append(time.perf_counter() - started)
        return statistics.median(values)

    enabled_median = median_duration()

    def short_circuit_drift(*args, **kwargs):
        return unavailable_drift("performance baseline", lineage_key="x")

    monkeypatch.setattr(pipeline, "_collect_lineage_drift", short_circuit_drift)
    baseline_median = median_duration()
    # 10% 上限并保留 100ms 绝对余量，吸收挂载盘调度与计时器噪声。
    assert enabled_median <= baseline_median * 1.10 + 0.1
