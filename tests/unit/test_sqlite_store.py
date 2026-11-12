"""SQLite 任务存储单元测试。"""

import pytest

from gateway.store.sqlite_store import SQLiteStore


def _task(task_id="task1", name="mock.zip", **extra):
    task = {
        "task_id": task_id, "packet_name": name,
        "uploaded_at": "2024-03-01T10:00:00", "packet_size": 10,
        "status": "passed", "passed": True,
        "result_json": {"results": [{"key": "archive", "passed": True}]},
    }
    task.update(extra)
    return task


def test_create_get_and_update(store):
    assert store.create_task(_task()) == "task1"
    item = store.get_task("task1")
    assert item["packet_name"] == "mock.zip"
    assert item["passed"] is True
    assert item["result"]["results"][0]["key"] == "archive"
    assert store.get_task("missing") is None
    assert store.update_task("task1", passed=False, status="failed",
                             error_summary="bad", result_json=[{"x": 1}])
    updated = store.get_task("task1")
    assert updated["passed"] is False
    assert updated["status"] == "failed"
    assert updated["result"] == [{"x": 1}]
    assert not store.update_task("missing", status="passed")
    assert not store.update_task("task1", unknown="ignored")


def test_create_requires_fields(store):
    with pytest.raises(ValueError, match="必填"):
        store.create_task({"task_id": "x"})
    with pytest.raises(ValueError, match="必填"):
        store.create_task({"packet_name": "x", "uploaded_at": "2024-01-01"})


def test_list_filters_and_limits(store):
    store.create_task(_task("alpha", "alpha.zip", uploaded_at="2024-01-01T10:00:00"))
    store.create_task(_task("beta", "beta.zip", status="failed", passed=False,
                            uploaded_at="2024-02-01T10:00:00"))
    store.create_task(_task("gamma", "gamma.tar.gz", status="running",
                            uploaded_at="2024-03-01T10:00:00"))
    assert [item["task_id"] for item in store.list_tasks(query="alpha")] == ["alpha"]
    assert [item["task_id"] for item in store.list_tasks(query="zip")] == ["beta", "alpha"]
    assert [item["task_id"] for item in store.list_tasks(status="passed")] == ["alpha"]
    assert [item["task_id"] for item in store.list_tasks(status="failed")] == ["beta"]
    assert [item["task_id"] for item in store.list_tasks(status="running")] == ["gamma"]
    assert [item["task_id"] for item in store.list_tasks(status="other")] == [
        "gamma", "beta", "alpha"]
    assert [item["task_id"] for item in store.list_tasks(
        date_from="2024-02-01", date_to="2024-02-28")] == ["beta"]
    assert len(store.list_tasks(limit=0)) == 1
    assert len(store.list_tasks(limit=999)) == 3


def test_stats_and_delete(store):
    store.create_task(_task("one"))
    store.create_task(_task("two", passed=False, status="failed"))
    store.create_task(_task("three", status="running", passed=False))
    stats = store.stats()
    assert stats == {"total": 3, "passed": 1, "failed": 1}
    assert store.delete_task("one")
    assert not store.delete_task("one")
    assert store.get_task("one") is None


def test_reopen_database(tmp_path):
    path = tmp_path / "data" / "gateway.db"
    first = SQLiteStore(path)
    first.create_task(_task("persisted"))
    second = SQLiteStore(path)
    assert second.get_task("persisted")["packet_name"] == "mock.zip"


def _metrics(task_fingerprint="fp1", table="users", value=100.0):
    return [{
        "contract_fingerprint": task_fingerprint,
        "metric_key": "%s:%s::row_count" % (task_fingerprint, table),
        "table_name": table, "column_name": "", "rule": "row_count",
        "metric_value": value,
    }]


def test_finalize_task_writes_metrics_atomically(store):
    store.create_task(_task("m1"))
    assert store.finalize_task(
        "m1", metrics=_metrics(), status="passed", passed=True,
        finished_at="2024-03-01T10:01:00")
    stored = store.get_task("m1")
    assert stored["status"] == "passed"
    rows = store.task_metrics("m1")
    assert len(rows) == 1
    assert rows[0]["metric_key"] == "fp1:users::row_count"
    assert rows[0]["metric_value"] == 100.0
    assert rows[0]["task_status"] == "passed"
    assert rows[0]["created_at"] == "2024-03-01T10:01:00"
    # 重复 finalize 整体替换指标，不产生重复行。
    store.finalize_task("m1", metrics=_metrics(value=200.0), status="passed")
    rows = store.task_metrics("m1")
    assert len(rows) == 1 and rows[0]["metric_value"] == 200.0
    # metrics=None 不触碰指标表。
    store.finalize_task("m1", metrics=None, error_summary="x")
    assert len(store.task_metrics("m1")) == 1


def test_delete_task_cascades_metrics(store):
    store.create_task(_task("d1"))
    store.finalize_task("d1", metrics=_metrics(), status="passed")
    assert store.task_metrics("d1")
    assert store.delete_task("d1")
    assert store.task_metrics("d1") == []


def test_baseline_metrics_filters_and_limits(store):
    for index in range(1, 5):
        task_id = "b%d" % index
        store.create_task(_task(
            task_id, uploaded_at="2024-03-0%dT10:00:00" % index,
            status="passed" if index != 3 else "failed"))
        store.finalize_task(task_id, metrics=_metrics(value=float(index * 10)),
                            status="passed" if index != 3 else "failed")
    # 只取成功任务，按时间倒序，排除当前任务自身。
    rows = store.baseline_metrics("fp1", exclude_task_id="b4", max_tasks=5)
    assert [row["task_id"] for row in rows] == ["b2", "b1"]
    # 限制基线任务数量。
    rows = store.baseline_metrics("fp1", exclude_task_id="", max_tasks=1)
    assert [row["task_id"] for row in rows] == ["b4"]
    # 指纹不同不参与基线。
    assert store.baseline_metrics("other-fp", exclude_task_id="") == []
    # 删除任务后不再出现在基线中。
    store.delete_task("b4")
    rows = store.baseline_metrics("fp1", exclude_task_id="", max_tasks=5)
    assert [row["task_id"] for row in rows] == ["b2", "b1"]


def test_open_legacy_database_without_metrics_table(tmp_path):
    """老版本库（仅 tasks 表）打开时平滑补齐 metrics 表，不报错。"""
    import sqlite3

    path = tmp_path / "legacy" / "gateway.db"
    path.parent.mkdir(parents=True)
    connection = sqlite3.connect(str(path))
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
            "INSERT INTO tasks (task_id, packet_name, uploaded_at, status) "
            "VALUES ('old1', 'legacy.zip', '2023-01-01T00:00:00', 'passed')")
    connection.close()
    store = SQLiteStore(path)
    assert store.get_task("old1")["packet_name"] == "legacy.zip"
    assert store.stats()["total"] == 1
    store.create_task(_task("new1"))
    store.finalize_task("new1", metrics=_metrics(), status="passed")
    assert store.baseline_metrics("fp1", exclude_task_id="") != []
    # 老任务没有指标，删除也不报错。
    assert store.delete_task("old1")
