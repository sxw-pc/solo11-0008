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


def test_generated_task_id_is_unique(store):
    store.create_task(_task("fixed1"))
    for _ in range(20):
        new_id = store.generate_task_id()
        assert new_id != "fixed1"
        assert not store.task_exists(new_id)
        store.create_task(_task(new_id))
    # 已占用的 ID 必须能被识别
    assert store.task_exists("fixed1")
    assert not store.task_exists("not-used-id")


def test_duplicate_insert_raises_value_error(store):
    store.create_task(_task("dup"))
    with pytest.raises(ValueError, match="任务 ID 已存在"):
        store.create_task(_task("dup"))


def test_legacy_database_remains_accessible(tmp_path):
    """存量库（缺少后加列也不影响）可直接打开并读取历史任务。"""
    import sqlite3
    path = tmp_path / "legacy" / "gateway.db"
    path.parent.mkdir(parents=True)
    connection = sqlite3.connect(str(path))
    connection.execute(
        "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, packet_name TEXT NOT NULL, "
        "packet_size INTEGER NOT NULL DEFAULT 0, packet_sha256 TEXT NOT NULL DEFAULT '', "
        "archive_type TEXT NOT NULL DEFAULT '', uploaded_at TEXT NOT NULL, "
        "finished_at TEXT, status TEXT NOT NULL DEFAULT 'running', "
        "passed INTEGER NOT NULL DEFAULT 0, contract_name TEXT NOT NULL DEFAULT '', "
        "lineage_name TEXT NOT NULL DEFAULT '', duration_seconds REAL NOT NULL DEFAULT 0, "
        "config_hash TEXT NOT NULL DEFAULT '', tool_version TEXT NOT NULL DEFAULT '', "
        "error_summary TEXT NOT NULL DEFAULT '', report_md TEXT NOT NULL DEFAULT '', "
        "report_html TEXT NOT NULL DEFAULT '', report_json TEXT NOT NULL DEFAULT '', "
        "log_path TEXT NOT NULL DEFAULT '', result_json TEXT NOT NULL DEFAULT '{}')")
    connection.execute(
        "INSERT INTO tasks (task_id, packet_name, uploaded_at) VALUES "
        "('legacy1', 'old.zip', '2024-01-01T10:00:00')")
    connection.commit()
    connection.close()
    store = SQLiteStore(path)
    item = store.get_task("legacy1")
    assert item is not None and item["packet_name"] == "old.zip"
    assert item["result"] == {}
