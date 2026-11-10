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
