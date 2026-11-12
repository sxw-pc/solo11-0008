"""SQLite 存储降级标记与历史库迁移单元测试。"""

import json
import sqlite3

from gateway.store.sqlite_store import SQLiteStore

# 1.0 版本的任务表结构（无 degraded 列），用于验证自动迁移。
_LEGACY_SCHEMA = """
CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    packet_name TEXT NOT NULL,
    packet_size INTEGER NOT NULL DEFAULT 0,
    packet_sha256 TEXT NOT NULL DEFAULT '',
    archive_type TEXT NOT NULL DEFAULT '',
    uploaded_at TEXT NOT NULL,
    finished_at TEXT,
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
"""


def _task(task_id="task1", **extra):
    task = {
        "task_id": task_id, "packet_name": "mock.zip",
        "uploaded_at": "2024-03-01T10:00:00", "status": "failed",
        "passed": False,
    }
    task.update(extra)
    return task


def test_degraded_round_trip(store):
    degradation = {
        "levels": {"archive": "block", "hash": "degrade"},
        "degraded_stages": ["hash"], "terminated_at": None,
        "skipped_stages": [],
    }
    store.create_task(_task("d1", degraded=True,
                            result_json={"results": [], "degradation": degradation}))
    item = store.get_task("d1")
    assert item["degraded"] is True
    assert item["degradation"]["degraded_stages"] == ["hash"]
    assert store.update_task("d1", degraded=False)
    assert store.get_task("d1")["degraded"] is False
    assert store.update_task("d1", degraded=True)
    assert store.get_task("d1")["degraded"] is True


def test_default_degraded_is_false(store):
    store.create_task(_task("plain"))
    item = store.get_task("plain")
    assert item["degraded"] is False
    assert item["degradation"] is None


def test_migrates_legacy_database(tmp_path):
    """历史版本数据库打开时自动补列，存量记录查询不受影响。"""
    db_path = tmp_path / "gateway.db"
    connection = sqlite3.connect(str(db_path))
    with connection:
        connection.execute(_LEGACY_SCHEMA)
        connection.execute(
            "INSERT INTO tasks (task_id, packet_name, uploaded_at, status, "
            "result_json) VALUES (?, ?, ?, ?, ?)",
            ("old1", "legacy.zip", "2024-01-01T00:00:00", "failed",
             json.dumps({"results": [{"key": "archive", "passed": False}]})))
    connection.close()
    store = SQLiteStore(db_path)
    task = store.get_task("old1")
    assert task["packet_name"] == "legacy.zip"
    assert task["degraded"] is False
    assert task["degradation"] is None
    assert task["result"]["results"][0]["key"] == "archive"
    # 迁移后新任务可正常写入降级标记，统计口径不变。
    store.create_task(_task("new1", degraded=True))
    assert store.get_task("new1")["degraded"] is True
    stats = store.stats()
    assert stats == {"total": 2, "passed": 0, "failed": 2}
    # 重复打开已迁移的库不会报错。
    again = SQLiteStore(db_path)
    assert again.get_task("old1")["packet_name"] == "legacy.zip"


def test_list_tasks_surfaces_degraded(store):
    store.create_task(_task("a", degraded=True))
    store.create_task(_task("b"))
    items = {item["task_id"]: item for item in store.list_tasks()}
    assert items["a"]["degraded"] is True
    assert items["b"]["degraded"] is False
