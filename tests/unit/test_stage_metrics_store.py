"""任务历史表 stage_metrics 列的迁移与读写单元测试。"""

import json
import sqlite3

from gateway.store.sqlite_store import SQLiteStore


def _task(task_id="task1", **extra):
    task = {
        "task_id": task_id, "packet_name": "mock.zip",
        "uploaded_at": "2024-03-01T10:00:00",
    }
    task.update(extra)
    return task


def _create_old_schema_db(path):
    """按重构前的 20 列结构创建存量数据库并写入一条历史任务。"""
    connection = sqlite3.connect(str(path))
    with connection:
        connection.execute("""
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
        """)
        connection.execute(
            "INSERT INTO tasks (task_id, packet_name, uploaded_at, status) "
            "VALUES ('legacy', 'old.zip', '2024-01-01T00:00:00', 'passed')")
    connection.close()


def test_migrate_old_database_adds_stage_metrics(tmp_path):
    db_path = tmp_path / "gateway.db"
    _create_old_schema_db(db_path)
    store = SQLiteStore(db_path)  # 打开时触发迁移
    columns = {row[1] for row in
               sqlite3.connect(str(db_path)).execute("PRAGMA table_info(tasks)")}
    assert "stage_metrics" in columns
    legacy = store.get_task("legacy")
    assert legacy is not None, "存量任务数据不得丢失"
    assert legacy["packet_name"] == "old.zip"
    assert legacy["stage_metrics"] == "[]"
    assert legacy["stages"] == []
    # 迁移后新任务可正常写入阶段指标。
    metrics = [{"key": "archive", "name": "压缩包安全与结构检查", "status": "passed",
                "duration_seconds": 0.5, "error_summary": ""}]
    store.create_task(_task("new", stage_metrics=metrics))
    item = store.get_task("new")
    assert item["stages"] == metrics
    assert json.loads(item["stage_metrics"]) == metrics
    # 重复打开不报错（迁移幂等）。
    assert SQLiteStore(db_path).get_task("new")["stages"] == metrics


def test_stage_metrics_roundtrip_and_update(store):
    assert store.create_task(_task()) == "task1"
    assert store.get_task("task1")["stages"] == []
    metrics = [
        {"key": "archive", "name": "压缩包安全与结构检查", "status": "passed",
         "duration_seconds": 0.12, "error_summary": ""},
        {"key": "hash", "name": "文件完整性与哈希校验", "status": "skipped",
         "duration_seconds": 0.0, "error_summary": "压缩包安全检查未通过"},
    ]
    assert store.update_task("task1", stage_metrics=metrics)
    stored = store.get_task("task1")
    assert stored["stages"] == metrics
    assert json.loads(stored["stage_metrics"]) == metrics
    # 直接写入字符串同样可行；非法 JSON 读取时回退为空列表。
    assert store.update_task("task1", stage_metrics="not-json")
    assert store.get_task("task1")["stages"] == []
    # 列表查询同样附带解析后的阶段指标。
    assert store.list_tasks()[0]["stages"] == []


def test_create_task_serializes_stage_metrics(store):
    metrics = [{"key": "schema", "status": "failed", "duration_seconds": 1.5,
                "error_summary": "类型不匹配"}]
    store.create_task(_task("with-metrics", stage_metrics=metrics))
    assert store.get_task("with-metrics")["stages"] == metrics
