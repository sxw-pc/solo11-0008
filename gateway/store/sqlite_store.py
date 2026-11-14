"""SQLite 校验任务、结果与日志路径存储封装。

仅使用 Python 标准库 sqlite3，数据文件位于本地工作目录。每次操作创建短连接，
适配 Flask 多线程请求，避免跨线程连接复用问题。
"""

from contextlib import contextmanager
from datetime import datetime
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

_COLUMNS = (
    "task_id", "packet_name", "packet_size", "packet_sha256", "archive_type",
    "uploaded_at", "finished_at", "status", "passed", "contract_name",
    "lineage_name", "duration_seconds", "config_hash", "tool_version",
    "error_summary", "report_md", "report_html", "report_json", "log_path",
    "result_json", "terminated_stage", "terminate_requested_at",
)
_UPDATABLE = set(_COLUMNS) - {"task_id"}

#: 1.1.0 新增列，旧库通过 ALTER TABLE 迁移，历史行取默认值，不受影响。
_MIGRATIONS = (
    ("terminated_stage", "ALTER TABLE tasks ADD COLUMN terminated_stage "
                         "TEXT NOT NULL DEFAULT ''"),
    ("terminate_requested_at", "ALTER TABLE tasks ADD COLUMN "
                               "terminate_requested_at TEXT NOT NULL DEFAULT ''"),
)


class SQLiteStore:
    """本地校验任务持久化接口。"""

    def __init__(self, db_path: Path):
        """保存数据库路径并初始化表结构。"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def _connect(self) -> sqlite3.Connection:
        """创建短连接并启用行工厂。"""
        connection = sqlite3.connect(str(self.db_path), timeout=15)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self):
        """提供自动提交并确保关闭的连接上下文。"""
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def init_db(self) -> None:
        """创建任务表与常用筛选索引，可重复执行。

        对已存在的旧版数据库按列补齐迁移（ALTER TABLE ADD COLUMN），
        不会改写任何历史任务的状态、报告关联或结果数据。
        """
        with self._connection() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
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
                    result_json TEXT NOT NULL DEFAULT '{}',
                    terminated_stage TEXT NOT NULL DEFAULT '',
                    terminate_requested_at TEXT NOT NULL DEFAULT ''
                )
            """)
            existing = {row[1] for row in
                        connection.execute("PRAGMA table_info(tasks)").fetchall()}
            for column, statement in _MIGRATIONS:
                if column not in existing:
                    connection.execute(statement)
            connection.execute("CREATE INDEX IF NOT EXISTS idx_tasks_time "
                               "ON tasks(uploaded_at DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status "
                               "ON tasks(status)")

    @staticmethod
    def _serialize(task: Dict[str, Any]) -> Dict[str, Any]:
        """把字典/列表结果序列化为 JSON 字符串。"""
        values = dict(task)
        if "result_json" in values and not isinstance(values["result_json"], str):
            values["result_json"] = json.dumps(
                values["result_json"], ensure_ascii=False, default=str)
        return values

    def create_task(self, task: Dict[str, Any]) -> str:
        """插入一条任务记录并返回 task_id。"""
        task = self._serialize(task)
        missing = [name for name in ("task_id", "packet_name", "uploaded_at") if not task.get(name)]
        if missing:
            raise ValueError("任务缺少必填字段: %s" % ", ".join(missing))
        row = {name: task.get(name) for name in _COLUMNS}
        row["packet_size"] = int(row.get("packet_size") or 0)
        row["passed"] = 1 if row.get("passed") else 0
        row["status"] = row.get("status") or "running"
        row["uploaded_at"] = row.get("uploaded_at") or datetime.now().isoformat(timespec="seconds")
        row["result_json"] = row.get("result_json") or "{}"
        row["duration_seconds"] = float(row.get("duration_seconds") or 0)
        for name in _COLUMNS:
            if row.get(name) is None and name not in ("finished_at",):
                row[name] = ""
        placeholders = ",".join("?" for _ in _COLUMNS)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO tasks (%s) VALUES (%s)" % (",".join(_COLUMNS), placeholders),
                [row[name] for name in _COLUMNS],
            )
        return str(row["task_id"])

    def update_task(self, task_id: str, **fields: Any) -> bool:
        """更新任务指定字段；非法字段名会被忽略。"""
        updates = {key: value for key, value in fields.items() if key in _UPDATABLE}
        if not updates:
            return False
        if "result_json" in updates and not isinstance(updates["result_json"], str):
            updates["result_json"] = json.dumps(
                updates["result_json"], ensure_ascii=False, default=str)
        if "passed" in updates:
            updates["passed"] = 1 if updates["passed"] else 0
        assignments = ", ".join("%s = ?" % key for key in updates)
        params = [updates[key] for key in updates] + [task_id]
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE tasks SET %s WHERE task_id = ?" % assignments, params)
            return cursor.rowcount > 0

    def _conditional_update(self, task_id: str, condition: str,
                            fields: Dict[str, Any]) -> bool:
        """仅在任务当前状态满足条件时原子写入（比较并交换）。

        条件直接拼入 WHERE 子句，与 SET 赋值处于同一条 UPDATE 语句中，
        由 SQLite 单语句事务保证检查与写入的原子性，并发下只有一方生效。
        """
        updates = {key: value for key, value in fields.items() if key in _UPDATABLE}
        if not updates:
            return False
        if "result_json" in updates and not isinstance(updates["result_json"], str):
            updates["result_json"] = json.dumps(
                updates["result_json"], ensure_ascii=False, default=str)
        if "passed" in updates:
            updates["passed"] = 1 if updates["passed"] else 0
        assignments = ", ".join("%s = ?" % key for key in updates)
        params = [updates[key] for key in updates] + [task_id]
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE tasks SET %s WHERE task_id = ? AND %s"
                % (assignments, condition), params)
            return cursor.rowcount > 0

    def request_terminate(self, task_id: str, requested_at: str) -> bool:
        """把 running 任务原子迁移为 terminating；其他状态返回 False。

        已完成（passed/failed/error）或已终止的历史任务永远不会被改写。
        """
        return self._conditional_update(
            task_id, "status = 'running'",
            {"status": "terminating",
             "terminate_requested_at": str(requested_at)})

    def complete_task(self, task_id: str, **fields: Any) -> bool:
        """仅当任务仍处于 running 时写入最终结果。

        若终止请求已先把状态迁移为 terminating，本次写入失败，调用方应
        改走终止收尾流程，避免覆盖已受理的终止请求。
        """
        return self._conditional_update(task_id, "status = 'running'", fields)

    def finalize_termination(self, task_id: str, **fields: Any) -> bool:
        """仅当任务处于 running/terminating 时原子写入终止结果。

        状态强制为 terminated；已进入终态的任务返回 False，保证并发
        终止与正常完成竞争时任务状态只被最终写入一次。
        """
        fields["status"] = "terminated"
        return self._conditional_update(
            task_id, "status IN ('running', 'terminating')", fields)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        """将数据库行转换为含解析后 result 的字典。"""
        item = dict(row)
        item["passed"] = bool(item.get("passed"))
        try:
            item["result"] = json.loads(item.get("result_json") or "{}")
        except (ValueError, TypeError):
            item["result"] = {}
        return item

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """按任务 ID 查询，未找到返回 None。"""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def list_tasks(self, query: str = "", status: str = "",
                   date_from: str = "", date_to: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        """按任务 ID/包名、状态与时间范围筛选任务，按时间倒序返回。"""
        clauses = []
        params: List[Any] = []
        if query:
            clauses.append("(task_id LIKE ? OR packet_name LIKE ?)")
            like = "%" + str(query).strip() + "%"
            params.extend([like, like])
        if status in ("passed", "failed", "running", "terminated"):
            if status == "passed":
                clauses.append("status = 'passed'")
            elif status == "failed":
                clauses.append("status IN ('failed', 'error')")
            elif status == "terminated":
                clauses.append("status = 'terminated'")
            else:
                clauses.append("status IN ('running', 'terminating')")
        if date_from:
            clauses.append("uploaded_at >= ?")
            params.append(str(date_from) + "T00:00:00")
        if date_to:
            clauses.append("uploaded_at <= ?")
            params.append(str(date_to) + "T23:59:59")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = max(1, min(int(limit), 500))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM tasks%s ORDER BY uploaded_at DESC LIMIT ?" % where,
                params + [limit]).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_task(self, task_id: str) -> bool:
        """删除数据库任务记录，返回是否删除成功。"""
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
            return cursor.rowcount > 0

    def stats(self) -> Dict[str, int]:
        """返回首页所需的任务总数与通过/失败计数。"""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN status='passed' THEN 1 ELSE 0 END) AS passed, "
                "SUM(CASE WHEN status IN ('failed','error') THEN 1 ELSE 0 END) AS failed "
                "FROM tasks").fetchone()
        return {
            "total": int(row["total"] or 0),
            "passed": int(row["passed"] or 0),
            "failed": int(row["failed"] or 0),
        }
