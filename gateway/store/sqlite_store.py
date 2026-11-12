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
    "result_json",
)
_UPDATABLE = set(_COLUMNS) - {"task_id"}

_METRIC_COLUMNS = (
    "task_id", "contract_fingerprint", "metric_key", "table_name",
    "column_name", "rule", "metric_value", "task_status", "created_at",
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
        """创建任务表、指标表与常用筛选索引，可重复执行。

        老版本数据库缺少 metrics 表，``CREATE TABLE IF NOT EXISTS`` 会在
        打开时平滑补齐，不需要停机迁移。
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
                    result_json TEXT NOT NULL DEFAULT '{}'
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    contract_fingerprint TEXT NOT NULL,
                    metric_key TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    column_name TEXT NOT NULL DEFAULT '',
                    rule TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    task_status TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT ''
                )
            """)
            connection.execute("CREATE INDEX IF NOT EXISTS idx_tasks_time "
                               "ON tasks(uploaded_at DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status "
                               "ON tasks(status)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_metrics_fingerprint "
                               "ON metrics(contract_fingerprint, task_id)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_metrics_task "
                               "ON metrics(task_id)")

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

    def finalize_task(self, task_id: str, metrics: Optional[List[Dict[str, Any]]] = None,
                      **fields: Any) -> bool:
        """在同一事务中更新任务状态并整体替换任务指标。

        指标写入与任务状态更新同生共死：任一失败都会整体回滚，不会留下
        半截指标污染后续基线。``metrics=None`` 表示本次不触碰指标表。
        """
        updates = {key: value for key, value in fields.items() if key in _UPDATABLE}
        if "result_json" in updates and not isinstance(updates["result_json"], str):
            updates["result_json"] = json.dumps(
                updates["result_json"], ensure_ascii=False, default=str)
        if "passed" in updates:
            updates["passed"] = 1 if updates["passed"] else 0
        updated = False
        with self._connection() as connection:
            if updates:
                assignments = ", ".join("%s = ?" % key for key in updates)
                params = [updates[key] for key in updates] + [task_id]
                cursor = connection.execute(
                    "UPDATE tasks SET %s WHERE task_id = ?" % assignments, params)
                updated = cursor.rowcount > 0
            if metrics is not None:
                connection.execute("DELETE FROM metrics WHERE task_id = ?", (task_id,))
                if metrics:
                    status = str(updates.get("status", ""))
                    created = str(updates.get("finished_at")
                                  or datetime.now().isoformat(timespec="seconds"))
                    rows = [(
                        task_id,
                        str(item.get("contract_fingerprint", "")),
                        str(item.get("metric_key", "")),
                        str(item.get("table_name", "")),
                        str(item.get("column_name", "")),
                        str(item.get("rule", "")),
                        float(item.get("metric_value", 0.0)),
                        status,
                        created,
                    ) for item in metrics]
                    connection.executemany(
                        "INSERT INTO metrics (%s) VALUES (%s)"
                        % (",".join(_METRIC_COLUMNS),
                           ",".join("?" for _ in _METRIC_COLUMNS)),
                        rows)
        return updated

    def baseline_metrics(self, contract_fingerprint: str, exclude_task_id: str = "",
                         max_tasks: int = 5) -> List[Dict[str, Any]]:
        """查询同契约指纹下最近若干次成功任务的指标，作为趋势基线。

        通过 JOIN tasks 过滤状态，被删除任务的指标自然不可见；同一任务的
        指标按插入顺序连续返回。
        """
        max_tasks = max(1, int(max_tasks))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT m.task_id AS task_id, m.table_name AS table_name, "
                "m.column_name AS column_name, m.rule AS rule, "
                "m.metric_value AS metric_value, t.uploaded_at AS uploaded_at "
                "FROM metrics m JOIN tasks t ON t.task_id = m.task_id "
                "WHERE m.contract_fingerprint = ? AND t.status = 'passed' "
                "AND m.task_id <> ? "
                "ORDER BY t.uploaded_at DESC, t.rowid DESC, m.id ASC",
                (contract_fingerprint, exclude_task_id)).fetchall()
        selected: List[Dict[str, Any]] = []
        seen = set()
        for row in rows:
            task_id = row["task_id"]
            if task_id not in seen:
                if len(seen) >= max_tasks:
                    break
                seen.add(task_id)
            selected.append(dict(row))
        return selected

    def task_metrics(self, task_id: str) -> List[Dict[str, Any]]:
        """返回单个任务已持久化的全部指标，按写入顺序排列。"""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM metrics WHERE task_id = ? ORDER BY id",
                (task_id,)).fetchall()
        return [dict(row) for row in rows]

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
        if status in ("passed", "failed", "running"):
            if status == "passed":
                clauses.append("status = 'passed'")
            elif status == "failed":
                clauses.append("status IN ('failed', 'error')")
            else:
                clauses.append("status = 'running'")
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
        """删除任务记录及其质量指标，同一事务保证不残留孤儿指标。"""
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
            connection.execute("DELETE FROM metrics WHERE task_id = ?", (task_id,))
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
