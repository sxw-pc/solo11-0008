"""批量任务队列的 SQLite 持久化。

与 :class:`gateway.store.sqlite_store.SQLiteStore` 共用同一个本地数据库
文件，但使用独立的 ``batch_jobs`` 表与独立的封装类，互不影响。队列持久化
是服务重启后自动恢复未完成任务的基础：queued/running 状态都落在磁盘上，
重启时把 running 重置为 queued 并重新加载即可。

仅使用标准库 sqlite3，每次操作创建短连接，适配 Flask 多线程与调度器
后台 worker 并发访问。
"""

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from .models import BatchJob, JobStatus, Priority

_COLUMNS = (
    "job_id", "batch_id", "packet_name", "packet_path", "packet_size",
    "estimated_bytes", "priority", "status", "created_at", "started_at",
    "finished_at", "task_id", "error", "contract_path", "lineage_path",
    "expected_hash",
)
_UPDATABLE = set(_COLUMNS) - {"job_id"}


def _now() -> str:
    """返回本地秒级 ISO 时间，与既有任务记录格式保持一致。"""
    return datetime.now().isoformat(timespec="seconds")


class BatchQueueStore:
    """批量队列的本地持久化接口。"""

    def __init__(self, db_path: Path):
        """保存数据库路径并初始化队列表结构。"""
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
        """创建队列表与索引，可重复执行。"""
        with self._connection() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS batch_jobs (
                    job_id TEXT PRIMARY KEY,
                    batch_id TEXT NOT NULL,
                    packet_name TEXT NOT NULL,
                    packet_path TEXT NOT NULL,
                    packet_size INTEGER NOT NULL DEFAULT 0,
                    estimated_bytes INTEGER NOT NULL DEFAULT 0,
                    priority INTEGER NOT NULL DEFAULT 5,
                    status TEXT NOT NULL DEFAULT 'queued',
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    task_id TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    contract_path TEXT NOT NULL DEFAULT '',
                    lineage_path TEXT NOT NULL DEFAULT '',
                    expected_hash TEXT NOT NULL DEFAULT ''
                )
            """)
            connection.execute("CREATE INDEX IF NOT EXISTS idx_batch_jobs_status "
                               "ON batch_jobs(status)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_batch_jobs_batch "
                               "ON batch_jobs(batch_id)")

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> BatchJob:
        """把数据库行转换为 BatchJob，rowid 作为单调入队序号。"""
        data = dict(row)
        return BatchJob(
            job_id=data["job_id"], batch_id=data["batch_id"],
            packet_name=data["packet_name"], packet_path=data["packet_path"],
            packet_size=int(data["packet_size"] or 0),
            estimated_bytes=int(data["estimated_bytes"] or 0),
            priority=Priority.clamp(data["priority"]),
            status=data["status"] or JobStatus.QUEUED,
            seq=int(data["seq"] or 0),
            created_at=data["created_at"] or "",
            started_at=data["started_at"],
            finished_at=data["finished_at"],
            task_id=data["task_id"] or "",
            error=data["error"] or "",
            contract_path=data["contract_path"] or "",
            lineage_path=data["lineage_path"] or "",
            expected_hash=data["expected_hash"] or "",
        )

    def create_job(self, job: BatchJob) -> str:
        """插入一条排队任务并返回 job_id。

        入队序号直接使用 SQLite 自增 rowid：单条 INSERT 原子完成，多线程
        提交也不会出现序号竞态，且重启后序号继续单调递增，同优先级任务的
        先进先出语义跨重启保持。
        """
        if not job.job_id or not job.batch_id:
            raise ValueError("批量任务缺少 job_id 或 batch_id")
        job.created_at = job.created_at or _now()
        job.priority = Priority.clamp(job.priority)
        job.task_id = job.task_id or job.job_id
        values = {name: getattr(job, name) for name in _COLUMNS}
        placeholders = ",".join("?" for _ in _COLUMNS)
        with self._connection() as connection:
            cursor = connection.execute(
                "INSERT INTO batch_jobs (%s) VALUES (%s)"
                % (",".join(_COLUMNS), placeholders),
                [values[name] for name in _COLUMNS])
            job.seq = int(cursor.lastrowid)
        return job.job_id

    def get_job(self, job_id: str) -> Optional[BatchJob]:
        """按任务 ID 查询，未找到返回 None。"""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT rowid AS seq, * FROM batch_jobs WHERE job_id = ?",
                (job_id,)).fetchone()
        return self._row_to_job(row) if row else None

    def update_job(self, job_id: str, **fields: Any) -> bool:
        """更新任务指定字段；非法字段名会被忽略。"""
        updates = {key: value for key, value in fields.items() if key in _UPDATABLE}
        if not updates:
            return False
        if "priority" in updates:
            updates["priority"] = Priority.clamp(updates["priority"])
        assignments = ", ".join("%s = ?" % key for key in updates)
        params = [updates[key] for key in updates] + [job_id]
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE batch_jobs SET %s WHERE job_id = ?" % assignments, params)
            return cursor.rowcount > 0

    def list_jobs(self, status: Optional[str] = None, batch_id: Optional[str] = None,
                  limit: int = 100) -> List[BatchJob]:
        """按状态/批次筛选任务。

        排队与运行中的任务按调度顺序（优先级、入队序号）返回；其他场景按
        入队序号倒序（最新提交在前）。
        """
        clauses = []
        params: List[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if batch_id:
            clauses.append("batch_id = ?")
            params.append(batch_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        if status in (JobStatus.QUEUED, JobStatus.RUNNING):
            order = "priority ASC, rowid ASC"
        else:
            order = "rowid DESC"
        limit = max(1, min(int(limit), 500))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT rowid AS seq, * FROM batch_jobs%s ORDER BY %s LIMIT ?"
                % (where, order), params + [limit]).fetchall()
        return [self._row_to_job(row) for row in rows]

    def queued_jobs(self) -> List[BatchJob]:
        """返回全部排队任务，按调度顺序排列（重启恢复时加载用）。"""
        return self.list_jobs(status=JobStatus.QUEUED, limit=500)

    def recent_terminal_jobs(self, limit: int = 20) -> List[BatchJob]:
        """返回最近到达终态的任务，按入队序号倒序。"""
        limit = max(1, min(int(limit), 200))
        placeholders = ",".join("?" for _ in JobStatus.TERMINAL)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT rowid AS seq, * FROM batch_jobs WHERE status IN (%s) "
                "ORDER BY rowid DESC LIMIT ?" % placeholders,
                list(JobStatus.TERMINAL) + [limit]).fetchall()
        return [self._row_to_job(row) for row in rows]

    def reset_running_to_queued(self) -> int:
        """把运行中任务重置为排队状态，返回重置数量（服务重启恢复用）。"""
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE batch_jobs SET status = ?, started_at = NULL "
                "WHERE status = ?", (JobStatus.QUEUED, JobStatus.RUNNING))
            return cursor.rowcount

    def count_active(self) -> int:
        """返回排队中与运行中的任务总数（队列容量控制用）。"""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM batch_jobs WHERE status IN (?, ?)",
                (JobStatus.QUEUED, JobStatus.RUNNING)).fetchone()
        return int(row["total"] or 0)

    def count_active_in_batch(self, batch_id: str) -> int:
        """返回指定批次中尚未到达终态的任务数（批次目录清理用）。"""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM batch_jobs "
                "WHERE batch_id = ? AND status IN (?, ?)",
                (batch_id, JobStatus.QUEUED, JobStatus.RUNNING)).fetchone()
        return int(row["total"] or 0)

    def purge_terminal(self, keep_latest: int = 500) -> int:
        """清理已终态的历史队列记录，保留最近若干条，返回删除数量。

        队列记录只含元数据（不含报告与日志），长期累积会影响列表查询
        效率；运维可定期调用。默认保留最近 500 条。
        """
        keep_latest = max(0, int(keep_latest))
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM batch_jobs WHERE status IN (%s) AND rowid NOT IN "
                "(SELECT rowid FROM batch_jobs WHERE status IN (%s) "
                " ORDER BY rowid DESC LIMIT ?)"
                % (",".join("?" for _ in JobStatus.TERMINAL),
                   ",".join("?" for _ in JobStatus.TERMINAL)),
                list(JobStatus.TERMINAL) + list(JobStatus.TERMINAL) + [keep_latest])
            return cursor.rowcount
