"""血缘版本快照的 SQLite 持久化与保留策略。

与任务表同库但使用独立的 ``lineage_snapshots`` 表：旧版本数据库通过
``CREATE TABLE IF NOT EXISTS`` 自动补建，``tasks`` 表结构与已归档历史数据
均不做任何改动。快照按业务契约键（lineage_key）分组并各自维护版本号，
默认每组仅自动保留最近 30 个非保护快照，超出后清理最旧的非保护快照。
"""

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
import uuid

from ..validator.lineage_drift import (DEFAULT_LINEAGE_KEY,
                                       LineageSnapshotError,
                                       validate_snapshot_payload)

DEFAULT_MAX_VERSIONS = 30


class LineageSnapshotStore:
    """血缘快照持久化接口，短连接适配多线程请求。"""

    def __init__(self, db_path: Path, max_versions: int = DEFAULT_MAX_VERSIONS):
        """保存数据库路径并初始化快照表；保留数量必须为正整数。"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_versions = max(1, int(max_versions))
        self.init_db()

    def _connect(self) -> sqlite3.Connection:
        """创建短连接并按本地部署文件系统调优提交策略。

        工具的实际运行环境多为挂载盘（如 Windows 盘透传的 9p/drvfs），单次
        ``fsync`` 可达数十毫秒：SQLite 默认 DELETE/FULL 模式每个事务提交都
        触发两次同步，WAL 在短连接模型下每次关闭又强制 checkpoint，实测
        都会让一次快照保存耗时上百毫秒。这里使用 MEMORY 回滚日志 +
        ``synchronous=OFF``：回滚日志只在内存维护、提交不产生 ``fsync``。
        安全性由数据定位兜底——血缘快照是可由任务重跑重建的派生审计数据，
        且读取侧已实现损坏即降级；OFF 仅在操作系统断电/崩溃时可能丢失最后
        一个写入事务，进程级异常仍由事务回滚保证一致性，任务主表
        （``tasks``）使用独立连接与默认同步级别，完全不受影响。
        日志模式是连接级属性，每次连接显式设置，避免历史 WAL 库继承慢路径。
        """
        connection = sqlite3.connect(str(self.db_path), timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode=MEMORY")
            connection.execute("PRAGMA synchronous=OFF")
        except sqlite3.DatabaseError:
            # 文件系统不支持自定义日志模式时回退默认配置，功能不受影响。
            pass
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
        """创建血缘快照表与索引，可对旧库重复执行而不影响既有数据。"""
        with self._connection() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS lineage_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    lineage_key TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    task_id TEXT NOT NULL,
                    packet_name TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    protected INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL,
                    UNIQUE(lineage_key, version),
                    UNIQUE(task_id)
                )
            """)
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_lineage_snapshots_group "
                "ON lineage_snapshots(lineage_key, version DESC)")

    @staticmethod
    def _row_to_payload(row: sqlite3.Row) -> Dict[str, Any]:
        """解析单条快照记录，JSON 损坏或版本不兼容时上抛专用异常。"""
        raw = row["payload_json"]
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise LineageSnapshotError(
                "血缘快照数据损坏，无法解析 JSON: %s" % exc) from exc
        validate_snapshot_payload(payload)
        return payload

    @staticmethod
    def _row_meta(row: sqlite3.Row) -> Dict[str, Any]:
        """提取不包含快照体的审计元数据。"""
        return {
            "snapshot_id": row["snapshot_id"],
            "lineage_key": row["lineage_key"],
            "version": int(row["version"]),
            "task_id": row["task_id"],
            "packet_name": row["packet_name"],
            "created_at": row["created_at"],
            "protected": bool(row["protected"]),
        }

    def save_snapshot(self, payload: Dict[str, Any], *,
                      protected: bool = False) -> Dict[str, Any]:
        """写入当前版本快照并执行保留清理，返回新快照元数据。

        Raises:
            LineageSnapshotError: 快照结构校验不通过。
        """
        validate_snapshot_payload(payload)
        lineage_key = str(payload.get("lineage_key") or DEFAULT_LINEAGE_KEY)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS max_version "
                "FROM lineage_snapshots WHERE lineage_key = ?",
                (lineage_key,)).fetchone()
            version = int(row["max_version"]) + 1
            snapshot_id = uuid.uuid4().hex
            meta = {
                "snapshot_id": snapshot_id,
                "lineage_key": lineage_key,
                "version": version,
                "task_id": str(payload.get("task_id") or snapshot_id),
                "packet_name": str(payload.get("packet_name") or ""),
                "created_at": str(payload.get("created_at") or ""),
                "protected": bool(protected),
            }
            connection.execute(
                "INSERT INTO lineage_snapshots "
                "(snapshot_id, lineage_key, version, task_id, packet_name, "
                "created_at, protected, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (snapshot_id, lineage_key, version, meta["task_id"],
                 meta["packet_name"], meta["created_at"],
                 1 if protected else 0,
                 json.dumps(payload, ensure_ascii=False, default=str)))
            self._prune(connection, lineage_key)
        return meta

    def _prune(self, connection: sqlite3.Connection, lineage_key: str) -> None:
        """同事务内清理超出保留数量的最旧非保护快照；保护快照不受影响。"""
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM lineage_snapshots "
            "WHERE lineage_key = ? AND protected = 0", (lineage_key,)).fetchone()
        overflow = int(row["total"]) - self.max_versions
        if overflow <= 0:
            return
        connection.execute(
            "DELETE FROM lineage_snapshots WHERE rowid IN ("
            "  SELECT rowid FROM lineage_snapshots "
            "  WHERE lineage_key = ? AND protected = 0 "
            "  ORDER BY version ASC LIMIT ?)",
            (lineage_key, overflow))

    def get_latest_snapshot(self, lineage_key: str
                            ) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """读取该业务契约最新快照，无历史时返回 None。

        Raises:
            LineageSnapshotError: 最新快照数据损坏或版本不兼容。
        """
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM lineage_snapshots WHERE lineage_key = ? "
                "ORDER BY version DESC LIMIT 1", (lineage_key,)).fetchone()
        if row is None:
            return None
        payload = self._row_to_payload(row)
        return payload, self._row_meta(row)

    def list_snapshots(self, lineage_key: str) -> List[Dict[str, Any]]:
        """按版本倒序返回该业务契约的全部快照元数据（不含快照体）。"""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT snapshot_id, lineage_key, version, task_id, packet_name, "
                "created_at, protected FROM lineage_snapshots "
                "WHERE lineage_key = ? ORDER BY version DESC",
                (lineage_key,)).fetchall()
        return [self._row_meta(row) for row in rows]

    def snapshot_count(self, lineage_key: str,
                       include_protected: bool = True) -> int:
        """统计该业务契约现存快照数量，供保留策略测试与页面展示使用。"""
        sql = "SELECT COUNT(*) AS total FROM lineage_snapshots WHERE lineage_key = ?"
        params: List[Any] = [lineage_key]
        if not include_protected:
            sql += " AND protected = 0"
        with self._connection() as connection:
            row = connection.execute(sql, params).fetchone()
        return int(row["total"])

    def set_protected(self, snapshot_id: str, protected: bool) -> bool:
        """标记或取消保护快照，返回是否命中记录。"""
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE lineage_snapshots SET protected = ? WHERE snapshot_id = ?",
                (1 if protected else 0, snapshot_id))
            return cursor.rowcount > 0
