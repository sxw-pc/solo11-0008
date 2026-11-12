"""血缘快照存储与保留策略单元测试。"""

import json

import pytest

from gateway.store.lineage_snapshot_store import (DEFAULT_MAX_VERSIONS,
                                                  LineageSnapshotStore)
from gateway.validator.lineage_drift import LineageSnapshotError


def _payload(task_id="task1", lineage_key="domain_a", version=1, **tables):
    return {
        "snapshot_version": version, "lineage_key": lineage_key,
        "task_id": task_id, "packet_name": task_id + ".zip",
        "created_at": "2024-03-01T10:00:00", "lineage_passed": True,
        "tables": tables or {"users": {"fields": ["id"], "row_count": 1}},
        "relations": [],
    }


def test_init_creates_table_on_legacy_database(tmp_path):
    # 先构造一个不含快照表的旧库，模拟已归档历史任务数据库。
    import sqlite3
    db_path = tmp_path / "gateway.db"
    connection = sqlite3.connect(str(db_path))
    connection.execute("CREATE TABLE tasks (task_id TEXT PRIMARY KEY)")
    connection.execute("INSERT INTO tasks VALUES ('legacy-task')")
    connection.commit()
    connection.close()

    store = LineageSnapshotStore(db_path)
    assert store.get_latest_snapshot("domain_a") is None
    # 旧表与旧数据完全不受影响。
    connection = sqlite3.connect(str(db_path))
    row = connection.execute("SELECT task_id FROM tasks").fetchone()
    connection.close()
    assert row == ("legacy-task",)


def test_save_assigns_incrementing_versions_per_domain(tmp_path):
    store = LineageSnapshotStore(tmp_path / "gateway.db")
    meta1 = store.save_snapshot(_payload("t1", "domain_a"))
    meta2 = store.save_snapshot(_payload("t2", "domain_a"))
    meta_other = store.save_snapshot(_payload("t3", "domain_b"))
    assert (meta1["version"], meta2["version"]) == (1, 2)
    assert meta_other["version"] == 1
    assert meta1["protected"] is False
    payload, meta = store.get_latest_snapshot("domain_a")
    assert meta["version"] == 2
    assert payload["task_id"] == "t2"
    assert store.get_latest_snapshot("missing") is None


def test_list_and_count_snapshots(tmp_path):
    store = LineageSnapshotStore(tmp_path / "gateway.db")
    for index in range(3):
        store.save_snapshot(_payload("t%d" % index, "domain_a"))
    store.save_snapshot(_payload("b1", "domain_b"))
    metas = store.list_snapshots("domain_a")
    assert [meta["version"] for meta in metas] == [3, 2, 1]
    assert store.snapshot_count("domain_a") == 3
    assert store.snapshot_count("domain_a", include_protected=False) == 3
    assert store.snapshot_count("domain_b") == 1


def test_retention_prunes_oldest_non_protected(tmp_path):
    store = LineageSnapshotStore(tmp_path / "gateway.db", max_versions=3)
    first = store.save_snapshot(_payload("t1"))
    second = store.save_snapshot(_payload("t2"))
    assert store.set_protected(first["snapshot_id"], True)
    for index in range(3, 6):  # 再写 3 个非保护快照
        store.save_snapshot(_payload("t%d" % index))
    versions = [meta["version"] for meta in store.list_snapshots("domain_a")]
    # 保护的 v1 保留；非保护仅留最近 3 个（v3/v4/v5），v2 被清理。
    assert versions == [5, 4, 3, 1]
    assert store.snapshot_count("domain_a", include_protected=False) == 3
    assert not store.set_protected("not-exist", True)
    assert store.set_protected(second["snapshot_id"], False) is False


def test_max_versions_floored_to_one(tmp_path):
    store = LineageSnapshotStore(tmp_path / "gateway.db", max_versions=0)
    assert store.max_versions == 1
    store.save_snapshot(_payload("t1"))
    store.save_snapshot(_payload("t2"))
    assert store.snapshot_count("domain_a", include_protected=False) == 1


def test_save_rejects_invalid_payload(tmp_path):
    store = LineageSnapshotStore(tmp_path / "gateway.db")
    with pytest.raises(LineageSnapshotError, match="版本"):
        store.save_snapshot(_payload(version=99))


def test_get_latest_reports_json_corruption(tmp_path):
    store = LineageSnapshotStore(tmp_path / "gateway.db")
    store.save_snapshot(_payload("t1"))
    import sqlite3
    connection = sqlite3.connect(str(store.db_path))
    connection.execute("UPDATE lineage_snapshots SET payload_json = 'not-json'")
    connection.commit()
    connection.close()
    with pytest.raises(LineageSnapshotError, match="损坏"):
        store.get_latest_snapshot("domain_a")


def test_get_latest_reports_incompatible_version(tmp_path):
    store = LineageSnapshotStore(tmp_path / "gateway.db")
    store.save_snapshot(_payload("t1"))
    raw = json.dumps(_payload("t1"), ensure_ascii=False)
    tampered = raw.replace('"snapshot_version": 1', '"snapshot_version": 2')
    import sqlite3
    connection = sqlite3.connect(str(store.db_path))
    connection.execute("UPDATE lineage_snapshots SET payload_json = ?", (tampered,))
    connection.commit()
    connection.close()
    with pytest.raises(LineageSnapshotError, match="版本"):
        store.get_latest_snapshot("domain_a")


def test_reopen_database_persists_snapshots(tmp_path):
    db_path = tmp_path / "gateway.db"
    LineageSnapshotStore(db_path).save_snapshot(_payload("t1"))
    store = LineageSnapshotStore(db_path)
    payload, meta = store.get_latest_snapshot("domain_a")
    assert payload["tables"]["users"]["row_count"] == 1
    assert meta["task_id"] == "t1"


def test_default_retention_constant():
    assert DEFAULT_MAX_VERSIONS == 30


def test_pragma_unsupported_filesystem_falls_back(tmp_path, monkeypatch):
    import sqlite3

    class PragmaFailingConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if str(sql).startswith("PRAGMA"):
                raise sqlite3.DatabaseError("unsupported filesystem")
            return super().execute(sql, parameters)

    real_connect = sqlite3.connect

    def connect_with_factory(database, *args, **kwargs):
        kwargs.setdefault("factory", PragmaFailingConnection)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connect_with_factory)
    # pragma 异常被吞掉后，建表与读写仍可在默认日志模式下工作。
    store = LineageSnapshotStore(tmp_path / "gateway.db")
    meta = store.save_snapshot(_payload("t-fs"))
    payload, loaded = store.get_latest_snapshot("domain_a")
    assert loaded["snapshot_id"] == meta["snapshot_id"]
    assert payload["task_id"] == "t-fs"
