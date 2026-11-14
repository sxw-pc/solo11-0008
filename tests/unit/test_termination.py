"""终止令牌、注册表、状态机迁移与资源回收的单元测试。"""

import sqlite3
import threading

import pytest

from gateway.cleanup import (extract_temp_prefix, reclaim_task_resources,
                             upload_temp_prefix, validate_task_id)
from gateway.parser.archive_loader import load_archive
from gateway.store.sqlite_store import SQLiteStore
from gateway.termination import (TaskTerminated, TerminationRegistry,
                                 TerminationToken, stage_label)
from gateway.validator.hash_verify import verify_hashes
from gateway.validator.lineage_check import validate_lineage


def _task(task_id="task1", name="mock.zip", **extra):
    task = {
        "task_id": task_id, "packet_name": name,
        "uploaded_at": "2024-03-01T10:00:00", "packet_size": 10,
        "status": "passed", "passed": True,
        "result_json": {"results": [{"key": "archive", "passed": True}]},
    }
    task.update(extra)
    return task


def test_stage_label_and_token_basics():
    assert stage_label("archive") == "压缩包安全检查与解压"
    assert stage_label("lineage") == "跨表血缘一致性校验"
    assert stage_label("unknown-stage") == "unknown-stage"
    token = TerminationToken("t1")
    assert not token.is_requested()
    token.check("archive")
    assert token.current_stage == "archive"
    token.request()
    assert token.is_requested()
    with pytest.raises(TaskTerminated) as exc:
        token.check("hash")
    assert exc.value.stage == "hash"
    assert "哈希" in str(exc.value)


def test_registry_lifecycle_and_concurrent_requests():
    registry = TerminationRegistry()
    token = registry.register("t1")
    assert registry.register("t1") is token
    assert registry.is_registered("t1")
    assert registry.active_task_ids() == ["t1"]
    errors = []

    def hammer():
        try:
            for _ in range(100):
                registry.request("t1")
                registry.get("t1")
                registry.is_registered("t1")
        except Exception as exc:  # pragma: no cover - 失败时记录
            errors.append(exc)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert token.is_requested()
    registry.unregister("t1")
    assert not registry.is_registered("t1")
    assert not registry.request("t1")
    registry.unregister("t1")  # 重复注销安全


def test_request_terminate_is_atomic_and_terminal_safe(store):
    store.create_task(_task("run1", status="running", passed=False))
    assert store.request_terminate("run1", "2026-01-01T00:00:00")
    row = store.get_task("run1")
    assert row["status"] == "terminating"
    assert row["terminate_requested_at"] == "2026-01-01T00:00:00"
    # 重复请求 CAS 失败，由服务层转为幂等语义
    assert not store.request_terminate("run1", "2026-01-02T00:00:00")
    assert row["terminate_requested_at"] == "2026-01-01T00:00:00"
    # 终态与不存在任务一律拒绝
    for tid, status in (("t-passed", "passed"), ("t-failed", "failed"),
                        ("t-error", "error"), ("t-term", "terminated")):
        store.create_task(_task(tid, status=status))
        assert not store.request_terminate(tid, "now")
        assert store.get_task(tid)["status"] == status
    assert not store.request_terminate("missing", "now")


def test_complete_and_finalize_conditional_updates(store):
    store.create_task(_task("c1", status="running", passed=False))
    assert store.complete_task("c1", status="passed", passed=True,
                               report_md="reports/c1.md")
    assert store.get_task("c1")["status"] == "passed"
    assert not store.complete_task("c1", status="failed")  # 已终态不可再写
    store.create_task(_task("c2", status="running", passed=False))
    assert store.request_terminate("c2", "now")
    assert not store.complete_task("c2", status="passed")  # 终止请求优先
    assert store.finalize_termination(
        "c2", terminated_stage="hash", result_json={"results": []})
    row = store.get_task("c2")
    assert row["status"] == "terminated"
    assert row["terminated_stage"] == "hash"
    assert row["result"] == {"results": []}
    assert not store.finalize_termination("c2", terminated_stage="x")  # 已终态
    # running 可直接被终止收尾（残留回收路径）
    store.create_task(_task("c3", status="running", passed=False))
    assert store.finalize_termination("c3", terminated_stage="orphan")
    assert store.get_task("c3")["status"] == "terminated"
    assert not store.complete_task("missing", status="passed")


def test_list_tasks_terminated_and_running_filters(store):
    store.create_task(_task("a", status="terminated",
                            uploaded_at="2024-01-01T10:00:00"))
    store.create_task(_task("b", status="terminating",
                            uploaded_at="2024-02-01T10:00:00"))
    store.create_task(_task("c", status="running",
                            uploaded_at="2024-03-01T10:00:00"))
    store.create_task(_task("d", status="passed",
                            uploaded_at="2024-04-01T10:00:00"))
    assert [t["task_id"] for t in store.list_tasks(status="terminated")] == ["a"]
    assert [t["task_id"] for t in store.list_tasks(status="running")] == ["c", "b"]
    assert [t["task_id"] for t in store.list_tasks(status="passed")] == ["d"]
    # 统计口径保持不变：terminated 仅计入总数
    assert store.stats() == {"total": 4, "passed": 1, "failed": 0}


def test_old_database_migrates_without_touching_history(tmp_path):
    """旧版库文件（无终止列）打开后自动迁移，历史行状态与报告关联不变。"""
    db_path = tmp_path / "data" / "gateway.db"
    db_path.parent.mkdir(parents=True)
    connection = sqlite3.connect(str(db_path))
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
        "INSERT INTO tasks (task_id, packet_name, uploaded_at, status, passed,"
        " report_md, result_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("old-passed", "old.zip", "2023-12-01T09:00:00", "passed", 1,
         "reports/old-passed.md", '{"results": [{"key": "archive"}]}'))
    connection.execute(
        "INSERT INTO tasks (task_id, packet_name, uploaded_at, status, passed)"
        " VALUES (?, ?, ?, ?, ?)",
        ("old-failed", "bad.zip", "2023-12-02T09:00:00", "failed", 0))
    connection.commit()
    connection.close()

    store = SQLiteStore(db_path)  # 触发迁移
    passed = store.get_task("old-passed")
    assert passed["status"] == "passed"
    assert passed["report_md"] == "reports/old-passed.md"
    assert passed["result"]["results"][0]["key"] == "archive"
    assert passed["terminated_stage"] == ""
    assert passed["terminate_requested_at"] == ""
    assert store.get_task("old-failed")["status"] == "failed"
    # 迁移后历史任务仍拒绝终止
    assert not store.request_terminate("old-passed", "now")
    assert store.get_task("old-passed")["status"] == "passed"
    # 索引与完整性不受影响
    connection = sqlite3.connect(str(db_path))
    assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    indexes = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    connection.close()
    assert {"idx_tasks_time", "idx_tasks_status"} <= indexes
    # 迁移幂等：再次打开不报错
    SQLiteStore(db_path)


def test_validate_task_id_and_prefixes():
    assert validate_task_id("abc-123_X") == "abc-123_X"
    assert upload_temp_prefix("t1") == "upload-t1-"
    assert extract_temp_prefix("t1") == "gateway-t1-"
    for bad in ("", "../x", "a/b", "a b", "a;b", "x*" ):
        with pytest.raises(ValueError):
            validate_task_id(bad)


def test_reclaim_task_resources_only_removes_own_task(config):
    keep = config.temp_dir / "gateway-other-123"
    keep.mkdir()
    (keep / "keep.txt").write_text("keep", encoding="utf-8")
    victims = []
    for prefix in ("gateway-task9-a", "gateway-task9-b", "upload-task9-c"):
        folder = config.temp_dir / prefix
        folder.mkdir()
        (folder / "payload.bin").write_bytes(b"x")
        victims.append(folder)
    stray_file = config.temp_dir / "upload-task9-loose.tmp"
    stray_file.write_text("x", encoding="utf-8")
    removed = reclaim_task_resources(config, "task9")
    assert len(removed) == 4
    for folder in victims:
        assert not folder.exists()
    assert not stray_file.exists()
    assert keep.exists()
    assert reclaim_task_resources(config, "task9") == []  # 幂等
    with pytest.raises(ValueError):
        reclaim_task_resources(config, "../escape")


def test_load_archive_stop_during_extraction(config, tmp_path):
    import hashlib
    import zipfile

    payload = b"user_id,user_name\n" + b"U1,Mock\n" * 200000
    digest = hashlib.md5(payload).hexdigest()
    manifest = ("schema_version: '1.0'\n"
                "tables:\n  users: {path: data/users.csv, format: csv}\n"
                "files:\n  data/users.csv: {md5: '%s'}\n" % digest)
    packet = tmp_path / "big.zip"
    with zipfile.ZipFile(packet, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.yaml", manifest)
        archive.writestr("data/users.csv", payload)
    calls = {"count": 0}

    def stop():
        calls["count"] += 1
        return calls["count"] > 2

    with pytest.raises(TaskTerminated) as exc:
        load_archive(packet, config, should_stop=stop, task_id="stopunit1")
    assert exc.value.stage == "archive"
    # 半成品解压目录已由 load_archive 清理
    assert not list(config.temp_dir.iterdir())


def test_verify_hashes_stop(config, tmp_path):
    root = tmp_path / "extract"
    root.mkdir()
    (root / "a.csv").write_text("x", encoding="utf-8")
    (root / "b.csv").write_text("y", encoding="utf-8")
    manifest = {"files": {"a.csv": {"md5": "0" * 32}, "b.csv": {"md5": "1" * 32}}}
    with pytest.raises(TaskTerminated) as exc:
        verify_hashes(root, manifest, config, should_stop=lambda: True)
    assert exc.value.stage == "hash"
    # 不注入 should_stop 时行为不变
    result = verify_hashes(root, manifest, config)
    assert not result["passed"]


def test_validate_lineage_stop(valid_users, valid_trades):
    rules = {"relations": [{
        "name": "trade_owner", "relationship": "many_to_one",
        "left": {"table": "trades", "field": "user_id"},
        "right": {"table": "users", "field": "user_id"},
    }]}
    tables = {"users": valid_users, "trades": valid_trades}
    with pytest.raises(TaskTerminated) as exc:
        validate_lineage(tables, rules, should_stop=lambda: True)
    assert exc.value.stage == "lineage"
    assert validate_lineage(tables, rules)["passed"]
