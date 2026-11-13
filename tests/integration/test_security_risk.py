"""安全风险拦截与离线运行集成测试。"""

import ast
from pathlib import Path
import socket
import threading
import shutil

from gateway.app import create_app, _sweep_stale_temp_dirs
from gateway.config import PROJECT_ROOT, AppConfig
from gateway.pipeline import run_validation
from gateway.store.sqlite_store import SQLiteStore

ROOT = Path(__file__).resolve().parents[2]
VALID_PACKET = ROOT / "fixtures" / "valid_packets" / "retail_valid_a.zip"
TRAVERSAL = ROOT / "fixtures" / "invalid_packets" / "path_traversal" / "path_traversal.zip"
BOMB = ROOT / "fixtures" / "invalid_packets" / "zip_bomb" / "zip_bomb.zip"
REDUNDANT = ROOT / "fixtures" / "invalid_packets" / "redundant_file" / "redundant_file.zip"


def test_path_traversal_cannot_escape_workspace(config, store):
    outcome = run_validation(TRAVERSAL, TRAVERSAL.name, config, store)
    assert outcome["task"]["status"] == "failed"
    assert not list(config.temp_dir.iterdir())
    assert not list(config.workspace_dir.rglob("escape.txt"))
    assert not (config.workspace_dir.parent / "escape.txt").exists()


def test_zip_bomb_is_rejected_without_extraction(config, store):
    outcome = run_validation(BOMB, BOMB.name, config, store)
    archive = next(item for item in outcome["results"] if item["key"] == "archive")
    assert archive["errors"][0]["code"] == "zip_bomb"
    assert not list(config.temp_dir.iterdir())


def test_dangerous_executable_is_flagged(config, store):
    outcome = run_validation(REDUNDANT, REDUNDANT.name, config, store)
    hash_result = next(item for item in outcome["results"] if item["key"] == "hash")
    paths = {item["path"] for item in hash_result["errors"]
             if item["code"] == "dangerous_file"}
    assert paths == {"payload.exe"}
    assert outcome["task"]["status"] == "failed"


def test_pipeline_makes_no_network_connection(config, store, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("检测到网络连接尝试")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store)
    assert outcome["task"]["status"] == "passed"


def test_gateway_imports_no_network_clients():
    forbidden = {"requests", "urllib", "http", "ftplib", "smtplib",
                 "websocket", "aiohttp"}
    found = []
    for path in (PROJECT_ROOT / "gateway").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.append(node.module.split(".")[0])
    assert not (set(found) & forbidden)


def test_pages_have_no_external_resources(config):
    app = create_app(config)
    client = app.test_client()
    for url in ("/", "/tasks"):
        text = client.get(url).get_data(as_text=True)
        assert "http://" not in text and "https://" not in text
        assert "//cdn" not in text


def test_delete_cleans_report_and_log_files(config):
    store = SQLiteStore(config.db_path)
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store)
    task_id = outcome["task"]["task_id"]
    files = [Path(path) for path in outcome["report_paths"].values()]
    log_file = config.workspace_dir / outcome["task"]["log_path"]
    assert all(path.is_file() for path in files)
    assert log_file.is_file()
    app = create_app(config)
    response = app.test_client().post("/tasks/%s/delete" % task_id, follow_redirects=True)
    assert response.status_code == 200
    assert not any(path.exists() for path in files)
    assert not log_file.exists()
    assert store.get_task(task_id) is None


def test_small_packet_completes_quickly(config, store):
    import time
    started = time.perf_counter()
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store)
    elapsed = time.perf_counter() - started
    assert outcome["task"]["status"] == "passed"
    assert elapsed < 10


def test_delete_removes_all_associated_local_resources(config, store):
    """删除任务必须同时清理三类报告、日志，且不残留临时解压目录。"""
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store)
    task_id = outcome["task"]["task_id"]
    report_paths = [Path(p) for p in outcome["report_paths"].values()]
    log_path = config.workspace_dir / outcome["task"]["log_path"]
    assert all(path.is_file() for path in report_paths)
    assert log_path.is_file()
    # 正常流程结束后不应有临时目录残留
    assert not list(config.temp_dir.iterdir())

    app = create_app(AppConfig(workspace_dir=config.workspace_dir))
    response = app.test_client().post("/tasks/%s/delete" % task_id, follow_redirects=True)
    assert response.status_code == 200
    assert not any(path.exists() for path in report_paths)
    assert not log_path.exists()
    assert store.get_task(task_id) is None


def test_delete_is_idempotent_with_missing_files(config, store):
    """报告文件已被手工删除时，删除任务仍成功且不报错。"""
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store)
    task_id = outcome["task"]["task_id"]
    for path in outcome["report_paths"].values():
        Path(path).unlink()
    app = create_app(AppConfig(workspace_dir=config.workspace_dir))
    response = app.test_client().post("/tasks/%s/delete" % task_id, follow_redirects=True)
    assert response.status_code == 200
    assert store.get_task(task_id) is None


def test_stale_temp_dirs_are_swept_but_fresh_kept(config):
    """启动清扫只清理超龄残留，在途的新目录不受影响。"""
    import os
    import time
    stale = config.temp_dir / "gateway-stale-residue"
    stale.mkdir()
    old_time = time.time() - 48 * 3600
    os.utime(stale, (old_time, old_time))
    fresh = config.temp_dir / "gateway-running-task"
    fresh.mkdir()
    removed = _sweep_stale_temp_dirs(config.temp_dir)
    assert not stale.exists()
    assert fresh.exists()
    assert removed >= 1
    shutil.rmtree(fresh, ignore_errors=True)


def test_concurrent_submissions_have_isolated_reports(config, store):
    """重复/并发提交同名数据包，任务 ID 与报告必须完全隔离。"""
    outcomes = []
    errors = []

    def worker(index):
        try:
            packet = config.workspace_dir / ("submit_%d.zip" % index)
            shutil.copy(VALID_PACKET, packet)
            outcomes.append(run_validation(packet, "same-name.zip", config, store))
        except Exception as exc:  # pragma: no cover - 并发不应抛异常
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    assert len(outcomes) == 10
    task_ids = [item["task"]["task_id"] for item in outcomes]
    assert len(set(task_ids)) == 10
    for item in outcomes:
        task = item["task"]
        for key in ("report_md", "report_html", "report_json"):
            relative = task[key]
            assert task["task_id"] in relative
            assert (config.workspace_dir / relative).is_file()
    # 并发结束后临时目录全部回收
    assert not list(config.temp_dir.iterdir())
