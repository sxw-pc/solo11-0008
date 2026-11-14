"""批量校验端到端集成测试。

覆盖：批量提交与单包逐个提交的结果一致性、并发执行下的临时资源回收、
Web 批量提交路由、逐包优先级与调度开关。
"""

from pathlib import Path
import time

import pytest

from gateway.app import create_app
from gateway.batch import BatchScheduler, JobStatus, Priority
from gateway.config import AppConfig
from gateway.pipeline import run_validation
from gateway.store.sqlite_store import SQLiteStore

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
VALID = FIXTURES / "valid_packets"
INVALID = FIXTURES / "invalid_packets"

# 覆盖通过与失败两类结果、zip 与 tar.gz 两种格式、安全拦截场景。
PACKETS = [
    VALID / "retail_valid_a.zip",
    VALID / "retail_valid_c.tar.gz",
    INVALID / "hash_tampered" / "hash_tampered.zip",
    INVALID / "schema_mismatch" / "schema_mismatch.zip",
    INVALID / "path_traversal" / "path_traversal.zip",
]
PRIORITIES = [Priority.LOW, Priority.HIGH, Priority.NORMAL,
              Priority.LOW, Priority.HIGH]


def _scrub(value, config):
    """把文本中的机器相关路径替换为占位符，保证结果可比较。"""
    return (str(value)
            .replace(str(config.temp_dir), "<TMP>")
            .replace(str(config.workspace_dir), "<WS>"))


def normalize_results(results, config):
    """提取校验结果中与执行环境无关的部分用于一致性比较。"""
    normalized = []
    for item in results:
        errors = [{key: _scrub(val, config) for key, val in error.items()}
                  for error in item.get("errors", [])]
        samples = _scrub(item.get("samples", []), config)
        normalized.append({
            "key": item.get("key"),
            "passed": bool(item.get("passed")),
            "summary": _scrub(item.get("summary", ""), config),
            "errors": errors,
            "samples": samples,
        })
    return normalized


def wait_all_terminal(queue, timeout=60.0):
    """等待队列中不再有任何排队/运行中的任务。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if queue.count_active() == 0:
            return
        time.sleep(0.1)
    raise AssertionError("批量队列未在超时内清空")


def test_batch_results_match_sequential_submission(config, store):
    """批量并发执行的校验结果与单包逐个提交完全一致。"""
    baseline = {}
    for packet in PACKETS:
        outcome = run_validation(packet, packet.name, config, store)
        baseline[packet.name] = {
            "status": outcome["task"]["status"],
            "sha256": outcome["task"]["packet_sha256"],
            "results": normalize_results(outcome["results"], config),
        }
    scheduler = BatchScheduler(config, store)
    scheduler.start()
    try:
        items = [{"packet_path": packet, "packet_name": packet.name,
                  "priority": PRIORITIES[index]}
                 for index, packet in enumerate(PACKETS)]
        scheduler.submit_batch(items)
        wait_all_terminal(scheduler.queue_store)
    finally:
        scheduler.stop()
    jobs = scheduler.queue_store.list_jobs(limit=50)
    assert len(jobs) == len(PACKETS)
    by_name = {job.packet_name: job for job in jobs}
    for packet in PACKETS:
        job = by_name[packet.name]
        expected = baseline[packet.name]
        expected_status = (JobStatus.DONE if expected["status"] == "passed"
                           else JobStatus.FAILED)
        assert job.status == expected_status, packet.name
        task = store.get_task(job.task_id)
        assert task["status"] == expected["status"], packet.name
        assert task["packet_sha256"] == expected["sha256"]
        assert (normalize_results(task["result"]["results"], config)
                == expected["results"]), packet.name
    # 异常与失败任务的临时资源全部释放，无残留文件堆积。
    assert list(config.temp_dir.iterdir()) == []
    assert list(config.batch_upload_dir.iterdir()) == []


def test_batch_isolation_between_tasks(config, store):
    """并发任务的报告、日志与记录相互独立，一一对应。"""
    scheduler = BatchScheduler(config, store)
    scheduler.start()
    try:
        packets = sorted(VALID.iterdir())
        scheduler.submit_batch(
            [{"packet_path": p, "packet_name": p.name,
              "priority": Priority.NORMAL} for p in packets])
        wait_all_terminal(scheduler.queue_store)
    finally:
        scheduler.stop()
    jobs = scheduler.queue_store.list_jobs(limit=10)
    assert len(jobs) == len(packets)
    report_paths = set()
    log_paths = set()
    for job in jobs:
        task = store.get_task(job.task_id)
        assert task["task_id"] == job.job_id
        assert task["packet_name"] == job.packet_name
        assert task["status"] == "passed"
        assert task["report_html"] and task["log_path"]
        report_paths.add(task["report_html"])
        log_paths.add(task["log_path"])
    # 每个任务的报告与日志文件互不共享。
    assert len(report_paths) == len(packets)
    assert len(log_paths) == len(packets)


@pytest.fixture
def client(config):
    """提供测试客户端，并在用例结束后停止后台调度器。"""
    app = create_app(config)
    yield app.test_client()
    scheduler = app.extensions.get("gateway_scheduler")
    if scheduler is not None:
        scheduler.stop()


def _wait_web_queue_empty(client, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get("/batch/api/status").get_json()
        if not data["queued"] and not data["running"]:
            return data
        time.sleep(0.2)
    raise AssertionError("批量队列未在超时内清空")


def test_batch_page_renders(client):
    response = client.get("/batch")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "批量优先级校验" in text
    assert 'name="packets"' in text
    assert "执行队列" in text
    assert "http://" not in text.replace("http://127.0.0.1", "")


def test_batch_web_submission_end_to_end(client, config, store):
    packets = [VALID / "retail_valid_a.zip", VALID / "retail_valid_b.zip"]
    handles = [packet.open("rb") for packet in packets]
    try:
        response = client.post("/batch", data={
            "packets": [(handles[0], packets[0].name),
                        (handles[1], packets[1].name)],
            "priority": str(Priority.HIGH),
            "preset": "trade",
        }, content_type="multipart/form-data")
    finally:
        for handle in handles:
            handle.close()
    assert response.status_code == 302
    data = _wait_web_queue_empty(client)
    assert len(data["recent"]) == 2
    for job in data["recent"]:
        assert job["status"] == "done"
        assert job["priority"] == Priority.HIGH
        task = store.get_task(job["task_id"])
        assert task["status"] == "passed"
        report = client.get("/tasks/%s/report/html" % job["task_id"])
        assert report.status_code == 200
        report.close()
    assert list(config.temp_dir.iterdir()) == []
    assert list(config.batch_upload_dir.iterdir()) == []


def test_batch_web_per_packet_priorities(client, store):
    packets = [VALID / "retail_valid_a.zip", VALID / "retail_valid_b.zip"]
    handles = [packet.open("rb") for packet in packets]
    try:
        response = client.post("/batch", data={
            "packets": [(handles[0], packets[0].name),
                        (handles[1], packets[1].name)],
            "priority": str(Priority.NORMAL),
            "priorities": "9, 1",
            "preset": "trade",
        }, content_type="multipart/form-data")
    finally:
        for handle in handles:
            handle.close()
    assert response.status_code == 302
    _wait_web_queue_empty(client)
    from gateway.batch import BatchQueueStore
    queue = BatchQueueStore(store.db_path)
    jobs = sorted(queue.list_jobs(limit=10), key=lambda job: job.packet_name)
    assert [job.priority for job in jobs] == [9, 1]
    assert all(job.status == JobStatus.DONE for job in jobs)


def test_batch_web_per_packet_priority_gap_falls_back(client, store):
    """逐包优先级列表中的空段与缺省项回落到整批优先级。"""
    packets = [VALID / "retail_valid_a.zip", VALID / "retail_valid_b.zip",
               VALID / "retail_valid_c.tar.gz"]
    handles = [packet.open("rb") for packet in packets]
    try:
        response = client.post("/batch", data={
            "packets": [(handles[0], packets[0].name),
                        (handles[1], packets[1].name),
                        (handles[2], packets[2].name)],
            "priority": str(Priority.LOW),
            "priorities": "1,,9",
            "preset": "trade",
        }, content_type="multipart/form-data")
    finally:
        for handle in handles:
            handle.close()
    assert response.status_code == 302
    _wait_web_queue_empty(client)
    from gateway.batch import BatchQueueStore
    queue = BatchQueueStore(store.db_path)
    jobs = sorted(queue.list_jobs(limit=10), key=lambda job: job.packet_name)
    assert [job.priority for job in jobs] == [1, Priority.LOW, 9]


def test_batch_web_invalid_packet_fails_and_cleans_up(client, config):
    corrupt = INVALID / "path_traversal" / "path_traversal.zip"
    with corrupt.open("rb") as handle:
        response = client.post("/batch", data={
            "packets": [(handle, corrupt.name)],
            "preset": "trade",
        }, content_type="multipart/form-data")
    assert response.status_code == 302
    data = _wait_web_queue_empty(client)
    assert len(data["recent"]) == 1
    job = data["recent"][0]
    assert job["status"] == "failed"
    assert list(config.temp_dir.iterdir()) == []
    assert list(config.batch_upload_dir.iterdir()) == []


def test_batch_web_empty_submission_rejected(client):
    response = client.post("/batch", data={}, follow_redirects=True)
    assert response.status_code == 200
    assert "请选择至少一个" in response.get_data(as_text=True)


def test_batch_web_custom_contract_and_lineage(client, store):
    """批量提交支持整批自定义契约与血缘规则文件。"""
    packet = VALID / "retail_valid_b.zip"
    contract = FIXTURES / "mock_contract" / "product_contract.yaml"
    lineage = FIXTURES / "mock_lineage" / "product_lineage_rule.yaml"
    with packet.open("rb") as packet_handle, \
            contract.open("rb") as contract_handle, \
            lineage.open("rb") as lineage_handle:
        response = client.post("/batch", data={
            "packets": [(packet_handle, packet.name)],
            "contract": (contract_handle, contract.name),
            "lineage": (lineage_handle, lineage.name),
            "preset": "trade",
        }, content_type="multipart/form-data")
    assert response.status_code == 302
    data = _wait_web_queue_empty(client)
    assert len(data["recent"]) == 1
    job = data["recent"][0]
    assert job["status"] == "done"
    task = store.get_task(job["task_id"])
    # 批次共享文件以固定名暂存（与单包上传时随机命名行为一致，均为暂存副本名）。
    assert task["contract_name"] == "contract.yaml"
    assert task["lineage_name"] == "lineage.yaml"


def test_batch_web_queue_full_flash(config, monkeypatch):
    """队列容量满时页面提示而非报错崩溃。"""
    from gateway.batch import QueueFullError
    app = create_app(config)
    scheduler = app.extensions["gateway_scheduler"]

    def full(*args, **kwargs):
        raise QueueFullError("排队任务数已达上限 1，请等待部分任务完成后再提交")

    monkeypatch.setattr(scheduler, "submit_batch", full)
    try:
        client = app.test_client()
        with (VALID / "retail_valid_a.zip").open("rb") as handle:
            response = client.post(
                "/batch", data={"packets": [(handle, "a.zip")]},
                follow_redirects=True)
        assert response.status_code == 200
        assert "已达上限" in response.get_data(as_text=True)
    finally:
        scheduler.stop()


def test_batch_web_unexpected_error_flash(config, monkeypatch):
    """批量提交出现未知异常时页面给出友好提示。"""
    app = create_app(config)
    scheduler = app.extensions["gateway_scheduler"]

    def boom(*args, **kwargs):
        raise RuntimeError("模拟存储故障")

    monkeypatch.setattr(scheduler, "submit_batch", boom)
    try:
        client = app.test_client()
        with (VALID / "retail_valid_a.zip").open("rb") as handle:
            response = client.post(
                "/batch", data={"packets": [(handle, "a.zip")]},
                follow_redirects=True)
        assert response.status_code == 200
        assert "批量提交失败" in response.get_data(as_text=True)
    finally:
        scheduler.stop()


def test_batch_disabled_returns_404(tmp_path):
    config = AppConfig(workspace_dir=tmp_path / "workspace",
                       batch_enabled=False)
    app = create_app(config)
    client = app.test_client()
    assert client.get("/batch").status_code == 404
    assert client.get("/batch/api/status").status_code == 404
    # 单包提交与首页不受批量开关影响。
    assert client.get("/").status_code == 200
