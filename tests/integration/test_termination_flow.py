"""运行中任务终止流程集成测试。

覆盖：解压阶段终止、血缘校验阶段终止、报告阶段终止竞争、多任务并发终止、
单任务并发终止请求、残留任务回收、历史任务兼容与 Web 终止端点。
"""

import hashlib
import json
import sqlite3
import threading
import time
import zipfile
from pathlib import Path

from gateway.app import create_app
from gateway.pipeline import run_validation
from gateway.termination import (TaskTerminated, TerminationRegistry,
                                 TerminationToken, terminate_task)

ROOT = Path(__file__).resolve().parents[2]
VALID_PACKET = ROOT / "fixtures" / "valid_packets" / "retail_valid_a.zip"


def _make_big_packet(path: Path, rows: int = 600000) -> Path:
    """生成结构合法但体积较大的数据包，拉长解压阶段便于终止测试。"""
    lines = ["user_id,user_name,region,age,email,signup_date"]
    lines.extend(
        "U%06d,Mock%d,north,%d,u%d@mock.local,2024-01-05" % (i, i, 20 + i % 40, i)
        for i in range(rows))
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    manifest = (
        "schema_version: '1.0'\n"
        "packet: {name: big_test}\n"
        "tables:\n  users: {path: data/users.csv, format: csv}\n"
        "files:\n  data/users.csv: {md5: '%s', sha256: '%s'}\n"
        % (hashlib.md5(payload).hexdigest(), hashlib.sha256(payload).hexdigest()))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.yaml", manifest)
        archive.writestr("data/users.csv", payload)
    return path


class StageTripToken:
    """测试令牌：在指定阶段边界武装终止标志，由阶段内部检查点触发终止。"""

    def __init__(self, arm_at: str):
        self.arm_at = arm_at
        self.armed = False
        self.current_stage = ""

    def check(self, stage: str) -> None:
        self.current_stage = stage
        if stage == self.arm_at:
            self.armed = True
            return
        if self.armed:
            raise TaskTerminated(stage)

    def is_requested(self) -> bool:
        return self.armed


def _running_task(task_id: str, **extra) -> dict:
    task = {
        "task_id": task_id, "packet_name": task_id + ".zip",
        "uploaded_at": "2026-01-01T10:00:00", "packet_size": 128,
        "status": "running", "passed": False, "result_json": "{}",
    }
    task.update(extra)
    return task


def test_terminate_during_archive_stage(config, store, tmp_path):
    """解压阶段终止：任务停在 archive 阶段，资源完整回收，报告标注阶段。"""
    packet = _make_big_packet(tmp_path / "big.zip")
    token = StageTripToken("archive")
    outcome = run_validation(packet, packet.name, config, store,
                             task_id="term-archive-1", termination_token=token)
    task = outcome["task"]
    assert task["status"] == "terminated"
    assert task["terminated_stage"] == "archive"
    assert not task["passed"]
    keys = [item["key"] for item in outcome["results"]]
    assert keys == ["terminated"]
    stored = store.get_task("term-archive-1")
    assert stored["status"] == "terminated"
    assert stored["terminated_stage"] == "archive"
    assert stored["finished_at"]
    # 上传包、解压目录等临时资源无残留
    assert not list(config.temp_dir.iterdir())
    # 部分报告三格式齐备且标注终止阶段
    for fmt in ("md", "html", "json"):
        assert Path(outcome["report_paths"][fmt]).is_file()
    markdown = Path(outcome["report_paths"]["md"]).read_text(encoding="utf-8")
    assert "终止说明" in markdown
    assert "压缩包安全检查与解压" in markdown
    assert "不可作为准入依据" in markdown
    html = Path(outcome["report_paths"]["html"]).read_text(encoding="utf-8")
    assert "已终止" in html and "终止说明" in html
    report = json.loads(Path(outcome["report_paths"]["json"]).read_text(encoding="utf-8"))
    assert report["termination"]["stage"] == "archive"
    assert report["termination"]["stage_label"] == "压缩包安全检查与解压"
    assert any(item["key"] == "terminated" for item in stored["result"]["results"])
    # 日志记录终止信息
    log_text = (config.workspace_dir / stored["log_path"]).read_text(encoding="utf-8")
    assert "终止" in log_text


def test_terminate_during_lineage_stage(config, store):
    """血缘校验阶段终止：已完成阶段结果保留，血缘及后续阶段不执行。"""
    token = StageTripToken("lineage")
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store,
                             task_id="term-lineage-1", termination_token=token)
    task = outcome["task"]
    assert task["status"] == "terminated"
    assert task["terminated_stage"] == "lineage"
    keys = [item["key"] for item in outcome["results"]]
    assert "archive" in keys and "hash" in keys and "schema" in keys
    assert "lineage" not in keys  # 血缘阶段被终止，未产出校验结果
    assert "anomaly" not in keys
    assert keys[-1] == "terminated"
    stored = store.get_task("term-lineage-1")
    assert stored["status"] == "terminated"
    assert stored["terminated_stage"] == "lineage"
    assert not list(config.temp_dir.iterdir())
    report = json.loads(Path(outcome["report_paths"]["json"]).read_text(encoding="utf-8"))
    assert report["termination"]["stage"] == "lineage"
    assert report["termination"]["stage_label"] == "跨表血缘一致性校验"


def test_terminate_during_table_read_stage(config, store):
    """表读取阶段终止：逐表检查终止标志，已完成的解压与哈希结果保留。"""
    token = StageTripToken("table_read")
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store,
                             task_id="term-read-1", termination_token=token)
    task = outcome["task"]
    assert task["status"] == "terminated"
    assert task["terminated_stage"] == "table_read"
    keys = [item["key"] for item in outcome["results"]]
    assert "archive" in keys and "hash" in keys
    assert "schema" not in keys and "lineage" not in keys
    assert keys[-1] == "terminated"
    assert not list(config.temp_dir.iterdir())


def test_pre_requested_termination_stops_before_extraction(config, store):
    """终止请求先于流水线启动：首个检查点即停止，不创建解压目录。"""
    token = TerminationToken("term-pre-1")
    token.request()
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store,
                             task_id="term-pre-1", termination_token=token)
    assert outcome["task"]["status"] == "terminated"
    assert outcome["task"]["terminated_stage"] == "archive"
    assert not list(config.temp_dir.iterdir())
    assert store.get_task("term-pre-1")["status"] == "terminated"


def test_termination_request_during_finalize_wins_race(config, store):
    """报告阶段到达的终止请求优先于正常完成写入（CAS 竞争）。"""

    class TerminateAtReportToken:
        """在报告阶段检查点模拟并发终止请求落库。"""

        def __init__(self):
            self.current_stage = ""

        def check(self, stage):
            self.current_stage = stage
            if stage == "report":
                store.request_terminate("term-report-1", "2026-01-01T00:00:00")

        def is_requested(self):
            return False

    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store,
                             task_id="term-report-1",
                             termination_token=TerminateAtReportToken())
    task = outcome["task"]
    assert task["status"] == "terminated"
    assert task["terminated_stage"] == "report"
    stored = store.get_task("term-report-1")
    assert stored["status"] == "terminated"
    assert stored["terminated_stage"] == "report"
    assert stored["terminate_requested_at"] == "2026-01-01T00:00:00"
    report = json.loads(Path(outcome["report_paths"]["json"]).read_text(encoding="utf-8"))
    assert report["termination"]["stage"] == "report"
    assert not list(config.temp_dir.iterdir())


def test_concurrent_termination_of_multiple_tasks(config, store, tmp_path):
    """多任务并发终止：互不影响、无卡死状态、库完整、资源无残留。"""
    registry = TerminationRegistry()
    packet = _make_big_packet(tmp_path / "big.zip")
    victim_ids = ["term-multi-%d" % index for index in range(4)]
    keep_id = "term-multi-keep"
    outcomes = {}
    errors = {}

    def worker(task_id, packet_path):
        try:
            outcomes[task_id] = run_validation(
                packet_path, packet_path.name, config, store,
                task_id=task_id, termination_registry=registry)
        except Exception as exc:  # pragma: no cover - 失败时记录
            errors[task_id] = exc

    threads = [threading.Thread(target=worker, args=(task_id, packet))
               for task_id in victim_ids]
    keep_thread = threading.Thread(target=worker, args=(keep_id, VALID_PACKET))
    for thread in threads + [keep_thread]:
        thread.start()
    deadline = time.time() + 15
    while time.time() < deadline:
        if all(registry.is_registered(task_id) for task_id in victim_ids):
            break
        time.sleep(0.005)
    replies = []

    def stop(task_id):
        replies.append(terminate_task(task_id, store, config, registry))

    stoppers = [threading.Thread(target=stop, args=(task_id,))
                for task_id in victim_ids]
    for thread in stoppers:
        thread.start()
    for thread in stoppers:
        thread.join()
    for thread in threads + [keep_thread]:
        thread.join()

    assert not errors
    assert all(reply["ok"] for reply in replies)
    for task_id in victim_ids:
        stored = store.get_task(task_id)
        assert stored["status"] == "terminated", (task_id, stored["status"])
        assert stored["terminated_stage"]
        assert stored["report_md"] and stored["report_json"]
    # 未被终止的并行任务正常通过，不受干扰
    assert outcomes[keep_id]["task"]["status"] == "passed"
    assert store.get_task(keep_id)["status"] == "passed"
    # 无卡在 running/terminating 的任务
    assert store.list_tasks(status="running") == []
    # SQLite 索引与数据完整性未受破坏
    connection = sqlite3.connect(str(config.db_path))
    assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    indexes = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    connection.close()
    assert {"idx_tasks_time", "idx_tasks_status"} <= indexes
    # 全部任务的临时资源无残留
    assert not list(config.temp_dir.iterdir())


def test_concurrent_termination_requests_on_single_task(config, store, tmp_path):
    """同一任务的并发终止请求：恰好一次状态迁移，其余幂等返回。"""
    registry = TerminationRegistry()
    packet = _make_big_packet(tmp_path / "big.zip")
    outcome = {}

    def worker():
        outcome["result"] = run_validation(
            packet, packet.name, config, store,
            task_id="term-single-1", termination_registry=registry)

    thread = threading.Thread(target=worker)
    thread.start()
    deadline = time.time() + 15
    while not registry.is_registered("term-single-1") and time.time() < deadline:
        time.sleep(0.005)
    replies = []

    def stop():
        replies.append(terminate_task("term-single-1", store, config, registry))

    stoppers = [threading.Thread(target=stop) for _ in range(8)]
    for stopper in stoppers:
        stopper.start()
    for stopper in stoppers:
        stopper.join()
    thread.join()

    assert all(reply["ok"] for reply in replies)
    assert {reply["reason"] for reply in replies} <= {
        "cooperative", "already_requested", "already_terminated"}
    stored = store.get_task("term-single-1")
    assert stored["status"] == "terminated"
    assert outcome["result"]["task"]["status"] == "terminated"
    connection = sqlite3.connect(str(config.db_path))
    assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    connection.close()
    assert not list(config.temp_dir.iterdir())


def test_orphan_running_task_is_reclaimed(config, store):
    """进程异常退出留下的残留运行中任务：直接回收并生成部分报告。"""
    store.create_task(_running_task("orphan-1"))
    leftover_extract = config.temp_dir / "gateway-orphan-1-abc"
    leftover_upload = config.temp_dir / "upload-orphan-1-def"
    leftover_extract.mkdir()
    (leftover_extract / "part.csv").write_text("x", encoding="utf-8")
    leftover_upload.mkdir()
    (leftover_upload / "pkt.zip").write_text("y", encoding="utf-8")
    other_task_dir = config.temp_dir / "gateway-other-999"
    other_task_dir.mkdir()

    outcome = terminate_task("orphan-1", store, config)
    assert outcome["ok"] and outcome["reason"] == "reclaimed"
    stored = store.get_task("orphan-1")
    assert stored["status"] == "terminated"
    assert stored["terminated_stage"] == "orphan"
    assert stored["report_md"] and stored["report_html"] and stored["report_json"]
    report_path = config.workspace_dir / stored["report_json"]
    assert report_path.is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["termination"]["stage"] == "orphan"
    assert any(item["key"] == "terminated"
               for item in stored["result"]["results"])
    # 残留资源被回收，其他任务目录不受影响
    assert not leftover_extract.exists()
    assert not leftover_upload.exists()
    assert other_task_dir.exists()
    # 重复终止幂等返回，不做任何修改
    again = terminate_task("orphan-1", store, config)
    assert again["ok"] and again["reason"] == "already_terminated"
    assert store.get_task("orphan-1")["status"] == "terminated"


def test_terminating_orphan_is_finalized(config, store):
    """状态卡在 terminating 的残留任务同样被回收收尾。"""
    store.create_task(_running_task(
        "orphan-2", status="terminating",
        terminate_requested_at="2026-01-01T10:01:00"))
    outcome = terminate_task("orphan-2", store, config)
    assert outcome["ok"] and outcome["reason"] == "reclaimed"
    stored = store.get_task("orphan-2")
    assert stored["status"] == "terminated"
    assert stored["terminate_requested_at"] == "2026-01-01T10:01:00"


def test_finished_tasks_are_never_modified(config, store):
    """历史已完成/失败/异常任务拒绝终止；已终止任务幂等；数据均不变。"""
    protected = [("hist-passed", "passed"), ("hist-failed", "failed"),
                 ("hist-error", "error")]
    store.create_task(_running_task(
        "hist-terminated", status="terminated",
        report_md="reports/hist-terminated.md",
        result_json={"results": [{"key": "terminated", "passed": False}]}))
    for task_id, status in protected:
        store.create_task(_running_task(
            task_id, status=status, passed=status == "passed",
            report_md="reports/%s.md" % task_id,
            result_json={"results": [{"key": "archive", "passed": True}]}))
    for task_id, status in protected:
        before = store.get_task(task_id)
        outcome = terminate_task(task_id, store, config)
        assert not outcome["ok"]
        assert outcome["reason"] == "already_finished"
        after = store.get_task(task_id)
        assert after == before
        assert after["status"] == status
        assert after["report_md"] == "reports/%s.md" % task_id
    # 已终止任务：幂等成功且数据不变
    before = store.get_task("hist-terminated")
    outcome = terminate_task("hist-terminated", store, config)
    assert outcome["ok"] and outcome["reason"] == "already_terminated"
    assert store.get_task("hist-terminated") == before
    assert terminate_task("missing-id", store, config)["reason"] == "not_found"


def test_web_terminate_live_running_task(config, tmp_path):
    """端到端：上传校验执行期间，运维通过终止接口停止该运行中任务。"""
    app = create_app(config)
    uploader = app.test_client()
    operator = app.test_client()
    store = app.extensions["gateway_store"]
    packet = _make_big_packet(tmp_path / "big.zip")
    holder = {}

    def upload():
        with packet.open("rb") as handle:
            holder["response"] = uploader.post("/", data={
                "packet": (handle, packet.name), "preset": "trade",
            }, content_type="multipart/form-data")

    thread = threading.Thread(target=upload)
    thread.start()
    task_id = None
    deadline = time.time() + 15
    while time.time() < deadline:
        running = store.list_tasks(status="running")
        if running:
            task_id = running[0]["task_id"]
            break
        time.sleep(0.005)
    assert task_id, "上传请求未产生运行中任务"
    stop_response = operator.post("/tasks/%s/terminate" % task_id)
    assert stop_response.status_code == 302
    thread.join()
    assert holder["response"].status_code == 302
    stored = store.get_task(task_id)
    assert stored["status"] == "terminated"
    assert stored["terminated_stage"]
    assert stored["report_md"] and stored["report_json"]
    # 上传临时目录与解压缓存均已回收
    assert not list(config.temp_dir.iterdir())
    # 详情页可正常打开并展示终止信息
    detail = operator.get("/tasks/%s" % task_id)
    assert detail.status_code == 200
    assert "已终止" in detail.get_data(as_text=True)


def test_web_terminate_endpoint_and_filters(config):
    """Web 终止端点、详情页展示、列表筛选与删除兼容。"""
    app = create_app(config)
    client = app.test_client()
    store = app.extensions["gateway_store"]
    store.create_task(_running_task("web-term-1"))

    response = client.post("/tasks/web-term-1/terminate")
    assert response.status_code == 302
    stored = store.get_task("web-term-1")
    assert stored["status"] == "terminated"
    detail = client.get("/tasks/web-term-1")
    assert detail.status_code == 200
    text = detail.get_data(as_text=True)
    assert "已终止" in text and "部分报告" in text
    # 部分报告可下载
    report = client.get("/tasks/web-term-1/report/json")
    assert report.status_code == 200
    assert b"termination" in report.data
    report.close()
    # 列表筛选与已终止标识
    listing = client.get("/tasks?status=terminated")
    assert listing.status_code == 200
    listing_text = listing.get_data(as_text=True)
    assert "web-term-1" in listing_text and "已终止" in listing_text
    # 已完成任务拒绝终止
    store.create_task(_running_task("web-done-1", status="passed", passed=True))
    client.post("/tasks/web-done-1/terminate")
    assert store.get_task("web-done-1")["status"] == "passed"
    # 不存在的任务
    missing = client.post("/tasks/web-missing/terminate", follow_redirects=True)
    assert missing.status_code == 200
    # 已终止任务可正常删除（历史任务删除功能不受影响）
    deleted = client.post("/tasks/web-term-1/delete", follow_redirects=True)
    assert deleted.status_code == 200
    assert store.get_task("web-term-1") is None
