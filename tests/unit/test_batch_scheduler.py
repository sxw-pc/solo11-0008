"""批量优先级调度器行为测试。

使用注入的假执行器验证调度语义：并发上限、优先级插队、同优先级 FIFO、
资源阈值限流、异常任务资源回收与重启恢复，不依赖真实校验流水线。
"""

from pathlib import Path
import threading
import time

import pytest

from gateway.batch import (BatchScheduler, JobStatus, Priority, QueueFullError)
from gateway.config import AppConfig

TERMINAL = JobStatus.TERMINAL


def make_config(tmp_path, **overrides):
    """构造隔离工作目录的批量配置；磁盘余量阈值默认置零避免环境干扰。"""
    params = {"workspace_dir": tmp_path / "workspace",
              "batch_min_free_bytes": 0}
    params.update(overrides)
    return AppConfig(**params)


def make_packet(tmp_path, name, size=64):
    """生成指定大小的伪数据包（预估器对未知格式回退为文件大小）。"""
    path = tmp_path / name
    path.write_bytes(b"x" * size)
    return path


class FakeRunner:
    """记录调用顺序与并发峰值的假校验执行器。"""

    def __init__(self, delay=0.0, gate=None, fail_on=(), task_status="passed"):
        self.delay = delay
        self.gate = gate
        self.fail_on = tuple(fail_on)
        self.task_status = task_status
        self.calls = []
        self.peak = 0
        self._current = 0
        self._gated = False
        self._lock = threading.Lock()

    def __call__(self, job):
        with self._lock:
            self._current += 1
            self.peak = max(self.peak, self._current)
            self.calls.append(job.job_id)
            first = not self._gated
            self._gated = True
        try:
            if first and self.gate is not None:
                self.gate.wait(timeout=15)
            if self.delay:
                time.sleep(self.delay)
            if any(key in job.packet_name for key in self.fail_on):
                raise RuntimeError("模拟执行异常")
            return {"task": {"status": self.task_status, "task_id": job.job_id,
                             "error_summary": ""}}
        finally:
            with self._lock:
                self._current -= 1


def wait_for(predicate, timeout=15.0, interval=0.02):
    """轮询等待条件成立，超时返回 False。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def wait_terminal(queue, job_ids, timeout=15.0):
    """等待全部任务到达终态。"""
    ok = wait_for(lambda: all(queue.get_job(job_id).status in TERMINAL
                              for job_id in job_ids), timeout)
    assert ok, "任务未在超时内到达终态: %s" % [
        (job_id, queue.get_job(job_id).status) for job_id in job_ids]


def submit_one(scheduler, path, priority=Priority.NORMAL, name=None):
    """提交单个数据包并返回其 job_id。"""
    batch_id = scheduler.submit_batch(
        [{"packet_path": path, "packet_name": name or path.name,
          "priority": priority}])
    jobs = scheduler.queue_store.list_jobs(batch_id=batch_id)
    assert len(jobs) == 1
    return jobs[0].job_id


@pytest.fixture
def scheduler(tmp_path):
    """提供已启动的调度器并在用例结束后停止。"""
    holders = []

    def factory(config=None, runner=None, autostart=True, **overrides):
        config = config or make_config(tmp_path, **overrides)
        instance = BatchScheduler(config, runner=runner or FakeRunner())
        if autostart:
            instance.start()
        holders.append(instance)
        return instance

    yield factory
    for instance in holders:
        instance.stop()


def test_submit_and_complete_all(scheduler, tmp_path):
    fake = FakeRunner(delay=0.05)
    instance = scheduler(runner=fake, batch_max_workers=2)
    job_ids = [submit_one(instance, make_packet(tmp_path, "p%d.zip" % i, 100))
               for i in range(3)]
    wait_terminal(instance.queue_store, job_ids)
    for job_id in job_ids:
        job = instance.queue_store.get_job(job_id)
        assert job.status == JobStatus.DONE
        assert job.started_at and job.finished_at
    assert 1 <= fake.peak <= 2
    assert instance.snapshot()["inflight_bytes"] == 0


def test_concurrency_limit(scheduler, tmp_path):
    fake = FakeRunner(delay=0.2)
    instance = scheduler(runner=fake, batch_max_workers=2)
    job_ids = [submit_one(instance, make_packet(tmp_path, "c%d.zip" % i, 100))
               for i in range(6)]
    wait_terminal(instance.queue_store, job_ids)
    assert fake.peak == 2
    assert len(fake.calls) == 6


def test_single_worker_serializes(scheduler, tmp_path):
    fake = FakeRunner(delay=0.05)
    instance = scheduler(runner=fake, batch_max_workers=1)
    job_ids = [submit_one(instance, make_packet(tmp_path, "s%d.zip" % i, 100))
               for i in range(3)]
    wait_terminal(instance.queue_store, job_ids)
    assert fake.peak == 1


def test_priority_preemption_at_task_boundary(scheduler, tmp_path):
    """高优先级任务在运行中任务完成后插队到普通任务之前。"""
    gate = threading.Event()
    fake = FakeRunner(gate=gate)
    instance = scheduler(runner=fake, batch_max_workers=1)
    low = submit_one(instance, make_packet(tmp_path, "low.zip", 100),
                     priority=Priority.LOW)
    assert wait_for(lambda: len(fake.calls) == 1)
    normal = submit_one(instance, make_packet(tmp_path, "normal.zip", 100),
                        priority=Priority.NORMAL)
    high = submit_one(instance, make_packet(tmp_path, "high.zip", 100),
                      priority=Priority.HIGH)
    gate.set()
    wait_terminal(instance.queue_store, [low, normal, high])
    assert fake.calls == [low, high, normal]


def test_same_priority_fifo(scheduler, tmp_path):
    gate = threading.Event()
    fake = FakeRunner(gate=gate)
    instance = scheduler(runner=fake, batch_max_workers=1)
    first = submit_one(instance, make_packet(tmp_path, "a.zip", 100))
    assert wait_for(lambda: len(fake.calls) == 1)
    second = submit_one(instance, make_packet(tmp_path, "b.zip", 100))
    third = submit_one(instance, make_packet(tmp_path, "c.zip", 100))
    gate.set()
    wait_terminal(instance.queue_store, [first, second, third])
    assert fake.calls == [first, second, third]


def test_inflight_bytes_throttle(scheduler, tmp_path):
    """在途预估解压体积超阈值时，后续任务保持排队直到资源释放。"""
    gate = threading.Event()
    fake = FakeRunner(gate=gate)
    instance = scheduler(runner=fake, batch_max_workers=2,
                         batch_max_inflight_bytes=1500)
    first = submit_one(instance, make_packet(tmp_path, "big1.zip", 1000))
    assert wait_for(lambda: len(fake.calls) == 1)
    second = submit_one(instance, make_packet(tmp_path, "big2.zip", 1000))
    # 1000 + 1000 > 1500：第二个任务在第一个完成前不得被调度。
    time.sleep(0.4)
    assert instance.queue_store.get_job(second).status == JobStatus.QUEUED
    assert fake.peak == 1
    gate.set()
    wait_terminal(instance.queue_store, [first, second])
    assert fake.calls == [first, second]
    assert instance.snapshot()["inflight_bytes"] == 0


def test_inflight_threshold_allows_parallel_when_room(scheduler, tmp_path):
    fake = FakeRunner(delay=0.2)
    instance = scheduler(runner=fake, batch_max_workers=2,
                         batch_max_inflight_bytes=2500)
    job_ids = [submit_one(instance, make_packet(tmp_path, "r%d.zip" % i, 1000))
               for i in range(2)]
    wait_terminal(instance.queue_store, job_ids)
    assert fake.peak == 2


def test_oversized_single_task_still_runs(scheduler, tmp_path):
    """单任务预估超过批量阈值时，在途为空仍放行，避免永久饥饿。"""
    fake = FakeRunner()
    instance = scheduler(runner=fake, batch_max_workers=1,
                         batch_max_inflight_bytes=500)
    job_id = submit_one(instance, make_packet(tmp_path, "huge.zip", 1000))
    wait_terminal(instance.queue_store, [job_id])
    assert instance.queue_store.get_job(job_id).status == JobStatus.DONE


def test_disk_free_threshold_blocks_scheduling(scheduler, tmp_path):
    """磁盘余量低于阈值时任务保持排队（资源不足限流）。"""
    fake = FakeRunner()
    instance = scheduler(runner=fake, batch_max_workers=1,
                         batch_min_free_bytes=10 ** 18)
    job_id = submit_one(instance, make_packet(tmp_path, "disk.zip", 100))
    time.sleep(0.4)
    assert instance.queue_store.get_job(job_id).status == JobStatus.QUEUED
    assert fake.calls == []


def test_runner_exception_releases_resources(scheduler, tmp_path):
    """执行器异常：任务进入 error 终态，暂存文件与在途计数都被释放。"""
    fake = FakeRunner(fail_on=("broken",))
    instance = scheduler(runner=fake, batch_max_workers=1)
    broken = submit_one(instance, make_packet(tmp_path, "broken.zip", 100))
    good = submit_one(instance, make_packet(tmp_path, "good.zip", 100))
    wait_terminal(instance.queue_store, [broken, good])
    broken_job = instance.queue_store.get_job(broken)
    assert broken_job.status == JobStatus.ERROR
    assert "模拟执行异常" in broken_job.error
    assert instance.queue_store.get_job(good).status == JobStatus.DONE
    assert instance.snapshot()["inflight_bytes"] == 0
    # 异常不破坏调度器：后续任务仍可正常执行。
    follow_up = submit_one(instance, make_packet(tmp_path, "follow.zip", 100))
    wait_terminal(instance.queue_store, [follow_up])
    assert instance.queue_store.get_job(follow_up).status == JobStatus.DONE


def test_missing_packet_file_marks_error(scheduler, tmp_path):
    """暂存包被外部清除：任务以 error 收尾且不残留批次目录。"""
    from gateway.batch import PipelineRunner
    from gateway.store.sqlite_store import SQLiteStore
    config = make_config(tmp_path)
    store = SQLiteStore(config.db_path)
    # 使用真实适配器：只有它会真正读取并校验包文件的存在性。
    instance = scheduler(config=config,
                         runner=PipelineRunner(config, store), autostart=False)
    job_id = submit_one(instance, make_packet(tmp_path, "lost.zip", 100))
    job = instance.queue_store.get_job(job_id)
    batch_dir = config.batch_upload_dir / job.batch_id
    for item in batch_dir.iterdir():
        item.unlink()
    instance.start()
    wait_terminal(instance.queue_store, [job_id])
    job = instance.queue_store.get_job(job_id)
    assert job.status == JobStatus.ERROR
    assert "不存在" in job.error
    assert not batch_dir.exists()


def test_staging_files_released_after_terminal(scheduler, tmp_path):
    """任务到达终态后上传副本与批次目录被自动清理，无残留堆积。"""
    config = make_config(tmp_path)
    fake = FakeRunner()
    instance = scheduler(config=config, runner=fake, batch_max_workers=2)
    contract = tmp_path / "custom_contract.yaml"
    contract.write_text("contract: {}\n", encoding="utf-8")
    batch_id = instance.submit_batch(
        [{"packet_path": make_packet(tmp_path, "k%d.zip" % i, 100),
          "packet_name": "k%d.zip" % i, "priority": Priority.NORMAL}
         for i in range(3)],
        contract_path=contract)
    batch_dir = config.batch_upload_dir / batch_id
    assert (batch_dir / "contract.yaml").is_file()
    assert len(list(batch_dir.iterdir())) == 4
    job_ids = [job.job_id for job in
               instance.queue_store.list_jobs(batch_id=batch_id)]
    wait_terminal(instance.queue_store, job_ids)
    assert wait_for(lambda: not batch_dir.exists())
    assert list(config.batch_upload_dir.iterdir()) == []


def test_restart_recovers_unfinished_jobs(scheduler, tmp_path):
    """服务重启：queued 与 running 任务都恢复到排队队列并被重新执行。"""
    config = make_config(tmp_path)
    first = scheduler(config=config, runner=FakeRunner(), autostart=False)
    queued_id = submit_one(first, make_packet(tmp_path, "queued.zip", 100))
    running_id = submit_one(first, make_packet(tmp_path, "running.zip", 100))
    # 模拟进程崩溃瞬间：一个任务排队中，一个任务处于运行中。
    first.queue_store.update_job(running_id, status=JobStatus.RUNNING,
                                 started_at="2026-01-01T00:00:00")
    # 用同一工作目录与数据库重建调度器，等价于服务重启。
    recovered_runner = FakeRunner()
    second = scheduler(config=config, runner=recovered_runner)
    wait_terminal(second.queue_store, [queued_id, running_id])
    assert sorted(recovered_runner.calls) == sorted([queued_id, running_id])
    for job_id in (queued_id, running_id):
        job = second.queue_store.get_job(job_id)
        assert job.status == JobStatus.DONE
        assert job.started_at and job.finished_at


def test_restart_skips_already_completed_task(scheduler, tmp_path):
    """重启恢复：校验已完成但队列状态未及更新的任务直接同步终态，不重跑。"""
    from gateway.store.sqlite_store import SQLiteStore
    config = make_config(tmp_path)
    store = SQLiteStore(config.db_path)
    first = scheduler(config=config, runner=FakeRunner(), autostart=False)
    job_id = submit_one(first, make_packet(tmp_path, "done.zip", 100))
    first.queue_store.update_job(job_id, status=JobStatus.RUNNING)
    # 模拟上次进程退出瞬间：校验结果已落库，队列状态仍停留 running。
    store.create_task({"task_id": job_id, "packet_name": "done.zip",
                       "uploaded_at": "2026-01-01T00:00:00"})
    store.update_task(job_id, status="passed", passed=True)
    recovered = FakeRunner()
    second = scheduler(config=config, runner=recovered)
    wait_terminal(second.queue_store, [job_id])
    assert second.queue_store.get_job(job_id).status == JobStatus.DONE
    assert recovered.calls == []
    assert store.get_task(job_id)["status"] == "passed"


def test_restart_reruns_interrupted_task(scheduler, tmp_path):
    """重启恢复：校验中断的 running 残留记录被清理后重新执行。"""
    from gateway.store.sqlite_store import SQLiteStore
    config = make_config(tmp_path)
    store = SQLiteStore(config.db_path)
    first = scheduler(config=config, runner=FakeRunner(), autostart=False)
    job_id = submit_one(first, make_packet(tmp_path, "half.zip", 100))
    first.queue_store.update_job(job_id, status=JobStatus.RUNNING)
    # 模拟中断残留：tasks 表停留在 running，没有完整校验结果。
    store.create_task({"task_id": job_id, "packet_name": "half.zip",
                       "uploaded_at": "2026-01-01T00:00:00"})
    recovered = FakeRunner()
    second = scheduler(config=config, runner=recovered)
    wait_terminal(second.queue_store, [job_id])
    assert recovered.calls == [job_id]
    assert second.queue_store.get_job(job_id).status == JobStatus.DONE
    # 残留的 running 记录已被清理，避免主键冲突。
    assert store.get_task(job_id) is None


def test_orphan_temp_dirs_cleaned_on_start(scheduler, tmp_path):
    """启动时清理上次进程残留的解压/上传临时目录，保留批量暂存区。"""
    config = make_config(tmp_path)
    for prefix in ("gateway-orphan", "upload-orphan"):
        orphan = config.temp_dir / prefix
        orphan.mkdir(parents=True)
        (orphan / "leftover.bin").write_bytes(b"0" * 8)
    staged = config.batch_upload_dir / "keep-batch"
    staged.mkdir(parents=True)
    (staged / "packet.zip").write_bytes(b"0" * 8)
    instance = scheduler(config=config, runner=FakeRunner())
    assert list(config.temp_dir.iterdir()) == []
    assert (staged / "packet.zip").is_file()
    instance.stop()


def test_queue_full_rejects_submission(scheduler, tmp_path):
    instance = scheduler(autostart=False, batch_queue_limit=2)
    submit_one(instance, make_packet(tmp_path, "q1.zip", 100))
    submit_one(instance, make_packet(tmp_path, "q2.zip", 100))
    with pytest.raises(QueueFullError):
        submit_one(instance, make_packet(tmp_path, "q3.zip", 100))


def test_submit_empty_items_rejected(scheduler):
    instance = scheduler(autostart=False)
    with pytest.raises(ValueError):
        instance.submit_batch([])


def test_failed_task_status_mapping(scheduler, tmp_path):
    """校验未通过的任务映射为 failed 终态而非调度异常。"""
    fake = FakeRunner(task_status="failed")
    instance = scheduler(runner=fake)
    job_id = submit_one(instance, make_packet(tmp_path, "bad.zip", 100))
    wait_terminal(instance.queue_store, [job_id])
    job = instance.queue_store.get_job(job_id)
    assert job.status == JobStatus.FAILED
    assert job.error == ""


def test_shared_contract_never_moved(scheduler, tmp_path):
    """批次共享的契约文件始终复制暂存：即使 move=True 也不动源文件。"""
    config = make_config(tmp_path)
    contract = tmp_path / "shared_contract.yaml"
    contract.write_text("contract: {}\n", encoding="utf-8")
    digest_before = contract.read_bytes()
    instance = scheduler(config=config, runner=FakeRunner())
    batch_id = instance.submit_batch(
        [{"packet_path": make_packet(tmp_path, "m.zip", 100),
          "packet_name": "m.zip"}],
        contract_path=contract, move=True)
    job_ids = [job.job_id for job in
               instance.queue_store.list_jobs(batch_id=batch_id)]
    wait_terminal(instance.queue_store, job_ids)
    assert contract.is_file()
    assert contract.read_bytes() == digest_before
    assert wait_for(
        lambda: not (config.batch_upload_dir / batch_id).exists())


def test_started_property_and_double_start(scheduler):
    instance = scheduler(autostart=False)
    assert not instance.started
    instance.start()
    assert instance.started
    instance.start()  # 重复启动幂等，不重复加载队列
    assert instance.started


def test_staging_failure_cleans_batch_dir(scheduler, tmp_path):
    """暂存源文件失败时抛出异常且不留批次目录残骸。"""
    config = make_config(tmp_path)
    instance = scheduler(config=config, autostart=False)
    with pytest.raises(OSError):
        instance.submit_batch(
            [{"packet_path": tmp_path / "missing.zip",
              "packet_name": "missing.zip"}])
    assert list(config.batch_upload_dir.iterdir()) == []


def test_stale_heap_entry_discarded(scheduler, tmp_path):
    """堆内任务被外部推进终态后，worker 丢弃该条目而不再执行。"""
    gate = threading.Event()
    fake = FakeRunner(gate=gate)
    instance = scheduler(runner=fake, batch_max_workers=1)
    blocker = submit_one(instance, make_packet(tmp_path, "blocker.zip", 100))
    assert wait_for(lambda: len(fake.calls) == 1)
    stale = submit_one(instance, make_packet(tmp_path, "stale.zip", 100))
    instance.queue_store.update_job(stale, status=JobStatus.CANCELLED)
    gate.set()
    wait_terminal(instance.queue_store, [blocker])
    time.sleep(0.5)
    assert fake.calls == [blocker]
    assert instance.queue_store.get_job(stale).status == JobStatus.CANCELLED


def test_disk_usage_error_blocks_scheduling(scheduler, tmp_path, monkeypatch):
    """磁盘状态不可读时按资源不足处理，任务保持排队。"""
    import shutil

    def boom(path):
        raise OSError("模拟磁盘读取失败")

    monkeypatch.setattr(shutil, "disk_usage", boom)
    instance = scheduler(runner=FakeRunner())
    job_id = submit_one(instance, make_packet(tmp_path, "d.zip", 100))
    time.sleep(0.4)
    assert instance.queue_store.get_job(job_id).status == JobStatus.QUEUED


def test_runner_error_status_mapped(scheduler, tmp_path):
    """校验流水线返回 error 状态时映射为调度层 error 终态。"""
    fake = FakeRunner(task_status="error")
    instance = scheduler(runner=fake)
    job_id = submit_one(instance, make_packet(tmp_path, "e.zip", 100))
    wait_terminal(instance.queue_store, [job_id])
    job = instance.queue_store.get_job(job_id)
    assert job.status == JobStatus.ERROR


def test_unlink_quiet_swallows_os_error(tmp_path):
    """删除失败（如目标为目录）被静默吞掉，交由后续运维清理。"""
    BatchScheduler._unlink_quiet(tmp_path)
    assert tmp_path.is_dir()


def test_cleanup_orphan_handles_io_error(scheduler, monkeypatch, tmp_path):
    """临时目录不可读时启动流程不中断。"""
    config = make_config(tmp_path)

    def boom(self):
        raise OSError("模拟目录读取失败")

    monkeypatch.setattr(Path, "iterdir", boom)
    instance = scheduler(config=config, autostart=False)
    instance.start()
    assert instance.started


def test_release_never_deletes_outside_batch_area(scheduler, tmp_path):
    """队列记录被篡改指向暂存区外时，清理逻辑不越界删除文件。"""
    config = make_config(tmp_path)
    outside = tmp_path / "outside.zip"
    outside.write_bytes(b"0" * 8)
    instance = scheduler(config=config, runner=FakeRunner(), autostart=False)
    job_id = submit_one(instance, make_packet(tmp_path, "normal.zip", 100))
    instance.queue_store.update_job(job_id, packet_path="../outside.zip")
    instance.start()
    wait_terminal(instance.queue_store, [job_id])
    assert outside.is_file()


def test_runner_invalid_result_mapped(scheduler, tmp_path):
    """执行器返回无效结果时任务以 error 收尾并记录原因。"""
    instance = scheduler(runner=lambda job: None)
    job_id = submit_one(instance, make_packet(tmp_path, "n.zip", 100))
    wait_terminal(instance.queue_store, [job_id])
    job = instance.queue_store.get_job(job_id)
    assert job.status == JobStatus.ERROR
    assert "有效结果" in job.error


def test_push_locked_deduplicates(scheduler, tmp_path):
    """内存堆对同一任务去重，重复推送不会放大队列。"""
    instance = scheduler(autostart=False)
    job_id = submit_one(instance, make_packet(tmp_path, "dup.zip", 100))
    job = instance.queue_store.get_job(job_id)
    instance.start()
    with instance._cond:
        instance._push_locked(job)
        assert len(instance._heap) == 1


def test_inflight_released_even_if_db_update_fails(scheduler, tmp_path,
                                                   monkeypatch):
    """状态写库失败时在途计数与暂存文件仍被释放，调度器不卡死。"""
    config = make_config(tmp_path)
    instance = scheduler(config=config, runner=FakeRunner(), autostart=False)
    job_id = submit_one(instance, make_packet(tmp_path, "db.zip", 100))
    job = instance.queue_store.get_job(job_id)
    original_update = instance.queue_store.update_job

    def flaky(job_id_arg, **fields):
        if fields.get("status") == JobStatus.RUNNING:
            raise OSError("模拟数据库写失败")
        return original_update(job_id_arg, **fields)

    monkeypatch.setattr(instance.queue_store, "update_job", flaky)
    instance.start()
    wait_terminal(instance.queue_store, [job_id])
    job = instance.queue_store.get_job(job_id)
    assert job.status == JobStatus.ERROR
    assert "模拟数据库写失败" in job.error
    assert instance.snapshot()["inflight_bytes"] == 0
    assert wait_for(
        lambda: not (config.batch_upload_dir / job.batch_id).exists())
    # 调度器未卡死：恢复写库后后续任务照常执行。
    monkeypatch.undo()
    follow_up = submit_one(instance, make_packet(tmp_path, "next.zip", 100))
    wait_terminal(instance.queue_store, [follow_up])
    assert instance.queue_store.get_job(follow_up).status == JobStatus.DONE


def test_invalid_batch_config_rejected(tmp_path):
    with pytest.raises(ValueError):
        make_config(tmp_path, batch_max_workers=0)
    with pytest.raises(ValueError):
        make_config(tmp_path, batch_max_workers=99)
    with pytest.raises(ValueError):
        make_config(tmp_path, batch_max_inflight_bytes=0)
    with pytest.raises(ValueError):
        make_config(tmp_path, batch_min_free_bytes=-1)
    with pytest.raises(ValueError):
        make_config(tmp_path, batch_queue_limit=0)
