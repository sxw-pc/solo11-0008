"""批量队列持久化存储的单元测试。"""

import pytest

from gateway.batch import BatchJob, BatchQueueStore, JobStatus, Priority


@pytest.fixture
def queue(config):
    """返回绑定临时数据库的队列存储实例。"""
    return BatchQueueStore(config.db_path)


def make_job(job_id, batch_id="batch-1", priority=Priority.NORMAL,
             status=JobStatus.QUEUED, **overrides):
    params = {"job_id": job_id, "batch_id": batch_id,
              "packet_name": "%s.zip" % job_id,
              "packet_path": "uploads/batch/%s/%s.zip" % (batch_id, job_id),
              "priority": priority, "status": status}
    params.update(overrides)
    return BatchJob(**params)


def test_create_and_get_roundtrip(queue):
    job = make_job("job-a", estimated_bytes=2048, packet_size=512,
                   expected_hash="sha256:abc", contract_path="uploads/batch/b/contract.yaml")
    queue.create_job(job)
    stored = queue.get_job("job-a")
    assert stored is not None
    assert stored.job_id == "job-a"
    assert stored.batch_id == "batch-1"
    assert stored.estimated_bytes == 2048
    assert stored.packet_size == 512
    assert stored.expected_hash == "sha256:abc"
    assert stored.contract_path == "uploads/batch/b/contract.yaml"
    assert stored.status == JobStatus.QUEUED
    assert stored.task_id == "job-a"
    assert stored.created_at
    assert stored.seq > 0
    assert not stored.is_terminal
    assert queue.get_job("missing") is None


def test_seq_monotonic_across_instances(queue, config):
    first = make_job("seq-1")
    queue.create_job(first)
    # 模拟重启后新建的存储实例：序号继续单调递增，FIFO 语义跨重启保持。
    second_store = BatchQueueStore(config.db_path)
    second = make_job("seq-2")
    second_store.create_job(second)
    assert second.seq > first.seq


def test_create_requires_ids(queue):
    with pytest.raises(ValueError):
        queue.create_job(make_job("", batch_id=""))
    with pytest.raises(ValueError):
        queue.create_job(make_job("job-x", batch_id=""))


def test_update_job_fields(queue):
    queue.create_job(make_job("job-u"))
    assert queue.update_job("job-u", status=JobStatus.RUNNING,
                            started_at="2026-01-01T00:00:00",
                            unknown_field="ignored")
    stored = queue.get_job("job-u")
    assert stored.status == JobStatus.RUNNING
    assert stored.started_at == "2026-01-01T00:00:00"
    assert not queue.update_job("job-u")
    assert not queue.update_job("missing", status=JobStatus.DONE)


def test_priority_clamped_on_write_and_read(queue):
    queue.create_job(make_job("job-p", priority=99))
    assert queue.get_job("job-p").priority == Priority.MAX
    queue.update_job("job-p", priority=-5)
    assert queue.get_job("job-p").priority == Priority.MIN


def test_queued_jobs_ordered_by_priority_then_seq(queue):
    for job_id, priority in (("n1", 5), ("h1", 1), ("n2", 5), ("l1", 9), ("h2", 1)):
        queue.create_job(make_job(job_id, priority=priority))
    ordered = [job.job_id for job in queue.queued_jobs()]
    assert ordered == ["h1", "h2", "n1", "n2", "l1"]


def test_list_jobs_filters(queue):
    queue.create_job(make_job("b1-a", batch_id="b1"))
    queue.create_job(make_job("b1-b", batch_id="b1", status=JobStatus.DONE))
    queue.create_job(make_job("b2-a", batch_id="b2"))
    assert [j.job_id for j in queue.list_jobs(batch_id="b1")] == ["b1-b", "b1-a"]
    assert [j.job_id for j in queue.list_jobs(status=JobStatus.DONE)] == ["b1-b"]
    assert len(queue.list_jobs()) == 3


def test_reset_running_to_queued(queue):
    queue.create_job(make_job("run-1", status=JobStatus.RUNNING,
                              started_at="2026-01-01T00:00:00"))
    queue.create_job(make_job("run-2", status=JobStatus.RUNNING))
    queue.create_job(make_job("done-1", status=JobStatus.DONE))
    assert queue.reset_running_to_queued() == 2
    assert queue.get_job("run-1").status == JobStatus.QUEUED
    assert queue.get_job("run-1").started_at is None
    assert queue.get_job("done-1").status == JobStatus.DONE
    assert queue.get_job("done-1").is_terminal
    assert queue.reset_running_to_queued() == 0


def test_count_active(queue):
    queue.create_job(make_job("a1", status=JobStatus.QUEUED))
    queue.create_job(make_job("a2", status=JobStatus.RUNNING))
    queue.create_job(make_job("a3", status=JobStatus.DONE))
    queue.create_job(make_job("a4", status=JobStatus.ERROR))
    assert queue.count_active() == 2


def test_count_active_in_batch(queue):
    queue.create_job(make_job("m1", batch_id="bx", status=JobStatus.QUEUED))
    queue.create_job(make_job("m2", batch_id="bx", status=JobStatus.DONE))
    queue.create_job(make_job("m3", batch_id="by", status=JobStatus.QUEUED))
    assert queue.count_active_in_batch("bx") == 1
    assert queue.count_active_in_batch("by") == 1
    queue.update_job("m1", status=JobStatus.FAILED)
    assert queue.count_active_in_batch("bx") == 0


def test_recent_terminal_jobs(queue):
    for index in range(5):
        status = JobStatus.DONE if index % 2 == 0 else JobStatus.QUEUED
        queue.create_job(make_job("t%d" % index, status=status))
    recent = queue.recent_terminal_jobs(limit=10)
    assert [job.job_id for job in recent] == ["t4", "t2", "t0"]
    assert [job.job_id for job in queue.recent_terminal_jobs(limit=1)] == ["t4"]


def test_purge_terminal(queue):
    for index in range(6):
        queue.create_job(make_job("p%d" % index, status=JobStatus.DONE))
    queue.create_job(make_job("keep", status=JobStatus.QUEUED))
    assert queue.purge_terminal(keep_latest=2) == 4
    remaining = [job.job_id for job in queue.recent_terminal_jobs(limit=10)]
    assert remaining == ["p5", "p4"]
    assert queue.get_job("keep") is not None


def test_priority_clamp_and_label():
    assert Priority.clamp("1") == 1
    assert Priority.clamp("abc") == Priority.NORMAL
    assert Priority.clamp(None) == Priority.NORMAL
    assert Priority.clamp(-3) == Priority.MIN
    assert Priority.clamp(42) == Priority.MAX
    assert Priority.label(Priority.HIGH) == "高"
    assert Priority.label(Priority.NORMAL) == "普通"
    assert Priority.label(Priority.LOW) == "低"
    assert "3" in Priority.label(3)


def test_job_to_dict_is_serializable():
    job = make_job("dict-1", estimated_bytes=10)
    job.seq = 7
    data = job.to_dict()
    assert data["job_id"] == "dict-1"
    assert data["priority_label"] == "普通"
    assert data["status_label"] == "排队中"
    assert data["seq"] == 7
    import json
    json.dumps(data)
