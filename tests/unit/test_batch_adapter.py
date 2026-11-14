"""批量任务适配器的安全防御测试。"""

import pytest

from gateway.batch import BatchJob, PipelineRunner
from gateway.batch.adapter import _resolve_inside


def test_resolve_inside_accepts_normal_path(config):
    path = _resolve_inside(config.workspace_dir, "uploads/batch/b1/x.zip")
    assert path == (config.workspace_dir / "uploads/batch/b1/x.zip").resolve()


def test_resolve_inside_rejects_escape(config):
    with pytest.raises(ValueError):
        _resolve_inside(config.workspace_dir, "../../etc/passwd")
    with pytest.raises(ValueError):
        _resolve_inside(config.workspace_dir, "uploads/../../outside.zip")


def test_runner_rejects_missing_packet(config, store):
    runner = PipelineRunner(config, store)
    job = BatchJob(job_id="a" * 16, batch_id="b1", packet_name="x.zip",
                   packet_path="uploads/batch/b1/x.zip")
    with pytest.raises(FileNotFoundError):
        runner(job)


def test_runner_rejects_out_of_workspace_contract(config, store):
    """契约路径越界时在进入校验流水线前被拦截。"""
    packet_dir = config.batch_upload_dir / "b1"
    packet_dir.mkdir(parents=True, exist_ok=True)
    (packet_dir / "x.zip").write_bytes(b"0" * 8)
    runner = PipelineRunner(config, store)
    job = BatchJob(job_id="c" * 16, batch_id="b1", packet_name="x.zip",
                   packet_path="uploads/batch/b1/x.zip",
                   contract_path="../../outside.yaml")
    with pytest.raises(ValueError):
        runner(job)
