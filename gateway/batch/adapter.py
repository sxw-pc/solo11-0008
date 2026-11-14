"""批量任务到单包校验流水线的适配层。

本模块不修改 ``gateway.pipeline.run_validation`` 的任何逻辑，只负责把
队列中的批量任务记录转换为一次标准的单包校验调用：

- 把队列中保存的相对路径解析回工作目录内的绝对路径，并防御越界；
- 复用与单包提交完全相同的参数体系（契约、血缘、整包哈希）；
- 任务 ID 与队列 job_id 一致，校验历史与队列记录一一对应、可追溯。

调度器通过注入该适配器执行真实校验；测试可以注入任意可调用对象
替代，从而在不运行真实流水线的情况下验证调度行为。
"""

from pathlib import Path
from typing import Any, Dict

from ..config import AppConfig
from ..pipeline import run_validation
from ..store.sqlite_store import SQLiteStore
from .models import BatchJob


def _resolve_inside(workspace: Path, relative: str) -> Path:
    """把队列中的相对路径解析为工作目录内绝对路径，拒绝越界。"""
    candidate = (workspace / relative).resolve()
    try:
        candidate.relative_to(workspace.resolve())
    except ValueError as exc:
        raise ValueError("队列任务路径越界: %s" % relative) from exc
    return candidate


class PipelineRunner:
    """把批量任务适配为既有单包校验调用的可调用对象。"""

    def __init__(self, config: AppConfig, store: SQLiteStore):
        """绑定全局配置与任务存储，供每次调用复用。"""
        self._config = config
        self._store = store

    def __call__(self, job: BatchJob) -> Dict[str, Any]:
        """执行一次单包校验并返回与 ``run_validation`` 相同的结果字典。"""
        config = self._config
        packet_path = _resolve_inside(config.workspace_dir, job.packet_path)
        if not packet_path.is_file():
            raise FileNotFoundError("待校验数据包不存在: %s" % job.packet_path)
        contract_path = (_resolve_inside(config.workspace_dir, job.contract_path)
                         if job.contract_path else None)
        lineage_path = (_resolve_inside(config.workspace_dir, job.lineage_path)
                        if job.lineage_path else None)
        return run_validation(
            packet_path, job.packet_name, config, self._store,
            contract_path=contract_path, lineage_path=lineage_path,
            expected_package_hash=job.expected_hash or None,
            task_id=job.job_id)
