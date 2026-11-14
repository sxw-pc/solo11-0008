"""批量优先级调度：本地队列、并发执行与资源限流。

该子包在既有单包校验流水线之上提供批量提交能力，全部组件仅依赖
标准库与项目内模块，通过适配器对接 ``gateway.pipeline.run_validation``，
不改动单任务校验核心逻辑。
"""

from .adapter import PipelineRunner
from .estimator import estimate_uncompressed_bytes
from .models import BatchJob, JobStatus, Priority
from .queue_store import BatchQueueStore
from .scheduler import BatchScheduler, QueueFullError

__all__ = [
    "BatchJob",
    "BatchQueueStore",
    "BatchScheduler",
    "JobStatus",
    "PipelineRunner",
    "Priority",
    "QueueFullError",
    "estimate_uncompressed_bytes",
]
