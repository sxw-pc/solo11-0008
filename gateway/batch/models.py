"""批量优先级调度的数据模型与状态定义。

本模块只包含纯数据定义，不依赖任何第三方包。批量调度能力通过适配器
对接既有单包校验流水线，不改动 ``gateway.pipeline`` 的核心逻辑。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class Priority:
    """任务优先级：数值越小越优先调度。

    提供高/普通/低三档常用档位，同时接受 0-9 的任意整数，便于运维
    按部门或紧急程度细分。非法输入一律回落到普通优先级。
    """

    HIGH = 1
    NORMAL = 5
    LOW = 9
    MIN = 0
    MAX = 9

    LABELS = {HIGH: "高", NORMAL: "普通", LOW: "低"}

    @classmethod
    def clamp(cls, value: Any) -> int:
        """把外部输入规范化为 0-9 的整数优先级。"""
        try:
            level = int(str(value).strip())
        except (TypeError, ValueError):
            return cls.NORMAL
        return max(cls.MIN, min(cls.MAX, level))

    @classmethod
    def label(cls, value: Any) -> str:
        """返回优先级的展示文本。"""
        level = cls.clamp(value)
        return cls.LABELS.get(level, "优先级%d" % level)


class JobStatus:
    """批量队列任务状态机。

    queued → running → done / failed / error；queued 也可转为 cancelled。
    服务重启时 running 会被重置回 queued 重新排队（见调度器恢复逻辑）。
    """

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"          # 校验流水线执行完成且通过
    FAILED = "failed"      # 校验流水线执行完成但未通过
    ERROR = "error"        # 调度或执行过程异常（包丢失、流水线崩溃等）
    CANCELLED = "cancelled"

    TERMINAL = (DONE, FAILED, ERROR, CANCELLED)
    ACTIVE = (QUEUED, RUNNING)

    LABELS = {
        QUEUED: "排队中",
        RUNNING: "校验中",
        DONE: "通过",
        FAILED: "未通过",
        ERROR: "执行异常",
        CANCELLED: "已取消",
    }


@dataclass
class BatchJob:
    """一条批量队列任务。

    Attributes:
        job_id: 任务 ID，同时作为校验流水线的 task_id，保证两份记录一一对应。
        batch_id: 一次批量提交的批次 ID。
        packet_name: 展示用原始文件名。
        packet_path: 待校验包在工作目录内的相对路径（uploads/batch 下）。
        packet_size: 压缩包字节数。
        estimated_bytes: 预估解压后字节数，用于调度限流。
        priority: 优先级，数值越小越优先。
        status: 见 :class:`JobStatus`。
        seq: 入队单调序号，同优先级时保证先进先出。
        contract_path: 批次共享的自定义契约相对路径，空串表示使用内置契约。
        lineage_path: 批次共享的自定义血缘规则相对路径。
        expected_hash: 可选整包哈希。
        task_id: 关联的校验任务 ID（与 job_id 相同）。
    """

    job_id: str
    batch_id: str
    packet_name: str
    packet_path: str
    packet_size: int = 0
    estimated_bytes: int = 0
    priority: int = Priority.NORMAL
    status: str = JobStatus.QUEUED
    seq: int = 0
    created_at: str = ""
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    task_id: str = ""
    error: str = ""
    contract_path: str = ""
    lineage_path: str = ""
    expected_hash: str = ""

    @property
    def is_terminal(self) -> bool:
        """任务是否已到达终态。"""
        return self.status in JobStatus.TERMINAL

    def to_dict(self) -> Dict[str, Any]:
        """转换为可 JSON 序列化的字典，供页面与 API 使用。"""
        return {
            "job_id": self.job_id,
            "batch_id": self.batch_id,
            "packet_name": self.packet_name,
            "packet_path": self.packet_path,
            "packet_size": self.packet_size,
            "estimated_bytes": self.estimated_bytes,
            "priority": self.priority,
            "priority_label": Priority.label(self.priority),
            "status": self.status,
            "status_label": JobStatus.LABELS.get(self.status, self.status),
            "seq": self.seq,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "task_id": self.task_id,
            "error": self.error,
            "expected_hash": self.expected_hash,
        }
