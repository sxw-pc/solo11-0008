"""运行中任务的协作式终止支持。

终止模型：

- 流水线在每个校验阶段边界以及长耗时阶段内部（解压、哈希、表读取、血缘
  关系）检查终止标志，因此从发起终止到任务停止的等待时长不超过单个校验
  阶段的最大耗时，且不会在写库、写报告等关键区中间强制中断。
- 任务状态迁移（running → terminating → terminated）通过 SQLite 条件更新
  原子完成；已完成的 passed/failed/error 历史任务永远不会被终止流程改写。
- 终止令牌按任务隔离，多任务同时终止互不影响；对同一任务的重复终止请求
  幂等。
- 对本地已无存活流水线、但数据库仍卡在 running 的残留任务，终止服务会
  直接回收：补齐终止状态、生成部分报告并清理临时资源。
"""

from datetime import datetime
import threading
from typing import Any, Dict, List, Optional

#: 校验流水线阶段标识与展示名。``orphan`` 用于异常中断后的残留任务回收，
#: 此时原始执行阶段已不可知。
STAGE_LABELS = {
    "archive": "压缩包安全检查与解压",
    "hash": "文件完整性与哈希校验",
    "table_read": "结构化表读取适配",
    "schema": "数据契约 Schema 校验",
    "lineage": "跨表血缘一致性校验",
    "anomaly": "异常值抽检规则校验",
    "report": "报告生成与归档",
    "orphan": "中断残留回收",
}

#: 终态状态集合；处于这些状态的任务拒绝终止请求。
TERMINAL_STATUSES = ("passed", "failed", "error", "terminated")

#: 历史完成状态；这些任务受保护，终止请求一律拒绝且不做任何修改。
_FINISHED_STATUSES = ("passed", "failed", "error")


def stage_label(stage: str) -> str:
    """返回阶段展示名，未知阶段原样返回。"""
    return STAGE_LABELS.get(stage, stage or "未知")


class TaskTerminated(Exception):
    """流水线在校验点检测到终止请求后抛出，携带终止生效时所处的阶段。"""

    def __init__(self, stage: str):
        self.stage = stage
        super().__init__("任务在「%s」阶段被终止" % stage_label(stage))


class TerminationToken:
    """单个任务的终止令牌，线程安全。

    流水线通过 :meth:`check` 在阶段边界主动检查，通过 :meth:`is_requested`
    把标志传给长耗时阶段内部循环；任一线程调用 :meth:`request` 后令牌即
    生效，且操作幂等。
    """

    def __init__(self, task_id: str):
        self.task_id = str(task_id)
        self._event = threading.Event()
        self._stage_lock = threading.Lock()
        self.current_stage = ""

    def request(self) -> None:
        """置位终止标志；重复调用安全。"""
        self._event.set()

    def is_requested(self) -> bool:
        """返回是否已收到终止请求。"""
        return self._event.is_set()

    def check(self, stage: str) -> None:
        """记录当前阶段；若已请求终止则抛出 :class:`TaskTerminated`。"""
        with self._stage_lock:
            self.current_stage = stage
        if self._event.is_set():
            raise TaskTerminated(stage)


class TerminationRegistry:
    """进程内运行中任务的终止令牌注册表（线程安全）。

    仅跟踪本进程存活的任务；流水线结束时必须注销，避免把残留任务误判为
    存活任务。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._tokens: Dict[str, TerminationToken] = {}

    def register(self, task_id: str) -> TerminationToken:
        """为任务创建并登记令牌；重复登记返回已有令牌。"""
        task_id = str(task_id)
        with self._lock:
            token = self._tokens.get(task_id)
            if token is None:
                token = TerminationToken(task_id)
                self._tokens[task_id] = token
            return token

    def unregister(self, task_id: str) -> None:
        """移除任务令牌；任务不存在时静默忽略。"""
        with self._lock:
            self._tokens.pop(str(task_id), None)

    def get(self, task_id: str) -> Optional[TerminationToken]:
        """查询任务令牌，未登记返回 None。"""
        with self._lock:
            return self._tokens.get(str(task_id))

    def is_registered(self, task_id: str) -> bool:
        """返回任务是否在本进程存活。"""
        with self._lock:
            return str(task_id) in self._tokens

    def request(self, task_id: str) -> bool:
        """向存活任务发出终止请求；任务不在本进程返回 False。"""
        token = self.get(task_id)
        if token is None:
            return False
        token.request()
        return True

    def active_task_ids(self) -> List[str]:
        """返回当前登记的全部任务 ID（用于测试与诊断）。"""
        with self._lock:
            return sorted(self._tokens)


#: 应用级默认注册表；Web 请求与流水线共用同一进程内实例。
default_registry = TerminationRegistry()


def _terminated_marker(stage: str) -> Dict[str, Any]:
    """生成终止占位校验项，并入部分报告的 results 列表。"""
    label = stage_label(stage)
    return {
        "key": "terminated", "name": "任务终止", "passed": False,
        "summary": "任务在「%s」阶段被人工终止，后续校验未执行" % label,
        "terminated_stage": stage,
        "errors": [{
            "code": "terminated",
            "message": "任务在「%s」阶段被终止，本报告仅包含终止前的部分结果" % label,
        }],
        "samples": [],
    }


def _safe_relative(path: Any, workspace: Any) -> str:
    """把路径转为工作目录内相对路径（与流水线保持同一约定）。"""
    from pathlib import Path

    try:
        return Path(path).resolve().relative_to(Path(workspace).resolve()).as_posix()
    except ValueError:
        return Path(path).name


def _parse_time(value: str) -> Optional[datetime]:
    """尽力解析 ISO 时间，失败返回 None。"""
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _finalize_orphan(task: Dict[str, Any], store: Any, config: Any,
                     requested_at: str) -> bool:
    """回收无存活流水线的残留任务：补状态、生成部分报告、清理资源。

    报告渲染失败不会阻断状态收尾；最终状态更新使用条件更新，与并发的
    其他终止/完成写入竞争时只有一方生效。
    """
    from .cleanup import reclaim_task_resources
    from .report.renderer import build_report_context, render_reports

    task_id = task["task_id"]
    results = list((task.get("result") or {}).get("results") or [])
    results.append(_terminated_marker("orphan"))
    finished = datetime.now()
    started = _parse_time(task.get("uploaded_at") or "")
    duration = (round(max(0.0, (finished - started).total_seconds()), 3)
                if started else 0.0)
    summary = "任务被终止（原任务异常中断，已按残留任务回收）"
    updates: Dict[str, Any] = {
        "finished_at": finished.isoformat(timespec="seconds"),
        "passed": False,
        "duration_seconds": duration,
        "terminated_stage": "orphan",
        "error_summary": summary,
        "result_json": {"results": results},
    }
    report_task = dict(task)
    report_task.update(updates)
    report_task["status"] = "terminated"
    report_task["terminate_requested_at"] = (
        task.get("terminate_requested_at") or requested_at)
    try:
        report = build_report_context(report_task, results, config)
        paths = render_reports(report, config, task_id)
        updates["report_md"] = _safe_relative(paths["md"], config.workspace_dir)
        updates["report_html"] = _safe_relative(paths["html"], config.workspace_dir)
        updates["report_json"] = _safe_relative(paths["json"], config.workspace_dir)
    except Exception as exc:  # 报告失败不阻断残留回收
        updates["error_summary"] = (summary + "；部分报告生成失败: %s" % exc)[:500]
    log_lines = [
        "[%s] 任务 %s 被终止" % (requested_at, task_id),
        "原任务异常中断，数据库状态卡在运行中，已按残留任务回收。",
        "任务结束: terminated",
    ]
    log_relative = task.get("log_path") or ""
    log_path = None
    if log_relative:
        candidate = (config.workspace_dir / log_relative).resolve()
        try:  # 仅复用 logs 目录内的既有日志，拒绝越界路径
            candidate.relative_to(config.logs_dir.resolve())
            if candidate.is_file():
                log_path = candidate
        except ValueError:
            log_path = None
    if log_path is None:
        log_path = config.logs_dir / (task_id + ".log")
    try:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(log_lines) + "\n")
        updates["log_path"] = _safe_relative(log_path, config.workspace_dir)
    except OSError:
        pass
    finalized = store.finalize_termination(task_id, **updates)
    try:
        reclaim_task_resources(config, task_id)
    except ValueError:
        pass  # 历史数据中的非法任务 ID 不阻断状态收尾
    return finalized


def terminate_task(task_id: str, store: Any, config: Any,
                   registry: Optional[TerminationRegistry] = None) -> Dict[str, Any]:
    """请求终止一个任务，返回结构化处理结果。

    处理模式：

    - ``cooperative``：任务在本进程存活，已置位终止标志，流水线会在当前
      阶段的安全检查点收尾，等待时长不超过单个校验阶段最大耗时。
    - ``reclaimed``：数据库中仍为 running/terminating 但本地无存活流水线
      （如进程被杀），直接回收并生成部分报告。
    - ``already_requested`` / ``already_terminated``：终止请求已存在或任务
      已终止，幂等返回成功，不做任何修改。
    - ``already_finished`` / ``not_found``：拒绝终止，历史任务不受影响。
    """
    registry = registry or default_registry
    task_id = str(task_id)
    task = store.get_task(task_id)
    if task is None:
        return {"ok": False, "reason": "not_found", "task_id": task_id}
    status = task.get("status") or ""
    if status in _FINISHED_STATUSES:
        return {"ok": False, "reason": "already_finished",
                "task_id": task_id, "status": status}
    if status == "terminated":
        return {"ok": True, "reason": "already_terminated", "task_id": task_id}
    requested_at = datetime.now().isoformat(timespec="seconds")
    if status == "terminating":
        if registry.is_registered(task_id):
            return {"ok": True, "reason": "already_requested", "task_id": task_id}
        _finalize_orphan(task, store, config, requested_at)
        return {"ok": True, "reason": "reclaimed", "task_id": task_id}
    if not store.request_terminate(task_id, requested_at):
        # 与并发完成/终止竞争失败，重新读取真实状态后按幂等语义返回。
        current = store.get_task(task_id) or {}
        current_status = current.get("status") or ""
        if current_status == "terminating":
            return {"ok": True, "reason": "already_requested", "task_id": task_id}
        if current_status == "terminated":
            return {"ok": True, "reason": "already_terminated", "task_id": task_id}
        return {"ok": False, "reason": "already_finished",
                "task_id": task_id, "status": current_status}
    if registry.request(task_id):
        return {"ok": True, "reason": "cooperative", "task_id": task_id}
    latest = store.get_task(task_id) or task
    _finalize_orphan(latest, store, config, requested_at)
    return {"ok": True, "reason": "reclaimed", "task_id": task_id}
