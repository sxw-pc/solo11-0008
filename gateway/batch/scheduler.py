"""本地批量优先级调度器。

在单包校验流水线之外提供批量提交、优先级排队、并发执行与资源限流能力，
完全运行于本机进程内：队列持久化在本地 SQLite，执行器是若干后台线程，
不引入任何外部服务或新增第三方依赖，也不改动既有单包校验逻辑。

设计取舍（高优先级响应、普通任务吞吐、本地资源占用三者的平衡）：

- 调度粒度为任务边界：运行中的任务不被打断，其已完成的校验步骤无需
  回滚；高优先级任务入队后，将在任一运行中任务完成当前执行单元后，
  优先于队列中其他普通任务被调度（插队）。
- 并发度默认 2（可配置，上限 8），避免过度占用本机 CPU 与磁盘 IO。
- 存储限流：按预估解压体积控制在途任务总量，并检查磁盘剩余空间，
  防止大体积数据包并发解压占满本地存储；单任务安全阈值与既有单包
  校验默认规则完全一致（复用同一份 AppConfig，不另设标准）。
- 异常自愈：损坏包、校验失败、执行异常都会把任务推进终态并自动释放
  其占用的上传副本与临时解压目录；服务重启时未完成任务自动恢复排队，
  残留的孤儿临时目录在启动时一并清理。
- 任务隔离：每个任务使用独立的上传副本、解压临时目录、日志与报告，
  校验记录一一对应，多任务数据互不污染。
"""

from datetime import datetime
from pathlib import Path
import heapq
import shutil
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from ..config import AppConfig
from ..store.sqlite_store import SQLiteStore
from .adapter import PipelineRunner
from .estimator import estimate_uncompressed_bytes
from .models import BatchJob, JobStatus, Priority
from .queue_store import BatchQueueStore

# 与既有模块保持一致的临时目录命名前缀，用于重启后的孤儿目录清理。
_ORPHAN_PREFIXES = ("gateway-", "upload-")

_TASK_STATUS_MAP = {"passed": JobStatus.DONE, "failed": JobStatus.FAILED}


def _now() -> str:
    """返回本地秒级 ISO 时间。"""
    return datetime.now().isoformat(timespec="seconds")


class QueueFullError(Exception):
    """排队任务数达到容量上限，拒绝继续受理。"""


class BatchScheduler:
    """批量优先级调度器。

    Args:
        config: 全局配置，批量相关阈值取自 ``batch_*`` 配置项。
        store: 校验任务存储，默认按配置路径创建。
        runner: 任务执行器，默认使用 :class:`PipelineRunner` 适配既有
            单包校验流水线；测试可注入任意 ``callable(job) -> dict``。
    """

    def __init__(self, config: AppConfig, store: Optional[SQLiteStore] = None,
                 runner: Optional[Callable[[BatchJob], Dict[str, Any]]] = None):
        self._config = config
        self._store = store or SQLiteStore(config.db_path)
        self._queue = BatchQueueStore(config.db_path)
        self._runner = runner or PipelineRunner(config, self._store)
        self._heap: List[Any] = []          # (priority, seq, job_id) 最小堆
        self._queued_ids = set()            # 堆内任务去重
        self._cond = threading.Condition()
        self._inflight_bytes = 0            # 在途任务预估解压总量
        self._workers: List[threading.Thread] = []
        self._started = False
        self._stop = False

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    @property
    def queue_store(self) -> BatchQueueStore:
        """暴露队列存储，便于页面与测试查询。"""
        return self._queue

    @property
    def started(self) -> bool:
        """调度器是否已启动。"""
        return self._started

    def start(self) -> None:
        """恢复持久化队列、清理孤儿临时目录并启动 worker 线程。"""
        with self._cond:
            if self._started:
                return
            self._started = True
            self._stop = False
        # 上次进程退出时处于运行中的任务一律回到排队状态，重新排队执行；
        # 其残留的解压临时目录随下面的孤儿清理一并释放。
        self._queue.reset_running_to_queued()
        self._cleanup_orphan_temp_dirs()
        with self._cond:
            self._heap = []
            self._queued_ids = set()
            for job in self._queue.queued_jobs():
                self._push_locked(job)
            self._workers = []
            for index in range(int(self._config.batch_max_workers)):
                worker = threading.Thread(
                    target=self._worker_loop, args=(index,),
                    name="batch-worker-%d" % index, daemon=True)
                worker.start()
                self._workers.append(worker)
            self._cond.notify_all()

    def stop(self, wait: bool = True, timeout: float = 10.0) -> None:
        """停止调度；运行中的任务会执行到当前任务结束再退出。"""
        with self._cond:
            self._stop = True
            self._cond.notify_all()
        if wait:
            deadline = time.time() + timeout
            for worker in self._workers:
                remaining = max(0.05, deadline - time.time())
                worker.join(timeout=remaining)

    # ------------------------------------------------------------------
    # 提交
    # ------------------------------------------------------------------
    def submit_batch(self, items: List[Dict[str, Any]],
                     contract_path: Optional[Path] = None,
                     lineage_path: Optional[Path] = None,
                     move: bool = False) -> str:
        """受理一批数据包，返回批次 ID。

        Args:
            items: 每个元素为 ``{"packet_path", "packet_name", "priority"?,
                "expected_hash"?}``；priority 缺省为普通。
            contract_path: 批次共享的自定义契约，缺省使用内置契约。
            lineage_path: 批次共享的自定义血缘规则，缺省使用内置规则。
            move: 为 True 时把数据包源文件移入批次暂存目录（Web 上传场景，
                避免额外拷贝）；为 False 时复制（调用方保留源文件）。
                契约与血缘文件始终复制暂存，不受该参数影响。
        Raises:
            ValueError: 任务列表为空。
            QueueFullError: 在途任务数超过 ``batch_queue_limit``。
            OSError: 暂存文件落盘失败；已落盘的部分会被整体清理。
        """
        if not items:
            raise ValueError("批量提交至少需要一个数据包")
        if self._queue.count_active() + len(items) > int(self._config.batch_queue_limit):
            raise QueueFullError(
                "排队任务数已达上限 %d，请等待部分任务完成后再提交"
                % int(self._config.batch_queue_limit))
        batch_id = uuid.uuid4().hex[:12]
        batch_dir = self._config.batch_upload_dir / batch_id
        batch_dir.mkdir(parents=True, exist_ok=True)
        jobs: List[BatchJob] = []
        try:
            # 契约/血缘属于批次共享文件：源可能是内置 fixtures 或被多次
            # 提交复用的文件，必须复制暂存，绝不能移动。
            contract_rel = self._stage_shared_file(
                contract_path, batch_dir, "contract.yaml")
            lineage_rel = self._stage_shared_file(
                lineage_path, batch_dir, "lineage.yaml")
            for item in items:
                job = self._stage_one(item, batch_id, batch_dir,
                                      contract_rel, lineage_rel, move)
                jobs.append(job)
        except Exception:
            shutil.rmtree(batch_dir, ignore_errors=True)
            raise
        if self._started:
            with self._cond:
                for job in jobs:
                    self._push_locked(job)
                self._cond.notify_all()
        return batch_id

    def _stage_shared_file(self, source: Optional[Path], batch_dir: Path,
                           name: str) -> str:
        """把批次共享的契约/血缘文件复制到批次目录，返回相对路径。"""
        if source is None:
            return ""
        target = batch_dir / name
        shutil.copy2(str(source), str(target))
        return target.relative_to(self._config.workspace_dir).as_posix()

    def _stage_one(self, item: Dict[str, Any], batch_id: str, batch_dir: Path,
                   contract_rel: str, lineage_rel: str, move: bool) -> BatchJob:
        """暂存单个数据包并写入队列记录。"""
        source = Path(item["packet_path"])
        job_id = uuid.uuid4().hex[:16]
        suffix = ".tar.gz" if source.name.lower().endswith(
            (".tar.gz", ".tgz")) else source.suffix.lower() or ".zip"
        target = batch_dir / (job_id + suffix)
        self._place_file(source, target, move)
        relative = target.relative_to(self._config.workspace_dir).as_posix()
        job = BatchJob(
            job_id=job_id, batch_id=batch_id,
            packet_name=str(item.get("packet_name") or source.name),
            packet_path=relative,
            packet_size=target.stat().st_size,
            estimated_bytes=estimate_uncompressed_bytes(target),
            priority=Priority.clamp(item.get("priority")),
            status=JobStatus.QUEUED,
            created_at=_now(),
            task_id=job_id,
            contract_path=contract_rel,
            lineage_path=lineage_rel,
            expected_hash=str(item.get("expected_hash") or "").strip(),
        )
        self._queue.create_job(job)
        return job

    @staticmethod
    def _place_file(source: Path, target: Path, move: bool) -> None:
        """按 move 标志移动或复制源文件到目标位置。"""
        if move:
            shutil.move(str(source), str(target))
        else:
            shutil.copy2(str(source), str(target))

    # ------------------------------------------------------------------
    # 调度主循环
    # ------------------------------------------------------------------
    def _push_locked(self, job: BatchJob) -> None:
        """把任务放入内存优先级堆（须持有条件锁）。"""
        if job.job_id in self._queued_ids:
            return
        heapq.heappush(self._heap, (job.priority, job.seq, job.job_id))
        self._queued_ids.add(job.job_id)

    def _worker_loop(self, index: int) -> None:
        """worker 主循环：取任务、执行、释放，直到收到停止信号。"""
        while True:
            job = self._take_next()
            if job is None:
                return
            self._run_job(job)

    def _take_next(self) -> Optional[BatchJob]:
        """按优先级取出下一个资源允许执行的任务；停止时返回 None。"""
        with self._cond:
            while not self._stop:
                if self._heap:
                    _, _, job_id = self._heap[0]
                    job = self._queue.get_job(job_id)
                    if job is None or job.status != JobStatus.QUEUED:
                        # 记录已被外部推进（取消/重置），丢弃堆内条目。
                        heapq.heappop(self._heap)
                        self._queued_ids.discard(job_id)
                        continue
                    if self._resources_allow(job):
                        heapq.heappop(self._heap)
                        self._queued_ids.discard(job_id)
                        self._inflight_bytes += max(0, job.estimated_bytes)
                        return job
                # 队列为空或堆顶任务暂受资源限流，等待状态变化后重估。
                self._cond.wait(timeout=1.0)
            return None

    def _resources_allow(self, job: BatchJob) -> bool:
        """检查在途字节数与磁盘余量是否允许调度该任务。

        在途为空时总是放行：单个任务即使预估超过批量限流阈值也允许
        运行（其真实上限由单包安全阈值在解压时强制），避免阈值配置
        小于单包上限时任务永远饥饿。
        """
        estimate = max(0, job.estimated_bytes)
        limit = int(self._config.batch_max_inflight_bytes)
        if self._inflight_bytes > 0 and self._inflight_bytes + estimate > limit:
            return False
        try:
            free = shutil.disk_usage(str(self._config.temp_dir)).free
        except OSError:
            return False
        return free >= int(self._config.batch_min_free_bytes)

    def _run_job(self, job: BatchJob) -> None:
        """执行单个任务：状态推进、异常兜底、资源释放与文件清理。"""
        status, error = JobStatus.ERROR, ""
        try:
            self._queue.update_job(
                job.job_id, status=JobStatus.RUNNING, started_at=_now())
            prefinished = self._prefinished_status(job)
            if prefinished is not None:
                status = prefinished
            else:
                outcome = self._runner(job)
                task = outcome.get("task", {}) if isinstance(outcome, dict) else {}
                status = _TASK_STATUS_MAP.get(task.get("status"), JobStatus.ERROR)
                if status == JobStatus.ERROR:
                    error = (task.get("error_summary")
                             or "校验流水线未返回有效结果")[:500]
        except Exception as exc:  # 损坏包、包丢失、执行器崩溃等统一兜底。
            status = JobStatus.ERROR
            error = ("%s: %s" % (type(exc).__name__, exc))[:500]
        finally:
            # 在途计数与暂存文件必须释放，即使数据库更新本身失败，
            # 否则后续任务会被永久限流、暂存文件会堆积。
            with self._cond:
                self._inflight_bytes -= max(0, job.estimated_bytes)
                self._cond.notify_all()
            try:
                self._queue.update_job(
                    job.job_id, status=status, finished_at=_now(), error=error)
            finally:
                self._release_job_files(job)

    def _prefinished_status(self, job: BatchJob) -> Optional[str]:
        """协调重启恢复时已存在的校验记录，返回终态或 None（需要执行）。

        上次进程退出时任务可能已完成校验、但队列状态未及更新（tasks 表
        已是 passed/failed）——此时直接同步终态，不重复校验；也可能校验
        中断留下 running/error 残留记录——此时删除残留（其报告与日志会
        被重跑以同一任务 ID 覆盖生成），返回 None 让任务正常重跑。
        """
        existing = self._store.get_task(job.job_id)
        if existing is None:
            return None
        if existing.get("status") in _TASK_STATUS_MAP:
            return _TASK_STATUS_MAP[existing["status"]]
        self._store.delete_task(job.job_id)
        return None

    # ------------------------------------------------------------------
    # 资源清理
    # ------------------------------------------------------------------
    def _release_job_files(self, job: BatchJob) -> None:
        """释放任务占用的暂存文件；批次全部终态后清理整个批次目录。"""
        packet = (self._config.workspace_dir / job.packet_path).resolve()
        if self._inside_batch_area(packet):
            self._unlink_quiet(packet)
        if self._queue.count_active_in_batch(job.batch_id) == 0:
            batch_dir = self._config.batch_upload_dir / job.batch_id
            if self._inside_batch_area(batch_dir):
                shutil.rmtree(batch_dir, ignore_errors=True)

    def _inside_batch_area(self, path: Path) -> bool:
        """确认路径位于批量暂存区内，防止越界删除。"""
        try:
            path.relative_to(self._config.batch_upload_dir.resolve())
            return True
        except ValueError:
            return False

    @staticmethod
    def _unlink_quiet(path: Path) -> None:
        """尽力删除文件；被占用时保留，交由后续运维清理。"""
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def _cleanup_orphan_temp_dirs(self) -> None:
        """清理上次进程退出时残留的解压/上传临时目录。

        只在调度器启动时执行：此时本进程尚无任何在途任务，带既定前缀
        的目录一定是孤儿。批量暂存区（uploads/batch）不在清理范围，
        排队中的任务仍需要其中的数据包副本。
        """
        temp_dir = self._config.temp_dir
        try:
            entries = list(temp_dir.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_dir() and entry.name.startswith(_ORPHAN_PREFIXES):
                shutil.rmtree(entry, ignore_errors=True)

    # ------------------------------------------------------------------
    # 状态查询
    # ------------------------------------------------------------------
    def snapshot(self, recent_limit: int = 20) -> Dict[str, Any]:
        """返回队列实时状态，供页面与 JSON API 展示。"""
        with self._cond:
            inflight = self._inflight_bytes
        return {
            "started": self._started,
            "max_workers": int(self._config.batch_max_workers),
            "inflight_bytes": inflight,
            "max_inflight_bytes": int(self._config.batch_max_inflight_bytes),
            "min_free_bytes": int(self._config.batch_min_free_bytes),
            "queue_limit": int(self._config.batch_queue_limit),
            "queued": [job.to_dict() for job in
                       self._queue.list_jobs(status=JobStatus.QUEUED, limit=200)],
            "running": [job.to_dict() for job in
                        self._queue.list_jobs(status=JobStatus.RUNNING, limit=200)],
            "recent": [job.to_dict() for job in
                       self._queue.recent_terminal_jobs(limit=recent_limit)],
        }
