"""临时资源生命周期注册与回收。

集中登记本进程创建的解压临时目录，保证以下场景都能回收磁盘空间：

- 任务正常结束：流水线 ``finally`` 主动清理；
- 阶段抛出未捕获异常：``finally``、上下文管理器与对象终结器兜底；
- 进程收到终止信号或解释器正常退出：SIGTERM 链式处理器与 ``atexit`` 钩子；
- 进程被强杀等极端情况：下次启动时按目录年龄清扫残留目录。

所有回收操作只针对本进程登记过、或超过存活阈值且未被登记的 ``gateway-*``
目录，同一工作目录下并发执行的其他任务的临时文件不会被误删。仅使用标准库。
"""

import atexit
import os
from pathlib import Path
import shutil
import signal
import threading
import time
from typing import List, Optional, Tuple

TEMP_PREFIX = "gateway-"
DEFAULT_STALE_MAX_AGE_SECONDS = 24 * 3600


class TempDirRegistry:
    """登记并回收本进程拥有的临时目录，线程安全。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owned = set()  # type: set

    def register(self, path: Path) -> Path:
        """登记一个本进程拥有的临时目录并原样返回。"""
        path = Path(path)
        with self._lock:
            self._owned.add(path)
        return path

    def unregister(self, path: Path) -> None:
        """撤销登记；未登记的路径调用安全。"""
        with self._lock:
            self._owned.discard(Path(path))

    def is_registered(self, path: Path) -> bool:
        """判断路径是否仍由本进程登记持有。"""
        with self._lock:
            return Path(path) in self._owned

    def owned(self) -> List[Path]:
        """返回当前登记的全部目录快照。"""
        with self._lock:
            return sorted(self._owned)

    def cleanup_all(self) -> None:
        """清理全部仍登记的目录；重复调用安全，异常不向上抛。"""
        with self._lock:
            paths = list(self._owned)
        for path in paths:
            try:
                shutil.rmtree(path, ignore_errors=True)
            except Exception:  # 解释器退出阶段模块可能已部分卸载。
                pass
            finally:
                try:
                    self.unregister(path)
                except Exception:
                    pass


#: 进程级单例；解压模块在创建临时目录后登记，清理后注销。
REGISTRY = TempDirRegistry()

atexit.register(REGISTRY.cleanup_all)

_installed_signals = set()  # type: set
_install_lock = threading.Lock()


def install_signal_cleanup(signals: Optional[Tuple[int, ...]] = None) -> bool:
    """为终止信号安装链式清理处理器，返回本次是否新装了处理器。

    仅在主线程生效；重复调用对同一信号只安装一次，避免处理器链无限增长。
    清理完成后按原处理器语义继续：原先是可调用处理器则链式调用，原先
    是忽略则保持忽略，否则恢复默认行为并重新发送信号以正确退出。
    """
    if threading.current_thread() is not threading.main_thread():
        return False
    targets = signals if signals is not None else (signal.SIGTERM,)
    installed = False
    with _install_lock:
        for sig in targets:
            if sig in _installed_signals:
                continue
            try:
                previous = signal.getsignal(sig)
            except (ValueError, OSError):
                continue

            def handler(signum, frame, _previous=previous, _sig=sig):
                REGISTRY.cleanup_all()
                if callable(_previous):
                    _previous(signum, frame)
                elif _previous == signal.SIG_IGN:
                    return
                else:
                    signal.signal(_sig, signal.SIG_DFL)
                    os.kill(os.getpid(), _sig)

            try:
                signal.signal(sig, handler)
            except (ValueError, OSError, RuntimeError):
                continue
            _installed_signals.add(sig)
            installed = True
    return installed


def sweep_stale_temp_dirs(temp_root: Path,
                          max_age_seconds: float = DEFAULT_STALE_MAX_AGE_SECONDS,
                          prefix: str = TEMP_PREFIX,
                          now: Optional[float] = None) -> List[Path]:
    """清扫 ``temp_root`` 下超过存活阈值的遗留临时目录。

    仅处理名称以 ``prefix`` 开头、且未被本进程登记的目录；目录年龄按
    mtime 计算，正在运行的其他任务（目录较新或已登记）不受影响。任何
    单个目录的失败都不会中断整体清扫，也不会向上抛异常。

    Returns:
        实际删除成功的目录列表。
    """
    removed: List[Path] = []
    root = Path(temp_root)
    try:
        entries = list(root.iterdir())
    except OSError:
        return removed
    current = time.time() if now is None else now
    for entry in entries:
        try:
            if not entry.is_dir() or not entry.name.startswith(prefix):
                continue
            if REGISTRY.is_registered(entry):
                continue
            age = current - entry.stat().st_mtime
            if age < max_age_seconds:
                continue
            shutil.rmtree(entry, ignore_errors=True)
            if not entry.exists():
                removed.append(entry)
        except OSError:
            continue
    return removed
