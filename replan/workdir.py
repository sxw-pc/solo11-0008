"""隔离临时工作目录与可靠清理。

每次分析在指定根目录下创建独立的 ``replan-<pid>-<uuid8>`` 目录：

* 目录名含进程号与随机 UUID，两次并发分析同一输入目录也互不干扰；
* 输入数据包始终只读流式访问，不向输入目录写入任何内容；
* 正常结束、异常退出均通过 :meth:`WorkDir.cleanup` 清理；
* 进程被中断（SIGINT/SIGTERM）时由 atexit/信号处理兜底清理；
* 清理采用 ``shutil.rmtree(ignore_errors=True)``，单个残留文件不会掩盖
  原始异常；同时提供 :func:`cleanup_stale` 清理历史崩溃遗留目录。
"""

import atexit
import os
from pathlib import Path
import shutil
import signal
import tempfile
import uuid

_PREFIX = "replan-"
_REGISTERED = set()


def _cleanup_path(path):
    shutil.rmtree(path, ignore_errors=True)


def _atexit_cleanup():
    for path in list(_REGISTERED):
        _cleanup_path(path)


atexit.register(_atexit_cleanup)


class WorkDir:
    """单次分析专属临时目录的上下文管理器。"""

    def __init__(self, base_dir=None):
        base = Path(base_dir) if base_dir else Path(tempfile.gettempdir())
        base.mkdir(parents=True, exist_ok=True)
        name = "%s%d-%s" % (_PREFIX, os.getpid(), uuid.uuid4().hex[:8])
        self.path = base / name
        self._cleaned = False

    def __enter__(self):
        self.path.mkdir(parents=True, exist_ok=False)
        _REGISTERED.add(str(self.path))
        self._install_signal_handlers()
        return self.path

    def __exit__(self, exc_type, exc, tb):
        self.cleanup()
        return False

    def cleanup(self):
        """删除临时目录；重复调用安全，绝不抛出异常。"""
        if self._cleaned:
            return
        self._cleaned = True
        _REGISTERED.discard(str(self.path))
        _cleanup_path(self.path)

    def _install_signal_handlers(self):
        """在收到中断信号时先清理临时目录再按默认行为终止。"""
        self._previous = {}
        for sig_name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, sig_name, None)
            if sig is None:
                continue
            try:
                previous = signal.getsignal(sig)
            except (ValueError, OSError):
                continue

            def handler(signum, frame, _sig=sig, _prev=previous):
                self.cleanup()
                if callable(_prev):
                    _prev(signum, frame)
                elif _prev == signal.SIG_IGN:
                    return
                else:
                    # 默认动作：恢复默认处理器后重新抛出信号。
                    signal.signal(_sig, signal.SIG_DFL)
                    os.kill(os.getpid(), _sig)

            try:
                signal.signal(sig, handler)
                self._previous[sig] = previous
            except (ValueError, OSError):
                # 非主线程或受限环境无法注册信号，atexit 仍然兜底。
                pass


def cleanup_stale(base_dir=None):
    """清理 base_dir 下历史崩溃遗留的 ``replan-*`` 目录。

    仅清理目录前缀完全匹配、且不属于当前存活进程的目录；判断失败时
    保守跳过，避免误删并发运行中的目录。
    """
    base = Path(base_dir) if base_dir else Path(tempfile.gettempdir())
    if not base.is_dir():
        return 0
    removed = 0
    alive = set()
    for entry in sorted(base.iterdir()):
        if not entry.is_dir() or not entry.name.startswith(_PREFIX):
            continue
        parts = entry.name[len(_PREFIX):].split("-", 1)
        owner_pid = int(parts[0]) if parts and parts[0].isdigit() else -1
        if owner_pid == os.getpid() or owner_pid in alive:
            continue
        if owner_pid > 0 and _pid_alive(owner_pid):
            continue
        _cleanup_path(entry)
        removed += 1
    return removed


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True
