"""临时资源注册、异常回收与残留清扫单元测试。"""

import gc
import os
from pathlib import Path
import signal
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from gateway import resource
from gateway.parser.archive_loader import load_archive
from gateway.resource import (REGISTRY, TempDirRegistry, install_signal_cleanup,
                              sweep_stale_temp_dirs)

ROOT = Path(__file__).resolve().parents[2]
VALID_PACKET = ROOT / "fixtures" / "valid_packets" / "retail_valid_a.zip"


def test_registry_cleanup_only_removes_registered(tmp_path):
    registry = TempDirRegistry()
    owned = tmp_path / "gateway-owned"
    other = tmp_path / "gateway-other"
    owned.mkdir()
    other.mkdir()
    (owned / "data.txt").write_text("x", encoding="utf-8")
    registry.register(owned)
    assert registry.is_registered(owned)
    assert registry.owned() == [owned]
    registry.cleanup_all()
    assert not owned.exists()
    assert other.exists(), "未登记的目录不得被误删"
    assert registry.owned() == []
    registry.cleanup_all()  # 重复调用安全


def test_registry_unregister_is_idempotent(tmp_path):
    registry = TempDirRegistry()
    path = tmp_path / "gateway-x"
    path.mkdir()
    registry.register(path)
    registry.unregister(path)
    registry.unregister(path)
    assert not registry.is_registered(path)
    registry.cleanup_all()
    assert path.exists(), "已注销的目录不属于本注册表管理"


def test_extraction_registers_and_cleanup_unregisters(config):
    result = load_archive(VALID_PACKET, config)
    temp_dir = result.temp_dir
    assert REGISTRY.is_registered(temp_dir)
    result.cleanup()
    assert not temp_dir.exists()
    assert not REGISTRY.is_registered(temp_dir)
    result.cleanup()  # 重复清理安全


def test_extraction_finalizer_cleans_temp_dir(config):
    result = load_archive(VALID_PACKET, config)
    temp_dir = result.temp_dir
    assert temp_dir.is_dir()
    del result
    gc.collect()
    assert not temp_dir.exists(), "对象回收时应兜底清理临时目录"
    assert not REGISTRY.is_registered(temp_dir)


def test_concurrent_extractions_do_not_interfere(config):
    first = load_archive(VALID_PACKET, config)
    second = load_archive(VALID_PACKET, config)
    try:
        assert first.temp_dir != second.temp_dir, "并发任务临时目录不得重名"
        first.cleanup()
        assert not first.temp_dir.exists()
        assert second.temp_dir.is_dir(), "清理任务一不得影响任务二的文件"
        assert (second.temp_dir / "manifest.yaml").is_file()
    finally:
        second.cleanup()
    assert not second.temp_dir.exists()


def test_sweep_removes_only_stale_gateway_dirs(tmp_path, config):
    stale = tmp_path / "gateway-stale1"
    fresh = tmp_path / "gateway-fresh1"
    other = tmp_path / "upload-keep"
    stray_file = tmp_path / "gateway-not-a-dir"
    for folder in (stale, fresh, other):
        folder.mkdir()
        (folder / "junk.txt").write_text("x", encoding="utf-8")
    stray_file.write_text("x", encoding="utf-8")
    old = time.time() - 48 * 3600
    os.utime(stale, (old, old))
    os.utime(other, (old, old))
    os.utime(stray_file, (old, old))
    # 已登记（模拟其他在途任务持有）的目录即使超龄也不得删除。
    active = tmp_path / "gateway-active1"
    active.mkdir()
    os.utime(active, (old, old))
    REGISTRY.register(active)
    try:
        removed = sweep_stale_temp_dirs(tmp_path, max_age_seconds=3600)
        assert removed == [stale]
        assert not stale.exists()
        for kept in (fresh, other, stray_file, active):
            assert kept.exists(), "%s 不应被清扫" % kept.name
    finally:
        REGISTRY.unregister(active)


def test_sweep_tolerates_missing_root(tmp_path):
    assert sweep_stale_temp_dirs(tmp_path / "missing") == []


def test_install_signal_cleanup_is_idempotent():
    previous = signal.getsignal(signal.SIGTERM)
    resource._installed_signals.discard(signal.SIGTERM)
    try:
        assert install_signal_cleanup() is True
        assert install_signal_cleanup() is False, "同一信号不应重复安装"
        assert callable(signal.getsignal(signal.SIGTERM))
    finally:
        signal.signal(signal.SIGTERM, previous)
        resource._installed_signals.discard(signal.SIGTERM)


def test_install_signal_cleanup_skips_worker_thread():
    outcome = []

    def worker():
        outcome.append(install_signal_cleanup())

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    assert outcome == [False], "非主线程不得安装信号处理器"


def test_atexit_cleans_unclosed_extraction(tmp_path):
    """子进程正常退出但未主动清理时，atexit 钩子应回收临时目录。"""
    script = textwrap.dedent("""
        import sys
        sys.path.insert(0, {root!r})
        from gateway.config import AppConfig
        from gateway.parser.archive_loader import load_archive
        config = AppConfig(workspace_dir={ws!r})
        result = load_archive({packet!r}, config)
        print(result.temp_dir, flush=True)
        # 不调用 cleanup，直接退出，模拟遗漏清理的代码路径。
    """.format(root=str(ROOT), ws=str(tmp_path / "ws"), packet=str(VALID_PACKET)))
    proc = subprocess.run([sys.executable, "-I", "-c", script],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    temp_dir = Path(proc.stdout.strip())
    assert not temp_dir.exists(), "进程退出后临时目录应被 atexit 回收"


@pytest.mark.skipif(sys.platform.startswith("win"),
                    reason="Windows  terminate 无 POSIX 信号处理语义")
def test_sigterm_triggers_cleanup_in_subprocess(tmp_path):
    """进程被 SIGTERM 终止时，信号处理器应回收在途临时目录。"""
    script = textwrap.dedent("""
        import sys
        import time
        sys.path.insert(0, {root!r})
        from gateway.config import AppConfig
        from gateway.parser.archive_loader import load_archive
        from gateway.resource import install_signal_cleanup
        config = AppConfig(workspace_dir={ws!r})
        install_signal_cleanup()
        result = load_archive({packet!r}, config)
        print(result.temp_dir, flush=True)
        time.sleep(60)
    """.format(root=str(ROOT), ws=str(tmp_path / "ws"), packet=str(VALID_PACKET)))
    proc = subprocess.Popen([sys.executable, "-I", "-c", script],
                            stdout=subprocess.PIPE, text=True)
    try:
        temp_dir = Path(proc.stdout.readline().strip())
        assert temp_dir.is_dir()
        proc.terminate()
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
    assert not temp_dir.exists(), "SIGTERM 终止后临时目录应被回收"
