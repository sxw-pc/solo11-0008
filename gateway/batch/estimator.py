"""批量调度前的解压体积启发式预估。

调度器需要在任务入队时估算其解压后的磁盘占用，用于本地存储限流。
预估只读取压缩包的结构元数据，不做真实解压：

- zip：读取中央目录中各成员声明的未压缩大小并求和，O(条目数)；
- tar.gz：读取 gzip 尾部 ISIZE 字段（未压缩数据大小对 4 GiB 取模），O(1)；
- 无法识别或文件损坏：退回压缩包自身的文件大小，保证调度决策始终
  有一个保守下界可用；文件不可读时返回 0。

预估结果只用于调度限流，不影响校验结论；单包安全阈值仍由
``gateway.parser.archive_loader`` 在真实解压时严格执行。
"""

from pathlib import Path
import struct
import tarfile
import zipfile

_GZIP_MIN_BYTES = 18  # 最小 gzip 头（10）+ 尾（8）


def _zip_estimate(path: Path) -> int:
    """汇总 zip 中央目录声明的未压缩大小。"""
    with zipfile.ZipFile(path, "r") as archive:
        return sum(max(0, info.file_size) for info in archive.infolist()
                   if not info.is_dir())


def _tar_gzip_estimate(path: Path) -> int:
    """读取 gzip 尾部 ISIZE 作为 tar 内容大小估计。

    ISIZE 以 4 GiB 为模；当估值明显小于压缩包本身时判定发生回绕，
    退回压缩包文件大小作为保守下界。
    """
    file_size = path.stat().st_size
    if file_size < _GZIP_MIN_BYTES:
        return file_size
    with path.open("rb") as handle:
        handle.seek(-4, 2)
        (isize,) = struct.unpack("<I", handle.read(4))
    if isize == 0 or isize < file_size // 4:
        return file_size
    return int(isize)


def estimate_uncompressed_bytes(path: Path) -> int:
    """估算压缩包解压后的总字节数。

    Args:
        path: 本地压缩包路径。
    Returns:
        预估字节数，非负整数；任何异常都回落到保守估计而不会抛出。
        压缩包内容不可信，解析过程可能抛出任意异常（EOFError、
        ValueError 等），这里统一兜底。
    """
    path = Path(path)
    try:
        if zipfile.is_zipfile(path):
            return _zip_estimate(path)
    except Exception:
        pass
    try:
        if tarfile.is_tarfile(path) or _looks_like_gzip(path):
            return _tar_gzip_estimate(path)
    except Exception:
        pass
    try:
        return max(0, path.stat().st_size)
    except OSError:
        return 0


def _looks_like_gzip(path: Path) -> bool:
    """按魔数快速判断 gzip，避免 tarfile 对损坏文件做全格式探测。"""
    try:
        with path.open("rb") as handle:
            return handle.read(2) == b"\x1f\x8b"
    except OSError:
        return False
