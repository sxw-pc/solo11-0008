"""压缩包安全检查、解压与清单解析。

本模块仅使用标准库完成 zip/tar.gz 处理。所有成员路径先经过规范化与
``..``/绝对路径检查，再逐个流式解压到工作目录内的随机临时目录，避免
``extractall`` 的路径穿越风险。压缩包必须包含根目录 manifest.yaml。
"""

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile
from typing import Any, Dict, List, Optional
import zipfile

import yaml

from ..config import AppConfig

if sys.platform.startswith("win"):  # Windows 缺少 libmagic，导入可能阻塞。
    _magic = None
else:  # pragma: no cover - 平台相关
    try:
        import magic as _magic  # type: ignore
    except Exception:
        _magic = None

MANIFEST_NAME = "manifest.yaml"
MANIFEST_MAX_BYTES = 1024 * 1024
_DRIVE_RE = re.compile(r"^[a-zA-Z]:")


class ArchiveError(Exception):
    """压缩包格式错误或清单缺失。"""


class SecurityError(ArchiveError):
    """压缩包触发路径穿越、炸弹或危险文件规则。"""


@dataclass
class ExtractionResult:
    """一次安全解压的结果。

    Attributes:
        temp_dir: 本次任务专属临时目录。
        archive_type: ``zip`` 或 ``tar.gz``。
        files: 已解压文件描述列表（相对路径、字节数）。
        manifest: 解析后的 manifest.yaml 字典。
        mime_type: 可选的文件 MIME 类型。
    """

    temp_dir: Path
    archive_type: str
    files: List[Dict[str, Any]]
    manifest: Dict[str, Any]
    mime_type: str = "application/octet-stream"
    _cleaned: bool = field(default=False, init=False)

    def safe_path(self, relative: str) -> Path:
        """取得临时目录内的文件绝对路径，拒绝任何越界路径。

        当清单中的路径与解压文件仅存在 ``./``、``//``、反斜杠或大小写
        差异时，按归一化形式回退定位真实文件，保证合法包不会因等价写法
        被误报缺失；越界检查仍在回退前完成。
        """
        candidate = _safe_join(self.temp_dir, relative)
        if candidate.exists():
            return candidate
        normalized = normalize_relative_path(relative)
        if not normalized:
            return candidate
        for path in self.temp_dir.rglob("*"):
            if path.is_file() and normalize_relative_path(
                    path.relative_to(self.temp_dir).as_posix()) == normalized:
                return path
        return candidate

    def cleanup(self) -> None:
        """删除临时解压目录；重复调用安全。"""
        if not self._cleaned:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self._cleaned = True

    def __enter__(self) -> "ExtractionResult":
        """支持 with 语句自动清理。"""
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """退出上下文时清理临时文件。"""
        self.cleanup()


def normalize_relative_path(value: str) -> str:
    """把清单键或相对路径折叠为可比较形式，用于等价路径匹配。

    仅处理语义等价差异：``./`` 前缀、重复 ``/``、反斜杠、首尾空白与
    大小写。不执行越界判定，调用方仍需先完成安全检查。

    Args:
        value: 原始相对路径或 manifest 键。
    Returns:
        POSIX 分隔、无空段的小写相对路径。
    """
    parts = [part for part in PurePosixPath(
        str(value).strip().replace("\\", "/")).parts
        if part not in ("", ".", "/")]
    return "/".join(parts).lower()


def _safe_join(root: Path, relative: str) -> Path:
    """将相对路径拼接到 root，并确认结果仍位于 root 下。"""
    candidate = (root / relative).resolve()
    root_resolved = root.resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise SecurityError("检测到路径穿越: %s" % relative) from exc
    return candidate


def _normalize_member(name: str) -> str:
    """规范化压缩包成员名并执行路径安全检查。

    反斜杠在 Windows 上具备目录分隔语义，因此统一按 ``/`` 处理。拒绝空名、
    NUL、绝对路径、盘符以及任何 ``..`` 片段。
    """
    if not name or "\x00" in name:
        raise SecurityError("压缩包包含非法成员名")
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("/") or _DRIVE_RE.match(normalized):
        raise SecurityError("压缩包包含绝对路径: %s" % name)
    parts = [part for part in PurePosixPath(normalized).parts if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise SecurityError("压缩包包含路径穿越: %s" % name)
    if not parts:
        raise SecurityError("压缩包包含空路径")
    return "/".join(parts)


def detect_archive_type(path: Path) -> str:
    """按文件内容识别 zip/tar.gz，不依赖扩展名或系统解压命令。"""
    path = Path(path)
    if not path.is_file():
        raise ArchiveError("待校验文件不存在")
    try:
        with path.open("rb") as handle:
            head = handle.read(4)
    except OSError as exc:
        raise ArchiveError("无法读取压缩包: %s" % exc) from exc
    if head.startswith(b"PK") and zipfile.is_zipfile(path):
        return "zip"
    if head.startswith(b"\x1f\x8b") and tarfile.is_tarfile(path):
        return "tar.gz"
    raise ArchiveError("仅支持 zip 或 tar.gz 格式的压缩包")


def _mime_type(path: Path) -> str:
    """使用 python-magic（可用时）识别 MIME，否则退回安全默认值。"""
    if _magic is None:
        return "application/octet-stream"
    try:  # pragma: no cover - 依赖本机 libmagic
        return str(_magic.from_file(str(path), mime=True))
    except Exception:  # pragma: no cover
        return "application/octet-stream"


def _check_size(total: int, size: int, config: AppConfig, label: str) -> int:
    """累计解压大小并执行单文件、总量与压缩比阈值校验。"""
    if size < 0:
        raise SecurityError("压缩包声明了非法文件大小: %s" % label)
    total += size
    if size > config.max_single_file_bytes:
        raise SecurityError("单文件解压后超过上限: %s" % label)
    if total > config.max_uncompressed_bytes:
        raise SecurityError("解压后总大小超过 %d 字节，疑似 Zip 炸弹"
                            % config.max_uncompressed_bytes)
    return total


def _inspect_zip(path: Path, config: AppConfig) -> Dict[str, Any]:
    """检查 zip 中央目录，提前拦截加密、链接、越界与压缩比异常。"""
    infos = []
    names = set()
    total = 0
    with zipfile.ZipFile(path, "r") as archive:
        raw_infos = archive.infolist()
        if len(raw_infos) > config.max_archive_entries:
            raise SecurityError("压缩包条目数超过上限")
        for info in raw_infos:
            normalized = _normalize_member(info.filename)
            if normalized in names:
                raise SecurityError("压缩包包含重复成员: %s" % normalized)
            names.add(normalized)
            if info.flag_bits & 0x1:
                raise SecurityError("不支持加密压缩包")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise SecurityError("压缩包包含符号链接: %s" % normalized)
            if info.is_dir():
                continue
            total = _check_size(total, info.file_size, config, normalized)
            ratio_guard = (info.file_size >= config.ratio_check_min_bytes
                           and info.compress_size > 0
                           and info.file_size / info.compress_size
                           > config.max_compression_ratio)
            if ratio_guard:
                raise SecurityError("检测到疑似 Zip 炸弹条目: %s" % normalized)
            infos.append((info, normalized))
    if MANIFEST_NAME not in names:
        raise ArchiveError("压缩包根目录缺少 manifest.yaml")
    return {"members": infos, "total": total}


def _inspect_tar(path: Path, config: AppConfig) -> Dict[str, Any]:
    """检查 tar.gz 成员类型、路径和声明大小。"""
    members = []
    names = set()
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        raw_members = archive.getmembers()
        if len(raw_members) > config.max_archive_entries:
            raise SecurityError("压缩包条目数超过上限")
        for member in raw_members:
            normalized = _normalize_member(member.name)
            if normalized in names:
                raise SecurityError("压缩包包含重复成员: %s" % normalized)
            names.add(normalized)
            if member.issym() or member.islnk():
                raise SecurityError("压缩包包含链接文件: %s" % normalized)
            if not (member.isfile() or member.isdir()):
                raise SecurityError("压缩包包含特殊设备文件: %s" % normalized)
            if member.isdir():
                continue
            total = _check_size(total, member.size, config, normalized)
            members.append((member, normalized))
    if MANIFEST_NAME not in names:
        raise ArchiveError("压缩包根目录缺少 manifest.yaml")
    return {"members": members, "total": total}


def _extract_zip(path: Path, temp_dir: Path, inspected: Dict[str, Any]) -> List[Dict[str, Any]]:
    """流式解压 zip 成员并在每次写入时校验实际大小。"""
    files = []
    with zipfile.ZipFile(path, "r") as archive:
        for info, normalized in inspected["members"]:
            target = _safe_join(temp_dir, normalized)
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info, "r") as src, target.open("wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > info.file_size:
                        raise SecurityError("解压数据超过声明大小: %s" % normalized)
                    dst.write(chunk)
            files.append({"path": normalized, "size": written})
    return files


def _extract_tar(path: Path, temp_dir: Path, inspected: Dict[str, Any]) -> List[Dict[str, Any]]:
    """流式解压 tar.gz 并阻止实际字节数超出声明大小。"""
    files = []
    with tarfile.open(path, "r:gz") as archive:
        for member, normalized in inspected["members"]:
            src = archive.extractfile(member)
            if src is None:
                raise ArchiveError("无法读取成员: %s" % normalized)
            target = _safe_join(temp_dir, normalized)
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with src, target.open("wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > member.size:
                        raise SecurityError("解压数据超过声明大小: %s" % normalized)
                    dst.write(chunk)
            files.append({"path": normalized, "size": written})
    return files


def _parse_manifest(temp_dir: Path) -> Dict[str, Any]:
    """读取并校验根目录 manifest.yaml 的基础结构。"""
    manifest_path = _safe_join(temp_dir, MANIFEST_NAME)
    if not manifest_path.is_file():
        raise ArchiveError("压缩包根目录缺少 manifest.yaml")
    if manifest_path.stat().st_size > MANIFEST_MAX_BYTES:
        raise SecurityError("manifest.yaml 体积异常")
    try:
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise ArchiveError("manifest.yaml 解析失败: %s" % exc) from exc
    if not isinstance(data, dict):
        raise ArchiveError("manifest.yaml 根节点必须是映射")
    if not isinstance(data.get("files", {}), dict):
        raise ArchiveError("manifest.yaml 的 files 必须为映射")
    if not isinstance(data.get("tables", {}), dict):
        raise ArchiveError("manifest.yaml 的 tables 必须为映射")
    return data


def load_archive(path: Path, config: AppConfig) -> ExtractionResult:
    """安全加载压缩包并返回解压结果。

    Args:
        path: 本地 zip/tar.gz 文件路径。
        config: 全局配置，提供大小、条目数与压缩比阈值。
    Returns:
        ExtractionResult: 临时目录、文件列表和 manifest 数据。
    Raises:
        ArchiveError: 格式不支持、清单缺失或内容损坏。
        SecurityError: 命中路径穿越、Zip 炸弹、链接文件等规则。
    """
    path = Path(path).resolve()
    archive_type = detect_archive_type(path)
    temp_dir = Path(tempfile.mkdtemp(prefix="gateway-", dir=str(config.temp_dir)))
    try:
        inspected = (_inspect_zip(path, config) if archive_type == "zip"
                     else _inspect_tar(path, config))
        files = (_extract_zip(path, temp_dir, inspected) if archive_type == "zip"
                 else _extract_tar(path, temp_dir, inspected))
        manifest = _parse_manifest(temp_dir)
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    return ExtractionResult(
        temp_dir=temp_dir,
        archive_type=archive_type,
        files=files,
        manifest=manifest,
        mime_type=_mime_type(path),
    )


def lookup_manifest_file(manifest: Dict[str, Any], relative: str) -> Optional[Dict[str, Any]]:
    """在 manifest.files 中查询声明，支持 ``./`` 前缀归一化。"""
    normalized = _normalize_member(relative)
    for key, value in manifest.get("files", {}).items():
        if _normalize_member(str(key)) == normalized:
            return value if isinstance(value, dict) else {}
    return None
