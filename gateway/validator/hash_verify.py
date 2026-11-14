"""文件哈希、完整性、冗余文件与高危可执行文件检测。"""

from fnmatch import fnmatch
from hashlib import md5, sha256
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

from ..config import AppConfig

MANIFEST_NAME = "manifest.yaml"


def _normalize_relpath(value: Any) -> str:
    """把 manifest 中的相对路径归一化为压缩包内 POSIX 形式。

    统一反斜杠、折叠 ``./``、重复斜杠与空段，使 ``./data/users.csv``、
    ``data//users.csv`` 与 ``data/./users.csv`` 都归一到 ``data/users.csv``。
    与归档解压时的 :func:`_normalize_member` 口径保持一致，但不在此抛安全
    异常——越界路径在解压阶段已被拒绝，这里仅做字符串归一。
    """
    text = str(value).replace("\\", "/")
    parts = [part for part in PurePosixPath(text).parts if part not in ("", ".")]
    return "/".join(parts)


def compute_file_hashes(path: Path) -> Dict[str, str]:
    """以流式方式计算文件 MD5 与 SHA256。

    Args:
        path: 待计算文件。
    Returns:
        含 ``md5``、``sha256`` 与 ``size`` 的字典。
    Raises:
        OSError: 文件无法读取。
    """
    md5_digest = md5()
    sha_digest = sha256()
    size = 0
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            md5_digest.update(chunk)
            sha_digest.update(chunk)
    return {"md5": md5_digest.hexdigest(), "sha256": sha_digest.hexdigest(), "size": size}


def is_dangerous_file(relative: str, config: AppConfig) -> bool:
    """根据扩展名判断文件是否属于高危可执行/脚本黑名单。"""
    suffix = Path(str(relative).replace("\\", "/")).suffix.lower()
    return suffix in config.blocked_extensions


def _allowed_extra(relative: str, config: AppConfig) -> bool:
    """判断未声明文件是否命中配置的额外白名单。"""
    normalized = str(relative).replace("\\", "/")
    return any(fnmatch(normalized, pattern) for pattern in config.allowed_extra_paths)


def _parse_expected_hash(expected: str) -> Dict[str, str]:
    """解析 ``algo:digest`` 或按长度识别 MD5/SHA256。"""
    value = str(expected).strip().lower()
    if ":" in value:
        algorithm, digest = value.split(":", 1)
        if algorithm in ("md5", "sha256"):
            return {algorithm: digest}
        raise ValueError("预期哈希算法仅支持 md5 或 sha256")
    if len(value) == 32:
        return {"md5": value}
    if len(value) == 64:
        return {"sha256": value}
    raise ValueError("预期哈希格式不正确，应为 md5/sha256 摘要或 algo:digest")


def verify_package_hash(package_path: Path, expected: str) -> Dict[str, Any]:
    """校验压缩包自身哈希，供上传时可选填写预期值。

    Returns:
        包含 passed、algorithm、expected、actual 的结果字典。
    Raises:
        ValueError: 预期哈希格式非法。
    """
    parsed = _parse_expected_hash(expected)
    actual = compute_file_hashes(package_path)
    errors = []
    for algorithm, digest in parsed.items():
        if actual[algorithm].lower() != digest:
            errors.append({
                "code": "package_hash_mismatch",
                "message": "压缩包 %s 哈希不一致" % algorithm.upper(),
                "path": Path(package_path).name,
                "expected": digest,
                "actual": actual[algorithm],
            })
    return {
        "passed": not errors,
        "algorithm": next(iter(parsed)),
        "expected": next(iter(parsed.values())),
        "actual": actual[next(iter(parsed))],
        "errors": errors,
    }


def verify_hashes(extract_root: Path, manifest: Dict[str, Any], config: AppConfig,
                  expected_package_hash: Optional[str] = None,
                  package_path: Optional[Path] = None) -> Dict[str, Any]:
    """对解压文件执行哈希、缺失、冗余与恶意文件校验。

    manifest.files 中键为相对路径，值至少包含 md5 或 sha256。未被声明且不在
    白名单内的文件会被标记为冗余；exe/sh/py 等扩展名会触发高危告警。

    Args:
        extract_root: 解压临时目录。
        manifest: 已解析的 manifest 字典。
        config: 黑名单与白名单配置。
        expected_package_hash: 可选的压缩包预期哈希。
        package_path: 压缩包原始路径，用于包哈希校验。
    Returns:
        统一格式的校验结果字典，含 errors 与 checked_files。
    """
    extract_root = Path(extract_root)
    raw_declared = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
    actual_files = []
    for path in sorted(extract_root.rglob("*")):
        if path.is_file():
            relative = path.relative_to(extract_root).as_posix()
            actual_files.append((relative, path))
    actual_names = {relative for relative, _ in actual_files}
    # 同时提供精确与小写两个索引，兼容 manifest 与磁盘大小写不一致的场景。
    actual_lower = {name.lower(): name for name in actual_names}
    errors: List[Dict[str, Any]] = []

    def _resolve_actual(relative: str) -> Optional[str]:
        """把归一化声明路径解析为磁盘上的实际相对路径，大小写不敏感。"""
        if relative in actual_names:
            return relative
        return actual_lower.get(relative.lower())

    declared_norm: Dict[str, Dict[str, Any]] = {}
    for key, value in raw_declared.items():
        normalized = _normalize_relpath(key)
        if not normalized:
            continue
        if normalized in declared_norm:
            errors.append({
                "code": "duplicate_declaration", "path": normalized,
                "message": "manifest 存在指向同一文件的重复声明: %s" % key,
            })
            continue
        declared_norm[normalized] = value
    checked = 0
    for relative, value in declared_norm.items():
        if relative == MANIFEST_NAME:
            continue
        actual_relative = _resolve_actual(relative)
        if actual_relative is None:
            errors.append({
                "code": "missing_file", "path": relative,
                "message": "manifest 声明的文件缺失",
            })
            continue
        if not isinstance(value, dict):
            errors.append({
                "code": "invalid_hash_declaration", "path": relative,
                "message": "manifest 哈希声明格式错误",
            })
            continue
        expected_md5 = value.get("md5")
        expected_sha = value.get("sha256")
        if not expected_md5 and not expected_sha:
            errors.append({
                "code": "missing_hash_declaration", "path": relative,
                "message": "manifest 未声明 MD5 或 SHA256",
            })
            continue
        computed = compute_file_hashes(extract_root / actual_relative)
        checked += 1
        if expected_md5 and computed["md5"].lower() != str(expected_md5).lower():
            errors.append({
                "code": "hash_mismatch", "path": relative, "algorithm": "md5",
                "expected": str(expected_md5), "actual": computed["md5"],
                "message": "文件 MD5 哈希不一致，疑似被篡改",
            })
        if expected_sha and computed["sha256"].lower() != str(expected_sha).lower():
            errors.append({
                "code": "hash_mismatch", "path": relative, "algorithm": "sha256",
                "expected": str(expected_sha), "actual": computed["sha256"],
                "message": "文件 SHA256 哈希不一致，疑似被篡改",
            })
    declared_lower = {name.lower() for name in declared_norm}
    for relative, _ in actual_files:
        if relative == MANIFEST_NAME:
            continue
        if is_dangerous_file(relative, config):
            errors.append({
                "code": "dangerous_file", "path": relative,
                "message": "检测到高危可执行或脚本文件",
            })
        if relative.lower() not in declared_lower and not _allowed_extra(relative, config):
            errors.append({
                "code": "redundant_file", "path": relative,
                "message": "检测到 manifest 未声明的冗余文件",
            })
    package_result = None
    if expected_package_hash:
        if package_path is None:
            errors.append({
                "code": "package_hash_unavailable",
                "message": "缺少压缩包路径，无法执行整包哈希校验",
            })
        else:
            try:
                package_result = verify_package_hash(package_path, expected_package_hash)
                errors.extend(package_result["errors"])
            except ValueError as exc:
                errors.append({"code": "invalid_expected_hash", "message": str(exc)})
    codes = sorted({error["code"] for error in errors})
    return {
        "key": "hash", "name": "文件完整性与哈希校验", "passed": not errors,
        "checked_files": checked, "declared_files": len(declared_norm),
        "actual_files": len(actual_names), "errors": errors[:100],
        "error_codes": codes, "package_hash": package_result,
        "summary": ("全部文件哈希与完整性校验通过" if not errors
                    else "发现 %d 项完整性问题: %s" % (len(errors), "、".join(codes))),
    }
