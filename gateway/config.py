"""全局配置加载、校验与目录初始化。

配置优先级：构造参数 / YAML 文件 > 环境变量 > 默认值。默认服务只监听
127.0.0.1，工作目录位于项目根目录下的 workspace，便于离线部署与清理。
"""

from dataclasses import dataclass, field, fields
from hashlib import sha256
from pathlib import Path
import json
import os
from typing import Any, Dict, Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKSPACE = PROJECT_ROOT / "workspace"
DEFAULT_CONTRACT = PROJECT_ROOT / "fixtures" / "mock_contract" / "user_trade_contract.yaml"
DEFAULT_LINEAGE = PROJECT_ROOT / "fixtures" / "mock_lineage" / "trade_lineage_rule.yaml"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

#: 支持通过 GATEWAY_ 前缀环境变量覆盖的数值/整型配置项。
_INT_ENV_KEYS = (
    "port", "random_seed", "max_uncompressed_bytes", "max_single_file_bytes",
    "max_archive_entries", "ratio_check_min_bytes", "max_content_length",
)
_FLOAT_ENV_KEYS = ("sample_ratio", "max_compression_ratio")
_ENV_KEY_ALIASES = {"GATEWAY_MAX_ENTRIES": "max_archive_entries"}


def _coerce_int(value: Any, name: str) -> int:
    """把任意来源（YAML、环境变量、构造参数）的值严格转为 int。

    接受 int、可解析为整数的 str（去掉首尾空白）以及 bool 之外的数值；
    浮点字符串、含非数字字符或空字符串都会抛出可读的 ValueError。
    """
    if isinstance(value, bool):
        raise ValueError("配置项 %s 必须是整数，不能使用布尔值" % name)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        raise ValueError("配置项 %s 必须是整数，收到浮点值 %r" % (name, value))
    text = str(value).strip()
    try:
        return int(text, 10)
    except (TypeError, ValueError):
        raise ValueError("配置项 %s 必须是整数，收到无法解析的值: %r" % (name, value))


def _coerce_float(value: Any, name: str) -> float:
    """把任意来源的值严格转为 float，非法输入抛出可读的 ValueError。"""
    if isinstance(value, bool):
        raise ValueError("配置项 %s 必须是数值，不能使用布尔值" % name)
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        result = float(text)
    except (TypeError, ValueError):
        raise ValueError("配置项 %s 必须是数值，收到无法解析的值: %r" % (name, value))
    if result != result or result in (float("inf"), float("-inf")):
        raise ValueError("配置项 %s 必须是有限数值，收到: %r" % (name, value))
    return result


@dataclass
class AppConfig:
    """应用运行配置。

    所有路径最终会被转换为 :class:`pathlib.Path`。``__post_init__`` 同时完成
    参数合法性检查并创建必需目录；非法配置会立即抛出 ValueError，避免服务
    在错误状态下运行。
    """

    workspace_dir: Path = DEFAULT_WORKSPACE
    host: str = "127.0.0.1"
    port: int = 5000
    sample_ratio: float = 0.1
    random_seed: int = 42
    max_uncompressed_bytes: int = 10 * 1024 ** 3
    max_single_file_bytes: int = 4 * 1024 ** 3
    max_archive_entries: int = 5000
    max_compression_ratio: float = 500.0
    ratio_check_min_bytes: int = 10 * 1024 ** 2
    max_content_length: int = 1536 * 1024 ** 2
    builtin_contract: Path = DEFAULT_CONTRACT
    builtin_lineage: Path = DEFAULT_LINEAGE
    blocked_extensions: tuple = (
        ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".msi", ".ps1",
        ".sh", ".bash", ".py", ".pyw", ".jar", ".vbs", ".js", ".jsp",
        ".php", ".pl", ".rb", ".so", ".dylib", ".apk", ".elf",
    )
    allowed_extra_paths: tuple = ()
    log_level: str = "INFO"

    reports_dir: Path = field(init=False)
    uploads_dir: Path = field(init=False)
    temp_dir: Path = field(init=False)
    logs_dir: Path = field(init=False)
    db_path: Path = field(init=False)

    def __post_init__(self) -> None:
        """规范化路径、校验安全参数并创建运行目录。"""
        # 统一把来自构造参数、YAML 或环境变量的数值项转为正确类型，
        # 避免字符串（如 "0.2"、"5000"）流入后引发类型错误或行为偏差。
        self.port = _coerce_int(self.port, "port")
        self.random_seed = _coerce_int(self.random_seed, "random_seed")
        self.max_uncompressed_bytes = _coerce_int(
            self.max_uncompressed_bytes, "max_uncompressed_bytes")
        self.max_single_file_bytes = _coerce_int(
            self.max_single_file_bytes, "max_single_file_bytes")
        self.max_archive_entries = _coerce_int(
            self.max_archive_entries, "max_archive_entries")
        self.ratio_check_min_bytes = _coerce_int(
            self.ratio_check_min_bytes, "ratio_check_min_bytes")
        self.max_content_length = _coerce_int(
            self.max_content_length, "max_content_length")
        self.sample_ratio = _coerce_float(self.sample_ratio, "sample_ratio")
        self.max_compression_ratio = _coerce_float(
            self.max_compression_ratio, "max_compression_ratio")
        self.workspace_dir = Path(self.workspace_dir).resolve()
        self.builtin_contract = Path(self.builtin_contract).resolve()
        self.builtin_lineage = Path(self.builtin_lineage).resolve()
        if self.host not in LOOPBACK_HOSTS:
            raise ValueError("服务仅允许监听本机回环地址")
        if not 1 <= self.port <= 65535:
            raise ValueError("端口必须在 1-65535 之间")
        if not 0 < self.sample_ratio <= 1:
            raise ValueError("sample_ratio 必须位于 (0, 1]")
        if self.max_uncompressed_bytes <= 0:
            raise ValueError("解压大小上限必须为正数")
        if self.max_archive_entries <= 0:
            raise ValueError("压缩包条目上限必须为正数")
        if self.max_single_file_bytes <= 0:
            raise ValueError("单文件大小上限必须为正数")
        if self.max_compression_ratio <= 0:
            raise ValueError("压缩比阈值必须为正数")
        # 即使调用方传入软链接或相对路径，也统一固定在工作目录之下。
        self.reports_dir = self.workspace_dir / "reports"
        self.uploads_dir = self.workspace_dir / "uploads"
        self.temp_dir = self.workspace_dir / "tmp"
        self.logs_dir = self.workspace_dir / "logs"
        for folder in (self.workspace_dir, self.reports_dir, self.uploads_dir,
                       self.temp_dir, self.logs_dir):
            folder.mkdir(parents=True, exist_ok=True)
        self.db_path = self.workspace_dir / "gateway.db"
        self.blocked_extensions = tuple(
            str(ext).lower() if str(ext).startswith(".") else "." + str(ext).lower()
            for ext in self.blocked_extensions
        )
        self.allowed_extra_paths = tuple(str(p).replace("\\", "/") for p in self.allowed_extra_paths)

    @classmethod
    def from_yaml(cls, path: Path) -> "AppConfig":
        """从 YAML 文件构造配置。

        Args:
            path: YAML 配置文件路径。
        Returns:
            AppConfig: 校验后的配置对象。
        Raises:
            ValueError: 文件内容不是映射或包含未知配置项。
        """
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("配置文件根节点必须是映射")
        data = _merge_env_overrides(data)
        allowed = {item.name for item in fields(cls) if item.init}
        unknown = set(data) - allowed
        if unknown:
            raise ValueError("未知配置项: " + ", ".join(sorted(unknown)))
        return cls(**data)

    def fingerprint(self) -> str:
        """返回稳定的配置指纹，用于报告审计留痕。"""
        snapshot: Dict[str, Any] = {
            "sample_ratio": self.sample_ratio,
            "max_uncompressed_bytes": self.max_uncompressed_bytes,
            "max_archive_entries": self.max_archive_entries,
            "max_compression_ratio": self.max_compression_ratio,
            "blocked_extensions": list(self.blocked_extensions),
            "allowed_extra_paths": list(self.allowed_extra_paths),
        }
        raw = json.dumps(snapshot, sort_keys=True, ensure_ascii=False)
        return sha256(raw.encode("utf-8")).hexdigest()[:16]

    def public_dict(self) -> Dict[str, Any]:
        """返回适合页面展示的非敏感配置摘要。"""
        return {
            "host": self.host,
            "port": self.port,
            "sample_ratio": self.sample_ratio,
            "max_uncompressed_bytes": self.max_uncompressed_bytes,
            "max_compression_ratio": self.max_compression_ratio,
            "config_hash": self.fingerprint(),
        }


def _merge_env_overrides(data: Dict[str, Any]) -> Dict[str, Any]:
    """把 GATEWAY_ 前缀环境变量合并进配置字典。

    环境变量优先级低于显式传入/YAML 中已给出的键，但高于代码默认值
    （默认值在 :class:`AppConfig` 构造时补齐）。仅覆盖白名单中的数值项与
    工作目录，未知环境变量一律忽略，避免把无关变量误当作配置。
    """
    merged = dict(data)
    env_map = {"GATEWAY_" + name.upper(): name for name in
               _INT_ENV_KEYS + _FLOAT_ENV_KEYS}
    env_map.update(_ENV_KEY_ALIASES)
    for env_name, field_name in env_map.items():
        raw = os.environ.get(env_name)
        if raw is None or field_name in merged:
            continue
        if field_name in _INT_ENV_KEYS:
            merged[field_name] = _coerce_int(raw, field_name)
        else:
            merged[field_name] = _coerce_float(raw, field_name)
    return merged


def load_config(path: Optional[Path] = None) -> AppConfig:
    """加载配置，支持 ``GATEWAY_WORKSPACE`` 与数值型环境变量覆盖。"""
    data = {}
    if path:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("配置文件根节点必须是映射")
    env_workspace = os.environ.get("GATEWAY_WORKSPACE")
    if env_workspace:
        data["workspace_dir"] = Path(env_workspace)
    data = _merge_env_overrides(data)
    allowed = {item.name for item in fields(AppConfig) if item.init}
    unknown = set(data) - allowed
    if unknown:
        raise ValueError("未知配置项: " + ", ".join(sorted(unknown)))
    return AppConfig(**data)
