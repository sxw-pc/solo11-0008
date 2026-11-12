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
    trend_enabled: bool = True
    trend_baseline_tasks: int = 5
    trend_row_change_ratio: float = 0.5
    trend_rate_increase: float = 0.05

    reports_dir: Path = field(init=False)
    uploads_dir: Path = field(init=False)
    temp_dir: Path = field(init=False)
    logs_dir: Path = field(init=False)
    db_path: Path = field(init=False)

    def __post_init__(self) -> None:
        """规范化路径、校验安全参数并创建运行目录。"""
        self.workspace_dir = Path(self.workspace_dir).resolve()
        self.builtin_contract = Path(self.builtin_contract).resolve()
        self.builtin_lineage = Path(self.builtin_lineage).resolve()
        if self.host not in LOOPBACK_HOSTS:
            raise ValueError("服务仅允许监听本机回环地址")
        if not 1 <= int(self.port) <= 65535:
            raise ValueError("端口必须在 1-65535 之间")
        if not 0 < float(self.sample_ratio) <= 1:
            raise ValueError("sample_ratio 必须位于 (0, 1]")
        if int(self.max_uncompressed_bytes) <= 0:
            raise ValueError("解压大小上限必须为正数")
        if int(self.max_archive_entries) <= 0:
            raise ValueError("压缩包条目上限必须为正数")
        if int(self.trend_baseline_tasks) < 1:
            raise ValueError("trend_baseline_tasks 必须为正整数")
        if float(self.trend_row_change_ratio) < 0:
            raise ValueError("trend_row_change_ratio 不能为负数")
        if float(self.trend_rate_increase) < 0:
            raise ValueError("trend_rate_increase 不能为负数")
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
            "trend_enabled": self.trend_enabled,
            "trend_baseline_tasks": self.trend_baseline_tasks,
            "trend_row_change_ratio": self.trend_row_change_ratio,
            "trend_rate_increase": self.trend_rate_increase,
            "config_hash": self.fingerprint(),
        }


def load_config(path: Optional[Path] = None) -> AppConfig:
    """加载配置，支持 ``GATEWAY_WORKSPACE`` 环境变量覆盖工作目录。"""
    data = {}
    if path:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("配置文件根节点必须是映射")
    env_workspace = os.environ.get("GATEWAY_WORKSPACE")
    if env_workspace:
        data["workspace_dir"] = Path(env_workspace)
    allowed = {item.name for item in fields(AppConfig) if item.init}
    unknown = set(data) - allowed
    if unknown:
        raise ValueError("未知配置项: " + ", ".join(sorted(unknown)))
    return AppConfig(**data)
