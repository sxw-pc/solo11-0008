"""任务级临时资源回收。

上传副本目录与解压临时目录均以任务 ID 作为目录名前缀
（``upload-<task_id>-*``、``gateway-<task_id>-*``），因此无论任务正常
结束、被人工终止还是进程异常退出，都可以按任务 ID 精确回收残留资源，
且不会误删其他并行任务的目录。
"""

from pathlib import Path
import re
import shutil
from typing import List

from .config import AppConfig

#: 任务 ID 仅允许字母数字、短横线与下划线，防止 glob 注入与路径穿越。
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
UPLOAD_PREFIX = "upload-"
EXTRACT_PREFIX = "gateway-"


def validate_task_id(task_id: str) -> str:
    """校验任务 ID 合法性，非法时抛出 ValueError。"""
    task_id = str(task_id)
    if not task_id or not _TASK_ID_RE.match(task_id):
        raise ValueError("非法任务 ID")
    return task_id


def upload_temp_prefix(task_id: str) -> str:
    """上传副本临时目录名前缀。"""
    return UPLOAD_PREFIX + validate_task_id(task_id) + "-"


def extract_temp_prefix(task_id: str) -> str:
    """解压临时目录名前缀。"""
    return EXTRACT_PREFIX + validate_task_id(task_id) + "-"


def reclaim_task_resources(config: AppConfig, task_id: str) -> List[Path]:
    """删除指定任务的全部临时目录与文件，返回实际移除的路径列表。

    仅允许清理 ``config.temp_dir`` 的直接子级，且目录名必须带有该任务
    专属前缀；其他任务的资源、报告、日志与数据库均不受影响。重复调用
    安全。
    """
    task_id = validate_task_id(task_id)
    removed: List[Path] = []
    temp_root = config.temp_dir.resolve()
    prefixes = (upload_temp_prefix(task_id), extract_temp_prefix(task_id))
    for prefix in prefixes:
        for path in sorted(config.temp_dir.glob(prefix + "*")):
            candidate = path.resolve()
            # 防越界：仅处理 temp_dir 的直接子级，拒绝软链接逃逸。
            if candidate.parent != temp_root:
                continue
            if candidate.is_dir() and not candidate.is_symlink():
                shutil.rmtree(candidate, ignore_errors=True)
            else:
                try:
                    candidate.unlink(missing_ok=True)
                except OSError:
                    pass
            if not candidate.exists():
                removed.append(candidate)
    return removed
