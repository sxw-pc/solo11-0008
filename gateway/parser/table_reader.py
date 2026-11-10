"""csv、parquet、sqlite 三种结构化表的统一读取适配。

CSV 自动识别 UTF-8/UTF-8 BOM 与 GBK 编码，并清理表头空白及换行。
抽样使用固定随机种子的均匀随机抽样，确保同一任务结果可复现。
"""

import csv
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any, Dict, Optional

import pandas as pd

from ..config import AppConfig
from .archive_loader import ExtractionResult


class TableReadError(Exception):
    """表文件缺失、损坏或格式不支持。"""


@dataclass
class TableData:
    """结构化表读取结果及审计元数据。"""

    name: str
    frame: pd.DataFrame
    source_format: str
    total_rows: int
    sampled_rows: int
    sample_ratio: float
    encoding: Optional[str] = None
    sqlite_table: Optional[str] = None
    row_offset: int = 1

    def sample_rows(self) -> int:
        """返回实际参与校验的行数。"""
        return self.sampled_rows


def _clean_columns(frame: pd.DataFrame) -> pd.DataFrame:
    """清理表头中的换行、回车、BOM 与首尾空白。"""
    columns = []
    for column in frame.columns:
        cleaned = str(column).replace("﻿", "").replace("\n", "").replace("\r", "")
        columns.append(cleaned.strip())
    if len(set(columns)) != len(columns):
        raise TableReadError("表头包含重复字段名")
    frame = frame.copy()
    frame.columns = columns
    return frame


def _read_csv(path: Path) -> TableData:
    """读取 CSV，依次尝试 UTF-8 与 GBK 编码。"""
    last_error = None
    for encoding in ("utf-8-sig", "gbk"):
        try:
            with path.open("r", encoding=encoding, newline="") as handle:
                header = next(csv.reader(handle), None)
            if header is None:
                raise TableReadError("CSV 文件为空: %s" % path.name)
            cleaned_header = [str(item).replace(chr(10), "").replace(chr(13), "").strip()
                              for item in header]
            if len(set(cleaned_header)) != len(cleaned_header):
                raise TableReadError("表头包含重复字段名")
            frame = pd.read_csv(path, encoding=encoding, skip_blank_lines=True)
            frame = _clean_columns(frame)
            if frame.shape[1] == 0:
                raise TableReadError("CSV 表不包含任何字段")
            return TableData(
                name="", frame=frame, source_format="csv",
                total_rows=len(frame), sampled_rows=len(frame),
                sample_ratio=1.0, encoding=encoding, row_offset=2,
            )
        except UnicodeDecodeError as exc:
            last_error = exc
        except pd.errors.EmptyDataError as exc:
            raise TableReadError("CSV 文件为空: %s" % path.name) from exc
        except (pd.errors.ParserError, OSError, ValueError) as exc:
            raise TableReadError("CSV 读取失败: %s" % exc) from exc
    raise TableReadError("CSV 编码识别失败，仅支持 UTF-8/GBK: %s" % last_error)


def _read_parquet(path: Path) -> TableData:
    """读取 parquet 表；缺少 pyarrow 或文件损坏时返回清晰错误。"""
    try:
        frame = pd.read_parquet(path)
    except Exception as exc:
        raise TableReadError("Parquet 读取失败: %s" % exc) from exc
    if frame.shape[1] == 0:
        raise TableReadError("Parquet 表不包含任何字段")
    frame = _clean_columns(frame)
    return TableData(
        name="", frame=frame, source_format="parquet",
        total_rows=len(frame), sampled_rows=len(frame),
        sample_ratio=1.0, row_offset=1,
    )


def _sqlite_tables(path: Path) -> list:
    """检查 SQLite 完整性并返回用户表名。"""
    try:
        connection = sqlite3.connect(str(path))
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise TableReadError("SQLite 完整性检查未通过")
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.DatabaseError as exc:
        raise TableReadError("SQLite 文件损坏或格式错误: %s" % exc) from exc
    return [row[0] for row in rows]


def _read_sqlite(path: Path, table_name: Optional[str]) -> TableData:
    """读取 SQLite 指定表；未指定时要求库内仅有一张业务表。"""
    tables = _sqlite_tables(path)
    if not tables:
        raise TableReadError("SQLite 库内没有业务表")
    if table_name is None:
        if len(tables) != 1:
            raise TableReadError("SQLite 存在多张表，必须通过 manifest 指定表名")
        table_name = tables[0]
    if table_name not in tables:
        raise TableReadError("SQLite 中不存在表: %s" % table_name)
    safe_table = '"' + table_name.replace('"', '""') + '"'
    try:
        connection = sqlite3.connect(str(path))
        try:
            frame = pd.read_sql_query("SELECT * FROM %s" % safe_table, connection)
        finally:
            connection.close()
    except (sqlite3.DatabaseError, pd.errors.DatabaseError) as exc:
        raise TableReadError("SQLite 查询失败: %s" % exc) from exc
    frame = _clean_columns(frame)
    return TableData(
        name="", frame=frame, source_format="sqlite",
        total_rows=len(frame), sampled_rows=len(frame),
        sample_ratio=1.0, sqlite_table=table_name, row_offset=1,
    )


def _apply_sample(frame: pd.DataFrame, ratio: float, seed: int) -> pd.DataFrame:
    """按比例执行可复现的均匀随机抽样，至少保留一行。"""
    if ratio >= 1.0 or frame.empty:
        return frame
    count = max(1, int(round(len(frame) * ratio)))
    if count >= len(frame):
        return frame
    try:
        return frame.sample(n=count, random_state=seed).sort_index()
    except (ValueError, KeyError) as exc:
        raise TableReadError("抽样失败: %s" % exc) from exc


def read_table(path: Path, source_format: str, config: AppConfig,
               name: str = "", table_name: Optional[str] = None,
               sample: bool = True) -> TableData:
    """读取单个结构化表并按配置抽样。

    Args:
        path: 表文件绝对路径。
        source_format: ``csv``、``parquet`` 或 ``sqlite``。
        config: 提供抽样比例与随机种子。
        name: 表逻辑名称。
        table_name: SQLite 库内表名。
        sample: 是否执行抽样；血缘校验需要全量数据时传 False。
    Returns:
        TableData: 数据帧与行数、编码等元数据。
    Raises:
        TableReadError: 文件不存在、损坏、编码或格式不支持。
    """
    path = Path(path)
    if not path.is_file():
        raise TableReadError("表文件不存在: %s" % path.name)
    fmt = (source_format or path.suffix.lstrip(".")).lower()
    readers = {"csv": _read_csv, "parquet": _read_parquet}
    if fmt == "sqlite":
        result = _read_sqlite(path, table_name)
    elif fmt in readers:
        result = readers[fmt](path)
    else:
        raise TableReadError("不支持的表格式: %s" % source_format)
    result.name = name or path.stem
    if sample:
        sampled = _apply_sample(result.frame, config.sample_ratio, config.random_seed)
        result.frame = sampled
        result.sampled_rows = len(sampled)
        result.sample_ratio = config.sample_ratio if len(sampled) < result.total_rows else 1.0
    return result


def read_manifest_table(extraction: ExtractionResult, table_name: str,
                        config: AppConfig, sample: bool = True) -> TableData:
    """依据 manifest.tables 中的映射读取表并检查文件路径。

    Raises:
        TableReadError: 表未声明、路径越界或读取失败。
    """
    specs = extraction.manifest.get("tables", {})
    spec = specs.get(table_name)
    if not isinstance(spec, dict):
        raise TableReadError("manifest 未声明表: %s" % table_name)
    relative = spec.get("path")
    if not relative:
        raise TableReadError("manifest 表 %s 缺少 path" % table_name)
    try:
        path = extraction.safe_path(str(relative))
    except Exception as exc:
        raise TableReadError("表路径非法: %s" % relative) from exc
    fmt = str(spec.get("format") or path.suffix.lstrip(".")).lower()
    return read_table(
        path=path, source_format=fmt, config=config, name=table_name,
        table_name=spec.get("table"), sample=sample,
    )


def iter_table_specs(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """返回 manifest 中合法的表声明副本。"""
    result = {}
    for name, spec in (manifest.get("tables") or {}).items():
        if isinstance(spec, dict) and spec.get("path"):
            result[str(name)] = dict(spec)
    return result
