"""csv、parquet、sqlite 三种结构化表的统一读取适配。

CSV 自动识别 UTF-8/UTF-8 BOM 与 GBK 编码，并清理表头空白及换行。
抽样使用固定随机种子的均匀随机抽样，确保同一任务结果可复现。
"""

import csv
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

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


def _sample_indices(total: int, ratio: float, seed: int) -> List[int]:
    """对整包一次抽样生成行索引，返回已排序的位置列表。

    抽样以 ``total``（整包全部行数）为总体、``seed`` 为唯一随机源，因此
    同一包在同一配置下任意表、任意格式得到完全相同的抽样行位置；比例和
    种子不会每张表重新起算。行数按比例四舍五入并至少保留一行。

    Args:
        total: 整包待抽样总行数。
        ratio: 抽样比例，位于 (0, 1]。
        seed: 随机种子。
    Returns:
        升序排列的行位置（DataFrame 中的 0 基位置）。
    """
    if total <= 0 or ratio >= 1.0:
        return list(range(total))
    count = max(1, int(round(total * ratio)))
    if count >= total:
        return list(range(total))
    try:
        positions = pd.Series(range(total)).sample(
            n=count, random_state=seed).tolist()
    except (ValueError, KeyError) as exc:  # pragma: no cover - pandas 内部异常
        raise TableReadError("抽样失败: %s" % exc) from exc
    return sorted(int(position) for position in positions)


def _apply_sample(frame: pd.DataFrame, ratio: float, seed: int) -> pd.DataFrame:
    """按比例执行可复现的整包均匀随机抽样，至少保留一行。

    兼容单表调用：以当前表行数作为总体。整包抽样请使用
    :func:`_apply_packet_sample`，确保比例和种子在包内只生效一次。
    """
    positions = _sample_indices(len(frame), ratio, seed)
    if len(positions) >= len(frame):
        return frame
    return frame.iloc[positions].sort_index()


def _apply_packet_sample(frames: Dict[str, pd.DataFrame], ratio: float, seed: int
                         ) -> Dict[str, pd.DataFrame]:
    """对整包各表执行统一抽样，返回与输入同键的新数据帧映射。

    随机数生成器只在整包范围内创建一次，并按 manifest 中的表顺序连续
    抽取，因此抽样比例与种子不会对每张表重新生效。相同行数的表也会因
    随机流向前推进而得到不同行位置，结果仍可由种子完整复现。每张非空表
    至少保留一行，避免小表因四舍五入被完全抽样掉。

    Args:
        frames: 表名到全量数据帧的映射。
        ratio: 整包统一抽样比例。
        seed: 随机种子。
    Returns:
        ``{表名: 抽样后数据帧}``，空表原样保留。
    """
    result: Dict[str, pd.DataFrame] = {}
    if ratio >= 1.0:
        return {name: frame for name, frame in frames.items()}
    try:
        import numpy as np
        random_source: Any = np.random.RandomState(seed)
    except (ImportError, ValueError):  # pragma: no cover - numpy 为 pandas 依赖
        random_source = seed
    for name, frame in frames.items():
        total = len(frame)
        if total == 0:
            result[name] = frame
            continue
        count = max(1, int(round(total * ratio)))
        if count >= total:
            result[name] = frame
            continue
        try:
            result[name] = frame.sample(
                n=count, random_state=random_source).sort_index()
        except (ValueError, KeyError) as exc:
            raise TableReadError("抽样失败: %s" % exc) from exc
    return result


def sample_tables(tables: Dict[str, TableData], config: AppConfig) -> Dict[str, TableData]:
    """对整包各表执行统一抽样，返回新的 TableData 映射。

    抽样比例 ``config.sample_ratio`` 与种子 ``config.random_seed`` 在整个
    数据包范围内只生效一次，避免逐文件重新起算导致统计口径漂移。输入的
    全量表对象不被修改，便于血缘阶段继续使用全量数据。

    Args:
        tables: 表名到全量 TableData 的映射。
        config: 提供整包抽样比例与随机种子。
    Returns:
        表名到抽样后 TableData 的映射；原对象保持不变。
    """
    sampled_frames = _apply_packet_sample(
        {name: data.frame for name, data in tables.items()},
        config.sample_ratio, config.random_seed)
    result: Dict[str, TableData] = {}
    for name, data in tables.items():
        frame = sampled_frames[name]
        result[name] = TableData(
            name=data.name, frame=frame, source_format=data.source_format,
            total_rows=data.total_rows, sampled_rows=len(frame),
            sample_ratio=(config.sample_ratio if len(frame) < data.total_rows
                          else 1.0),
            encoding=data.encoding, sqlite_table=data.sqlite_table,
            row_offset=data.row_offset,
        )
    return result


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
