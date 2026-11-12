"""数据包只读流式读取与列级指纹采集。

支持三种数据包形态：

* ``.zip`` / ``.tar.gz`` / ``.tar`` 压缩包（直接流式读取成员，不做整包解压）；
* 已展开的目录（只读遍历，不写入）；
* 表格式：CSV（UTF-8/UTF-8 BOM/GBK）、JSONL、SQLite；Parquet 在环境中
  存在 pyarrow 时可用，否则返回 ``unsupported_format`` 由上层保守降级。

设计约束：

* 所有成员路径先做规范化与越界检查，拒绝绝对路径、盘符、``..``、链接、
  特殊设备文件、加密条目、重复成员与超阈值条目/体积；
* 只有需要随机访问的 SQLite/Parquet 表文件会被复制进隔离临时目录，
  其余内容全程流式读取，原始数据包目录不发生任何写入；
* 读取失败统一抛出 :class:`PacketReadError` 并带稳定原因码，调用方据此
  决定是致命退出还是保守降级为全量重检。
"""

import codecs
import csv
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import tarfile
import zipfile

from .errors import PlannerError

_DRIVE_RE = re.compile(r"^[a-zA-Z]:")
_CHUNK = 1024 * 1024
RECOGNIZED_TABLE_SUFFIX = {
    ".csv": "csv",
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
    ".sqlite": "sqlite",
    ".db": "sqlite",
    ".parquet": "parquet",
}


class PacketReadError(Exception):
    """数据包成员无法可靠读取。"""

    def __init__(self, message, code, table=None, member=None):
        super().__init__(message)
        self.code = code
        self.table = table
        self.member = member


@dataclass(frozen=True)
class Limits:
    """读取防护阈值，默认值与 gateway 闸检量级保持一致。"""

    max_entries: int = 5000
    max_total_bytes: int = 10 * 1024 ** 3
    max_single_bytes: int = 4 * 1024 ** 3


@dataclass
class ColumnFingerprint:
    """单列的稳定内容指纹与基础统计。"""

    column: str
    sha256: str
    row_count: int
    null_count: int


@dataclass
class TableScan:
    """一张表的结构与列级指纹采集结果。"""

    name: str
    member: str
    format: str
    columns: list
    fingerprints: dict = field(default_factory=dict)
    sqlite_table: str = None
    row_count: int = 0


@dataclass
class PacketRead:
    """一次成功（或部分成功）的数据包读取结果。"""

    location: str
    kind: str                       # zip / tar / directory
    members: list = field(default_factory=list)
    member_hashes: dict = field(default_factory=dict)
    member_sizes: dict = field(default_factory=dict)
    tables: dict = field(default_factory=dict)
    manifest: dict = field(default_factory=lambda: None)
    read_errors: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# 路径安全
# --------------------------------------------------------------------------- #

def normalize_member(name):
    """规范化压缩包成员名并执行路径安全检查。"""
    if not name or "\x00" in name:
        raise PacketReadError("压缩包包含非法成员名", "unsafe_member")
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("/") or _DRIVE_RE.match(normalized):
        raise PacketReadError("压缩包包含绝对路径: %s" % name, "path_traversal",
                              member=name)
    parts = [part for part in PurePosixPath(normalized).parts if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise PacketReadError("压缩包包含路径穿越: %s" % name, "path_traversal",
                              member=name)
    if not parts:
        raise PacketReadError("压缩包包含空路径成员", "unsafe_member")
    return "/".join(parts)


# --------------------------------------------------------------------------- #
# 数据源抽象
# --------------------------------------------------------------------------- #

class _Source:
    """统一的成员枚举/流式打开接口。"""

    kind = "unknown"

    def members(self):
        raise NotImplementedError

    def open_member(self, name):
        raise NotImplementedError

    def member_size(self, name):
        raise NotImplementedError

    def real_file(self, name, work_dir):
        """返回成员的本地真实文件路径；默认把流式内容复制到隔离临时目录。"""
        target = Path(work_dir) / ("spill-" + hashlib.sha1(
            name.encode("utf-8")).hexdigest()[:16])
        with self.open_member(name) as src, open(target, "wb") as dst:
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    break
                dst.write(chunk)
        return target


class _ZipSource(_Source):
    kind = "zip"

    def __init__(self, path, limits):
        self._path = str(path)
        self._names = []
        self._sizes = {}
        with zipfile.ZipFile(self._path, "r") as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_entries:
                raise PacketReadError("压缩包条目数超过上限", "too_many_entries")
            total = 0
            seen = set()
            for info in infos:
                if info.flag_bits & 0x1:
                    raise PacketReadError("不支持加密压缩包", "encrypted_archive")
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise PacketReadError("压缩包包含符号链接: %s" % info.filename,
                                          "unsafe_member", member=info.filename)
                normalized = normalize_member(info.filename)
                if normalized in seen:
                    raise PacketReadError("压缩包包含重复成员: %s" % normalized,
                                          "duplicate_member", member=normalized)
                seen.add(normalized)
                if info.is_dir():
                    continue
                if info.file_size > limits.max_single_bytes:
                    raise PacketReadError("单文件超过上限: %s" % normalized,
                                          "member_too_large", member=normalized)
                total += info.file_size
                if total > limits.max_total_bytes:
                    raise PacketReadError("解压总量超过上限，疑似压缩炸弹",
                                          "archive_too_large")
                self._names.append(normalized)
                self._sizes[normalized] = info.file_size

    def members(self):
        return sorted(self._names)

    def member_size(self, name):
        return self._sizes[name]

    def open_member(self, name):
        archive = zipfile.ZipFile(self._path, "r")
        try:
            stream = archive.open(name, "r")
        except Exception:
            archive.close()
            raise
        return _ClosableStream(stream, archive)


class _TarSource(_Source):
    kind = "tar"

    def __init__(self, path, limits):
        self._path = str(path)
        self._members = {}
        with tarfile.open(self._path, "r:*") as archive:
            raw = archive.getmembers()
            if len(raw) > limits.max_entries:
                raise PacketReadError("压缩包条目数超过上限", "too_many_entries")
            total = 0
            seen = set()
            for member in raw:
                normalized = normalize_member(member.name)
                if normalized in seen:
                    raise PacketReadError("压缩包包含重复成员: %s" % normalized,
                                          "duplicate_member", member=normalized)
                seen.add(normalized)
                if member.issym() or member.islnk():
                    raise PacketReadError("压缩包包含链接文件: %s" % normalized,
                                          "unsafe_member", member=normalized)
                if not (member.isfile() or member.isdir()):
                    raise PacketReadError("压缩包包含特殊设备文件: %s" % normalized,
                                          "unsafe_member", member=normalized)
                if member.isdir():
                    continue
                if member.size > limits.max_single_bytes:
                    raise PacketReadError("单文件超过上限: %s" % normalized,
                                          "member_too_large", member=normalized)
                total += member.size
                if total > limits.max_total_bytes:
                    raise PacketReadError("解压总量超过上限，疑似压缩炸弹",
                                          "archive_too_large")
                self._members[normalized] = member.size

    def members(self):
        return sorted(self._members)

    def member_size(self, name):
        return self._members[name]

    def open_member(self, name):
        archive = tarfile.open(self._path, "r:*")
        try:
            stream = archive.extractfile(name)
            if stream is None:
                raise PacketReadError("无法读取成员: %s" % name,
                                      "member_unreadable", member=name)
        except Exception:
            archive.close()
            raise
        return _ClosableStream(stream, archive)


class _DirectorySource(_Source):
    kind = "directory"

    def __init__(self, root, limits):
        self._root = Path(root).resolve()
        self._files = {}
        count = 0
        total = 0
        for current, dirs, files in os.walk(str(self._root)):
            dirs.sort()
            for filename in sorted(files):
                absolute = Path(current) / filename
                if absolute.is_symlink():
                    raise PacketReadError("数据包目录包含符号链接: %s" % filename,
                                          "unsafe_member", member=filename)
                relative = absolute.relative_to(self._root).as_posix()
                normalize_member(relative)
                size = absolute.stat().st_size
                if size > limits.max_single_bytes:
                    raise PacketReadError("单文件超过上限: %s" % relative,
                                          "member_too_large", member=relative)
                total += size
                count += 1
                if count > limits.max_entries or total > limits.max_total_bytes:
                    raise PacketReadError("数据包体积/条目超过上限",
                                          "archive_too_large")
                self._files[relative] = absolute

    def members(self):
        return sorted(self._files)

    def member_size(self, name):
        return self._files[name].stat().st_size

    def open_member(self, name):
        return open(str(self._files[name]), "rb")

    def real_file(self, name, work_dir):
        return self._files[name]


class _ClosableStream:
    """把成员流与归档句柄绑定，关闭时一并释放。"""

    def __init__(self, stream, owner):
        self._stream = stream
        self._owner = owner

    def read(self, size=-1):
        return self._stream.read(size)

    def readable(self):
        return True

    def seekable(self):
        return False

    def writable(self):
        return False

    def close(self):
        try:
            self._stream.close()
        finally:
            self._owner.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def open_packet(location, limits=None):
    """按内容识别并打开数据包（zip/tar/目录）。"""
    limits = limits or Limits()
    path = Path(location)
    if not path.exists():
        raise PlannerError("数据包不存在: %s" % location, "packet_not_found")
    if path.is_dir():
        return _DirectorySource(path, limits)
    try:
        with open(path, "rb") as handle:
            head = handle.read(512)
    except OSError as exc:
        raise PlannerError("数据包无法读取: %s" % exc, "packet_unreadable")
    if head[:2] == b"PK" and zipfile.is_zipfile(str(path)):
        return _ZipSource(path, limits)
    if head[:2] == b"\x1f\x8b" or head[257:262] == b"ustar":
        if not tarfile.is_tarfile(str(path)):
            raise PlannerError("仅支持 zip 或 tar/tar.gz 数据包",
                               "unsupported_archive")
        return _TarSource(path, limits)
    raise PlannerError("仅支持 zip、tar/tar.gz 或目录形态的数据包",
                       "unsupported_archive")


# --------------------------------------------------------------------------- #
# 表声明解析
# --------------------------------------------------------------------------- #

def _table_specs(source, manifest):
    """返回有序表声明列表：(表名, 成员, 格式, sqlite_table)。"""
    specs = []
    if isinstance(manifest, dict) and isinstance(manifest.get("tables"), dict):
        for name in sorted(manifest["tables"].keys()):
            spec = manifest["tables"][name]
            if not isinstance(spec, dict) or not spec.get("path"):
                raise PacketReadError("manifest 表声明缺少 path: %s" % name,
                                      "manifest_invalid", table=str(name))
            member = normalize_member(str(spec["path"]))
            fmt = str(spec.get("format") or "").lower() or \
                os.path.splitext(member)[1].lstrip(".").lower()
            sqlite_table = spec.get("sqlite_table") or spec.get("table")
            specs.append((str(name), member, fmt, sqlite_table))
        return specs
    # 无 manifest：按成员自动推导，data/ 目录或根目录下的可识别表文件。
    for member in source.members():
        suffix = os.path.splitext(member)[1].lower()
        fmt = RECOGNIZED_TABLE_SUFFIX.get(suffix)
        if not fmt:
            continue
        parts = PurePosixPath(member).parts
        if len(parts) > 2 or (len(parts) == 2 and parts[0] != "data"):
            continue
        name = PurePosixPath(member).stem
        specs.append((name, member, fmt, None))
    specs.sort(key=lambda item: item[0])
    return specs


def _load_manifest(source):
    for candidate in ("manifest.yaml", "manifest.yml", "manifest.json"):
        if candidate in source.members():
            try:
                with source.open_member(candidate) as stream:
                    text = stream.read().decode("utf-8-sig")
                if candidate.endswith(".json"):
                    return json.loads(text)
                from .textio import parse_yaml_subset
                try:
                    import yaml  # type: ignore
                    return yaml.safe_load(text)
                except ImportError:
                    return parse_yaml_subset(text)
            except (ValueError, UnicodeError) as exc:
                raise PacketReadError("manifest 无法可靠解析: %s" % exc,
                                      "manifest_unreadable", member=candidate)
    return None


# --------------------------------------------------------------------------- #
# 流式表读取
# --------------------------------------------------------------------------- #

def _decoded_lines(source, member):
    """依次尝试 UTF-8 BOM/UTF-8、GBK 解码成员，返回行迭代器。"""
    last_error = None
    for encoding in ("utf-8-sig", "gbk"):
        try:
            with source.open_member(member) as binary:
                decoder = codecs.getincrementaldecoder(encoding)()
                buffer = ""
                lines = []
                while True:
                    chunk = binary.read(_CHUNK)
                    if not chunk:
                        buffer += decoder.decode(b"", final=True)
                        break
                    buffer += decoder.decode(chunk, final=False)
                    head, _, tail = buffer.rpartition("\n")
                    if head:
                        lines.extend(head.split("\n"))
                    buffer = tail
                if buffer:
                    lines.append(buffer)
            # 完整解码成功后重新以文本方式逐行产出（保持流式，不整表驻留）。
            def generator():
                with source.open_member(member) as binary:
                    inc = codecs.getincrementaldecoder(encoding)()
                    pending = ""
                    while True:
                        chunk = binary.read(_CHUNK)
                        if not chunk:
                            pending += inc.decode(b"", final=True)
                            if pending:
                                yield pending
                            return
                        pending += inc.decode(chunk, final=False)
                        head, _, tail = pending.rpartition("\n")
                        if head:
                            for line in head.split("\n"):
                                yield line
                        pending = tail
            return generator(), encoding
        except UnicodeDecodeError as exc:
            last_error = exc
    raise PacketReadError("编码识别失败，仅支持 UTF-8/GBK: %s" % last_error,
                          "encoding_unreadable", member=member)


def _scan_csv(source, member, table_name):
    lines, encoding = _decoded_lines(source, member)
    reader = csv.reader(lines)
    try:
        header = next(reader)
    except StopIteration:
        raise PacketReadError("CSV 文件为空: %s" % member,
                              "empty_table", table=table_name, member=member)
    header = [str(item).replace("\n", "").replace("\r", "").strip() for item in header]
    if not header or any(not item for item in header):
        raise PacketReadError("CSV 表头存在空字段名: %s" % member,
                              "malformed_table", table=table_name, member=member)
    if len(set(header)) != len(header):
        raise PacketReadError("CSV 表头包含重复字段名: %s" % member,
                              "malformed_table", table=table_name, member=member)
    hashes = {column: hashlib.sha256() for column in header}
    nulls = dict.fromkeys(header, 0)
    rows = 0
    try:
        for record in reader:
            if not record or all(cell == "" for cell in record):
                continue
            if len(record) != len(header):
                raise PacketReadError(
                    "CSV 行列数与表头不一致: %s 第 %d 行" % (member, rows + 2),
                    "malformed_table", table=table_name, member=member)
            rows += 1
            for column, cell in zip(header, record):
                value = None if cell == "" else cell
                if value is None:
                    nulls[column] += 1
                hashes[column].update(b"r" + encode_cell(value))
    except UnicodeDecodeError as exc:
        raise PacketReadError("CSV 编码无法可靠读取: %s" % exc,
                              "encoding_unreadable", table=table_name,
                              member=member)
    return _build_scan(table_name, member, "csv", header, hashes, nulls, rows,
                       encoding=encoding)


def _iter_text_lines(binary_stream, encoding="utf-8"):
    """把二进制成员流增量解码为文本行（不依赖 TextIOWrapper 完整接口）。"""
    decoder = codecs.getincrementaldecoder(encoding)()
    pending = ""
    while True:
        chunk = binary_stream.read(_CHUNK)
        if not chunk:
            pending += decoder.decode(b"", final=True)
            if pending:
                yield pending
            return
        pending += decoder.decode(chunk, final=False)
        head, _, tail = pending.rpartition("\n")
        if head:
            for line in head.split("\n"):
                yield line
        pending = tail


def _scan_jsonl(source, member, table_name):
    all_keys = set()
    line_no = 0
    with source.open_member(member) as binary:
        for line in _iter_text_lines(binary, "utf-8"):
            line = line.strip()
            if not line:
                continue
            line_no += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PacketReadError(
                    "JSONL 第 %d 行无法解析: %s" % (line_no, exc),
                    "malformed_table", table=table_name, member=member)
            if not isinstance(record, dict):
                raise PacketReadError("JSONL 第 %d 行不是对象" % line_no,
                                      "malformed_table", table=table_name,
                                      member=member)
            all_keys.update(str(key) for key in record.keys())
    columns = sorted(all_keys)
    hashes = {column: hashlib.sha256() for column in columns}
    nulls = dict.fromkeys(columns, 0)
    rows = 0
    with source.open_member(member) as binary:
        for line in _iter_text_lines(binary, "utf-8"):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            rows += 1
            for column in columns:
                value = record.get(column)
                if value is None:
                    nulls[column] += 1
                hashes[column].update(b"r" + encode_cell(value))
    return _build_scan(table_name, member, "jsonl", columns, hashes, nulls, rows)


def _scan_sqlite(source, member, table_name, sqlite_table, work_dir):
    real_path = source.real_file(member, work_dir)
    uri = "file:%s?mode=ro&immutable=1" % str(real_path).replace("?", "%3f")
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.DatabaseError as exc:
        raise PacketReadError("SQLite 文件损坏或格式错误: %s" % exc,
                              "malformed_table", table=table_name, member=member)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise PacketReadError("SQLite 完整性检查未通过",
                                  "malformed_table", table=table_name, member=member)
        names = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()]
        if sqlite_table is None:
            if len(names) != 1:
                raise PacketReadError(
                    "SQLite 含多张表且未声明 sqlite_table: %s" % member,
                    "manifest_invalid", table=table_name, member=member)
            sqlite_table = names[0]
        if sqlite_table not in names:
            raise PacketReadError("SQLite 中不存在表: %s" % sqlite_table,
                                  "table_missing", table=table_name, member=member)
        columns = [row[1] for row in connection.execute(
            'PRAGMA table_info("%s")' % sqlite_table.replace('"', '""')).fetchall()]
        if not columns:
            raise PacketReadError("SQLite 表不包含字段: %s" % sqlite_table,
                                  "malformed_table", table=table_name, member=member)
        if len(set(columns)) != len(columns):
            raise PacketReadError("SQLite 表包含重复字段名: %s" % sqlite_table,
                                  "malformed_table", table=table_name, member=member)
        quoted = ",".join('"%s"' % col.replace('"', '""') for col in columns)
        hashes = {column: hashlib.sha256() for column in columns}
        nulls = dict.fromkeys(columns, 0)
        rows = 0
        cursor = connection.execute('SELECT %s FROM "%s"' % (
            quoted, sqlite_table.replace('"', '""')))
        for record in cursor:
            rows += 1
            for column, value in zip(columns, record):
                if value is None:
                    nulls[column] += 1
                hashes[column].update(b"r" + encode_cell(value))
    except sqlite3.DatabaseError as exc:
        raise PacketReadError("SQLite 查询失败: %s" % exc,
                              "malformed_table", table=table_name, member=member)
    finally:
        connection.close()
    return _build_scan(table_name, member, "sqlite", columns, hashes, nulls, rows,
                       sqlite_table=sqlite_table)


def _scan_parquet(source, member, table_name, work_dir):
    try:
        import pyarrow.parquet as pq  # type: ignore
    except ImportError:
        raise PacketReadError("环境缺少 pyarrow，无法可靠读取 Parquet 表: %s"
                              % member, "unsupported_format",
                              table=table_name, member=member)
    real_path = source.real_file(member, work_dir)
    try:
        table = pq.read_table(str(real_path))
    except Exception as exc:  # parquet 损坏时 pyarrow 抛 Arrow 系列异常
        raise PacketReadError("Parquet 读取失败: %s" % exc,
                              "malformed_table", table=table_name, member=member)
    columns = [str(name) for name in table.column_names]
    if len(set(columns)) != len(columns):
        raise PacketReadError("Parquet 表包含重复字段名: %s" % member,
                              "malformed_table", table=table_name, member=member)
    hashes = {column: hashlib.sha256() for column in columns}
    nulls = dict.fromkeys(columns, 0)
    rows = table.num_rows
    for column in columns:
        series = table.column(column).to_pylist()
        for value in series:
            if value is None:
                nulls[column] += 1
            hashes[column].update(b"r" + encode_cell(value))
    return _build_scan(table_name, member, "parquet", columns, hashes, nulls, rows)


def _build_scan(table_name, member, fmt, columns, hashes, nulls, rows,
                sqlite_table=None, encoding=None):
    fingerprints = {}
    for column in columns:
        digest = hashes[column]
        fingerprints[column] = ColumnFingerprint(
            column=column,
            sha256=digest.hexdigest(),
            row_count=rows,
            null_count=nulls[column],
        )
    scan = TableScan(name=table_name, member=member, format=fmt,
                     columns=list(columns), fingerprints=fingerprints,
                     sqlite_table=sqlite_table, row_count=rows)
    scan.encoding = encoding  # 仅 CSV 使用，便于报告留痕
    return scan


def encode_cell(value):
    """把单元格值编码为带类型标签与长度前缀的确定性字节串。"""
    if value is None:
        return b"0:"
    if isinstance(value, bool):
        payload = b"1" if value else b"0"
        return b"b1:" + payload
    if isinstance(value, int):
        payload = str(value).encode("utf-8")
        return b"i%d:%s" % (len(payload), payload)
    if isinstance(value, float):
        payload = repr(value).encode("utf-8")
        return b"f%d:%s" % (len(payload), payload)
    if isinstance(value, (bytes, bytearray)):
        payload = bytes(value).hex().encode("ascii")
        return b"x%d:%s" % (len(payload), payload)
    payload = str(value).encode("utf-8")
    return b"s%d:%s" % (len(payload), payload)


# --------------------------------------------------------------------------- #
# 整包读取入口
# --------------------------------------------------------------------------- #

def read_packet(location, work_dir, limits=None):
    """读取数据包：清单、成员字节指纹与每张表的列级指纹。

    Args:
        location: 压缩包或目录路径。
        work_dir: 隔离临时目录（SQLite/Parquet 随机访问落盘位置）。
        limits: 可选防护阈值。
    Returns:
        PacketRead。表级读取失败会记录在 ``read_errors`` 并跳过该表，
        由调用方决定保守降级策略；清单/成员级问题直接抛出。
    """
    limits = limits or Limits()
    source = open_packet(location, limits)
    manifest = _load_manifest(source)
    result = PacketRead(location=str(Path(location)), kind=source.kind,
                        manifest=manifest)
    for member in source.members():
        digest = hashlib.sha256()
        size = 0
        with source.open_member(member) as stream:
            while True:
                chunk = stream.read(_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        result.members.append(member)
        result.member_hashes[member] = digest.hexdigest()
        result.member_sizes[member] = size
    for table_name, member, fmt, sqlite_table in _table_specs(source, manifest):
        if member not in result.member_hashes:
            raise PacketReadError("manifest 声明的数据文件不存在: %s" % member,
                                  "table_missing", table=table_name, member=member)
        try:
            if fmt == "csv":
                scan = _scan_csv(source, member, table_name)
            elif fmt == "jsonl":
                scan = _scan_jsonl(source, member, table_name)
            elif fmt == "sqlite":
                scan = _scan_sqlite(source, member, table_name,
                                    sqlite_table, work_dir)
            elif fmt == "parquet":
                scan = _scan_parquet(source, member, table_name, work_dir)
            else:
                raise PacketReadError("不支持的表格式: %s" % fmt,
                                      "unsupported_format",
                                      table=table_name, member=member)
        except PacketReadError as exc:
            if exc.table is None:
                exc.table = table_name
            result.read_errors.append({
                "code": exc.code, "table": table_name,
                "member": member, "message": str(exc),
            })
            continue
        result.tables[table_name] = scan
    return result
