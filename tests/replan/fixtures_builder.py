"""测试夹具构建器：在临时目录生成成对数据包、契约、血缘与存档。

仅使用标准库（csv/json/zip/tar/sqlite），不依赖 pandas/pyarrow，保证在
离线、无第三方包的 Python 3.9-3.11 上可运行。所有生成目录彼此隔离，
测试结束由 unittest 的 TemporaryDirectory 清理。
"""

import csv
import io
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import zipfile


def write_csv_bytes(header, rows, encoding="utf-8"):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow(["" if value is None else value for value in row])
    return buffer.getvalue().encode(encoding)


def write_jsonl_bytes(records):
    return ("\n".join(json.dumps(record, ensure_ascii=False, sort_keys=True)
                      for record in records) + "\n").encode("utf-8")


def make_contract(tables_fields, anomaly_rules=None, column_renames=None):
    """构造契约 dict。

    Args:
        tables_fields: {table: {field: {type, nullable, required, ...约束}}}
    """
    tables = {}
    for table, fields in tables_fields.items():
        tables[table] = {
            "file": "data/%s.csv" % table,
            "fields": {
                name: {
                    "type": spec.get("type", "string"),
                    "required": spec.get("required", False),
                    "nullable": spec.get("nullable", True),
                    **{key: value for key, value in spec.items()
                       if key not in ("type", "nullable", "required")},
                }
                for name, spec in fields.items()
            },
        }
    payload = {
        "version": "1.0",
        "name": "test_contract",
        "allow_extra_fields": False,
        "tables": tables,
    }
    if anomaly_rules:
        payload["anomaly_rules"] = anomaly_rules
    if column_renames:
        payload["column_renames"] = column_renames
    return payload


def make_lineage(relations):
    """relations: [(name, left_table, left_field, right_table, right_field)]"""
    return {
        "version": "1.0",
        "name": "test_lineage",
        "relations": [
            {
                "name": name,
                "left": {"table": lt, "field": lf},
                "right": {"table": rt, "field": rf},
                "relationship": "many_to_one",
                "require_reference": True,
                "allow_null": False,
            }
            for name, lt, lf, rt, rf in relations
        ],
    }


def make_manifest(members):
    """members: {member: sha256}，生成 gateway 风格 manifest 映射。"""
    import hashlib
    files = {}
    tables = {}
    for member in sorted(members):
        files[member] = {"sha256": members[member]}
        if member.startswith("data/") and member.endswith(".csv"):
            table = Path(member).stem
            tables[table] = {"path": member, "format": "csv"}
        if member.startswith("data/") and member.endswith(".jsonl"):
            table = Path(member).stem
            tables[table] = {"path": member, "format": "jsonl"}
        if member.startswith("data/") and member.endswith(".sqlite"):
            table = Path(member).stem
            tables[table] = {"path": member, "format": "sqlite",
                             "sqlite_table": table}
    return {
        "schema_version": "1.0",
        "packet": {"name": "fixture"},
        "tables": tables,
        "files": files,
    }


def build_zip_packet(folder, name, files, archive_format="zip"):
    """把 {member: bytes} 写成 zip 或 tar.gz 数据包，返回路径。"""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    if archive_format == "zip":
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for member in sorted(files.keys()):
                archive.writestr(member, files[member])
    else:
        with tarfile.open(path, "w:gz") as archive:
            for member in sorted(files.keys()):
                data = files[member]
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return str(path)


def build_directory_packet(folder, name, files):
    root = Path(folder) / name
    root.mkdir(parents=True, exist_ok=True)
    for member, data in files.items():
        target = root / member
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return str(root)


def packet_files(tables_csv, extra_members=None):
    """组装数据包成员：data/*.csv + manifest.yaml（文本 YAML 子集）。"""
    import hashlib
    files = {}
    for table, (header, rows) in tables_csv.items():
        member = "data/%s.csv" % table
        files[member] = write_csv_bytes(header, rows)
    if extra_members:
        files.update(extra_members)
    hashes = {member: hashlib.sha256(data).hexdigest()
              for member, data in files.items()}
    manifest = make_manifest(hashes)
    files["manifest.yaml"] = _dump_simple_yaml(manifest).encode("utf-8")
    return files


def _dump_simple_yaml(obj, indent=0):
    """仅供夹具使用的极简 YAML 输出（映射/列表/标量）。"""
    pad = "  " * indent
    lines = []
    if isinstance(obj, dict):
        for key in obj:
            value = obj[key]
            if isinstance(value, (dict, list)) and value:
                lines.append("%s%s:" % (pad, key))
                lines.append(_dump_simple_yaml(value, indent + 1))
            else:
                lines.append("%s%s: %s" % (pad, key, _scalar(value)))
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                first = True
                for key in item:
                    prefix = "%s- " % pad if first else "%s  " % pad
                    lines.append("%s%s: %s" % (prefix, key,
                                               _scalar(item[key])))
                    first = False
            else:
                lines.append("%s- %s" % (pad, _scalar(item)))
    return "\n".join(lines) + ("\n" if indent == 0 else "")


def _scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "" or ":" in text or "#" in text:
        return '"%s"' % text.replace('"', '\\"')
    return text


def write_sqlite_bytes(table, header, rows):
    """在临时文件生成 sqlite 数据库后读回字节。"""
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        connection = sqlite3.connect(path)
        columns = ", ".join('"%s" TEXT' % col for col in header)
        connection.execute('CREATE TABLE "%s" (%s)' % (table, columns))
        placeholders = ", ".join("?" for _ in header)
        connection.executemany(
            'INSERT INTO "%s" VALUES (%s)' % (table, placeholders),
            [tuple(row) for row in rows])
        connection.commit()
        connection.close()
        return Path(path).read_bytes()
    finally:
        os.unlink(path)


def write_configs(base, contract, lineage):
    """落盘契约与血缘 JSON（测试统一 JSON，避免夹具 YAML 转义问题）。"""
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    contract_path = base / "contract.json"
    lineage_path = base / "lineage.json"
    contract_path.write_text(
        json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8")
    lineage_path.write_text(
        json.dumps(lineage, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8")
    return str(contract_path), str(lineage_path)


# --------------------------------------------------------------------------- #
# 标准业务场景：users（维表）+ trades（事实表，外键引用 users.user_id）
# --------------------------------------------------------------------------- #

def base_users_rows():
    return [
        ["U001", "Alice", "north", "30"],
        ["U002", "Bob", "south", "41"],
        ["U003", "Carol", "east", "25"],
    ]


USERS_HEADER = ["user_id", "user_name", "region", "age"]


def base_trades_rows():
    return [
        ["T001", "U001", "100.50", "paid"],
        ["T002", "U002", "88.00", "pending"],
        ["T003", "U003", "12.20", "paid"],
    ]


TRADES_HEADER = ["trade_id", "user_id", "amount", "status"]


def base_contract():
    return make_contract(
        {
            "users": {
                "user_id": {"type": "string", "required": True,
                            "nullable": False, "pattern": "^U[0-9]{3}$"},
                "user_name": {"type": "string", "required": True,
                              "nullable": False, "maxLength": 40},
                "region": {"type": "string", "required": True,
                           "nullable": False,
                           "enum": ["north", "south", "east", "west"]},
                "age": {"type": "integer", "required": True,
                        "nullable": False, "minimum": 18, "maximum": 100},
            },
            "trades": {
                "trade_id": {"type": "string", "required": True,
                             "nullable": False},
                "user_id": {"type": "string", "required": True,
                            "nullable": False},
                "amount": {"type": "number", "required": True,
                           "nullable": False, "minimum": 0},
                "status": {"type": "string", "required": True,
                           "nullable": False,
                           "enum": ["paid", "pending", "refunded"]},
            },
        },
        anomaly_rules={
            "users": {
                "user_id": [{"rule": "duplicate_rate", "max": 0.0}],
                "age": [{"rule": "range", "min": 18, "max": 100}],
            },
            "trades": {
                "trade_id": [{"rule": "duplicate_rate", "max": 0.0}],
                "amount": [{"rule": "range", "min": 0, "max": 100000}],
                "status": [{"rule": "regex",
                            "pattern": "^(paid|pending|refunded)$"}],
            },
        })


def base_lineage():
    return make_lineage([
        ("trade_owner", "trades", "user_id", "users", "user_id"),
    ])


def build_rename_packet(base):
    """当前包：trades.amount 改名为 trade_amount，且类型 number -> string。"""
    files = packet_files({
        "users": (USERS_HEADER, base_users_rows()),
        "trades": (
            ["trade_id", "user_id", "trade_amount", "status"],
            [
                ["T001", "U001", "100.50", "paid"],
                ["T002", "U002", "88.00", "pending"],
                ["T003", "U003", "12.20", "paid"],
            ],
        ),
    })
    return build_zip_packet(base, "current_rename.zip", files)


def build_rename_contract():
    contract = base_contract()
    trades_fields = contract["tables"]["trades"]["fields"]
    amount = trades_fields.pop("amount")
    amount["type"] = "string"
    trades_fields["trade_amount"] = amount
    # 规则迁移到新列名。
    contract["anomaly_rules"]["trades"] = {
        "trade_id": [{"rule": "duplicate_rate", "max": 0.0}],
        "trade_amount": [{"rule": "range", "min": 0, "max": 100000}],
        "status": [{"rule": "regex",
                    "pattern": "^(paid|pending|refunded)$"}],
    }
    contract["column_renames"] = {
        "trades": [{"from": "amount", "to": "trade_amount"}],
    }
    return contract
