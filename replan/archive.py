"""上一版准入结果存档的解析与可信度校验。

规划器需要的旧存档完整形态（replan 原生格式，可由本工具归档或由准入
流水线产出）::

    {
      "schema": "replan-admission-archive/1",
      "packet":   {"location": ..., "sha256": ..., "files": {member: {"sha256": ...}}},
      "contract_fingerprint": "...",
      "lineage_fingerprint": "...",
      "tables": {
        table: {
          "member": ..., "format": ..., "row_count": 12,
          "columns": {
             column: {"sha256": ..., "row_count": 12, "null_count": 1}
          }
        }
      },
      "rules": [{"id": ..., "fingerprint": ..., "table": ..., "column": ...}],
      "admission": {"passed": true, "task_id": ..., "generated_at": ...}
    }

历史存档字段不全会是常态：gateway 旧版 JSON 报告通常只有表级摘要、没有
列级指纹。此时本模块不是猜测，而是明确返回 ``usable=False`` 与可读原因，
由规划器保守退化为整包全量重检，绝不静默漏检。
"""

import json
import os

from .errors import FallbackError
from .textio import load_structured_file

ARCHIVE_SCHEMA = "replan-admission-archive/1"
REQUIRED_COLUMN_KEYS = ("sha256", "row_count", "null_count")


def load_admission_archive(path):
    """读取并校验旧准入存档。

    Returns:
        ``{"usable": bool, "reasons": [...], "data": dict|None}``。
        文件缺失或无法可靠读取时返回不可用结果（交给上层降级），
        不会抛出致命错误。
    """
    if path is None or not os.path.exists(str(path)):
        return _unusable(
            "未提供上一版准入结果存档，无任何列级指纹可沿用，"
            "保守执行整包全量重检",
            "missing_old_archive")
    try:
        data = load_structured_file(path)
    except (ValueError, OSError, UnicodeError) as exc:
        return _unusable(
            "旧准入存档格式或编码无法可靠读取（%s），保守执行整包全量重检"
            % exc,
            "old_archive_unreadable")
    if not isinstance(data, dict):
        return _unusable("旧准入存档根节点不是映射，保守执行整包全量重检",
                         "old_archive_invalid")

    # 兼容 gateway 报告 JSON：其结构里没有列级指纹块。
    if data.get("schema") != ARCHIVE_SCHEMA:
        return _unusable(
            "旧准入存档缺少 schema=%s 的列级指纹块（历史表级摘要无法支撑"
            "列级沿用判断），保守执行整包全量重检" % ARCHIVE_SCHEMA,
            "old_archive_table_level_only")

    reasons = []
    tables = data.get("tables")
    if not isinstance(tables, dict) or not tables:
        reasons.append({
            "code": "old_archive_missing_fingerprints",
            "message": "旧存档缺少 tables 列级指纹，无法判断哪些旧结论可沿用",
        })
        return _unusable_from_reasons(reasons)

    for table_name in sorted(tables.keys()):
        table = tables[table_name]
        if not isinstance(table, dict) or not isinstance(
                table.get("columns"), dict) or not table["columns"]:
            reasons.append({
                "code": "old_archive_missing_fingerprints",
                "message": "旧存档表 %s 缺少列级指纹块" % table_name,
                "table": str(table_name),
            })
            continue
        for column in sorted(table["columns"].keys()):
            column_info = table["columns"][column]
            if not isinstance(column_info, dict) or any(
                    key not in column_info for key in REQUIRED_COLUMN_KEYS):
                reasons.append({
                    "code": "old_archive_missing_fingerprints",
                    "message": "旧存档列 %s.%s 的指纹字段不全（需要 %s）"
                               % (table_name, column,
                                  "/".join(REQUIRED_COLUMN_KEYS)),
                    "table": str(table_name),
                    "column": str(column),
                })
    if reasons:
        return _unusable_from_reasons(reasons)

    packet = data.get("packet")
    if not isinstance(packet, dict):
        return _unusable("旧存档缺少 packet 完整性声明，无法核对旧包是否被改动",
                         "old_archive_missing_fingerprints")
    rules = data.get("rules")
    if rules is not None and not isinstance(rules, list):
        return _unusable("旧存档 rules 结构非法，保守执行整包全量重检",
                         "old_archive_invalid")
    return {
        "usable": True,
        "reasons": [],
        "data": data,
        "packet_sha256": packet.get("sha256"),
        "files": packet.get("files") if isinstance(packet.get("files"), dict) else {},
        "tables": tables,
        "rules": rules or [],
        "contract_fingerprint": data.get("contract_fingerprint"),
        "lineage_fingerprint": data.get("lineage_fingerprint"),
        "admission": data.get("admission") if isinstance(
            data.get("admission"), dict) else {},
    }


def verify_against_old_packet(archive_info, old_packet):
    """用旧数据包成员哈希核对存档声明，返回不一致原因列表（空列表=一致）。"""
    reasons = []
    if not archive_info["usable"]:
        return archive_info["reasons"]
    declared_files = archive_info["files"]
    actual_files = old_packet.member_hashes
    if set(declared_files.keys()) != set(actual_files.keys()):
        missing = sorted(set(declared_files) - set(actual_files))
        extra = sorted(set(actual_files) - set(declared_files))
        reasons.append({
            "code": "old_packet_mismatch",
            "message": "旧数据包成员清单与存档声明不一致（缺失 %s，新增 %s），"
                       "旧指纹可信度不足" % (missing or "-", extra or "-"),
        })
        return reasons
    for member in sorted(declared_files.keys()):
        declared = declared_files[member]
        declared_hash = declared.get("sha256") if isinstance(declared, dict) \
            else declared
        if declared_hash != actual_files[member]:
            reasons.append({
                "code": "old_packet_mismatch",
                "message": "旧数据包成员 %s 的哈希与存档声明不一致，"
                           "旧指纹可信度不足" % member,
                "member": member,
            })
    # 存档声明的表/列在旧包物理结构中必须仍然存在。
    for table_name in sorted(archive_info["tables"].keys()):
        archived_table = archive_info["tables"][table_name]
        scan = old_packet.tables.get(table_name)
        if scan is None:
            reasons.append({
                "code": "old_packet_mismatch",
                "message": "旧数据包缺少存档声明的表 %s" % table_name,
                "table": table_name,
            })
            continue
        archived_columns = set(archived_table["columns"].keys())
        if not archived_columns.issubset(set(scan.columns)):
            reasons.append({
                "code": "old_packet_mismatch",
                "message": "旧数据包表 %s 缺少存档声明的列 %s"
                           % (table_name,
                              sorted(archived_columns - set(scan.columns))),
                "table": table_name,
            })
    return reasons


def _unusable(message, code):
    return {
        "usable": False,
        "reasons": [{"code": code, "message": message}],
        "data": None,
    }


def _unusable_from_reasons(reasons):
    return {"usable": False, "reasons": reasons, "data": None}


def build_admission_archive(packet_read, contract, lineage, admission=None):
    """从一次数据包读取结果构造可归档的列级指纹存档。"""
    tables = {}
    for table_name in sorted(packet_read.tables.keys()):
        scan = packet_read.tables[table_name]
        tables[table_name] = {
            "member": scan.member,
            "format": scan.format,
            "row_count": scan.row_count,
            "columns": {
                column: {
                    "sha256": scan.fingerprints[column].sha256,
                    "row_count": scan.fingerprints[column].row_count,
                    "null_count": scan.fingerprints[column].null_count,
                }
                for column in sorted(scan.fingerprints.keys())
            },
        }
    files = {
        member: {"sha256": packet_read.member_hashes[member]}
        for member in sorted(packet_read.member_hashes.keys())
    }
    return {
        "schema": ARCHIVE_SCHEMA,
        "packet": {
            "location": packet_read.location,
            "kind": packet_read.kind,
            "files": files,
        },
        "contract_fingerprint": contract["fingerprint"],
        "lineage_fingerprint": lineage["fingerprint"] if lineage else None,
        # 快照旧契约字段定义与血缘边，供下一版比较类型/可空性/约束变化。
        "contract": _contract_snapshot(contract),
        "lineage": {
            "edges": [
                {key: edge[key] for key in sorted(edge)}
                for edge in lineage["edges"]
            ],
        } if lineage else {"edges": []},
        "tables": tables,
        "rules": [
            {
                "id": rule["id"],
                "table": rule["table"],
                "column": rule["column"],
                "kind": rule["kind"],
                "fingerprint": rule["fingerprint"],
            }
            for rule in contract["rules"]
        ],
        "admission": admission or {},
    }


def _contract_snapshot(contract):
    """提取归档所需的旧契约字段视图（不含原始大对象）。"""
    return {
        "name": contract["name"],
        "tables": {
            table_name: {
                "fields": {
                    field_name: {
                        "type": field_spec["type"],
                        "required": field_spec["required"],
                        "nullable": field_spec["nullable"],
                        "constraints": field_spec["constraints"],
                    }
                    for field_name, field_spec in table["fields"].items()
                },
            }
            for table_name, table in contract["tables"].items()
        },
    }


def write_json(path, payload):
    """以确定性 JSON（键排序、无 ASCII 转义）落盘。"""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


# 供其它模块复用：存档不可用统一转换为降级异常。
def archive_fallback(reasons):
    messages = "；".join(reason["message"] for reason in reasons)
    code = reasons[0]["code"] if reasons else "old_archive_invalid"
    return FallbackError(messages, code)
