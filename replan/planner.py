"""规划器主编排：读取两侧输入、决定定向分析或全量降级并产出计划。"""

import hashlib
import json

from . import MODE_FULL_FALLBACK, MUST, SUGGESTED, REUSE
from .archive import build_admission_archive, load_admission_archive, \
    verify_against_old_packet
from .contract import load_contract, load_lineage, fingerprint_of
from .engine import PlannerEngine
from .errors import FallbackError, PlannerError
from .packet import read_packet
from .workdir import WorkDir

PLAN_SCHEMA = "replan-minimal-recheck/1"


def _packet_fingerprint(packet_read):
    """整包确定性指纹：成员名排序后的 (成员名, sha256) 序列。"""
    payload = [
        {"member": member, "sha256": packet_read.member_hashes[member]}
        for member in sorted(packet_read.member_hashes.keys())
    ]
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8")).hexdigest()


def _empty_contract(contract_path):
    """契约无法可靠解析时使用的空模型，仅用于构造全量降级计划。"""
    import os
    return {
        "name": os.path.basename(str(contract_path)),
        "version": "",
        "tables": {},
        "rules": [],
        "renames": {},
        "raw": {},
        "fingerprint": None,
    }


def _packet_error_reasons(packet_read, label):
    return [
        {
            "code": "packet_read_error",
            "message": "%s数据包成员 %s（表 %s）无法可靠读取：%s"
                       % (label, err.get("member"), err.get("table"),
                          err.get("message")),
            "table": err.get("table"),
            "member": err.get("member"),
            "detail_code": err.get("code"),
        }
        for err in packet_read.read_errors
    ]


def build_plan(old_packet_path, new_packet_path, contract_path, lineage_path,
               old_archive_path, work_base=None, limits=None,
               generated_at=None):
    """执行一次完整规划，返回计划字典（同时含归档所需全部信息）。

    Args:
        old_packet_path: 上一版数据包；可为 None（此时必须有旧存档，否则降级）。
        new_packet_path: 当前数据包，必须可读取，否则抛 PlannerError。
        contract_path: 当前契约文件。
        lineage_path: 当前血缘规则文件。
        old_archive_path: 上一版准入结果存档；可为 None。
        work_base: 临时目录根；每次运行仍会创建独立子目录。
        generated_at: 注入生成时间（测试用），None 时取当前 UTC。
    """
    from datetime import datetime, timezone
    generated_at = generated_at or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")

    with WorkDir(work_base) as work_dir:
        return _build_inner(
            old_packet_path, new_packet_path, contract_path, lineage_path,
            old_archive_path, work_dir, limits, generated_at)


def _build_inner(old_packet_path, new_packet_path, contract_path, lineage_path,
                 old_archive_path, work_dir, limits, generated_at):
    # 当前数据包是硬前提：缺失/不支持的形态直接致命退出。
    new_packet = read_packet(new_packet_path, work_dir, limits)

    fallback_reasons = []
    old_packet = None
    archive_info = {"usable": False, "reasons": [], "data": None,
                    "tables": {}, "rules": [], "files": {},
                    "packet_sha256": None, "contract_fingerprint": None,
                    "lineage_fingerprint": None, "admission": {}}

    # 契约/血缘“文件缺失”是致命输入错误；但内容无法可靠解析、规则引用无法
    # 解析等可降级问题，转换为整包全量重检原因而不是中断（绝不静默漏检）。
    try:
        contract = load_contract(contract_path)
        lineage = load_lineage(lineage_path, contract)
    except FallbackError as exc:
        fallback_reasons.append({
            "code": exc.code,
            "message": str(exc),
            "scope": getattr(exc, "scope", "package"),
        })
        contract = getattr(exc, "contract", None) or _empty_contract(
            contract_path)
        lineage = {"name": "", "edges": [], "adjacency": {}, "nodes": [],
                   "fingerprint": None}

    # 2) 当前包自身存在不可读成员时，无法保证列级完整性，保守降级。
    current_errors = _packet_error_reasons(new_packet, "当前")
    if current_errors:
        fallback_reasons.extend(current_errors)

    # 3) 旧存档解析（缺失/字段不全是常态）。
    loaded_archive = load_admission_archive(old_archive_path)
    if not loaded_archive["usable"]:
        fallback_reasons.extend(loaded_archive["reasons"])
    else:
        archive_info = loaded_archive

    # 4) 旧数据包读取（用于交叉核对存档可信度）。
    if old_packet_path is not None:
        try:
            old_packet = read_packet(old_packet_path, work_dir, limits)
        except PlannerError:
            raise
        except Exception as exc:  # 读取器的防护性异常统一转为降级原因
            fallback_reasons.append({
                "code": "old_packet_unreadable",
                "message": "上一版数据包无法可靠读取（%s），旧指纹无法交叉核对，"
                           "保守执行整包全量重检" % exc,
            })
            old_packet = None
        if old_packet is not None:
            old_errors = _packet_error_reasons(old_packet, "上一版")
            if old_errors:
                fallback_reasons.extend(old_errors)
            if loaded_archive["usable"]:
                mismatch = verify_against_old_packet(archive_info, old_packet)
                if mismatch:
                    fallback_reasons.extend(mismatch)

    # 5) 契约/血缘变化不直接降级：引擎会用存档中的旧契约/血缘快照做逐列、
    #    逐关系比较。只有存档缺少快照、无法可靠比较时才保守降级。
    #    若契约/血缘本身已无法解析（fingerprint 为 None），前置原因已记录，
    #    这里跳过比较避免叠加误导性原因。
    if archive_info["usable"] and contract["fingerprint"] is not None:
        data = archive_info["data"] or {}
        contract_changed = archive_info.get("contract_fingerprint") not in (
            None, contract["fingerprint"])
        lineage_changed = archive_info.get("lineage_fingerprint") not in (
            None, lineage["fingerprint"])
        if contract_changed and not isinstance(data.get("contract"), dict):
            fallback_reasons.append({
                "code": "old_archive_missing_contract_snapshot",
                "message": "契约已变化但旧存档缺少契约快照，无法逐列比较"
                           "字段定义，保守执行整包全量重检",
            })
        if lineage_changed and not isinstance(
                (data.get("lineage") or {}).get("edges"), list):
            fallback_reasons.append({
                "code": "old_archive_missing_lineage_snapshot",
                "message": "血缘规则已变化但旧存档缺少血缘快照，无法逐条"
                           "比较引用关系，保守执行整包全量重检",
            })

    # 6) 去重降级原因（保持确定性顺序）。
    unique_reasons = []
    seen = set()
    for reason in fallback_reasons:
        marker = (reason["code"], reason["message"],
                  reason.get("table"), reason.get("member"))
        if marker not in seen:
            seen.add(marker)
            unique_reasons.append(reason)
    fallback_reasons = unique_reasons

    engine = PlannerEngine(old_packet, new_packet, contract, lineage,
                           archive_info, fallback_reasons)
    if fallback_reasons:
        snapshot = engine.build_full_fallback()
    else:
        try:
            snapshot = engine.build_targeted()
        except FallbackError as exc:
            # 定向分析中发现引用无法解析等问题：带原因重新走全量降级。
            fallback_reasons.append({
                "code": exc.code,
                "message": str(exc),
                "scope": getattr(exc, "scope", "package"),
            })
            engine.fallback_reasons = fallback_reasons
            snapshot = engine.build_full_fallback()

    plan = _assemble_plan(snapshot, new_packet, contract, lineage,
                         old_packet, archive_info, generated_at)
    return plan


def _assemble_plan(snapshot, new_packet, contract, lineage, old_packet,
                   archive_info, generated_at):
    new_fp = _packet_fingerprint(new_packet)
    old_fp = _packet_fingerprint(old_packet) if old_packet is not None else None
    counts = {MUST: 0, SUGGESTED: 0, REUSE: 0}
    for column in snapshot["columns"]:
        counts[column["decision"]] += 1
    rule_counts = {MUST: 0, SUGGESTED: 0, REUSE: 0}
    for rule in snapshot["rules"]:
        rule_counts[rule["decision"]] += 1
    relation_counts = {MUST: 0, SUGGESTED: 0, REUSE: 0}
    for relation in snapshot["relations"]:
        relation_counts[relation["decision"]] += 1

    # 注意：location / kind 属于运行环境字段（同内容可由 zip、tar.gz、
    # 目录承载，路径也每次不同），不参与 plan_fingerprint 计算。
    environment = {
        "current_packet_location": new_packet.location,
        "current_packet_kind": new_packet.kind,
        "previous_packet_location":
            old_packet.location if old_packet else None,
    }
    plan_body = {
        "schema": PLAN_SCHEMA,
        "mode": snapshot["mode"],
        "inputs": {
            "current_packet": {
                "packet_fingerprint": new_fp,
                "member_count": len(new_packet.members),
                "table_count": len(new_packet.tables),
            },
            "previous_packet": {
                "packet_fingerprint": old_fp,
            },
            "contract": {
                "name": contract["name"],
                "fingerprint": contract["fingerprint"],
            },
            "lineage": {
                "name": lineage["name"],
                "fingerprint": lineage["fingerprint"],
                "relation_count": len(lineage["edges"]),
            },
            "admission_archive_usable": archive_info["usable"],
        },
        "fallback_reasons": snapshot["fallback_reasons"],
        "scope_summary": {
            "tables_total": len(new_packet.tables),
            "tables_must_recheck": sum(
                1 for table in snapshot["tables"]
                if table["decision"] == MUST),
            "columns_total": len(snapshot["columns"]),
            "columns": counts,
            "rules_total": len(snapshot["rules"]),
            "rules": rule_counts,
            "relations_total": len(snapshot["relations"]),
            "relations": relation_counts,
            "reuse_ratio": _reuse_ratio(snapshot),
        },
        "table_changes": {
            "added": snapshot["added_tables"],
            "removed": snapshot["removed_tables"],
            "renames": snapshot["rename_map"],
        },
        "tables": snapshot["tables"],
        "columns": snapshot["columns"],
        "rules": snapshot["rules"],
        "relations": snapshot["relations"],
        "recheck_plan": _executable_plan(snapshot),
        "reuse_evidence": _reuse_evidence(snapshot),
    }
    # 计划内容指纹：仅基于 plan_body，排除时间与环境字段。
    content_fingerprint = fingerprint_of(plan_body)
    plan_body["environment"] = environment
    plan_body["generated_at"] = generated_at
    plan_body["plan_fingerprint"] = content_fingerprint
    return plan_body


def _reuse_ratio(snapshot):
    total = len(snapshot["columns"])
    if not total:
        return 0.0
    reused = sum(1 for column in snapshot["columns"]
                 if column["decision"] == REUSE)
    return round(reused / total, 4)


def _executable_plan(snapshot):
    """生成可直接交给现有校验流水线消费的重检范围清单。"""
    tables = []
    for table in snapshot["tables"]:
        if table["decision"] == REUSE:
            continue
        tables.append({
            "table": table["table"],
            "decision": table["decision"],
            "columns": sorted(table["must_columns"]
                              + table["suggested_columns"]
                              + table.get("removed_columns", [])),
            "must_columns": sorted(table["must_columns"]),
            "suggested_columns": sorted(table["suggested_columns"]),
            "removed_columns": sorted(table.get("removed_columns", [])),
            "rule_ids": sorted(
                rule["rule_id"] for rule in snapshot["rules"]
                if rule["table"] == table["table"]
                and rule["decision"] != REUSE),
            "relation_names": sorted(
                relation["relation"] for relation in snapshot["relations"]
                if relation["decision"] != REUSE
                and (relation["left_table"] == table["table"]
                     or relation["right_table"] == table["table"])),
        })
    return {
        "mode": snapshot["mode"],
        "full_recheck": snapshot["mode"] == MODE_FULL_FALLBACK,
        "tables": sorted(tables, key=lambda item: item["table"]),
        "rule_ids": sorted(
            rule["rule_id"] for rule in snapshot["rules"]
            if rule["decision"] != REUSE),
        "relation_names": sorted(
            relation["relation"] for relation in snapshot["relations"]
            if relation["decision"] != REUSE),
    }


def _reuse_evidence(snapshot):
    """列出可沿用旧结论的对象及依据，供归档审计。"""
    columns = [
        {
            "table": column["table"],
            "column": column["column"],
            "old_fingerprint": column["old_fingerprint"],
            "new_fingerprint": column["new_fingerprint"],
            "basis": "列级 SHA256 指纹一致，且契约字段定义未变化",
        }
        for column in snapshot["columns"] if column["decision"] == REUSE
    ]
    rules = [
        {
            "rule_id": rule["rule_id"],
            "basis": rule["reasons"][0]["message"],
            "reused_from": rule.get("reused_from"),
        }
        for rule in snapshot["rules"] if rule["decision"] == REUSE
    ]
    relations = [
        {
            "relation": relation["relation"],
            "basis": relation["reasons"][0]["message"],
        }
        for relation in snapshot["relations"]
        if relation["decision"] == REUSE
    ]
    return {
        "columns": sorted(columns,
                          key=lambda item: (item["table"], item["column"])),
        "rules": sorted(rules, key=lambda item: item["rule_id"]),
        "relations": sorted(relations, key=lambda item: item["relation"]),
    }


def build_archive_from_plan(new_packet_path, contract_path, lineage_path,
                            admission=None, work_base=None, limits=None):
    """便捷入口：对当前数据包生成可归档的列级指纹存档。"""
    with WorkDir(work_base) as work_dir:
        packet_read = read_packet(new_packet_path, work_dir, limits)
        contract = load_contract(contract_path)
        lineage = load_lineage(lineage_path, contract)
        return build_admission_archive(packet_read, contract, lineage,
                                       admission=admission)
