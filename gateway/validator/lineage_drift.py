"""跨版本血缘漂移检测（纯函数模块，不直接读写数据库）。

快照数据全部来自 :func:`gateway.validator.lineage_check.validate_lineage`
的标准化输出与已读表的结构元数据，本模块不重新执行任何引用完整性校验。
存储层的损坏/不兼容异常通过 :class:`LineageSnapshotError` 上抛，由流水线
统一降级，保证单包校验主流程不被阻断。
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

SNAPSHOT_VERSION = 1
DEFAULT_LINEAGE_KEY = "default_lineage"

# 漂移类型固定顺序，保证报告与 JSON 输出在不同版本间稳定可解析。
CHANGE_TYPES = (
    "relation_added", "relation_removed", "relation_changed",
    "table_added", "table_removed", "table_split", "table_merged",
    "field_added", "field_removed",
)
_TYPE_ORDER = {name: index for index, name in enumerate(CHANGE_TYPES)}
_CHANGE_LABELS = {
    "relation_added": "血缘关联新增", "relation_removed": "血缘关联移除",
    "relation_changed": "血缘关联调整", "table_added": "表新增",
    "table_removed": "表移除", "table_split": "表拆分",
    "table_merged": "表合并", "field_added": "字段新增",
    "field_removed": "字段移除",
}
# 参与版本比对的关联属性，name/passed 仅作展示与存档，不参与属性漂移判定。
_RELATION_ATTRS = (
    "left_table", "left_field", "right_table", "right_field",
    "relationship", "require_reference", "allow_null",
)
_BOOL_DEFAULTS = {"require_reference": True, "allow_null": False}


class LineageSnapshotError(Exception):
    """血缘快照损坏或格式不兼容，调用方应降级处理而非中断主流程。"""


def lineage_domain_key(rules: Optional[Dict[str, Any]],
                       lineage_name: str = "") -> str:
    """确定同一业务契约的分组键。

    优先使用血缘规则顶层 ``name``（业务契约名，迭代间保持稳定）；规则
    不可用时退化为规则文件名主干；都缺失时落到默认分组。
    """
    key = ""
    if isinstance(rules, dict):
        key = str(rules.get("name") or "").strip()
    if not key and lineage_name:
        key = Path(str(lineage_name)).stem.strip()
    return key or DEFAULT_LINEAGE_KEY


def _attr_default(attr: str) -> Any:
    """关联属性在旧快照缺省情况下的默认值，与血缘校验器的规则默认对齐。"""
    if attr in _BOOL_DEFAULTS:
        return _BOOL_DEFAULTS[attr]
    return ""


def _relation_endpoint(relation: Dict[str, Any]) -> Dict[str, Any]:
    """抽取关联的可比属性子集。"""
    return {attr: relation.get(attr, _attr_default(attr)) for attr in _RELATION_ATTRS}


def build_lineage_snapshot(lineage_result: Dict[str, Any],
                           tables: Dict[str, Any],
                           rules: Optional[Dict[str, Any]],
                           *, task_id: str, packet_name: str,
                           created_at: Optional[str] = None) -> Dict[str, Any]:
    """基于血缘标准化结果与表结构构造当前版本的全量血缘快照。

    Args:
        lineage_result: ``validate_lineage`` 的统一输出（失败占位结果也可）。
        tables: 表名到 :class:`TableData` 的映射，仅读取列名与行数。
        rules: 已加载的血缘规则，用于解析业务契约分组键。
        task_id: 关联的校验任务 ID。
        packet_name: 数据包展示名。
        created_at: 测试可注入固定时间。
    """
    relations: List[Dict[str, Any]] = []
    for item in lineage_result.get("relations", []) or []:
        if not isinstance(item, dict):
            continue
        entry: Dict[str, Any] = {"name": str(item.get("name") or "")}
        for attr in _RELATION_ATTRS:
            if attr in _BOOL_DEFAULTS:
                entry[attr] = bool(item.get(attr, _attr_default(attr)))
            else:
                entry[attr] = item.get(attr, "")
        entry["passed"] = bool(item.get("passed"))
        relations.append(entry)

    table_snapshot: Dict[str, Any] = {}
    for table_name, table_data in (tables or {}).items():
        frame = getattr(table_data, "frame", None)
        if frame is None:
            fields: List[str] = []
            row_count = 0
        else:
            fields = [str(column) for column in frame.columns]
            row_count = int(len(frame))
        table_snapshot[str(table_name)] = {
            "fields": fields, "row_count": row_count,
        }

    return {
        "snapshot_version": SNAPSHOT_VERSION,
        "lineage_key": lineage_domain_key(rules),
        "task_id": str(task_id),
        "packet_name": str(packet_name),
        "created_at": created_at or datetime.now().isoformat(timespec="seconds"),
        "lineage_passed": bool(lineage_result.get("passed")),
        "tables": table_snapshot,
        "relations": relations,
    }


def validate_snapshot_payload(payload: Any) -> None:
    """校验历史快照结构与版本，不兼容时抛出 :class:`LineageSnapshotError`。"""
    if not isinstance(payload, dict):
        raise LineageSnapshotError("血缘快照格式不兼容：根节点不是映射")
    if payload.get("snapshot_version") != SNAPSHOT_VERSION:
        raise LineageSnapshotError(
            "血缘快照版本不受支持: %r" % payload.get("snapshot_version"))
    if not isinstance(payload.get("tables"), dict):
        raise LineageSnapshotError("血缘快照缺少 tables 结构")
    if not isinstance(payload.get("relations"), list):
        raise LineageSnapshotError("血缘快照缺少 relations 结构")


def _meta_block(payload: Dict[str, Any],
                meta: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """优先使用存储层元数据，缺失时回落到快照体内的审计字段。"""
    if isinstance(meta, dict) and meta:
        keys = ("snapshot_id", "version", "task_id", "packet_name",
                "created_at", "protected")
        return {key: meta[key] for key in keys if key in meta}
    return {
        "task_id": payload.get("task_id", ""),
        "packet_name": payload.get("packet_name", ""),
        "created_at": payload.get("created_at", ""),
    }


def _empty_counts() -> Dict[str, int]:
    """所有漂移类型归零的计数表，保证报告字段结构恒定。"""
    return {change_type: 0 for change_type in CHANGE_TYPES}


def _diff_relations(current_relations: List[Any],
                    baseline_relations: List[Any],
                    counts: Dict[str, int]) -> List[Dict[str, Any]]:
    """按关联 name 比对新增、移除与属性调整（含字段映射/基数变化）。"""
    current = {str(item.get("name")): item for item in current_relations
               if isinstance(item, dict)}
    baseline = {str(item.get("name")): item for item in baseline_relations
                if isinstance(item, dict)}
    changes: List[Dict[str, Any]] = []
    for name in sorted(set(current) - set(baseline)):
        counts["relation_added"] += 1
        changes.append({
            "type": "relation_added", "target": name, "detail": "新增血缘关联",
            "before": None, "after": _relation_endpoint(current[name]),
        })
    for name in sorted(set(baseline) - set(current)):
        counts["relation_removed"] += 1
        changes.append({
            "type": "relation_removed", "target": name, "detail": "血缘关联被移除",
            "before": _relation_endpoint(baseline[name]), "after": None,
        })
    for name in sorted(set(current) & set(baseline)):
        before: Dict[str, Any] = {}
        after: Dict[str, Any] = {}
        for attr in _RELATION_ATTRS:
            old_value = baseline[name].get(attr, _attr_default(attr))
            new_value = current[name].get(attr, _attr_default(attr))
            if old_value != new_value:
                before[attr] = old_value
                after[attr] = new_value
        if before:
            counts["relation_changed"] += 1
            changes.append({
                "type": "relation_changed", "target": name,
                "detail": "关联属性调整: %s" % "、".join(sorted(before)),
                "before": before, "after": after,
            })
    return changes


def _field_sets(tables: Dict[str, Any]) -> Dict[str, set]:
    """把快照表结构归一化为 表名 -> 字段集合。"""
    return {
        str(name): {str(field) for field in table.get("fields", [])}
        if isinstance(table, dict) else set()
        for name, table in tables.items()
    }


def _diff_tables(current_tables: Dict[str, Any],
                 baseline_tables: Dict[str, Any],
                 counts: Dict[str, int]) -> List[Dict[str, Any]]:
    """比对表增删、字段增删，并启发式识别表拆分/合并。"""
    current_fields = _field_sets(current_tables)
    baseline_fields = _field_sets(baseline_tables)
    added_tables = sorted(set(current_fields) - set(baseline_fields))
    removed_tables = sorted(set(baseline_fields) - set(current_fields))
    explained_added: set = set()
    explained_removed: set = set()
    changes: List[Dict[str, Any]] = []

    # 合并：一张新表的字段由两张及以上被移除表共同贡献，且覆盖新表过半字段。
    for name in added_tables:
        contributors = [old for old in removed_tables
                        if baseline_fields[old] & current_fields[name]]
        union = set()
        for old in contributors:
            union |= baseline_fields[old]
        threshold = max(1, len(current_fields[name]) // 2)
        if len(contributors) >= 2 and len(union & current_fields[name]) >= threshold:
            counts["table_merged"] += 1
            changes.append({
                "type": "table_merged", "target": name,
                "detail": "由 %s 合并形成" % "、".join(contributors),
                "before": {"tables": contributors},
                "after": {"fields": sorted(current_fields[name])},
            })
            explained_added.add(name)
            explained_removed.update(contributors)

    # 拆分：被移除表的过半字段分散到一张或多张新表中。
    for name in removed_tables:
        if name in explained_removed:
            continue
        targets = [new for new in added_tables
                   if new not in explained_added
                   and baseline_fields[name] & current_fields[new]]
        union = set()
        for new in targets:
            union |= baseline_fields[name] & current_fields[new]
        threshold = max(1, len(baseline_fields[name]) // 2)
        if targets and len(union) >= threshold:
            counts["table_split"] += 1
            changes.append({
                "type": "table_split", "target": name,
                "detail": "拆分为 %s" % "、".join(targets),
                "before": {"fields": sorted(baseline_fields[name])},
                "after": {"tables": targets},
            })
            explained_removed.add(name)
            explained_added.update(targets)

    for name in added_tables:
        if name in explained_added:
            continue
        counts["table_added"] += 1
        changes.append({
            "type": "table_added", "target": name, "detail": "新增表",
            "before": None,
            "after": {"fields": sorted(current_fields[name]),
                      "row_count": int(current_tables[name].get("row_count", 0))},
        })
    for name in removed_tables:
        if name in explained_removed:
            continue
        counts["table_removed"] += 1
        changes.append({
            "type": "table_removed", "target": name, "detail": "表被移除",
            "before": {"fields": sorted(baseline_fields[name]),
                       "row_count": int(baseline_tables[name].get("row_count", 0))},
            "after": None,
        })

    for name in sorted(set(current_fields) & set(baseline_fields)):
        for field in sorted(current_fields[name] - baseline_fields[name]):
            counts["field_added"] += 1
            changes.append({
                "type": "field_added", "target": "%s.%s" % (name, field),
                "detail": "字段新增", "before": None, "after": field,
            })
        for field in sorted(baseline_fields[name] - current_fields[name]):
            counts["field_removed"] += 1
            changes.append({
                "type": "field_removed", "target": "%s.%s" % (name, field),
                "detail": "字段移除", "before": field, "after": None,
            })
    return changes


def _build_summary(counts: Dict[str, int], has_changes: bool) -> str:
    """生成稳定的中文概要，供报告概览与任务日志直接使用。"""
    if not has_changes:
        return "与上一版本相比，血缘结构未发生变化"
    parts = ["%s %d 处" % (_CHANGE_LABELS[change_type], counts[change_type])
             for change_type in CHANGE_TYPES if counts[change_type]]
    return "检测到血缘漂移: " + "，".join(parts)


def detect_lineage_drift(current: Dict[str, Any],
                         baseline: Dict[str, Any],
                         *, current_meta: Optional[Dict[str, Any]] = None,
                         baseline_meta: Optional[Dict[str, Any]] = None
                         ) -> Dict[str, Any]:
    """比对两个全量快照，输出结构化漂移结果。

    Raises:
        LineageSnapshotError: 任一快照损坏或版本不兼容。
    """
    validate_snapshot_payload(current)
    validate_snapshot_payload(baseline)
    counts = _empty_counts()
    changes = _diff_relations(current.get("relations", []),
                              baseline.get("relations", []), counts)
    changes.extend(_diff_tables(current.get("tables", {}),
                                baseline.get("tables", {}), counts))
    changes.sort(key=lambda change: (_TYPE_ORDER[change["type"]],
                                     change["target"]))
    has_changes = bool(changes)
    lineage_key = (current.get("lineage_key") or baseline.get("lineage_key")
                   or DEFAULT_LINEAGE_KEY)
    return {
        "enabled": True,
        "degraded": False,
        "lineage_key": lineage_key,
        "baseline": _meta_block(baseline, baseline_meta),
        "current": _meta_block(current, current_meta),
        "has_changes": has_changes,
        "changes": changes,
        "counts": counts,
        "summary": _build_summary(counts, has_changes),
    }


def first_version_drift(snapshot: Dict[str, Any],
                        current_meta: Optional[Dict[str, Any]] = None,
                        lineage_key: Optional[str] = None) -> Dict[str, Any]:
    """业务契约首个版本的漂移结果：无基线但不属于降级。"""
    return {
        "enabled": True,
        "degraded": False,
        "lineage_key": lineage_key or snapshot.get("lineage_key")
        or DEFAULT_LINEAGE_KEY,
        "baseline": None,
        "current": _meta_block(snapshot, current_meta),
        "has_changes": False,
        "changes": [],
        "counts": _empty_counts(),
        "summary": "首次存档血缘快照，暂无历史版本可比对",
    }


def unavailable_drift(reason: str, *, code: str = "drift_unavailable",
                      lineage_key: Optional[str] = None,
                      current_meta: Optional[Dict[str, Any]] = None,
                      baseline_meta: Optional[Dict[str, Any]] = None
                      ) -> Dict[str, Any]:
    """构造降级结果：保留当前任务审计信息，不产出漂移变更。"""
    return {
        "enabled": True,
        "degraded": True,
        "lineage_key": lineage_key or DEFAULT_LINEAGE_KEY,
        "baseline": baseline_meta,
        "current": current_meta,
        "has_changes": False,
        "changes": [],
        "counts": _empty_counts(),
        "summary": reason,
        "error": {"code": code, "message": reason},
    }
