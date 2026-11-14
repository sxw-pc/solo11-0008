"""跨表血缘一致性校验与链路图生成。

规则以 YAML 声明左右表、关联字段和基数关系。校验时对关联键做规范化，
因此 csv、parquet 与 sqlite 之间的数值/文本键也能稳定比较。检测范围包括
空引用、孤立记录、被引用键缺失以及一对一等基数异常。
"""

from datetime import date, datetime
from numbers import Integral
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import yaml

from ..parser.table_reader import TableData

RELATIONSHIPS = {"one_to_one", "one_to_many", "many_to_one"}
_REL_LABELS = {"one_to_one": "1→1", "one_to_many": "1→多", "many_to_one": "多→1"}


class LineageRuleError(Exception):
    """血缘规则文件格式错误。"""


def load_lineage_rules(path: Path) -> Dict[str, Any]:
    """加载并检查血缘 YAML 规则。

    Raises:
        LineageRuleError: 文件缺失、YAML 损坏或 relations 结构非法。
    """
    path = Path(path)
    if not path.is_file():
        raise LineageRuleError("血缘规则文件不存在: %s" % path.name)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise LineageRuleError("血缘规则 YAML 解析失败: %s" % exc) from exc
    if not isinstance(data, dict) or not isinstance(data.get("relations"), list):
        raise LineageRuleError("血缘规则必须包含 relations 列表")
    return data


def _endpoint(relation: Dict[str, Any], side: str) -> Tuple[str, str]:
    """兼容嵌套与扁平两种端点写法。"""
    nested = relation.get(side)
    if isinstance(nested, dict):
        table, field = nested.get("table"), nested.get("field")
    else:
        table, field = relation.get(side + "_table"), relation.get(side + "_field")
    if not table or not field:
        raise LineageRuleError("关联 %s 的 %s 端点缺少 table/field"
                               % (relation.get("name", "?"), side))
    return str(table), str(field)


def _normalize_key(value: Any) -> Optional[str]:
    """把关联键转为稳定的字符串键，空值统一为 None。"""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, float):
        if pd.isna(value):
            return None
        return str(int(value)) if value.is_integer() else repr(value)
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if hasattr(value, "item"):
        try:
            return _normalize_key(value.item())
        except (ValueError, AttributeError):
            pass
    return str(value)


def _series_keys(series: pd.Series) -> List[Tuple[Any, Optional[str]]]:
    """返回 (原始索引, 规范键) 列表，保留行号用于定位样例。"""
    keys = []
    for index, value in series.items():
        keys.append((index, _normalize_key(value)))
    return keys


def _sample_issue(relation: str, issue: str, value: Any,
                  row: Any, message: str, offset: int = 0) -> Dict[str, Any]:
    """构造单条血缘异常样例，并折算为原始行号。"""
    row_number = int(row) + offset if isinstance(row, Integral) else None
    return {
        "relation": relation, "issue": issue,
        "value": value if not isinstance(value, str) or len(value) <= 60 else value[:60] + "...",
        "row": row_number, "message": message,
    }


def _check_relation(name: str, relation: Dict[str, Any],
                    tables: Dict[str, TableData]) -> Dict[str, Any]:
    """执行单条关联规则并返回明细。"""
    left_table, left_field = _endpoint(relation, "left")
    right_table, right_field = _endpoint(relation, "right")
    relationship = str(relation.get("relationship", "many_to_one"))
    if relationship not in RELATIONSHIPS:
        raise LineageRuleError("关联 %s 的 relationship 不受支持" % name)
    left_data = tables.get(left_table)
    right_data = tables.get(right_table)
    base = {
        "name": name, "left_table": left_table, "left_field": left_field,
        "right_table": right_table, "right_field": right_field,
        "relationship": relationship,
    }
    missing_tables = [table for table, data in ((left_table, left_data),
                                                (right_table, right_data)) if data is None]
    if missing_tables:
        error = {"code": "table_missing", "message": "关联表不存在: %s"
                 % "、".join(missing_tables)}
        return {**base, "passed": False, "errors": [error], "samples": [],
                "orphan_count": 0, "missing_reference_count": 0,
                "cardinality_errors": 0, "left_rows": 0, "right_rows": 0}
    if left_field not in left_data.frame.columns or right_field not in right_data.frame.columns:
        missing_fields = []
        if left_field not in left_data.frame.columns:
            missing_fields.append("%s.%s" % (left_table, left_field))
        if right_field not in right_data.frame.columns:
            missing_fields.append("%s.%s" % (right_table, right_field))
        error = {"code": "field_missing", "message": "关联字段不存在: %s"
                 % "、".join(missing_fields)}
        return {**base, "passed": False, "errors": [error], "samples": [],
                "orphan_count": 0, "missing_reference_count": 0,
                "cardinality_errors": 0, "left_rows": len(left_data.frame),
                "right_rows": len(right_data.frame)}
    left_keys = _series_keys(left_data.frame[left_field])
    right_keys = _series_keys(right_data.frame[right_field])
    right_set = {key for _, key in right_keys if key is not None}
    left_non_null = [(index, key) for index, key in left_keys if key is not None]
    null_left = [(index, None) for index, key in left_keys if key is None]
    allow_null = bool(relation.get("allow_null", False))
    require_reference = bool(relation.get("require_reference", True))
    errors: List[Dict[str, Any]] = []
    samples: List[Dict[str, Any]] = []
    missing_reference_count = 0 if allow_null else len(null_left)
    if require_reference and missing_reference_count:
        errors.append({"code": "reference_missing",
                       "message": "关联字段存在 %d 个空引用" % missing_reference_count})
        for index, _ in null_left[:10]:
            if len(samples) < 20:
                samples.append(_sample_issue(name, "reference_missing", None, index,
                                             "关联字段为空", left_data.row_offset))
    orphan = [(index, key) for index, key in left_non_null if key not in right_set]
    if require_reference and orphan:
        errors.append({"code": "orphan_record",
                       "message": "存在 %d 条孤立记录，引用键在被引用表中不存在" % len(orphan)})
        for index, key in orphan[:10]:
            if len(samples) < 20:
                samples.append(_sample_issue(name, "orphan_record", key, index,
                                             "引用键在 %s 中不存在" % right_table,
                                             left_data.row_offset))
    cardinality_errors = 0
    left_duplicate = len(left_non_null) - len({key for _, key in left_non_null})
    right_duplicate = len([1 for _, key in right_keys if key is not None]) - len(right_set)
    if relationship in ("one_to_one", "one_to_many") and left_duplicate:
        cardinality_errors += left_duplicate
        errors.append({"code": "cardinality_error",
                       "message": "%s.%s 存在 %d 个重复关联键，违反 %s 基数"
                                  % (left_table, left_field, left_duplicate,
                                     _REL_LABELS[relationship])})
    if relationship in ("one_to_one", "many_to_one") and right_duplicate:
        cardinality_errors += right_duplicate
        errors.append({"code": "cardinality_error",
                       "message": "%s.%s 存在 %d 个重复被引用键，违反 %s 基数"
                                  % (right_table, right_field, right_duplicate,
                                     _REL_LABELS[relationship])})
    if cardinality_errors and len(samples) < 20:
        samples.append({
            "relation": name, "issue": "cardinality_error",
            "value": None, "row": None,
            "message": "重复键数量: %d" % cardinality_errors,
        })
    return {
        **base, "passed": not errors, "errors": errors, "samples": samples[:20],
        "orphan_count": len(orphan) if require_reference else 0,
        "missing_reference_count": missing_reference_count,
        "cardinality_errors": cardinality_errors,
        "left_rows": len(left_data.frame), "right_rows": len(right_data.frame),
    }


def _build_graph(relations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """生成文本链路和可离线渲染的 Mermaid 源码。"""
    node_ids: Dict[str, str] = {}
    lines = []
    for relation in relations:
        for table in (relation.get("left_table"), relation.get("right_table")):
            if table and table not in node_ids:
                node_ids[str(table)] = "T%d" % len(node_ids)
    broken_nodes = set()
    mermaid = ["graph LR"]
    for table, node_id in node_ids.items():
        safe_label = table.replace('"', "'")
        mermaid.append('  %s["%s"]' % (node_id, safe_label))
    for relation in relations:
        left = str(relation.get("left_table") or "")
        right = str(relation.get("right_table") or "")
        if left not in node_ids or right not in node_ids:
            continue
        left_id, right_id = node_ids[left], node_ids[right]
        label = "%s %s %s" % (relation.get("left_field"), _REL_LABELS.get(
            relation.get("relationship"), relation.get("relationship")), relation.get("right_field"))
        mermaid.append('  %s -->|"%s"| %s' % (left_id, label, right_id))
        status = "通过" if relation.get("passed") else "断链"
        lines.append("[%s] %s.%s --%s--> %s.%s"
                     % (status, left, relation.get("left_field"),
                        _REL_LABELS.get(relation.get("relationship")), right,
                        relation.get("right_field")))
        if not relation.get("passed"):
            broken_nodes.update([left, right])
    if broken_nodes:
        ids = ",".join(node_ids[node] for node in sorted(broken_nodes))
        mermaid.append("  classDef broken fill:#ffe2e2,stroke:#c62828,color:#8b0000;")
        mermaid.append("  class %s broken;" % ids)
    text = "血缘链路（%d 条关联）:\n%s" % (len(relations), "\n".join(lines))
    if broken_nodes:
        text += "\n断链节点: " + "、".join(sorted(broken_nodes))
    return {"text": text, "mermaid": "\n".join(mermaid),
            "broken_nodes": sorted(broken_nodes), "relation_count": len(relations)}


def validate_lineage(tables: Dict[str, TableData],
                     rules: Dict[str, Any]) -> Dict[str, Any]:
    """执行所有血缘关联规则。

    Args:
        tables: 表名到全量 TableData 的映射。血缘必须使用全量数据，避免抽样
            造成被引用键缺失的假阳性。
        rules: load_lineage_rules 返回的规则对象。
    Returns:
        含 passed、relations、graph、samples 的统一结果字典。
    """
    relations = []
    config_errors = []
    for index, relation in enumerate(rules.get("relations", [])):
        if not isinstance(relation, dict):
            config_errors.append({"code": "rule_invalid", "message": "第 %d 条规则不是映射" % (index + 1)})
            continue
        name = str(relation.get("name") or "relation_%d" % (index + 1))
        try:
            relations.append(_check_relation(name, relation, tables))
        except LineageRuleError as exc:
            relations.append({
                "name": name, "passed": False, "errors": [
                    {"code": "rule_invalid", "message": str(exc)}],
                "samples": [], "orphan_count": 0, "missing_reference_count": 0,
                "cardinality_errors": 0, "left_rows": 0, "right_rows": 0,
                "left_table": "", "right_table": "",
            })
    graph = _build_graph(relations)
    samples: List[Dict[str, Any]] = []
    for relation in relations:
        samples.extend(relation.get("samples", []))
    failed = [item for item in relations if not item.get("passed")]
    passed = not failed and not config_errors
    return {
        "key": "lineage", "name": "跨表血缘一致性校验", "passed": passed,
        "relations": relations, "graph": graph, "samples": samples[:20],
        "errors": config_errors + [{"code": "relation_failed", "message": item["name"]}
                                   for item in failed],
        "orphan_count": sum(item.get("orphan_count", 0) for item in relations),
        "missing_reference_count": sum(item.get("missing_reference_count", 0)
                                       for item in relations),
        "cardinality_errors": sum(item.get("cardinality_errors", 0) for item in relations),
        "summary": ("%d 条血缘关联全部通过" % len(relations) if passed
                    else "发现 %d 条断链关联" % len(failed)),
    }
