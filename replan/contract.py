"""契约与血缘规则的规范化解析。

输入兼容 gateway 风格 YAML/JSON 契约与血缘文件，输出稳定、可散列的内部
模型。本模块不执行任何数据校验，只做结构解析与引用预检查；引用无法在
当前契约/数据包中解析时抛出 :class:`ReferenceUnresolved`，由规划器保守
降级为整包全量重检。
"""

import copy
import hashlib
import json
import os

from .errors import FallbackError
from .textio import load_structured_file

_TYPE_ORDER = {
    "boolean": 1,
    "integer": 2,
    "number": 3,
    "string": 4,
    "date": 4,
    "datetime": 4,
}
_NUMERIC = {"integer", "number"}
_TEXTUAL = {"string", "date", "datetime"}


class ReferenceUnresolved(FallbackError):
    """契约/血缘中的表或列在当前模型里无法解析。"""


def _canonical(obj):
    """稳定序列化：键排序、默认分隔符，保证同结构同指纹。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def fingerprint_of(obj):
    """对任意 JSON 兼容结构计算稳定 SHA256 指纹。"""
    return hashlib.sha256(_canonical(obj)).hexdigest()


def load_contract(path):
    """加载并规范化数据契约。"""
    if not os.path.isfile(str(path)):
        from .errors import PlannerError
        raise PlannerError("契约文件不存在: %s" % path, "contract_not_found")
    try:
        data = load_structured_file(path)
    except (ValueError, OSError, UnicodeError) as exc:
        raise FallbackError("当前契约无法可靠解析，保守执行整包全量重检: %s"
                            % exc, "contract_unparseable")
    if not isinstance(data, dict) or not isinstance(data.get("tables"), dict):
        raise FallbackError("契约缺少 tables 映射，保守执行整包全量重检",
                            "contract_unparseable")
    tables = {}
    for table_name in sorted(data["tables"].keys()):
        spec = data["tables"][table_name]
        if not isinstance(spec, dict) or not isinstance(spec.get("fields"), dict):
            raise FallbackError("契约表 %s 缺少 fields 定义" % table_name,
                                "contract_unparseable")
        fields = {}
        for field_name in sorted(spec["fields"].keys()):
            field_spec = spec["fields"][field_name]
            if not isinstance(field_spec, dict):
                raise FallbackError("契约字段 %s.%s 定义非法"
                                    % (table_name, field_name),
                                    "contract_unparseable")
            fields[str(field_name)] = {
                "type": str(field_spec.get("type", "string")).lower(),
                "required": bool(field_spec.get("required", False)),
                "nullable": bool(field_spec.get("nullable", True)),
                "constraints": {
                    key: value for key, value in field_spec.items()
                    if key not in ("type", "required", "nullable")
                },
            }
        aliases = spec.get("aliases") or {}
        normalized_aliases = {}
        if isinstance(aliases, dict):
            for canonical, alias_list in aliases.items():
                if isinstance(alias_list, str):
                    alias_list = [alias_list]
                normalized_aliases[str(canonical)] = sorted(
                    str(alias) for alias in (alias_list or []))
        tables[str(table_name)] = {
            "file": spec.get("file"),
            "sqlite_table": spec.get("sqlite_table") or spec.get("table"),
            "fields": fields,
            "aliases": normalized_aliases,
            "allow_extra_fields": bool(spec.get("allow_extra_fields",
                                                data.get("allow_extra_fields", False))),
        }
    rules = _extract_rules(data.get("anomaly_rules") or {}, tables)
    renames = _extract_renames(data.get("column_renames") or {}, tables)
    return {
        "name": str(data.get("name", os.path.basename(str(path)))),
        "version": str(data.get("version", "")),
        "tables": tables,
        "rules": rules,
        "renames": renames,
        "raw": data,
        "fingerprint": fingerprint_of({
            "tables": {
                name: {
                    "fields": {
                        field: {
                            "type": spec["type"],
                            "required": spec["required"],
                            "nullable": spec["nullable"],
                            "constraints": spec["constraints"],
                        }
                        for field, spec in table["fields"].items()
                    },
                }
                for name, table in tables.items()
            },
            "rules": [
                {key: rule[key] for key in ("id", "table", "column", "kind", "params")}
                for rule in rules
            ],
        }),
    }


def _extract_rules(anomaly_rules, tables):
    """把 anomaly_rules 展开为带稳定 ID 的规则列表。"""
    rules = []
    for table_name in sorted(anomaly_rules.keys()):
        field_map = anomaly_rules[table_name]
        if not isinstance(field_map, dict):
            continue
        for field_name in sorted(field_map.keys()):
            rule_list = field_map[field_name]
            if isinstance(rule_list, dict):
                rule_list = [rule_list]
            if not isinstance(rule_list, list):
                continue
            for index, rule_spec in enumerate(rule_list):
                if not isinstance(rule_spec, dict) or "rule" not in rule_spec:
                    continue
                kind = str(rule_spec["rule"])
                params = {
                    key: value for key, value in sorted(rule_spec.items())
                    if key != "rule"
                }
                rule_id = "%s.%s.%s.%d" % (table_name, field_name, kind, index)
                rules.append({
                    "id": rule_id,
                    "table": str(table_name),
                    "column": str(field_name),
                    "kind": kind,
                    "params": params,
                    "fingerprint": fingerprint_of(
                        {"kind": kind, "params": params}),
                })
    rules.sort(key=lambda item: item["id"])
    return rules


def _extract_renames(column_renames, tables):
    """解析显式改名映射 ``column_renames: {table: [{from, to}, ...]}``。"""
    renames = {}
    if not isinstance(column_renames, dict):
        return renames
    for table_name, mappings in column_renames.items():
        if not isinstance(mappings, list):
            continue
        pairs = []
        for mapping in mappings:
            if isinstance(mapping, dict) and mapping.get("from") and mapping.get("to"):
                pairs.append((str(mapping["from"]), str(mapping["to"])))
        if pairs:
            renames[str(table_name)] = sorted(pairs)
    return renames


def is_narrowing(old_type, new_type):
    """判断类型变化是否为收窄（值域/约束语义变严）。

    规则：

    * 同族内按精度序：``number -> integer``、``integer -> boolean`` 收窄，
      反向（``integer -> number``）放宽；
    * 数值族 -> 文本族（``integer/number -> string``）视为收窄：数值专用
      约束（minimum/maximum、数值 range 规则）在自由文本上不再可强制，
      旧数据校验前提失效，必须重检；
    * 文本族 -> 数值族同样视为收窄：新类型接受的值域显著变小，存量文本
      可能无法通过；
    * 文本族内部（string/date/datetime）互转按收窄处理（格式约束增强）；
    * 未知类型且发生变化，保守按收窄处理。
    """
    if old_type == new_type:
        return False
    old_rank = _TYPE_ORDER.get(old_type)
    new_rank = _TYPE_ORDER.get(new_type)
    if old_rank is None or new_rank is None:
        return True
    if old_type in _NUMERIC and new_type in _NUMERIC:
        return new_rank < old_rank
    if old_type in _TEXTUAL and new_type in _TEXTUAL:
        # 同族文本类型互转：date/datetime 的格式约束强于自由 string。
        return old_type != new_type
    # 跨族（数值 <-> 文本）一律按收窄处理，保守要求重检。
    return True


def load_lineage(path, contract):
    """加载血缘规则并在当前契约范围内解析全部引用。"""
    if not os.path.isfile(str(path)):
        from .errors import PlannerError
        raise PlannerError("血缘规则文件不存在: %s" % path, "lineage_not_found")
    try:
        data = load_structured_file(path)
    except (ValueError, OSError, UnicodeError) as exc:
        raise FallbackError("血缘规则无法可靠解析，保守执行整包全量重检: %s"
                            % exc, "lineage_unparseable")
    if not isinstance(data, dict) or not isinstance(data.get("relations"), list):
        raise FallbackError("血缘规则缺少 relations 列表，保守执行整包全量重检",
                            "lineage_unparseable")
    edges = []
    node_set = set()
    for index, relation in enumerate(data["relations"]):
        if not isinstance(relation, dict):
            raise FallbackError("血缘第 %d 条关系结构非法" % (index + 1),
                                "rule_reference_unresolved")
        left = _endpoint(relation, "left")
        right = _endpoint(relation, "right")
        for side, (table, field) in (("left", left), ("right", right)):
            if table not in contract["tables"]:
                raise ReferenceUnresolved(
                    "血缘关系 %s 的 %s 端引用了契约中不存在的表 %s.%s，"
                    "规则引用无法可靠解析"
                    % (relation.get("name", "?"), side, table, field),
                    "rule_reference_unresolved")
            if field not in contract["tables"][table]["fields"]:
                raise ReferenceUnresolved(
                    "血缘关系 %s 的 %s 端引用了契约中不存在的列 %s.%s，"
                    "规则引用无法可靠解析"
                    % (relation.get("name", "?"), side, table, field),
                    "rule_reference_unresolved")
            node_set.add((table, field))
        name = str(relation.get("name") or "relation_%d" % index)
        edge = {
            "name": name,
            "left_table": left[0],
            "left_column": left[1],
            "right_table": right[0],
            "right_column": right[1],
            "relationship": str(relation.get("relationship", "many_to_one")),
            "require_reference": bool(relation.get("require_reference", True)),
            "allow_null": bool(relation.get("allow_null", False)),
        }
        edge["fingerprint"] = fingerprint_of(
            {key: edge[key] for key in sorted(edge)})
        edges.append(edge)
    edges.sort(key=lambda item: item["name"])
    # 邻接表：键/值均为 (table, column)，沿引用双向传播。
    adjacency = {}
    for edge in edges:
        left = (edge["left_table"], edge["left_column"])
        right = (edge["right_table"], edge["right_column"])
        adjacency.setdefault(left, []).append((right, edge["name"]))
        adjacency.setdefault(right, []).append((left, edge["name"]))
    return {
        "name": str(data.get("name", os.path.basename(str(path)))),
        "edges": edges,
        "adjacency": adjacency,
        "nodes": sorted(node_set),
        "fingerprint": fingerprint_of(
            [edge["fingerprint"] for edge in edges]),
    }


def _endpoint(relation, side):
    nested = relation.get(side)
    if isinstance(nested, dict):
        table, field = nested.get("table"), nested.get("field")
    else:
        table = relation.get(side + "_table")
        field = relation.get(side + "_field")
    if not table or not field:
        raise ReferenceUnresolved(
            "血缘关系 %s 的 %s 端点缺少 table/field"
            % (relation.get("name", "?"), side),
            "rule_reference_unresolved")
    return str(table), str(field)


def build_alias_index(contract):
    """构建 表 -> {别名列名: 规范列名} 索引，用于改名列识别兜底。"""
    index = {}
    for table_name, table in contract["tables"].items():
        mapping = {}
        for canonical, aliases in table["aliases"].items():
            for alias in aliases:
                mapping[alias] = canonical
        index[table_name] = mapping
    return index


def clone_contract_model(contract):
    """深拷贝契约模型，规划过程中需要记录旧版字段视图。"""
    return copy.deepcopy(contract)
