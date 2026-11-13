"""基于 JSON Schema 的数据契约校验。

覆盖字段名匹配、数据类型、非空约束、枚举范围与字符串长度等规则，并将
错误定位到具体表、字段与原始行号。支持字段别名映射，兼容上游字段改名。
"""

from datetime import date, datetime
from numbers import Integral
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jsonschema
import pandas as pd
import yaml

from ..parser.table_reader import TableData

_TYPE_MAP = {
    "string": "string", "integer": "integer", "int": "integer",
    "number": "number", "float": "number", "boolean": "boolean",
    "bool": "boolean", "array": "array", "object": "object",
}
_MESSAGES = {
    "type": "数据类型不符合契约", "enum": "取值不在枚举范围",
    "maxLength": "字符串长度超过限制", "minLength": "字符串长度低于限制",
    "pattern": "取值不匹配正则表达式", "format": "格式不符合要求",
    "minimum": "数值低于下限", "maximum": "数值超过上限",
    "required": "必填字段缺失",
}
_FORMAT_CHECKER = jsonschema.FormatChecker()


class ContractError(Exception):
    """契约文件格式错误。"""


def load_contract(path: Path) -> Dict[str, Any]:
    """加载并校验 YAML 契约基础结构。

    Raises:
        ContractError: 文件缺失、YAML 损坏或 tables 结构非法。
    """
    path = Path(path)
    if not path.is_file():
        raise ContractError("契约文件不存在: %s" % path.name)
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ContractError("契约文件体积异常")
    try:
        contract = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise ContractError("契约 YAML 解析失败: %s" % exc) from exc
    if not isinstance(contract, dict) or not isinstance(contract.get("tables"), dict):
        raise ContractError("契约必须包含 tables 映射")
    for table_name, table in contract["tables"].items():
        if not isinstance(table, dict) or not isinstance(table.get("fields"), dict):
            raise ContractError("表 %s 必须定义 fields 映射" % table_name)
    return contract


def _is_null(value: Any) -> bool:
    """安全判断标量是否为空，兼容 pandas 缺失值与字符串空值。"""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    try:
        result = pd.isna(value)
        return bool(result) if isinstance(result, bool) else False
    except (TypeError, ValueError):
        return False


def _to_python(value: Any) -> Any:
    """将 numpy/pandas 标量转换为 jsonschema 可识别的 Python 值。"""
    if _is_null(value):
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if hasattr(value, "item"):
        try:
            return value.item()
        except (ValueError, AttributeError):
            pass
    if isinstance(value, (list, tuple)):
        return [_to_python(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _to_python(item) for key, item in value.items()}
    return value


def _field_schema(field: str, rule: Dict[str, Any]) -> Dict[str, Any]:
    """将契约字段规则转换为 JSON Schema 片段。"""
    if not isinstance(rule, dict):
        raise ContractError("字段 %s 的规则必须为映射" % field)
    schema: Dict[str, Any] = {}
    raw_type = rule.get("type")
    if raw_type:
        type_name = _TYPE_MAP.get(str(raw_type).lower())
        if type_name is None:
            raise ContractError("字段 %s 的 type 不受支持" % field)
        nullable = bool(rule.get("nullable", not rule.get("required", False)))
        schema["type"] = [type_name, "null"] if nullable else type_name
    elif bool(rule.get("nullable", True)):
        schema["type"] = ["string", "number", "integer", "boolean", "null"]
    for key in ("enum", "minimum", "maximum", "pattern", "minLength", "maxLength", "format"):
        if key in rule:
            schema[key] = rule[key]
    return schema


def _apply_aliases(frame: pd.DataFrame, table: Dict[str, Any],
                   table_name: str) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    """按 aliases 配置把上游字段名映射为契约标准字段名。

    标准写法是 ``标准字段: [上游候选列]``；同时兼容 ``上游列: 标准字段``
    的简写，避免自定义契约因方向写反而把合法别名列当成缺失/多余字段。

    Returns:
        ``(映射后的数据帧, 别名冲突错误列表)``；调用方应只使用映射后的
        列名参与 required、nullable、enum 与异常规则判断。
    """
    aliases = table.get("aliases") or {}
    if not isinstance(aliases, dict):
        raise ContractError("表 %s 的 aliases 必须为映射" % table_name)
    fields = table.get("fields") or {}
    renamed = frame.copy()
    errors: List[Dict[str, Any]] = []
    for canonical, candidates in aliases.items():
        if candidates is None:
            continue
        canonical_name = str(canonical)
        candidate_list = ([candidates] if isinstance(candidates, str)
                          else list(candidates))
        candidate_names = [str(item) for item in candidate_list
                           if str(item) in renamed.columns]
        # 反向简写：键是上游列名，值是契约标准字段名。
        if canonical_name not in fields:
            targets = [str(item) for item in candidate_list if str(item) in fields]
            if len(targets) == 1 and canonical_name in renamed.columns:
                target = targets[0]
                if target in renamed.columns:
                    errors.append({
                        "table": table_name, "field": target, "row": None,
                        "code": "alias_conflict",
                        "message": "标准字段与别名字段同时存在",
                    })
                else:
                    renamed = renamed.rename(columns={canonical_name: target})
                continue
        if canonical_name in renamed.columns:
            if candidate_names:
                errors.append({
                    "table": table_name, "field": canonical_name, "row": None,
                    "code": "alias_conflict",
                    "message": "标准字段与别名字段同时存在",
                })
            continue
        if len(candidate_names) > 1:
            errors.append({
                "table": table_name, "field": canonical_name, "row": None,
                "code": "alias_conflict", "message": "多个别名字段同时命中",
            })
        elif len(candidate_names) == 1:
            renamed = renamed.rename(columns={candidate_names[0]: canonical_name})
    return renamed, errors


def _check_table(table_name: str, table_data: TableData,
                 table_rule: Dict[str, Any], contract: Dict[str, Any]) -> Dict[str, Any]:
    """校验单张表并统计错误字段、错误行与 Top10 样例。"""
    fields = table_rule.get("fields", {})
    frame, alias_errors = _apply_aliases(table_data.frame, table_rule, table_name)
    table_errors: List[Dict[str, Any]] = list(alias_errors)
    error_rows = set()
    error_fields = set()
    expected = set(str(name) for name in fields)
    actual = set(str(name) for name in frame.columns)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    for missing_field in missing:
        rule = fields.get(missing_field) or {}
        if rule.get("required", False):
            table_errors.append({
                "table": table_name, "field": missing_field, "row": None,
                "code": "required", "message": "必填字段在表中缺失",
            })
            error_fields.add(missing_field)
            error_rows.add(1)
    allow_extra = bool(table_rule.get("allow_extra_fields",
                                      contract.get("allow_extra_fields", False)))
    if not allow_extra:
        for extra_field in extra:
            table_errors.append({
                "table": table_name, "field": extra_field, "row": 1,
                "code": "unexpected_field", "message": "表包含契约未声明字段",
            })
            error_fields.add(extra_field)
            error_rows.add(1)
    properties = {}
    for field, rule in fields.items():
        properties[str(field)] = _field_schema(str(field), rule)
    row_schema = {"type": "object", "properties": properties}
    validator = jsonschema.Draft7Validator(row_schema, format_checker=_FORMAT_CHECKER)
    samples: List[Dict[str, Any]] = []
    present_fields = [str(field) for field in fields if str(field) in frame.columns]
    required_fields = [str(field) for field, rule in fields.items()
                       if rule.get("required", False)]
    for index, row in frame.iterrows():
        instance = {field: _to_python(row[field]) for field in present_fields}
        row_number = int(index) + table_data.row_offset if isinstance(index, Integral) else index
        row_number_value = row_number if isinstance(row_number, Integral) else None
        # 缺失列已在表级检查中报告；此处处理必填但允许 nullable 的显式空值。
        for required_field in required_fields:
            if (required_field in instance and _is_null(instance[required_field])
                    and fields[required_field].get("nullable", False)):
                item = {
                    "table": table_name, "field": required_field,
                    "row": row_number_value, "code": "required",
                    "message": "必填字段值为空", "value": None,
                }
                error_rows.add(row_number_value if row_number_value is not None else 0)
                error_fields.add(required_field)
                if len(samples) < 10:
                    samples.append(item)
                if len(table_errors) < 50:
                    table_errors.append(item)
        for error in validator.iter_errors(instance):
            field = str(error.path[0]) if error.path else "unknown"
            readable = _MESSAGES.get(error.validator, "不符合契约约束")
            item = {
                "table": table_name, "field": field,
                "row": row_number_value, "code": error.validator,
                "message": "%s: %s" % (readable, error.message),
                "value": _truncate(instance.get(field, None)),
            }
            error_rows.add(row_number_value if row_number_value is not None else 0)
            error_fields.add(field)
            if len(samples) < 10:
                samples.append(item)
            if len(table_errors) < 50:
                table_errors.append(item)
    return {
        "table": table_name, "passed": not table_errors,
        "rows_checked": int(len(frame)), "sample_ratio": table_data.sample_ratio,
        "error_rows": len(error_rows), "error_fields": len(error_fields),
        "missing_fields": missing, "extra_fields": extra,
        "errors": table_errors[:50], "samples": samples[:10],
        "source_format": table_data.source_format,
    }


def _truncate(value: Any, limit: int = 80) -> Any:
    """缩短错误样例中的值，避免报告中输出超长业务数据。"""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "..."
    return value


def validate_schema(tables: Dict[str, TableData], contract: Dict[str, Any]) -> Dict[str, Any]:
    """对所有契约表执行 Schema 校验。

    Args:
        tables: 表名到 TableData 的映射。
        contract: load_contract 返回的契约对象。
    Returns:
        含 passed、tables、errors、samples 的统一结果字典。
    """
    table_results = []
    all_errors: List[Dict[str, Any]] = []
    all_samples: List[Dict[str, Any]] = []
    contract_tables = contract.get("tables", {})
    for table_name, table_rule in contract_tables.items():
        table_data = tables.get(table_name)
        if table_data is None:
            item = {
                "table": table_name, "field": None, "row": None,
                "code": "table_missing", "message": "契约表在数据包中不存在",
            }
            all_errors.append(item)
            table_results.append({
                "table": table_name, "passed": False, "rows_checked": 0,
                "error_rows": 1, "error_fields": 0, "missing_fields": [],
                "extra_fields": [], "errors": [item], "samples": [item],
                "source_format": None,
            })
            continue
        try:
            result = _check_table(table_name, table_data, table_rule, contract)
        except ContractError as exc:
            item = {
                "table": table_name, "field": None, "row": None,
                "code": "contract_error", "message": str(exc),
            }
            result = {
                "table": table_name, "passed": False, "rows_checked": 0,
                "error_rows": 1, "error_fields": 0, "missing_fields": [],
                "extra_fields": [], "errors": [item], "samples": [item],
                "source_format": table_data.source_format,
            }
        table_results.append(result)
        all_errors.extend(result["errors"])
        all_samples.extend(result["samples"])
    passed = not all_errors
    total_rows = sum(item["rows_checked"] for item in table_results)
    total_error_rows = sum(item["error_rows"] for item in table_results)
    return {
        "key": "schema", "name": "数据契约 Schema 校验", "passed": passed,
        "tables": table_results, "errors": all_errors[:100],
        "samples": all_samples[:10], "rows_checked": total_rows,
        "error_rows": total_error_rows,
        "summary": ("全部 %d 张契约表校验通过" % len(table_results) if passed
                    else "发现 %d 项 Schema 错误，涉及 %d 张表"
                         % (len(all_errors), sum(1 for item in table_results
                                                if not item["passed"]))),
    }
