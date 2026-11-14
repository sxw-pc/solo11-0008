"""字段级异常值抽检规则引擎。

内置规则包括数值范围、正则匹配、日期格式、空值率阈值、重复值率阈值。
规则作用于已抽样数据；任何单值规则默认发现一条异常即判定不通过，可通过
``max_rate`` 放宽。自定义函数从受控白名单加载，禁止任意上传代码执行。
"""

from datetime import date, datetime
import re
from typing import Any, Dict, List, Optional

import pandas as pd

from ..parser.table_reader import TableData
from .custom_rules import get_custom_rule

_BUILTIN_RULES = {"range", "regex", "date", "null_rate", "duplicate_rate", "custom"}


def _null_mask(series: pd.Series) -> pd.Series:
    """返回与 series 同索引的空值布尔掩码。

    空值口径与 Schema 校验及契约手册一致：None/NaN 以及仅含空白的字符串
    都计为空，保证字段级统计与 null_rate 规则使用同一套口径、结果可复现。
    """
    return series.map(_is_null).fillna(True).astype(bool)


def _resolve_field(columns: List[str], field: str,
                   aliases: Dict[str, Any]) -> Optional[str]:
    """把契约规范字段名解析为表中实际存在的列名。

    优先使用同名列；否则按 ``aliases`` 中“规范字段 -> 上游候选列名”的映射
    解析唯一命中的别名。未配置别名或无候选命中时返回 None，由调用方按
    ``field_missing`` 处理。与 Schema 校验共用同一份别名语义，避免只含别名
    列的合法表在异常抽检阶段被误判为字段缺失。
    """
    if field in columns:
        return field
    candidates = aliases.get(field)
    if candidates is None:
        return None
    candidate_list = [candidates] if isinstance(candidates, str) else list(candidates)
    matches = [str(item) for item in candidate_list if str(item) in columns]
    if len(matches) == 1:
        return matches[0]
    return None


def _is_null(value: Any) -> bool:
    """判断标量是否为空，字符串空白按空值处理。"""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    try:
        result = pd.isna(value)
        return bool(result) if isinstance(result, bool) else False
    except (TypeError, ValueError):
        return False


def _safe_value(value: Any) -> Any:
    """转换为可 JSON 序列化的短值。"""
    if _is_null(value):
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if hasattr(value, "item"):
        try:
            value = value.item()
        except (ValueError, AttributeError):
            pass
    if isinstance(value, str) and len(value) > 60:
        return value[:60] + "..."
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _row_number(index: Any, offset: int) -> Optional[int]:
    """把 DataFrame 索引转换为对用户友好的原始行号。"""
    try:
        return int(index) + int(offset)
    except (TypeError, ValueError):
        return None


def _add_sample(samples: List[Dict[str, Any]], table: str, field: str,
                rule_type: str, index: Any, value: Any, offset: int,
                message: str) -> None:
    """向全局异常样例中加入一条，最多保留 20 条。"""
    if len(samples) >= 20:
        return
    samples.append({
        "table": table, "field": field, "rule": rule_type,
        "row": _row_number(index, offset), "value": _safe_value(value),
        "message": message,
    })


def _matches_any(series: pd.Series, rule: Dict[str, Any]) -> tuple:
    """执行 range/regex/date 单值规则，返回异常索引与原因列表。"""
    rule_type = rule["rule"]
    indices = []
    reasons: Dict[Any, str] = {}
    if rule_type == "range":
        lower = rule.get("min")
        upper = rule.get("max")
        if lower is None and upper is None:
            raise ValueError("range 规则至少需要 min 或 max")
        for index, value in series.items():
            if _is_null(value):
                continue
            try:
                number = float(value)
                if (lower is not None and number < float(lower)) or (
                        upper is not None and number > float(upper)):
                    indices.append(index)
                    reasons[index] = "数值超出范围 [%s, %s]" % (lower, upper)
            except (TypeError, ValueError):
                indices.append(index)
                reasons[index] = "非数值，无法执行范围校验"
    elif rule_type == "regex":
        pattern = rule.get("pattern")
        if not pattern:
            raise ValueError("regex 规则缺少 pattern")
        compiled = re.compile(str(pattern))
        full_match = bool(rule.get("full_match", False))
        for index, value in series.items():
            if _is_null(value):
                continue
            text = value if isinstance(value, str) else str(value)
            matched = compiled.fullmatch(text) if full_match else compiled.search(text)
            if not matched:
                indices.append(index)
                reasons[index] = "不匹配正则表达式"
    elif rule_type == "date":
        formats = rule.get("formats") or [rule.get("format", "%Y-%m-%d")]
        if isinstance(formats, str):
            formats = [formats]
        parsed_formats = [str(item) for item in formats]
        for index, value in series.items():
            if _is_null(value):
                continue
            parsed = False
            if isinstance(value, (datetime, date)):
                parsed = True
            else:
                for fmt in parsed_formats:
                    try:
                        datetime.strptime(str(value), fmt)
                        parsed = True
                        break
                    except ValueError:
                        continue
            if not parsed:
                indices.append(index)
                reasons[index] = "日期格式不符合 %s" % "、".join(parsed_formats)
    return indices, reasons


def _run_rule(series: pd.Series, rule: Dict[str, Any], table: str, field: str,
              offset: int, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """执行单条规则并返回规则级统计。"""
    if not isinstance(rule, dict) or "rule" not in rule:
        return {"rule": "unknown", "passed": False, "error": "规则必须包含 rule 字段",
                "violations": 0}
    rule_type = str(rule["rule"])
    if rule_type not in _BUILTIN_RULES:
        return {"rule": rule_type, "passed": False, "error": "未知规则类型", "violations": 0}
    total = len(series)
    nulls = _null_mask(series)
    non_null_count = int((~nulls).sum())
    violations = 0
    try:
        if rule_type == "range" or rule_type == "regex" or rule_type == "date":
            indices, reasons = _matches_any(series, rule)
            violations = len(indices)
            for index in indices:
                _add_sample(samples, table, field, rule_type, index,
                            series.loc[index], offset, reasons[index])
            checked = non_null_count
            rate = violations / checked if checked else 0.0
            max_rate = float(rule.get("max_rate", 0.0))
            passed = rate <= max_rate
            return {"rule": rule_type, "passed": passed, "violations": violations,
                    "checked": checked, "rate": round(rate, 4),
                    "threshold": max_rate, "max_rate": max_rate}
        if rule_type == "null_rate":
            threshold = float(rule.get("max", rule.get("max_rate", 0.0)))
            null_count = int(nulls.sum())
            rate = null_count / total if total else 0.0
            if rate > threshold:
                for index in nulls[nulls].index:
                    _add_sample(samples, table, field, rule_type, index,
                                series.loc[index], offset,
                                "空值率 %.2f%% 超过阈值 %.2f%%"
                                % (rate * 100, threshold * 100))
                    if len(samples) >= 20:
                        break
            return {"rule": rule_type, "passed": rate <= threshold,
                    "violations": null_count, "checked": total,
                    "rate": round(rate, 4), "threshold": threshold}
        if rule_type == "duplicate_rate":
            threshold = float(rule.get("max", rule.get("max_rate", 0.0)))
            valid = series[~nulls].astype(str).str.strip()
            valid = valid[valid != ""]
            counts = valid.value_counts()
            duplicate_mask = valid.isin(counts[counts > 1].index)
            duplicate_count = int(duplicate_mask.sum())
            rate = duplicate_count / len(valid) if len(valid) else 0.0
            if rate > threshold:
                for index in valid[duplicate_mask].index[:20]:
                    _add_sample(samples, table, field, rule_type, index,
                                series.loc[index], offset, "检测到重复值")
            return {"rule": rule_type, "passed": rate <= threshold,
                    "violations": duplicate_count, "checked": len(valid),
                    "rate": round(rate, 4), "threshold": threshold}
        function = get_custom_rule(str(rule.get("function", "")))
        if not callable(function):
            raise ValueError("自定义规则函数不存在")
        mask = function(series)
        mask = pd.Series(mask, index=series.index).fillna(False).astype(bool)
        violations = int(mask.sum())
        threshold = float(rule.get("max_rate", 0.0))
        rate = violations / non_null_count if non_null_count else 0.0
        for index in mask[mask].index:
            _add_sample(samples, table, field, rule_type, index, series.loc[index],
                        offset, "自定义规则判定异常")
        return {"rule": rule_type, "passed": rate <= threshold,
                "violations": violations, "checked": non_null_count,
                "rate": round(rate, 4), "threshold": threshold,
                "function": rule.get("function")}
    except (ValueError, TypeError, KeyError, re.error) as exc:
        return {"rule": rule_type, "passed": False, "violations": 0,
                "error": "规则执行失败: %s" % exc}


def _check_field(table: str, field: str, series: pd.Series, rules: List[Any],
                 offset: int, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """执行单个字段的全部规则并汇总异常率、空值率与重复值率。"""
    rule_results = []
    for rule in rules:
        result = _run_rule(series, rule, table, field, offset, samples)
        rule_results.append(result)
    total = len(series)
    nulls = _null_mask(series)
    null_count = int(nulls.sum())
    valid = series[~nulls].astype(str).str.strip()
    valid = valid[valid != ""]
    # 与 duplicate_rate 规则及契约手册保持同一口径：重复出现的行数 / 非空行数。
    if len(valid):
        counts = valid.value_counts()
        duplicate_row_count = int(valid.isin(counts[counts > 1].index).sum())
        duplicate_rate = duplicate_row_count / len(valid)
    else:
        duplicate_rate = 0.0
    failed_rules = [item for item in rule_results if not item.get("passed")]
    anomaly_count = sum(item.get("violations", 0) for item in rule_results)
    return {
        "table": table, "field": field, "passed": not failed_rules,
        "rules": rule_results, "checked": total,
        "null_count": null_count, "null_rate": round(null_count / total, 4) if total else 0.0,
        "duplicate_rate": round(duplicate_rate, 4),
        "anomaly_count": anomaly_count,
        "anomaly_rate": round(min(1.0, anomaly_count / total), 4) if total else 0.0,
        "failed_rules": len(failed_rules),
    }


def validate_anomalies(tables: Dict[str, TableData],
                       config: Dict[str, Any]) -> Dict[str, Any]:
    """执行契约中的 anomaly_rules 字段规则。

    Args:
        tables: 表名到抽样后 TableData 的映射。
        config: 包含 ``anomaly_rules`` 的配置字典。
    Returns:
        含 passed、fields、samples 的统一结果字典。
    """
    rule_config = config.get("anomaly_rules", config.get("checks", {}))
    if not isinstance(rule_config, dict):
        rule_config = {}
    contract_tables = config.get("tables", {}) if isinstance(config, dict) else {}
    fields = []
    samples: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for table_name, table_rules in rule_config.items():
        table_data = tables.get(str(table_name))
        if table_data is None:
            errors.append({"code": "table_missing", "message": "异常规则表不存在: %s" % table_name})
            continue
        if not isinstance(table_rules, dict):
            errors.append({"code": "rule_invalid", "message": "表 %s 规则必须为映射" % table_name})
            continue
        table_rule = contract_tables.get(str(table_name), {})
        aliases = table_rule.get("aliases") if isinstance(table_rule, dict) else {}
        if not isinstance(aliases, dict):
            aliases = {}
        columns = [str(column) for column in table_data.frame.columns]
        for field, rules in table_rules.items():
            actual_field = _resolve_field(columns, str(field), aliases)
            if actual_field is None:
                errors.append({"code": "field_missing", "message": "异常规则字段不存在: %s.%s"
                               % (table_name, field)})
                continue
            if not isinstance(rules, list):
                rules = [rules]
            fields.append(_check_field(str(table_name), str(field),
                                       table_data.frame[actual_field], rules,
                                       table_data.row_offset, samples))
    failed_fields = [item for item in fields if not item["passed"]]
    passed = not failed_fields and not errors
    return {
        "key": "anomaly", "name": "异常值抽检规则校验", "passed": passed,
        "fields": fields, "samples": samples[:20], "errors": errors,
        "total_rules": sum(len(item["rules"]) for item in fields),
        "failed_rules": sum(item["failed_rules"] for item in fields),
        "summary": ("%d 个字段、%d 条规则全部通过"
                    % (len(fields), sum(len(item["rules"]) for item in fields))
                    if passed else ("发现 %d 个字段异常、%d 项规则配置错误"
                                    % (len(failed_fields), len(errors))
                                    if errors else "发现 %d 个字段异常" % len(failed_fields))),
    }
