"""跨批次质量趋势对比。

把每次任务的表级行数、列级空值率、重复率与异常抽检命中率，按稳定指标键
（契约指纹+表+列+规则）持久化到 SQLite；新任务完成校验后，取同一契约指纹下
最近若干次成功任务作为基线做偏差检测。趋势对比只警示、不阻断准入结论：
结果字典的 ``passed`` 恒为 True。

契约内容一旦变化，契约指纹随之改变，新旧契约的指标自然断代，不做跨指纹对齐。
"""

from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from ..config import AppConfig
from ..parser.table_reader import TableData

# 指标规则标识：row_count 为表级指标，其余为列级比率指标。
RULE_ROW_COUNT = "row_count"
RULE_NULL_RATE = "null_rate"
RULE_DUPLICATE_RATE = "duplicate_rate"
RULE_ANOMALY_RATE = "anomaly_rate"
_RATE_RULES = (RULE_NULL_RATE, RULE_DUPLICATE_RATE, RULE_ANOMALY_RATE)
RULE_LABELS = {
    RULE_ROW_COUNT: "表行数",
    RULE_NULL_RATE: "空值率",
    RULE_DUPLICATE_RATE: "重复率",
    RULE_ANOMALY_RATE: "异常抽检命中率",
}


def contract_fingerprint(contract: Dict[str, Any]) -> str:
    """按契约内容计算稳定指纹；内容相同则指纹相同，内容变化即断代。"""
    raw = yaml.safe_dump(contract, sort_keys=True, allow_unicode=True)
    return sha256(raw.encode("utf-8")).hexdigest()[:16]


def contract_fingerprint_from_file(path: Path) -> str:
    """从契约文件计算指纹；解析失败时退化为原始字节哈希，保证可用。"""
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return contract_fingerprint(data)
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        pass
    try:
        return sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return sha256(str(path).encode("utf-8")).hexdigest()[:16]


def metric_key(fingerprint: str, table: str, column: str, rule: str) -> str:
    """拼接稳定指标键：契约指纹+表+列+规则。"""
    return "%s:%s:%s:%s" % (fingerprint, table, column, rule)


def _metric(fingerprint: str, table: str, column: str, rule: str,
            value: float) -> Dict[str, Any]:
    """构造一条待持久化的指标记录。"""
    return {
        "contract_fingerprint": fingerprint,
        "metric_key": metric_key(fingerprint, table, column, rule),
        "table_name": table,
        "column_name": column,
        "rule": rule,
        "metric_value": float(value),
    }


def extract_metrics(fingerprint: str, tables: Dict[str, TableData],
                    anomaly_result: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """从全量表与异常抽检结果中提取本次任务的质量指标。

    Args:
        fingerprint: 契约指纹。
        tables: 全量读取的表映射（提供精确行数）。
        anomaly_result: 异常抽检统一结果（提供列级比率指标）。
    Returns:
        指标记录列表；任一来源缺失时仅返回可得部分。
    """
    metrics: List[Dict[str, Any]] = []
    for table_name in sorted(tables or {}):
        table_data = tables[table_name]
        metrics.append(_metric(fingerprint, str(table_name), "",
                               RULE_ROW_COUNT, float(table_data.total_rows)))
    for field in (anomaly_result or {}).get("fields", []):
        table = str(field.get("table", ""))
        column = str(field.get("field", ""))
        if not table or not column:
            continue
        for rule in _RATE_RULES:
            value = field.get(rule)
            if value is None:
                continue
            metrics.append(_metric(fingerprint, table, column, rule, float(value)))
    return metrics


def _format_value(rule: str, value: float) -> str:
    """按指标类型格式化数值，行数取整、比率转百分比。"""
    if rule == RULE_ROW_COUNT:
        return str(int(round(value)))
    return "%.2f%%" % (value * 100)


def _format_change(rule: str, change: Optional[float]) -> str:
    """格式化变化量：行数为相对波动，比率为百分点增量。"""
    if change is None:
        return "-"
    if rule == RULE_ROW_COUNT:
        return "%+.1f%%" % (change * 100)
    return "%+.2fpp" % (change * 100)


def _threshold_text(rule: str, row_change_ratio: float, rate_increase: float) -> str:
    """生成人类可读的阈值说明。"""
    if rule == RULE_ROW_COUNT:
        return "±%.0f%%" % (row_change_ratio * 100)
    return "+%.2fpp" % (rate_increase * 100)


def _deviation_message(metric: Dict[str, Any], baseline_text: str, current_text: str,
                       change_text: str, threshold_text: str) -> str:
    """生成突变指标的中文说明。"""
    rule = metric["rule"]
    label = RULE_LABELS.get(rule, rule)
    if rule == RULE_ROW_COUNT:
        return ("%s 表行数由基线 %s 变为 %s（%s），超出 %s 波动阈值"
                % (metric["table_name"], baseline_text, current_text,
                   change_text, threshold_text))
    return ("%s.%s %s由基线 %s 升至 %s（%s），超出 %s 增量阈值"
            % (metric["table_name"], metric["column_name"], label,
               baseline_text, current_text, change_text, threshold_text))


def detect_deviations(current_metrics: List[Dict[str, Any]],
                      baseline_rows: List[Dict[str, Any]],
                      row_change_ratio: float,
                      rate_increase: float) -> List[Dict[str, Any]]:
    """把本次指标与基线均值对比，返回超限的突变指标列表。

    行数按相对波动比例双向判定；空值率、重复率、异常命中率按百分点增量
    单向（仅上升）判定。基线中不存在的指标键直接跳过，不做新旧契约对齐。
    """
    grouped: Dict[Tuple[str, str, str], List[float]] = {}
    for row in baseline_rows:
        key = (str(row["table_name"]), str(row["column_name"]), str(row["rule"]))
        grouped.setdefault(key, []).append(float(row["metric_value"]))
    deviations: List[Dict[str, Any]] = []
    for metric in current_metrics:
        key = (metric["table_name"], metric["column_name"], metric["rule"])
        values = grouped.get(key)
        if not values:
            continue
        baseline = sum(values) / len(values)
        current = float(metric["metric_value"])
        rule = metric["rule"]
        if rule == RULE_ROW_COUNT:
            if baseline == 0:
                change = None
                deviated = current > 0
            else:
                change = (current - baseline) / baseline
                deviated = abs(change) > row_change_ratio
        else:
            change = current - baseline
            deviated = change > rate_increase
        if not deviated:
            continue
        baseline_text = _format_value(rule, baseline)
        current_text = _format_value(rule, current)
        change_text = _format_change(rule, change)
        threshold_text = _threshold_text(rule, row_change_ratio, rate_increase)
        deviations.append({
            "metric_key": metric["metric_key"],
            "table": metric["table_name"],
            "column": metric["column_name"],
            "rule": rule,
            "rule_label": RULE_LABELS.get(rule, rule),
            "baseline": round(baseline, 6),
            "current": round(current, 6),
            "change": round(change, 6) if change is not None else None,
            "baseline_text": baseline_text,
            "current_text": current_text,
            "change_text": change_text,
            "threshold_text": threshold_text,
            "baseline_tasks": len(values),
            "message": _deviation_message(metric, baseline_text, current_text,
                                          change_text, threshold_text),
        })
    deviations.sort(key=lambda item: item["metric_key"])
    return deviations


def _build_result(fingerprint: str, metrics: List[Dict[str, Any]],
                  baseline_rows: List[Dict[str, Any]],
                  config: AppConfig) -> Dict[str, Any]:
    """组装趋势对比统一结果；``passed`` 恒为 True，只警示不阻断。"""
    baseline_task_ids = list(dict.fromkeys(row["task_id"] for row in baseline_rows))
    result: Dict[str, Any] = {
        "key": "trend", "name": "跨批次质量趋势对比", "passed": True,
        "contract_fingerprint": fingerprint,
        "metrics_count": len(metrics),
        "row_change_ratio": float(config.trend_row_change_ratio),
        "rate_increase": float(config.trend_rate_increase),
        "errors": [], "samples": [],
    }
    if not baseline_rows:
        result.update({
            "status": "no_baseline", "baseline_tasks": 0, "baseline_task_ids": [],
            "deviations": [],
            "summary": "同契约指纹下暂无历史成功任务作为基线，本次仅记录质量指标，"
                       "趋势对比已降级跳过",
        })
        return result
    deviations = detect_deviations(
        metrics, baseline_rows,
        float(config.trend_row_change_ratio), float(config.trend_rate_increase))
    if deviations:
        summary = "对比最近 %d 次成功任务，发现 %d 项指标突变（仅警示，不影响准入）" % (
            len(baseline_task_ids), len(deviations))
    else:
        summary = "对比最近 %d 次成功任务，未发现跨批次质量突变" % len(baseline_task_ids)
    result.update({
        "status": "ok", "baseline_tasks": len(baseline_task_ids),
        "baseline_task_ids": baseline_task_ids[:8],
        "deviations": deviations, "summary": summary,
    })
    return result


def run_trend_stage(config: AppConfig, store: Any, contract_path: Path,
                    task_id: str, tables: Dict[str, TableData],
                    anomaly_result: Optional[Dict[str, Any]]) -> Tuple:
    """执行趋势对比阶段，返回 ``(结果字典, 待持久化指标)``。

    趋势功能关闭时返回 ``(None, None)``；阶段内部任何异常都降级为提示性
    结果并放弃本次指标写入，避免半截指标污染后续基线。
    """
    if not getattr(config, "trend_enabled", True):
        return None, None
    try:
        fingerprint = contract_fingerprint_from_file(contract_path)
        metrics = extract_metrics(fingerprint, tables, anomaly_result)
        baseline_rows = store.baseline_metrics(
            fingerprint, exclude_task_id=task_id,
            max_tasks=int(config.trend_baseline_tasks))
        result = _build_result(fingerprint, metrics, baseline_rows, config)
        return result, metrics
    except Exception as exc:  # 趋势阶段不得影响主流程与准入结论。
        return {
            "key": "trend", "name": "跨批次质量趋势对比", "passed": True,
            "status": "degraded", "error": str(exc),
            "summary": "趋势对比执行异常，已跳过: %s" % exc,
            "deviations": [], "errors": [], "samples": [],
        }, None
