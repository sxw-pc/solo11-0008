"""校验阶段与单条规则的阻断级别模型。

阻断级别决定某个校验阶段或某条规则命中后流水线是否继续：

- ``block``（阻断）：命中后立即终止后续阶段，未执行阶段生成跳过占位。
- ``degrade``（降级）：命中后记录失败结果并继续执行后续可运行阶段，
  一次任务即可收集多类问题；任务最终结论仍为不通过，降级不会放宽准入。

设计取舍：

- 安全类规则（路径穿越、压缩炸弹、高危可执行文件等）与基础设施异常
  （表读取失败、契约/血缘文件损坏、内部异常）钉死为阻断，不允许配置
  降级——继续执行要么不安全，要么结果不可信。
- 数据类规则（哈希不一致、字段类型不匹配、血缘断链、异常率超标等）
  默认降级，保持与历史版本完全一致的行为；可通过配置收紧为阻断。
- 压缩包安全阶段（archive）物理上不可降级：无法安全解压就没有后续
  阶段所需的输入。
"""

from typing import Any, Dict, List, Mapping, Optional, Set

BLOCK = "block"
DEGRADE = "degrade"

# 流水线阶段顺序（archive 之后按序执行）。
STAGE_SEQUENCE = ("archive", "hash", "table_read", "schema", "lineage", "anomaly")

STAGE_NAMES = {
    "archive": "压缩包安全与结构检查",
    "hash": "文件完整性与哈希校验",
    "table_read": "结构化表读取适配",
    "schema": "数据契约 Schema 校验",
    "lineage": "跨表血缘一致性校验",
    "anomaly": "异常值抽检规则校验",
}

# 默认阶段级别：与 1.0 行为完全一致——只有压缩包安全阶段阻断，
# 其余阶段失败后继续执行后续校验。
DEFAULT_STAGE_LEVELS = {
    "archive": BLOCK,
    "hash": DEGRADE,
    "table_read": DEGRADE,
    "schema": DEGRADE,
    "lineage": DEGRADE,
    "anomaly": DEGRADE,
}

# 钉死为阻断的阶段：压缩包无法安全解压时后续阶段没有可运行的输入。
PINNED_STAGE_LEVELS = {"archive": BLOCK}

# 钉死为阻断的规则错误码，分为两类：
# - 安全类：path_traversal、zip_bomb、dangerous_file、archive_error。
#   命中后必须立即终止，避免在不可信内容上继续执行。
# - 基础设施类：table_read_error、contract_error、lineage_rule_error、
#   internal。属于环境或工具异常（临时文件损坏、表读取失败、契约/血缘
#   文件损坏、未预期异常），继续降级执行的结果不可信，自动回退到终止逻辑。
PINNED_BLOCK_RULES = frozenset({
    "path_traversal", "zip_bomb", "dangerous_file", "archive_error",
    "table_read_error", "contract_error", "lineage_rule_error", "internal",
})

_LEVEL_ALIASES = {
    "block": BLOCK, "degrade": DEGRADE,
    "阻断": BLOCK, "降级": DEGRADE,
}


def _normalize_level(value: Any) -> str:
    """把配置值归一化为 block/degrade，非法值抛出 ValueError。"""
    text = str(value).strip().lower()
    if text in _LEVEL_ALIASES:
        return _LEVEL_ALIASES[text]
    raise ValueError("阻断级别只支持 block/degrade: %s" % value)


def normalize_stage_levels(overrides: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """合并用户阶段级别配置与默认值。

    Args:
        overrides: 用户配置的阶段到级别映射，None 或空表示全部默认。
    Returns:
        六个阶段的完整有效级别表。
    Raises:
        ValueError: 配置不是映射、阶段名未知、级别非法，或试图降级钉死阶段。
    """
    if overrides is None:
        overrides = {}
    if not isinstance(overrides, Mapping):
        raise ValueError("stage_levels 必须是阶段到级别的映射")
    levels = dict(DEFAULT_STAGE_LEVELS)
    for key, value in overrides.items():
        stage = str(key).strip()
        if stage not in DEFAULT_STAGE_LEVELS:
            raise ValueError("未知校验阶段: %s（可选: %s）"
                             % (stage, ", ".join(STAGE_SEQUENCE)))
        level = _normalize_level(value)
        pinned = PINNED_STAGE_LEVELS.get(stage)
        if pinned and level != pinned:
            raise ValueError("阶段 %s 属于安全阶段，不允许配置为降级" % stage)
        levels[stage] = level
    return levels


def normalize_rule_levels(overrides: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """校验并归一化单条规则的级别配置。

    Raises:
        ValueError: 配置不是映射、级别非法，或试图降级钉死的安全/基础设施规则。
    """
    if overrides is None:
        overrides = {}
    if not isinstance(overrides, Mapping):
        raise ValueError("rule_levels 必须是错误码到级别的映射")
    levels: Dict[str, str] = {}
    for code, value in overrides.items():
        name = str(code).strip()
        if not name:
            raise ValueError("rule_levels 包含空规则名")
        level = _normalize_level(value)
        if name in PINNED_BLOCK_RULES and level != BLOCK:
            raise ValueError("规则 %s 属于安全或基础设施规则，不允许配置为降级" % name)
        levels[name] = level
    return levels


def error_level(code: Any, rule_levels: Optional[Mapping[str, str]] = None,
                stage_level: str = DEGRADE) -> str:
    """解析单个错误码的有效阻断级别。

    优先级：钉死规则 > 用户规则级配置 > 所属阶段级别。
    """
    name = str(code or "")
    if name in PINNED_BLOCK_RULES:
        return BLOCK
    if rule_levels and name in rule_levels:
        return rule_levels[name]
    return stage_level


def annotate_errors(errors: Optional[List[Dict[str, Any]]],
                    rule_levels: Optional[Mapping[str, str]],
                    stage_level: str = DEGRADE) -> None:
    """就地给每条错误明细补充 ``level`` 阻断级别标记。"""
    if not errors:
        return
    for error in errors:
        if isinstance(error, dict):
            error["level"] = error_level(error.get("code"), rule_levels, stage_level)


def result_error_codes(result: Mapping[str, Any]) -> Set[str]:
    """提取校验结果中的全部错误码。

    血缘规则的明细错误码位于 relations 内层，异常抽检的失败规则以规则名
    作为可配置码（如 null_rate、range），均一并提取。
    """
    codes: Set[str] = set()
    for error in result.get("errors") or []:
        if isinstance(error, dict) and error.get("code"):
            codes.add(str(error["code"]))
    if result.get("key") == "lineage":
        for relation in result.get("relations") or []:
            for error in relation.get("errors") or []:
                if isinstance(error, dict) and error.get("code"):
                    codes.add(str(error["code"]))
    if result.get("key") == "anomaly":
        for field_result in result.get("fields") or []:
            for rule in field_result.get("rules") or []:
                if not rule.get("passed") and rule.get("rule"):
                    codes.add(str(rule["rule"]))
    return codes


def result_is_blocking(result: Mapping[str, Any],
                       stage_levels: Optional[Mapping[str, str]] = None,
                       rule_levels: Optional[Mapping[str, str]] = None) -> bool:
    """判断一个失败的校验结果是否应终止后续阶段。

    钉死阶段与任何命中钉死规则/阻断规则的结果都会终止流水线；其余失败
    按阶段默认级别处理。
    """
    if result.get("passed"):
        return False
    stage = str(result.get("key") or "")
    if PINNED_STAGE_LEVELS.get(stage) == BLOCK:
        return True
    levels = stage_levels or DEFAULT_STAGE_LEVELS
    stage_level = levels.get(stage, BLOCK)
    codes = result_error_codes(result)
    if not codes:
        return stage_level == BLOCK
    return any(error_level(code, rule_levels, stage_level) == BLOCK
               for code in codes)
