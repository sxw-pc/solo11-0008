"""分级豁免规则的数据模型、本地加载与匹配冲突仲裁。

规则只允许从本地 YAML 文件加载，模块不包含任何网络能力。每条规则以
``业务域 + 异常类型 + 影响范围`` 三维定位，配合动作（豁免/拒绝）、分级与
有效期。多条规则同时命中同一异常时按最严格优先级仲裁，并同步输出冲突提示。

设计原则：任何结构非法、时间非法或状态停用的规则都不会产生豁免放行，
加载阶段直接抛出 :class:`ExemptionRuleError`，由上层转入严格拦截兜底。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

# 允许的豁免动作。deny 表示显式拒绝（维持拦截），exempt 表示按规则豁免。
_ACTIONS = ("deny", "exempt")
# 豁免分级：L1 临时豁免 < L2 限期豁免 < L3 长期备案，数字越小管控越紧。
_GRADES = ("L1", "L2", "L3")
_WILDCARD = "*"
# 规则 ID 仅允许字母数字与少量安全符号，避免被注入到路径或报告模板。
_ID_ALLOWED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class ExemptionRuleError(ValueError):
    """豁免规则文件缺失、YAML 损坏或规则结构非法。"""


def canonical_json(payload: Any) -> str:
    """生成稳定、紧凑、可复现的 JSON 文本，用于哈希与链式审计。"""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def parse_datetime(value: Any, field_name: str = "时间") -> datetime:
    """把 YAML 中的日期/时间统一解析为朴素本地时间。

    同时接受 ``YYYY-MM-DD``、``YYYY-MM-DDTHH:MM:SS`` 与 datetime 对象；
    带时区的时间会被转换为朴素时间，避免朴素/感知时间无法比较。
    """
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    if not isinstance(value, str) or not value.strip():
        raise ExemptionRuleError("%s字段必须是日期或时间字符串" % field_name)
    text = value.strip().replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise ExemptionRuleError("%s字段格式无法解析: %s" % (field_name, value))


def _validate_id(rule_id: Any) -> str:
    """校验规则唯一标识的非空与字符安全。"""
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ExemptionRuleError("规则必须包含非空字符串 id")
    rule_id = rule_id.strip()
    if len(rule_id) > 64 or any(char not in _ID_ALLOWED for char in rule_id):
        raise ExemptionRuleError("规则 id 含非法字符或超长: %s" % rule_id)
    return rule_id


def _ensure_str_list(value: Any, label: str, allow_wildcard: bool) -> List[str]:
    """校验并规范化字符串列表字段。"""
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value:
        raise ExemptionRuleError("%s必须是非空列表或字符串" % label)
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ExemptionRuleError("%s只能包含非空字符串" % label)
        item = item.strip()
        if item == _WILDCARD:
            if not allow_wildcard:
                raise ExemptionRuleError("%s不支持通配符 *" % label)
        result.append(item)
    return result


@dataclass(frozen=True)
class ExemptionRule:
    """单条不可变分级豁免规则。

    Attributes:
        rule_id: 规则唯一标识，豁免记录据此关联。
        business_domain: 适用业务域，``*`` 表示任意业务域。
        anomaly_types: 可命中的异常类型代码列表，``*`` 表示任意类型。
        tables/fields/paths: 影响范围约束，空列表表示不限制该维度。
        action: ``exempt`` 豁免或 ``deny`` 显式拒绝。
        grade: 豁免分级 L1/L2/L3。
        effective_from/effective_to: 有效期闭区间。
        approvers: 多部门确认信息，用于审计留痕。
        reason: 历史遗留问题与放行依据说明。
        enabled: 是否启用，停用规则不参与匹配。
    """

    rule_id: str
    business_domain: str
    anomaly_types: Tuple[str, ...]
    action: str
    grade: str
    effective_from: datetime
    effective_to: datetime
    tables: Tuple[str, ...] = ()
    fields: Tuple[str, ...] = ()
    paths: Tuple[str, ...] = ()
    approvers: Tuple[str, ...] = ()
    reason: str = ""
    enabled: bool = True

    def to_audit_dict(self) -> Dict[str, Any]:
        """转换为可序列化、可哈希的稳定字典。"""
        return {
            "id": self.rule_id,
            "business_domain": self.business_domain,
            "anomaly_types": list(self.anomaly_types),
            "action": self.action,
            "grade": self.grade,
            "effective_from": self.effective_from.isoformat(timespec="seconds"),
            "effective_to": self.effective_to.isoformat(timespec="seconds"),
            "tables": list(self.tables),
            "fields": list(self.fields),
            "paths": list(self.paths),
            "approvers": list(self.approvers),
            "reason": self.reason,
            "enabled": self.enabled,
        }

    def is_active(self, now: datetime) -> bool:
        """规则在指定时刻是否处于有效期内且启用。"""
        return self.enabled and self.effective_from <= now <= self.effective_to

    def _scope_allows(self, unit: "AnomalyUnit") -> bool:
        """判断影响范围（表/字段/路径）是否覆盖异常单元。"""
        for allowed, actual in ((self.tables, unit.table),
                                (self.fields, unit.field),
                                (self.paths, unit.path)):
            if not allowed:
                continue  # 未配置该维度约束即不限制。
            if _WILDCARD in allowed:
                continue
            if not actual or actual not in allowed:
                return False
        return True

    def matches(self, unit: "AnomalyUnit", now: datetime) -> bool:
        """业务域、异常类型、影响范围与有效期全部满足才算命中。"""
        if not self.is_active(now):
            return False
        if self.business_domain != _WILDCARD and self.business_domain != unit.domain:
            return False
        if _WILDCARD not in self.anomaly_types and unit.anomaly_type not in self.anomaly_types:
            return False
        return self._scope_allows(unit)

    def specificity(self, unit: "AnomalyUnit") -> int:
        """规则相对异常单元的具体度，约束维度越多越具体（越严格）。"""
        score = 0
        if self.business_domain != _WILDCARD:
            score += 16
        if _WILDCARD not in self.anomaly_types:
            score += 8
        if self.tables:
            score += 4
        if self.fields:
            score += 2
        if self.paths:
            score += 1
        return score


@dataclass(frozen=True)
class AnomalyUnit:
    """待仲裁的异常单元，屏蔽各校验项结果结构差异。"""

    check: str
    anomaly_type: str
    domain: str = ""
    table: str = ""
    field: str = ""
    path: str = ""
    message: str = ""

    def key(self) -> Tuple[str, str, str, str, str, str]:
        """异常单元稳定标识，用于冲突去重与审计关联。"""
        return (self.check, self.anomaly_type, self.domain,
                self.table, self.field, self.path)

    def to_dict(self) -> Dict[str, str]:
        return {
            "check": self.check, "anomaly_type": self.anomaly_type,
            "domain": self.domain, "table": self.table,
            "field": self.field, "path": self.path, "message": self.message,
        }


@dataclass(frozen=True)
class ConflictDecision:
    """单条异常的仲裁结论，含冲突候选与选择依据。"""

    unit: AnomalyUnit
    chosen: ExemptionRule
    candidates: Tuple[ExemptionRule, ...]
    conflicted: bool

    @property
    def exempted(self) -> bool:
        """最终是否按豁免放行；显式拒绝或非豁免动作均维持拦截。"""
        return self.chosen.action == "exempt"


@dataclass(frozen=True)
class RuleSet:
    """一次加载形成的不可变规则快照，任务期间不受文件变更影响。"""

    rules: Tuple[ExemptionRule, ...] = field(default_factory=tuple)
    ruleset_hash: str = ""

    def __bool__(self) -> bool:
        """无规则时引擎可整体短路，保证旧流程结果零变化。"""
        return bool(self.rules)

    def decide(self, unit: AnomalyUnit, now: datetime) -> Optional[ConflictDecision]:
        """返回异常单元的最严格仲裁结论；无命中规则返回 None（维持拦截）。"""
        candidates = [rule for rule in self.rules if rule.matches(unit, now)]
        if not candidates:
            return None
        # 仲裁键：deny 优先、具体度高优先、到期早优先、ID 字典序兜底，全部确定性。
        ranked = sorted(
            candidates,
            key=lambda rule: (
                0 if rule.action == "deny" else 1,
                -rule.specificity(unit),
                rule.effective_to,
                rule.rule_id,
            ),
        )
        chosen = ranked[0]
        conflicted = len(candidates) > 1
        return ConflictDecision(unit=unit, chosen=chosen,
                                candidates=tuple(ranked), conflicted=conflicted)

    def active_rule_ids(self, now: datetime) -> List[str]:
        """当前仍在有效期内的规则 ID，供报告与审计展示。"""
        return sorted(rule.rule_id for rule in self.rules if rule.is_active(now))

    def expired_matches(self, unit: AnomalyUnit, now: datetime) -> List[str]:
        """返回维度命中但已过有效期（或未生效）的规则 ID。

        用于审计中区分“无规则匹配”与“规则存在但已失效”，两者都维持拦截。
        """
        expired = []
        for rule in self.rules:
            if rule.is_active(now):
                continue
            if rule.enabled and rule.matches(unit, rule.effective_from):
                expired.append(rule.rule_id)
        return sorted(set(expired))


def _build_rule(raw: Any, index: int) -> ExemptionRule:
    """把单条 YAML 映射校验并转换为不可变规则对象。"""
    if not isinstance(raw, dict):
        raise ExemptionRuleError("第 %d 条规则必须是映射" % (index + 1))
    rule_id = _validate_id(raw.get("id"))
    domain = raw.get("business_domain")
    if not isinstance(domain, str) or not domain.strip():
        raise ExemptionRuleError("规则 %s 缺少 business_domain" % rule_id)
    if "anomaly_types" not in raw:
        raise ExemptionRuleError("规则 %s 缺少 anomaly_types" % rule_id)
    anomaly_types = tuple(_ensure_str_list(
        raw.get("anomaly_types"), "规则 %s 的 anomaly_types" % rule_id, True))
    if not anomaly_types:
        raise ExemptionRuleError("规则 %s 的 anomaly_types 不能为空" % rule_id)
    scope = raw.get("scope") or {}
    if not isinstance(scope, dict):
        raise ExemptionRuleError("规则 %s 的 scope 必须是映射" % rule_id)
    tables = tuple(_ensure_str_list(scope.get("tables"),
                                    "规则 %s 的 scope.tables" % rule_id, True))
    fields = tuple(_ensure_str_list(scope.get("fields"),
                                    "规则 %s 的 scope.fields" % rule_id, True))
    paths = tuple(_ensure_str_list(scope.get("paths"),
                                   "规则 %s 的 scope.paths" % rule_id, True))
    action = str(raw.get("action", "")).strip()
    if action not in _ACTIONS:
        raise ExemptionRuleError(
            "规则 %s 的 action 仅支持 %s" % (rule_id, "/".join(_ACTIONS)))
    grade = str(raw.get("grade", "L2")).strip()
    if grade not in _GRADES:
        raise ExemptionRuleError("规则 %s 的 grade 仅支持 %s"
                                 % (rule_id, "/".join(_GRADES)))
    effective_from = parse_datetime(raw.get("effective_from"),
                                    "规则 %s effective_from" % rule_id)
    effective_to = parse_datetime(raw.get("effective_to"),
                                  "规则 %s effective_to" % rule_id)
    if effective_from > effective_to:
        raise ExemptionRuleError("规则 %s 的生效时间晚于失效时间" % rule_id)
    approvers = tuple(_ensure_str_list(
        raw.get("approvers"), "规则 %s 的 approvers" % rule_id, False))
    if not approvers:
        raise ExemptionRuleError("规则 %s 必须提供至少一个 approvers 确认部门" % rule_id)
    reason = raw.get("reason", "")
    if not isinstance(reason, str):
        raise ExemptionRuleError("规则 %s 的 reason 必须是字符串" % rule_id)
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ExemptionRuleError("规则 %s 的 enabled 必须是布尔值" % rule_id)
    return ExemptionRule(
        rule_id=rule_id, business_domain=domain.strip(),
        anomaly_types=anomaly_types, action=action, grade=grade,
        effective_from=effective_from, effective_to=effective_to,
        tables=tables, fields=fields, paths=paths, approvers=approvers,
        reason=reason.strip(), enabled=enabled)


def compute_ruleset_hash(rules: Sequence[ExemptionRule]) -> str:
    """对全部规则的规范化内容计算 SHA256，作为规则快照指纹。"""
    payload = [rule.to_audit_dict() for rule in sorted(rules, key=lambda r: r.rule_id)]
    return sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def load_exemption_rules(path: Optional[Path]) -> RuleSet:
    """从本地 YAML 加载并校验豁免规则，返回不可变快照。

    Args:
        path: 本地规则文件路径；传入 None 或文件不存在时返回空快照，
            表示未启用豁免，调用方据此完全跳过豁免逻辑。
    Raises:
        ExemptionRuleError: YAML 损坏、根结构错误、规则字段非法或 ID 重复。
    """
    if path is None:
        return RuleSet()
    path = Path(path)
    if not path.is_file():
        return RuleSet()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
        raise ExemptionRuleError("豁免规则 YAML 解析失败: %s" % exc) from exc
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ExemptionRuleError("豁免规则文件必须包含 rules 列表")
    if not data["rules"]:
        return RuleSet()
    rules = tuple(_build_rule(raw, index)
                  for index, raw in enumerate(data["rules"]))
    seen = set()
    for rule in rules:
        if rule.rule_id in seen:
            raise ExemptionRuleError("豁免规则 id 重复: %s" % rule.rule_id)
        seen.add(rule.rule_id)
    return RuleSet(rules=rules, ruleset_hash=compute_ruleset_hash(rules))


def iter_units(units: Iterable[AnomalyUnit]) -> Iterable[AnomalyUnit]:
    """仅供类型检查与测试复用的单元迭代辅助。"""
    return units
