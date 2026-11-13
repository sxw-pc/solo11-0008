"""分级豁免复核引擎与校验结果适配。

引擎在任务启动时一次性加载不可变规则快照，任务结束后随上下文退出自动释放，
因此任务运行期间规则文件如何变更都不会影响其最终结论。引擎把
archive/hash/schema/lineage/anomaly 等不同结构的校验结果归一化为
:class:`~gateway.exemption.rules.AnomalyUnit`，统一完成匹配、最严格仲裁、
豁免标记、结论重算与防篡改审计。

安全底线：未命中规则、规则过期、规则配置错误或任何内部异常，异常项一律维持
拦截状态，绝不会出现未授权豁免放行。
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import threading
import weakref
from typing import Any, Callable, Dict, List, Optional, Tuple

from .audit import ExemptionAuditTrail
from .rules import AnomalyUnit, ConflictDecision, RuleSet, load_exemption_rules

# 结果字典中豁免信息的固定键，历史任务无此键即视为全部拦截。
EXEMPTION_KEY = "exemption"
# 参与豁免复核的校验项；压缩包安全类高危项默认永不豁免。
_EXEMPTIBLE_CHECKS = frozenset({"hash", "schema", "lineage", "anomaly"})
_BANNED_ANOMALY = frozenset({
    "path_traversal", "zip_bomb", "dangerous_file", "package_hash_mismatch",
})
_DENY_TAG = "blocked_by_rule"


class ExemptionEngine:
    """单任务豁免复核引擎，持有独立规则快照与审计链。"""

    # 类级弱引用登记表，用于核查在跑实例与验证任务结束后的自动释放。
    _registry_lock = threading.Lock()
    _live_instances: "weakref.WeakSet[ExemptionEngine]" = weakref.WeakSet()

    def __init__(self, ruleset: RuleSet, task_id: str, business_domain: str,
                 audit_dir: Path, now: Optional[datetime] = None,
                 audit_path: Optional[Path] = None):
        """绑定规则快照并准备审计链；不读取任何外部资源。"""
        self.ruleset = ruleset
        self.task_id = task_id
        self.business_domain = business_domain or ""
        self.now = now or datetime.now()
        self._audit = ExemptionAuditTrail(
            audit_path or (Path(audit_dir) / (task_id + ".audit.jsonl")),
            task_id, ruleset.ruleset_hash, self.business_domain, now=self.now)
        self._released = False
        with self._registry_lock:
            self._live_instances.add(self)

    # ---- 生命周期与资源释放 -------------------------------------------------
    def __enter__(self) -> "ExemptionEngine":
        if self.ruleset:
            self._audit.open_chain(self.ruleset.active_rule_ids(self.now))
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self, summary: Optional[Dict[str, Any]] = None) -> None:
        """关闭审计链并释放规则快照引用，重复调用安全。"""
        if self._released:
            return
        if self.ruleset:
            self._audit.close_chain(summary or {})
        self.ruleset = RuleSet()  # 解除对不可变规则元组的持有，便于内存回收。
        self._released = True
        with self._registry_lock:
            self._live_instances.discard(self)

    @classmethod
    def live_count(cls) -> int:
        """当前尚未释放的引擎实例数，主要供测试验证无资源泄漏。"""
        with cls._registry_lock:
            return len(cls._live_instances)

    @classmethod
    def reset_registry(cls) -> None:
        """清空弱引用登记表，仅用于测试隔离。"""
        with cls._registry_lock:
            cls._live_instances = weakref.WeakSet()

    # ---- 主入口 -------------------------------------------------------------
    def apply(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """对校验结果执行豁免复核并原地标记，返回豁免汇总。"""
        if not self.ruleset:
            return _empty_summary()
        summary = _empty_summary()
        conflicts: List[Dict[str, Any]] = []
        for result in results:
            check = str(result.get("key", ""))
            if check not in _EXEMPTIBLE_CHECKS:
                continue
            units, attach = _extract_units(result, check, self.business_domain)
            if not units:
                continue
            for unit, error_ref in units:
                if unit.anomaly_type in _BANNED_ANOMALY:
                    # 高危安全异常不接受任何豁免，直接维持拦截并留痕。
                    self._audit.log_unmatched(unit)
                    summary["blocked"] += 1
                    continue
                decision = self.ruleset.decide(unit, self.now)
                if decision is None:
                    expired_ids = self.ruleset.expired_matches(unit, self.now)
                    if expired_ids:
                        self._audit.log_expired(unit, expired_ids)
                        summary["expired_blocked"] += 1
                    else:
                        self._audit.log_unmatched(unit)
                        summary["blocked"] += 1
                    continue
                self._record_decision(unit, decision, attach(error_ref), summary)
                if decision.conflicted:
                    conflicts.append(_conflict_payload(decision))
            _recompute_passed(result, check)
        summary["conflicts"] = conflicts
        summary["conflict_count"] = len(conflicts)
        summary["ruleset_hash"] = self.ruleset.ruleset_hash
        summary["rule_ids"] = self.ruleset.active_rule_ids(self.now)
        summary["audit_path"] = str(self._audit.audit_path)
        self.close(summary)
        return summary

    # ---- 内部辅助 -----------------------------------------------------------
    def _record_decision(self, unit: AnomalyUnit, decision: ConflictDecision,
                         error_obj: Dict[str, Any], summary: Dict[str, Any]) -> None:
        """把仲裁结论写入异常对象与审计链，并累计汇总计数。"""
        rule = decision.chosen
        candidate_ids = [item.rule_id for item in decision.candidates]
        valid_from = rule.effective_from.isoformat(timespec="seconds")
        valid_to = rule.effective_to.isoformat(timespec="seconds")
        if rule.action == "exempt":
            error_obj[EXEMPTION_KEY] = {
                "status": "exempted", "rule_id": rule.rule_id,
                "grade": rule.grade, "action": rule.action,
                "valid_from": valid_from, "valid_to": valid_to,
                "approvers": list(rule.approvers), "reason": rule.reason,
                "candidate_rule_ids": candidate_ids,
                "conflicted": decision.conflicted,
                "decided_at": self.now.isoformat(timespec="seconds"),
            }
            self._audit.log_decision(
                unit, rule, candidate_ids, decision.conflicted,
                "exempted", valid_from, valid_to)
            summary["exempted"] += 1
            summary["exemption_records"].append({
                "rule_id": rule.rule_id, "check": unit.check,
                "anomaly_type": unit.anomaly_type, "table": unit.table,
                "field": unit.field, "path": unit.path,
                "grade": rule.grade, "valid_from": valid_from,
                "valid_to": valid_to,
            })
        else:
            error_obj[EXEMPTION_KEY] = {
                "status": _DENY_TAG, "rule_id": rule.rule_id,
                "grade": rule.grade, "action": rule.action,
                "valid_from": valid_from, "valid_to": valid_to,
                "approvers": list(rule.approvers), "reason": rule.reason,
                "candidate_rule_ids": candidate_ids,
                "conflicted": decision.conflicted,
                "decided_at": self.now.isoformat(timespec="seconds"),
            }
            self._audit.log_decision(
                unit, rule, candidate_ids, decision.conflicted,
                "denied", valid_from, valid_to)
            summary["denied"] += 1


def _empty_summary() -> Dict[str, Any]:
    """构造结构稳定的空豁免汇总。"""
    return {
        "enabled": False, "exempted": 0, "denied": 0, "blocked": 0,
        "expired_blocked": 0, "conflict_count": 0, "conflicts": [],
        "exemption_records": [], "rule_ids": [], "ruleset_hash": "",
        "audit_path": "",
    }


def _conflict_payload(decision: ConflictDecision) -> Dict[str, Any]:
    """生成可归档的冲突提示结构。"""
    return {
        "anomaly": decision.unit.to_dict(),
        "chosen_rule_id": decision.chosen.rule_id,
        "chosen_action": decision.chosen.action,
        "candidate_rule_ids": [rule.rule_id for rule in decision.candidates],
        "message": "异常同时命中 %d 条规则，已按最严格优先级采用规则 %s（%s）"
                   % (len(decision.candidates), decision.chosen.rule_id,
                      decision.chosen.action),
    }


# ---- 各校验项结果到异常单元的适配 -----------------------------------------
def _make_unit(check: str, anomaly_type: Any, domain: str, **scope: Any) -> AnomalyUnit:
    """安全构造异常单元，缺失字段统一为空字符串。"""
    return AnomalyUnit(
        check=check, anomaly_type=str(anomaly_type or "unknown"), domain=domain,
        table=str(scope.get("table") or ""), field=str(scope.get("field") or ""),
        path=str(scope.get("path") or ""),
        message=str(scope.get("message") or ""))


def _extract_units(result: Dict[str, Any], check: str, domain: str
                   ) -> Tuple[List[Tuple[AnomalyUnit, Dict[str, Any]]],
                              Callable[[Dict[str, Any]], Dict[str, Any]]]:
    """按校验项类型抽取 (异常单元, 错误对象) 对与标记回写函数。"""
    if check == "schema":
        return _schema_units(result, domain), _identity_attach
    if check == "lineage":
        return _lineage_units(result, domain), _lineage_attach(result)
    if check == "anomaly":
        return _anomaly_units(result, domain), _anomaly_attach(result)
    # hash 及其它 errors 列表型结果。
    pairs = [(_make_unit(check, err.get("code"), domain,
                         table=err.get("table"), field=err.get("field"),
                         path=err.get("path"), message=err.get("message")), err)
             for err in result.get("errors", []) if isinstance(err, dict)]
    return pairs, _identity_attach


def _identity_attach(error_obj: Dict[str, Any]) -> Dict[str, Any]:
    """errors 列表型结果直接在原错误对象上标记。"""
    return error_obj


def _schema_units(result: Dict[str, Any], domain: str
                  ) -> List[Tuple[AnomalyUnit, Dict[str, Any]]]:
    """Schema 以表级 errors 内的每条错误为最小豁免单元。"""
    pairs: List[Tuple[AnomalyUnit, Dict[str, Any]]] = []
    for table_result in result.get("tables", []):
        if not isinstance(table_result, dict):
            continue
        for err in table_result.get("errors", []):
            if isinstance(err, dict):
                pairs.append((_make_unit("schema", err.get("code"), domain,
                                         table=err.get("table"),
                                         field=err.get("field"),
                                         path=err.get("path"),
                                         message=err.get("message")), err))
    # 顶层 errors 可能包含表缺失等表级错误，去重后补充。
    known = {id(err) for _, err in pairs}
    for err in result.get("errors", []):
        if isinstance(err, dict) and id(err) not in known:
            pairs.append((_make_unit("schema", err.get("code"), domain,
                                     table=err.get("table"),
                                     field=err.get("field"),
                                     path=err.get("path"),
                                     message=err.get("message")), err))
    return pairs


def _lineage_units(result: Dict[str, Any], domain: str
                   ) -> List[Tuple[AnomalyUnit, Dict[str, Any]]]:
    """血缘以每条关联的每个错误代码为最小豁免单元。"""
    pairs: List[Tuple[AnomalyUnit, Dict[str, Any]]] = []
    for relation in result.get("relations", []):
        if not isinstance(relation, dict):
            continue
        for err in relation.get("errors", []):
            if isinstance(err, dict):
                pairs.append((_make_unit(
                    "lineage", err.get("code"), domain,
                    table=relation.get("left_table"),
                    field=relation.get("left_field"),
                    message="%s: %s" % (relation.get("name"), err.get("message"))),
                    err))
    return pairs


def _lineage_attach(result: Dict[str, Any]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """血缘错误标记在 relation.errors 的错误对象上，闭包无需额外回写。"""
    return _identity_attach


def _anomaly_units(result: Dict[str, Any], domain: str
                   ) -> List[Tuple[AnomalyUnit, Dict[str, Any]]]:
    """异常抽检以“字段 × 失败规则”为最小豁免单元。"""
    pairs: List[Tuple[AnomalyUnit, Dict[str, Any]]] = []
    for field_result in result.get("fields", []):
        if not isinstance(field_result, dict):
            continue
        for rule in field_result.get("rules", []):
            if isinstance(rule, dict) and not rule.get("passed"):
                pairs.append((_make_unit(
                    "anomaly", rule.get("rule"), domain,
                    table=field_result.get("table"),
                    field=field_result.get("field"),
                    message=rule.get("error") or rule.get("rule")), rule))
    # 规则配置类错误（表/字段缺失）同样纳入复核，默认仍可被规则匹配或拦截。
    for err in result.get("errors", []):
        if isinstance(err, dict):
            pairs.append((_make_unit("anomaly", err.get("code"), domain,
                                     table=err.get("table"),
                                     field=err.get("field"),
                                     message=err.get("message")), err))
    return pairs


def _anomaly_attach(result: Dict[str, Any]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """异常规则标记直接落在 rules 列表的规则对象上。"""
    return _identity_attach


def _recompute_passed(result: Dict[str, Any], check: str) -> None:
    """依据豁免标记重算单个校验项是否仍存在未豁免拦截。"""
    if check == "schema":
        blocking = [
            table for table in result.get("tables", [])
            if isinstance(table, dict) and any(
                isinstance(err, dict) and not _is_exempted(err)
                for err in table.get("errors", []))]
        top_blocking = [err for err in result.get("errors", [])
                        if isinstance(err, dict) and not _is_exempted(err)]
        result["passed"] = not blocking and not top_blocking
    elif check == "lineage":
        result["passed"] = all(
            relation.get("passed", True) or all(
                _is_exempted(err) for err in relation.get("errors", [])
                if isinstance(err, dict))
            for relation in result.get("relations", []))
    elif check == "anomaly":
        field_blocking = any(
            isinstance(field_item, dict) and any(
                isinstance(rule, dict) and not rule.get("passed", True)
                and not _is_exempted(rule)
                for rule in field_item.get("rules", []))
            for field_item in result.get("fields", []))
        error_blocking = any(
            isinstance(err, dict) and not _is_exempted(err)
            for err in result.get("errors", []))
        result["passed"] = not field_blocking and not error_blocking
    else:
        result["passed"] = all(
            _is_exempted(err) for err in result.get("errors", [])
            if isinstance(err, dict))


def _is_exempted(obj: Dict[str, Any]) -> bool:
    """判断错误/规则对象是否已被有效豁免（deny 不算豁免）。"""
    info = obj.get(EXEMPTION_KEY)
    return isinstance(info, dict) and info.get("status") == "exempted"


# ---- 工厂与业务域解析 ------------------------------------------------------
def resolve_business_domain(manifest: Optional[Dict[str, Any]]) -> str:
    """从 manifest 解析数据包业务域，兼容 packet 嵌套与顶层两种写法。

    历史数据包不含该字段时返回空字符串，此时仅 ``*`` 通配规则可命中，
    避免把无域数据错误地归入某个具体业务域而产生越权豁免。
    """
    if not isinstance(manifest, dict):
        return ""
    candidates = [manifest.get("business_domain")]
    packet = manifest.get("packet")
    if isinstance(packet, dict):
        candidates.append(packet.get("business_domain"))
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def build_engine(rules_path: Optional[Path], task_id: str,
                 business_domain: str, audit_dir: Path,
                 now: Optional[datetime] = None) -> Optional[ExemptionEngine]:
    """任务启动时加载本地规则快照并构造引擎。

    规则文件缺失/未配置返回 None（完全跳过豁免，旧流程零变化）；规则文件
    存在但内容非法时抛出 :class:`ExemptionRuleError`，由上层保持严格拦截。
    """
    ruleset = load_exemption_rules(rules_path)
    if not ruleset:
        return None
    return ExemptionEngine(ruleset, task_id, business_domain, audit_dir, now=now)
