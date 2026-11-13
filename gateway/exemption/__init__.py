"""分级豁免规则复核模块。

仅依赖本地规则文件与标准库，提供规则加载、最严格仲裁、豁免标记、结论
重算与不可篡改审计能力。未配置规则时整个模块短路，不影响原有校验流程。
"""

from .audit import ExemptionAuditTrail, verify_audit_chain
from .engine import (EXEMPTION_KEY, ExemptionEngine, build_engine,
                     resolve_business_domain)
from .rules import (AnomalyUnit, ConflictDecision, ExemptionRule,
                    ExemptionRuleError, RuleSet, load_exemption_rules)

__all__ = [
    "EXEMPTION_KEY", "AnomalyUnit", "ConflictDecision", "ExemptionAuditTrail",
    "ExemptionEngine", "ExemptionRule", "ExemptionRuleError", "RuleSet",
    "build_engine", "load_exemption_rules", "resolve_business_domain",
    "verify_audit_chain",
]
