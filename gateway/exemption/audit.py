"""豁免操作的不可篡改审计留痕。

每个校验任务生成独立的只追加 JSONL 审计文件：每条记录携带序列号、创建
时间、前一条记录哈希与自身内容哈希，形成哈希链。任何对历史记录的增删改
都会破坏链式哈希并被 :func:`verify_audit_chain` 检出。模块仅使用标准库
与本地文件，不发起任何网络请求。
"""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .rules import AnomalyUnit, ExemptionRule, canonical_json

# 审计版本号，便于后续格式演进时识别。
AUDIT_VERSION = "1.0"
GENESIS_HASH = "0" * 64


class AuditError(RuntimeError):
    """审计文件写入或校验失败。"""


def record_hash(record: Dict[str, Any]) -> str:
    """计算单条审计记录的内容哈希（不含自身 hash 字段）。"""
    payload = {key: value for key, value in record.items() if key != "hash"}
    return sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class ExemptionAuditTrail:
    """单任务豁免审计链，生命周期与任务一致，结束即可释放。"""

    def __init__(self, audit_path: Path, task_id: str, ruleset_hash: str,
                 business_domain: str = "", now: Optional[datetime] = None):
        """准备审计文件路径与任务上下文，不立即写盘。"""
        self.audit_path = Path(audit_path)
        self.task_id = task_id
        self.ruleset_hash = ruleset_hash
        self.business_domain = business_domain
        self._now_factory = now
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._records: List[Dict[str, Any]] = []
        self._closed = False

    def _now(self) -> datetime:
        if callable(self._now_factory):
            value = self._now_factory()
            return value if isinstance(value, datetime) else datetime.now()
        return datetime.now()

    def _append(self, event: str, detail: Dict[str, Any]) -> Dict[str, Any]:
        """构造、链式签名并以只追加方式落盘一条记录。"""
        if self._closed:
            raise AuditError("审计链已关闭，不能再追加记录")
        self._seq += 1
        record = {
            "version": AUDIT_VERSION,
            "seq": self._seq,
            "task_id": self.task_id,
            "event": event,
            "timestamp": self._now().isoformat(timespec="seconds"),
            "prev_hash": self._prev_hash,
            "ruleset_hash": self.ruleset_hash,
            "business_domain": self.business_domain,
            "detail": detail,
        }
        record["hash"] = record_hash(record)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        # 仅追加写入，避免覆盖历史；失败向上抛出由上层转入严格拦截兜底。
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False,
                                    sort_keys=True, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._prev_hash = record["hash"]
        self._records.append(record)
        return record

    def open_chain(self, rule_ids: Sequence[str]) -> Dict[str, Any]:
        """写入链头，固化任务使用的规则快照指纹与规则 ID 清单。"""
        return self._append("chain_open", {
            "rule_ids": list(rule_ids),
            "active_rule_count": len(rule_ids),
        })

    def log_decision(self, unit: AnomalyUnit, chosen: ExemptionRule,
                     candidate_ids: Sequence[str], conflicted: bool,
                     decision: str, valid_from: str, valid_to: str) -> Dict[str, Any]:
        """记录一次异常仲裁（豁免放行或显式拒绝/维持拦截）。"""
        return self._append("decision", {
            "decision": decision,
            "anomaly": unit.to_dict(),
            "matched_rule": chosen.to_audit_dict(),
            "candidate_rule_ids": list(candidate_ids),
            "conflict": bool(conflicted),
            "valid_from": valid_from,
            "valid_to": valid_to,
        })

    def log_unmatched(self, unit: AnomalyUnit) -> Dict[str, Any]:
        """记录未命中任何规则、按默认策略维持拦截的异常。"""
        return self._append("default_block", {
            "anomaly": unit.to_dict(),
            "decision": "blocked",
            "reason": "未匹配到有效豁免规则，默认保持严格拦截",
        })

    def log_expired(self, unit: AnomalyUnit, rule_ids: Sequence[str]) -> Dict[str, Any]:
        """记录存在相关规则但已过期、因而维持拦截的异常。"""
        return self._append("expired_block", {
            "anomaly": unit.to_dict(),
            "expired_rule_ids": list(rule_ids),
            "decision": "blocked",
            "reason": "匹配规则不在有效期内，默认保持严格拦截",
        })

    def close_chain(self, summary: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """写入链尾汇总并收紧文件权限，之后拒绝再追加。

        重复调用时直接返回最近一条记录，保证引擎/上下文多重关闭安全。
        """
        if self._closed:
            return self._records[-1] if self._records else None
        record = self._append("chain_close", {"summary": dict(summary)})
        self._closed = True
        try:
            # 仅属主可读写，降低事后被普通账号篡改的可能性。
            os.chmod(self.audit_path, 0o600)
        except OSError:
            # Windows 等平台 chmod 语义有限，忽略以保持跨平台可用。
            pass
        return record

    @property
    def records(self) -> List[Dict[str, Any]]:
        """返回本次任务内存中的审计记录副本。"""
        return list(self._records)


def read_audit_records(audit_path: Path) -> List[Dict[str, Any]]:
    """读取并解析审计文件，空行忽略，损坏行会抛出 AuditError。"""
    path = Path(audit_path)
    if not path.is_file():
        raise AuditError("审计文件不存在: %s" % path)
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AuditError("审计文件第 %d 行不是合法 JSON" % line_no) from exc
    return records


def verify_audit_chain(audit_path: Path) -> Dict[str, Any]:
    """校验审计链的连续性与内容完整性。

    Returns:
        含 ``valid``、``records``、``task_id`` 与首个错误 ``error`` 的字典。
        任何序列号断裂、前序哈希不匹配或内容被篡改都会令 valid 为 False。
    """
    try:
        records = read_audit_records(audit_path)
    except AuditError as exc:
        return {"valid": False, "records": [], "task_id": "", "error": str(exc)}
    if not records:
        return {"valid": False, "records": [], "task_id": "",
                "error": "审计文件为空"}
    previous = GENESIS_HASH
    expected_seq = 0
    task_id = str(records[0].get("task_id", ""))
    for record in records:
        expected_seq += 1
        stored_hash = record.get("hash", "")
        actual_hash = record_hash(record)
        if record.get("seq") != expected_seq:
            return _invalid(records, task_id,
                            "第 %d 条序列号断裂，期望 %d" % (expected_seq, expected_seq))
        if record.get("prev_hash") != previous:
            return _invalid(records, task_id,
                            "第 %d 条前序哈希不匹配，链已断裂" % expected_seq)
        if stored_hash != actual_hash:
            return _invalid(records, task_id,
                            "第 %d 条内容哈希不匹配，记录疑似被篡改" % expected_seq)
        previous = stored_hash
    if records[-1].get("event") != "chain_close":
        return _invalid(records, task_id, "审计链缺少正常关闭记录")
    return {"valid": True, "records": records, "task_id": task_id, "error": ""}


def _invalid(records: List[Dict[str, Any]], task_id: str,
             error: str) -> Dict[str, Any]:
    """组装校验失败结果。"""
    return {"valid": False, "records": records, "task_id": task_id, "error": error}
