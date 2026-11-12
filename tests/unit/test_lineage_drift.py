"""跨版本血缘漂移检测纯函数单元测试。"""

import pytest

from gateway.validator.lineage_drift import (
    DEFAULT_LINEAGE_KEY, SNAPSHOT_VERSION, LineageSnapshotError,
    build_lineage_snapshot, detect_lineage_drift, first_version_drift,
    lineage_domain_key, unavailable_drift, validate_snapshot_payload)


def _lineage_result(relations=None, passed=True):
    return {"key": "lineage", "passed": passed,
            "relations": relations if relations is not None else [],
            "graph": {}}


def _relation(name="rel", left_table="trades", left_field="user_id",
              right_table="users", right_field="user_id",
              relationship="many_to_one", require_reference=True,
              allow_null=False, passed=True):
    return {"name": name, "left_table": left_table, "left_field": left_field,
            "right_table": right_table, "right_field": right_field,
            "relationship": relationship, "require_reference": require_reference,
            "allow_null": allow_null, "passed": passed}


def _snapshot(tables=None, relations=None, lineage_key="trade_domain",
              task_id="task-1", packet_name="v1.zip", passed=True,
              version=SNAPSHOT_VERSION):
    return {
        "snapshot_version": version, "lineage_key": lineage_key,
        "task_id": task_id, "packet_name": packet_name,
        "created_at": "2024-03-01T10:00:00", "lineage_passed": passed,
        "tables": tables if tables is not None else {},
        "relations": relations if relations is not None else [],
    }


# ---------------- 业务契约键 ----------------

def test_lineage_domain_key_prefers_rule_name():
    assert lineage_domain_key({"name": "trade_domain"}, "rule.yaml") == "trade_domain"


def test_lineage_domain_key_falls_back_to_filename():
    assert lineage_domain_key({"name": "  "}, "configs/trade_rule.yaml") == "trade_rule"
    assert lineage_domain_key(None, "") == DEFAULT_LINEAGE_KEY
    assert lineage_domain_key("not-a-dict", "") == DEFAULT_LINEAGE_KEY


# ---------------- 快照构造 ----------------

def test_build_snapshot_from_result_and_tables(valid_users, valid_trades):
    result = _lineage_result([_relation()])
    rules = {"name": "trade_domain", "relations": []}
    snapshot = build_lineage_snapshot(
        result, {"users": valid_users, "trades": valid_trades}, rules,
        task_id="t1", packet_name="p1.zip", created_at="2024-03-01T10:00:00")
    assert snapshot["snapshot_version"] == SNAPSHOT_VERSION
    assert snapshot["lineage_key"] == "trade_domain"
    assert snapshot["tables"]["users"]["fields"] == list(valid_users.frame.columns)
    assert snapshot["tables"]["users"]["row_count"] == 3
    assert snapshot["relations"][0]["require_reference"] is True
    assert snapshot["relations"][0]["allow_null"] is False


def test_build_snapshot_uses_attribute_defaults_and_skips_bad_entries(make_table):
    table = make_table("t", [{"id": "1"}])
    relation = {"name": "r", "left_table": "t", "left_field": "id",
                "right_table": "u", "right_field": "id",
                "relationship": "one_to_one"}
    snapshot = build_lineage_snapshot(
        _lineage_result([relation, "invalid"]), {"t": table}, None,
        task_id="t2", packet_name="p2.zip")
    entry = snapshot["relations"][0]
    assert entry["require_reference"] is True
    assert entry["allow_null"] is False
    assert entry["passed"] is False
    assert len(snapshot["relations"]) == 1


def test_build_snapshot_handles_table_without_frame():
    class BareTable:
        frame = None

    snapshot = build_lineage_snapshot(
        _lineage_result(), {"t": BareTable()}, {"name": "d"},
        task_id="t3", packet_name="p3.zip")
    assert snapshot["tables"]["t"] == {"fields": [], "row_count": 0}
    # tables 为 None 时也不报错。
    snapshot = build_lineage_snapshot(
        _lineage_result(), None, {"name": "d"}, task_id="t4", packet_name="p4.zip")
    assert snapshot["tables"] == {}


# ---------------- 载荷校验 ----------------

def test_validate_snapshot_payload_errors():
    with pytest.raises(LineageSnapshotError, match="根节点"):
        validate_snapshot_payload(["not", "mapping"])
    with pytest.raises(LineageSnapshotError, match="版本"):
        validate_snapshot_payload(_snapshot(version=99))
    with pytest.raises(LineageSnapshotError, match="tables"):
        bad = _snapshot()
        bad["tables"] = []
        validate_snapshot_payload(bad)
    with pytest.raises(LineageSnapshotError, match="relations"):
        bad = _snapshot()
        bad["relations"] = {}
        validate_snapshot_payload(bad)


# ---------------- 漂移检测 ----------------

def test_first_version_drift_shape():
    snapshot = _snapshot()
    drift = first_version_drift(
        snapshot, current_meta={"version": 1, "task_id": "t1",
                                "packet_name": "p1.zip", "created_at": "x"})
    assert drift["enabled"] and not drift["degraded"]
    assert drift["baseline"] is None
    assert drift["has_changes"] is False
    assert drift["counts"]["table_added"] == 0
    assert "首次" in drift["summary"]


def test_unavailable_drift_shape():
    drift = unavailable_drift("损坏", code="lineage_snapshot_corrupt",
                              lineage_key="d")
    assert drift["degraded"] is True
    assert drift["error"]["code"] == "lineage_snapshot_corrupt"
    assert drift["lineage_key"] == "d"
    default = unavailable_drift("原因")
    assert default["lineage_key"] == DEFAULT_LINEAGE_KEY
    assert default["error"]["code"] == "drift_unavailable"


def test_detect_no_changes():
    snapshot = _snapshot(
        tables={"users": {"fields": ["id"], "row_count": 1}},
        relations=[_relation()])
    drift = detect_lineage_drift(snapshot, snapshot)
    assert drift["has_changes"] is False
    assert drift["changes"] == []
    assert "未发生变化" in drift["summary"]
    assert drift["lineage_key"] == "trade_domain"
    # meta 优先使用外部传入的存储元数据。
    drift = detect_lineage_drift(
        snapshot, snapshot,
        current_meta={"snapshot_id": "s2", "version": 2, "task_id": "t2",
                      "packet_name": "p2", "created_at": "c", "protected": False},
        baseline_meta={"snapshot_id": "s1", "version": 1, "task_id": "t1",
                       "packet_name": "p1", "created_at": "b", "protected": True})
    assert drift["current"]["snapshot_id"] == "s2"
    assert drift["baseline"]["protected"] is True


def test_detect_falls_back_to_payload_meta():
    snapshot = _snapshot()
    drift = detect_lineage_drift(snapshot, snapshot)
    assert drift["current"]["task_id"] == "task-1"
    assert drift["baseline"]["packet_name"] == "v1.zip"


def test_detect_relation_added_removed_and_changed():
    baseline = _snapshot(relations=[_relation("a"), _relation("b")])
    current = _snapshot(relations=[
        _relation("b", left_field="owner_id"),
        _relation("c", relationship="one_to_one"),
    ])
    drift = detect_lineage_drift(current, baseline)
    by_type = {change["type"]: change for change in drift["changes"]}
    assert set(by_type) == {"relation_added", "relation_removed", "relation_changed"}
    assert by_type["relation_added"]["target"] == "c"
    assert by_type["relation_removed"]["target"] == "a"
    changed = by_type["relation_changed"]
    assert changed["before"]["left_field"] == "user_id"
    assert changed["after"]["left_field"] == "owner_id"
    assert drift["counts"]["relation_added"] == 1
    assert drift["counts"]["relation_removed"] == 1
    assert drift["counts"]["relation_changed"] == 1
    assert "血缘关联新增 1 处" in drift["summary"]


def test_detect_relation_bool_attribute_change():
    baseline = _snapshot(relations=[_relation("r", allow_null=False)])
    current = _snapshot(relations=[_relation("r", allow_null=True)])
    drift = detect_lineage_drift(current, baseline)
    change = drift["changes"][0]
    assert change["type"] == "relation_changed"
    assert change["before"]["allow_null"] is False
    assert change["after"]["allow_null"] is True


def test_detect_table_and_field_changes():
    baseline = _snapshot(tables={
        "users": {"fields": ["id", "name"], "row_count": 2},
        "trades": {"fields": ["trade_id", "user_id"], "row_count": 3},
    })
    current = _snapshot(tables={
        "users": {"fields": ["id", "name", "email"], "row_count": 2},
        "trades": {"fields": ["trade_id"], "row_count": 3},
        "logs": {"fields": ["log_id"], "row_count": 9},
    })
    drift = detect_lineage_drift(current, baseline)
    targets = {(change["type"], change["target"]) for change in drift["changes"]}
    assert ("table_added", "logs") in targets
    assert ("table_removed", "trades") not in targets  # trades 仍存在，仅字段变化
    assert ("field_added", "users.email") in targets
    assert ("field_removed", "trades.user_id") in targets
    assert drift["counts"]["table_added"] == 1
    assert drift["counts"]["field_added"] == 1
    assert drift["counts"]["field_removed"] == 1
    added = next(change for change in drift["changes"]
                 if change["type"] == "table_added")
    assert added["after"]["row_count"] == 9
    # 输出顺序按类型固定字典序排序，报告可稳定解析。
    ordered = [change["type"] for change in drift["changes"]]
    assert ordered == sorted(ordered, key=lambda value: {
        "relation_added": 0, "relation_removed": 1, "relation_changed": 2,
        "table_added": 3, "table_removed": 4, "table_split": 5,
        "table_merged": 6, "field_added": 7, "field_removed": 8}[value])


def test_detect_table_removed_with_row_count():
    baseline = _snapshot(tables={"old": {"fields": ["a", "b"], "row_count": 7}})
    current = _snapshot(tables={})
    drift = detect_lineage_drift(current, baseline)
    change = drift["changes"][0]
    assert change["type"] == "table_removed"
    assert change["before"]["row_count"] == 7


def test_detect_table_split():
    baseline = _snapshot(tables={
        "user": {"fields": ["id", "name", "email", "phone"], "row_count": 10},
    })
    current = _snapshot(tables={
        "user_base": {"fields": ["id", "name"], "row_count": 10},
        "user_contact": {"fields": ["email", "phone"], "row_count": 10},
    })
    drift = detect_lineage_drift(current, baseline)
    assert drift["counts"]["table_split"] == 1
    change = drift["changes"][0]
    assert change["type"] == "table_split"
    assert change["target"] == "user"
    assert set(change["after"]["tables"]) == {"user_base", "user_contact"}
    # 被解释为拆分的新表不再重复报告为 table_added。
    assert drift["counts"]["table_added"] == 0


def test_detect_table_merge():
    baseline = _snapshot(tables={
        "user_base": {"fields": ["id", "name"], "row_count": 1},
        "user_contact": {"fields": ["email", "phone"], "row_count": 1},
    })
    current = _snapshot(tables={
        "user": {"fields": ["id", "name", "email", "phone"], "row_count": 1},
    })
    drift = detect_lineage_drift(current, baseline)
    assert drift["counts"]["table_merged"] == 1
    change = drift["changes"][0]
    assert change["type"] == "table_merged"
    assert change["target"] == "user"
    assert set(change["before"]["tables"]) == {"user_base", "user_contact"}
    assert drift["counts"]["table_removed"] == 0


def test_detect_tolerates_non_mapping_table_entries():
    baseline = _snapshot(tables={"t": ["bad"]})
    current = _snapshot(tables={"t": {"fields": ["id"], "row_count": 1}})
    drift = detect_lineage_drift(current, baseline)
    # 旧表字段按空集合处理，当前字段全部识别为新增。
    assert any(change["type"] == "field_added" for change in drift["changes"])


def test_detect_rejects_corrupt_snapshot():
    good = _snapshot()
    with pytest.raises(LineageSnapshotError):
        detect_lineage_drift(good, {"snapshot_version": 99,
                                    "tables": {}, "relations": []})
    with pytest.raises(LineageSnapshotError):
        detect_lineage_drift("broken", good)
