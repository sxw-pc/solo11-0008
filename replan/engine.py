"""列级差异识别、引用传播与最小重检决策引擎。

引擎只消费 :mod:`replan.packet` / :mod:`replan.contract` /
:mod:`replan.archive` 产出的只读模型，不接触任何 gateway 校验代码。

决策分为三级：

* ``must_recheck``      —— 旧结论确定失效，必须重检；
* ``suggested_recheck`` —— 旧结论大概率有效但存在语义风险，建议重检；
* ``reuse``             —— 列级指纹与规则指纹均未变，旧结论可沿用。

任何引用关系变化（被外键引用的键变化、改名、删除）都沿血缘邻接表传播，
而不是只比较表名与文件哈希。
"""

from collections import deque

from . import MUST, SUGGESTED, REUSE, SEVERITY_RANK
from .contract import is_narrowing
from .errors import FallbackError

COLUMN_EVENT_CODES = {
    "added_column": "added_column",
    "removed_column": "removed_column",
    "renamed_column": "renamed_column",
    "type_narrowed": "type_narrowed",
    "type_widened": "type_widened",
    "type_changed": "type_changed",
    "nullable_tightened": "nullable_tightened",
    "nullable_relaxed": "nullable_relaxed",
    "constraint_changed": "constraint_changed",
    "data_changed": "data_changed",
    "data_unchanged": "data_unchanged",
}

_DECISION_LIST_KEY = {
    MUST: "must_columns",
    SUGGESTED: "suggested_columns",
    REUSE: "reuse_columns",
}


class NodeState:
    """单个 (表, 列) 节点的累计决策状态。"""

    def __init__(self, table, column):
        self.table = table
        self.column = column
        self.level = REUSE
        self.reasons = []
        self.events = []
        self.old_name = None
        self.new_name = None
        self.old_fingerprint = None
        self.new_fingerprint = None
        self.reused_from = None

    def escalate(self, level, code, message, extra=None):
        if SEVERITY_RANK[level] > SEVERITY_RANK[self.level]:
            self.level = level
        reason = {"code": code, "message": message}
        if extra:
            reason.update(extra)
        if reason not in self.reasons:
            self.reasons.append(reason)

    def to_dict(self):
        return {
            "table": self.table,
            "column": self.column,
            "decision": self.level,
            "old_name": self.old_name,
            "new_name": self.new_name,
            "old_fingerprint": self.old_fingerprint,
            "new_fingerprint": self.new_fingerprint,
            "reused_from": self.reused_from,
            "events": sorted(self.events),
            "reasons": self.reasons,
        }


class PlannerEngine:
    """持有两侧数据包、契约、血缘与存档，输出节点/规则/关系决策。"""

    def __init__(self, old_packet, new_packet, contract, lineage,
                 archive_info, fallback_reasons=None):
        self.old_packet = old_packet
        self.new_packet = new_packet
        self.contract = contract
        self.lineage = lineage
        self.archive_info = archive_info
        self.fallback_reasons = list(fallback_reasons or [])
        self.nodes = {}
        self.rule_decisions = []
        self.relation_decisions = []
        self.rename_map = {}      # table -> [(old, new)]
        self.heuristic_renames = {}
        self.added_tables = []
        self.removed_tables = []

    # ------------------------------------------------------------------ #
    # 全量降级
    # ------------------------------------------------------------------ #
    def build_full_fallback(self):
        """生成整包全量重检计划（所有表/列/规则/关系均为 must_recheck）。"""
        for table_name in sorted(self.new_packet.tables.keys()):
            scan = self.new_packet.tables[table_name]
            for column in scan.columns:
                state = self._node(table_name, column)
                state.old_name = None
                state.new_fingerprint = scan.fingerprints[column].sha256
                state.escalate(MUST, "full_fallback",
                               self._fallback_message(),
                               {"fallback_codes": self._fallback_codes()})
                state.events.append("full_fallback")
        self._decide_rules_full()
        self._decide_relations_full()
        return self._snapshot(full=True)

    def _fallback_codes(self):
        return sorted({reason["code"] for reason in self.fallback_reasons})

    def _fallback_message(self):
        return "保守退化为整包全量重检：" + "；".join(
            reason["message"] for reason in self.fallback_reasons)

    # ------------------------------------------------------------------ #
    # 定向分析
    # ------------------------------------------------------------------ #
    def build_targeted(self):
        self._detect_renames()
        self._diff_tables_and_columns()
        self._propagate_lineage()
        self._decide_rules_targeted()
        self._decide_relations_targeted()
        return self._snapshot(full=False)

    def _node(self, table, column):
        key = (table, column)
        state = self.nodes.get(key)
        if state is None:
            state = NodeState(table, column)
            self.nodes[key] = state
        return state

    # ---------------- 改名列映射 ---------------- #
    def _detect_renames(self):
        explicit = self.contract.get("renames") or {}
        archived_tables = self.archive_info["tables"]
        for table_name in sorted(self.new_packet.tables.keys()):
            new_scan = self.new_packet.tables[table_name]
            old_scan = self.old_packet.tables.get(table_name) if self.old_packet \
                else None
            archived = archived_tables.get(table_name, {})
            archived_columns = set(archived.get("columns", {}).keys())
            new_columns = set(new_scan.columns)
            pairs = []
            # 1) 契约显式改名映射（高置信）。
            for old_name, new_name in explicit.get(table_name, []):
                if old_name in archived_columns and new_name in new_columns:
                    pairs.append((old_name, new_name, "explicit"))
            matched_new = {new for _, new, _ in pairs}
            matched_old = {old for old, _, _ in pairs}
            # 2) 指纹相同且列名不同的启发式映射（低置信，仅建议级）。
            if old_scan is not None:
                old_only = [c for c in old_scan.columns
                            if c in archived_columns and c not in new_columns
                            and c not in matched_old]
                new_only = [c for c in new_scan.columns
                            if c not in archived_columns and c not in matched_new]
                for old_name in sorted(old_only):
                    old_fp = old_scan.fingerprints[old_name].sha256
                    for new_name in sorted(new_only):
                        new_fp = new_scan.fingerprints[new_name].sha256
                        if old_fp == new_fp and new_name not in matched_new:
                            pairs.append((old_name, new_name, "heuristic"))
                            matched_new.add(new_name)
                            matched_old.add(old_name)
                            self.heuristic_renames.setdefault(table_name, []).append(
                                (old_name, new_name))
                            break
            self.rename_map[table_name] = pairs

    def _renamed_old_to_new(self, table):
        return {old: (new, confidence)
                for old, new, confidence in self.rename_map.get(table, [])}

    # ---------------- 表/列差异 ---------------- #
    def _diff_tables_and_columns(self):
        archived_tables = self.archive_info["tables"]
        old_tables = self.old_packet.tables if self.old_packet else {}

        # 新增表 / 删除表。
        new_table_names = set(self.new_packet.tables.keys())
        old_table_names = set(archived_tables.keys())
        self.added_tables = sorted(new_table_names - old_table_names)
        self.removed_tables = sorted(old_table_names - new_table_names)

        for table_name in self.added_tables:
            scan = self.new_packet.tables[table_name]
            for column in scan.columns:
                state = self._node(table_name, column)
                state.new_fingerprint = scan.fingerprints[column].sha256
                state.events.append("added_table")
                state.escalate(MUST, "added_table",
                               "新增表 %s：无任何旧结论可沿用，必须全表重检"
                               % table_name, {"table": table_name})

        for table_name in sorted(new_table_names & old_table_names):
            self._diff_one_table(
                table_name,
                old_tables.get(table_name),
                self.new_packet.tables[table_name],
                archived_tables[table_name])

    def _diff_one_table(self, table_name, old_scan, new_scan, archived_table):
        archived_columns = archived_table["columns"]
        rename_pairs = self._renamed_old_to_new(table_name)
        new_columns = set(new_scan.columns)
        handled_new = set()
        contract_fields = self.contract["tables"].get(table_name, {}).get("fields", {})
        renamed_olds = set(rename_pairs.keys())

        # 1) 改名列（显式 + 启发式）。
        for old_name, (new_name, confidence) in sorted(rename_pairs.items()):
            handled_new.add(new_name)
            state = self._node(table_name, new_name)
            state.old_name = old_name
            state.new_name = new_name
            state.old_fingerprint = archived_columns[old_name]["sha256"]
            state.new_fingerprint = new_scan.fingerprints[new_name].sha256
            state.events.append("renamed_column")
            if confidence == "explicit":
                state.escalate(
                    MUST, "renamed_column",
                    "列改名 %s.%s -> %s（契约显式映射）：名称绑定的规则与"
                    "引用关系必须按新名重新解析"
                    % (table_name, old_name, new_name),
                    {"table": table_name, "old_column": old_name,
                     "new_column": new_name, "mapping": "explicit"})
            else:
                state.escalate(
                    SUGGESTED, "renamed_column",
                    "列 %s.%s 与 %s 列级指纹一致，疑似改名（启发式匹配，"
                    "无契约映射）：建议重检确认语义"
                    % (table_name, new_name, old_name),
                    {"table": table_name, "old_column": old_name,
                     "new_column": new_name, "mapping": "heuristic"})
            # 改名同时若类型/可空性变化，叠加对应事件。
            self._apply_contract_deltas(table_name, old_name, new_name, state,
                                        contract_fields)
            self._apply_data_delta(table_name, old_name, new_name, state,
                                   archived_table, new_scan, renamed=True)

        # 2) 删除列（节点以旧列名保留，标记 removed，供规则/传播决策识别）。
        for old_name in sorted(archived_columns.keys()):
            if old_name in new_columns or old_name in renamed_olds:
                continue
            state = self._node(table_name, old_name)
            state.old_name = old_name
            state.old_fingerprint = archived_columns[old_name]["sha256"]
            state.events.append("removed_column")
            state.escalate(
                MUST, "removed_column",
                "列被删除 %s.%s：绑定该列的规则与引用关系全部失效，必须重检"
                % (table_name, old_name),
                {"table": table_name, "old_column": old_name})

        # 3) 新增列（含可空性区分）。
        carried_names = set(archived_columns.keys()) | set(
            new for old, (new, _) in rename_pairs.items())
        for new_name in sorted(new_columns - carried_names):
            state = self._node(table_name, new_name)
            state.new_name = new_name
            state.new_fingerprint = new_scan.fingerprints[new_name].sha256
            state.events.append("added_column")
            field_spec = contract_fields.get(new_name, {})
            nullable = field_spec.get("nullable", True)
            if nullable:
                state.escalate(
                    MUST, "added_column",
                    "新增可空列 %s.%s：该列本身无旧结论，必须执行列级重检；"
                    "同表未改列的旧结论仍可沿用"
                    % (table_name, new_name),
                    {"table": table_name, "new_column": new_name,
                     "nullable": True})
            else:
                state.escalate(
                    MUST, "added_column",
                    "新增非空列 %s.%s：全表行结构发生变化，必须重检该表"
                    % (table_name, new_name),
                    {"table": table_name, "new_column": new_name,
                     "nullable": False})

        # 4) 同名保留列：契约差异 + 数据指纹差异。
        retained = (new_columns & set(archived_columns.keys())) - handled_new
        for name in sorted(retained):
            state = self._node(table_name, name)
            state.old_fingerprint = archived_columns[name]["sha256"]
            state.new_fingerprint = new_scan.fingerprints[name].sha256
            self._apply_contract_deltas(table_name, name, name, state,
                                        contract_fields)
            self._apply_data_delta(table_name, name, name, state,
                                   archived_table, new_scan, renamed=False)
            if not state.events:
                state.events.append("data_unchanged")

    def _apply_contract_deltas(self, table_name, old_name, new_name, state,
                               contract_fields):
        """比较契约字段定义（类型收窄/放宽、可空性、约束）。"""
        new_spec = contract_fields.get(new_name)
        if new_spec is None:
            state.escalate(
                MUST, "contract_field_missing",
                "当前契约缺少列定义 %s.%s，规则引用无法可靠解析"
                % (table_name, new_name),
                {"table": table_name, "column": new_name})
            raise FallbackError(
                "当前契约无法解析列 %s.%s，保守执行整包全量重检"
                % (table_name, new_name),
                "rule_reference_unresolved")
        # 旧契约字段定义随旧存档保存（若有）；否则只比较数据。
        old_contract = (self.archive_info["data"] or {}).get("contract")
        old_fields = ((old_contract or {}).get("tables", {})
                      .get(table_name, {}).get("fields", {}))
        old_spec = old_fields.get(old_name)
        if not old_spec:
            return
        if old_spec.get("type") != new_spec["type"]:
            if is_narrowing(old_spec.get("type", "string"), new_spec["type"]):
                state.events.append("type_narrowed")
                state.escalate(
                    MUST, "type_narrowed",
                    "类型收窄 %s.%s: %s -> %s：旧数据可能不再满足新值域，"
                    "必须重检并沿外键传播"
                    % (table_name, new_name, old_spec.get("type"),
                       new_spec["type"]),
                    {"table": table_name, "column": new_name,
                     "old_type": old_spec.get("type"),
                     "new_type": new_spec["type"]})
            else:
                state.events.append("type_widened")
                state.escalate(
                    SUGGESTED, "type_widened",
                    "类型放宽 %s.%s: %s -> %s：旧结论大概率有效，建议重检确认"
                    % (table_name, new_name, old_spec.get("type"),
                       new_spec["type"]),
                    {"table": table_name, "column": new_name,
                     "old_type": old_spec.get("type"),
                     "new_type": new_spec["type"]})
        old_nullable = bool(old_spec.get("nullable", True))
        if old_nullable != new_spec["nullable"]:
            if new_spec["nullable"]:
                state.events.append("nullable_relaxed")
                state.escalate(
                    SUGGESTED, "nullable_relaxed",
                    "可空性放宽 %s.%s: 非空 -> 可空，建议重检空值率类规则"
                    % (table_name, new_name),
                    {"table": table_name, "column": new_name})
            else:
                state.events.append("nullable_tightened")
                state.escalate(
                    MUST, "nullable_tightened",
                    "可空性收紧 %s.%s: 可空 -> 非空，必须重检存量空值"
                    % (table_name, new_name),
                    {"table": table_name, "column": new_name})
        old_constraints = old_spec.get("constraints") or {}
        if old_constraints != new_spec["constraints"]:
            state.events.append("constraint_changed")
            state.escalate(
                MUST, "constraint_changed",
                "字段约束变化 %s.%s（enum/pattern/长度/范围等），"
                "绑定规则的旧结论失效" % (table_name, new_name),
                {"table": table_name, "column": new_name,
                 "old_constraints": old_constraints,
                 "new_constraints": new_spec["constraints"]})

    def _apply_data_delta(self, table_name, old_name, new_name, state,
                          archived_table, new_scan, renamed):
        old_fp = archived_table["columns"][old_name]["sha256"]
        new_fp = new_scan.fingerprints[new_name].sha256
        old_row_count = archived_table["columns"][old_name]["row_count"]
        if old_fp != new_fp:
            state.events.append("data_changed")
            level = SUGGESTED if renamed else MUST
            state.escalate(
                level, "data_changed",
                "列级指纹变化 %s.%s（旧列 %s，行数 %s -> %d）：数据内容已变更，"
                "绑定规则需要重检"
                % (table_name, new_name, old_name, old_row_count,
                   new_scan.row_count),
                {"table": table_name, "column": new_name,
                 "old_column": old_name})
            state.reused_from = None
        elif state.level == REUSE:
            # 仅当该节点没有任何更高等级的变更时，才登记旧结论沿用来源。
            state.events.append("data_unchanged")
            state.reused_from = (table_name, old_name)

    # ---------------- 血缘传播 ---------------- #
    def _propagate_lineage(self):
        if not self.lineage:
            return
        adjacency = self.lineage["adjacency"]
        # 初始受影响节点：所有非 reuse 节点（含删除列）且参与血缘的节点。
        queue = deque()
        seen = set()
        for (table, column), state in self.nodes.items():
            if state.level != REUSE and (table, column) in adjacency:
                queue.append(((table, column), 0))
                seen.add((table, column))
        while queue:
            (table, column), depth = queue.popleft()
            for (neighbor_table, neighbor_column), relation_name in sorted(
                    adjacency.get((table, column), [])):
                neighbor = self._node(neighbor_table, neighbor_column)
                neighbor.events.append("lineage_propagated")
                neighbor.escalate(
                    MUST, "lineage_propagated",
                    "被外键引用的键发生变化：%s.%s 经血缘关系 %s 传播至 %s.%s，"
                    "引用完整性必须重检"
                    % (table, column, relation_name,
                       neighbor_table, neighbor_column),
                    {"table": neighbor_table, "column": neighbor_column,
                     "via_relation": relation_name,
                     "upstream_table": table,
                     "upstream_column": column, "depth": depth + 1})
                if (neighbor_table, neighbor_column) not in seen:
                    seen.add((neighbor_table, neighbor_column))
                    queue.append(((neighbor_table, neighbor_column), depth + 1))

    # ---------------- 规则决策 ---------------- #
    def _decide_rules_full(self):
        self.rule_decisions = []
        for rule in self.contract["rules"]:
            self.rule_decisions.append(self._rule_entry(
                rule, MUST, "full_fallback", self._fallback_message(),
                self._fallback_codes()))

    def _decide_rules_targeted(self):
        self.rule_decisions = []
        old_rules = {rule["id"]: rule for rule in self.archive_info["rules"]}
        for rule in self.contract["rules"]:
            table, column = rule["table"], rule["column"]
            target_state, target_old_name = self._resolve_rule_target(
                table, column)
            # 规则目标列已被删除。
            if target_state is not None and \
                    "removed_column" in target_state.events:
                self.rule_decisions.append(self._rule_entry(
                    rule, MUST, "rule_target_removed",
                    "规则目标列 %s.%s 已删除，规则必须重新定义/重检"
                    % (table, target_old_name or column)))
                continue
            if target_state is None:
                self.rule_decisions.append(self._rule_entry(
                    rule, MUST, "rule_target_unresolved",
                    "规则目标列 %s.%s 在当前数据包中不存在，必须重检"
                    % (table, column)))
                continue
            old_rule = old_rules.get(rule["id"])
            if old_rule is None:
                self.rule_decisions.append(self._rule_entry(
                    rule, MUST, "rule_added",
                    "新增规则 %s：无旧结论可沿用" % rule["id"]))
                continue
            if old_rule.get("fingerprint") != rule["fingerprint"]:
                self.rule_decisions.append(self._rule_entry(
                    rule, MUST, "rule_definition_changed",
                    "规则定义发生变化 %s，旧结论失效" % rule["id"]))
                continue
            if target_old_name and target_old_name != column:
                self.rule_decisions.append(self._rule_entry(
                    rule, MUST, "rule_target_renamed",
                    "规则目标列由 %s.%s 改名为 %s，名称绑定必须重新解析"
                    % (table, target_old_name, column)))
                continue
            if target_state.level == REUSE:
                self.rule_decisions.append(self._rule_entry(
                    rule, REUSE, "rule_reusable",
                    "目标列指纹与规则定义均未变化，旧抽检结论可沿用",
                    reused_from=old_rule.get("id", rule["id"])))
            elif target_state.level == SUGGESTED:
                self.rule_decisions.append(self._rule_entry(
                    rule, SUGGESTED, "rule_target_suggested",
                    "目标列 %s.%s 存在建议级变更，建议重检该规则"
                    % (table, column)))
            else:
                codes = [reason["code"] for reason in target_state.reasons]
                self.rule_decisions.append(self._rule_entry(
                    rule, MUST, "rule_target_changed",
                    "目标列 %s.%s 发生必须重检的变更（%s）"
                    % (table, column, ",".join(sorted(set(codes))))))

    def _resolve_rule_target(self, table, column):
        """把规则绑定的当前列名解析到引擎节点，兼容改名映射。"""
        direct = self.nodes.get((table, column))
        if direct is not None:
            return direct, None
        for old_name, (new_name, _) in self._renamed_old_to_new(table).items():
            if old_name == column:
                return self.nodes.get((table, new_name)), old_name
        return None, None

    def _rule_entry(self, rule, level, code, message, codes=None,
                    reused_from=None):
        entry = {
            "rule_id": rule["id"],
            "table": rule["table"],
            "column": rule["column"],
            "kind": rule["kind"],
            "decision": level,
            "reasons": [{"code": code, "message": message}],
        }
        if codes:
            entry["reasons"][0]["fallback_codes"] = codes
        if reused_from:
            entry["reused_from"] = reused_from
        return entry

    # ---------------- 血缘关系决策 ---------------- #
    def _decide_relations_full(self):
        self.relation_decisions = []
        for edge in self.lineage["edges"] if self.lineage else []:
            self.relation_decisions.append({
                "relation": edge["name"],
                "left_table": edge["left_table"],
                "left_column": edge["left_column"],
                "right_table": edge["right_table"],
                "right_column": edge["right_column"],
                "decision": MUST,
                "reasons": [{"code": "full_fallback",
                             "message": self._fallback_message(),
                             "fallback_codes": self._fallback_codes()}],
            })

    def _decide_relations_targeted(self):
        self.relation_decisions = []
        old_edges = self._old_lineage_edges()
        for edge in self.lineage["edges"]:
            left_state = self.nodes.get((edge["left_table"], edge["left_column"]))
            right_state = self.nodes.get((edge["right_table"],
                                          edge["right_column"]))
            old_edge = old_edges.get(edge["name"])
            if old_edge is None or old_edge != edge["fingerprint"]:
                level, code, message = MUST, "relation_definition_changed", \
                    "血缘关系 %s 定义发生变化或为新增关系，必须重检引用完整性" \
                    % edge["name"]
            elif (left_state and left_state.level != REUSE) or \
                    (right_state and right_state.level != REUSE):
                level, code, message = MUST, "relation_endpoint_changed", \
                    "血缘关系 %s 的端点列发生变更，引用完整性必须重检" \
                    % edge["name"]
            else:
                level, code, message = REUSE, "relation_reusable", \
                    "血缘关系 %s 两端列指纹均未变化，旧血缘结论可沿用" \
                    % edge["name"]
            self.relation_decisions.append({
                "relation": edge["name"],
                "left_table": edge["left_table"],
                "left_column": edge["left_column"],
                "right_table": edge["right_table"],
                "right_column": edge["right_column"],
                "decision": level,
                "reasons": [{"code": code, "message": message}],
            })

    def _old_lineage_edges(self):
        data = self.archive_info["data"] or {}
        lineage = data.get("lineage") or {}
        edges = lineage.get("edges") or []
        return {edge["name"]: edge.get("fingerprint")
                for edge in edges if isinstance(edge, dict) and "name" in edge}

    # ---------------- 快照 ---------------- #
    def _snapshot(self, full):
        columns = [state.to_dict()
                   for _, state in sorted(self.nodes.items())]
        table_rollup = self._rollup_tables(columns)
        return {
            "mode": "full_fallback" if full else "targeted",
            "fallback_reasons": self.fallback_reasons,
            "added_tables": getattr(self, "added_tables", []),
            "removed_tables": getattr(self, "removed_tables", []),
            "rename_map": {
                table: [{"from": old, "to": new, "confidence": confidence}
                        for old, new, confidence in sorted(pairs)]
                for table, pairs in sorted(self.rename_map.items())
            },
            "tables": table_rollup,
            "columns": columns,
            "rules": sorted(self.rule_decisions,
                            key=lambda item: item["rule_id"]),
            "relations": sorted(self.relation_decisions,
                                key=lambda item: item["relation"]),
        }

    def _rollup_tables(self, columns):
        rollup = {}
        for entry in columns:
            table = entry["table"]
            bucket = rollup.setdefault(table, {
                "table": table,
                "decision": REUSE,
                "must_columns": [],
                "suggested_columns": [],
                "reuse_columns": [],
                "removed_columns": [],
                "reasons": [],
            })
            if "removed_column" in entry["events"]:
                bucket["removed_columns"].append(
                    entry["old_name"] or entry["column"])
                continue
            if SEVERITY_RANK[entry["decision"]] > \
                    SEVERITY_RANK[bucket["decision"]]:
                bucket["decision"] = entry["decision"]
            key = _DECISION_LIST_KEY[entry["decision"]]
            bucket[key].append(entry["new_name"] or entry["column"])
            for reason in entry["reasons"]:
                if reason not in bucket["reasons"]:
                    bucket["reasons"].append(reason)
        # 删除表也要出现在表级视图中。
        for table in getattr(self, "removed_tables", []):
            rollup[table] = {
                "table": table,
                "decision": MUST,
                "must_columns": [],
                "suggested_columns": [],
                "reuse_columns": [],
                "removed_columns": [],
                "reasons": [{"code": "removed_table",
                             "message": "表 %s 已从当前数据包删除，"
                                        "其全部旧结论失效" % table}],
            }
        result = []
        for table in sorted(rollup.keys()):
            bucket = rollup[table]
            for key in ("must_columns", "suggested_columns", "reuse_columns",
                        "removed_columns"):
                bucket[key] = sorted(bucket[key])
            bucket["reasons"] = sorted(
                bucket["reasons"],
                key=lambda reason: (reason["code"], reason["message"]))
            result.append(bucket)
        return result
