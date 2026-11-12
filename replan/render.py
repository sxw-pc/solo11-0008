"""可归档 Markdown 摘要渲染与原子文件写入。

Markdown 与 JSON 一样由计划内容确定性生成：所有列表均按稳定键排序，
不含时间随机值；``generated_at`` 是唯一允许随运行变化的字段。
"""

import json
import os
from pathlib import Path
import tempfile

from . import MUST, SUGGESTED, REUSE

_LEVEL_LABELS = {
    MUST: "必须重检",
    SUGGESTED: "建议重检",
    REUSE: "可沿用",
}


def _escape(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(plan):
    """把计划字典渲染为可归档的 Markdown 摘要文本。"""
    lines = []
    inputs = plan["inputs"]
    lines.append("# 数据包列级变更影响与最小重检计划")
    lines.append("")
    lines.append("- 计划版本：`%s`" % plan["schema"])
    lines.append("- 生成时间：%s" % plan["generated_at"])
    lines.append("- 计划指纹：`%s`" % plan["plan_fingerprint"])
    mode_text = "整包全量重检（保守降级）" if plan["mode"] == "full_fallback" \
        else "定向最小重检"
    lines.append("- 计划模式：**%s**" % mode_text)
    lines.append("- 当前数据包：`%s`（%s，整包指纹 `%s`）"
                 % (_escape(plan["environment"]["current_packet_location"]),
                    plan["environment"]["current_packet_kind"],
                    inputs["current_packet"]["packet_fingerprint"]))
    prev = inputs["previous_packet"]
    prev_location = plan["environment"]["previous_packet_location"]
    if prev_location:
        lines.append("- 上一版数据包：`%s`（整包指纹 `%s`）"
                     % (_escape(prev_location),
                          prev["packet_fingerprint"] or "-"))
    else:
        lines.append("- 上一版数据包：未提供")
    lines.append("- 契约：%s（指纹 `%s`）"
                 % (_escape(inputs["contract"]["name"]),
                    inputs["contract"]["fingerprint"]))
    lines.append("- 血缘规则：%s（%d 条关系，指纹 `%s`）"
                 % (_escape(inputs["lineage"]["name"]),
                    inputs["lineage"]["relation_count"],
                    inputs["lineage"]["fingerprint"]))
    lines.append("")

    if plan["fallback_reasons"]:
        lines.append("## 一、降级原因（必须可读、可审计）")
        lines.append("")
        for reason in plan["fallback_reasons"]:
            lines.append("- **[%s]** %s"
                         % (reason["code"], _escape(reason["message"])))
        lines.append("")

    summary = plan["scope_summary"]
    lines.append("## 二、重检范围总览")
    lines.append("")
    lines.append("| 维度 | 必须重检 | 建议重检 | 可沿用 | 合计 |")
    lines.append("| --- | --- | --- | --- | --- |")
    lines.append("| 列 | %d | %d | %d | %d |"
                 % (summary["columns"][MUST], summary["columns"][SUGGESTED],
                    summary["columns"][REUSE], summary["columns_total"]))
    lines.append("| 规则 | %d | %d | %d | %d |"
                 % (summary["rules"][MUST], summary["rules"][SUGGESTED],
                    summary["rules"][REUSE], summary["rules_total"]))
    lines.append("| 血缘关系 | %d | %d | %d | %d |"
                 % (summary["relations"][MUST],
                    summary["relations"][SUGGESTED],
                    summary["relations"][REUSE],
                    summary["relations_total"]))
    lines.append("")
    lines.append("列级旧结论沿用比例：**%.2f%%**"
                 % (summary["reuse_ratio"] * 100))
    lines.append("")

    changes = plan["table_changes"]
    lines.append("## 三、表级与改名映射")
    lines.append("")
    lines.append("- 新增表：%s"
                 % (", ".join("`%s`" % name for name in changes["added"])
                    or "无"))
    lines.append("- 删除表：%s"
                 % (", ".join("`%s`" % name for name in changes["removed"])
                    or "无"))
    if any(changes["renames"].values()):
        lines.append("- 改名列映射：")
        for table in sorted(changes["renames"].keys()):
            for mapping in changes["renames"][table]:
                lines.append("  - `%s.%s` → `%s.%s`（%s映射）"
                             % (table, mapping["from"], table, mapping["to"],
                                "显式" if mapping["confidence"] == "explicit"
                                else "启发式"))
    else:
        lines.append("- 改名列映射：无")
    lines.append("")

    lines.append("## 四、表级决策与触发依据")
    lines.append("")
    lines.append("| 表 | 决策 | 必须重检列 | 建议重检列 | 可沿用列 | 已删除列 | 触发原因 |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for table in plan["tables"]:
        reason_text = "；".join(sorted(
            {"[%s] %s" % (reason["code"], reason["message"])
             for reason in table["reasons"]}))
        lines.append("| `%s` | %s | %s | %s | %s | %s | %s |"
                     % (_escape(table["table"]),
                        _LEVEL_LABELS[table["decision"]],
                        _escape(", ".join(table["must_columns"]) or "-"),
                        _escape(", ".join(table["suggested_columns"]) or "-"),
                        _escape(", ".join(table["reuse_columns"]) or "-"),
                        _escape(", ".join(table.get("removed_columns", []))
                                or "-"),
                        _escape(reason_text or "-")))
    lines.append("")

    lines.append("## 五、列级决策明细")
    lines.append("")
    lines.append("| 表 | 列 | 决策 | 事件 | 依据 |")
    lines.append("| --- | --- | --- | --- | --- |")
    for column in plan["columns"]:
        reason_text = "；".join(
            "[%s] %s" % (reason["code"], reason["message"])
            for reason in column["reasons"]) or "-"
        lines.append("| `%s` | `%s` | %s | %s | %s |"
                     % (_escape(column["table"]),
                        _escape(column["new_name"] or column["column"]),
                        _LEVEL_LABELS[column["decision"]],
                        _escape(", ".join(column["events"]) or "-"),
                        _escape(reason_text)))
    lines.append("")

    lines.append("## 六、规则重检决策")
    lines.append("")
    lines.append("| 规则 ID | 表.列 | 类型 | 决策 | 依据 |")
    lines.append("| --- | --- | --- | --- | --- |")
    for rule in plan["rules"]:
        reason_text = "；".join(reason["message"]
                                for reason in rule["reasons"])
        lines.append("| `%s` | `%s.%s` | %s | %s | %s |"
                     % (_escape(rule["rule_id"]),
                        _escape(rule["table"]), _escape(rule["column"]),
                        _escape(rule["kind"]),
                        _LEVEL_LABELS[rule["decision"]],
                        _escape(reason_text)))
    lines.append("")

    lines.append("## 七、血缘关系重检决策")
    lines.append("")
    lines.append("| 关系 | 左端 | 右端 | 决策 | 依据 |")
    lines.append("| --- | --- | --- | --- | --- |")
    for relation in plan["relations"]:
        reason_text = "；".join(reason["message"]
                                for reason in relation["reasons"])
        lines.append("| `%s` | `%s.%s` | `%s.%s` | %s | %s |"
                     % (_escape(relation["relation"]),
                        _escape(relation["left_table"]),
                        _escape(relation["left_column"]),
                        _escape(relation["right_table"]),
                        _escape(relation["right_column"]),
                        _LEVEL_LABELS[relation["decision"]],
                        _escape(reason_text)))
    lines.append("")

    lines.append("## 八、可沿用旧结论清单")
    lines.append("")
    evidence = plan["reuse_evidence"]
    if not (evidence["columns"] or evidence["rules"]
            or evidence["relations"]):
        lines.append("本次没有可沿用的旧结论。")
    else:
        if evidence["columns"]:
            lines.append("### 列")
            for item in evidence["columns"]:
                lines.append("- `%s.%s`：%s（指纹 `%s`）"
                             % (item["table"], item["column"], item["basis"],
                                item["new_fingerprint"]))
        if evidence["rules"]:
            lines.append("")
            lines.append("### 规则")
            for item in evidence["rules"]:
                lines.append("- `%s`：%s" % (item["rule_id"], item["basis"]))
        if evidence["relations"]:
            lines.append("")
            lines.append("### 血缘关系")
            for item in evidence["relations"]:
                lines.append("- `%s`：%s" % (item["relation"], item["basis"]))
    lines.append("")

    lines.append("## 九、可执行重检范围")
    lines.append("")
    executable = plan["recheck_plan"]
    lines.append("- 全量重检标记：`%s`" % executable["full_recheck"])
    lines.append("- 需重检规则：%s"
                 % (", ".join("`%s`" % rule_id
                              for rule_id in executable["rule_ids"]) or "无"))
    lines.append("- 需重检血缘关系：%s"
                 % (", ".join("`%s`" % name
                              for name in executable["relation_names"]) or "无"))
    lines.append("")
    return "\n".join(lines)


def canonical_json(plan):
    """生成确定性 JSON 文本（键排序、统一缩进、末尾换行）。"""
    return json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def atomic_write(path, content):
    """同目录临时文件 + os.replace 原子落盘，并发运行不会互相截断。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, tmp_name = tempfile.mkstemp(
        prefix=".replan-", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return str(target)
