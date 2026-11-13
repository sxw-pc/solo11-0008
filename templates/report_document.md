# 数包闸检 · 数据包准入校验报告

- **任务 ID**：{{ report.task.task_id }}
- **数据包**：{{ report.task.packet_name }}
- **总体结论**：{{ "通过" if report.overall_passed else "不通过" }}
- **校验项通过率**：{{ report.pass_rate }}%
- **工具版本**：{{ report.meta.tool_version }}
- **配置哈希**：{{ report.meta.config_hash }}
- **生成时间**：{{ report.meta.generated_at }}

## 任务信息

| 项目 | 内容 |
| --- | --- |
| 包大小 | {{ report.task.packet_size }} 字节 |
| 压缩格式 | {{ report.task.archive_type or "-" }} |
| 上传时间 | {{ report.task.uploaded_at }} |
| 校验耗时 | {{ "%.2f"|format(report.task.duration_seconds or 0) }} 秒 |
| 契约 | {{ report.task.contract_name or "-" }} |
| 血缘规则 | {{ report.task.lineage_name or "-" }} |

## 校验项概览

| 校验项 | 结果 | 错误数 | 说明 |
| --- | --- | --- | --- |
{% for check in report.checks -%}
| {{ check.name }} | {{ "通过" if check.passed else "不通过" }} | {{ check.error_count }} | {{ check.summary }} |
{% endfor %}

## 异常明细

{% if report.issues -%}
| 校验项 | 位置 | 代码 | 处置 | 说明 |
| --- | --- | --- | --- | --- |
{% for issue in report.issues -%}
| {{ issue.check }} | {{ issue.path or (issue.table or "-") }}{% if issue.field %} / {{ issue.field }}{% endif %}{% if issue.row %} / 行 {{ issue.row }}{% endif %} | {{ issue.code or "-" }} | {% if issue.exemption and issue.exemption.status == "exempted" %}已豁免（{{ issue.exemption.rule_id }}）{% elif issue.exemption and issue.exemption.status == "blocked_by_rule" %}规则拒绝{% else %}拦截{% endif %} | {{ issue.message }} |
{% endfor %}
{%- else -%}
未发现异常明细。
{%- endif %}

{% if report.exemption and report.exemption.enabled is defined -%}
## 分级豁免复核

- 规则快照指纹：`{{ report.exemption.ruleset_hash or "-" }}`
- 豁免放行：{{ report.exemption.exempted }} 项；规则拒绝：{{ report.exemption.denied }} 项；未匹配拦截：{{ report.exemption.blocked }} 项；过期拦截：{{ report.exemption.expired_blocked }} 项
- 冲突提示：{{ report.exemption.conflict_count }} 处（均按最严格优先级执行）
- 审计留痕：`{{ report.exemption.audit_path or "-" }}`（哈希链只追加，可独立校验完整性）

{% if report.exemption.exemption_records -%}
| 规则 ID | 分级 | 校验项 | 异常类型 | 位置 | 有效期 |
| --- | --- | --- | --- | --- | --- |
{% for record in report.exemption.exemption_records -%}
| {{ record.rule_id }} | {{ record.grade }} | {{ record.check }} | {{ record.anomaly_type }} | {{ record.table or "-" }}{% if record.field %} / {{ record.field }}{% endif %}{% if record.path %} / {{ record.path }}{% endif %} | {{ record.valid_from }} 至 {{ record.valid_to }} |
{% endfor %}
{%- endif %}
{% if report.exemption.conflicts -%}
冲突明细：
{% for conflict in report.exemption.conflicts -%}
- {{ conflict.message }}；候选规则：{{ conflict.candidate_rule_ids | join("、") }}
{% endfor %}
{%- endif %}
{%- endif %}

## 错误样例（已截断）

{% if report.samples -%}
| 表 / 字段 | 行号 | 值 | 规则 |
| --- | --- | --- | --- |
{% for sample in report.samples -%}
| {{ sample.table or "-" }}{% if sample.field %} / {{ sample.field }}{% endif %} | {{ sample.row if sample.row is not none else "-" }} | {{ sample.value if sample.value is not none else "-" }} | {{ sample.message or sample.rule or "-" }} |
{% endfor %}
{%- else -%}
本次校验未产生错误样例。
{%- endif %}

## 血缘链路

{% if report.lineage_graph.text -%}
```text
{{ report.lineage_graph.text }}
```

```mermaid
{{ report.lineage_graph.mermaid }}
```
{%- else -%}
本次任务未配置血缘关联规则。
{%- endif %}

## 修复建议

{% for suggestion in report.suggestions -%}
{{ loop.index }}. {{ suggestion }}
{% endfor %}

---
本报告由数包闸检 v{{ report.meta.tool_version }} 本地离线生成，无外部资源引用。
