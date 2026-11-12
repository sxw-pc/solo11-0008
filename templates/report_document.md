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
| 校验项 | 位置 | 代码 | 说明 |
| --- | --- | --- | --- |
{% for issue in report.issues -%}
| {{ issue.check }} | {{ issue.path or (issue.table or "-") }}{% if issue.field %} / {{ issue.field }}{% endif %}{% if issue.row %} / 行 {{ issue.row }}{% endif %} | {{ issue.code or "-" }} | {{ issue.message }} |
{% endfor %}
{%- else -%}
未发现异常明细。
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

## 血缘版本漂移

{% if report.lineage_drift and report.lineage_drift.enabled -%}
- **业务契约**：{{ report.lineage_drift.lineage_key }}
- **漂移结论**：{{ report.lineage_drift.summary }}
{% if report.lineage_drift.baseline -%}
- **比对基线**：v{{ report.lineage_drift.baseline.version }}（{{ report.lineage_drift.baseline.packet_name }}，{{ report.lineage_drift.baseline.created_at }}）
- **当前版本**：v{{ report.lineage_drift.current.version }}
{%- endif %}
{% if report.lineage_drift.degraded -%}
> ⚠ {{ report.lineage_drift.error.message }}，本报告仍完整保留当前数据包的血缘校验结果。
{%- endif %}
{% if report.lineage_drift.changes -%}

| 漂移类型 | 对象 | 说明 | 变更前 | 变更后 |
| --- | --- | --- | --- | --- |
{% for change in report.lineage_drift.changes -%}
| {{ change.type }} | {{ change.target }} | {{ change.detail }} | {{ change.before | tojson if change.before is not none else "-" }} | {{ change.after | tojson if change.after is not none else "-" }} |
{% endfor %}
{%- endif %}
{%- else -%}
本次任务未启用跨版本血缘漂移检测。
{%- endif %}

## 修复建议

{% for suggestion in report.suggestions -%}
{{ loop.index }}. {{ suggestion }}
{% endfor %}

---
本报告由数包闸检 v{{ report.meta.tool_version }} 本地离线生成，无外部资源引用。
