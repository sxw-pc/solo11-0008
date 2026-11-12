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

## 跨批次质量趋势

{% if report.trend -%}
{% if report.trend.status == "ok" -%}
- 基线：同契约指纹（`{{ report.trend.contract_fingerprint }}`）最近 {{ report.trend.baseline_tasks }} 次成功任务
- 对比指标 {{ report.trend.metrics_count }} 项；阈值：行数波动 ±{{ "%.0f"|format(report.trend.row_change_ratio * 100) }}%，比率增量 +{{ "%.2f"|format(report.trend.rate_increase * 100) }}pp
- 趋势对比仅作警示，不影响准入结论
{% if report.trend.deviations %}

| 指标 | 位置 | 基线值 | 本次值 | 变化 | 说明 |
| --- | --- | --- | --- | --- | --- |
{% for item in report.trend.deviations -%}
| {{ item.rule_label }} | {{ item.table }}{% if item.column %} / {{ item.column }}{% endif %} | {{ item.baseline_text }} | {{ item.current_text }} | {{ item.change_text }} | {{ item.message }} |
{% endfor %}
{%- else %}
未发现跨批次质量突变。
{%- endif %}
{%- else -%}
{{ report.trend.summary }}。趋势对比仅作警示，不影响准入结论。
{%- endif %}
{%- else -%}
本次任务未记录趋势对比数据。
{%- endif %}

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

## 修复建议

{% for suggestion in report.suggestions -%}
{{ loop.index }}. {{ suggestion }}
{% endfor %}

---
本报告由数包闸检 v{{ report.meta.tool_version }} 本地离线生成，无外部资源引用。
