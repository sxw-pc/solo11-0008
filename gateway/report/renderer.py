"""Markdown、HTML、JSON 三格式报告构建与落盘。

HTML 报告使用内联样式，不引用任何 CDN、字体、脚本或图片；离线浏览器可
直接打开。报告只保留必要错误样例与截断值，避免扩散全量业务数据。
"""

from datetime import datetime
from pathlib import Path
import json
import os
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..config import PROJECT_ROOT, AppConfig

TEMPLATE_DIR = PROJECT_ROOT / "templates"
_SUGGESTIONS = {
    "path_traversal": "移除压缩包中的绝对路径或 ../ 路径成员后重新打包。",
    "zip_bomb": "检查超高压缩比文件，拆分或压缩业务数据后重新提交。",
    "archive_error": "确认压缩包为完整 zip/tar.gz，并在根目录提供 manifest.yaml。",
    "hash_mismatch": "重新生成 manifest 中的 MD5/SHA256，确认文件未被二次修改。",
    "missing_file": "补齐 manifest 声明但缺失的文件，或修正声明路径。",
    "redundant_file": "删除未声明的冗余文件，或将合规文件加入白名单配置。",
    "dangerous_file": "移除 exe/sh/py 等高危文件，业务数据包不得携带可执行内容。",
    "package_hash_mismatch": "核对上传包来源，重新计算并填写正确的整包哈希。",
    "required": "补齐必填字段，或将契约要求调整为与上游一致。",
    "unexpected_field": "删除契约外字段，或在契约中补充其定义。",
    "type": "统一上游数据类型，确保与契约 type 声明一致。",
    "enum": "将枚举字段值修正为契约允许的取值集合。",
    "maxLength": "截断或修正超长字符串，使其满足长度限制。",
    "table_missing": "在 manifest.tables 中声明契约表，并确认物理文件已打包。",
    "orphan_record": "核对孤立记录的外键来源，在维表中补齐被引用主键。",
    "reference_missing": "补齐空外键，或确认该关联允许空值。",
    "cardinality_error": "按关联基数去重，或修正血缘关系类型声明。",
    "field_missing": "补齐关联字段或修正 manifest/规则中的字段映射。",
    "null_rate": "提升字段填充率，或在规则中调整合理的空值阈值。",
    "duplicate_rate": "按业务主键去重，并排查上游重复下发。",
}
_DEFAULT_SUGGESTION = "根据错误明细修正数据包后重新上传校验。"


def _check_error_count(result: Dict[str, Any]) -> int:
    """估算单项校验的错误数量，用于报告概览。"""
    if result.get("key") == "schema":
        return sum(int(item.get("error_rows", 0)) for item in result.get("tables", []))
    if result.get("key") == "lineage":
        return sum(max(1, len(item.get("errors", [])))
                   for item in result.get("relations", []) if not item.get("passed"))
    if result.get("key") == "anomaly":
        return sum(int(item.get("failed_rules", 0)) for item in result.get("fields", []))
    return len(result.get("errors", []))


def _collect_issues(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把各校验项的错误归一化为报告问题列表。"""
    issues: List[Dict[str, Any]] = []
    for result in results:
        check = result.get("name") or result.get("key")
        if result.get("key") == "schema":
            for item in result.get("errors", []):
                issues.append({**item, "check": check})
        elif result.get("key") == "lineage":
            for relation in result.get("relations", []):
                for error in relation.get("errors", []):
                    issues.append({
                        "check": check, "code": error.get("code"),
                        "message": "%s: %s" % (relation.get("name"), error.get("message")),
                        "relation": relation.get("name"),
                        "table": relation.get("left_table"),
                        "field": relation.get("left_field"),
                    })
        elif result.get("key") == "anomaly":
            for field in result.get("fields", []):
                for rule in field.get("rules", []):
                    if not rule.get("passed"):
                        issues.append({
                            "check": check, "code": rule.get("rule"),
                            "table": field.get("table"), "field": field.get("field"),
                            "message": rule.get("error") or (
                                "异常率 %.2f%% / 阈值 %.2f%%" % (
                                    float(rule.get("rate", 0)) * 100,
                                    float(rule.get("threshold", 0)) * 100)),
                        })
        else:
            for error in result.get("errors", []):
                issues.append({**error, "check": check})
    # 去重并限制报告问题数量，避免报告体积失控。
    unique = []
    seen = set()
    for item in issues:
        marker = (item.get("check"), item.get("code"), item.get("table"),
                  item.get("field"), item.get("path"), item.get("row"),
                  item.get("message"))
        if marker not in seen:
            seen.add(marker)
            unique.append(item)
    return unique[:100]


def build_report_context(task: Dict[str, Any], results: List[Dict[str, Any]],
                         config: AppConfig, generated_at: Optional[str] = None) -> Dict[str, Any]:
    """组装独立报告所需的上下文。

    Args:
        task: 任务元数据。
        results: 各校验模块的统一结果。
        config: 用于补充配置哈希。
        generated_at: 可选生成时间，测试可注入固定值。
    Returns:
        可直接传给 Jinja2、也可序列化为 JSON 的字典。
    """
    checks = []
    for result in results:
        checks.append({
            "key": result.get("key"), "name": result.get("name"),
            "passed": bool(result.get("passed")),
            "summary": result.get("summary", ""),
            "error_count": _check_error_count(result),
        })
    passed_count = sum(1 for item in checks if item["passed"])
    total = len(checks)
    issues = _collect_issues(results)
    codes = {str(item.get("code")) for item in issues if item.get("code")}
    suggestions = []
    for code in sorted(codes):
        suggestion = _SUGGESTIONS.get(code)
        if suggestion and suggestion not in suggestions:
            suggestions.append(suggestion)
    if not suggestions:
        suggestions.append("本次校验未发现阻断性问题，可按现网变更流程执行准入。")
    lineage = next((item for item in results if item.get("key") == "lineage"), {})
    samples = []
    for result in results:
        samples.extend(result.get("samples", []))
    # 以任务最终状态为唯一结论来源，避免历史、详情与报告各自推算而分叉。
    # 旧任务没有写入 config_hash 时再退回当前配置指纹。
    config_hash = str(task.get("config_hash") or config.fingerprint())
    return {
        "meta": {
            "tool": "数包闸检", "tool_version": __version__,
            "generated_at": generated_at or datetime.now().isoformat(timespec="seconds"),
            "config_hash": config_hash,
        },
        "task": task,
        "status": str(task.get("status") or ("passed" if task.get("passed") else "failed")),
        "checks": checks,
        "passed_checks": passed_count,
        "total_checks": total,
        "pass_rate": round(passed_count / total * 100, 2) if total else 0.0,
        "overall_passed": bool(task.get("passed")),
        "issues": issues,
        "samples": samples[:50],
        "suggestions": suggestions,
        "lineage_graph": lineage.get("graph", {}),
    }


def _environment() -> Environment:
    """创建本地 Jinja2 环境，HTML 开启自动转义。"""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _safe_task_id(task_id: str) -> str:
    """仅允许字母数字与短横线，避免报告路径穿越。"""
    cleaned = "".join(char for char in str(task_id) if char.isalnum() or char in "-_")
    if not cleaned or cleaned != str(task_id):
        raise ValueError("非法任务 ID")
    return cleaned


def _report_paths(config: AppConfig, safe_id: str) -> Dict[str, Path]:
    """返回三种报告的目标路径。"""
    return {
        "md": config.reports_dir / (safe_id + ".md"),
        "html": config.reports_dir / (safe_id + ".html"),
        "json": config.reports_dir / (safe_id + ".json"),
    }


def remove_reports(config: AppConfig, task_id: str) -> None:
    """尽力删除任务的三种报告文件及写入临时文件。

    任务 ID 非法时不做任何操作，避免误删报告目录之外的路径。重复调用安全。
    """
    try:
        safe_id = _safe_task_id(task_id)
    except ValueError:
        return
    candidates = list(_report_paths(config, safe_id).values())
    candidates.extend(path.with_name(path.name + ".tmp")
                      for path in _report_paths(config, safe_id).values())
    for path in candidates:
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            continue


def render_reports(report: Dict[str, Any], config: AppConfig, task_id: str) -> Dict[str, str]:
    """渲染三种报告并原子写入本地 reports 目录。

    三种格式全部渲染成功后才替换目标文件；任一步失败都会清理本次生成的
    临时文件，避免留下可下载的半成品。

    Returns:
        ``{"md": 路径, "html": 路径, "json": 路径}``。
    Raises:
        ValueError: 任务 ID 非法。
        OSError: 报告写入失败。
    """
    safe_id = _safe_task_id(task_id)
    env = _environment()
    html = env.get_template("report_document.html").render(report=report)
    markdown = env.get_template("report_document.md").render(report=report)
    json_text = json.dumps(report, ensure_ascii=False, indent=2, default=str)
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    paths = _report_paths(config, safe_id)
    temp_paths = {key: path.with_name(path.name + ".tmp")
                  for key, path in paths.items()}
    contents = {"md": markdown, "html": html, "json": json_text}
    try:
        for key, text in contents.items():
            temp_paths[key].write_text(text, encoding="utf-8")
        for key in paths:
            os.replace(str(temp_paths[key]), str(paths[key]))
    except BaseException:
        for temp_path in temp_paths.values():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise
    return {key: str(path) for key, path in paths.items()}
