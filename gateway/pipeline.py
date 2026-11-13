"""单任务校验编排流水线。

串联压缩包安全检查、哈希校验、表读取、Schema、血缘、异常规则与报告生成。
任何安全或格式异常都会转化为结构化失败结果并持久化，不会导致 Web 服务崩溃。
"""

from datetime import datetime
from pathlib import Path
import traceback
import uuid
from typing import Any, Dict, List, Optional

from . import __version__
from .config import AppConfig
from .exemption import ExemptionEngine, ExemptionRuleError, resolve_business_domain
from .exemption.rules import load_exemption_rules
from .parser.archive_loader import ArchiveError, SecurityError, load_archive
from .parser.table_reader import TableReadError, read_manifest_table
from .report.renderer import build_report_context, render_reports
from .store.sqlite_store import SQLiteStore
from .validator.anomaly_check import validate_anomalies
from .validator.hash_verify import compute_file_hashes, verify_hashes
from .validator.lineage_check import LineageRuleError, load_lineage_rules, validate_lineage
from .validator.schema_check import ContractError, load_contract, validate_schema


def _now() -> str:
    """返回本地秒级 ISO 时间。"""
    return datetime.now().isoformat(timespec="seconds")


def _error_result(key: str, name: str, message: str, code: str = "error") -> Dict[str, Any]:
    """生成统一的失败校验结果。"""
    return {
        "key": key, "name": name, "passed": False,
        "summary": message, "errors": [{"code": code, "message": message}],
        "samples": [],
    }


def _skipped_results(reason: str) -> List[Dict[str, Any]]:
    """当压缩包不可安全解压时，为其余校验项生成跳过占位。"""
    return [
        _error_result("hash", "文件完整性与哈希校验", "跳过：%s" % reason, "skipped"),
        _error_result("schema", "数据契约 Schema 校验", "跳过：%s" % reason, "skipped"),
        _error_result("lineage", "跨表血缘一致性校验", "跳过：%s" % reason, "skipped"),
        _error_result("anomaly", "异常值抽检规则校验", "跳过：%s" % reason, "skipped"),
    ]


def _archive_result(extraction: Any) -> Dict[str, Any]:
    """把成功解压结果转换为统一校验项。"""
    return {
        "key": "archive", "name": "压缩包安全与结构检查", "passed": True,
        "summary": "格式识别、路径安全、体积阈值与 manifest 检查通过",
        "archive_type": extraction.archive_type,
        "files_count": len(extraction.files),
        "mime_type": extraction.mime_type,
        "errors": [], "samples": [],
    }


def _archive_error_result(exc: Exception) -> Dict[str, Any]:
    """根据安全异常文本归类风险代码。"""
    message = str(exc)
    if "炸弹" in message:
        code = "zip_bomb"
    elif "穿越" in message or "绝对路径" in message:
        code = "path_traversal"
    elif "manifest" in message.lower():
        code = "archive_error"
    else:
        code = "archive_error"
    return _error_result("archive", "压缩包安全与结构检查", message, code)


def _safe_relative(path: Path, workspace: Path) -> str:
    """把报告/日志路径转为工作目录内相对路径。"""
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return path.name


def _write_log(config: AppConfig, task_id: str, lines: List[str]) -> Path:
    """将任务日志写入本地 logs 目录。"""
    path = config.logs_dir / (task_id + ".log")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _read_tables(extraction: Any, config: AppConfig, sample: bool) -> tuple:
    """读取 manifest 声明的全部表，返回表映射和失败明细。"""
    tables = {}
    errors = []
    for table_name in (extraction.manifest.get("tables") or {}).keys():
        try:
            tables[str(table_name)] = read_manifest_table(
                extraction, str(table_name), config, sample=sample)
        except TableReadError as exc:
            errors.append({"code": "table_read_error", "table": str(table_name),
                           "message": str(exc)})
    return tables, errors


def run_validation(packet_path: Path, packet_name: str, config: AppConfig,
                   store: SQLiteStore, contract_path: Optional[Path] = None,
                   lineage_path: Optional[Path] = None,
                   expected_package_hash: Optional[str] = None,
                   task_id: Optional[str] = None) -> Dict[str, Any]:
    """执行一次完整数据包准入校验并持久化结果。

    Args:
        packet_path: 本地压缩包路径。
        packet_name: 展示用原始文件名。
        config: 全局配置。
        store: SQLite 存储实例。
        contract_path: 可选自定义契约，默认使用内置契约。
        lineage_path: 可选自定义血缘规则，默认使用内置规则。
        expected_package_hash: 可选整包 MD5/SHA256。
        task_id: 测试可注入任务 ID；默认生成 UUID。
    Returns:
        含 task、results、report、report_paths 的字典。
    """
    packet_path = Path(packet_path).resolve()
    task_id = task_id or uuid.uuid4().hex[:16]
    if not all(char.isalnum() or char in "-_" for char in task_id):
        raise ValueError("非法任务 ID")
    contract_path = Path(contract_path) if contract_path else config.builtin_contract
    lineage_path = Path(lineage_path) if lineage_path else config.builtin_lineage
    started = datetime.now()
    uploaded_at = _now()
    try:
        packet_size = packet_path.stat().st_size
        packet_hashes = compute_file_hashes(packet_path)
    except OSError:
        packet_size = 0
        packet_hashes = {"sha256": ""}
    task: Dict[str, Any] = {
        "task_id": task_id, "packet_name": packet_name or packet_path.name,
        "packet_size": packet_size, "packet_sha256": packet_hashes.get("sha256", ""),
        "archive_type": "", "uploaded_at": uploaded_at, "finished_at": None,
        "status": "running", "passed": False,
        "contract_name": contract_path.name, "lineage_name": lineage_path.name,
        "duration_seconds": 0.0, "config_hash": config.fingerprint(),
        "tool_version": __version__, "error_summary": "", "report_md": "",
        "report_html": "", "report_json": "", "log_path": "",
        "result_json": "{}",
    }
    store.create_task(task)
    lines = ["[%s] 任务 %s 开始" % (uploaded_at, task_id),
             "数据包: %s (%d 字节)" % (task["packet_name"], packet_size)]
    # 任务启动阶段即固化豁免规则快照：任务运行期间规则文件变更不影响本任务。
    # 规则内容非法时不阻断校验，而是禁用一切豁免，回退到默认严格拦截。
    engine = None
    exemption_summary = None
    ruleset_snapshot = None
    try:
        ruleset_snapshot = load_exemption_rules(config.exemption_rules_path)
    except ExemptionRuleError as exc:
        ruleset_snapshot = None
        lines.append("豁免规则加载失败，已禁用豁免并保持严格拦截: %s" % exc)
    results: List[Dict[str, Any]] = []
    extraction = None
    unexpected = ""
    try:
        try:
            extraction = load_archive(packet_path, config)
            task["archive_type"] = extraction.archive_type
            results.append(_archive_result(extraction))
            lines.append("压缩包安全检查通过: %s" % extraction.archive_type)
            if ruleset_snapshot is not None and ruleset_snapshot:
                business_domain = resolve_business_domain(extraction.manifest)
                engine = ExemptionEngine(
                    ruleset_snapshot, task_id, business_domain,
                    config.exemption_audit_dir)
                engine.__enter__()
                lines.append("豁免规则快照已加载: 指纹 %s，业务域 %s"
                             % (ruleset_snapshot.ruleset_hash[:12],
                                business_domain or "(未声明)"))
        except (SecurityError, ArchiveError) as exc:
            results.append(_archive_error_result(exc))
            results.extend(_skipped_results("压缩包安全检查未通过"))
            lines.append("压缩包安全检查失败: %s" % exc)
        if extraction is not None:
            hash_result = verify_hashes(
                extraction.temp_dir, extraction.manifest, config,
                expected_package_hash=expected_package_hash, package_path=packet_path)
            results.append(hash_result)
            lines.append("哈希校验: %s" % hash_result["summary"])
            tables, read_errors = _read_tables(extraction, config, sample=False)
            if read_errors or not tables:
                read_result = _error_result(
                    "table_read", "结构化表读取适配",
                    "表读取失败: " + "；".join(item["message"] for item in read_errors[:3])
                    if read_errors else "manifest 未声明任何业务表", "table_read_error")
                read_result["errors"] = read_errors
                results.append(read_result)
            else:
                results.append({
                    "key": "table_read", "name": "结构化表读取适配", "passed": True,
                    "summary": "成功读取 %d 张表（血缘使用全量，规则校验使用抽样）"
                               % len(tables), "errors": [], "samples": [],
                })
            sampled_tables, sample_errors = _read_tables(extraction, config, sample=True)
            read_errors.extend(sample_errors)
            try:
                contract = load_contract(contract_path)
                schema_result = validate_schema(sampled_tables or tables, contract)
            except ContractError as exc:
                schema_result = _error_result("schema", "数据契约 Schema 校验",
                                              str(exc), "contract_error")
            results.append(schema_result)
            lines.append("Schema 校验: %s" % schema_result["summary"])
            try:
                lineage_rules = load_lineage_rules(lineage_path)
                lineage_result = validate_lineage(tables, lineage_rules)
            except LineageRuleError as exc:
                lineage_result = _error_result("lineage", "跨表血缘一致性校验",
                                               str(exc), "lineage_rule_error")
            results.append(lineage_result)
            lines.append("血缘校验: %s" % lineage_result["summary"])
            try:
                anomaly_result = validate_anomalies(sampled_tables or tables, contract)
            except (NameError, UnboundLocalError):
                anomaly_result = _error_result(
                    "anomaly", "异常值抽检规则校验",
                    "契约加载失败，无法执行异常规则", "contract_error")
            results.append(anomaly_result)
            lines.append("异常抽检: %s" % anomaly_result["summary"])
    except Exception as exc:  # 保证异常不会穿透 Web 请求，同时记录完整本地日志。
        unexpected = "%s: %s" % (type(exc).__name__, exc)
        results.append(_error_result("internal", "校验流水线", "内部异常: %s" % unexpected))
        lines.append("流水线异常:\n" + traceback.format_exc())
    finally:
        if extraction is not None:
            extraction.cleanup()
            lines.append("临时解压目录已清理")
    # 校验流程完成后再做豁免复核：未命中/过期/拒绝的异常一律保持拦截。
    # 引擎在 apply 内关闭审计链并释放规则快照，确保任务结束不残留内存引用。
    if engine is not None:
        try:
            exemption_summary = engine.apply(results)
            # 立即挂到任务，保证随后渲染的报告与持久化历史使用同一份豁免留痕。
            task["exemption"] = exemption_summary
            if exemption_summary.get("exempted"):
                lines.append("豁免复核: 放行 %d 项，拦截 %d 项，拒绝 %d 项，过期拦截 %d 项"
                             % (exemption_summary["exempted"],
                                exemption_summary["blocked"],
                                exemption_summary["denied"],
                                exemption_summary["expired_blocked"]))
            if exemption_summary.get("conflict_count"):
                lines.append("豁免规则冲突 %d 处，均已按最严格优先级执行"
                             % exemption_summary["conflict_count"])
        except Exception as exc:  # 豁免模块自身异常时绝不放行，回退严格拦截。
            exemption_summary = None
            task.pop("exemption", None)
            lines.append("豁免复核异常，已回退严格拦截: %s: %s"
                         % (type(exc).__name__, exc))
        finally:
            engine.close()
    passed = bool(results) and all(item.get("passed") for item in results) and not unexpected
    finished = datetime.now()
    duration = round((finished - started).total_seconds(), 3)
    task.update({
        "finished_at": finished.isoformat(timespec="seconds"),
        "status": "passed" if passed else "failed", "passed": passed,
        "duration_seconds": duration,
        "error_summary": "；".join(item.get("summary", "") for item in results
                                   if not item.get("passed"))[:500],
    })
    try:
        report = build_report_context(task, results, config)
        report_paths = render_reports(report, config, task_id)
        task["report_md"] = _safe_relative(Path(report_paths["md"]), config.workspace_dir)
        task["report_html"] = _safe_relative(Path(report_paths["html"]), config.workspace_dir)
        task["report_json"] = _safe_relative(Path(report_paths["json"]), config.workspace_dir)
        report["task"] = task
    except Exception as exc:
        unexpected = "报告生成失败: %s" % exc
        task["status"] = "error"
        task["passed"] = False
        report_paths = {}
        report = {}
        lines.append(unexpected)
    log_path = _write_log(config, task_id, lines + ["任务结束: %s" % task["status"]])
    task["log_path"] = _safe_relative(log_path, config.workspace_dir)
    if exemption_summary is not None:
        # 审计文件路径转工作目录相对路径，随任务历史与报告一起可归档、可迁移。
        if exemption_summary.get("audit_path"):
            exemption_summary["audit_path"] = _safe_relative(
                Path(exemption_summary["audit_path"]), config.workspace_dir)
        task["exemption"] = exemption_summary
        task["result_json"] = {"results": results, "exemption": exemption_summary}
    else:
        task["result_json"] = {"results": results}
    if not report:
        task["error_summary"] = (task["error_summary"] + "；" + unexpected)[:500]
    store.update_task(
        task_id, finished_at=task["finished_at"], status=task["status"],
        passed=task["passed"], archive_type=task["archive_type"],
        duration_seconds=task["duration_seconds"], error_summary=task["error_summary"],
        report_md=task["report_md"], report_html=task["report_html"],
        report_json=task["report_json"], log_path=task["log_path"],
        result_json=task["result_json"],
    )
    return {"task": task, "results": results, "report": report,
            "report_paths": report_paths}
