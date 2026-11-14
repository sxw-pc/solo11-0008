"""单任务校验编排流水线。

串联压缩包安全检查、哈希校验、表读取、Schema、血缘、异常规则与报告生成。
任何安全或格式异常都会转化为结构化失败结果并持久化，不会导致 Web 服务崩溃。

运行中的任务支持协作式终止：每个校验阶段边界与长耗时阶段内部（解压、
哈希、表读取、血缘关系）都设有终止检查点，收到终止请求后任务在当前阶段
的安全点收尾，等待时长不超过单个校验阶段的最大耗时；终止任务会生成标注
终止阶段的部分报告，并按任务 ID 完整回收上传副本与解压临时目录。任务
最终状态通过 SQLite 条件更新原子写入，与并发终止请求竞争时只有一方生效。
"""

from datetime import datetime
from pathlib import Path
import traceback
import uuid
from typing import Any, Dict, List, Optional

from . import __version__
from .cleanup import reclaim_task_resources, validate_task_id
from .config import AppConfig
from .parser.archive_loader import ArchiveError, SecurityError, load_archive
from .parser.table_reader import TableReadError, read_manifest_table
from .report.renderer import build_report_context, render_reports
from .store.sqlite_store import SQLiteStore
from .termination import (TaskTerminated, TerminationRegistry,
                          TerminationToken, default_registry, stage_label)
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


def _terminated_result(stage: str) -> Dict[str, Any]:
    """生成终止占位校验项，标注终止生效时所处的流水线阶段。"""
    label = stage_label(stage)
    return {
        "key": "terminated", "name": "任务终止", "passed": False,
        "summary": "任务在「%s」阶段被人工终止，后续校验未执行" % label,
        "terminated_stage": stage,
        "errors": [{
            "code": "terminated",
            "message": "任务在「%s」阶段被终止，本报告仅包含终止前的部分结果" % label,
        }],
        "samples": [],
    }


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


def _read_tables(extraction: Any, config: AppConfig, sample: bool,
                 should_stop: Any = None) -> tuple:
    """读取 manifest 声明的全部表，返回表映射和失败明细。

    逐表检查终止标志；收到终止请求时抛出 TaskTerminated。
    """
    tables = {}
    errors = []
    for table_name in (extraction.manifest.get("tables") or {}).keys():
        if should_stop is not None and should_stop():
            raise TaskTerminated("table_read")
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
                   task_id: Optional[str] = None,
                   termination_token: Optional[TerminationToken] = None,
                   termination_registry: Optional[TerminationRegistry] = None
                   ) -> Dict[str, Any]:
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
        termination_token: 可选外部终止令牌（测试注入）；缺省时在
            注册表中按任务 ID 登记，供 Web 终止请求查找。
        termination_registry: 可选令牌注册表，默认使用进程级共享实例。
    Returns:
        含 task、results、report、report_paths 的字典；被终止的任务
        status 为 ``terminated``，报告为标注终止阶段的部分报告。
    """
    packet_path = Path(packet_path).resolve()
    task_id = task_id or uuid.uuid4().hex[:16]
    validate_task_id(task_id)
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
        "result_json": "{}", "terminated_stage": "",
        "terminate_requested_at": "",
    }
    store.create_task(task)
    registry = termination_registry or default_registry
    # 外部注入令牌时不登记也不注销，由调用方全权管理生命周期。
    token = termination_token or registry.register(task_id)
    owns_token = termination_token is None
    lines = ["[%s] 任务 %s 开始" % (uploaded_at, task_id),
             "数据包: %s (%d 字节)" % (task["packet_name"], packet_size)]
    results: List[Dict[str, Any]] = []
    extraction = None
    unexpected = ""
    terminated_stage = ""
    try:
        try:
            token.check("archive")
            try:
                extraction = load_archive(
                    packet_path, config, should_stop=token.is_requested,
                    task_id=task_id)
                task["archive_type"] = extraction.archive_type
                results.append(_archive_result(extraction))
                lines.append("压缩包安全检查通过: %s" % extraction.archive_type)
            except (SecurityError, ArchiveError) as exc:
                results.append(_archive_error_result(exc))
                results.extend(_skipped_results("压缩包安全检查未通过"))
                lines.append("压缩包安全检查失败: %s" % exc)
            if extraction is not None:
                token.check("hash")
                hash_result = verify_hashes(
                    extraction.temp_dir, extraction.manifest, config,
                    expected_package_hash=expected_package_hash,
                    package_path=packet_path,
                    should_stop=token.is_requested)
                results.append(hash_result)
                lines.append("哈希校验: %s" % hash_result["summary"])
                token.check("table_read")
                tables, read_errors = _read_tables(
                    extraction, config, sample=False,
                    should_stop=token.is_requested)
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
                sampled_tables, sample_errors = _read_tables(
                    extraction, config, sample=True,
                    should_stop=token.is_requested)
                read_errors.extend(sample_errors)
                token.check("schema")
                try:
                    contract = load_contract(contract_path)
                    schema_result = validate_schema(sampled_tables or tables, contract)
                except ContractError as exc:
                    schema_result = _error_result("schema", "数据契约 Schema 校验",
                                                  str(exc), "contract_error")
                results.append(schema_result)
                lines.append("Schema 校验: %s" % schema_result["summary"])
                token.check("lineage")
                try:
                    lineage_rules = load_lineage_rules(lineage_path)
                    lineage_result = validate_lineage(
                        tables, lineage_rules, should_stop=token.is_requested)
                except LineageRuleError as exc:
                    lineage_result = _error_result("lineage", "跨表血缘一致性校验",
                                                   str(exc), "lineage_rule_error")
                results.append(lineage_result)
                lines.append("血缘校验: %s" % lineage_result["summary"])
                token.check("anomaly")
                try:
                    anomaly_result = validate_anomalies(sampled_tables or tables, contract)
                except (NameError, UnboundLocalError):
                    anomaly_result = _error_result(
                        "anomaly", "异常值抽检规则校验",
                        "契约加载失败，无法执行异常规则", "contract_error")
                results.append(anomaly_result)
                lines.append("异常抽检: %s" % anomaly_result["summary"])
                token.check("report")
        except TaskTerminated as exc:
            # 协作式终止：当前阶段的安全点收尾，不破坏已写入的校验结果。
            terminated_stage = exc.stage
            results.append(_terminated_result(exc.stage))
            lines.append("收到终止请求，任务在「%s」阶段停止"
                         % stage_label(exc.stage))
        except Exception as exc:  # 保证异常不会穿透 Web 请求，同时记录完整本地日志。
            unexpected = "%s: %s" % (type(exc).__name__, exc)
            results.append(_error_result("internal", "校验流水线", "内部异常: %s" % unexpected))
            lines.append("流水线异常:\n" + traceback.format_exc())
        finally:
            if extraction is not None:
                extraction.cleanup()
                lines.append("临时解压目录已清理")
        passed = (bool(results) and all(item.get("passed") for item in results)
                  and not unexpected and not terminated_stage)
        finished = datetime.now()
        duration = round((finished - started).total_seconds(), 3)
        task.update({
            "finished_at": finished.isoformat(timespec="seconds"),
            "duration_seconds": duration,
        })
        if terminated_stage:
            task.update({
                "status": "terminated", "passed": False,
                "terminated_stage": terminated_stage,
                "error_summary": ("任务在「%s」阶段被人工终止"
                                  % stage_label(terminated_stage))[:500],
            })
        else:
            task.update({
                "status": "passed" if passed else "failed", "passed": passed,
                "error_summary": "；".join(item.get("summary", "") for item in results
                                           if not item.get("passed"))[:500],
            })
        report: Dict[str, Any] = {}
        report_paths: Dict[str, str] = {}
        try:
            report = build_report_context(task, results, config)
            report_paths = render_reports(report, config, task_id)
            task["report_md"] = _safe_relative(Path(report_paths["md"]), config.workspace_dir)
            task["report_html"] = _safe_relative(Path(report_paths["html"]), config.workspace_dir)
            task["report_json"] = _safe_relative(Path(report_paths["json"]), config.workspace_dir)
            report["task"] = task
        except Exception as exc:
            unexpected = "报告生成失败: %s" % exc
            if not terminated_stage:
                task["status"] = "error"
            task["passed"] = False
            report_paths = {}
            report = {}
            lines.append(unexpected)
        lines.append("任务结束: %s" % task["status"])
        log_path = _write_log(config, task_id, lines)
        task["log_path"] = _safe_relative(log_path, config.workspace_dir)
        task["result_json"] = {"results": results}
        if not report:
            task["error_summary"] = (task["error_summary"] + "；" + unexpected)[:500]
        persist_fields = {
            "finished_at": task["finished_at"], "status": task["status"],
            "passed": task["passed"], "archive_type": task["archive_type"],
            "duration_seconds": task["duration_seconds"],
            "error_summary": task["error_summary"],
            "report_md": task["report_md"], "report_html": task["report_html"],
            "report_json": task["report_json"], "log_path": task["log_path"],
            "result_json": task["result_json"],
            "terminated_stage": task["terminated_stage"],
        }
        if terminated_stage:
            # 终止收尾：仅当任务仍处于 running/terminating 时原子写入，
            # 不覆盖任何已完成的终态。
            store.finalize_termination(task_id, **persist_fields)
        elif not store.complete_task(task_id, **persist_fields):
            # 终止请求在收尾阶段抢先迁移了状态：改按终止归档，保证已受理
            # 的终止请求不会被正常完成结果覆盖。
            current = store.get_task(task_id) or {}
            if current.get("status") == "terminating":
                terminated_stage = "report"
                results.append(_terminated_result(terminated_stage))
                task.update({
                    "status": "terminated", "passed": False,
                    "terminated_stage": terminated_stage,
                    "error_summary": ("任务在「%s」阶段被人工终止"
                                      % stage_label(terminated_stage))[:500],
                })
                try:
                    report = build_report_context(task, results, config)
                    report_paths = render_reports(report, config, task_id)
                    task["report_md"] = _safe_relative(
                        Path(report_paths["md"]), config.workspace_dir)
                    task["report_html"] = _safe_relative(
                        Path(report_paths["html"]), config.workspace_dir)
                    task["report_json"] = _safe_relative(
                        Path(report_paths["json"]), config.workspace_dir)
                    report["task"] = task
                except Exception:
                    report = {}
                    report_paths = {}
                lines.append("终止请求在报告阶段生效，任务按终止归档")
                lines.append("任务结束: terminated")
                log_path = _write_log(config, task_id, lines)
                task["log_path"] = _safe_relative(log_path, config.workspace_dir)
                task["result_json"] = {"results": results}
                persist_fields.update({
                    "status": "terminated", "passed": False,
                    "terminated_stage": terminated_stage,
                    "error_summary": task["error_summary"],
                    "report_md": task["report_md"],
                    "report_html": task["report_html"],
                    "report_json": task["report_json"],
                    "log_path": task["log_path"],
                    "result_json": task["result_json"],
                })
                store.finalize_termination(task_id, **persist_fields)
        return {"task": task, "results": results, "report": report,
                "report_paths": report_paths}
    finally:
        # 终止或异常路径下的资源安全网：按任务 ID 精确回收上传副本与
        # 解压临时目录残留；不影响其他并行任务的资源。
        reclaim_task_resources(config, task_id)
        if owns_token:
            registry.unregister(task_id)
