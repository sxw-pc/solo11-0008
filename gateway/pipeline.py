"""单任务校验编排流水线。

按固定顺序调度压缩包安全、完整性、表读取、Schema、血缘、异常抽检六个
阶段。各阶段共享同一份解压目录与表数据：表文件只从磁盘读取一次，抽样
表由全量表在内存中派生，整包哈希也只计算一次，避免重复磁盘 IO。

默认配置下执行逻辑与历史串行实现完全一致；``continue_on_failure=False``
时，任一前置阶段失败后非核心阶段记为“跳过”并终止。每个阶段的耗时、
跳过状态与失败原因统一写入 SQLite 任务历史表（``stage_metrics`` 列）。
临时解压目录由资源注册表兜底回收，进程异常终止也不会长期残留。
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import time
import traceback
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import __version__
from .config import AppConfig
from .parser.archive_loader import ArchiveError, SecurityError, load_archive
from .parser.table_reader import (TableData, TableReadError,
                                  derive_sampled_table, read_manifest_table)
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


@dataclass
class _StageContext:
    """跨阶段共享的校验上下文。

    解压目录、全量表、抽样表与契约只加载一次，后续阶段直接复用，
    不再各自读取磁盘。
    """

    config: AppConfig
    packet_path: Path
    contract_path: Path
    lineage_path: Path
    expected_package_hash: Optional[str]
    packet_hashes: Dict[str, str]
    log_lines: List[str]
    extraction: Any = None
    tables: Dict[str, TableData] = field(default_factory=dict)
    sampled_tables: Dict[str, TableData] = field(default_factory=dict)
    contract: Optional[Dict[str, Any]] = None


def _stage_archive(ctx: _StageContext) -> Dict[str, Any]:
    """阶段一：压缩包安全与结构检查，产出共享解压目录。"""
    try:
        ctx.extraction = load_archive(ctx.packet_path, ctx.config)
    except (SecurityError, ArchiveError) as exc:
        ctx.log_lines.append("压缩包安全检查失败: %s" % exc)
        return _archive_error_result(exc)
    ctx.log_lines.append("压缩包安全检查通过: %s" % ctx.extraction.archive_type)
    return _archive_result(ctx.extraction)


def _stage_hash(ctx: _StageContext) -> Dict[str, Any]:
    """阶段二：文件完整性与哈希校验，复用已计算的整包哈希。"""
    package_hashes = ctx.packet_hashes if ctx.packet_hashes.get("sha256") else None
    result = verify_hashes(
        ctx.extraction.temp_dir, ctx.extraction.manifest, ctx.config,
        expected_package_hash=ctx.expected_package_hash,
        package_path=ctx.packet_path, package_hashes=package_hashes)
    ctx.log_lines.append("哈希校验: %s" % result["summary"])
    return result


def _stage_table_read(ctx: _StageContext) -> Dict[str, Any]:
    """阶段三：结构化表读取适配。

    每张表只从磁盘读取一次（全量），抽样表由全量表在内存中派生；
    读取失败的表在抽样阶段按旧行为记录同样的错误。
    """
    tables: Dict[str, TableData] = {}
    read_errors: List[Dict[str, Any]] = []
    table_names = [str(name)
                   for name in (ctx.extraction.manifest.get("tables") or {}).keys()]
    for table_name in table_names:
        try:
            tables[table_name] = read_manifest_table(
                ctx.extraction, table_name, ctx.config, sample=False)
        except TableReadError as exc:
            read_errors.append({"code": "table_read_error", "table": table_name,
                                "message": str(exc)})
    sampled: Dict[str, TableData] = {}
    sample_errors: List[Dict[str, Any]] = []
    for table_name in table_names:
        source = tables.get(table_name)
        if source is None:
            # 与旧实现一致：完整读取失败的表在抽样读取时会再次失败，
            # 错误内容相同，这里直接复用，避免无意义的二次磁盘读取。
            sample_errors.extend(dict(item) for item in read_errors
                                 if item["table"] == table_name)
            continue
        try:
            sampled[table_name] = derive_sampled_table(source, ctx.config)
        except TableReadError as exc:
            sample_errors.append({"code": "table_read_error", "table": table_name,
                                  "message": str(exc)})
    ctx.tables = tables
    ctx.sampled_tables = sampled
    if read_errors or not tables:
        result = _error_result(
            "table_read", "结构化表读取适配",
            "表读取失败: " + "；".join(item["message"] for item in read_errors[:3])
            if read_errors else "manifest 未声明任何业务表", "table_read_error")
        result["errors"] = read_errors + sample_errors
        return result
    return {
        "key": "table_read", "name": "结构化表读取适配", "passed": True,
        "summary": "成功读取 %d 张表（血缘使用全量，规则校验使用抽样）"
                   % len(tables), "errors": [], "samples": [],
    }


def _stage_schema(ctx: _StageContext) -> Dict[str, Any]:
    """阶段四：数据契约 Schema 校验（使用抽样表）。"""
    try:
        ctx.contract = load_contract(ctx.contract_path)
        result = validate_schema(ctx.sampled_tables or ctx.tables, ctx.contract)
    except ContractError as exc:
        result = _error_result("schema", "数据契约 Schema 校验",
                               str(exc), "contract_error")
    ctx.log_lines.append("Schema 校验: %s" % result["summary"])
    return result


def _stage_lineage(ctx: _StageContext) -> Dict[str, Any]:
    """阶段五：跨表血缘一致性校验（使用全量表）。"""
    try:
        lineage_rules = load_lineage_rules(ctx.lineage_path)
        result = validate_lineage(ctx.tables, lineage_rules)
    except LineageRuleError as exc:
        result = _error_result("lineage", "跨表血缘一致性校验",
                               str(exc), "lineage_rule_error")
    ctx.log_lines.append("血缘校验: %s" % result["summary"])
    return result


def _stage_anomaly(ctx: _StageContext) -> Dict[str, Any]:
    """阶段六：异常值抽检规则校验（使用抽样表与已加载契约）。"""
    if ctx.contract is None:
        # 契约加载失败时旧实现依赖未绑定变量触发 NameError，这里显式判断，
        # 输出与旧实现完全一致的结果。
        result = _error_result("anomaly", "异常值抽检规则校验",
                               "契约加载失败，无法执行异常规则", "contract_error")
    else:
        try:
            result = validate_anomalies(ctx.sampled_tables or ctx.tables, ctx.contract)
        except (NameError, UnboundLocalError):
            result = _error_result("anomaly", "异常值抽检规则校验",
                                   "契约加载失败，无法执行异常规则", "contract_error")
    ctx.log_lines.append("异常抽检: %s" % result["summary"])
    return result


#: 阶段定义：(key, 名称, 是否核心阶段, 执行函数)。核心阶段产出共享资源，
#: 始终执行；非核心阶段受 continue_on_failure 配置控制。
_STAGES: Tuple[Tuple[str, str, bool, Callable[[_StageContext], Dict[str, Any]]], ...] = (
    ("archive", "压缩包安全与结构检查", True, _stage_archive),
    ("hash", "文件完整性与哈希校验", True, _stage_hash),
    ("table_read", "结构化表读取适配", True, _stage_table_read),
    ("schema", "数据契约 Schema 校验", False, _stage_schema),
    ("lineage", "跨表血缘一致性校验", False, _stage_lineage),
    ("anomaly", "异常值抽检规则校验", False, _stage_anomaly),
)

#: 压缩包安全检查未通过时需要生成跳过占位结果的阶段（与旧实现一致，
#: table_read 不生成占位结果）。
_ARCHIVE_GATE_SKIPPED = ("hash", "schema", "lineage", "anomaly")


def _metric_entry(key: str, name: str, status: str, duration: float,
                  error_summary: str = "") -> Dict[str, Any]:
    """生成单阶段指标记录。"""
    return {
        "key": key, "name": name, "status": status,
        "duration_seconds": round(duration, 3),
        "error_summary": str(error_summary)[:500],
    }


def _fill_unexecuted_metrics(metrics: List[Dict[str, Any]], reason: str) -> None:
    """为未执行的阶段补齐跳过指标，保证指标覆盖全部阶段。"""
    executed = {item["key"] for item in metrics}
    for key, name, _core, _func in _STAGES:
        if key not in executed:
            metrics.append(_metric_entry(key, name, "skipped", 0.0, reason))


def _run_stages(ctx: _StageContext, results: List[Dict[str, Any]],
                metrics: List[Dict[str, Any]]) -> None:
    """按固定顺序执行各阶段，结果与指标就地追加到给定列表。

    默认配置下与旧串行实现一致：压缩包安全检查未通过时后续阶段记为跳过，
    其余阶段失败不阻断后续。``continue_on_failure=False`` 时，任一前置
    阶段失败后非核心阶段记为跳过。未捕获异常会记录当前阶段指标后继续
    向上抛出，由外层统一转换为内部错误结果。
    """
    archive_failed = False
    any_failed = False
    for key, name, core, func in _STAGES:
        if archive_failed:
            if key in _ARCHIVE_GATE_SKIPPED:
                results.append(_error_result(
                    key, name, "跳过：压缩包安全检查未通过", "skipped"))
            metrics.append(_metric_entry(key, name, "skipped", 0.0,
                                         "压缩包安全检查未通过"))
            continue
        if not core and any_failed and not ctx.config.continue_on_failure:
            reason = "前置校验阶段未通过"
            results.append(_error_result(key, name, "跳过：%s" % reason, "skipped"))
            ctx.log_lines.append("阶段跳过: %s（%s）" % (name, reason))
            metrics.append(_metric_entry(key, name, "skipped", 0.0, reason))
            continue
        started = time.perf_counter()
        try:
            result = func(ctx)
        except Exception as exc:
            metrics.append(_metric_entry(
                key, name, "failed", time.perf_counter() - started,
                "%s: %s" % (type(exc).__name__, exc)))
            raise
        results.append(result)
        passed = bool(result.get("passed"))
        metrics.append(_metric_entry(
            key, name, "passed" if passed else "failed",
            time.perf_counter() - started,
            "" if passed else result.get("summary", "")))
        if not passed:
            any_failed = True
        if key == "archive" and ctx.extraction is None:
            archive_failed = True


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
        含 task、results、report、report_paths、stage_metrics 的字典。
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
    results: List[Dict[str, Any]] = []
    ctx = _StageContext(
        config=config, packet_path=packet_path, contract_path=contract_path,
        lineage_path=lineage_path, expected_package_hash=expected_package_hash,
        packet_hashes=packet_hashes, log_lines=lines)
    stage_metrics: List[Dict[str, Any]] = []
    unexpected = ""
    try:
        _run_stages(ctx, results, stage_metrics)
    except Exception as exc:  # 保证异常不会穿透 Web 请求，同时记录完整本地日志。
        unexpected = "%s: %s" % (type(exc).__name__, exc)
        results.append(_error_result("internal", "校验流水线", "内部异常: %s" % unexpected))
        lines.append("流水线异常:\n" + traceback.format_exc())
        _fill_unexecuted_metrics(stage_metrics, "流水线内部异常终止")
    finally:
        if ctx.extraction is not None:
            ctx.extraction.cleanup()
            lines.append("临时解压目录已清理")
    if ctx.extraction is not None:
        task["archive_type"] = ctx.extraction.archive_type
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
    task["result_json"] = {"results": results}
    if not report:
        task["error_summary"] = (task["error_summary"] + "；" + unexpected)[:500]
    store.update_task(
        task_id, finished_at=task["finished_at"], status=task["status"],
        passed=task["passed"], archive_type=task["archive_type"],
        duration_seconds=task["duration_seconds"], error_summary=task["error_summary"],
        report_md=task["report_md"], report_html=task["report_html"],
        report_json=task["report_json"], log_path=task["log_path"],
        result_json=task["result_json"], stage_metrics=stage_metrics,
    )
    return {"task": task, "results": results, "report": report,
            "report_paths": report_paths, "stage_metrics": stage_metrics}
