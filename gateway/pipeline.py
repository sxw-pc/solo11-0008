"""单任务校验编排流水线。

串联压缩包安全检查、哈希校验、表读取、Schema、血缘、异常规则与报告生成。
任何安全或格式异常都会转化为结构化失败结果并持久化，不会导致 Web 服务崩溃。

阻断级别模型（见 gateway/levels.py）：

- 命中阻断（block）规则时立即终止后续阶段，未执行阶段生成跳过占位。
- 命中降级（degrade）规则时记录失败并继续执行后续可运行阶段，一次任务
  即可暴露多类数据问题；任务最终结论仍为不通过，降级不会放宽准入。
- 安全类规则（路径穿越、压缩炸弹、高危可执行文件）与基础设施异常
  （表读取失败、临时文件损坏、契约/血缘文件损坏）钉死为阻断：降级
  执行过程中一旦遇到这类异常，自动回退到原有的终止逻辑。
"""

from datetime import datetime
from pathlib import Path
import traceback
import uuid
from typing import Any, Dict, List, Optional

from . import __version__
from .config import AppConfig
from .levels import STAGE_NAMES, STAGE_SEQUENCE, result_is_blocking
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


def _placeholder(key: str, reason: str) -> Dict[str, Any]:
    """为未执行的阶段生成跳过占位结果。"""
    result = _error_result(key, STAGE_NAMES[key], "跳过：%s" % reason, "skipped")
    result["skipped"] = True
    return result


def _skipped_results(reason: str) -> List[Dict[str, Any]]:
    """当压缩包不可安全解压时，为其余校验项生成跳过占位。

    保持历史输出结构：不包含 table_read 占位，与既有报告与任务数据一致。
    """
    return [
        _placeholder("hash", reason),
        _placeholder("schema", reason),
        _placeholder("lineage", reason),
        _placeholder("anomaly", reason),
    ]


def _skipped_remaining(after_key: str, reason: str) -> List[Dict[str, Any]]:
    """为指定阶段之后未执行的阶段生成跳过占位。"""
    sequence = [key for key in STAGE_SEQUENCE if key != "archive"]
    start = sequence.index(after_key) + 1
    return [_placeholder(key, reason) for key in sequence[start:]]


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


class _StageTracker:
    """记录各阶段执行结果并按阻断级别决定是否终止流水线。"""

    def __init__(self, config: AppConfig):
        self.stage_levels = config.stage_levels
        self.rule_levels = config.rule_levels
        self.results: List[Dict[str, Any]] = []
        self.degraded_stages: List[str] = []
        self.terminated_at: Optional[str] = None

    @property
    def terminated(self) -> bool:
        """流水线是否已命中阻断规则终止。"""
        return self.terminated_at is not None

    def finish_stage(self, result: Dict[str, Any]) -> None:
        """登记阶段结果；失败时按级别标记降级或终止。"""
        self.results.append(result)
        if result.get("passed") or self.terminated:
            return
        key = str(result.get("key") or "")
        if result_is_blocking(result, self.stage_levels, self.rule_levels):
            result["terminated"] = True
            self.terminated_at = key
        else:
            result["degraded"] = True
            self.degraded_stages.append(key)

    def skip_remaining(self, after_key: str, reason: str) -> None:
        """为终止点之后的未执行阶段补充跳过占位。"""
        self.results.extend(_skipped_remaining(after_key, reason))

    def degradation(self) -> Dict[str, Any]:
        """汇总本次任务的降级执行信息，随结果持久化。"""
        return {
            "levels": {key: self.stage_levels.get(key)
                       for key in STAGE_SEQUENCE},
            "degraded_stages": list(self.degraded_stages),
            "terminated_at": self.terminated_at,
            "skipped_stages": [item.get("key") for item in self.results
                               if item.get("skipped")],
        }


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
        "status": "running", "passed": False, "degraded": False,
        "contract_name": contract_path.name, "lineage_name": lineage_path.name,
        "duration_seconds": 0.0, "config_hash": config.fingerprint(),
        "tool_version": __version__, "error_summary": "", "report_md": "",
        "report_html": "", "report_json": "", "log_path": "",
        "result_json": "{}",
    }
    store.create_task(task)
    lines = ["[%s] 任务 %s 开始" % (uploaded_at, task_id),
             "数据包: %s (%d 字节)" % (task["packet_name"], packet_size)]
    tracker = _StageTracker(config)
    results = tracker.results
    extraction = None
    unexpected = ""
    try:
        # 阶段一：压缩包安全与结构检查（钉死阻断，失败即终止）。
        try:
            extraction = load_archive(packet_path, config)
            task["archive_type"] = extraction.archive_type
            results.append(_archive_result(extraction))
            lines.append("压缩包安全检查通过: %s" % extraction.archive_type)
        except (SecurityError, ArchiveError) as exc:
            archive_result = _archive_error_result(exc)
            archive_result["terminated"] = True
            results.append(archive_result)
            results.extend(_skipped_results("压缩包安全检查未通过"))
            tracker.terminated_at = "archive"
            lines.append("压缩包安全检查失败: %s" % exc)
        # 阶段二：文件完整性与哈希校验（数据类问题默认降级继续）。
        if not tracker.terminated:
            hash_result = verify_hashes(
                extraction.temp_dir, extraction.manifest, config,
                expected_package_hash=expected_package_hash,
                package_path=packet_path, rule_levels=config.rule_levels)
            tracker.finish_stage(hash_result)
            lines.append("哈希校验: %s" % hash_result["summary"])
            if tracker.terminated:
                tracker.skip_remaining("hash", "哈希校验命中阻断规则")
        # 阶段三：结构化表读取。表读取失败属于基础设施异常，钉死阻断，
        # 自动回退到终止逻辑；manifest 未声明表属于数据问题，降级继续。
        if not tracker.terminated:
            tables, read_errors = _read_tables(extraction, config, sample=False)
            if read_errors:
                read_result = _error_result(
                    "table_read", STAGE_NAMES["table_read"],
                    "表读取失败: " + "；".join(item["message"]
                                           for item in read_errors[:3]),
                    "table_read_error")
                read_result["errors"] = read_errors
                tracker.finish_stage(read_result)
                if tracker.terminated:
                    tracker.skip_remaining("table_read", "表读取失败，已回退为终止")
            elif not tables:
                read_result = _error_result(
                    "table_read", STAGE_NAMES["table_read"],
                    "manifest 未声明任何业务表", "no_tables_declared")
                tracker.finish_stage(read_result)
            else:
                results.append({
                    "key": "table_read", "name": STAGE_NAMES["table_read"],
                    "passed": True,
                    "summary": "成功读取 %d 张表（血缘使用全量，规则校验使用抽样）"
                               % len(tables), "errors": [], "samples": [],
                })
            if not tracker.terminated:
                sampled_tables, sample_errors = _read_tables(
                    extraction, config, sample=True)
                read_errors.extend(sample_errors)
        # 阶段四：数据契约 Schema 校验。
        if not tracker.terminated:
            try:
                contract = load_contract(contract_path)
                schema_result = validate_schema(sampled_tables or tables, contract,
                                                rule_levels=config.rule_levels)
            except ContractError as exc:
                schema_result = _error_result("schema", STAGE_NAMES["schema"],
                                              str(exc), "contract_error")
            tracker.finish_stage(schema_result)
            lines.append("Schema 校验: %s" % schema_result["summary"])
            if tracker.terminated:
                tracker.skip_remaining("schema", "Schema 校验命中阻断规则")
        # 阶段五：跨表血缘一致性校验。
        if not tracker.terminated:
            try:
                lineage_rules = load_lineage_rules(lineage_path)
                lineage_result = validate_lineage(tables, lineage_rules,
                                                  rule_levels=config.rule_levels)
            except LineageRuleError as exc:
                lineage_result = _error_result("lineage", STAGE_NAMES["lineage"],
                                               str(exc), "lineage_rule_error")
            tracker.finish_stage(lineage_result)
            lines.append("血缘校验: %s" % lineage_result["summary"])
            if tracker.terminated:
                tracker.skip_remaining("lineage", "血缘校验命中阻断规则")
        # 阶段六：异常值抽检规则校验。
        if not tracker.terminated:
            try:
                anomaly_result = validate_anomalies(
                    sampled_tables or tables, contract,
                    rule_levels=config.rule_levels)
            except (NameError, UnboundLocalError):
                anomaly_result = _error_result(
                    "anomaly", STAGE_NAMES["anomaly"],
                    "契约加载失败，无法执行异常规则", "contract_error")
            tracker.finish_stage(anomaly_result)
            lines.append("异常抽检: %s" % anomaly_result["summary"])
    except Exception as exc:  # 保证异常不会穿透 Web 请求，同时记录完整本地日志。
        unexpected = "%s: %s" % (type(exc).__name__, exc)
        results.append(_error_result("internal", "校验流水线", "内部异常: %s" % unexpected))
        lines.append("流水线异常:\n" + traceback.format_exc())
    finally:
        # 无论正常结束、阻断终止还是异常回退，临时解压目录都必须清理。
        if extraction is not None:
            extraction.cleanup()
            lines.append("临时解压目录已清理")
    degradation = tracker.degradation()
    if degradation["degraded_stages"]:
        lines.append("降级执行阶段: %s" % "、".join(
            STAGE_NAMES.get(key, key) for key in degradation["degraded_stages"]))
    if degradation["terminated_at"]:
        lines.append("流水线在 %s 阶段命中阻断规则终止"
                     % STAGE_NAMES.get(degradation["terminated_at"],
                                       degradation["terminated_at"]))
    task["degraded"] = bool(degradation["degraded_stages"])
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
        report = build_report_context(task, results, config, degradation=degradation)
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
    task["result_json"] = {"results": results, "degradation": degradation}
    if not report:
        task["error_summary"] = (task["error_summary"] + "；" + unexpected)[:500]
    store.update_task(
        task_id, finished_at=task["finished_at"], status=task["status"],
        passed=task["passed"], degraded=task["degraded"],
        archive_type=task["archive_type"],
        duration_seconds=task["duration_seconds"], error_summary=task["error_summary"],
        report_md=task["report_md"], report_html=task["report_html"],
        report_json=task["report_json"], log_path=task["log_path"],
        result_json=task["result_json"],
    )
    return {"task": task, "results": results, "report": report,
            "report_paths": report_paths}
