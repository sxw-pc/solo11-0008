"""Flask 本地应用入口与路由。

服务默认仅监听 127.0.0.1:5000。上传文件在工作目录的 uploads/tmp 下处理，
校验结束后删除上传副本与临时配置；仅报告、日志和 SQLite 记录长期保留。
"""

from pathlib import Path
import secrets
import shutil
import tempfile
import uuid
from typing import Any, Optional

from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, url_for)

from . import __version__
from .config import PROJECT_ROOT, AppConfig, load_config
from .pipeline import run_validation
from .report.renderer import build_report_context
from .store.sqlite_store import SQLiteStore

_PRESETS = {
    "trade": (PROJECT_ROOT / "fixtures" / "mock_contract" / "user_trade_contract.yaml",
              PROJECT_ROOT / "fixtures" / "mock_lineage" / "trade_lineage_rule.yaml"),
    "product": (PROJECT_ROOT / "fixtures" / "mock_contract" / "product_contract.yaml",
                PROJECT_ROOT / "fixtures" / "mock_lineage" / "product_lineage_rule.yaml"),
}


def _display_name(filename: str) -> str:
    """从客户端文件名中剥离目录，仅保留安全展示名。"""
    name = str(filename or "packet").replace("\\", "/").split("/")[-1].strip()
    return name[:200] or "packet"


def _save_upload(file_storage: Any, folder: Path, suffix: str = "") -> Path:
    """把上传内容流式保存到指定目录内唯一文件。"""
    folder.mkdir(parents=True, exist_ok=True)
    suffix = suffix.lower()
    if suffix not in (".zip", ".tar.gz", ".tgz", ".yaml", ".yml"):
        suffix = Path(_display_name(file_storage.filename)).suffix.lower()
    path = folder / (uuid.uuid4().hex + suffix)
    file_storage.save(str(path))
    return path


def _inside(path: Path, root: Path) -> bool:
    """判断路径是否位于指定根目录内。"""
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _unlink_quiet(path: Path) -> None:
    """尽力删除文件；Windows 下被占用时保留记录并交由后续运维清理。"""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _report_file(task: dict, fmt: str, config: AppConfig) -> Path:
    """解析任务报告路径并阻止越界访问。"""
    key = {"md": "report_md", "html": "report_html", "json": "report_json"}.get(fmt)
    if not key:
        abort(404)
    relative = task.get(key) or ""
    path = (config.workspace_dir / relative).resolve()
    if not relative or not _inside(path, config.reports_dir) or not path.is_file():
        abort(404)
    return path


def _log_preview(task: dict, config: AppConfig) -> str:
    """读取本地任务日志末尾内容用于页面展示。"""
    relative = task.get("log_path") or ""
    path = (config.workspace_dir / relative).resolve()
    if not relative or not _inside(path, config.logs_dir) or not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-120:])[-20000:]


def create_app(config: Optional[AppConfig] = None,
               config_path: Optional[Path] = None) -> Flask:
    """创建 Flask 应用，可注入测试配置。"""
    config = config or load_config(config_path)
    app = Flask(
        __name__,
        template_folder=str(PROJECT_ROOT / "templates"),
        static_folder=str(PROJECT_ROOT / "static"),
    )
    app.config.update(
        MAX_CONTENT_LENGTH=config.max_content_length,
        SECRET_KEY=secrets.token_hex(16),
        JSON_AS_ASCII=False,
    )
    store = SQLiteStore(config.db_path)
    app.extensions["gateway_config"] = config
    app.extensions["gateway_store"] = store

    @app.after_request
    def security_headers(response: Any) -> Any:
        """添加本地运行所需的最小安全响应头。"""
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; img-src 'self' data:")
        return response

    @app.route("/", methods=["GET", "POST"])
    def index() -> Any:
        """首页：展示任务上传表单与统计信息。"""
        if request.method == "GET":
            return render_template("index.html", stats=store.stats(),
                                   version=__version__, config=config)
        packet = request.files.get("packet")
        if packet is None or not packet.filename:
            flash("请选择待校验的 zip 或 tar.gz 数据包", "error")
            return redirect(url_for("index"))
        preset = request.form.get("preset", "trade")
        contract_file = request.files.get("contract")
        lineage_file = request.files.get("lineage")
        expected_hash = (request.form.get("expected_hash") or "").strip() or None
        temp_root = Path(tempfile.mkdtemp(prefix="upload-", dir=str(config.temp_dir)))
        try:
            upload = _save_upload(packet, temp_root)
            builtin_contract, builtin_lineage = _PRESETS.get(preset, _PRESETS["trade"])
            contract_path, lineage_path = builtin_contract, builtin_lineage
            if contract_file is not None and contract_file.filename:
                contract_path = _save_upload(contract_file, temp_root, ".yaml")
            if lineage_file is not None and lineage_file.filename:
                lineage_path = _save_upload(lineage_file, temp_root, ".yaml")
            outcome = run_validation(
                upload, _display_name(packet.filename), config, store,
                contract_path=contract_path, lineage_path=lineage_path,
                expected_package_hash=expected_hash)
            status = outcome["task"].get("status")
            if status == "passed":
                flash("校验通过，报告已生成", "success")
            else:
                flash("校验未通过，请查看报告中的异常明细", "error")
            return redirect(url_for("task_detail", task_id=outcome["task"]["task_id"]))
        except Exception as exc:
            flash("任务执行失败: %s" % exc, "error")
            return redirect(url_for("index"))
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

    @app.route("/tasks")
    def task_list() -> Any:
        """历史任务列表，支持 ID/名称、状态与时间范围筛选。"""
        filters = {
            "query": request.args.get("q", "").strip(),
            "status": request.args.get("status", "").strip(),
            "date_from": request.args.get("date_from", "").strip(),
            "date_to": request.args.get("date_to", "").strip(),
        }
        tasks = store.list_tasks(**filters)
        return render_template("task_list.html", tasks=tasks, filters=filters,
                               config=config)

    @app.route("/tasks/<task_id>")
    def task_detail(task_id: str) -> Any:
        """报告详情页，展示校验项、异常与本地日志预览。"""
        task = store.get_task(task_id)
        if task is None:
            abort(404)
        results = task.get("result", {}).get("results", [])
        report = build_report_context(task, results, config)
        return render_template("report_detail.html", task=task, report=report,
                               log_preview=_log_preview(task, config), config=config)

    @app.route("/tasks/<task_id>/report/<fmt>")
    def download_report(task_id: str, fmt: str) -> Any:
        """下载 Markdown/HTML/JSON 报告。"""
        task = store.get_task(task_id)
        if task is None:
            abort(404)
        path = _report_file(task, fmt, config)
        mimetype = {"md": "text/markdown; charset=utf-8",
                    "html": "text/html; charset=utf-8",
                    "json": "application/json; charset=utf-8"}[fmt]
        return send_file(path, mimetype=mimetype, as_attachment=True,
                         download_name="gateway_report_%s.%s" % (task_id, fmt))

    @app.route("/tasks/<task_id>/delete", methods=["POST"])
    def delete_task(task_id: str) -> Any:
        """删除任务记录、报告与日志文件。"""
        task = store.get_task(task_id)
        if task is None:
            abort(404)
        for key, root in (("report_md", config.reports_dir),
                          ("report_html", config.reports_dir),
                          ("report_json", config.reports_dir),
                          ("log_path", config.logs_dir)):
            relative = task.get(key) or ""
            path = (config.workspace_dir / relative).resolve()
            if relative and _inside(path, root) and path.is_file():
                _unlink_quiet(path)
        store.delete_task(task_id)
        flash("任务 %s 已删除" % task_id, "success")
        return redirect(url_for("task_list"))

    @app.route("/healthz")
    def healthz() -> Any:
        """本地健康检查，不访问任何外部依赖。"""
        return {"status": "ok", "version": __version__, "host": config.host}

    @app.errorhandler(404)
    def not_found(error: Any) -> Any:
        """统一 404 页面。"""
        return render_template("base.html", error_message="请求的页面或任务不存在"), 404

    @app.errorhandler(413)
    def too_large(error: Any) -> Any:
        """上传体积超限提示。"""
        return render_template("base.html", error_message="上传文件超过体积限制"), 413

    return app


def main() -> None:
    """命令行入口：启动仅回环监听的本地服务。"""
    config = load_config()
    app = create_app(config)
    print("数包闸检 %s 已启动: http://%s:%d" % (__version__, config.host, config.port))
    app.run(host=config.host, port=config.port, debug=False,
            use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
