"""八类异常数据包识别流程集成测试。"""

from pathlib import Path

from gateway.app import create_app
from gateway.pipeline import run_validation

ROOT = Path(__file__).resolve().parents[2]
INVALID_ROOT = ROOT / "fixtures" / "invalid_packets"


def _by_key(results, key):
    return next(item for item in results if item["key"] == key)


def _run(config, store, scenario):
    packet = INVALID_ROOT / scenario / (scenario + ".zip")
    return packet, run_validation(packet, packet.name, config, store)


def test_all_eight_scenarios_are_detected(config, store):
    scenario_dirs = sorted(path.name for path in INVALID_ROOT.iterdir() if path.is_dir())
    assert scenario_dirs == [
        "field_missing", "hash_tampered", "lineage_broken", "null_rate_over",
        "path_traversal", "redundant_file", "schema_mismatch", "zip_bomb",
    ]

    _, field = _run(config, store, "field_missing")
    assert not _by_key(field["results"], "schema")["passed"]
    assert any(item.get("field") == "status" and item.get("code") == "required"
               for item in _by_key(field["results"], "schema")["errors"])

    _, schema = _run(config, store, "schema_mismatch")
    assert any(item.get("code") == "type" and item.get("field") == "amount"
               for item in _by_key(schema["results"], "schema")["errors"])

    _, lineage = _run(config, store, "lineage_broken")
    relation = _by_key(lineage["results"], "lineage")["relations"][0]
    assert relation["name"] == "trade_owner"
    assert relation["orphan_count"] > 0
    assert not relation["passed"]

    _, hashed = _run(config, store, "hash_tampered")
    assert "hash_mismatch" in _by_key(hashed["results"], "hash")["error_codes"]

    _, null_rate = _run(config, store, "null_rate_over")
    anomaly = _by_key(null_rate["results"], "anomaly")
    note = next(item for item in anomaly["fields"]
                if item["table"] == "trades" and item["field"] == "note")
    assert not note["passed"]
    assert any(rule["rule"] == "null_rate" and not rule["passed"]
               for rule in note["rules"])

    _, traversal = _run(config, store, "path_traversal")
    assert _by_key(traversal["results"], "archive")["errors"][0]["code"] == "path_traversal"

    _, bomb = _run(config, store, "zip_bomb")
    assert _by_key(bomb["results"], "archive")["errors"][0]["code"] == "zip_bomb"

    _, redundant = _run(config, store, "redundant_file")
    assert {"redundant_file", "dangerous_file"} <= set(
        _by_key(redundant["results"], "hash")["error_codes"])

    for outcome in (field, schema, lineage, hashed, null_rate,
                    traversal, bomb, redundant):
        task = outcome["task"]
        assert task["status"] == "failed"
        assert task["error_summary"]
        assert Path(outcome["report_paths"]["html"]).is_file()
        assert outcome["report"]["issues"]
        assert store.get_task(task["task_id"])["status"] == "failed"
    assert not list(config.temp_dir.iterdir())
    assert store.stats()["failed"] == 8


def test_sequential_fail_then_pass_does_not_leak(config, store):
    """连续提交坏包与合法包时不得串任务；合法包结果完全独立。"""
    failing = INVALID_ROOT / "hash_tampered" / "hash_tampered.zip"
    passing = ROOT / "fixtures" / "valid_packets" / "retail_valid_a.zip"
    for _ in range(2):
        bad = run_validation(failing, failing.name, config, store)
        good = run_validation(passing, "same_name.zip", config, store)
        assert bad["task"]["task_id"] != good["task"]["task_id"]
        assert bad["task"]["status"] == "failed"
        assert good["task"]["status"] == "passed"
        assert not good["report"]["issues"]
        assert all(item["passed"] for item in good["results"])
        assert good["report"]["task"]["task_id"] == good["task"]["task_id"]
        stored = store.get_task(good["task"]["task_id"])
        assert stored["status"] == "passed"
        assert all(item["passed"] for item in stored["result"]["results"])
    assert not list(config.temp_dir.iterdir())


def test_report_failure_is_consistent_and_leaves_nothing(config, store, monkeypatch):
    """报告生成失败时历史、详情、下载均不可见半成品，状态统一为失败。"""
    import gateway.pipeline as pipeline
    from gateway.app import create_app

    def broken_render(report, app_config, task_id):
        (app_config.reports_dir / (task_id + ".md")).write_text("half", encoding="utf-8")
        raise OSError("模拟报告写入失败")

    monkeypatch.setattr(pipeline, "render_reports", broken_render)
    packet = ROOT / "fixtures" / "valid_packets" / "retail_valid_a.zip"
    outcome = run_validation(packet, packet.name, config, store, task_id="repfail01")
    task = outcome["task"]
    assert task["status"] == "failed"
    assert task["passed"] is False
    assert task["report_md"] == task["report_html"] == task["report_json"] == ""
    assert outcome["report_paths"] == {}
    stored = store.get_task("repfail01")
    assert stored["status"] == "failed"
    assert stored["passed"] is False
    assert "报告生成失败" in stored["error_summary"]
    assert not list(config.reports_dir.glob("repfail01.*"))
    monkeypatch.undo()
    client = create_app(config).test_client()
    assert client.get("/tasks/repfail01/report/html").status_code == 404
    detail = client.get("/tasks/repfail01")
    assert detail.status_code == 200
    assert "准入不通过" in detail.get_data(as_text=True)


def test_reused_task_id_resets_history_and_artifacts(config, store):
    """同一任务 ID 重跑时历史只保留本次结果，报告与日志被覆盖。"""
    failing = INVALID_ROOT / "schema_mismatch" / "schema_mismatch.zip"
    passing = ROOT / "fixtures" / "valid_packets" / "retail_valid_a.zip"
    run_validation(failing, failing.name, config, store, task_id="reused01")
    first_log = (config.logs_dir / "reused01.log").read_text(encoding="utf-8")
    outcome = run_validation(passing, passing.name, config, store, task_id="reused01")
    stored = store.get_task("reused01")
    assert stored["status"] == "passed"
    assert all(item["passed"] for item in stored["result"]["results"])
    first_result = stored["result"]["results"][0]
    assert first_result["key"] == "archive"
    assert (config.logs_dir / "reused01.log").read_text(encoding="utf-8") != first_log
    assert not [path for path in config.logs_dir.glob("reused01*") if path.suffix == ".tmp"]
    assert len([path for path in config.reports_dir.glob("reused01.*")
                if not path.name.endswith(".tmp")]) == 3


def test_invalid_upload_does_not_crash_web(config):
    app = create_app(config)
    client = app.test_client()
    packet = INVALID_ROOT / "schema_mismatch" / "schema_mismatch.zip"
    with packet.open("rb") as handle:
        response = client.post("/", data={
            "packet": (handle, packet.name), "preset": "trade",
        }, content_type="multipart/form-data")
    assert response.status_code == 302
    detail = client.get(response.headers["Location"])
    assert detail.status_code == 200
    assert "准入不通过" in detail.get_data(as_text=True)
    assert "数据类型不符合契约" in detail.get_data(as_text=True)
    assert not list(config.temp_dir.iterdir())
