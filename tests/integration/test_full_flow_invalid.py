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
