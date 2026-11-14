"""合法数据包全流程集成测试。"""

from hashlib import sha256
from pathlib import Path

from gateway.app import create_app
from gateway.pipeline import run_validation

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
CONTRACT = FIXTURES / "mock_contract" / "user_trade_contract.yaml"
PRODUCT_CONTRACT = FIXTURES / "mock_contract" / "product_contract.yaml"
LINEAGE = FIXTURES / "mock_lineage" / "trade_lineage_rule.yaml"
PRODUCT_LINEAGE = FIXTURES / "mock_lineage" / "product_lineage_rule.yaml"
VALID_PACKETS = sorted((FIXTURES / "valid_packets").iterdir())


def test_all_four_valid_packets(config, store):
    for packet in VALID_PACKETS:
        outcome = run_validation(packet, packet.name, config, store)
        task = outcome["task"]
        assert task["status"] == "passed", (packet.name, task["error_summary"])
        assert all(item["passed"] for item in outcome["results"])
        assert Path(outcome["report_paths"]["html"]).is_file()
        assert Path(outcome["report_paths"]["md"]).is_file()
        assert Path(outcome["report_paths"]["json"]).is_file()
        assert outcome["report"]["overall_passed"]
        stored = store.get_task(task["task_id"])
        assert stored["status"] == "passed"
        assert stored["result"]["results"]
    assert not list(config.temp_dir.iterdir())
    assert store.stats()["passed"] == 4


def test_custom_contract_paths_and_expected_hash(config, store):
    packet = VALID_PACKETS[0]
    expected = sha256(packet.read_bytes()).hexdigest()
    outcome = run_validation(
        packet, packet.name, config, store, contract_path=CONTRACT,
        lineage_path=LINEAGE, expected_package_hash="sha256:" + expected)
    assert outcome["task"]["status"] == "passed"
    assert outcome["task"]["packet_sha256"] == expected


def test_product_contract_flow(config, store):
    outcome = run_validation(
        VALID_PACKETS[1], VALID_PACKETS[1].name, config, store,
        contract_path=PRODUCT_CONTRACT, lineage_path=PRODUCT_LINEAGE)
    assert outcome["task"]["status"] == "passed"
    assert outcome["task"]["contract_name"] == "product_contract.yaml"


def test_web_upload_download_and_delete(config):
    app = create_app(config)
    client = app.test_client()
    with VALID_PACKETS[0].open("rb") as handle:
        response = client.post("/", data={
            "packet": (handle, VALID_PACKETS[0].name),
            "preset": "trade",
        }, content_type="multipart/form-data")
    assert response.status_code == 302
    detail_url = response.headers["Location"]
    task_id = detail_url.rstrip("/").split("/")[-1]
    detail = client.get(detail_url)
    assert detail.status_code == 200
    assert "准入通过" in detail.get_data(as_text=True)
    assert "校验项" in detail.get_data(as_text=True)
    for fmt in ("html", "md", "json"):
        report = client.get("/tasks/%s/report/%s" % (task_id, fmt))
        assert report.status_code == 200
        assert len(report.data) > 100
        if fmt == "html":
            text = report.get_data(as_text=True)
            assert "http://" not in text and "https://" not in text
        report.close()
    listing = client.get("/tasks?status=passed")
    assert listing.status_code == 200
    assert task_id in listing.get_data(as_text=True)
    deleted = client.post("/tasks/%s/delete" % task_id, follow_redirects=True)
    assert deleted.status_code == 200
    assert client.get("/tasks/%s" % task_id).status_code == 404


def test_empty_upload_and_filters(config):
    app = create_app(config)
    client = app.test_client()
    response = client.post("/", data={}, follow_redirects=True)
    assert response.status_code == 200
    assert "请选择" in response.get_data(as_text=True)
    assert client.get("/tasks?q=missing&status=passed&date_from=2024-01-01").status_code == 200
    assert client.get("/healthz").json["status"] == "ok"
    assert client.get("/missing").status_code == 404
    assert client.get("/tasks/not-found").status_code == 404
