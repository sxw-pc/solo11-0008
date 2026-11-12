"""降级执行流程集成测试。

覆盖：默认配置下数据类问题降级继续、安全类规则钉死阻断、阶段/规则级
配置收紧、表读取失败回退终止、降级结果持久化与连续多轮降级任务的
临时文件清理和 SQLite 写入稳定性。
"""

from concurrent.futures import ThreadPoolExecutor
from hashlib import md5, sha256
from pathlib import Path
import json
import zipfile

import pandas as pd
import pytest
import yaml

from gateway.app import create_app
from gateway.config import AppConfig
from gateway.pipeline import run_validation

MINI_CONTRACT = """
version: "1.0"
name: mini_contract
tables:
  users:
    fields:
      user_id: {type: string, required: true}
      age: {type: integer, required: true}
  orders:
    fields:
      order_id: {type: string, required: true}
      user_id: {type: string, required: true}
anomaly_rules:
  users:
    age:
      - rule: range
        min: 0
        max: 150
"""

MINI_LINEAGE = """
relations:
  - name: order_owner
    left: {table: orders, field: user_id}
    right: {table: users, field: user_id}
    relationship: many_to_one
"""

TABLES = {
    "users": {"path": "data/users.csv", "format": "csv"},
    "orders": {"path": "data/orders.csv", "format": "csv"},
}

USERS = [{"user_id": "U001", "age": 30}, {"user_id": "U002", "age": 40}]
ORDERS = [{"order_id": "O001", "user_id": "U001"},
          {"order_id": "O002", "user_id": "U002"}]


def _csv(rows):
    return pd.DataFrame(rows).to_csv(index=False).encode("utf-8")


def _base_files(users=None, orders=None):
    return {
        "data/users.csv": _csv(USERS if users is None else users),
        "data/orders.csv": _csv(ORDERS if orders is None else orders),
    }


def _packet(path, files, tables=None, tamper=(), extra_manifest=None,
            undeclared=()):
    """在指定路径构造一个 zip 数据包，自动写入正确哈希。

    Args:
        undeclared: 只打入压缩包、不写入 manifest.files 声明的文件，
            用于构造冗余/高危文件场景。
    """
    declared = {rel: data for rel, data in files.items() if rel not in undeclared}
    manifest = {
        "schema_version": "1.0",
        "packet": {"name": path.stem},
        "tables": TABLES if tables is None else tables,
        "files": {rel: {"md5": md5(data).hexdigest(),
                        "sha256": sha256(data).hexdigest()}
                  for rel, data in declared.items()},
    }
    if extra_manifest:
        manifest.update(extra_manifest)
    for rel in tamper:
        manifest["files"][rel]["sha256"] = "0" * 64
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.yaml",
                         yaml.safe_dump(manifest, allow_unicode=True))
        for rel, data in files.items():
            archive.writestr(rel, data)
    return path


@pytest.fixture
def mini_contract(tmp_path):
    path = tmp_path / "contract.yaml"
    path.write_text(MINI_CONTRACT, encoding="utf-8")
    return path


@pytest.fixture
def mini_lineage(tmp_path):
    path = tmp_path / "lineage.yaml"
    path.write_text(MINI_LINEAGE, encoding="utf-8")
    return path


@pytest.fixture
def full_config(tmp_path):
    """sample_ratio=1.0，保证小样本数据全部进入 Schema/异常校验。"""
    return AppConfig(workspace_dir=tmp_path / "workspace", sample_ratio=1.0)


@pytest.fixture
def full_store(full_config):
    from gateway.store.sqlite_store import SQLiteStore
    return SQLiteStore(full_config.db_path)


def _by_key(results, key):
    return next(item for item in results if item["key"] == key)


def _run(config, store, packet, contract, lineage, **kwargs):
    return run_validation(packet, packet.name, config, store,
                          contract_path=contract, lineage_path=lineage, **kwargs)


def test_valid_mini_packet_passes(full_config, full_store, tmp_path,
                                  mini_contract, mini_lineage):
    packet = _packet(tmp_path / "ok.zip", _base_files())
    outcome = _run(full_config, full_store, packet, mini_contract, mini_lineage)
    assert outcome["task"]["status"] == "passed", outcome["task"]["error_summary"]
    assert outcome["task"]["degraded"] is False
    assert not list(full_config.temp_dir.iterdir())


def test_hash_mismatch_degrades_and_continues(full_config, full_store, tmp_path,
                                              mini_contract, mini_lineage):
    """默认配置下哈希不一致降级：后续阶段全部执行，问题一次收集。"""
    packet = _packet(tmp_path / "tampered.zip", _base_files(),
                     tamper=("data/orders.csv",))
    outcome = _run(full_config, full_store, packet, mini_contract, mini_lineage)
    task = outcome["task"]
    assert task["status"] == "failed"
    assert task["degraded"] is True
    keys = [item["key"] for item in outcome["results"]]
    assert keys == ["archive", "hash", "table_read", "schema", "lineage", "anomaly"]
    hash_result = _by_key(outcome["results"], "hash")
    assert hash_result["degraded"] is True
    assert "hash_mismatch" in hash_result["error_codes"]
    assert _by_key(outcome["results"], "schema")["passed"]
    assert _by_key(outcome["results"], "lineage")["passed"]
    # 降级阶段的校验结果完整留存在 SQLite 与报告中。
    stored = full_store.get_task(task["task_id"])
    assert stored["degraded"] is True
    assert stored["degradation"]["degraded_stages"] == ["hash"]
    assert stored["degradation"]["terminated_at"] is None
    report = outcome["report"]
    assert report["degradation"]["active"]
    assert report["degradation"]["degraded_names"] == ["文件完整性与哈希校验"]
    parsed = json.loads(Path(outcome["report_paths"]["json"]).read_text("utf-8"))
    assert parsed["degradation"]["degraded_stages"] == ["hash"]
    markdown = Path(outcome["report_paths"]["md"]).read_text("utf-8")
    assert "降级执行" in markdown and "已降级" in markdown
    assert not list(full_config.temp_dir.iterdir())


def test_schema_type_error_degrades(full_config, full_store, tmp_path,
                                    mini_contract, mini_lineage):
    bad_users = [{"user_id": "U001", "age": "abc"},
                 {"user_id": "U002", "age": "def"}]
    packet = _packet(tmp_path / "bad_schema.zip", _base_files(users=bad_users))
    outcome = _run(full_config, full_store, packet, mini_contract, mini_lineage)
    schema = _by_key(outcome["results"], "schema")
    assert schema["degraded"] is True
    assert any(error["code"] == "type" for error in schema["errors"])
    assert all(error.get("level") == "degrade" for error in schema["errors"])
    # 后续血缘、异常抽检仍然执行。
    assert _by_key(outcome["results"], "lineage")["passed"]
    assert "anomaly" in [item["key"] for item in outcome["results"]]
    assert outcome["task"]["status"] == "failed"


def test_dangerous_file_is_pinned_blocking(full_config, full_store, tmp_path,
                                           mini_contract, mini_lineage):
    """高危可执行文件属于安全类规则：默认配置下命中即终止。"""
    files = _base_files()
    files["payload.exe"] = b"MZ-mock"
    packet = _packet(tmp_path / "evil.zip", files, undeclared=("payload.exe",))
    outcome = _run(full_config, full_store, packet, mini_contract, mini_lineage)
    hash_result = _by_key(outcome["results"], "hash")
    assert hash_result["terminated"] is True
    assert "dangerous_file" in hash_result["error_codes"]
    levels = {error["code"]: error.get("level")
              for error in hash_result["errors"]}
    assert levels["dangerous_file"] == "block"
    assert levels["redundant_file"] == "degrade"
    keys = [item["key"] for item in outcome["results"]]
    assert keys == ["archive", "hash", "table_read", "schema", "lineage", "anomaly"]
    assert all(item.get("skipped") for item in outcome["results"][2:])
    degradation = outcome["report"]["degradation"]
    assert degradation["terminated_at"] == "hash"
    assert degradation["degraded_stages"] == []
    assert outcome["task"]["status"] == "failed"
    assert not list(full_config.temp_dir.iterdir())


def test_stage_level_block_config(tmp_path, mini_contract, mini_lineage):
    """stage_levels 可将哈希阶段收紧为阻断。"""
    config = AppConfig(workspace_dir=tmp_path / "ws", sample_ratio=1.0,
                       stage_levels={"hash": "block"})
    from gateway.store.sqlite_store import SQLiteStore
    store = SQLiteStore(config.db_path)
    packet = _packet(tmp_path / "tampered.zip", _base_files(),
                     tamper=("data/orders.csv",))
    outcome = _run(config, store, packet, mini_contract, mini_lineage)
    hash_result = _by_key(outcome["results"], "hash")
    assert hash_result["terminated"] is True
    assert all(item.get("skipped") for item in outcome["results"][2:])
    assert outcome["report"]["degradation"]["terminated_at"] == "hash"
    assert not list(config.temp_dir.iterdir())


def test_rule_level_block_overrides_stage(tmp_path, mini_contract, mini_lineage):
    """单条规则可单独收紧为阻断，其余数据类规则仍降级。"""
    config = AppConfig(workspace_dir=tmp_path / "ws", sample_ratio=1.0,
                       rule_levels={"type": "block"})
    from gateway.store.sqlite_store import SQLiteStore
    store = SQLiteStore(config.db_path)
    bad_users = [{"user_id": "U001", "age": "abc"},
                 {"user_id": "U002", "age": "def"}]
    packet = _packet(tmp_path / "bad_schema.zip", _base_files(users=bad_users))
    outcome = _run(config, store, packet, mini_contract, mini_lineage)
    schema = _by_key(outcome["results"], "schema")
    assert schema["terminated"] is True
    keys = [item["key"] for item in outcome["results"]]
    assert keys == ["archive", "hash", "table_read", "schema", "lineage", "anomaly"]
    assert _by_key(outcome["results"], "lineage").get("skipped")
    assert _by_key(outcome["results"], "anomaly").get("skipped")
    assert not list(config.temp_dir.iterdir())


def test_lineage_rule_level_block(tmp_path, mini_contract, mini_lineage):
    config = AppConfig(workspace_dir=tmp_path / "ws", sample_ratio=1.0,
                       rule_levels={"orphan_record": "block"})
    from gateway.store.sqlite_store import SQLiteStore
    store = SQLiteStore(config.db_path)
    broken_orders = [{"order_id": "O001", "user_id": "U999"},
                     {"order_id": "O002", "user_id": "U002"}]
    packet = _packet(tmp_path / "broken.zip", _base_files(orders=broken_orders))
    outcome = _run(config, store, packet, mini_contract, mini_lineage)
    lineage = _by_key(outcome["results"], "lineage")
    assert lineage["terminated"] is True
    assert _by_key(outcome["results"], "anomaly").get("skipped")
    assert outcome["report"]["degradation"]["terminated_at"] == "lineage"


def test_table_read_failure_falls_back_to_termination(
        full_config, full_store, tmp_path, mini_contract, mini_lineage):
    """表读取失败（临时文件损坏/表损坏）自动回退到原有终止逻辑。"""
    files = _base_files()
    files["data/products.parquet"] = b"not-a-parquet-file"
    tables = dict(TABLES)
    tables["products"] = {"path": "data/products.parquet", "format": "parquet"}
    packet = _packet(tmp_path / "corrupt.zip", files, tables=tables)
    outcome = _run(full_config, full_store, packet, mini_contract, mini_lineage)
    table_read = _by_key(outcome["results"], "table_read")
    assert table_read["terminated"] is True
    assert table_read["errors"][0]["code"] == "table_read_error"
    assert all(item.get("skipped") for item in outcome["results"][3:])
    assert outcome["report"]["degradation"]["terminated_at"] == "table_read"
    assert outcome["task"]["status"] == "failed"
    assert not list(full_config.temp_dir.iterdir())


def test_table_read_error_cannot_be_degraded(tmp_path):
    with pytest.raises(ValueError, match="不允许配置为降级"):
        AppConfig(workspace_dir=tmp_path / "ws",
                  rule_levels={"table_read_error": "degrade"})


def test_infra_exception_during_degradation_falls_back(
        full_config, full_store, tmp_path, mini_contract, mini_lineage,
        monkeypatch):
    """降级执行过程中遇到表读取异常，立即回退终止并清理临时目录。"""
    packet = _packet(tmp_path / "tampered.zip", _base_files(),
                     tamper=("data/orders.csv",))

    def corrupt_read(*args, **kwargs):
        from gateway.parser.table_reader import TableReadError
        raise TableReadError("模拟临时文件损坏")

    monkeypatch.setattr("gateway.pipeline.read_manifest_table", corrupt_read)
    outcome = _run(full_config, full_store, packet, mini_contract, mini_lineage)
    hash_result = _by_key(outcome["results"], "hash")
    assert hash_result["degraded"] is True
    table_read = _by_key(outcome["results"], "table_read")
    assert table_read["terminated"] is True
    assert all(item.get("skipped") for item in outcome["results"][3:])
    assert outcome["task"]["status"] == "failed"
    assert not list(full_config.temp_dir.iterdir())


def test_no_tables_declared_degrades(full_config, full_store, tmp_path,
                                     mini_contract, mini_lineage):
    """manifest 未声明业务表属于数据问题，降级继续并暴露各阶段明细。"""
    packet = _packet(tmp_path / "empty.zip", _base_files(), tables={})
    outcome = _run(full_config, full_store, packet, mini_contract, mini_lineage)
    table_read = _by_key(outcome["results"], "table_read")
    assert table_read["degraded"] is True
    assert table_read["errors"][0]["code"] == "no_tables_declared"
    schema = _by_key(outcome["results"], "schema")
    assert not schema["passed"]
    assert outcome["task"]["status"] == "failed"
    assert not list(full_config.temp_dir.iterdir())


def test_contract_error_is_infrastructure_blocking(
        full_config, full_store, tmp_path, mini_lineage):
    bad_contract = tmp_path / "broken_contract.yaml"
    bad_contract.write_text("tables: [not-a-map]\n", encoding="utf-8")
    packet = _packet(tmp_path / "ok.zip", _base_files())
    outcome = _run(full_config, full_store, packet, bad_contract, mini_lineage)
    schema = _by_key(outcome["results"], "schema")
    assert schema["terminated"] is True
    assert schema["errors"][0]["code"] == "contract_error"
    assert _by_key(outcome["results"], "lineage").get("skipped")
    assert _by_key(outcome["results"], "anomaly").get("skipped")
    assert not list(full_config.temp_dir.iterdir())


def test_lineage_rule_error_is_infrastructure_blocking(
        full_config, full_store, tmp_path, mini_contract):
    bad_lineage = tmp_path / "broken_lineage.yaml"
    bad_lineage.write_text("relations: not-a-list\n", encoding="utf-8")
    packet = _packet(tmp_path / "ok.zip", _base_files())
    outcome = _run(full_config, full_store, packet, mini_contract, bad_lineage)
    lineage = _by_key(outcome["results"], "lineage")
    assert lineage["terminated"] is True
    assert lineage["errors"][0]["code"] == "lineage_rule_error"
    assert _by_key(outcome["results"], "anomaly").get("skipped")
    assert not list(full_config.temp_dir.iterdir())


def test_unexpected_exception_keeps_cleanup_and_failure(
        full_config, full_store, tmp_path, mini_contract, mini_lineage,
        monkeypatch):
    """降级执行中出现未预期异常：记录内部错误、任务失败、临时目录清理。"""
    packet = _packet(tmp_path / "ok.zip", _base_files())

    def boom(*args, **kwargs):
        raise RuntimeError("模拟内部异常")

    monkeypatch.setattr("gateway.pipeline.verify_hashes", boom)
    outcome = _run(full_config, full_store, packet, mini_contract, mini_lineage)
    assert outcome["task"]["status"] == "failed"
    internal = _by_key(outcome["results"], "internal")
    assert "模拟内部异常" in internal["summary"]
    assert not list(full_config.temp_dir.iterdir())


def test_consecutive_degraded_runs_leave_no_residue(
        full_config, full_store, tmp_path, mini_contract, mini_lineage):
    """连续提交多轮降级任务：无临时文件残留、无 SQLite 锁冲突。"""
    packets = []
    for index in range(6):
        packets.append(_packet(tmp_path / ("round%d.zip" % index),
                               _base_files(), tamper=("data/orders.csv",)))
    task_ids = []
    for packet in packets:
        outcome = _run(full_config, full_store, packet,
                       mini_contract, mini_lineage)
        assert outcome["task"]["status"] == "failed"
        assert outcome["task"]["degraded"] is True
        task_ids.append(outcome["task"]["task_id"])
        assert not list(full_config.temp_dir.iterdir())
    assert len(set(task_ids)) == 6
    assert full_store.stats()["failed"] == 6
    for task_id in task_ids:
        stored = full_store.get_task(task_id)
        assert stored["degradation"]["degraded_stages"] == ["hash"]


def test_concurrent_degraded_runs_no_sqlite_lock(
        full_config, full_store, tmp_path, mini_contract, mini_lineage):
    packets = [_packet(tmp_path / ("concurrent%d.zip" % index), _base_files(),
                       tamper=("data/orders.csv",)) for index in range(4)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_run, full_config, full_store, packet,
                               mini_contract, mini_lineage)
                   for packet in packets]
        outcomes = [future.result() for future in futures]
    assert all(outcome["task"]["status"] == "failed" for outcome in outcomes)
    assert len({outcome["task"]["task_id"] for outcome in outcomes}) == 4
    assert full_store.stats()["failed"] == 4
    assert not list(full_config.temp_dir.iterdir())


def test_web_flow_shows_degradation(full_config, tmp_path,
                                    mini_contract, mini_lineage):
    """Web 上传降级任务：详情页与列表页展示降级信息，报告可下载。"""
    packet = _packet(tmp_path / "tampered.zip", _base_files(),
                     tamper=("data/orders.csv",))
    app = create_app(full_config)
    client = app.test_client()
    with packet.open("rb") as packet_handle, \
            mini_contract.open("rb") as contract_handle, \
            mini_lineage.open("rb") as lineage_handle:
        response = client.post("/", data={
            "packet": (packet_handle, "tampered.zip"),
            "contract": (contract_handle, "contract.yaml"),
            "lineage": (lineage_handle, "lineage.yaml"),
        }, content_type="multipart/form-data")
    assert response.status_code == 302
    detail_url = response.headers["Location"]
    detail = client.get(detail_url).get_data(as_text=True)
    assert "降级执行" in detail
    assert "已降级" in detail
    assert "准入不通过" in detail
    task_id = detail_url.rstrip("/").split("/")[-1]
    listing = client.get("/tasks").get_data(as_text=True)
    assert "含降级" in listing
    for fmt in ("html", "md", "json"):
        report = client.get("/tasks/%s/report/%s" % (task_id, fmt))
        assert report.status_code == 200
        if fmt == "json":
            parsed = json.loads(report.get_data(as_text=True))
            assert parsed["degradation"]["degraded_stages"] == ["hash"]
        report.close()
    assert not list(full_config.temp_dir.iterdir())
