"""阶段调度、资源复用、异常回收与耗时落库集成测试。"""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import time
import zipfile

import pandas as pd
import pytest
import yaml

from gateway.app import create_app
from gateway.config import AppConfig
from gateway.parser.archive_loader import load_archive
from gateway.parser.table_reader import derive_sampled_table, read_manifest_table
from gateway.pipeline import run_validation

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
VALID_PACKET = FIXTURES / "valid_packets" / "retail_valid_a.zip"
VALID_PACKETS = sorted((FIXTURES / "valid_packets").iterdir())
HASH_TAMPERED = FIXTURES / "invalid_packets" / "hash_tampered" / "hash_tampered.zip"
SCHEMA_MISMATCH = FIXTURES / "invalid_packets" / "schema_mismatch" / "schema_mismatch.zip"
TRAVERSAL = FIXTURES / "invalid_packets" / "path_traversal" / "path_traversal.zip"

STAGE_KEYS = ["archive", "hash", "table_read", "schema", "lineage", "anomaly"]


def _by_key(results, key):
    return next(item for item in results if item["key"] == key)


def _strict_config(tmp_path):
    return AppConfig(workspace_dir=tmp_path / "workspace", continue_on_failure=False)


def _manifest_table_count(packet):
    with zipfile.ZipFile(packet) as archive:
        manifest = yaml.safe_load(archive.read("manifest.yaml").decode("utf-8"))
    return len(manifest.get("tables") or {})


# ---------------------------------------------------------------- 配置短路逻辑

def test_default_config_keeps_legacy_flow(config, store):
    """默认配置下前置阶段失败不阻断后续非核心阶段（与旧实现一致）。"""
    outcome = run_validation(HASH_TAMPERED, HASH_TAMPERED.name, config, store)
    assert [item["key"] for item in outcome["results"]] == STAGE_KEYS
    assert not _by_key(outcome["results"], "hash")["passed"]
    for key in ("schema", "lineage", "anomaly"):
        result = _by_key(outcome["results"], key)
        assert not result["summary"].startswith("跳过："), "默认配置下阶段应真实执行"
    assert outcome["task"]["status"] == "failed"
    assert not list(config.temp_dir.iterdir())


def test_continue_on_failure_disabled_skips_non_core(tmp_path):
    """严格模式下哈希失败后，核心阶段仍执行，非核心阶段记为跳过。"""
    config = _strict_config(tmp_path)
    from gateway.store.sqlite_store import SQLiteStore
    store = SQLiteStore(config.db_path)
    outcome = run_validation(HASH_TAMPERED, HASH_TAMPERED.name, config, store)
    results = outcome["results"]
    assert _by_key(results, "archive")["passed"]
    assert not _by_key(results, "hash")["passed"]
    assert _by_key(results, "table_read")["passed"], "核心表读取阶段不受开关影响"
    for key in ("schema", "lineage", "anomaly"):
        result = _by_key(results, key)
        assert not result["passed"]
        assert result["summary"].startswith("跳过：")
        assert result["errors"][0]["code"] == "skipped"
    assert outcome["task"]["status"] == "failed"
    metrics = {item["key"]: item for item in outcome["stage_metrics"]}
    for key in ("schema", "lineage", "anomaly"):
        assert metrics[key]["status"] == "skipped"
        assert metrics[key]["duration_seconds"] == 0.0
    assert metrics["hash"]["status"] == "failed"
    assert metrics["table_read"]["status"] == "passed"
    stored = store.get_task(outcome["task"]["task_id"])
    assert {item["key"] for item in stored["stages"]} == set(STAGE_KEYS)
    assert not list(config.temp_dir.iterdir())


def test_strict_mode_valid_packet_still_passes(tmp_path):
    """严格模式下合法数据包全部阶段真实执行并通过。"""
    config = _strict_config(tmp_path)
    from gateway.store.sqlite_store import SQLiteStore
    store = SQLiteStore(config.db_path)
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store)
    assert outcome["task"]["status"] == "passed"
    assert all(item["passed"] for item in outcome["results"])
    assert all(item["status"] == "passed" for item in outcome["stage_metrics"])


def test_strict_mode_schema_failure_skips_lineage_and_anomaly(tmp_path):
    """严格模式下 Schema 失败后，血缘与异常抽检记为跳过。"""
    config = _strict_config(tmp_path)
    from gateway.store.sqlite_store import SQLiteStore
    store = SQLiteStore(config.db_path)
    outcome = run_validation(SCHEMA_MISMATCH, SCHEMA_MISMATCH.name, config, store)
    results = outcome["results"]
    assert _by_key(results, "hash")["passed"]
    assert not _by_key(results, "schema")["passed"]
    for key in ("lineage", "anomaly"):
        assert _by_key(results, key)["errors"][0]["code"] == "skipped"


def test_archive_failure_identical_in_both_modes(config, store, tmp_path):
    """压缩包安全失败时两种配置产生完全一致的占位结果。"""
    default_outcome = run_validation(TRAVERSAL, TRAVERSAL.name, config, store)
    strict_config = _strict_config(tmp_path)
    from gateway.store.sqlite_store import SQLiteStore
    strict_store = SQLiteStore(strict_config.db_path)
    strict_outcome = run_validation(TRAVERSAL, TRAVERSAL.name, strict_config, strict_store)
    assert [item["key"] for item in default_outcome["results"]] == [
        "archive", "hash", "schema", "lineage", "anomaly"]
    assert default_outcome["results"] == strict_outcome["results"]
    metrics = {item["key"]: item["status"] for item in strict_outcome["stage_metrics"]}
    assert metrics == {"archive": "failed", "hash": "skipped",
                       "table_read": "skipped", "schema": "skipped",
                       "lineage": "skipped", "anomaly": "skipped"}
    assert not list(config.temp_dir.iterdir())
    assert not list(strict_config.temp_dir.iterdir())


def test_continue_on_failure_config_validation(tmp_path):
    with pytest.raises(ValueError, match="布尔"):
        AppConfig(workspace_dir=tmp_path / "ws", continue_on_failure="yes")
    config_file = tmp_path / "config.yaml"
    config_file.write_text("continue_on_failure: false\n", encoding="utf-8")
    assert AppConfig.from_yaml(config_file).continue_on_failure is False
    config_file.write_text("continue_on_failure: true\n", encoding="utf-8")
    assert AppConfig.from_yaml(config_file).continue_on_failure is True
    config_file.write_text("unknown_option: 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="未知配置项"):
        AppConfig.from_yaml(config_file)


# ---------------------------------------------------------------- 资源复用一致性

def test_table_files_read_from_disk_once(config, store, monkeypatch):
    """每张表只从磁盘读取一次，抽样表由全量表内存派生。"""
    calls = []
    import gateway.pipeline as pipeline_module
    original = pipeline_module.read_manifest_table

    def counting(*args, **kwargs):
        calls.append(args[1])
        return original(*args, **kwargs)

    monkeypatch.setattr(pipeline_module, "read_manifest_table", counting)
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store)
    assert outcome["task"]["status"] == "passed"
    expected = _manifest_table_count(VALID_PACKET)
    assert len(calls) == expected, "磁盘读取次数应等于表数量而非两倍"


def test_derived_sample_matches_disk_reread(config):
    """内存派生的抽样表与再次磁盘读取抽样的结果完全一致。"""
    with load_archive(VALID_PACKET, config) as extraction:
        for name in extraction.manifest["tables"]:
            full = read_manifest_table(extraction, name, config, sample=False)
            derived = derive_sampled_table(full, config)
            reread = read_manifest_table(extraction, name, config, sample=True)
            assert derived.name == reread.name
            assert derived.source_format == reread.source_format
            assert derived.total_rows == reread.total_rows
            assert derived.sampled_rows == reread.sampled_rows
            assert derived.sample_ratio == reread.sample_ratio
            assert derived.encoding == reread.encoding
            assert derived.sqlite_table == reread.sqlite_table
            assert derived.row_offset == reread.row_offset
            pd.testing.assert_frame_equal(derived.frame, reread.frame)
            assert full.total_rows == len(full.frame), "全量表不应被派生修改"


def test_package_hash_computed_once(config, store, monkeypatch):
    """整包哈希只计算一次，完整性校验阶段复用结果。"""
    import gateway.validator.hash_verify as hash_module
    original = hash_module.compute_file_hashes
    calls = []

    def counting(path):
        calls.append(str(path))
        return original(path)

    monkeypatch.setattr(hash_module, "compute_file_hashes", counting)
    expected = sha256(VALID_PACKET.read_bytes()).hexdigest()
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store,
                             expected_package_hash="sha256:" + expected)
    assert outcome["task"]["status"] == "passed"
    packet_reads = [path for path in calls
                    if Path(path) == VALID_PACKET or Path(path).suffix in (".zip", ".gz")]
    assert packet_reads == [], "verify_package_hash 不应重复读取整包: %s" % packet_reads
    assert calls, "manifest 声明文件的哈希仍应正常计算"


# ---------------------------------------------------------------- 异常回收

def test_uncaught_stage_exception_recovers_and_cleans(config, store, monkeypatch):
    """阶段抛出未捕获异常时：任务转为失败、临时目录回收、指标完整落库。"""
    import gateway.pipeline as pipeline_module

    def boom(*args, **kwargs):
        raise RuntimeError("mock stage crash")

    monkeypatch.setattr(pipeline_module, "validate_schema", boom)
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store)
    keys = [item["key"] for item in outcome["results"]]
    assert keys == ["archive", "hash", "table_read", "internal"]
    assert outcome["task"]["status"] == "failed"
    assert "内部异常" in outcome["task"]["error_summary"]
    assert not list(config.temp_dir.iterdir()), "异常后临时目录必须回收"
    metrics = {item["key"]: item for item in outcome["stage_metrics"]}
    assert [item["key"] for item in outcome["stage_metrics"]] == STAGE_KEYS
    assert metrics["schema"]["status"] == "failed"
    assert "RuntimeError" in metrics["schema"]["error_summary"]
    assert metrics["lineage"]["status"] == "skipped"
    assert metrics["anomaly"]["status"] == "skipped"
    stored = store.get_task(outcome["task"]["task_id"])
    assert stored["stages"] == outcome["stage_metrics"]
    log_text = (config.workspace_dir / outcome["task"]["log_path"]).read_text(
        encoding="utf-8")
    assert "流水线异常" in log_text
    assert "临时解压目录已清理" in log_text


def test_startup_sweep_removes_only_stale_dirs(config):
    """应用启动时清扫超龄残留目录，在途与其他前缀目录不受影响。"""
    stale = config.temp_dir / "gateway-stale0001"
    stale.mkdir()
    (stale / "junk.txt").write_text("x", encoding="utf-8")
    old = time.time() - 25 * 3600
    os.utime(stale, (old, old))
    fresh = config.temp_dir / "gateway-fresh0001"
    fresh.mkdir()
    upload = config.temp_dir / "upload-keep"
    upload.mkdir()
    create_app(config)
    assert not stale.exists(), "超龄残留目录应在启动时被清扫"
    assert fresh.exists(), "新目录可能属于在途任务，不得误删"
    assert upload.exists(), "非 gateway 前缀目录不得误删"


def test_concurrent_tasks_have_isolated_temp_dirs(config, store):
    """同一工作目录并发执行多个任务：目录不冲突、清理不互相影响。"""
    packets = VALID_PACKETS * 2
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(
            lambda packet: run_validation(packet, packet.name, config, store), packets))
    assert len({outcome["task"]["task_id"] for outcome in outcomes}) == len(packets)
    for outcome in outcomes:
        assert outcome["task"]["status"] == "passed", outcome["task"]["error_summary"]
        assert Path(outcome["report_paths"]["html"]).is_file()
    assert not list(config.temp_dir.iterdir()), "全部任务结束后不得残留临时目录"
    assert store.stats()["passed"] == len(packets)


# ---------------------------------------------------------------- 耗时落库准确性

def test_stage_metrics_persisted_accurately(config, store):
    """各阶段耗时、状态与失败原因完整写入任务历史表。"""
    outcome = run_validation(VALID_PACKET, VALID_PACKET.name, config, store)
    task = outcome["task"]
    metrics = outcome["stage_metrics"]
    assert [item["key"] for item in metrics] == STAGE_KEYS
    assert [item["name"] for item in metrics] == [
        "压缩包安全与结构检查", "文件完整性与哈希校验", "结构化表读取适配",
        "数据契约 Schema 校验", "跨表血缘一致性校验", "异常值抽检规则校验"]
    for item in metrics:
        assert item["status"] == "passed"
        assert item["duration_seconds"] >= 0
        assert item["error_summary"] == ""
    total = sum(item["duration_seconds"] for item in metrics)
    assert 0 < total <= task["duration_seconds"] + 0.1, \
        "阶段耗时之和不应超过任务总耗时"
    stored = store.get_task(task["task_id"])
    assert stored["stages"] == metrics, "落库的阶段指标应与执行结果一致"
    assert json.loads(stored["stage_metrics"]) == metrics
    assert stored["duration_seconds"] == task["duration_seconds"]


def test_failed_stage_metrics_carry_reason(config, store):
    """失败与跳过阶段在库中记录状态与原因，便于运维定位。"""
    outcome = run_validation(TRAVERSAL, TRAVERSAL.name, config, store)
    stored = store.get_task(outcome["task"]["task_id"])
    stages = {item["key"]: item for item in stored["stages"]}
    assert stages["archive"]["status"] == "failed"
    assert "穿越" in stages["archive"]["error_summary"]
    for key in ("hash", "table_read", "schema", "lineage", "anomaly"):
        assert stages[key]["status"] == "skipped"
        assert stages[key]["error_summary"]
    assert stages["archive"]["duration_seconds"] >= 0
