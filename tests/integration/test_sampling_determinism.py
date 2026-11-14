"""异常抽检可复现性与抽样口径集成测试。"""

import json
from pathlib import Path

from gateway.pipeline import run_validation

ROOT = Path(__file__).resolve().parents[2]
VALID_PACKET = ROOT / "fixtures" / "valid_packets" / "retail_valid_a.zip"


def _anomaly(outcome):
    return next(item for item in outcome["results"] if item["key"] == "anomaly")


def _stable_blob(outcome):
    """剥离时间、耗时与任务 ID 后，报告内容应可逐字节复现。"""
    report = json.loads(Path(outcome["report_paths"]["json"]).read_text(encoding="utf-8"))
    report["meta"].pop("generated_at", None)
    for key in ("uploaded_at", "finished_at", "duration_seconds", "task_id"):
        report["task"].pop(key, None)
    return json.dumps(report, ensure_ascii=False, sort_keys=True, default=str)


def test_same_packet_two_runs_are_identical(config, store):
    first = run_validation(VALID_PACKET, VALID_PACKET.name, config, store,
                           task_id="det-run-1")
    second = run_validation(VALID_PACKET, VALID_PACKET.name, config, store,
                            task_id="det-run-2")
    a, b = _anomaly(first), _anomaly(second)
    # 抽检统计、规则结果与 Top20 样例完全一致
    assert a["fields"] == b["fields"]
    assert a["samples"] == b["samples"]
    assert _stable_blob(first) == _stable_blob(second)
    # 默认比例与种子保持生效
    assert config.sample_ratio == 0.1 and config.random_seed == 42
    # 临时目录已清理、两条历史都保留
    assert not list(config.temp_dir.iterdir())
    assert store.get_task("det-run-1") and store.get_task("det-run-2")


def test_failed_task_cleans_temp_and_keeps_history(config, store):
    redundant = (ROOT / "fixtures" / "invalid_packets" / "redundant_file"
                 / "redundant_file.zip")
    outcome = run_validation(redundant, redundant.name, config, store,
                             task_id="det-fail")
    assert outcome["task"]["status"] == "failed"
    assert not list(config.temp_dir.iterdir())
    stored = store.get_task("det-fail")
    assert stored is not None and stored["status"] == "failed"
    # 报告文件仍然落盘可供复核
    assert Path(outcome["report_paths"]["json"]).is_file()
