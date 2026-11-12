"""降级执行信息的报告渲染单元测试。"""

import json

from gateway.report.renderer import build_report_context, render_reports


def _task(passed=False):
    return {
        "task_id": "task009", "packet_name": "mock.zip", "packet_size": 123,
        "archive_type": "zip", "uploaded_at": "2024-03-01T00:00:00",
        "duration_seconds": 0.25, "contract_name": "contract.yaml",
        "lineage_name": "lineage.yaml", "passed": passed,
    }


def _degraded_results():
    return [
        {"key": "archive", "name": "压缩包安全与结构检查", "passed": True,
         "summary": "通过", "errors": [], "samples": []},
        {"key": "hash", "name": "文件完整性与哈希校验", "passed": False,
         "degraded": True, "summary": "发现 1 项完整性问题",
         "errors": [{"code": "hash_mismatch", "path": "data/a.csv",
                     "message": "哈希不一致", "level": "degrade"}],
         "samples": []},
        {"key": "schema", "name": "数据契约 Schema 校验", "passed": True,
         "summary": "通过", "errors": [], "samples": []},
    ]


def test_degradation_context_from_markers(config):
    report = build_report_context(_task(), _degraded_results(), config,
                                  generated_at="2024-03-01T12:00:00")
    degradation = report["degradation"]
    assert degradation["active"]
    assert degradation["degraded_stages"] == ["hash"]
    assert degradation["degraded_names"] == ["文件完整性与哈希校验"]
    assert degradation["terminated_at"] is None
    assert degradation["levels"]["archive"] == "block"
    assert degradation["levels"]["hash"] == "degrade"
    hash_check = report["checks"][1]
    assert hash_check["degraded"] is True
    assert hash_check["level"] == "degrade"
    assert report["issues"][0]["level"] == "degrade"


def test_degradation_in_rendered_reports(config):
    report = build_report_context(_task(), _degraded_results(), config,
                                  generated_at="2024-03-01T12:00:00")
    paths = render_reports(report, config, "task009")
    markdown = open(paths["md"], encoding="utf-8").read()
    html = open(paths["html"], encoding="utf-8").read()
    parsed = json.loads(open(paths["json"], encoding="utf-8").read())
    assert "降级执行" in markdown
    assert "不通过（已降级）" in markdown
    assert "文件完整性与哈希校验" in markdown
    assert "降级执行" in html
    assert "不通过（已降级）" in html
    assert "http://" not in html and "https://" not in html
    assert parsed["degradation"]["degraded_stages"] == ["hash"]
    assert parsed["degradation"]["levels"]["archive"] == "block"


def test_terminated_and_skipped_rendering(config):
    results = [
        {"key": "archive", "name": "压缩包安全与结构检查", "passed": True,
         "summary": "通过", "errors": [], "samples": []},
        {"key": "hash", "name": "文件完整性与哈希校验", "passed": False,
         "terminated": True, "summary": "高危文件",
         "errors": [{"code": "dangerous_file", "message": "exe",
                     "level": "block"}], "samples": []},
        {"key": "schema", "name": "数据契约 Schema 校验", "passed": False,
         "skipped": True, "summary": "跳过：哈希校验命中阻断规则",
         "errors": [{"code": "skipped", "message": "跳过"}], "samples": []},
    ]
    report = build_report_context(_task(), results, config)
    degradation = report["degradation"]
    assert degradation["active"]
    assert degradation["terminated_at"] == "hash"
    assert degradation["terminated_name"] == "文件完整性与哈希校验"
    assert degradation["skipped_stages"] == ["schema"]
    assert report["checks"][1]["terminated"] is True
    assert report["checks"][2]["skipped"] is True
    paths = render_reports(report, config, "task009")
    markdown = open(paths["md"], encoding="utf-8").read()
    assert "不通过（阻断）" in markdown
    assert "跳过" in markdown


def test_legacy_results_without_markers(config):
    """历史任务数据没有降级标记时，报告照常渲染并反推终止点。"""
    results = [
        {"key": "archive", "name": "压缩包安全与结构检查", "passed": False,
         "summary": "疑似 Zip 炸弹",
         "errors": [{"code": "zip_bomb", "message": "炸弹"}], "samples": []},
        {"key": "hash", "name": "文件完整性与哈希校验", "passed": False,
         "summary": "跳过：压缩包安全检查未通过",
         "errors": [{"code": "skipped", "message": "跳过"}], "samples": []},
        {"key": "schema", "name": "数据契约 Schema 校验", "passed": False,
         "summary": "跳过：压缩包安全检查未通过",
         "errors": [{"code": "skipped", "message": "跳过"}], "samples": []},
    ]
    report = build_report_context(_task(), results, config)
    degradation = report["degradation"]
    assert degradation["terminated_at"] == "archive"
    assert degradation["degraded_stages"] == []
    assert degradation["skipped_stages"] == ["hash", "schema"]
    assert report["checks"][1]["skipped"] is True
    paths = render_reports(report, config, "task009")
    assert "降级执行" in open(paths["md"], encoding="utf-8").read()


def test_all_pass_has_inactive_degradation(config):
    results = [{"key": "archive", "name": "压缩包", "passed": True,
                "summary": "通过", "errors": []}]
    report = build_report_context(_task(True), results, config)
    assert not report["degradation"]["active"]
    paths = render_reports(report, config, "task009")
    markdown = open(paths["md"], encoding="utf-8").read()
    assert "未发生降级" in markdown


def test_explicit_degradation_param_preferred(config):
    degradation = {
        "levels": {"archive": "block", "hash": "block"},
        "degraded_stages": ["schema"], "terminated_at": "hash",
        "skipped_stages": ["lineage"],
    }
    report = build_report_context(_task(), [], config, degradation=degradation)
    assert report["degradation"]["levels"]["hash"] == "block"
    assert report["degradation"]["degraded_stages"] == ["schema"]
    assert report["degradation"]["terminated_at"] == "hash"
