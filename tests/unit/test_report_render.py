"""多格式报告渲染单元测试。"""

import json

import pytest

from gateway.report.renderer import build_report_context, render_reports


def _task(passed=False):
    return {
        "task_id": "task001", "packet_name": "mock.zip", "packet_size": 123,
        "archive_type": "zip", "uploaded_at": "2024-03-01T00:00:00",
        "duration_seconds": 0.25, "contract_name": "contract.yaml",
        "lineage_name": "lineage.yaml", "passed": passed,
    }


def _results():
    return [
        {"key": "archive", "name": "压缩包安全与结构检查", "passed": True,
         "summary": "通过", "errors": [], "samples": []},
        {"key": "hash", "name": "文件完整性", "passed": False, "summary": "失败",
         "errors": [{"code": "hash_mismatch", "path": "data/a.csv",
                     "message": "哈希不一致"}], "samples": []},
        {"key": "schema", "name": "Schema", "passed": False, "summary": "失败",
         "tables": [{"error_rows": 3, "samples": [{"table": "t", "field": "id",
                                                   "row": 2, "message": "类型错误"}]}],
         "errors": [{"code": "type", "table": "t", "field": "id", "row": 2,
                     "message": "类型错误"}],
         "samples": [{"table": "t", "field": "id", "row": 2, "message": "类型错误"}]},
        {"key": "lineage", "name": "血缘", "passed": False, "summary": "失败",
         "relations": [{"name": "rel", "passed": False, "left_table": "a",
                        "left_field": "id",
                        "errors": [{"code": "orphan_record", "message": "孤立记录"}]}],
         "graph": {"text": "链路", "mermaid": "graph LR", "broken_nodes": ["a"]},
         "samples": []},
        {"key": "anomaly", "name": "异常值", "passed": False, "summary": "失败",
         "fields": [{"table": "t", "field": "num", "failed_rules": 1,
                      "rules": [{"rule": "range", "passed": False, "rate": 0.5,
                                 "threshold": 0.0, "violations": 1}]}],
         "samples": [{"table": "t", "field": "num", "row": 3, "value": 99,
                      "message": "越界"}]},
    ]


def test_build_context_collects_issues_and_suggestions(config):
    report = build_report_context(_task(), _results(), config,
                                  generated_at="2024-03-01T12:00:00")
    assert report["pass_rate"] == 20.0
    assert not report["overall_passed"]
    assert report["passed_checks"] == 1
    assert len(report["issues"]) == 4
    assert report["checks"][2]["error_count"] == 3
    assert report["checks"][3]["error_count"] == 1
    assert report["checks"][4]["error_count"] == 1
    assert any("manifest" in item for item in report["suggestions"])
    assert report["lineage_graph"]["broken_nodes"] == ["a"]
    assert report["meta"]["config_hash"] == config.fingerprint()


def test_all_pass_default_suggestion(config):
    results = [{"key": "archive", "name": "压缩包", "passed": True,
                "summary": "通过", "errors": []}]
    report = build_report_context(_task(True), results, config)
    assert report["overall_passed"]
    assert "未发现阻断性问题" in report["suggestions"][0]


def test_render_three_formats_is_offline(config):
    report = build_report_context(_task(), _results(), config,
                                  generated_at="2024-03-01T12:00:00")
    paths = render_reports(report, config, "task001")
    html = paths["html"] and open(paths["html"], encoding="utf-8").read()
    markdown = open(paths["md"], encoding="utf-8").read()
    parsed = json.loads(open(paths["json"], encoding="utf-8").read())
    assert "数据包准入校验报告" in html
    assert "http://" not in html and "https://" not in html
    assert "<script src" not in html and "<link " not in html
    assert "Mermaid 源码" in html
    assert "修复建议" in markdown
    assert "graph LR" in markdown
    assert parsed["task"]["task_id"] == "task001"
    assert parsed["meta"]["tool_version"]


def test_render_rejects_path_traversal_task_id(config):
    report = build_report_context(_task(), _results(), config)
    with pytest.raises(ValueError, match="任务 ID"):
        render_reports(report, config, "../evil")


def test_empty_results(config):
    report = build_report_context(_task(True), [], config)
    assert report["pass_rate"] == 0.0
    assert report["overall_passed"]
    assert report["issues"] == []


def test_issue_deduplication(config):
    duplicate = {"key": "hash", "name": "哈希", "passed": False, "summary": "x",
                 "errors": [{"code": "hash_mismatch", "path": "a", "message": "m"},
                            {"code": "hash_mismatch", "path": "a", "message": "m"}]}
    report = build_report_context(_task(), [duplicate], config)
    assert len(report["issues"]) == 1
