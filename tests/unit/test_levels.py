"""阻断级别模型与配置集成单元测试。"""

import json
from hashlib import sha256

import pytest
import yaml

from gateway.config import AppConfig, load_config
from gateway.levels import (BLOCK, DEGRADE, DEFAULT_STAGE_LEVELS,
                            PINNED_BLOCK_RULES, STAGE_SEQUENCE,
                            annotate_errors, error_level, normalize_rule_levels,
                            normalize_stage_levels, result_error_codes,
                            result_is_blocking)


def test_default_stage_levels_match_legacy_behavior():
    """默认级别与历史行为一致：仅压缩包安全阶段阻断。"""
    levels = normalize_stage_levels(None)
    assert levels == DEFAULT_STAGE_LEVELS
    assert levels["archive"] == BLOCK
    assert all(levels[key] == DEGRADE for key in STAGE_SEQUENCE if key != "archive")


def test_stage_level_overrides_and_aliases():
    levels = normalize_stage_levels({"hash": "block", "schema": "降级"})
    assert levels["hash"] == BLOCK
    assert levels["schema"] == DEGRADE
    assert levels["lineage"] == DEGRADE
    assert normalize_stage_levels({"hash": "阻断"})["hash"] == BLOCK


def test_stage_level_rejects_invalid_config():
    with pytest.raises(ValueError, match="未知校验阶段"):
        normalize_stage_levels({"ghost": "block"})
    with pytest.raises(ValueError, match="block/degrade"):
        normalize_stage_levels({"hash": "sometimes"})
    with pytest.raises(ValueError, match="映射"):
        normalize_stage_levels(["hash"])
    with pytest.raises(ValueError, match="不允许配置为降级"):
        normalize_stage_levels({"archive": "degrade"})


def test_rule_levels_pinned_rules_cannot_degrade():
    assert "dangerous_file" in PINNED_BLOCK_RULES
    assert "path_traversal" in PINNED_BLOCK_RULES
    assert "zip_bomb" in PINNED_BLOCK_RULES
    assert "table_read_error" in PINNED_BLOCK_RULES
    for code in ("dangerous_file", "path_traversal", "table_read_error"):
        with pytest.raises(ValueError, match="不允许配置为降级"):
            normalize_rule_levels({code: "degrade"})
    levels = normalize_rule_levels({"hash_mismatch": "block", "type": "degrade"})
    assert levels == {"hash_mismatch": BLOCK, "type": DEGRADE}
    assert normalize_rule_levels(None) == {}
    with pytest.raises(ValueError, match="映射"):
        normalize_rule_levels("hash_mismatch")
    with pytest.raises(ValueError, match="空规则名"):
        normalize_rule_levels({"  ": "block"})


def test_error_level_precedence():
    rules = {"hash_mismatch": BLOCK}
    assert error_level("dangerous_file", rules, DEGRADE) == BLOCK
    assert error_level("hash_mismatch", rules, DEGRADE) == BLOCK
    assert error_level("missing_file", rules, DEGRADE) == DEGRADE
    assert error_level("missing_file", rules, BLOCK) == BLOCK
    assert error_level(None, rules, DEGRADE) == DEGRADE


def test_annotate_errors_marks_levels():
    errors = [{"code": "hash_mismatch", "message": "a"},
              {"code": "dangerous_file", "message": "b"},
              {"message": "no-code"}]
    annotate_errors(errors, {"hash_mismatch": BLOCK}, DEGRADE)
    assert errors[0]["level"] == BLOCK
    assert errors[1]["level"] == BLOCK
    assert errors[2]["level"] == DEGRADE
    annotate_errors([], {}, DEGRADE)
    annotate_errors(None, {}, DEGRADE)


def test_result_is_blocking_by_stage_and_rule():
    failed = {"key": "hash", "passed": False,
              "errors": [{"code": "hash_mismatch"}]}
    assert not result_is_blocking(failed, DEFAULT_STAGE_LEVELS, {})
    assert result_is_blocking(failed, {**DEFAULT_STAGE_LEVELS, "hash": BLOCK}, {})
    assert result_is_blocking(failed, DEFAULT_STAGE_LEVELS,
                              {"hash_mismatch": BLOCK})
    dangerous = {"key": "hash", "passed": False,
                 "errors": [{"code": "dangerous_file"}]}
    assert result_is_blocking(dangerous, DEFAULT_STAGE_LEVELS, {})
    passed = {"key": "hash", "passed": True, "errors": []}
    assert not result_is_blocking(passed, DEFAULT_STAGE_LEVELS, {})
    archive = {"key": "archive", "passed": False,
               "errors": [{"code": "archive_error"}]}
    assert result_is_blocking(archive, DEFAULT_STAGE_LEVELS, {})
    no_codes = {"key": "schema", "passed": False, "errors": []}
    assert not result_is_blocking(no_codes, DEFAULT_STAGE_LEVELS, {})
    assert result_is_blocking(no_codes, {**DEFAULT_STAGE_LEVELS, "schema": BLOCK}, {})


def test_result_error_codes_extracts_nested():
    lineage = {"key": "lineage", "passed": False,
               "errors": [{"code": "relation_failed"}],
               "relations": [{"errors": [{"code": "orphan_record"}]}]}
    assert result_error_codes(lineage) == {"relation_failed", "orphan_record"}
    anomaly = {"key": "anomaly", "passed": False, "errors": [],
               "fields": [{"rules": [{"rule": "null_rate", "passed": False},
                                     {"rule": "range", "passed": True}]}]}
    assert result_error_codes(anomaly) == {"null_rate"}
    blocking = result_is_blocking(anomaly, DEFAULT_STAGE_LEVELS,
                                  {"null_rate": BLOCK})
    assert blocking


def test_appconfig_level_defaults_and_overrides(tmp_path):
    config = AppConfig(workspace_dir=tmp_path / "ws")
    assert config.stage_levels == DEFAULT_STAGE_LEVELS
    assert config.rule_levels == {}
    custom = AppConfig(workspace_dir=tmp_path / "ws2",
                       stage_levels={"hash": "block"},
                       rule_levels={"type": "block"})
    assert custom.stage_levels["hash"] == BLOCK
    assert custom.stage_levels["schema"] == DEGRADE
    assert custom.rule_levels == {"type": BLOCK}
    with pytest.raises(ValueError, match="不允许配置为降级"):
        AppConfig(workspace_dir=tmp_path / "ws3",
                  rule_levels={"zip_bomb": "degrade"})


def test_load_config_from_yaml(tmp_path, monkeypatch):
    monkeypatch.delenv("GATEWAY_WORKSPACE", raising=False)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({
        "workspace_dir": str(tmp_path / "ws"),
        "stage_levels": {"hash": "block"},
        "rule_levels": {"redundant_file": "block"},
    }), encoding="utf-8")
    config = load_config(path)
    assert config.stage_levels["hash"] == BLOCK
    assert config.rule_levels == {"redundant_file": BLOCK}
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"workspace_dir": str(tmp_path / "ws_bad"),
                                   "stage_levels": {"archive": "degrade"}}),
                   encoding="utf-8")
    with pytest.raises(ValueError, match="不允许配置为降级"):
        load_config(bad)
    # 非法配置在建目录前失败，不产生工作目录副作用。
    assert not (tmp_path / "ws_bad").exists()


def test_fingerprint_stable_for_default_levels(tmp_path):
    """默认级别下配置指纹与历史版本完全一致，便于存量任务比对。"""
    config = AppConfig(workspace_dir=tmp_path / "ws")
    legacy_snapshot = {
        "sample_ratio": config.sample_ratio,
        "max_uncompressed_bytes": config.max_uncompressed_bytes,
        "max_archive_entries": config.max_archive_entries,
        "max_compression_ratio": config.max_compression_ratio,
        "blocked_extensions": list(config.blocked_extensions),
        "allowed_extra_paths": list(config.allowed_extra_paths),
    }
    raw = json.dumps(legacy_snapshot, sort_keys=True, ensure_ascii=False)
    assert config.fingerprint() == sha256(raw.encode("utf-8")).hexdigest()[:16]
    explicit_default = AppConfig(
        workspace_dir=tmp_path / "ws",
        stage_levels={key: value for key, value in DEFAULT_STAGE_LEVELS.items()})
    assert explicit_default.fingerprint() == config.fingerprint()
    tightened = AppConfig(workspace_dir=tmp_path / "ws",
                          stage_levels={"hash": "block"})
    assert tightened.fingerprint() != config.fingerprint()
