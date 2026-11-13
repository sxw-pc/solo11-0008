"""数值型配置解析、环境变量覆盖与默认行为单元测试。"""

from pathlib import Path

import pytest

from gateway.config import AppConfig, load_config


def test_string_numbers_are_coerced(tmp_path):
    """构造参数/YAML 中的字符串数值应被转换为正确的 Python 类型。"""
    config = AppConfig(
        workspace_dir=tmp_path / "ws",
        sample_ratio="0.2", max_archive_entries="123",
        max_uncompressed_bytes="1073741824", max_single_file_bytes="4294967296",
        max_compression_ratio="500", ratio_check_min_bytes="10485760",
        port="5077", random_seed="9", max_content_length="1610612736",
    )
    assert config.sample_ratio == 0.2 and isinstance(config.sample_ratio, float)
    assert config.max_archive_entries == 123 and isinstance(config.max_archive_entries, int)
    assert config.max_uncompressed_bytes == 1073741824
    assert config.max_single_file_bytes == 4294967296
    assert config.max_compression_ratio == 500.0
    assert config.ratio_check_min_bytes == 10485760
    assert config.port == 5077 and config.random_seed == 9
    assert config.max_content_length == 1610612736


def test_invalid_numbers_raise_readable_errors(tmp_path):
    """非法数值应抛出含配置项名称与取值的明确错误，而非裸类型错误。"""
    cases = {
        "sample_ratio": ("abc", "sample_ratio"),
        "max_archive_entries": ("1.5", "max_archive_entries"),
        "port": ("not-a-port", "port"),
        "max_compression_ratio": ("xx", "max_compression_ratio"),
    }
    for key, (value, label) in cases.items():
        with pytest.raises(ValueError) as excinfo:
            AppConfig(workspace_dir=tmp_path / key, **{key: value})
        assert label in str(excinfo.value)


def test_bool_and_inf_rejected(tmp_path):
    with pytest.raises(ValueError, match="布尔"):
        AppConfig(workspace_dir=tmp_path / "b1", sample_ratio=True)
    with pytest.raises(ValueError, match="有限"):
        AppConfig(workspace_dir=tmp_path / "b2", max_compression_ratio="inf")


def test_range_validation_unchanged(tmp_path):
    with pytest.raises(ValueError, match="sample_ratio"):
        AppConfig(workspace_dir=tmp_path / "r1", sample_ratio="0")
    with pytest.raises(ValueError, match="sample_ratio"):
        AppConfig(workspace_dir=tmp_path / "r2", sample_ratio="1.5")
    with pytest.raises(ValueError, match="条目上限"):
        AppConfig(workspace_dir=tmp_path / "r3", max_archive_entries="0")


def test_defaults_unchanged(tmp_path):
    """默认配置行为不能因新增解析逻辑发生变化。"""
    config = AppConfig(workspace_dir=tmp_path / "defaults")
    assert config.sample_ratio == 0.1
    assert config.random_seed == 42
    assert config.port == 5000
    assert config.max_archive_entries == 5000
    assert config.max_compression_ratio == 500.0
    assert config.max_uncompressed_bytes == 10 * 1024 ** 3
    assert config.max_single_file_bytes == 4 * 1024 ** 3


def test_yaml_quoted_numbers_are_coerced(tmp_path):
    yaml_path = tmp_path / "config.yaml"
    yaml_path.write_text(
        'sample_ratio: "0.2"\nmax_archive_entries: "77"\n'
        'max_compression_ratio: "250"\n', encoding="utf-8")
    config = AppConfig.from_yaml(yaml_path)
    assert config.sample_ratio == 0.2
    assert config.max_archive_entries == 77
    assert config.max_compression_ratio == 250.0


def test_env_var_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("GATEWAY_SAMPLE_RATIO", "0.35")
    monkeypatch.setenv("GATEWAY_MAX_ARCHIVE_ENTRIES", "888")
    monkeypatch.setenv("GATEWAY_WORKSPACE", str(tmp_path / "env_ws"))
    config = load_config()
    assert config.sample_ratio == 0.35
    assert config.max_archive_entries == 888
    assert config.workspace_dir == (tmp_path / "env_ws").resolve()


def test_env_var_invalid_raises_readable_error(monkeypatch, tmp_path):
    monkeypatch.setenv("GATEWAY_WORKSPACE", str(tmp_path / "bad_env"))
    monkeypatch.setenv("GATEWAY_SAMPLE_RATIO", "not-a-number")
    with pytest.raises(ValueError, match="sample_ratio"):
        load_config()


def test_unknown_env_ignored(monkeypatch, tmp_path):
    monkeypatch.setenv("GATEWAY_UNRELATED_OPTION", "whatever")
    monkeypatch.setenv("GATEWAY_WORKSPACE", str(tmp_path / "ignore_ws"))
    config = load_config()
    assert config.sample_ratio == 0.1


def test_sampling_behavior_matches_configured_ratio(tmp_path):
    """字符串比例解析后，抽样行数必须与同值浮点比例一致。"""
    import pandas as pd
    from gateway.parser.table_reader import _apply_sample

    frame = pd.DataFrame({"id": range(100)})
    str_config = AppConfig(workspace_dir=tmp_path / "s1", sample_ratio="0.2")
    float_config = AppConfig(workspace_dir=tmp_path / "s2", sample_ratio=0.2)
    str_sampled = _apply_sample(frame, str_config.sample_ratio, str_config.random_seed)
    float_sampled = _apply_sample(frame, float_config.sample_ratio, float_config.random_seed)
    assert len(str_sampled) == 20
    assert str_sampled.index.tolist() == float_sampled.index.tolist()
