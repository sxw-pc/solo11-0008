"""AppConfig 参数校验单元测试。"""

import pytest

from gateway.config import AppConfig


def test_random_seed_must_be_deterministic_integer(tmp_path):
    """random_seed 为 null/浮点/字符串时必须报错，避免抽样回退全局随机源。"""
    for bad in (None, 1.5, "42", True):
        with pytest.raises(ValueError, match="random_seed"):
            AppConfig(workspace_dir=tmp_path / ("ws-%s" % type(bad).__name__),
                      random_seed=bad)


def test_default_seed_and_ratio_are_retained(tmp_path):
    config = AppConfig(workspace_dir=tmp_path / "ws")
    assert config.random_seed == 42
    assert config.sample_ratio == 0.1


def test_sample_ratio_bounds_validated(tmp_path):
    with pytest.raises(ValueError, match="sample_ratio"):
        AppConfig(workspace_dir=tmp_path / "ws-a", sample_ratio=0)
    with pytest.raises(ValueError, match="sample_ratio"):
        AppConfig(workspace_dir=tmp_path / "ws-b", sample_ratio=1.5)
