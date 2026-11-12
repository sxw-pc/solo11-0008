"""应用配置单元测试（聚焦血缘快照保留策略配置项）。"""

import pytest

from gateway.config import AppConfig


def test_default_snapshot_versions(config):
    assert config.lineage_snapshot_versions == 30


def test_custom_snapshot_versions_accepted(tmp_path):
    config = AppConfig(workspace_dir=tmp_path / "ws",
                       lineage_snapshot_versions=10)
    assert config.lineage_snapshot_versions == 10


@pytest.mark.parametrize("bad_value", [0, -1])
def test_snapshot_versions_must_be_positive(tmp_path, bad_value):
    with pytest.raises(ValueError, match="血缘快照保留版本数"):
        AppConfig(workspace_dir=tmp_path / "ws",
                  lineage_snapshot_versions=bad_value)
