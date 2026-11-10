"""pytest 公共夹具：临时工作目录、SQLite 存储与离线样例路径。"""

from pathlib import Path
import sys

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.config import AppConfig  # noqa: E402
from gateway.parser.table_reader import TableData  # noqa: E402
from gateway.store.sqlite_store import SQLiteStore  # noqa: E402

FIXTURES = ROOT / "fixtures"
CONTRACT = FIXTURES / "mock_contract" / "user_trade_contract.yaml"
PRODUCT_CONTRACT = FIXTURES / "mock_contract" / "product_contract.yaml"
LINEAGE = FIXTURES / "mock_lineage" / "trade_lineage_rule.yaml"
PRODUCT_LINEAGE = FIXTURES / "mock_lineage" / "product_lineage_rule.yaml"
VALID_PACKETS = sorted((FIXTURES / "valid_packets").iterdir())
INVALID_ROOT = FIXTURES / "invalid_packets"


@pytest.fixture
def config(tmp_path):
    """每个测试使用独立的临时工作目录，避免污染项目 workspace。"""
    return AppConfig(workspace_dir=tmp_path / "workspace")


@pytest.fixture
def store(config):
    """返回绑定临时数据库的存储实例。"""
    return SQLiteStore(config.db_path)


@pytest.fixture
def make_table():
    """构造 TableData 的便捷工厂。"""
    def factory(name, rows, source_format="csv", offset=2, sample_ratio=1.0):
        frame = pd.DataFrame(rows)
        return TableData(
            name=name, frame=frame, source_format=source_format,
            total_rows=len(frame), sampled_rows=len(frame),
            sample_ratio=sample_ratio, row_offset=offset,
        )
    return factory


@pytest.fixture
def valid_users(make_table):
    """三条合法用户维表记录。"""
    return make_table("users", [
        {"user_id": "U0001", "user_name": "Mock A", "region": "north",
         "age": 30, "email": "a@mock.local", "signup_date": "2024-01-05"},
        {"user_id": "U0002", "user_name": "Mock B", "region": "south",
         "age": 31, "email": "b@mock.local", "signup_date": "2024-01-06"},
        {"user_id": "U0003", "user_name": "Mock C", "region": "east",
         "age": 32, "email": "c@mock.local", "signup_date": "2024-01-07"},
    ])


@pytest.fixture
def valid_trades(make_table):
    """两条引用合法用户的交易记录。"""
    return make_table("trades", [
        {"trade_id": "T0001", "user_id": "U0001", "product_id": "P001",
         "amount": 10.5, "quantity": 1, "status": "paid",
         "trade_date": "2024-02-01", "note": None},
        {"trade_id": "T0002", "user_id": "U0002", "product_id": "P002",
         "amount": 20.0, "quantity": 2, "status": "pending",
         "trade_date": "2024-02-02", "note": "mock"},
    ])
