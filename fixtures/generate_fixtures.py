"""生成离线 Mock 数据包。

仅使用 pandas/pyarrow 与标准库，不访问网络。重新执行会覆盖 fixtures 下的
合法与异常压缩包。数据均为虚构样例，不包含真实企业或个人信息。
"""

from datetime import datetime, timedelta
from hashlib import md5, sha256
from pathlib import Path
import shutil
import sqlite3
import tarfile
import tempfile
import zipfile

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parent
FIXED_TIME = "2024-03-01T00:00:00"


def _users() -> pd.DataFrame:
    """构造 24 条虚构用户数据。"""
    regions = ["north", "south", "east", "west"]
    rows = []
    for index in range(1, 25):
        signup = datetime(2024, 1, 1) + timedelta(days=index * 3)
        rows.append({
            "user_id": "U%04d" % index,
            "user_name": "Mock User %02d" % index,
            "region": regions[index % 4],
            "age": 20 + (index % 30),
            "email": "user%02d@mock.local" % index,
            "signup_date": signup.strftime("%Y-%m-%d"),
        })
    return pd.DataFrame(rows)


def _products() -> pd.DataFrame:
    """构造 8 条虚构商品数据。"""
    categories = ["electronics", "books", "home", "sports"]
    rows = []
    for index in range(1, 9):
        rows.append({
            "product_id": "P%03d" % index,
            "product_name": "Mock Product %02d" % index,
            "category": categories[(index - 1) % 4],
            "price": round(19.9 + index * 12.35, 2),
            "stock": 10 + index * 7,
            "listed_date": (datetime(2024, 1, 15) + timedelta(days=index)).strftime("%Y-%m-%d"),
        })
    return pd.DataFrame(rows)


def _trades() -> pd.DataFrame:
    """构造 60 条虚构交易，约 10% 备注为空。"""
    statuses = ["paid", "pending", "refunded"]
    rows = []
    for index in range(1, 61):
        trade_date = datetime(2024, 2, 1) + timedelta(days=index % 28)
        rows.append({
            "trade_id": "T%04d" % index,
            "user_id": "U%04d" % (((index - 1) % 24) + 1),
            "product_id": "P%03d" % (((index - 1) % 8) + 1),
            "amount": round(20 + (index * 13.7) % 900, 2),
            "quantity": 1 + index % 5,
            "status": statuses[index % 3],
            "trade_date": trade_date.strftime("%Y-%m-%d"),
            "note": None if index % 10 == 0 else "mock note %02d" % index,
        })
    return pd.DataFrame(rows)


def _orders(trades: pd.DataFrame) -> pd.DataFrame:
    """由交易构造一一对应的订单数据。"""
    rows = []
    for index, trade in trades.iterrows():
        rows.append({
            "order_id": "O%04d" % (index + 1),
            "trade_id": trade["trade_id"],
            "product_id": trade["product_id"],
            "amount": float(trade["amount"]),
            "order_date": trade["trade_date"],
        })
    return pd.DataFrame(rows)


def _write_database(path: Path, orders: pd.DataFrame) -> None:
    """写入订单 SQLite 库并创建主键与唯一约束。"""
    path.unlink(missing_ok=True)
    connection = sqlite3.connect(str(path))
    try:
        connection.execute(
            "CREATE TABLE orders (order_id TEXT PRIMARY KEY, trade_id TEXT UNIQUE, "
            "product_id TEXT NOT NULL, amount REAL NOT NULL, order_date TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO orders VALUES (?, ?, ?, ?, ?)",
            [tuple(row) for row in orders.itertuples(index=False, name=None)])
        connection.commit()
    finally:
        connection.close()


def _hashes(path: Path) -> dict:
    """计算文件 MD5 与 SHA256。"""
    md5_hash, sha_hash = md5(), sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            md5_hash.update(chunk)
            sha_hash.update(chunk)
    return {"md5": md5_hash.hexdigest(), "sha256": sha_hash.hexdigest(),
            "size": path.stat().st_size}


def _build_data(folder: Path, users, trades, products, orders) -> None:
    """将三格式业务表写入 staging 目录。"""
    data_dir = folder / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    users.to_csv(data_dir / "users.csv", index=False, encoding="utf-8")
    trades.to_csv(data_dir / "trades.csv", index=False, encoding="utf-8")
    products.to_parquet(data_dir / "products.parquet", index=False)
    _write_database(data_dir / "orders.sqlite", orders)


def _write_manifest(folder: Path, packet_name: str, tamper: bool = False) -> None:
    """生成 manifest，可选篡改交易表哈希用于异常样本。"""
    files = {}
    for path in sorted((folder / "data").glob("*")):
        files["data/" + path.name] = _hashes(path)
    if tamper:
        files["data/trades.csv"]["sha256"] = "0" * 64
    manifest = {
        "schema_version": "1.0",
        "packet": {"name": packet_name, "created_at": FIXED_TIME,
                   "description": "离线 Mock 数据包，全部内容为虚构样例"},
        "tables": {
            "users": {"path": "data/users.csv", "format": "csv"},
            "trades": {"path": "data/trades.csv", "format": "csv"},
            "products": {"path": "data/products.parquet", "format": "parquet"},
            "orders": {"path": "data/orders.sqlite", "format": "sqlite", "table": "orders"},
        },
        "files": files,
    }
    (folder / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False), encoding="utf-8")


def _zip_folder(folder: Path, destination: Path, extra: dict = None) -> None:
    """将 staging 目录打成 zip，可附加恶意或冗余成员。"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(folder).as_posix())
        for name, payload in (extra or {}).items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)


def _tar_folder(folder: Path, destination: Path) -> None:
    """将 staging 目录打成 tar.gz。"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w:gz") as archive:
        for path in sorted(folder.rglob("*")):
            archive.add(path, arcname=path.relative_to(folder).as_posix(),
                        recursive=False)


def _base(folder: Path, name: str, users=None, trades=None,
          products=None, orders=None) -> None:
    """构建一套完整业务表并生成 manifest。"""
    users = _users() if users is None else users
    products = _products() if products is None else products
    trades = _trades() if trades is None else trades
    orders = _orders(trades) if orders is None else orders
    _build_data(folder, users, trades, products, orders)
    _write_manifest(folder, name)


def generate() -> None:
    """生成 4 份合法包与 8 类异常包。"""
    valid_dir = ROOT / "valid_packets"
    invalid_dir = ROOT / "invalid_packets"
    for directory in (valid_dir, invalid_dir):
        if directory.exists():
            shutil.rmtree(directory)
    valid_dir.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="fixture-") as temp:
        temp_path = Path(temp)
        for index, (filename, maker) in enumerate((
                ("retail_valid_a.zip", _zip_folder),
                ("retail_valid_b.zip", _zip_folder),
                ("retail_valid_c.tar.gz", _tar_folder),
                ("retail_valid_d.tar.gz", _tar_folder)), start=1):
            folder = temp_path / ("valid_%d" % index)
            folder.mkdir()
            _base(folder, "retail_valid_%d" % index)
            maker(folder, valid_dir / filename)

        scenarios = ["schema_mismatch", "field_missing", "lineage_broken",
                     "hash_tampered", "null_rate_over", "path_traversal",
                     "zip_bomb", "redundant_file"]
        for scenario in scenarios:
            folder = temp_path / scenario
            folder.mkdir()
            base_trades = _trades()
            base_orders = _orders(base_trades)
            if scenario == "schema_mismatch":
                base_trades["amount"] = "not-a-number"
                _base(folder, scenario, trades=base_trades, orders=base_orders)
            elif scenario == "field_missing":
                _base(folder, scenario, trades=base_trades.drop(columns=["status"]),
                      orders=base_orders)
            elif scenario == "lineage_broken":
                base_trades["user_id"] = "U9999"
                _base(folder, scenario, trades=base_trades, orders=base_orders)
            elif scenario == "null_rate_over":
                base_trades["note"] = None
                _base(folder, scenario, trades=base_trades, orders=base_orders)
            elif scenario == "hash_tampered":
                _base(folder, scenario, orders=base_orders)
                _write_manifest(folder, scenario, tamper=True)
            else:
                _base(folder, scenario, orders=base_orders)
            extras = {}
            if scenario == "redundant_file":
                extras = {"data/extra.txt": b"unlisted fixture",
                          "payload.exe": b"MZ-mock-not-executable"}
            if scenario == "zip_bomb":
                extras = {"data/bulk.csv": b"0" * (30 * 1024 * 1024)}
            if scenario == "path_traversal":
                extras = {"../escape.txt": b"escape attempt"}
            _zip_folder(folder, invalid_dir / scenario / (scenario + ".zip"), extras)


if __name__ == "__main__":
    generate()
    print("fixtures generated at", ROOT)
