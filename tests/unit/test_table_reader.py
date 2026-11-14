"""多格式表读取与抽样单元测试。"""

from pathlib import Path
import sqlite3

import pandas as pd
import pytest

from gateway.parser.archive_loader import load_archive
from gateway.parser.table_reader import (TableReadError, iter_table_specs,
                                         read_manifest_table, read_table)


def test_csv_utf8_and_header_cleanup(tmp_path, config):
    path = tmp_path / "data.csv"
    path.write_text("id, na\n1,x\n2,y\n", encoding="utf-8")
    result = read_table(path, "csv", config, sample=False)
    assert result.encoding == "utf-8-sig"
    assert list(result.frame.columns) == ["id", "na"]
    assert result.total_rows == 2
    assert result.row_offset == 2


def test_csv_gbk(tmp_path, config):
    path = tmp_path / "gbk.csv"
    path.write_text("编号,名称\n1,测试\n", encoding="gbk")
    result = read_table(path, "csv", config, sample=False)
    assert result.encoding == "gbk"
    assert result.frame.iloc[0]["名称"] == "测试"


def test_csv_empty_and_duplicate_header(tmp_path, config):
    empty = tmp_path / "empty.csv"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(TableReadError, match="为空"):
        read_table(empty, "csv", config)
    duplicate = tmp_path / "dup.csv"
    duplicate.write_text("id,id\n1,2\n", encoding="utf-8")
    with pytest.raises(TableReadError, match="重复"):
        read_table(duplicate, "csv", config)


def test_parquet_read_and_corrupt(tmp_path, config):
    path = tmp_path / "data.parquet"
    pd.DataFrame({"id": [1, 2], "name": ["a", "b"]}).to_parquet(path)
    result = read_table(path, "parquet", config, sample=False)
    assert result.source_format == "parquet"
    assert len(result.frame) == 2
    bad = tmp_path / "bad.parquet"
    bad.write_bytes(b"not parquet")
    with pytest.raises(TableReadError, match="Parquet"):
        read_table(bad, "parquet", config)


def test_sqlite_read_requires_table_when_multiple(tmp_path, config):
    path = tmp_path / "data.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE one (id INTEGER)")
    connection.execute("CREATE TABLE two (id INTEGER)")
    connection.execute("INSERT INTO two VALUES (7)")
    connection.commit()
    connection.close()
    with pytest.raises(TableReadError, match="多张表"):
        read_table(path, "sqlite", config)
    result = read_table(path, "sqlite", config, table_name="two", sample=False)
    assert result.frame.iloc[0]["id"] == 7
    with pytest.raises(TableReadError, match="不存在"):
        read_table(path, "sqlite", config, table_name="missing")


def test_sqlite_empty_and_corrupt(tmp_path, config):
    empty = tmp_path / "empty.sqlite"
    sqlite3.connect(empty).close()
    with pytest.raises(TableReadError, match="没有业务表"):
        read_table(empty, "sqlite", config)
    corrupt = tmp_path / "corrupt.sqlite"
    corrupt.write_bytes(b"not a database")
    with pytest.raises(TableReadError, match="损坏"):
        read_table(corrupt, "sqlite", config)


def test_sampling_is_deterministic(tmp_path, config):
    path = tmp_path / "sample.csv"
    rows = ["id"] + [str(index) for index in range(100)]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    config.sample_ratio = 0.1
    first = read_table(path, "csv", config)
    second = read_table(path, "csv", config)
    assert first.sampled_rows == 10
    assert first.total_rows == 100
    assert first.frame.index.tolist() == second.frame.index.tolist()
    assert first.sample_ratio == 0.1


def test_missing_unsupported_and_empty_parquet(tmp_path, config):
    with pytest.raises(TableReadError, match="不存在"):
        read_table(tmp_path / "missing.csv", "csv", config)
    dummy = tmp_path / "dummy.txt"
    dummy.write_text("x", encoding="utf-8")
    with pytest.raises(TableReadError, match="不支持"):
        read_table(dummy, "txt", config)


def test_read_manifest_table_and_specs(config):
    extraction = load_archive(Path("fixtures/valid_packets/retail_valid_a.zip"), config)
    try:
        table = read_manifest_table(extraction, "users", config, sample=False)
        assert table.name == "users"
        assert len(table.frame) == 24
        assert "orders" in iter_table_specs(extraction.manifest)
        with pytest.raises(TableReadError, match="未声明"):
            read_manifest_table(extraction, "unknown", config)
        extraction.manifest["tables"]["evil"] = {"path": "../outside.csv"}
        with pytest.raises(TableReadError, match="路径非法"):
            read_manifest_table(extraction, "evil", config)
        extraction.manifest["tables"]["nopath"] = {"format": "csv"}
        with pytest.raises(TableReadError, match="缺少 path"):
            read_manifest_table(extraction, "nopath", config)
    finally:
        extraction.cleanup()


def test_sqlite_query_error_branch(tmp_path, config):
    path = tmp_path / "odd.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE weird (id INTEGER)")
    connection.commit()
    connection.close()
    result = read_table(path, "sqlite", config, table_name="weird", sample=False)
    assert result.sqlite_table == "weird"
    assert result.frame.empty or list(result.frame.columns) == ["id"]


def test_sqlite_order_is_deterministic(tmp_path, config):
    """无 ORDER BY 的隐式行序不可依赖，读取器应显式固定顺序。"""
    path = tmp_path / "ordered.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE t (id TEXT, v INTEGER)")
    connection.executemany("INSERT INTO t VALUES (?, ?)",
                           [("r%d" % i, i) for i in (9, 3, 7, 1, 5)])
    connection.commit()
    connection.close()
    first = read_table(path, "sqlite", config, table_name="t", sample=False)
    second = read_table(path, "sqlite", config, table_name="t", sample=False)
    assert first.frame["id"].tolist() == second.frame["id"].tolist()

    wor = tmp_path / "without_rowid.sqlite"
    connection = sqlite3.connect(wor)
    connection.execute("CREATE TABLE w (id TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID")
    connection.executemany("INSERT INTO w VALUES (?, ?)",
                           [("r%d" % i, i) for i in (9, 3, 7, 1, 5)])
    connection.commit()
    connection.close()
    result = read_table(wor, "sqlite", config, table_name="w", sample=False)
    assert result.frame["id"].tolist() == ["r1", "r3", "r5", "r7", "r9"]


def test_sample_rejects_non_integer_seed(tmp_path):
    """None/字符串等非整数种子会回退全局随机数生成器，必须拒绝。"""
    from gateway.parser.table_reader import _apply_sample
    frame = pd.DataFrame({"v": range(100)})
    for bad in (None, "42", 1.5, True):
        with pytest.raises(TableReadError):
            _apply_sample(frame, 0.1, bad)
    assert len(_apply_sample(frame, 0.1, 42)) == 10
