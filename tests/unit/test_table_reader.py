"""多格式表读取与抽样单元测试。"""

from pathlib import Path
import sqlite3

import pandas as pd
import pytest

from gateway.config import AppConfig
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


def test_packet_sampling_uses_single_ratio_and_seed(make_table):
    """整包抽样：比例与种子只生效一次，同长度表不再抽到相同行位置。"""
    from gateway.parser.table_reader import sample_tables

    def table(name, count):
        rows = [{"value": index} for index in range(count)]
        return make_table(name, rows, offset=1)

    tables = {"a": table("a", 100), "b": table("b", 100)}
    first = sample_tables(tables, AppConfig(sample_ratio=0.1, random_seed=42))
    second = sample_tables(tables, AppConfig(sample_ratio=0.1, random_seed=42))
    for name in ("a", "b"):
        assert first[name].sampled_rows == 10
        assert first[name].total_rows == 100
        assert first[name].sample_ratio == 0.1
        assert first[name].frame.index.tolist() == second[name].frame.index.tolist()
    # 随机流跨表推进，两张等长表不会得到完全相同的抽样行。
    assert first["a"].frame.index.tolist() != first["b"].frame.index.tolist()
    # 全量表对象不被修改，供血缘阶段继续使用。
    assert len(tables["a"].frame) == 100


def test_packet_sampling_keeps_small_tables_and_changes_seed(make_table):
    from gateway.parser.table_reader import sample_tables

    small = make_table("small", [{"value": index} for index in range(3)], offset=1)
    large = make_table("large", [{"value": index} for index in range(97)], offset=1)
    sampled = sample_tables({"small": small, "large": large},
                            AppConfig(sample_ratio=0.1, random_seed=42))
    assert sampled["small"].sampled_rows == 1
    assert sampled["large"].sampled_rows == 10
    other = sample_tables({"small": small, "large": large},
                          AppConfig(sample_ratio=0.1, random_seed=7))
    assert other["large"].frame.index.tolist() != sampled["large"].frame.index.tolist()


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
