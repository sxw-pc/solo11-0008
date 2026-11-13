"""压缩包安全解析单元测试。"""

from io import BytesIO
from pathlib import Path
import tarfile
import zipfile

import pytest

from gateway.parser.archive_loader import (ArchiveError, SecurityError,
                                           detect_archive_type, load_archive,
                                           lookup_manifest_file)


def _make_zip(path, entries, compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def _safe_zip(tmp_path, extra=None):
    entries = {"manifest.yaml": "files: {}\ntables: {}\n", "data/a.csv": "id\n1\n"}
    entries.update(extra or {})
    return _make_zip(tmp_path / "packet.zip", entries)


def test_valid_zip_and_cleanup(config):
    result = load_archive(Path("fixtures/valid_packets/retail_valid_a.zip"), config)
    try:
        assert result.archive_type == "zip"
        assert result.manifest["tables"]["users"]["format"] == "csv"
        assert len(result.files) == 5
        assert result.safe_path("data/users.csv").is_file()
        assert lookup_manifest_file(result.manifest, "./data/users.csv") is not None
        assert lookup_manifest_file(result.manifest, "nope.csv") is None
    finally:
        temp_dir = result.temp_dir
        result.cleanup()
        result.cleanup()
    assert not temp_dir.exists()


def test_valid_tar_and_context_manager(config):
    with load_archive(Path("fixtures/valid_packets/retail_valid_c.tar.gz"), config) as result:
        temp_dir = result.temp_dir
        assert result.archive_type == "tar.gz"
        assert result.temp_dir.is_dir()
    assert not temp_dir.exists()


def test_missing_manifest(tmp_path, config):
    path = _make_zip(tmp_path / "no_manifest.zip", {"data/a.csv": "id\n1\n"})
    with pytest.raises(ArchiveError, match="manifest"):
        load_archive(path, config)


def test_malformed_manifest(tmp_path, config):
    path = _make_zip(tmp_path / "bad.zip", {"manifest.yaml": "- not-a-map"})
    with pytest.raises(ArchiveError, match="映射"):
        load_archive(path, config)


def test_invalid_manifest_yaml(tmp_path, config):
    path = _make_zip(tmp_path / "bad.zip", {"manifest.yaml": "files: ["})
    with pytest.raises(ArchiveError, match="解析失败"):
        load_archive(path, config)


def test_forbidden_table_structure(tmp_path, config):
    path = _make_zip(tmp_path / "bad.zip", {"manifest.yaml": "files: []\ntables: {}\n"})
    with pytest.raises(ArchiveError, match="files"):
        load_archive(path, config)


def test_path_traversal_fixture(config):
    with pytest.raises(SecurityError, match="穿越"):
        load_archive(Path("fixtures/invalid_packets/path_traversal/path_traversal.zip"), config)


def test_absolute_and_backslash_paths(tmp_path, config):
    path = _make_zip(tmp_path / "abs.zip", {"manifest.yaml": "files: {}\ntables: {}\n",
                                           "/etc/evil.txt": "x"})
    with pytest.raises(SecurityError, match="绝对路径"):
        load_archive(path, config)
    path2 = _make_zip(tmp_path / "back.zip", {"manifest.yaml": "files: {}\ntables: {}\n",
                                             "ok\\..\\evil.txt": "x"})
    with pytest.raises(SecurityError, match="穿越"):
        load_archive(path2, config)


def test_duplicate_member(tmp_path, config):
    path = tmp_path / "dup.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.yaml", "files: {}\ntables: {}\n")
        archive.writestr("data/a.csv", "a")
        archive.writestr("data/a.csv", "b")
    with pytest.raises(SecurityError, match="重复"):
        load_archive(path, config)


def test_symlink_member(tmp_path, config):
    path = tmp_path / "link.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.yaml", "files: {}\ntables: {}\n")
        info = zipfile.ZipInfo("data/link")
        info.external_attr = (0o120777 & 0xFFFF) << 16
        archive.writestr(info, "target")
    with pytest.raises(SecurityError, match="符号链接"):
        load_archive(path, config)


def test_entry_and_size_limits(config):
    config.max_archive_entries = 1
    with pytest.raises(SecurityError, match="条目数"):
        load_archive(Path("fixtures/valid_packets/retail_valid_a.zip"), config)
    config.max_archive_entries = 100
    config.max_uncompressed_bytes = 10
    with pytest.raises(SecurityError, match="总大小"):
        load_archive(Path("fixtures/valid_packets/retail_valid_a.zip"), config)
    config.max_uncompressed_bytes = 10 ** 9
    config.max_single_file_bytes = 1
    with pytest.raises(SecurityError, match="单文件"):
        load_archive(Path("fixtures/valid_packets/retail_valid_a.zip"), config)


def test_zip_bomb_blocked(config):
    with pytest.raises(SecurityError, match="炸弹"):
        load_archive(Path("fixtures/invalid_packets/zip_bomb/zip_bomb.zip"), config)


def test_unsupported_and_missing_file(tmp_path, config):
    bogus = tmp_path / "bogus.bin"
    bogus.write_bytes(b"not an archive")
    with pytest.raises(ArchiveError, match="仅支持"):
        load_archive(bogus, config)
    with pytest.raises(ArchiveError, match="不存在"):
        load_archive(tmp_path / "missing.zip", config)
    with pytest.raises(ArchiveError, match="不存在"):
        detect_archive_type(tmp_path / "missing.zip")


def test_safe_path_escape(config):
    result = load_archive(Path("fixtures/valid_packets/retail_valid_a.zip"), config)
    try:
        with pytest.raises(SecurityError):
            result.safe_path("../outside.txt")
    finally:
        result.cleanup()


def test_tar_link_and_device_rejected(tmp_path, config):
    link_tar = tmp_path / "link.tar.gz"
    with tarfile.open(link_tar, "w:gz") as archive:
        for name, data in (("manifest.yaml", b"files: {}\ntables: {}\n"),
                           ("data/a.csv", b"id\n1\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, BytesIO(data))
        link = tarfile.TarInfo("data/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "a.csv"
        archive.addfile(link)
    with pytest.raises(SecurityError, match="链接"):
        load_archive(link_tar, config)
    device_tar = tmp_path / "device.tar.gz"
    with tarfile.open(device_tar, "w:gz") as archive:
        info = tarfile.TarInfo("manifest.yaml")
        info.type = tarfile.CHRTYPE
        archive.addfile(info)
    with pytest.raises(SecurityError, match="特殊设备"):
        load_archive(device_tar, config)


def test_tar_size_limit(config):
    config.max_uncompressed_bytes = 10
    with pytest.raises(SecurityError, match="总大小"):
        load_archive(Path("fixtures/valid_packets/retail_valid_c.tar.gz"), config)


def test_unicode_tar_members_accepted_across_formats(tmp_path, config):
    """中文/emoji 等合法 Unicode 成员名在三种 tar 格式下都应放行。"""
    entries = [
        ("manifest.yaml", b"files: {}\ntables: {}\n"),
        ("数据目录/用户数据.csv", "编号,名称\n1,张三\n".encode("utf-8")),
        ("报表/导出😀.parquet", b"fake-parquet"),
    ]
    for fmt in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
        packet = tmp_path / ("unicode_%d.tar.gz" % fmt)
        with tarfile.open(packet, "w:gz", format=fmt) as archive:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, BytesIO(data))
        with load_archive(packet, config) as result:
            assert result.archive_type == "tar.gz"
            paths = {item["path"] for item in result.files}
            assert "数据目录/用户数据.csv" in paths
            assert "报表/导出😀.parquet" in paths
            assert result.safe_path("数据目录/用户数据.csv").is_file()


def test_tar_root_dot_entry_is_skipped(tmp_path, config):
    """GNU tar 打包目录时写入的根标记 '.' 不应被判为空路径或路径穿越。"""
    packet = tmp_path / "root_dot.tar.gz"
    with tarfile.open(packet, "w:gz") as archive:
        for name, data in ((".", b""),
                           ("manifest.yaml", b"files: {}\ntables: {}\n"),
                           ("数据/文件.csv", b"id\n1\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, BytesIO(data) if data else None)
    with load_archive(packet, config) as result:
        assert {item["path"] for item in result.files} == {
            "manifest.yaml", "数据/文件.csv"}


def test_unicode_does_not_weakening_security_checks(config):
    """Unicode 放行的同时，越界/绝对路径/链接拦截逻辑保持不变。"""
    from gateway.parser.archive_loader import _normalize_member, _RootMember
    blocked = ["数据/../../etc", "../中文/文件", "/绝对/路径.csv", "C:/数据/x",
               "目录\\..\\evil", "数据\\..\\x", "a/../b"]
    for name in blocked:
        with pytest.raises(SecurityError):
            _normalize_member(name)
    with pytest.raises(_RootMember):
        _normalize_member(".")
    # 合法 Unicode 名称原样保留
    assert _normalize_member("数据/报告 😀.csv") == "数据/报告 😀.csv"


def test_unicode_tar_symlink_still_rejected(tmp_path, config):
    """含 Unicode 路径的符号链接 tar 成员仍必须被拦截。"""
    packet = tmp_path / "unicode_link.tar.gz"
    with tarfile.open(packet, "w:gz") as archive:
        manifest = tarfile.TarInfo("manifest.yaml")
        manifest.size = len(b"files: {}\ntables: {}\n")
        archive.addfile(manifest, BytesIO(b"files: {}\ntables: {}\n"))
        link = tarfile.TarInfo("数据/链接")
        link.type = tarfile.SYMTYPE
        link.linkname = "../文件.csv"
        archive.addfile(link)
    with pytest.raises(SecurityError, match="链接"):
        load_archive(packet, config)
