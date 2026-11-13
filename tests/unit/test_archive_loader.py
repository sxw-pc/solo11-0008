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


def test_case_only_collision_rejected(tmp_path, config):
    """同目录下仅大小写不同的两个文件仍必须拦截。"""
    path = tmp_path / "case.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.yaml", "files: {}\ntables: {}\n")
        archive.writestr("data/a.csv", "a")
        archive.writestr("data/A.csv", "b")
    with pytest.raises(SecurityError, match="大小写"):
        load_archive(path, config)
    tar_path = tmp_path / "case.tar.gz"
    with tarfile.open(tar_path, "w:gz") as archive:
        for name, data in (("manifest.yaml", b"files: {}\ntables: {}\n"),
                           ("data/a.csv", b"a"), ("data/A.csv", b"b")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, BytesIO(data))
    with pytest.raises(SecurityError, match="大小写"):
        load_archive(tar_path, config)


def test_backslash_and_case_resolution(tmp_path, config):
    """manifest 的反斜杠与大小写写法应解析到包内实际成员。"""
    path = _safe_zip(tmp_path, extra={"TABLE/Users.CSV": "id\n1\n"})
    result = load_archive(path, config)
    try:
        assert result.resolve_relative("table\\users.csv") == "TABLE/Users.CSV"
        assert result.resolve_relative("./TABLE\\USERS.CSV") == "TABLE/Users.CSV"
        assert result.resolve_relative("data\\missing.csv") is None
        assert result.safe_path("TABLE\\users.CSV").is_file()
    finally:
        result.cleanup()


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
