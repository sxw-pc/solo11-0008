"""解压体积预估器的单元测试。"""

import gzip
from pathlib import Path
import zipfile

from gateway.batch import estimate_uncompressed_bytes

ROOT = Path(__file__).resolve().parents[2]
VALID_PACKETS = ROOT / "fixtures" / "valid_packets"


def test_zip_estimate_matches_central_directory():
    packet = VALID_PACKETS / "retail_valid_a.zip"
    with zipfile.ZipFile(packet) as archive:
        expected = sum(info.file_size for info in archive.infolist()
                       if not info.is_dir())
    assert estimate_uncompressed_bytes(packet) == expected
    assert expected > 0


def test_tar_gz_estimate_matches_gzip_payload_size():
    packet = VALID_PACKETS / "retail_valid_c.tar.gz"
    with gzip.open(packet, "rb") as handle:
        payload_size = len(handle.read())
    assert estimate_uncompressed_bytes(packet) == payload_size
    assert payload_size > 0


def test_all_valid_packets_have_positive_estimates():
    for packet in sorted(VALID_PACKETS.iterdir()):
        assert estimate_uncompressed_bytes(packet) > 0, packet.name


def test_corrupt_file_falls_back_to_file_size(tmp_path):
    corrupt = tmp_path / "corrupt.zip"
    corrupt.write_bytes(b"\x00\x01\x02\x03" * 64)
    assert estimate_uncompressed_bytes(corrupt) == 256


def test_truncated_zip_falls_back_to_file_size(tmp_path):
    packet = VALID_PACKETS / "retail_valid_a.zip"
    truncated = tmp_path / "truncated.zip"
    data = packet.read_bytes()[:128]
    truncated.write_bytes(data)
    assert estimate_uncompressed_bytes(truncated) == len(data)


def test_missing_file_returns_zero(tmp_path):
    assert estimate_uncompressed_bytes(tmp_path / "missing.zip") == 0


def test_empty_file_returns_zero(tmp_path):
    empty = tmp_path / "empty.zip"
    empty.write_bytes(b"")
    assert estimate_uncompressed_bytes(empty) == 0


def test_tiny_gzip_falls_back_to_file_size(tmp_path):
    tiny = tmp_path / "tiny.tar.gz"
    tiny.write_bytes(b"\x1f\x8b\x08\x00")
    assert estimate_uncompressed_bytes(tiny) == 4


def test_non_tar_gzip_uses_isize(tmp_path):
    """有效 gzip 但内容不是 tar（如单文件压缩）：按 ISIZE 预估。"""
    payload = b"hello gateway batch estimator" * 10
    packed = tmp_path / "single.gz"
    packed.write_bytes(gzip.compress(payload))
    assert estimate_uncompressed_bytes(packed) == len(payload)


def test_empty_gzip_falls_back_to_file_size(tmp_path):
    packed = tmp_path / "empty.gz"
    packed.write_bytes(gzip.compress(b""))
    assert estimate_uncompressed_bytes(packed) == packed.stat().st_size


def test_gzip_isize_wraparound_falls_back(tmp_path):
    """ISIZE 明显小于压缩包本身时判定回绕，回退文件大小。"""
    packed = tmp_path / "wrap.gz"
    packed.write_bytes(gzip.compress(b"\x00\x01\x02\x03"))
    assert packed.stat().st_size >= 18
    assert estimate_uncompressed_bytes(packed) == packed.stat().st_size


def test_tiny_gzip_estimate_uses_file_size(tmp_path):
    """不足最小 gzip 头尾长度的文件直接按文件大小估计。"""
    from gateway.batch.estimator import _tar_gzip_estimate
    tiny = tmp_path / "tiny.gz"
    tiny.write_bytes(b"\x1f\x8b\x08\x00")
    assert _tar_gzip_estimate(tiny) == 4


def test_looks_like_gzip_on_directory(tmp_path):
    from gateway.batch.estimator import _looks_like_gzip
    assert _looks_like_gzip(tmp_path) is False


def test_zip_central_directory_failure_falls_back(tmp_path, monkeypatch):
    """中央目录读取异常时回退文件大小，预估器自身绝不抛异常。"""
    packet = VALID_PACKETS / "retail_valid_a.zip"

    def boom(*args, **kwargs):
        raise zipfile.BadZipFile("模拟中央目录损坏")

    monkeypatch.setattr(zipfile, "ZipFile", boom)
    assert estimate_uncompressed_bytes(packet) == packet.stat().st_size
