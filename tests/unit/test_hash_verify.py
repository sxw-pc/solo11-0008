"""哈希、冗余文件与高风险文件检测单元测试。"""

from hashlib import md5, sha256
from pathlib import Path

import pytest

from gateway.parser.archive_loader import load_archive
from gateway.validator.hash_verify import (compute_file_hashes, is_dangerous_file,
                                           verify_hashes, verify_package_hash)


def _manifest_for(path, extra=None):
    data = path.read_bytes()
    result = {
        "files": {path.name: {"md5": md5(data).hexdigest(),
                              "sha256": sha256(data).hexdigest()}},
        "tables": {},
    }
    if extra:
        result["files"].update(extra)
    return result


def test_compute_hashes_and_dangerous(config):
    path = Path("fixtures/valid_packets/retail_valid_a.zip")
    hashes = compute_file_hashes(path)
    assert len(hashes["md5"]) == 32
    assert len(hashes["sha256"]) == 64
    assert hashes["size"] == path.stat().st_size
    assert is_dangerous_file("payload.EXE", config)
    assert not is_dangerous_file("data/users.csv", config)


def test_valid_packet_hashes(config):
    with load_archive(Path("fixtures/valid_packets/retail_valid_a.zip"), config) as extracted:
        result = verify_hashes(extracted.temp_dir, extracted.manifest, config)
    assert result["passed"]
    assert result["checked_files"] == 4


def test_hash_tampered_fixture(config):
    with load_archive(Path("fixtures/invalid_packets/hash_tampered/hash_tampered.zip"), config) as extracted:
        result = verify_hashes(extracted.temp_dir, extracted.manifest, config)
    assert not result["passed"]
    assert "hash_mismatch" in result["error_codes"]


def test_redundant_and_dangerous_fixture(config):
    with load_archive(Path("fixtures/invalid_packets/redundant_file/redundant_file.zip"), config) as extracted:
        result = verify_hashes(extracted.temp_dir, extracted.manifest, config)
    assert not result["passed"]
    assert {"redundant_file", "dangerous_file"} <= set(result["error_codes"])


def test_missing_and_bad_declarations(tmp_path, config):
    root = tmp_path / "root"
    root.mkdir()
    data = root / "a.csv"
    data.write_text("id\n1\n", encoding="utf-8")
    manifest = {
        "files": {
            "missing.csv": {"sha256": "0" * 64},
            "a.csv": "not-a-dict",
        },
        "tables": {},
    }
    result = verify_hashes(root, manifest, config)
    codes = {item["code"] for item in result["errors"]}
    assert "missing_file" in codes
    assert "invalid_hash_declaration" in codes
    manifest["files"] = {"a.csv": {}}
    missing = verify_hashes(root, manifest, config)
    assert "missing_hash_declaration" in missing["error_codes"]


def test_whitelist_extra_file(tmp_path, config):
    root = tmp_path / "root"
    root.mkdir()
    data = root / "a.csv"
    data.write_text("id\n1\n", encoding="utf-8")
    (root / "notice.txt").write_text("allowed", encoding="utf-8")
    manifest = _manifest_for(data)
    result = verify_hashes(root, manifest, config)
    assert not result["passed"]
    config.allowed_extra_paths = ("*.txt",)
    allowed = verify_hashes(root, manifest, config)
    assert allowed["passed"]


def test_both_hash_algorithms_mismatch(tmp_path, config):
    root = tmp_path / "root"
    root.mkdir()
    data = root / "a.csv"
    data.write_text("id\n1\n", encoding="utf-8")
    manifest = {"files": {"a.csv": {"md5": "0" * 32, "sha256": "1" * 64}}, "tables": {}}
    result = verify_hashes(root, manifest, config)
    algorithms = {item.get("algorithm") for item in result["errors"]}
    assert {"md5", "sha256"} <= algorithms


def test_package_hash_verification():
    path = Path("fixtures/valid_packets/retail_valid_a.zip")
    expected = sha256(path.read_bytes()).hexdigest()
    result = verify_package_hash(path, expected)
    assert result["passed"]
    assert verify_package_hash(path, "sha256:" + expected)["passed"]
    wrong = verify_package_hash(path, "md5:" + "0" * 32)
    assert not wrong["passed"]
    assert wrong["errors"][0]["code"] == "package_hash_mismatch"
    with pytest.raises(ValueError, match="格式"):
        verify_package_hash(path, "too-short")
    with pytest.raises(ValueError, match="算法"):
        verify_package_hash(path, "sha512:" + "0" * 128)


def test_verify_hashes_package_options(config):
    path = Path("fixtures/valid_packets/retail_valid_a.zip")
    expected = sha256(path.read_bytes()).hexdigest()
    with load_archive(path, config) as extracted:
        good = verify_hashes(extracted.temp_dir, extracted.manifest, config,
                             expected_package_hash=expected, package_path=path)
        no_path = verify_hashes(extracted.temp_dir, extracted.manifest, config,
                                expected_package_hash=expected)
        invalid = verify_hashes(extracted.temp_dir, extracted.manifest, config,
                                expected_package_hash="bad", package_path=path)
    assert good["passed"]
    assert no_path["error_codes"] == ["package_hash_unavailable"]
    assert invalid["error_codes"] == ["invalid_expected_hash"]


def test_manifest_itself_excluded(tmp_path, config):
    root = tmp_path / "root"
    root.mkdir()
    (root / "manifest.yaml").write_text("files: {}\n", encoding="utf-8")
    result = verify_hashes(root, {"files": {}, "tables": {}}, config)
    assert result["passed"]


def test_bare_md5_and_declared_manifest_key(tmp_path, config):
    from hashlib import md5 as md5_func
    path = Path("fixtures/valid_packets/retail_valid_a.zip")
    result = verify_package_hash(path, md5_func(path.read_bytes()).hexdigest())
    assert result["passed"]
    root = tmp_path / "root"
    root.mkdir()
    manifest = root / "manifest.yaml"
    manifest.write_text("files: {}\n", encoding="utf-8")
    result = verify_hashes(root, {"files": {"manifest.yaml": {"sha256": "0" * 64}},
                                  "tables": {}}, config)
    assert result["passed"]


def test_equivalent_declared_paths_do_not_double_report(tmp_path, config):
    """等价写法（./、//、大小写）不应同时触发缺失与冗余。"""
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    data = root / "data" / "users.csv"
    data.write_text("id\n1\n", encoding="utf-8")
    hashes = {"md5": md5(data.read_bytes()).hexdigest(),
              "sha256": sha256(data.read_bytes()).hexdigest()}
    for declared in ("./data/users.csv", "data//users.csv", "DATA/USERS.CSV"):
        result = verify_hashes(root, {"files": {declared: hashes}, "tables": {}}, config)
        assert result["passed"], (declared, result["errors"])
        assert result["checked_files"] == 1


def test_redundant_file_still_blocked_with_normalized_declarations(tmp_path, config):
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    data = root / "data" / "users.csv"
    data.write_text("id\n1\n", encoding="utf-8")
    (root / "data" / "extra.csv").write_text("id\n2\n", encoding="utf-8")
    hashes = {"sha256": sha256(data.read_bytes()).hexdigest()}
    result = verify_hashes(root, {"files": {"data//users.csv": hashes}, "tables": {}}, config)
    assert not result["passed"]
    assert result["error_codes"] == ["redundant_file"]
    assert result["errors"][0]["path"] == "data/extra.csv"


def test_md5_only_manifest_still_accepted(tmp_path, config):
    root = tmp_path / "root"
    root.mkdir()
    data = root / "a.csv"
    data.write_text("id\n1\n", encoding="utf-8")
    result = verify_hashes(root, {
        "files": {"a.csv": {"md5": md5(data.read_bytes()).hexdigest()}},
        "tables": {},
    }, config)
    assert result["passed"]
    assert result["checked_files"] == 1
