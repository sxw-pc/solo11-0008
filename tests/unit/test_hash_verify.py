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


def _write_declared(root, name, data=b"id\n1\n"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    digest_md5 = md5(data).hexdigest()
    digest_sha = sha256(data).hexdigest()
    return name, {"md5": digest_md5, "sha256": digest_sha}


def test_path_spelling_variants_match_same_file(tmp_path, config):
    """./ 前缀、双斜杠等写法不应再产生缺失+冗余双误判。"""
    from gateway.validator.hash_verify import _normalize_relpath
    assert _normalize_relpath("./data/users.csv") == "data/users.csv"
    assert _normalize_relpath("data//users.csv") == "data/users.csv"
    assert _normalize_relpath("data/./x.csv") == "data/x.csv"
    root = tmp_path / "root"
    root.mkdir()
    _, hashes = _write_declared(root, "data/users.csv")
    for key in ("./data/users.csv", "data//users.csv", "data/./users.csv"):
        result = verify_hashes(root, {"files": {key: hashes}, "tables": {}}, config)
        assert result["passed"], (key, result["errors"])
        assert result["checked_files"] == 1


def test_case_insensitive_declaration_matches_actual(tmp_path, config):
    """manifest 与磁盘仅大小写不同的路径按同一文件处理，不误报缺失/冗余。"""
    root = tmp_path / "root"
    root.mkdir()
    _, hashes = _write_declared(root, "data/users.csv")
    result = verify_hashes(root, {"files": {"DATA/USERS.CSV": hashes}, "tables": {}},
                           config)
    assert result["passed"], result["errors"]


def test_real_redundant_file_still_blocked_with_normalization(tmp_path, config):
    """路径归一化后，真正未声明的文件仍必须被判冗余拦截。"""
    root = tmp_path / "root"
    root.mkdir()
    _, hashes = _write_declared(root, "data/users.csv")
    (root / "data").mkdir(exist_ok=True)
    (root / "data" / "extra.txt").write_text("unlisted", encoding="utf-8")
    result = verify_hashes(root, {"files": {"./data//users.csv": hashes},
                                  "tables": {}}, config)
    assert not result["passed"]
    assert "redundant_file" in result["error_codes"]


def test_duplicate_normalized_declaration_is_flagged(tmp_path, config):
    """两种写法归一化后指向同一文件时报告重复声明，而不是静默覆盖。"""
    root = tmp_path / "root"
    root.mkdir()
    name, hashes = _write_declared(root, "data/users.csv")
    manifest = {"files": {"data//users.csv": hashes, "./data/users.csv": hashes},
                "tables": {}}
    result = verify_hashes(root, manifest, config)
    assert "duplicate_declaration" in result["error_codes"]


def test_md5_only_legacy_manifest_still_passes(tmp_path, config):
    """仅提供 MD5、未提供 SHA256 的旧版 manifest 继续兼容通过。"""
    root = tmp_path / "root"
    root.mkdir()
    data = b"id\n1\n"
    (root / "a.csv").write_bytes(data)
    manifest = {"files": {"a.csv": {"md5": md5(data).hexdigest()}}, "tables": {}}
    result = verify_hashes(root, manifest, config)
    assert result["passed"], result["errors"]
