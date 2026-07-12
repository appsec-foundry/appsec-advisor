"""P3 (weakness-class evidence model) — crypto rule pack (data/crypto-checks.yaml)
and the path-traversal / XXE additions (INJ-004/005 in source-auth-checks.yaml),
both run through the existing source_auth_scanner engine."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import source_auth_scanner as S  # noqa: E402

CRYPTO = REPO_ROOT / "data" / "crypto-checks.yaml"
SOURCE_AUTH = REPO_ROOT / "data" / "source-auth-checks.yaml"


def _write(tmp_path: Path, name: str, body: str) -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


def _crypto_ids(tmp_path: Path) -> set[str]:
    findings = S.scan_repo(tmp_path, S.load_checks(CRYPTO))
    return {f.check_id for f in findings}


def _inj_ids(tmp_path: Path) -> set[str]:
    findings = S.scan_repo(tmp_path, S.load_checks(SOURCE_AUTH))
    return {f.check_id for f in findings if f.check_id.startswith("INJ-")}


# --- crypto pack ------------------------------------------------------------


def test_md5_hash_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "crypto.createHash('md5').update(pw).digest('hex')\n")
    assert "CRYPTO-001" in _crypto_ids(tmp_path)


def test_md5_for_etag_suppressed(tmp_path: Path) -> None:
    # counter-pattern: non-security hashing must not fire.
    _write(tmp_path, "a.js", "const etag = crypto.createHash('md5').update(body) // cache etag\n")
    assert "CRYPTO-001" not in _crypto_ids(tmp_path)


def test_math_random_token_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "const token = 'r' + Math.random()\n")
    assert "CRYPTO-002" in _crypto_ids(tmp_path)


def test_math_random_animation_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "const jitter = Math.random() * 100 // animation delay\n")
    assert "CRYPTO-002" not in _crypto_ids(tmp_path)


def test_low_bcrypt_rounds_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "bcrypt.genSaltSync(8)\nawait bcrypt.hash(pw, 6)\n")
    assert "CRYPTO-003" in _crypto_ids(tmp_path)


def test_adequate_bcrypt_rounds_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "bcrypt.genSaltSync(12)\n")
    assert "CRYPTO-003" not in _crypto_ids(tmp_path)


def test_ecb_mode_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "crypto.createCipheriv('aes-128-ecb', key, null)\n")
    assert "CRYPTO-004" in _crypto_ids(tmp_path)


# --- path traversal / XXE ---------------------------------------------------


def test_path_traversal_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "res.sendFile(path.join(root, req.query.name))\n")
    assert "INJ-004" in _inj_ids(tmp_path)


def test_path_traversal_sanitized_suppressed(tmp_path: Path) -> None:
    # The common safe form canonicalizes inline → counter-pattern suppresses.
    _write(tmp_path, "a.js", "res.sendFile(path.join(root, path.basename(req.query.name)))\n")
    assert "INJ-004" not in _inj_ids(tmp_path)


def test_xxe_noent_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "libxmljs.parseXml(input, { noent: true })\n")
    assert "INJ-005" in _inj_ids(tmp_path)


def test_crypto_cwes_map_to_weak_crypto_class() -> None:
    # The crypto CWEs must land in the weak_crypto weakness cluster so a
    # crypto finding folds under a weak_crypto weakness (P3 verify).
    import weakness_classifier as wc

    for cwe in ("CWE-328", "CWE-330", "CWE-916", "CWE-327"):
        assert wc.classify_cwe(cwe) == "weak_crypto", cwe
    assert wc.classify_cwe("CWE-22") == "injection"
    assert wc.classify_cwe("CWE-611") == "injection"


def test_crypto_findings_fold_under_weak_crypto_weakness() -> None:
    """P3 verify — crypto findings (insecure-practice) fold under one
    weak_crypto weakness rather than standing as confirmed vulns."""
    import merge_threats as mt

    threats = [
        {"t_id": "T-001", "source": "source-scan", "cwe": "CWE-328", "component_id": "auth",
         "risk": "Medium", "evidence": {"file": "auth.js", "line": 1}},
        {"t_id": "T-002", "source": "source-scan", "cwe": "CWE-916", "component_id": "auth",
         "risk": "Medium", "evidence": {"file": "auth.js", "line": 3}},
    ]
    w = mt.build_weakness_register(threats, None)
    assert len(w) == 1
    assert w[0]["weakness_class"] == "weak_crypto"
    assert len(w[0]["observable_backing"]["practice_evidence"]) == 2
    # crypto is a practice, never a confirmed exploit
    assert all(t["evidence_tier"] == "insecure-practice" for t in threats)
