"""Unit tests for scripts/secret_scan.py — strict-format leaks, loose-pattern
credential assignments, and the masking-marker exemption."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "secret_scan.py"


def _load():
    spec = importlib.util.spec_from_file_location("secret_scan", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["secret_scan"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def secret_scan():
    return _load()


# ----------------------------------------------------------------------------
# Strict format patterns — a match means a real leak. These should fire even
# when surrounded by masking markers elsewhere in the document, because the
# format itself is the leak.
# ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,pattern_name",
    [
        ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        ("ASIAIOSFODNN7EXAMPLE", "aws_access_key"),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github_pat"),
        ("gho_abcdefghijklmnopqrstuvwxyz0123456789", "github_oauth"),
        ("ghs_abcdefghijklmnopqrstuvwxyz0123456789", "github_app"),
        ("ghr_abcdefghijklmnopqrstuvwxyz0123456789", "github_refresh"),
        ("AIzaSyDxYz0123456789abcdefghijklmnopQRS", "google_api_key"),
        ("xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx", "slack_token"),
        ("xoxp-1234567890-1234567890-1234567890-abcdefabcdefabcdef", "slack_token"),
        ("sk_live_abcdefghijklmnopqrstuvwxyz", "stripe_live_secret"),
        ("sk_test_abcdefghijklmnopqrstuvwxyz", "stripe_test_secret"),
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_here_for_test",
            "jwt",
        ),
    ],
)
def test_strict_patterns_flagged(secret_scan, raw, pattern_name):
    hits = secret_scan.scan_text(f"prefix {raw} suffix")
    names = {h.pattern for h in hits}
    assert pattern_name in names, f"expected {pattern_name} in {names}"


def test_pem_private_key_flagged(secret_scan):
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    hits = secret_scan.scan_text(pem)
    assert any(h.pattern == "pem_private_key" for h in hits)


def test_pem_private_key_variants(secret_scan):
    for header in (
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ):
        hits = secret_scan.scan_text(header)
        assert any(h.pattern == "pem_private_key" for h in hits), header


# ----------------------------------------------------------------------------
# Loose key=value patterns — must be exempted when the captured value
# contains any masking marker.
# ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        'password = "admin123longer"',
        "API_KEY: deadbeef12345678",
        "secret='hunter2longenough'",
        "bearer=abcdefghijklmnop",
        "token: someopaquetoken1234",
    ],
)
def test_loose_assignment_flagged(secret_scan, raw):
    hits = secret_scan.scan_text(raw)
    assert any(h.pattern == "generic_credential_assignment" for h in hits), raw


@pytest.mark.parametrize(
    "raw",
    [
        'password = "****"',
        'password: "**** (12 chars)"',
        "API_KEY = AIza****",
        "secret = [REDACTED]",
        "token: <REDACTED>",
        "bearer = MASKED",
        "password: XXXXXXXX",
        "secret = <...>",
        "API_KEY = TRwz****",  # 4-char prefix style
    ],
)
def test_masked_values_not_flagged(secret_scan, raw):
    hits = [h for h in secret_scan.scan_text(raw) if h.pattern == "generic_credential_assignment"]
    assert hits == [], f"expected no loose-pattern hits for {raw!r}, got {hits}"


# ----------------------------------------------------------------------------
# Clean inputs — properly redacted threat-model prose must produce 0 hits.
# ----------------------------------------------------------------------------


def test_realistic_masked_report_clean(secret_scan):
    sample = """
    | T-014 | Hardcoded JWT signing key in `lib/insecurity.ts:18` (`L8T1****`). |
    | T-031 | Default admin password in `data/seed-users.ts:4` (`**** (8 chars)`). |
    | T-042 | CTF answer secret in `ctf.key:1` (`TRwz****`). |
    | T-055 | Stripe live key in `config/payments.yaml:12` (`sk_live_****`). |
    """
    hits = secret_scan.scan_text(sample)
    assert hits == [], f"expected clean, got {hits}"


def test_empty_input_clean(secret_scan):
    assert secret_scan.scan_text("") == []


# ----------------------------------------------------------------------------
# Line numbers and snippet truncation.
# ----------------------------------------------------------------------------


def test_line_number_reported(secret_scan):
    text = "line 1\nline 2\nAKIAIOSFODNN7EXAMPLE\nline 4\n"
    hits = secret_scan.scan_text(text)
    aws_hits = [h for h in hits if h.pattern == "aws_access_key"]
    assert len(aws_hits) == 1
    assert aws_hits[0].line == 3


def test_snippet_truncated_to_80(secret_scan):
    # PEM headers are short; manufacture a long match by stacking a JWT segment.
    long_jwt = "eyJ" + "A" * 200 + ".eyJ" + "B" * 200 + "." + "C" * 200
    hits = secret_scan.scan_text(long_jwt)
    jwt_hits = [h for h in hits if h.pattern == "jwt"]
    assert jwt_hits
    assert len(jwt_hits[0].snippet) <= 80


# ----------------------------------------------------------------------------
# File-based entry point.
# ----------------------------------------------------------------------------


def test_scan_file_roundtrip(secret_scan, tmp_path):
    p = tmp_path / "sample.md"
    p.write_text("Inline AWS key AKIAIOSFODNN7EXAMPLE for demo.\n")
    hits = secret_scan.scan_file(p)
    assert any(h.pattern == "aws_access_key" for h in hits)


def test_scan_file_missing_returns_empty(secret_scan, tmp_path):
    assert secret_scan.scan_file(tmp_path / "does-not-exist.md") == []


# ----------------------------------------------------------------------------
# CLI entry point — exit code semantics.
# ----------------------------------------------------------------------------


def test_main_clean_exit_0(secret_scan, tmp_path, capsys):
    p = tmp_path / "clean.md"
    p.write_text("All secrets are masked here: `AIza****`.\n")
    rc = secret_scan.main(["secret_scan.py", str(p)])
    assert rc == 0


def test_main_leak_exit_1(secret_scan, tmp_path, capsys):
    p = tmp_path / "leak.md"
    p.write_text("Leaked: AKIAIOSFODNN7EXAMPLE\n")
    rc = secret_scan.main(["secret_scan.py", str(p)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "aws_access_key" in out


def test_main_bad_args_exit_2(secret_scan, capsys):
    rc = secret_scan.main(["secret_scan.py"])
    assert rc == 2
