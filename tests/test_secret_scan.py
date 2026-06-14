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
        "secret: publicKey",  # camelCase code identifier, not a secret
        "password: security.hash",  # dotted attribute path
        "secret = config.apiKey",  # dotted path with camelCase tail
        "token: PublicKey",  # PascalCase identifier
        "api_key: this.that.other",  # multi-segment dotted path
    ],
)
def test_bareword_code_reference_not_flagged(secret_scan, raw):
    """Unquoted code-identifier values (variable names in code excerpts) are
    references, not literal secrets — they must not trip the loose pattern."""
    hits = [h for h in secret_scan.scan_text(raw) if h.pattern == "generic_credential_assignment"]
    assert hits == [], f"code-reference value should not flag: {raw!r}, got {hits}"


@pytest.mark.parametrize(
    "raw",
    [
        "password: 'EinBelegtesBrotMitSchinkenSCHINKEN'",  # quoted literal — flags despite shape
        "bearer=abcdefghijklmnop",  # opaque all-lowercase token
        "token: someopaquetoken1234",  # has digits
        "secret = config2apiKey",  # has a digit → not a pure code ref
    ],
)
def test_real_or_opaque_credentials_still_flagged(secret_scan, raw):
    assert any(h.pattern == "generic_credential_assignment" for h in secret_scan.scan_text(raw)), (
        f"expected a loose-pattern hit for {raw!r}"
    )


@pytest.mark.parametrize(
    "raw",
    [
        # The 2026-06-05 juice-shop release-blocker: a credential keyword used
        # mid-sentence in a remediation step, not an assignment.
        "    - 'Rotate the secret: existing SecurityAnswers rows are invalidated.'",
        "Update the password: required before the next login window.",
        "Store the token: separately from the application config.",
    ],
)
def test_prose_credential_keyword_not_flagged(secret_scan, raw):
    """A credential keyword followed by a plain English word mid-sentence is
    prose, not `keyword = <literal>`. The guard requires unquoted value + colon
    operator + plain lowercase word + a preceding word, so it cannot mask a
    real literal."""
    hits = [h for h in secret_scan.scan_text(raw) if h.pattern == "generic_credential_assignment"]
    assert hits == [], f"prose credential keyword should not flag: {raw!r}, got {hits}"


@pytest.mark.parametrize(
    "raw",
    [
        "  secret: changeme",  # YAML key (indent, not mid-sentence) → flags
        "const secret = mypassword",  # code assignment with `=` → flags
        "Rotate the secret: hunter2longer",  # prose but value has a digit → flags
        "the secret: 'existing'",  # quoted value → flags
    ],
)
def test_prose_guard_does_not_swallow_real_assignments(secret_scan, raw):
    """The prose guard is narrow: a genuine assignment / key, a digit-bearing
    value, or a quoted value must still flag even in a sentence-like line."""
    assert any(h.pattern == "generic_credential_assignment" for h in secret_scan.scan_text(raw)), (
        f"expected a loose-pattern hit for {raw!r}"
    )


def test_prose_credential_keyword_not_masked(secret_scan):
    """mask_text mirrors the detector — it must not corrupt a remediation
    sentence by redacting an English word."""
    line = "    - 'Rotate the secret: existing rows are invalidated.'"
    masked, applied = secret_scan.mask_text(line)
    assert masked == line and applied == [], (masked, applied)


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


# ----------------------------------------------------------------------------
# mask_text — the masking twin of scan_text (juice-shop 2026-06-03 secret gate)
# ----------------------------------------------------------------------------


def test_mask_text_password_assignment(secret_scan):
    masked, applied = secret_scan.mask_text("  password: 'admin123'")
    assert "admin123" not in masked
    assert "**** (8 chars)" in masked
    assert "generic_credential_assignment" in applied


def test_mask_text_pem_marker(secret_scan):
    masked, applied = secret_scan.mask_text("const k = '-----BEGIN RSA PRIVATE KEY-----\\nMIIC...'")
    assert "BEGIN RSA PRIVATE KEY" not in masked
    assert "pem_private_key" in applied


def test_mask_text_is_symmetric_with_scan(secret_scan):
    # Anything scan_text would flag must be gone after mask_text — this is the
    # guarantee that the composer + yaml mask can never trip the gate.
    samples = [
        "password: 'admin123'",
        "email: admin\\n  password: 'admin123'",
        "AKIAIOSFODNN7EXAMPLE",
        "key AIzaSyA1234567890abcdefghijklmnopqrstuv end",
        "const privateKey = '-----BEGIN RSA PRIVATE KEY-----\\nMIIC...'",
    ]
    for s in samples:
        masked, _ = secret_scan.mask_text(s)
        assert secret_scan.scan_text(masked) == [], "residual hit for " + repr(s)


def test_mask_text_preserves_code_reference(secret_scan):
    # Unquoted code-identifier references are not literal secrets.
    for s in ("secret: publicKey", "password: security.hash"):
        masked, applied = secret_scan.mask_text(s)
        assert masked == s
        assert applied == []


def test_mask_text_idempotent(secret_scan):
    once, _ = secret_scan.mask_text("password: 'admin123'")
    twice, applied2 = secret_scan.mask_text(once)
    assert twice == once
    assert applied2 == []


def test_mask_text_empty_and_already_masked(secret_scan):
    assert secret_scan.mask_text("") == ("", [])

    sample = "password: MASKEDTOKEN"
    masked, applied = secret_scan.mask_text(sample)
    assert masked == sample
    assert applied == []


def test_mask_file_missing_returns_empty(secret_scan, tmp_path):
    assert secret_scan.mask_file(tmp_path / "missing.md") == []


def test_mask_file_writes_in_place(secret_scan, tmp_path):
    p = tmp_path / "leak.md"
    p.write_text("password: 'admin123'\n", encoding="utf-8")

    applied = secret_scan.mask_file(p)

    text = p.read_text(encoding="utf-8")
    assert "generic_credential_assignment" in applied
    assert "admin123" not in text
    assert "**** (8 chars)" in text
    assert secret_scan.scan_text(text) == []


def test_main_mask_mode_masks_and_reports(secret_scan, tmp_path, capsys):
    clean = tmp_path / "clean.md"
    leak = tmp_path / "leak.md"
    clean.write_text("password: **** (8 chars)\n", encoding="utf-8")
    leak.write_text("AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

    rc = secret_scan.main(["secret_scan.py", "--mask", str(clean), str(leak)])

    assert rc == 0
    out = capsys.readouterr().out
    assert str(leak) in out
    assert "aws_access_key" in out
    assert str(clean) not in out
    assert secret_scan.scan_file(leak) == []
