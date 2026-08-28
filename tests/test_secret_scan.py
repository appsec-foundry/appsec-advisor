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
        # The 2026-08-18 juice-shop release-blocker: `token=` glued into
        # `#access_token`, with the next English word of the sentence read as
        # the assigned value.
        "An attacker lures a victim to a URL carrying an attacker-supplied "
        "#access_token= fragment; the router matcher activates OAuthComponent.",
        "The handler sets the ?api_key= parameter in the query string before dispatch.",
        "Here the token: attacker-controlled value is accepted without validation.",
        "The endpoint reads password= directly from request.body and trusts it.",
        "It forwards the bearer token= Authorization header to the upstream service.",
    ],
)
def test_credential_parameter_name_in_prose_not_flagged(secret_scan, raw):
    """A threat model describes credential handling for a living, so a keyword
    glued into a larger token (``#access_token=``, ``?api_key=``) must not read
    as an assignment just because an English word follows it.

    ``mask_text`` is asserted alongside ``scan_text`` because the masker mirrors
    the detector: before this guard it rewrote the sentence to
    ``#access_token= **** (8 chars)``, silently corrupting prose.
    """
    hits = [h for h in secret_scan.scan_text(raw) if h.pattern == "generic_credential_assignment"]
    assert hits == [], f"prose credential keyword should not flag: {raw!r}, got {hits}"
    masked, _ = secret_scan.mask_text(raw)
    assert masked == raw, f"masker must leave prose intact: {raw!r} -> {masked!r}"


@pytest.mark.parametrize(
    "raw",
    [
        # The 2026-08-28 juice-shop case: a credential keyword opening a JSON
        # string scalar in a PRIOR RUN's artifact. The lead-in is `      "` —
        # no English word — so the backward mid-sentence test failed and the
        # next word of the sentence was harvested as a 10-char credential. It
        # then nuked every literal "referenced" in the freshly rendered report.
        '      "LLM_API_KEY: referenced in routes/chat.ts:111 via process.env '
        '— value at runtime only, not hardcoded"',
        # Same shape, other lead-ins that carry prose but no preceding word.
        "- API_KEY: referenced in the config loader, never hardcoded",
        "// token: retrieved from the vault at startup and cached in memory",
        "# password: supplied by the operator during first-run activation",
        "  * secret: injected through the deployment pipeline at boot",
    ],
)
def test_prose_after_non_alphabetic_lead_in_not_flagged(secret_scan, raw):
    """A credential keyword may open a line behind a quote, bullet, or comment
    marker and still be prose. The backward "a word precedes the keyword" test
    cannot see that, so the forward sentence-continuation test has to decide.

    Pure indentation stays excluded from this relief — ``  secret: changeme``
    is a YAML key and must keep flagging (asserted below).
    """
    hits = [h for h in secret_scan.scan_text(raw) if h.pattern == "generic_credential_assignment"]
    assert hits == [], f"prose after a non-alphabetic lead-in should not flag: {raw!r}, got {hits}"
    masked, _ = secret_scan.mask_text(raw)
    assert masked == raw, f"masker must leave prose intact: {raw!r} -> {masked!r}"


@pytest.mark.parametrize(
    "raw",
    [
        "  secret: changeme",  # YAML key (indent, not mid-sentence) → flags
        "const secret = mypassword",  # code assignment with `=` → flags
        "Rotate the secret: hunter2longer",  # prose but value has a digit → flags
        "the secret: 'existing'",  # quoted value → flags
        # Non-alphabetic lead-ins that are NOT prose: the value ends its line
        # (a config value), carries a digit, or is quoted. The lead-in relief
        # must not reach any of these.
        "# password: hunter2longer",
        "- api_key: 'quotedliteral'",
        "// token: opaquetokenvalue",
        # The same URL-fragment prose as above, but carrying a real token.
        "An attacker replays #access_token=eyJhbGciOiJIUzI1NiJ9 captured from the log",
        # Alphabetic, mid-sentence, sentence continues — but longer than any
        # English word the guard admits (segment cap is 13 chars).
        "the bearer=abcdefghijklmnop is hardcoded",
        "the bearer=sunflowerpower is hardcoded",
        "password= admin123456",  # digit-bearing value after `= ` → flags
    ],
)
def test_prose_guard_does_not_swallow_real_assignments(secret_scan, raw):
    """The prose guard is narrow: a genuine assignment / key, a digit-bearing
    value, or a quoted value must still flag even in a sentence-like line."""
    assert any(h.pattern == "generic_credential_assignment" for h in secret_scan.scan_text(raw)), (
        f"expected a loose-pattern hit for {raw!r}"
    )


# One evidence sentence whose credential-adjacent word is the LAST word before
# the wrapper. scan_text runs over raw bytes, so the same sentence reaches it
# differently per artifact — this is the axis the guard has to be blind to.
_PROSE_SENTENCE = "confirms the oauthMatcher routes on #access_token= presence"

_SERIALIZATION_WRAPPERS = {
    "markdown_raw": _PROSE_SENTENCE + ".",
    "markdown_table_cell": "| " + _PROSE_SENTENCE + ". |",
    "yaml_single_quoted": _PROSE_SENTENCE + ".'",
    "yaml_double_quoted": _PROSE_SENTENCE + '."',
    "json_string": '{"evidence_summary": "' + _PROSE_SENTENCE + '."}',
    "sarif_message_text": '"text": "' + _PROSE_SENTENCE + '."',
    "html_cell_break": _PROSE_SENTENCE + ".<br>",
    "closing_paren": "(" + _PROSE_SENTENCE + ".)",
    "closing_backtick": _PROSE_SENTENCE + ".`",
    # Every shape above appends a clause terminator first, so none of them
    # exercised a value left line-final by a FOLD rather than by a sentence end
    # — the one serialization behaviour that still broke the guard
    # (juice-shop 2026-08-21). `yaml.safe_dump(…, width=120)` breaks a long
    # scalar mid-sentence, and the continuation lands on the next line.
    "yaml_folded_scalar": "  evidence_summary: '" + _PROSE_SENTENCE + "\n    in the callback URL.'",
    "yaml_folded_then_key": "  evidence_summary: '" + _PROSE_SENTENCE + "\n    in the callback URL.'\n  impact: High",
}


@pytest.mark.parametrize("wrapper", sorted(_SERIALIZATION_WRAPPERS))
def test_prose_guard_is_serialization_independent(secret_scan, wrapper):
    """The prose false-positive guard must not depend on how the artifact
    serializes the sentence.

    The 2026-08-20 juice-shop release-blocker: the guard's "sentence continues"
    test accepted a clause terminator only when whitespace or the line end
    followed it. PyYAML wraps a scalar in ``'…'``, so the sentence-final period
    was followed by a quote, the guard fell through, and the English word
    "presence" was reported as a 9-character credential in threat-model.yaml —
    blocking the release gate with no automatic repair path. Only unwrapped
    markdown was ever covered; 7 of these 9 shapes false-positived.
    """
    raw = _SERIALIZATION_WRAPPERS[wrapper]
    hits = [h for h in secret_scan.scan_text(raw) if h.pattern == "generic_credential_assignment"]
    assert hits == [], f"{wrapper}: prose must not flag: {raw!r}, got {[h.value for h in hits]}"
    masked, _ = secret_scan.mask_text(raw)
    assert masked == raw, f"{wrapper}: masker must leave prose intact -> {masked!r}"


@pytest.mark.parametrize("wrapper", sorted(_SERIALIZATION_WRAPPERS))
@pytest.mark.parametrize(
    "literal",
    ["api_key= aB3xK9mQ7zR2pL5w", "password= Hunter2Winter99", "secret= s3cr3tvalue123"],
)
def test_wrapper_tolerance_does_not_hide_real_literals(secret_scan, wrapper, literal):
    """Tolerating a closing delimiter must not open a false-negative hole: the
    same wrappers carrying a REAL credential still have to flag."""
    raw = _SERIALIZATION_WRAPPERS[wrapper].replace("#access_token= presence", literal)
    assert any(h.pattern == "generic_credential_assignment" for h in secret_scan.scan_text(raw)), (
        f"{wrapper}: real literal must still flag: {raw!r}"
    )


def test_mask_structure_keeps_yaml_parseable(secret_scan):
    """Masking must happen on the decoded document, never on serialized YAML.

    ``**** (N chars)`` at the head of a plain scalar is a YAML alias indicator,
    so text-level masking of ``api_key: aB3xK9mQ7zR2pL5w`` yields a document
    PyYAML cannot parse — a corrupt canonical model. mask_structure() masks the
    string and leaves quoting to the serializer.
    """
    yaml = pytest.importorskip("yaml")
    doc = {"meta": {"api_key": "aB3xK9mQ7zR2pL5w"}, "threats": [{"evidence": "uses token=aB3xK9mQ7zR2pL5w here"}]}

    text_masked, _ = secret_scan.mask_text(yaml.safe_dump(doc, sort_keys=False))
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(text_masked)  # documents the corruption mask_structure avoids

    masked_doc, applied = secret_scan.mask_structure(doc)
    assert applied, "a real literal must be masked"
    roundtripped = yaml.safe_load(yaml.safe_dump(masked_doc, sort_keys=False))
    assert roundtripped == masked_doc
    assert "aB3xK9mQ7zR2pL5w" not in yaml.safe_dump(masked_doc)
    assert secret_scan.scan_text(yaml.safe_dump(masked_doc)) == []


def test_mask_structure_leaves_keys_and_non_strings_alone(secret_scan):
    """Mapping keys are structure, not analyst prose — rewriting one would drop
    a field. Non-string leaves pass through untouched."""
    doc = {"api_key": "n/a", "count": 7, "flag": True, "none": None, "items": ["plain", 3]}
    masked, applied = secret_scan.mask_structure(doc)
    assert applied == []
    assert masked == doc
    assert list(masked) == list(doc)


def test_mask_structure_reads_the_key_for_context(secret_scan):
    """Decoding splits ``keyword: value`` across a key and its value, so a
    key-blind masker would never see ``{"api_key": "<literal>"}``. The key is
    read for context but never rewritten."""
    doc = {"api_key": "aB3xK9mQ7zR2pL5w"}
    masked, applied = secret_scan.mask_structure(doc)
    assert applied == ["generic_credential_assignment"]
    assert list(masked) == ["api_key"], "the key itself must survive verbatim"
    assert masked["api_key"] == "**** (16 chars)"


@pytest.mark.parametrize(
    "raw",
    [
        # 2026-06-18 e2e regression: a requirements-compliance row whose ID ends
        # in a credential keyword (-AUTH) followed by a Capitalised title word.
        "| SEC-USER-AUTH: Authenticate users via standard mechanisms | FAIL |",
        "SEC-API-TOKEN: Issue scoped tokens to callers",
        "- REQ-USER-SECRET: Store rotation evidence per tenant",
    ],
)
def test_requirement_id_keyword_not_flagged(secret_scan, raw):
    """A credential keyword that is the trailing segment of a SCREAMING-KEBAB
    identifier (requirement ID) is an ID label, not `keyword = <literal>` — the
    detector and masker must leave the title word intact."""
    hits = [h for h in secret_scan.scan_text(raw) if h.pattern == "generic_credential_assignment"]
    assert hits == [], f"requirement-ID keyword should not flag: {raw!r}, got {hits}"
    masked, applied = secret_scan.mask_text(raw)
    assert masked == raw and applied == [], (masked, applied)


@pytest.mark.parametrize(
    "raw",
    [
        "client-secret: hunter2longerval",  # lowercase kebab config key → flags
        "x-auth: somecredvalue123",  # lowercase header-style key → flags
        "API_KEY: skabcdefghij12345",  # uppercase but NOT hyphen-preceded → flags
    ],
)
def test_identifier_suffix_guard_does_not_swallow_real_keys(secret_scan, raw):
    """The identifier-suffix guard only skips an UPPERCASE keyword preceded by a
    hyphen. A lowercase hyphen-kebab config key, or an uppercase key that is not
    a hyphen suffix, must still flag."""
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


# --- Regression: loose-pattern false positives that corrupted a shipped report
# (2026-07-19 insecure-python-app run). Each of the three guards below let the
# exact-value redactor rewrite legitimate prose/code; the strict-format patterns
# must keep firing in exactly the same contexts.


def test_trailing_sentence_punctuation_does_not_defeat_keyword_echo(secret_scan):
    """``Password: password.`` captured ``password.`` — the trailing period made
    the keyword-echo guard miss, and the redactor then rewrote every
    ``password``-prefixed token document-wide."""
    prose = "Demo users: alice, bob, admin. Password: password. <a href=/register>"
    assert secret_scan.scan_text(prose) == []


def test_snake_case_identifier_is_a_code_reference(secret_scan):
    assert secret_scan.scan_text("Auth: read_unsigned_jwt_claims") == []
    assert secret_scan.scan_text("Auth: decode_homegrown_session_token") == []


def test_mermaid_labels_are_not_credential_assignments(secret_scan):
    diagram = (
        "```mermaid\n"
        "sequenceDiagram\n"
        '    participant Auth as "auth.py:84"\n'
        "    Auth->>Auth: base64-decode payload\n"
        "```\n"
    )
    assert secret_scan.scan_text(diagram) == []


def test_strict_formats_still_fire_inside_mermaid(secret_scan):
    """Mermaid is exempt from the LOOSE pattern only — a real token pasted into a
    diagram label is still a leak."""
    diagram = (
        "```mermaid\n    A->>B: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiQURNSU4ifQ.sigsigsigsig\n```\n"
    )
    assert [h.pattern for h in secret_scan.scan_text(diagram)] == ["jwt"]


def test_secrets_in_non_mermaid_fences_still_fire(secret_scan):
    """Only ```mermaid is exempt (and only from the loose pattern) — a strict
    token inside any other fence is a genuine leak. Uses AWS's documentation
    key: a literal matching a live provider format trips GitHub push
    protection even as an obvious dummy."""
    block = '```python\naws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n```\n'
    assert "aws_access_key" in {h.pattern for h in secret_scan.scan_text(block)}


def test_quoted_keyword_echo_and_opaque_values_still_flag(secret_scan):
    assert secret_scan.scan_text('password = "password"') != []
    assert secret_scan.scan_text("secret: deadbeef1234") != []


# --- Special-character credentials: mask must consume the WHOLE value --------
# Regression for the 2026-07-25 juice-shop run: the value charset stopped at the
# first character outside [A-Za-z0-9_\-+/=.], so only the alnum head was masked
# and the rest of the password shipped in cleartext after the mask marker.


def test_mask_consumes_whole_special_character_password(secret_scan):
    """The full credential is replaced — no cleartext tail survives the mask,
    and the reported length matches the real password length."""
    pw = "J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P"
    masked, applied = secret_scan.mask_text(f"  password: '{pw}'")
    assert "generic_credential_assignment" in applied
    assert f"**** ({len(pw)} chars)" in masked
    # No fragment of the secret may survive anywhere in the output.
    for tail in ("@?5l!", "Zkq2AYnCE", "@RF$P", "J6aVjTgOpRs"):
        assert tail not in masked


def test_masked_special_character_password_has_no_residual_leak(secret_scan):
    """End-to-end: the masked document must be clean under the detector AND
    contain no substring of the original secret. The gate shares this regex, so
    an under-capture would be invisible to it — this asserts the value itself."""
    pw = "Tr0ub4dor#%3xK"
    masked, _ = secret_scan.mask_text(f'password = "{pw}"')
    assert secret_scan.scan_text(masked) == []
    assert pw not in masked
    assert "#%3xK" not in masked


def test_special_character_password_is_detected_at_full_length(secret_scan):
    hits = secret_scan.scan_text("password: 'A9x!c@dE#f$g%h?j'")
    assert [h.value for h in hits] == ["A9x!c@dE#f$g%h?j"]


def test_unquoted_env_and_anchor_references_are_not_credentials(secret_scan):
    """The widened charset admits ``$`` and ``#``; unquoted values that are
    plainly references (env/template vars, markdown anchors) must not be
    flagged — masking them would blind-replace the reference document-wide."""
    assert secret_scan.scan_text("password: $DATABASE_PASSWORD") == []
    assert secret_scan.scan_text("secret: #section-anchor-name") == []


def test_quoted_dollar_value_still_flags(secret_scan):
    """A quoted value is an intentional literal even when it looks like a
    variable — the reference carve-out is unquoted-only, as for code refs."""
    assert secret_scan.scan_text("password: '$DATABASE_PASSWORD'") != []


def test_widened_charset_does_not_swallow_markup_or_urls(secret_scan):
    """Markdown-active characters and ``:`` stay out of the charset so the
    blind exact-value redactor can never rewrite prose, links, or URLs."""
    assert secret_scan.scan_text("token: *placeholder-value*") == []
    assert secret_scan.scan_text("secret: [see the docs](secrets.md)") == []
    assert secret_scan.scan_text("auth: https://example.com/path?x=1") == []


# --- Env-style credential assignments ---------------------------------------
# A bare \b rejects a keyword preceded by "_", so DB_PASSWORD= and friends were
# never detected — the canonical shape in .env files, docker-compose, and k8s
# manifests. A report quoting one passed the release gate in cleartext.


def test_env_style_credential_assignments_are_detected(secret_scan):
    for line in (
        "DB_PASSWORD=Pr0dDbP4ss!2024",
        "export DB_PASSWORD=Pr0dDbP4ss!2024",
        "MYSQL_ROOT_PASSWORD: Pr0dDbP4ss!24",
        "SPRING_DATASOURCE_PASSWORD=Sup3rS3cretDb",
        "X_AUTH_TOKEN=abcdef1234567890",
        "ANTHROPIC_API_KEY=sk-ant-abcdef123456",
    ):
        assert secret_scan.scan_text(line), f"missed env-style credential: {line}"


def test_env_style_credential_is_masked_in_a_report(secret_scan):
    """The release gate reads the rendered report — a quoted env credential must
    not survive masking, which is the path that shipped cleartext before."""
    report = "The manifest hardcodes it:\n\n    DB_PASSWORD=Pr0dDbP4ss!2024\n"
    masked, applied = secret_scan.mask_text(report)
    assert "generic_credential_assignment" in applied
    assert "Pr0dDbP4ss!2024" not in masked
    assert secret_scan.scan_text(masked) == []


def test_keyword_ending_a_word_is_not_a_credential(secret_scan):
    """Only "_" is admitted before the keyword. Dropping the word boundary
    entirely would mask ordinary headings and prose whose last word happens to
    end in a credential keyword."""
    assert secret_scan.scan_text("## OAuth: Configuration Options") == []
    assert secret_scan.scan_text("See reauth: Documentation for details") == []


# ---------------------------------------------------------------------------
# Demonstrated attacker input is not secret material
# ---------------------------------------------------------------------------


def test_sqli_tautology_payload_is_not_a_credential(secret_scan):
    """Regression (2026-07-25 insecure-spring-app): the §3 walkthrough and the
    finding's Verification line quote the request that reproduces the SQLi, and
    its ``password=`` query parameter carries the tautology payload — the loose
    credential-assignment shape without a credential. The gate hard-failed
    (exit 2; headless aborts the whole run), and masking to clear it left
    ``?username=x&password=**** (21 chars)`` — a reproduction step that no
    longer reproduces anything."""
    for line in (
        "An attacker sends `GET /api/legacy-sqlite/login-raw?username=x&password=%27+OR+%271%27%3D%271`.",
        'curl "http://host/login?password=%27%20OR%20%271%27%3D%271"',
        "POST /login with password=' OR '1'='1",
        "password=%22+OR+1%3D1--",
    ):
        assert secret_scan.scan_text(line) == [], f"SQLi payload flagged as a secret: {line}"


def test_unsigned_alg_none_jwt_is_not_a_credential(secret_scan):
    """An ``alg:none`` JWT has no signature by construction — anyone can mint
    one, and quoting it is what demonstrates the missing verification. It holds
    no secret material, so masking it only destroys the PoC."""
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4Iiwicm9sZSI6IkFETUlOIn0."
    line = f"Send `GET /api/legacy-admin/audit?token={token}` — must return HTTP 401 or 403."
    assert secret_scan.scan_text(line) == [], "unsigned alg:none demo token flagged as a secret"


def test_signed_jwt_is_still_flagged(secret_scan):
    """The alg:none carve-out must not extend to a real signed token — that one
    carries a signature produced with the server's key and stays a leak."""
    signed = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrst"
    hits = secret_scan.scan_text(f"token={signed}")
    assert hits, "signed JWT must still be flagged"
    assert "jwt" in {h.pattern for h in hits}


def test_demo_payload_carveout_does_not_leak_real_credentials(secret_scan):
    """Precision guard: the carve-out is decided structurally on the value, so a
    genuine credential sitting on a walkthrough line is still caught."""
    line = "An attacker sends `GET /login?password=Pr0dDbP4ss!2024` to the endpoint."
    assert secret_scan.scan_text(line), "real credential in a walkthrough must still flag"


def test_masker_preserves_demo_payloads(secret_scan):
    """mask_text is the detector's masking twin and mirrors every skip rule. If
    the demo-payload guard lived only in scan_text, the composer's masking pass
    would still rewrite the PoC — the gate would go green while the walkthrough
    stayed destroyed. Both halves must agree."""
    walkthrough = (
        "1. An attacker sends `GET /login-raw?username=x&password=%27+OR+%271%27%3D%271`.\n"
        "2. Send `GET /audit?token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.` — expect HTTP 401.\n"
    )
    masked, applied = secret_scan.mask_text(walkthrough)
    assert masked == walkthrough, f"masker rewrote a demo payload: {masked}"
    assert applied == []
    assert secret_scan.scan_text(masked) == []
