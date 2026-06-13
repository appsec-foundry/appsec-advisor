"""Tests for scripts/normalize_security_architecture.py.

Each structural-defect test asserts the *gate's own* check fails before the
normalizer runs and passes after — so detection (qa_checks) and remediation
(normalizer) stay tied to the same data/sections-contract.yaml.
"""

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import normalize_security_architecture as nrm  # noqa: E402
import qa_checks as qc  # noqa: E402


@pytest.fixture(autouse=True)
def _use_schema_v2(monkeypatch):
    """Reset the path-keyed contract cache around each normalizer test."""
    qc._PrePass._contract = None
    qc._PrePass._contract_path = None
    yield
    qc._PrePass._contract = None
    qc._PrePass._contract_path = None


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "security-architecture.md"
    p.write_text(body, encoding="utf-8")
    return p


# A §7 fragment with all three structural defects:
#  - §7.6 first #### is a specific parser block, not a validation-approach block
#  - §7.2 TOTP flow block carries no sequenceDiagram
#  - §7.2.3 is missing the **Relevant findings** label
DEFECTIVE = """## 7. Security Architecture

### 7.2 Identity and Authentication Controls

**Controls covered:** [Password-Based Authentication](#a), [Multi-Factor Authentication (TOTP)](#b), [User Registration](#c)

#### 7.2.1 Password-Based Authentication

Intro about password login.

```mermaid
sequenceDiagram
    participant U as User
    U->>API: login
```

**Security assessment**

Assessment text.

**Relevant findings**

- [F-001](#f-001)

#### 7.2.2 Multi-Factor Authentication (TOTP)

Intro about TOTP enrollment and verification.

**Security assessment**

Assessment text.

**Relevant findings**

- [F-002](#f-002)

#### 7.2.3 User Registration

Intro about registration.

**Security assessment**

Assessment text.

### 7.6 Input Boundary Validation Controls

**Controls covered:** [File Upload Validation](#u)

#### 7.6.1 File Upload Validation

Intro.

**Security assessment**

Assessment.

**Relevant findings**

- [F-003](#f-003)
"""


def test_defective_fixture_fails_all_three_gates(tmp_path):
    """Sanity: the fixture really does trip all three contract checks."""
    p = _write(tmp_path, DEFECTIVE)
    assert qc.check_validation_approach_first(p).ok == 0
    assert qc.check_auth_method_decomposition(p).ok == 0
    assert qc.check_control_subsection_coverage(p).ok == 0


def test_normalizer_makes_all_three_gates_pass(tmp_path):
    out, changes = nrm.normalize_text(DEFECTIVE)
    assert changes, "normalizer should report the fixes it applied"
    p = _write(tmp_path, out)
    assert qc.check_validation_approach_first(p).ok == 1, qc.check_validation_approach_first(p).issues
    assert qc.check_auth_method_decomposition(p).ok == 1, qc.check_auth_method_decomposition(p).issues
    assert qc.check_control_subsection_coverage(p).ok == 1, qc.check_control_subsection_coverage(p).issues


def test_validation_approach_inserted_first(tmp_path):
    out, _ = nrm.normalize_text(DEFECTIVE)
    # The first #### under §7.6 must now be the approach block.
    sec = out.split("### 7.6 ")[1]
    first_h4 = sec.split("#### ", 1)[1].splitlines()[0]
    assert "Validation Approach" in first_h4


def test_totp_flow_diagram_inserted(tmp_path):
    out, _ = nrm.normalize_text(DEFECTIVE)
    totp = out.split("#### 7.2.2 Multi-Factor Authentication (TOTP)")[1].split("#### ")[0]
    assert "sequenceDiagram" in totp


def test_missing_relevant_findings_label_added(tmp_path):
    out, _ = nrm.normalize_text(DEFECTIVE)
    reg = out.split("#### 7.2.3 User Registration")[1].split("### 7.6")[0]
    assert "**Relevant findings**" in reg


def test_password_block_diagram_not_duplicated(tmp_path):
    # §7.2.1 already has a sequenceDiagram — the normalizer must not add a 2nd.
    out, _ = nrm.normalize_text(DEFECTIVE)
    pw = out.split("#### 7.2.1 Password-Based Authentication")[1].split("#### 7.2.2")[0]
    assert pw.count("sequenceDiagram") == 1


def test_idempotent(tmp_path):
    once, changes1 = nrm.normalize_text(DEFECTIVE)
    twice, changes2 = nrm.normalize_text(once)
    assert changes1, "first pass should change something"
    assert changes2 == [], "second pass must be a no-op"
    assert twice == once


def test_clean_input_is_noop(tmp_path):
    # Feed the normalizer's own output back in: no further changes.
    out, _ = nrm.normalize_text(DEFECTIVE)
    out2, changes = nrm.normalize_text(out)
    assert changes == []
    assert out2 == out


def test_not_applicable_section_not_fabricated(tmp_path):
    frag = (
        "## 7. Security Architecture\n\n"
        "### 7.12 Real-time and Not Applicable Controls\n\n"
        "_Not applicable — no real-time channels in scope._\n"
    )
    out, changes = nrm.normalize_text(frag)
    assert changes == []
    assert out == frag


def test_section_with_no_subsections_left_for_repair_loop(tmp_path):
    # §7.6 with zero #### — normalizer must NOT fabricate one (out of scope).
    frag = (
        "## 7. Security Architecture\n\n"
        "### 7.6 Input Boundary Validation Controls\n\n"
        "Some prose but no H4 subsections.\n"
    )
    out, changes = nrm.normalize_text(frag)
    assert all("validation_approach_first" not in c for c in changes)


def test_cli_check_mode(tmp_path, capsys):
    p = _write(tmp_path, DEFECTIVE)
    rc = nrm.main([str(p), "--check"])
    assert rc == 1  # changes needed
    # --check must not modify the file
    assert p.read_text(encoding="utf-8") == DEFECTIVE


def test_cli_write_mode(tmp_path):
    p = _write(tmp_path, DEFECTIVE)
    rc = nrm.main([str(p)])
    assert rc == 0
    text = p.read_text(encoding="utf-8")
    assert "Validation Approach" in text
    # second run is a no-op
    assert nrm.main([str(p)]) == 0
    assert p.read_text(encoding="utf-8") == text


def test_cli_accepts_output_dir(tmp_path):
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    (frag_dir / "security-architecture.md").write_text(DEFECTIVE, encoding="utf-8")
    rc = nrm.main([str(tmp_path)])  # dir form resolves to .fragments/security-architecture.md
    assert rc == 0
    assert "Validation Approach" in (frag_dir / "security-architecture.md").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# §7.x heading canonicalization (Oxford-comma drift — 2026-06-06)
# --------------------------------------------------------------------------- #
# The contract's required_subsections use comma-free §7 titles deliberately
# (e.g. "7.9 Cryptography Secrets and Data Protection"); enforce_control_taxonomy
# canonicalises yaml domains to match. The enrich-on secarch LLM renderer
# routinely re-adds the Oxford comma, which trips the strict
# `required_subsection_missing` gate. normalize_text rewrites the heading back
# to the contract-exact title when it differs ONLY by punctuation.


def test_oxford_comma_heading_canonicalized():
    md = "### 7.9 Cryptography, Secrets and Data Protection\nBody text.\n"
    out, changes = nrm.normalize_text(md)
    assert "### 7.9 Cryptography Secrets and Data Protection" in out
    assert "Cryptography, Secrets" not in out
    assert any("heading_canonicalized" in c for c in changes)


def test_multiple_comma_headings_canonicalized():
    md = (
        "### 7.10 File, Parser and Outbound Request Controls\n\n"
        "### 7.11 Operations, Runtime and Supply Chain Controls\n"
    )
    out, _ = nrm.normalize_text(md)
    assert "### 7.10 File Parser and Outbound Request Controls" in out
    assert "### 7.11 Operations Runtime and Supply Chain Controls" in out


def test_already_canonical_heading_untouched():
    md = "### 7.9 Cryptography Secrets and Data Protection\nBody.\n"
    out, changes = nrm.normalize_text(md)
    assert "### 7.9 Cryptography Secrets and Data Protection" in out
    assert not any("heading_canonicalized" in c for c in changes)


def test_non_matching_heading_not_renamed():
    # A genuinely different §7.9 title (not just punctuation) must be left as-is.
    md = "### 7.9 Completely Different Title\nBody.\n"
    out, changes = nrm.normalize_text(md)
    assert "### 7.9 Completely Different Title" in out
    assert not any("heading_canonicalized" in c for c in changes)


def test_subsubsection_heading_not_touched():
    # 7.2.1 has no canonical entry (only 7.2 does) — must never be rewritten.
    md = "#### 7.2.1 Password-Based Authentication\nBody.\n"
    out, changes = nrm.normalize_text(md)
    assert "#### 7.2.1 Password-Based Authentication" in out
    assert not any("heading_canonicalized" in c for c in changes)
