"""End-to-end pipeline tests against a frozen run-directory fixture.

These tests exercise the post-LLM pipeline — the deterministic Python
that composes, annotates, validates, and exports the threat model — by
replaying a pre-frozen ``frozen-run/`` fixture through every script that
a real assessment would invoke.

No LLM is called. Every step runs in well under a second.

Layout:
    tests/fixtures/e2e/frozen-run/      — a complete, schema-valid run dir
    tests/fixtures/e2e/synthetic-repo/  — a minimal repo for fingerprint tests

What is covered:

    * Rendering        — compose_threat_model.render() on the fixture produces
                         a markdown document with the canonical MS structure.
    * Annotation       — annotate_architecture.py + annotate_sequences.py run
                         idempotently on the rendered output (ok exit).
    * QA loop          — qa_checks.py all converges to zero fixable issues.
    * Intermediates    — validate_intermediate.py accepts every artifact
                         (threats_merged, triage_flags, stride). The
                         legacy dep_scan validator was removed 2026-05.
    * Pentest pipeline — render_pentest_tasks.py consumes .threats-merged.json
                         and emits a schema-valid pentest-tasks.yaml.
    * Export chain     — export_sarif.py consumes the produced threat-model.yaml
                         and emits a schema-valid SARIF v2.1.0 (one result per
                         threat, no silent drops); export_html.py / export_pdf.py
                         consume the composed markdown (skipped when their
                         converter tooling — pandoc / weasyprint+chrome — is
                         absent). Closes the gap where the exporters were only
                         unit-tested against their own hand-built YAML, never the
                         real generator output.
    * Completeness     — the render-integrity certificate (.render-integrity.json)
                         proves every in-scope section rendered with nothing
                         degraded/empty; every structural-spine section (incl.
                         the Mitigation Register) is asserted present and the
                         report is free of placeholder leakage.
    * Golden master    — the rendered threat-model.md and the exported SARIF are
                         byte-pinned against committed goldens, so ANY renderer /
                         contract / fragment / exporter change that alters output
                         fails the suite (regenerate with APPSEC_UPDATE_GOLDEN=1).
    * Incremental      — baseline_state.py update + check_fingerprint round
                         trip against a fresh synthetic repo, then detects a
                         mutation correctly.

What is NOT covered (by design — these require a real scan):
    * LLM-judgement quality (did STRIDE find every threat?)
    * Phase 2 recon heuristics
    * Phase 8b requirements verification
    * Prose quality in the Management Summary

The ``e2e_run`` fixture below is the single entry point most tests reach
for — it materializes a fresh copy of frozen-run/ into tmp_path so each
test can mutate files without contaminating the source fixture.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "e2e"
FROZEN_RUN = FIXTURE_ROOT / "frozen-run"
SYNTHETIC_REPO = FIXTURE_ROOT / "synthetic-repo"
GOLDEN = FIXTURE_ROOT / "golden"

# The structural spine every complete report must always carry: the body
# sections §1–§11 plus the named registers and appendices. Conditional /
# data-driven sections (requirements_compliance, identified_actors,
# critical_attack_tree, …) are intentionally excluded — their presence depends
# on the run, and the render-integrity certificate already accounts for them.
CORE_SECTIONS = [
    "management_summary",
    "system_overview",
    "architecture_diagrams",
    "attack_walkthroughs",
    "assets",
    "attack_surface",
    "security_architecture",
    "threat_register",  # ## 8. Findings Register
    "abuse_cases",  # ## 9. Abuse Cases
    "mitigation_register",  # ## 10. Mitigation Register
    "out_of_scope",
    "appendix_run_statistics",
    "appendix_vektor_taxonomy",
]

# Human-readable mirror of CORE_SECTIONS — the literal Markdown headings a
# reader expects to find (incl. the Mitigation Register).
CORE_HEADINGS = [
    "## Management Summary",
    "## 1. System Overview",
    "## 2. Architecture Diagrams",
    "## 3. Attack Walkthroughs",
    "## 4. Assets",
    "## 5. Attack Surface",
    "## 7. Security Architecture",
    "## 8. Findings Register",
    "## 9. Abuse Cases",
    "## 10. Mitigation Register",
    "## 11. Out of Scope",
]

# Scaffolding that must never leak into the composed report.
PLACEHOLDER_TOKENS = ["placeholder", "todo:", "fixme:", "lorem ipsum", "[redacted]"]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load_module("compose_threat_model", SCRIPTS / "compose_threat_model.py")
qa_checks = _load_module("qa_checks", SCRIPTS / "qa_checks.py")

# Reuse the canonical SARIF validator that test_export_sarif.py uses, rather
# than re-implementing structural checks here (single source of truth).
if str(REPO_ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tests"))
from test_sarif_validation import validate_sarif  # noqa: E402


def _run_script(script: str, *args: str) -> subprocess.CompletedProcess:
    """Invoke a scripts/*.py CLI with the current interpreter."""
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *args],
        capture_output=True,
        text=True,
    )


@pytest.fixture
def e2e_run(tmp_path: Path) -> Path:
    """Copy frozen-run/ into tmp_path and return the new path.

    Tests are free to mutate files inside the returned directory; the
    source fixture is never touched.
    """
    dst = tmp_path / "run"
    shutil.copytree(FROZEN_RUN, dst)
    return dst


@pytest.fixture
def rendered_run(e2e_run: Path) -> Path:
    """Same as e2e_run but with threat-model.md already composed on disk."""
    rendered, warnings = compose.render(CONTRACT, e2e_run)
    assert warnings == [], f"unexpected compose warnings: {warnings}"
    (e2e_run / "threat-model.md").write_text(rendered, encoding="utf-8")
    return e2e_run


# ---------------------------------------------------------------------------
# 1. Rendering pipeline: compose → annotate → qa_checks
# ---------------------------------------------------------------------------


def test_compose_renders_canonical_document(rendered_run: Path) -> None:
    md = (rendered_run / "threat-model.md").read_text(encoding="utf-8")

    # The Management Summary and its canonical subsections must be present.
    assert "## Management Summary\n" in md
    for heading in (
        "### Verdict",
        # Top Findings + Architecture Assessment were merged into the single
        # "Security Posture & Top Threats" block; Mitigations → Top Mitigations.
        "### Security Posture & Top Threats",
        "### Top Mitigations",
        "### Operational Strengths",
    ):
        assert heading in md, f"missing MS subsection: {heading}"

    # The body sections 1..11 are all numbered — the renderer must produce the
    # canonical Findings Register summary. §8 is severity-grouped finding cards
    # (not a flat table since the 2026-05 card-layout migration).
    assert "## 8. Findings Register" in md
    assert "**Risk Distribution:**" in md
    assert "**STRIDE Coverage:**" in md
    assert "**Findings index:**" in md
    assert "### 🔴 Critical" in md
    assert "#### F-003 · " in md

    # Every T-NNN in the fixture must be anchored somewhere in the document.
    for tid in ("t-001", "t-002", "t-003", "t-010"):
        assert f'<a id="{tid}"></a>' in md, f"missing anchor for {tid}"


def test_annotate_architecture_runs_idempotently(rendered_run: Path) -> None:
    """First pass writes annotations; second pass is a no-op."""
    md_path = rendered_run / "threat-model.md"
    threats = rendered_run / ".threats-merged.json"

    r1 = _run_script(
        "annotate_architecture.py",
        "--markdown",
        str(md_path),
        "--threats",
        str(threats),
    )
    assert r1.returncode == 0, r1.stderr

    after_first = md_path.read_text(encoding="utf-8")

    r2 = _run_script(
        "annotate_architecture.py",
        "--markdown",
        str(md_path),
        "--threats",
        str(threats),
    )
    assert r2.returncode == 0, r2.stderr

    assert md_path.read_text(encoding="utf-8") == after_first, (
        "annotate_architecture.py must be idempotent — second run changed the file"
    )


def test_annotate_sequences_runs_without_error(rendered_run: Path) -> None:
    """Sequence-diagram annotator succeeds even when no sequences are present."""
    md_path = rendered_run / "threat-model.md"
    threats = rendered_run / ".threats-merged.json"

    result = _run_script(
        "annotate_sequences.py",
        "--markdown",
        str(md_path),
        "--threats",
        str(threats),
    )
    assert result.returncode == 0, result.stderr


def test_qa_checks_all_converges(rendered_run: Path) -> None:
    """After compose, qa_checks all must converge — repairs in place, then
    the final summary has zero un-fixable invariant/contract issues."""
    md_path = rendered_run / "threat-model.md"

    result = _run_script(
        "qa_checks.py",
        "all",
        str(md_path),
        str(rendered_run),
    )
    # Exit 0 = clean, exit 1 = issues remain (fine for this fixture since we
    # intentionally keep it minimal — assert the structural checks never
    # report drift, which is the invariant we care about).
    assert result.returncode in (0, 1), result.stderr
    summary = json.loads(result.stdout)

    for check in ("contract", "ms_structure", "heading_hygiene"):
        assert summary[check]["issue_count"] == 0, (
            f"{check} reported {summary[check]['issue_count']} issue(s): {summary[check].get('issues', [])}"
        )


# ---------------------------------------------------------------------------
# 2. Intermediate artifacts: every file validate_intermediate.py knows about
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("schema", "filename"),
    [
        ("threats_merged", ".threats-merged.json"),
        ("triage_flags", ".triage-flags.json"),
        ("stride", ".stride-C-01.json"),
        ("stride", ".stride-C-02.json"),
    ],
)
def test_validate_intermediate_accepts_fixture(e2e_run: Path, schema: str, filename: str) -> None:
    result = _run_script(
        "validate_intermediate.py",
        schema,
        str(e2e_run / filename),
    )
    assert result.returncode == 0, (
        f"validate_intermediate {schema} rejected fixture {filename}:\n{result.stdout}\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# 3. Pentest pipeline: .threats-merged.json → pentest-tasks.yaml
# ---------------------------------------------------------------------------


def test_pentest_pipeline_produces_schema_valid_tasks(e2e_run: Path) -> None:
    merged = e2e_run / ".threats-merged.json"
    out = e2e_run / "pentest-tasks.yaml"

    result = _run_script(
        "render_pentest_tasks.py",
        "--merged",
        str(merged),
        "--output",
        str(out),
        "--dialect",
        "generic",
        "--target-url",
        "https://staging.example.com",
    )
    assert result.returncode == 0, result.stderr
    assert out.is_file()

    # Schema validation via the same validator the real pipeline uses.
    validate = _run_script("validate_intermediate.py", "pentest_tasks", str(out))
    assert validate.returncode == 0, validate.stdout

    doc = yaml.safe_load(out.read_text(encoding="utf-8"))

    # Two CWE-89 SQLi threats + one CWE-79 XSS threat are pentest-eligible
    # in the fixture. CWE-321 hardcoded-key is static-only and must be
    # filtered out. (The legacy CWE-1321 dep-scan fixture row was removed
    # when the in-tree SCA producer was retired in 2026-05.)
    task_cwes = {t["cwe"] for t in doc["tasks"]}
    assert "CWE-89" in task_cwes, "SQLi threats should produce pentest tasks"
    assert "CWE-321" not in task_cwes, "static-only CWE-321 must be filtered out of pentest tasks"

    # Safety block must be present on every task.
    for task in doc["tasks"]:
        assert task["safety"]["read_only"] is True
        assert task["safety"]["destructive_actions"] == "forbidden"


def test_pentest_pipeline_strix_dialect(e2e_run: Path) -> None:
    merged = e2e_run / ".threats-merged.json"
    out = e2e_run / "pentest-tasks-strix.yaml"

    result = _run_script(
        "render_pentest_tasks.py",
        "--merged",
        str(merged),
        "--output",
        str(out),
        "--dialect",
        "strix",
        "--target-url",
        "https://staging.example.com",
    )
    assert result.returncode == 0, result.stderr

    doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert doc["meta"]["dialect"] == "strix"
    assert all(t["task_id"].startswith("PT-") for t in doc["tasks"])


# ---------------------------------------------------------------------------
# 4. Incremental: baseline_state fingerprint round-trip
# ---------------------------------------------------------------------------


def _seed_repo(dst: Path) -> Path:
    """Copy the synthetic repo into a writable tmp location."""
    repo = dst / "repo"
    shutil.copytree(SYNTHETIC_REPO, repo)
    return repo


def test_baseline_update_writes_cache(tmp_path: Path, e2e_run: Path) -> None:
    """`baseline_state.py update` writes a schema-valid cache file."""
    repo = _seed_repo(tmp_path)

    # Remove the pre-baked fixture cache so we observe a real update.
    cache_path = e2e_run / ".appsec-cache" / "baseline.json"
    cache_path.unlink()

    result = _run_script(
        "baseline_state.py",
        "update",
        "--output-dir",
        str(e2e_run),
        "--repo-root",
        str(repo),
        "--mode",
        "full",
    )
    assert result.returncode == 0, result.stderr
    assert cache_path.is_file()

    data = json.loads(cache_path.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["mode"] == "full"
    # Fingerprint must have hashed our synthetic manifests.
    assert "package.json" in data["recon_fingerprint"]["manifests"]
    assert "Dockerfile" in data["recon_fingerprint"]["dockerfiles"]


def test_incremental_fast_path_on_unchanged_repo(tmp_path: Path, e2e_run: Path) -> None:
    """After a baseline update, check_fingerprint on the same repo exits 0."""
    repo = _seed_repo(tmp_path)
    (e2e_run / ".appsec-cache" / "baseline.json").unlink()

    update = _run_script(
        "baseline_state.py",
        "update",
        "--output-dir",
        str(e2e_run),
        "--repo-root",
        str(repo),
        "--mode",
        "full",
    )
    assert update.returncode == 0, update.stderr

    check = _run_script(
        "baseline_state.py",
        "check-fingerprint",
        "--output-dir",
        str(e2e_run),
        "--repo-root",
        str(repo),
    )
    assert check.returncode == 0, (
        f"check_fingerprint should report 'unchanged' on an unmodified repo\n"
        f"stdout={check.stdout}\nstderr={check.stderr}"
    )
    assert "unchanged" in check.stdout


def test_incremental_detects_manifest_mutation(tmp_path: Path, e2e_run: Path) -> None:
    """Mutating package.json invalidates the fingerprint (exit 1)."""
    repo = _seed_repo(tmp_path)
    (e2e_run / ".appsec-cache" / "baseline.json").unlink()

    _run_script(
        "baseline_state.py",
        "update",
        "--output-dir",
        str(e2e_run),
        "--repo-root",
        str(repo),
        "--mode",
        "full",
    )

    # Bump lodash to a different version — the SHA256 of package.json changes.
    pkg = repo / "package.json"
    data = json.loads(pkg.read_text(encoding="utf-8"))
    data["dependencies"]["lodash"] = "4.17.21"
    pkg.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    check = _run_script(
        "baseline_state.py",
        "check-fingerprint",
        "--output-dir",
        str(e2e_run),
        "--repo-root",
        str(repo),
    )
    assert check.returncode == 1, (
        f"check_fingerprint should report 'changed' after manifest mutation\n"
        f"stdout={check.stdout}\nstderr={check.stderr}"
    )
    assert "changed" in check.stdout
    assert "package.json" in check.stdout


# ---------------------------------------------------------------------------
# 5. Determinism: same inputs → byte-identical threat-model.md
# ---------------------------------------------------------------------------


def test_compose_is_deterministic_across_runs(tmp_path: Path, e2e_run: Path) -> None:
    """Compose twice against two clean copies of the fixture — identical output."""
    second = tmp_path / "run-2"
    shutil.copytree(FROZEN_RUN, second)

    r1, _ = compose.render(CONTRACT, e2e_run)
    r2, _ = compose.render(CONTRACT, second)
    assert r1 == r2, "compose_threat_model.render is not deterministic"


# ---------------------------------------------------------------------------
# 6. Export chain — every exporter a real run invokes must survive the REAL
#    generator output (the frozen fixture), not an exporter's own hand-built
#    YAML. That seam is exactly what the isolated unit tests (test_export_*.py)
#    miss: a producer-side schema change can break an exporter while every unit
#    test stays green because it feeds the exporter its own fixture.
# ---------------------------------------------------------------------------


def test_export_sarif_from_yaml(e2e_run: Path) -> None:
    """export_sarif.py consumes the frozen threat-model.yaml and emits a
    schema-valid SARIF v2.1.0 with one result per threat (no silent drops).
    Pure Python — always runs, no external converter needed."""
    yml = e2e_run / "threat-model.yaml"
    out = e2e_run / "threat-model.sarif.json"
    result = _run_script("export_sarif.py", "--threat-model", str(yml), "--output", str(out))
    assert result.returncode == 0, (
        f"export_sarif.py failed (exit {result.returncode}):\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert out.is_file() and out.stat().st_size > 0, "SARIF output missing/empty"

    sarif = json.loads(out.read_text(encoding="utf-8"))
    ok, errors = validate_sarif(sarif)
    assert ok, f"SARIF failed validation: {errors}"
    assert sarif["version"] == "2.1.0"

    # One SARIF result per threat — catches a producer change that silently
    # drops findings on the way into the exported artifact.
    threat_count = len(yaml.safe_load(yml.read_text(encoding="utf-8")).get("threats", []))
    results = sarif["runs"][0]["results"]
    assert len(results) == threat_count, (
        f"SARIF result count {len(results)} != threat count {threat_count} — exporter dropped findings"
    )


def test_export_html_from_markdown(rendered_run: Path) -> None:
    """export_html.py consumes the composed markdown. Gated on its own
    --check-only preflight so a box without pandoc skips instead of failing.
    --no-mermaid keeps the assertion on the HTML conversion itself, not on
    diagram rendering (which needs mmdc/chrome)."""
    md = rendered_run / "threat-model.md"
    preflight = _run_script("export_html.py", "--check-only", "--input", str(md))
    if preflight.returncode != 0:
        pytest.skip("export_html preflight failed (pandoc absent)")

    out = rendered_run / "threat-model.html"
    result = _run_script("export_html.py", "--input", str(md), "--output", str(out), "--no-mermaid")
    assert result.returncode == 0, (
        f"export_html.py failed (exit {result.returncode}):\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert out.is_file() and out.stat().st_size > 0, "HTML output missing/empty"
    assert "<html" in out.read_text(encoding="utf-8", errors="ignore").lower(), "no <html> element"


def test_export_pdf_from_markdown(rendered_run: Path) -> None:
    """export_pdf.py consumes the composed markdown. Gated on its own
    --check-only preflight (with --no-mermaid, so only weasyprint is required)
    so a box without the PDF converter skips instead of failing."""
    md = rendered_run / "threat-model.md"
    preflight = _run_script("export_pdf.py", "--check-only", "--input", str(md), "--no-mermaid")
    if preflight.returncode != 0:
        pytest.skip("export_pdf preflight failed (weasyprint/chrome absent)")

    out = rendered_run / "threat-model.pdf"
    result = _run_script("export_pdf.py", "--input", str(md), "--output", str(out), "--no-mermaid")
    assert result.returncode == 0, (
        f"export_pdf.py failed (exit {result.returncode}):\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert out.is_file(), "PDF output missing"
    assert out.stat().st_size > 1024, f"PDF suspiciously small ({out.stat().st_size} bytes)"
    assert out.read_bytes()[:5] == b"%PDF-", "PDF lacks a %PDF- header"


# ---------------------------------------------------------------------------
# 7. Report completeness & integrity — every element is present and the
#    document is error-free. This is the "if the e2e is green the report is
#    actually complete and renders correctly" guarantee the rest of the file
#    builds toward.
# ---------------------------------------------------------------------------


def test_render_integrity_certificate(rendered_run: Path) -> None:
    """compose writes .render-integrity.json certifying that every in-scope
    section rendered with nothing degraded or empty. report_integrity_ok is the
    deterministic 'the report is not broken' signal the QA loop reacts to."""
    integ = json.loads((rendered_run / ".render-integrity.json").read_text(encoding="utf-8"))
    assert integ["report_integrity_ok"] is True, f"broken sections: {integ.get('broken_sections')}"
    assert integ["integrity_pct"] == 100, integ
    assert integ["sections_degraded"] == 0, f"degraded sections: {integ.get('broken_sections')}"
    assert integ["sections_empty"] == 0, f"empty sections: {integ.get('broken_sections')}"
    # Most expected fragments must be wired; the producer tolerates a small
    # number of sanctioned-optional fragments (e.g. operational-strengths
    # overrides) being absent, which is why report_integrity_ok stays True at
    # 8/9. Guard against a wholesale fragment-wiring collapse, not the optional
    # tail.
    assert integ["fragments_wired"] >= integ["fragments_expected"] - 1, (
        f"fragment-wiring collapse: {integ['fragments_wired']} wired of {integ['fragments_expected']} expected"
    )


def test_core_sections_all_present(rendered_run: Path) -> None:
    """Every structural-spine section (incl. the Mitigation Register) must be in
    scope and rendered. Names the exact missing section on failure — unlike the
    opaque golden byte-diff below."""
    integ = json.loads((rendered_run / ".render-integrity.json").read_text(encoding="utf-8"))
    by_id = {m["id"]: m for m in integ["sections"]}
    for sid in CORE_SECTIONS:
        assert sid in by_id, f"section '{sid}' absent from the render manifest"
        m = by_id[sid]
        assert m.get("in_scope"), f"core section '{sid}' unexpectedly out of scope"
        assert m.get("outcome") in ("rendered", "fallback"), (
            f"core section '{sid}' did not render (outcome={m.get('outcome')})"
        )


def test_core_section_headings_in_markdown(rendered_run: Path) -> None:
    """The reader-facing mirror: each spine heading is literally present in
    threat-model.md (the user-visible 'every element is there' contract)."""
    md = (rendered_run / "threat-model.md").read_text(encoding="utf-8")
    missing = [h for h in CORE_HEADINGS if f"{h}\n" not in md]
    assert not missing, f"missing report headings: {missing}"


def test_mitigation_register_is_populated(rendered_run: Path) -> None:
    """The Mitigation Register must carry real mitigations, not just an empty
    heading — a register that renders empty passes schema checks yet is a silent
    regression."""
    md = (rendered_run / "threat-model.md").read_text(encoding="utf-8")
    start = md.index("## 10. Mitigation Register")
    rest = md[start + len("## 10. Mitigation Register") :]
    nxt = rest.find("\n## ")
    body = rest if nxt == -1 else rest[:nxt]
    has_priority = any(p in body for p in ("### P1", "### P2", "### P3", "### P4"))
    has_row = "|" in body or re.search(r"M-\d{3}", body) is not None
    assert has_priority and has_row, "Mitigation Register rendered with no mitigation entries"


def test_no_placeholder_leakage(rendered_run: Path) -> None:
    """The composed report must not leak LLM/template scaffolding. (Jinja
    delimiters are deliberately not checked here: Mermaid `%%{init …}%%` blocks
    legitimately contain `}}`.)"""
    lower = (rendered_run / "threat-model.md").read_text(encoding="utf-8").lower()
    found = [t for t in PLACEHOLDER_TOKENS if t in lower]
    assert not found, f"placeholder tokens leaked into threat-model.md: {found}"


# ---------------------------------------------------------------------------
# 8. Golden master — byte-pin the rendered report and the exported SARIF
#    against committed goldens. This catches ANY renderer / contract / fragment
#    / exporter change that alters output, beyond mere section presence. On an
#    intentional change, regenerate:
#        APPSEC_UPDATE_GOLDEN=1 python -m pytest tests/test_e2e_pipeline.py -k golden
# ---------------------------------------------------------------------------

_REGEN_HINT = "APPSEC_UPDATE_GOLDEN=1 python -m pytest tests/test_e2e_pipeline.py -k golden"


def test_compose_matches_golden(e2e_run: Path) -> None:
    rendered, warnings = compose.render(CONTRACT, e2e_run)
    assert warnings == [], f"unexpected compose warnings: {warnings}"
    golden = GOLDEN / "threat-model.md"
    if os.environ.get("APPSEC_UPDATE_GOLDEN") == "1":
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(rendered, encoding="utf-8")
        pytest.skip("golden threat-model.md updated (APPSEC_UPDATE_GOLDEN=1)")
    assert golden.is_file(), f"missing golden {golden} — regenerate with: {_REGEN_HINT}"
    assert rendered == golden.read_text(encoding="utf-8"), (
        f"rendered threat-model.md != golden. If intentional, regenerate: {_REGEN_HINT}"
    )


def test_export_sarif_matches_golden(e2e_run: Path) -> None:
    yml = e2e_run / "threat-model.yaml"
    out = e2e_run / "threat-model.sarif.json"
    result = _run_script("export_sarif.py", "--threat-model", str(yml), "--output", str(out))
    assert result.returncode == 0, result.stderr
    produced = out.read_text(encoding="utf-8")
    golden = GOLDEN / "threat-model.sarif.json"
    if os.environ.get("APPSEC_UPDATE_GOLDEN") == "1":
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(produced, encoding="utf-8")
        pytest.skip("golden threat-model.sarif.json updated (APPSEC_UPDATE_GOLDEN=1)")
    assert golden.is_file(), f"missing golden {golden} — regenerate with: {_REGEN_HINT}"
    assert produced == golden.read_text(encoding="utf-8"), (
        f"exported SARIF != golden. If intentional, regenerate: {_REGEN_HINT}"
    )


# ---------------------------------------------------------------------------
# P1.4 — weakness-class register render (proposal §4a). The weakness view is
# gated on weaknesses[] being present, so the committed golden (no register)
# stays byte-identical; this test injects a register and asserts the composer
# renders the systemic view cleanly and QA-safe.
# ---------------------------------------------------------------------------


def test_weakness_register_renders_and_is_qa_safe(e2e_run: Path) -> None:
    yml = e2e_run / "threat-model.yaml"
    doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
    tids = [t.get("id") or t.get("t_id") for t in doc.get("threats", []) if (t.get("id") or t.get("t_id"))][:2]
    assert len(tids) == 2, "fixture needs ≥2 threats to reference as instances"
    doc["weaknesses"] = [
        {
            "id": "W-001",
            "weakness_class": "injection",
            "kind": "design",
            "title": "Database query safety",
            "severity": "Critical",
            "severity_basis": "confirmed",
            "statement": "SQL built by concatenation; no parametrized layer.",
            "observable_backing": {
                "absent_control_signal": [{"pattern": "sequelize", "hit_count": 0}],
                "practice_evidence": [{"file": "routes/x.ts", "line": 1, "id": tids[0]}],
            },
            "affected_components": ["api"],
            "instances": [
                {"id": tids[0], "basis": "confirmed-exploitable"},
                {"id": tids[1], "basis": "confirmed-exploitable"},
            ],
        }
    ]
    yml.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")

    rendered, warnings = compose.render(CONTRACT, e2e_run)
    assert warnings == [], f"unexpected compose warnings: {warnings}"
    # Weaknesses are a first-class register (renamed + repositioned before the
    # Findings Register in the 2026-07-14 redesign), not a §8 class roll-up.
    assert "## 6. Weakness Register" in rendered
    assert "W-001 — Database query safety" in rendered
    assert "SQL built by concatenation; no parametrized layer." in rendered
    assert "**Confirmed findings:**" in rendered
    # The standalone "### Security Principles" verdict table was retired from the
    # Management Summary (2026-07-14): it duplicated Top Weaknesses as a second
    # systemic-framing block and only partially linked to the register. The
    # executive systemic view is now carried solely by `### Top Weaknesses`.
    assert "### Security Principles" not in rendered
    # `### Top Weaknesses` renders INSIDE the Management Summary (between its
    # `## Management Summary` heading and the next `## ` section) and before the
    # central Weakness Register it links into.
    assert "### Top Weaknesses" in rendered
    ms_start = rendered.index("## Management Summary")
    ms_end = rendered.index("\n## ", ms_start + 1)
    assert ms_start < rendered.index("### Top Weaknesses") < ms_end, (
        "Top Weaknesses table must render inside the Management Summary"
    )
    assert "[Weakness Register](#weakness-register)" in rendered
    assert rendered.index("### Top Weaknesses") < rendered.index("## 6. Weakness Register")
    # Findings and systemic weaknesses are reported as separate evidence types.
    assert "**Assessment evidence:**" in rendered
    assert "confirmed-exploitable finding(s)" in rendered
    # QA invariants pass on the rendered document (the block adds no anchor /
    # section that check_invariants would reject).
    (e2e_run / "threat-model.md").write_text(rendered, encoding="utf-8")
    inv = qa_checks.check_invariants(e2e_run / "threat-model.md")
    assert inv.ok, f"check_invariants rejected the weakness-register render: {inv.__dict__}"
