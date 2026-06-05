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


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load_module("compose_threat_model", SCRIPTS / "compose_threat_model.py")


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
