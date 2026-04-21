"""Parametrized mutation matrix for compose_threat_model enforcement gates.

Every enforcement path — schema validation, fragment-markdown validation,
contract ordering, QA post-check — is exercised by at least one mutation.
Each mutation is a small transformation applied to a valid fixture; the
test asserts that the gate rejects the mutation with a concrete error
message.

If someone accidentally weakens an enforcement gate (e.g. removes a
required field from the verdict schema), the corresponding mutation in
this suite will start passing — which the test flags as a regression.

Layout:

    def mutate_xxx(workdir): ...
    MUTATIONS = [
        (mutate_fn, expected_exc, expected_error_substring),
        ...
    ]
    @pytest.mark.parametrize("mutation,...", MUTATIONS)
    def test_mutation_triggers_enforcement(...): ...

This is the last line of defense before the renderer trusts the input.
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
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"
QA_SCRIPT = REPO_ROOT / "scripts" / "qa_checks.py"
FIXTURE = Path(__file__).parent / "fixtures" / "compose"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load_module("compose_threat_model", SCRIPT_PATH)
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"


def _prepare(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    shutil.copytree(FIXTURE, out)
    return out


# ---------------------------------------------------------------------------
# Mutation functions. Each takes a workdir and applies a single defect.
# Convention: each mutation targets ONE enforcement gate so the error message
# is unambiguous.
# ---------------------------------------------------------------------------


def mutate_verdict_remove_required_field(out: Path) -> None:
    p = out / ".fragments" / "ms-verdict.json"
    d = json.loads(p.read_text())
    d.pop("severity", None)
    p.write_text(json.dumps(d))


def mutate_verdict_bad_enum(out: Path) -> None:
    p = out / ".fragments" / "ms-verdict.json"
    d = json.loads(p.read_text())
    d["severity"] = "apocalyptic"
    p.write_text(json.dumps(d))


def mutate_verdict_too_few_bullets(out: Path) -> None:
    p = out / ".fragments" / "ms-verdict.json"
    d = json.loads(p.read_text())
    d["bullets"] = []
    p.write_text(json.dumps(d))


def mutate_verdict_too_many_bullets(out: Path) -> None:
    p = out / ".fragments" / "ms-verdict.json"
    d = json.loads(p.read_text())
    # Fill beyond maxItems=5.
    orig = d["bullets"][0] if d["bullets"] else {
        "title": "X",
        "body": "x" * 40,
        "refs": ["T-001"],
    }
    d["bullets"] = [dict(orig) for _ in range(7)]
    p.write_text(json.dumps(d))


def mutate_verdict_bad_ref_pattern(out: Path) -> None:
    p = out / ".fragments" / "ms-verdict.json"
    d = json.loads(p.read_text())
    # `XYZ-001` does not match `^[FT]-\d{3,4}$`.
    d["bullets"][0]["refs"] = ["XYZ-001"]
    p.write_text(json.dumps(d))


def mutate_architecture_assessment_bad_severity(out: Path) -> None:
    p = out / ".fragments" / "ms-architecture-assessment.json"
    d = json.loads(p.read_text())
    d["verdict_severity"] = "not-a-color"
    p.write_text(json.dumps(d))


def mutate_architectural_findings_unknown_theme(out: Path) -> None:
    # Write an architectural-findings fragment that uses a theme not in the enum.
    p = out / ".fragments" / "architectural-findings.json"
    d = {
        "intro": "Intro paragraph describing architectural weaknesses (min 40 chars).",
        "findings": [{
            "id": "AF-001",
            "title": "Fake finding",
            "description": "x" * 45,
            "architectural_theme": "TotallyBogusTheme",
            "severity": "High",
            "structural_defect": "x" * 25,
            "target_architecture": "x" * 25,
            "remediation_effort": "Low",
        }]
    }
    p.write_text(json.dumps(d))


def mutate_critical_attack_chain_invalid_breach(out: Path) -> None:
    p = out / ".fragments" / "critical-attack-chain.json"
    d = json.loads(p.read_text())
    # Stage breach_distance not used directly, but mermaid orientation is enumerated.
    d["mermaid"]["orientation"] = "XY"  # enum is [LR, TD, TB]
    p.write_text(json.dumps(d))


def mutate_remove_required_fragment(out: Path) -> None:
    (out / ".fragments" / "ms-verdict.json").unlink()


def mutate_yaml_missing(out: Path) -> None:
    (out / "threat-model.yaml").unlink()


def mutate_arch_diagrams_missing_components_subsection(out: Path) -> None:
    p = out / ".fragments" / "architecture-diagrams.md"
    txt = p.read_text()
    # Rename away from the canonical title so the required-subsections
    # check fails.
    txt = txt.replace("### 2.3 Components", "### 2.3 Stuff")
    p.write_text(txt)


def mutate_system_overview_wrong_heading(out: Path) -> None:
    p = out / ".fragments" / "system-overview.md"
    txt = p.read_text()
    lines = txt.splitlines()
    lines[0] = "### 1. System Overview"  # wrong level + prefix
    p.write_text("\n".join(lines))


def mutate_attack_walkthroughs_missing_overview(out: Path) -> None:
    p = out / ".fragments" / "attack-walkthroughs.md"
    txt = p.read_text()
    # Remove the Attack Chain Overview heading entirely.
    txt = txt.replace("### 3.1 Attack Chain Overview\n", "")
    p.write_text(txt)


def mutate_attack_surface_rename_5_1(out: Path) -> None:
    p = out / ".fragments" / "attack-surface.md"
    txt = p.read_text()
    txt = txt.replace("### 5.1 Unauthenticated Entry Points", "### 5.1 Anonymous Entry Points")
    p.write_text(txt)


def mutate_sec_arch_rename_7_3(out: Path) -> None:
    p = out / ".fragments" / "security-architecture.md"
    txt = p.read_text()
    txt = txt.replace("### 7.3 Identity & Access Management", "### 7.3 IAM")
    p.write_text(txt)


# ---------------------------------------------------------------------------
# Mutation matrix — each row: (mutation_fn, expected error substring, mode).
#
# mode == "render": expect compose_threat_model.render() to raise FragmentError
#   or the CLI to exit non-zero.
# mode == "render_cli": run via subprocess and assert non-zero + stderr match.
# ---------------------------------------------------------------------------

MUTATIONS = [
    # ---- Schema-level enforcement (JSON fragments) ----
    ("verdict-remove-required",     mutate_verdict_remove_required_field,     "severity"),
    ("verdict-bad-enum",            mutate_verdict_bad_enum,                  "severity"),
    ("verdict-too-few-bullets",     mutate_verdict_too_few_bullets,           "bullets"),
    ("verdict-too-many-bullets",    mutate_verdict_too_many_bullets,          "bullets"),
    ("verdict-bad-ref-pattern",     mutate_verdict_bad_ref_pattern,           "does not match"),
    ("arch-ass-bad-severity",       mutate_architecture_assessment_bad_severity, "verdict_severity"),
    ("architectural-unknown-theme", mutate_architectural_findings_unknown_theme, "architectural_theme"),
    # NB: critical-attack-chain fragment is currently dormant — the §3.1
    # Attack Chain Overview content is authored in the prose fragment, not
    # from a JSON data fragment. Schema exists for forward-compatibility.
    # ---- Fragment presence ----
    ("verdict-missing",             mutate_remove_required_fragment,          "verdict"),
    ("yaml-missing",                mutate_yaml_missing,                      "threat-model.yaml"),
    # ---- Contract-level enforcement (markdown fragments) ----
    ("arch-diagrams-missing-2-3",   mutate_arch_diagrams_missing_components_subsection, "2.3 Components"),
    ("system-overview-wrong-head",  mutate_system_overview_wrong_heading,     "must begin with"),
    ("walkthroughs-missing-3-1",    mutate_attack_walkthroughs_missing_overview, "3.1 Attack Chain Overview"),
    ("attack-surface-rename-5-1",   mutate_attack_surface_rename_5_1,         "5.1 Unauthenticated Entry Points"),
    ("sec-arch-rename-7-3",         mutate_sec_arch_rename_7_3,               "7.3 Identity"),
]


def _strip_regex_escapes(s: str) -> str:
    """Remove `\\\\` backslash escapes used in regex patterns so the
    substring assertion matches the human-readable surface form.
    `'^5\\\\.1 Unauthenticated'` → `'^5.1 Unauthenticated'`.
    """
    return s.replace("\\\\.", ".").replace("\\.", ".")


@pytest.mark.parametrize("name,mutate_fn,expected_substring", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutation_triggers_enforcement(tmp_path: Path, name: str, mutate_fn, expected_substring: str) -> None:
    out = _prepare(tmp_path)
    mutate_fn(out)

    with pytest.raises(compose.FragmentError) as exc_info:
        compose.render(CONTRACT, out)

    err = _strip_regex_escapes(str(exc_info.value)).lower()
    assert expected_substring.lower() in err, (
        f"[{name}] mutation was detected but error message does not mention "
        f"{expected_substring!r}. Got: {str(exc_info.value)}"
    )


# ---------------------------------------------------------------------------
# Post-render QA mutations — exercise qa_checks.py auto-repair + detect paths.
# ---------------------------------------------------------------------------

def _render_then_mutate(tmp_path: Path, post_mutation) -> Path:
    out = _prepare(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    md = out / "threat-model.md"
    md.write_text(rendered, encoding="utf-8")
    post_mutation(md)
    return md


def test_qa_ms_structure_strips_numeric_prefix(tmp_path: Path) -> None:
    """QA `ms_structure` must auto-repair `### 1.1 Verdict` → `### Verdict`."""
    def add_prefix(p: Path):
        t = p.read_text()
        p.write_text(t.replace("### Verdict\n", "### 1.1 Verdict\n", 1))

    md = _render_then_mutate(tmp_path, add_prefix)
    result = subprocess.run(
        [sys.executable, str(QA_SCRIPT), "ms_structure", str(md)],
        capture_output=True, text=True,
    )
    # Auto-repair applies in-place → check the repaired file has `### Verdict`.
    assert "### Verdict\n" in md.read_text(), (
        "ms_structure auto-repair did not strip numeric prefix"
    )
    assert "Stripped numeric prefix" in result.stdout or result.stdout.count('"fix_count"'), (
        f"ms_structure output did not announce the fix. stdout: {result.stdout}"
    )


def test_qa_contract_detects_missing_section(tmp_path: Path) -> None:
    """If §7 is deleted from the body, `qa_checks.py contract` must flag it."""
    def drop_section_7(p: Path):
        t = p.read_text()
        # Remove the whole §7 block (from `## 7.` until the next `## `).
        import re as _re
        t = _re.sub(
            r"^## 7\. Security Architecture.*?(?=^## 8\.)",
            "",
            t,
            flags=_re.DOTALL | _re.MULTILINE,
        )
        p.write_text(t)

    md = _render_then_mutate(tmp_path, drop_section_7)
    result = subprocess.run(
        [sys.executable, str(QA_SCRIPT), "contract", str(md)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0, "qa_checks contract should have flagged missing §7"
    assert "Security Architecture" in result.stdout, (
        f"Missing §7 was flagged but message doesn't mention it. stdout: {result.stdout}"
    )


def test_qa_contract_detects_forbidden_ms_subsection(tmp_path: Path) -> None:
    """Injecting `### Risk Distribution` inside `## Management Summary` must be flagged."""
    def inject_forbidden(p: Path):
        t = p.read_text()
        t = t.replace("### Verdict\n", "### Risk Distribution\n\nblah\n\n### Verdict\n", 1)
        p.write_text(t)

    md = _render_then_mutate(tmp_path, inject_forbidden)
    result = subprocess.run(
        [sys.executable, str(QA_SCRIPT), "contract", str(md)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0, "contract check should flag forbidden MS subsection"
    assert "forbidden" in result.stdout.lower() or "risk distribution" in result.stdout.lower(), (
        f"Forbidden MS subsection was not flagged. stdout: {result.stdout}"
    )
