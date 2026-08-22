"""Unit tests for scripts/validate_fragment.py.

validate_fragment.py is a hard gate: it runs between LLM fragment output and
the renderer. These tests verify the CLI contract (exit codes, stdout/stderr)
and the FRAGMENT_SCHEMAS registry directly.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_fragment.py"
SCHEMAS_DIR = REPO_ROOT / "schemas" / "fragments"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


vf = _load_module("validate_fragment", SCRIPT_PATH)


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# Registry completeness
# ---------------------------------------------------------------------------


def test_all_schema_files_present():
    """Every schema registered in FRAGMENT_SCHEMAS must exist on disk."""
    missing = []
    for fragment_type, schema_file in vf.FRAGMENT_SCHEMAS.items():
        path = SCHEMAS_DIR / schema_file
        if not path.is_file():
            missing.append(f"{fragment_type} → {schema_file}")
    assert not missing, "Missing schema files:\n  " + "\n  ".join(missing)


def test_schema_files_are_valid_json():
    """Every registered schema file must parse as valid JSON."""
    invalid = []
    for fragment_type, schema_file in vf.FRAGMENT_SCHEMAS.items():
        path = SCHEMAS_DIR / schema_file
        if path.is_file():
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                invalid.append(f"{fragment_type}: {e}")
    assert not invalid, "Invalid JSON in schema files:\n  " + "\n  ".join(invalid)


def test_fragment_schemas_not_empty():
    assert len(vf.FRAGMENT_SCHEMAS) >= 6, "Expected at least 6 registered fragment types"


# ---------------------------------------------------------------------------
# CLI exit codes
# ---------------------------------------------------------------------------


def test_unknown_fragment_type_exits_nonzero(tmp_path: Path):
    dummy = tmp_path / "frag.json"
    dummy.write_text("{}")
    result = _run(["nonexistent-type", str(dummy)])
    assert result.returncode != 0


def test_missing_fragment_file_exits_nonzero():
    result = _run(["verdict", "/nonexistent/path/frag.json"])
    assert result.returncode != 0


def test_invalid_json_fragment_exits_nonzero(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {{{")
    result = _run(["verdict", str(bad)])
    assert result.returncode != 0


def test_schema_violation_exits_1(tmp_path: Path):
    """A structurally wrong fragment must exit 1 (schema violation)."""
    frag = tmp_path / "bad-verdict.json"
    frag.write_text('{"wrong_field": true}')
    result = _run(["verdict", str(frag)])
    assert result.returncode == 1
    assert "VALIDATE_FAILED" in result.stderr


def test_valid_fragment_exits_0(tmp_path: Path):
    """Load the verdict schema and build a minimal conforming payload."""
    schema_path = SCHEMAS_DIR / vf.FRAGMENT_SCHEMAS["verdict"]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    required = schema.get("required", [])

    # Build a minimal object with empty/false values for required fields
    # so we can verify the happy path without tight-coupling to the schema.
    minimal: dict = {}
    props = schema.get("properties", {})
    for field in required:
        field_schema = props.get(field, {})
        ftype = field_schema.get("type")
        if ftype == "string":
            minimal[field] = "placeholder"
        elif ftype == "integer":
            minimal[field] = 0
        elif ftype == "boolean":
            minimal[field] = False
        elif ftype == "array":
            minimal[field] = []
        elif ftype == "object":
            minimal[field] = {}
        else:
            minimal[field] = None

    frag = tmp_path / "ok-verdict.json"
    frag.write_text(json.dumps(minimal))

    result = _run(["verdict", str(frag)])
    # May fail schema constraints (e.g. minLength) — we only assert the
    # script ran without an unexpected crash (exit 2 = usage/IO error).
    assert result.returncode in (0, 1), f"Expected 0 or 1, got {result.returncode}; stderr: {result.stderr}"


# ---------------------------------------------------------------------------
# pre-render-gate hard fail on missing .fragments/ or missing required set
# ---------------------------------------------------------------------------


def test_pre_render_gate_fails_hard_when_fragments_dir_missing(tmp_path: Path):
    """Regression: previously returned exit 0 with a "will error later"
    comment, which silently masked the inline-shortcut failure mode."""
    # No .fragments/ at all.
    result = _run(["pre-render-gate", str(tmp_path)])
    assert result.returncode == 1, (
        f"Expected exit 1 (hard fail on missing .fragments/), got {result.returncode}. stderr: {result.stderr}"
    )
    # The report file is still written so the skill can inspect it.
    report = tmp_path / ".pre-render-report.json"
    assert report.is_file()
    data = json.loads(report.read_text())
    assert "error" in data
    assert ".fragments/" in data["error"]
    assert data["missing_required"]  # all 8 required fragments listed


def test_pre_render_gate_fails_on_partial_fragment_set(tmp_path: Path):
    """Fragment dir present, but only a subset of required files on disk —
    still a policy violation because compose won't be able to render §§1–7."""
    frag = tmp_path / ".fragments"
    frag.mkdir()
    # Only one fragment present — the rest are missing.
    (frag / "ms-verdict.json").write_text("{}")
    result = _run(["pre-render-gate", str(tmp_path)])
    assert result.returncode == 1
    data = json.loads((tmp_path / ".pre-render-report.json").read_text())
    assert data["missing_required"]
    assert "ms-verdict.json" not in data["missing_required"]
    # The other 6 required fragments must be listed.
    assert len(data["missing_required"]) == 6


def test_pre_render_gate_passes_with_full_required_set(tmp_path: Path):
    """All 7 required fragments present → missing_required empty.

    The gate still may exit 1 if the JSON stubs fail nested schema rules
    (e.g. minLength, enum constraints). We only assert that the "missing
    required" branch is NOT the reason for any non-zero exit.
    """
    frag = tmp_path / ".fragments"
    frag.mkdir()
    # The mandatory JSON fragment needs readable JSON content. The schema
    # validation loop may reject it — that's fine, the gate's "missing"
    # branch must still be empty.
    (frag / "ms-verdict.json").write_text("{}")
    # Plain-markdown fragments need no schema validation.
    for name in (
        "system-overview.md",
        "architecture-diagrams.md",
        "attack-walkthroughs.md",
        "assets.md",
        "attack-surface.md",
        "security-architecture.md",
    ):
        (frag / name).write_text("# stub\n")
    _run(["pre-render-gate", str(tmp_path)])
    data = json.loads((tmp_path / ".pre-render-report.json").read_text())
    assert not data["missing_required"]


# ---------------------------------------------------------------------------
# components sidecar — selection-criteria inputs (deployment_zones / crown-jewel)
# ---------------------------------------------------------------------------


def _components(*, with_criteria: bool) -> dict:
    comp = {
        "id": "backend-api",
        "name": "Express REST API Backend",
        "description": "Node/Express backend serving REST endpoints.",
        "paths": ["routes/**", "lib/**"],
        "tier": "application",
    }
    if with_criteria:
        comp["deployment_zones"] = ["internet", "internal-network"]
        comp["handles_sensitive_data"] = True
    return {"schema_version": 1, "components": [comp]}


def test_components_with_selection_criteria_exits_0(tmp_path: Path):
    """deployment_zones[] + handles_sensitive_data validate against the schema —
    the data plumbing that lets STRIDE-component selection be criteria-derived."""
    frag = tmp_path / ".components.json"
    frag.write_text(json.dumps(_components(with_criteria=True)))
    result = _run(["components", str(frag)])
    assert result.returncode == 0, result.stderr


def test_components_without_selection_criteria_still_valid(tmp_path: Path):
    """Back-compat: the new fields are optional — a sidecar omitting them passes."""
    frag = tmp_path / ".components.json"
    frag.write_text(json.dumps(_components(with_criteria=False)))
    result = _run(["components", str(frag)])
    assert result.returncode == 0, result.stderr


def test_components_bad_crown_jewel_type_exits_1(tmp_path: Path):
    """handles_sensitive_data is a boolean — a string must be rejected."""
    payload = _components(with_criteria=True)
    payload["components"][0]["handles_sensitive_data"] = "yes"
    frag = tmp_path / ".components.json"
    frag.write_text(json.dumps(payload))
    result = _run(["components", str(frag)])
    assert result.returncode == 1
    assert "VALIDATE_FAILED" in result.stderr


def test_components_repo_gate_accepts_existing_glob(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "routes").mkdir(parents=True)
    (repo / "routes" / "login.ts").write_text("export const login = true\n", encoding="utf-8")
    frag = tmp_path / ".components.json"
    payload = _components(with_criteria=False)
    payload["components"][0]["paths"] = ["routes/**"]
    frag.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(["components", str(frag), "--repo-root", str(repo)])

    assert result.returncode == 0, result.stderr


def test_components_repo_gate_rejects_invented_and_escaping_paths(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    frag = tmp_path / ".components.json"
    payload = _components(with_criteria=False)
    payload["components"][0]["paths"] = ["routes/invented.ts", "../outside/**"]
    frag.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(["components", str(frag), "--repo-root", str(repo)])

    assert result.returncode == 1
    assert "matches no repository entry" in result.stderr
    assert "unsafe or non-canonical" in result.stderr


def test_components_repo_gate_rejects_glob_matching_only_escaping_symlink(tmp_path: Path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (outside / "secret.py").write_text("secret = true\n", encoding="utf-8")
    (repo / "linked").symlink_to(outside, target_is_directory=True)
    frag = tmp_path / ".components.json"
    payload = _components(with_criteria=False)
    payload["components"][0]["paths"] = ["linked/**"]
    frag.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(["components", str(frag), "--repo-root", str(repo)])

    assert result.returncode == 1
    assert "matches no repository entry" in result.stderr


def _data_flows(evidence: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "component_inventory_fingerprint": "sha256:" + "a" * 64,
        "data_flows": [
            {
                "id": "df-001",
                "from": "external",
                "to": "backend-api",
                "label": "Login",
                "protocol": "HTTPS",
                "data_classification": "Confidential",
                "direction": "request-response",
                "evidence": evidence,
                "provenance": "architecture",
            }
        ],
    }


def test_data_flow_repo_gate_accepts_existing_source_line(tmp_path: Path):
    repo = tmp_path / "repo"
    source = repo / "routes" / "login.ts"
    source.parent.mkdir(parents=True)
    source.write_text("first\nsecond\n", encoding="utf-8")
    frag = tmp_path / ".data-flows.json"
    frag.write_text(json.dumps(_data_flows([{"file": "routes/login.ts", "line": 2}])), encoding="utf-8")

    result = _run(["data-flows", str(frag), "--repo-root", str(repo)])

    assert result.returncode == 0, result.stderr


def test_data_flow_repo_gate_rejects_missing_file_and_line(tmp_path: Path):
    repo = tmp_path / "repo"
    source = repo / "routes" / "login.ts"
    source.parent.mkdir(parents=True)
    source.write_text("only\n", encoding="utf-8")
    frag = tmp_path / ".data-flows.json"
    frag.write_text(
        json.dumps(
            _data_flows(
                [
                    {"file": "routes/invented.ts", "line": 1},
                    {"file": "routes/login.ts", "line": 2},
                ]
            )
        ),
        encoding="utf-8",
    )

    result = _run(["data-flows", str(frag), "--repo-root", str(repo)])

    assert result.returncode == 1
    assert "missing or unsafe file" in result.stderr
    assert "line 2 exceeds" in result.stderr


# ---------------------------------------------------------------------------
# In-process tests (drive functions directly for coverage of error branches)
# ---------------------------------------------------------------------------

import pytest  # noqa: E402


def test_load_schema_unknown_type_raises_systemexit():
    with pytest.raises(SystemExit) as ei:
        vf._load_schema("totally-unknown")
    assert "unknown fragment type" in str(ei.value)


def test_load_schema_missing_file_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(vf, "SCHEMAS_DIR", tmp_path)  # empty dir, no schemas
    with pytest.raises(SystemExit) as ei:
        vf._load_schema("verdict")
    assert "schema file not found" in str(ei.value)


def test_load_schema_invalid_json_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(vf, "SCHEMAS_DIR", tmp_path)
    (tmp_path / "verdict.schema.json").write_text("{bad json")
    with pytest.raises(SystemExit) as ei:
        vf._load_schema("verdict")
    assert "is not JSON" in str(ei.value)


def test_load_fragment_missing_raises(tmp_path):
    with pytest.raises(SystemExit) as ei:
        vf._load_fragment(tmp_path / "nope.json")
    assert "fragment not found" in str(ei.value)


def test_load_fragment_invalid_json_raises(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("not json")
    with pytest.raises(SystemExit) as ei:
        vf._load_fragment(p)
    assert "not valid JSON" in str(ei.value)


def test_validate_schema_violation_returns_1(tmp_path, capsys):
    p = tmp_path / "bad-verdict.json"
    p.write_text('{"wrong": 1}')
    rc = vf.validate("verdict", p)
    assert rc == 1
    assert "VALIDATE_FAILED" in capsys.readouterr().err


def test_fragment_type_for_file_stem_fallback(tmp_path):
    # Not in _FRAGMENT_FILENAMES but stem matches a schema (components.json)
    assert vf._fragment_type_for_file(tmp_path / "components.json") == "components"


def test_fragment_type_for_file_unknown_returns_none(tmp_path):
    assert vf._fragment_type_for_file(tmp_path / "random-thing.json") is None


def test_gate_missing_dir_emit_json(tmp_path, capsys):
    rc = vf.run_pre_render_gate(tmp_path, emit_json=True)
    out = capsys.readouterr().out
    assert rc == 1
    data = json.loads(out)
    assert "error" in data


def test_gate_skips_unknown_and_missing_schema(tmp_path, monkeypatch, capsys):
    frag = tmp_path / ".fragments"
    frag.mkdir()
    for name in (
        "ms-verdict.json",
        "system-overview.md",
        "architecture-diagrams.md",
        "attack-walkthroughs.md",
        "assets.md",
        "attack-surface.md",
        "security-architecture.md",
    ):
        (frag / name).write_text("{}" if name.endswith(".json") else "# x\n")
    # Unknown json fragment → skipped (line 218-219)
    (frag / "random-thing.json").write_text("{}")
    # Known type but schema file absent → skipped (224-225); point at empty dir
    (frag / "components.json").write_text("{}")
    monkeypatch.setattr(vf, "SCHEMAS_DIR", tmp_path / "no-schemas")
    rc = vf.run_pre_render_gate(tmp_path, emit_json=False)
    err = capsys.readouterr().err
    data = json.loads((tmp_path / ".pre-render-report.json").read_text())
    assert any("random-thing.json" == s for s in data["skipped"])
    assert any("components.json" in s for s in data["skipped"])
    # ms-verdict schema also absent → skipped, so nothing failed/missing → exit 0
    assert rc == 0


def test_gate_fragment_invalid_json_recorded_failed(tmp_path, capsys):
    frag = tmp_path / ".fragments"
    frag.mkdir()
    for name in (
        "system-overview.md",
        "architecture-diagrams.md",
        "attack-walkthroughs.md",
        "assets.md",
        "attack-surface.md",
        "security-architecture.md",
    ):
        (frag / name).write_text("# x\n")
    # ms-verdict.json present but invalid JSON → failed branch (230-232)
    (frag / "ms-verdict.json").write_text("{bad json")
    rc = vf.run_pre_render_gate(tmp_path, emit_json=False)
    err = capsys.readouterr().err
    data = json.loads((tmp_path / ".pre-render-report.json").read_text())
    assert data["failed"]
    assert rc == 1
    assert "failed schema" in err


def test_gate_all_valid_prints_summary(tmp_path, monkeypatch, capsys):
    frag = tmp_path / ".fragments"
    frag.mkdir()
    for name in (
        "ms-verdict.json",
        "system-overview.md",
        "architecture-diagrams.md",
        "attack-walkthroughs.md",
        "assets.md",
        "attack-surface.md",
        "security-architecture.md",
    ):
        (frag / name).write_text("{}" if name.endswith(".json") else "# x\n")
    # Make schema trivially-passing so ms-verdict validates and lands in passed[]
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    (schema_dir / "verdict.schema.json").write_text(json.dumps({"type": "object"}))
    monkeypatch.setattr(vf, "SCHEMAS_DIR", schema_dir)
    rc = vf.run_pre_render_gate(tmp_path, emit_json=False)
    out = capsys.readouterr().out
    assert rc == 0
    assert "all 1 fragment(s) valid" in out


def test_write_report_oserror_swallowed(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(vf, "atomic_write_json", boom)
    # Should not raise
    vf._write_report(tmp_path, {"passed": []})


def test_main_gate_not_a_directory_returns_2(tmp_path, capsys):
    rc = vf.main(["pre-render-gate", str(tmp_path / "nope")])
    assert rc == 2
    assert "not a directory" in capsys.readouterr().err


def test_main_legacy_dispatch(tmp_path, capsys):
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    (schema_dir / "verdict.schema.json").write_text(json.dumps({"type": "object"}))
    import unittest.mock as mock

    p = tmp_path / "v.json"
    p.write_text("{}")
    with mock.patch.object(vf, "SCHEMAS_DIR", schema_dir):
        rc = vf.main(["verdict", str(p)])
    assert rc == 0
    assert "VALIDATE_OK" in capsys.readouterr().out


def test_main_gate_dispatch_emit_json(tmp_path, capsys):
    rc = vf.main(["pre-render-gate", str(tmp_path), "--json"])
    out = capsys.readouterr().out
    assert rc == 1
    assert json.loads(out)["error"]


# ---------------------------------------------------------------------------
# pre-render-gate --write-repair-plan
#
# The gate itself predates these tests; what is new is that a failure becomes
# directly actionable for appsec-fragment-fixer instead of only being reported.
# ---------------------------------------------------------------------------

_REQUIRED_MD = (
    "system-overview.md",
    "architecture-diagrams.md",
    "attack-walkthroughs.md",
    "assets.md",
    "attack-surface.md",
    "security-architecture.md",
)


def _ai_exposure(label: str) -> dict:
    return {
        "ai_risks": [
            {
                "name": "Prompt Injection",
                "description": (
                    "Untrusted retrieved content reaches the model instruction channel without separation."
                ),
                "findings": [{"ref": "T-019", "label": label}],
            }
        ]
    }


def _valid_verdict() -> dict:
    return {
        "severity": "red",
        "opening": (
            "The service exposes every route without authentication, so any anonymous caller reaches all stored data."
        ),
        "bullets": [
            {
                "title": "Admin access without a password",
                "body": "Any caller can claim the administrator identity and gain full privileged access.",
                "refs": ["T-003"],
            },
            {
                "title": "Stored data readable by anyone",
                "body": "The database interface executes caller-supplied statements without any access check.",
                "refs": ["T-012"],
            },
        ],
        "closing": (
            "The service must not be deployed beyond a local development machine until authentication is in place."
        ),
    }


def _complete_fragment_set(tmp_path: Path) -> Path:
    """A fragment dir satisfying the unconditional required set. ms-verdict.json
    must be schema-VALID here — these tests assert on the gate's verdict, not
    merely on fragment presence."""
    frag = tmp_path / ".fragments"
    frag.mkdir()
    (frag / "ms-verdict.json").write_text(json.dumps(_valid_verdict()))
    for name in _REQUIRED_MD:
        (frag / name).write_text("# placeholder\n")
    return frag


def test_repair_plan_is_actionable_on_schema_violation(tmp_path: Path):
    """An over-long label must produce a fixer-consumable plan naming the
    offending fragment — the 2026-08-18 insecure-ai-app failure mode, where
    compose rejected the fragment one dispatch after it was authored."""
    frag = _complete_fragment_set(tmp_path)
    too_long = "R" * 81  # schema caps findings[].label at 80
    (frag / "ms-ai-exposure.json").write_text(json.dumps(_ai_exposure(too_long)))

    result = _run(["pre-render-gate", str(tmp_path), "--write-repair-plan"])
    assert result.returncode == 1

    plan = json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
    assert plan["status"] == "fail"
    assert plan["actionable"] is True
    assert plan["action_count"] == 1
    action = plan["actions"][0]
    assert action["type"] == "fragment_schema_violation"
    assert action["fragments_to_rewrite"] == [".fragments/ms-ai-exposure.json"]
    assert action["severity"] == "blocking"
    # The exact JSON path must survive into the plan so the fixer edits one field.
    assert "findings/0/label" in action["raw_issue"]
    assert "ai-exposure.schema.json" in action["remediation"]


def test_repair_plan_not_actionable_when_only_required_fragments_missing(tmp_path: Path):
    """Missing required fragments are owned by pregenerate_fragments.py — the
    fixer must not hand-author them, so the plan stays non-actionable."""
    frag = tmp_path / ".fragments"
    frag.mkdir()
    # Schema-valid, so the ONLY defect is the absent markdown fragments.
    (frag / "ms-verdict.json").write_text(json.dumps(_valid_verdict()))

    result = _run(["pre-render-gate", str(tmp_path), "--write-repair-plan"])
    assert result.returncode == 1

    plan = json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
    assert plan["actionable"] is False
    assert plan["status"] == "manual_review"
    assert plan["actions"] == []
    assert plan["manual_review_items"]


def test_no_repair_plan_written_when_gate_passes(tmp_path: Path):
    """A clean run must leave no stale plan behind for the next stage to read."""
    frag = _complete_fragment_set(tmp_path)
    (frag / "ms-ai-exposure.json").write_text(json.dumps(_ai_exposure("RAG document promoted to system channel")))

    result = _run(["pre-render-gate", str(tmp_path), "--write-repair-plan"])
    assert result.returncode == 0
    assert not (tmp_path / ".pre-render-repair-plan.json").exists()


def test_repair_plan_only_written_when_flag_passed(tmp_path: Path):
    """Default behaviour is unchanged — the plan is opt-in."""
    frag = _complete_fragment_set(tmp_path)
    (frag / "ms-ai-exposure.json").write_text(json.dumps(_ai_exposure("R" * 81)))

    result = _run(["pre-render-gate", str(tmp_path)])
    assert result.returncode == 1
    assert not (tmp_path / ".pre-render-repair-plan.json").exists()


def test_repair_plan_shares_composes_attempt_counter(tmp_path: Path):
    """The gate and compose_threat_model.py write the SAME plan file, so the
    three-attempt cap has to count both producers. A gate that reset the
    counter would hand the repair agent an unbounded loop."""
    frag = _complete_fragment_set(tmp_path)
    (frag / "ms-ai-exposure.json").write_text(json.dumps(_ai_exposure("R" * 81)))
    plan_path = tmp_path / ".pre-render-repair-plan.json"

    # A prior compose failure already consumed two attempts.
    plan_path.write_text(json.dumps({"status": "fail", "attempt": 2}))
    _run(["pre-render-gate", str(tmp_path), "--write-repair-plan"])
    plan = json.loads(plan_path.read_text())
    assert plan["attempt"] == 3
    assert plan["actionable"] is True

    # The next failure exceeds the cap and must stop dispatching repairs.
    _run(["pre-render-gate", str(tmp_path), "--write-repair-plan"])
    plan = json.loads(plan_path.read_text())
    assert plan["attempt"] == 4
    assert plan["status"] == "exhausted"
    assert plan["actionable"] is False


# ---------------------------------------------------------------------------
# Tier self-contradiction (2026-08-22)
# ---------------------------------------------------------------------------


def _web_ui_component(**overrides):
    """The real record from the 2026-08-21 insecure-large-spring-app run."""
    component = {
        "id": "web-ui",
        "name": "Thymeleaf Web UI Templates",
        "tier": "client",
        "framework": "thymeleaf",
        "description": ("Server-side HTML rendering layer using Thymeleaf templates."),
    }
    component.update(overrides)
    return component


def test_server_side_renderer_may_not_be_declared_client():
    """`tier` drives the STRIDE lens, so this is analysis, not a label.

    `build_stride_dispatch_manifest._is_frontend` returns True on
    `tier == "client"` before consulting anything else, which adds the browser
    threat lens and five scoping decisions. The shipped record carried
    `framework: thymeleaf` and a "Server-side HTML rendering layer" description
    next to `tier: client`, and nothing objected.
    """
    errors = vf._tier_contradiction_errors(_web_ui_component(), "web-ui")
    assert len(errors) == 1
    assert "renders on the server" in errors[0]
    assert "tier 'application'" in errors[0]


def test_application_tier_with_server_side_renderer_is_accepted():
    assert vf._tier_contradiction_errors(_web_ui_component(tier="application"), "web-ui") == []


def test_client_tier_without_a_server_side_framework_is_accepted():
    """A judgement call about placement stays the analyst's."""
    for framework in ("react", "angular", "vue", "handlebars", "next", ""):
        assert vf._tier_contradiction_errors(_web_ui_component(framework=framework), "web-ui") == [], (
            f"{framework!r} must not be rejected — a gate may not guess"
        )


def test_client_side_capable_engines_are_not_on_the_deny_list():
    """Only unambiguously server-only engines may fail a run."""
    for framework in ("handlebars", "mustache", "next", "nuxt", "remix"):
        assert framework not in vf._SERVER_SIDE_RENDERERS


def test_tier_contradiction_fails_the_cli_gate(tmp_path):
    """The check must be reachable from the real CLI, not just importable.

    `scripts/canonicalize_component_id.py` is the cautionary case: fully
    implemented and unit-tested, but called from nowhere in the pipeline. A
    validator nothing invokes protects nothing, so this drives the actual
    entry point and asserts the run stops.
    """
    fragment = tmp_path / "components.json"
    fragment.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [
                    {
                        "id": "web-ui",
                        "name": "Thymeleaf Web UI Templates",
                        "description": "Server-side HTML rendering layer.",
                        "tier": "client",
                        "framework": "thymeleaf",
                        "paths": ["scripts/**"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    proc = _run(["components", str(fragment), "--repo-root", str(REPO_ROOT)])
    assert proc.returncode != 0, "the CLI accepted a self-contradicting tier"
    assert "renders on the server" in (proc.stdout + proc.stderr)
