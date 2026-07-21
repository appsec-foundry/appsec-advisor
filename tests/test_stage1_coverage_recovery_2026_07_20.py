"""Recovery-path tests for the 2026-07-20 juice-shop Stage-1 dead end.

The existing suite covered the blocking mechanisms but never their aftermath:
what post_stage1 reports when coverage is legitimately blocked, whether a
component's turn budget can actually accommodate its file footprint, and whether
a stalled pre-seed is distinguishable from a genuine partial result.

  D1  post_stage1 demanded Analyst-B artifacts that the wave gate forbade producing
  D2a turn budget derived from role heuristics only, blind to file count
  D2b pre-seed placeholder byte-identical to a genuine zero-coverage partial
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import classify_component  # noqa: E402
import orchestration_controller as oc  # noqa: E402
import stride_dispatch_waves as waves  # noqa: E402


# --------------------------------------------------------------------------
# D2a — turn budget must account for how much reading a component requires
# --------------------------------------------------------------------------


def test_turn_budget_covers_mandatory_reads_for_file_heavy_component() -> None:
    """A 24-file component must get more turns than the moderate tier's 22.

    juice-shop data-persistence: paths spanned 24 model files; with the 8
    mandatory context reads that is 32 reads before analysis starts, against a
    22-turn soft target and a 40-turn hard ceiling. Both attempts died at
    exactly 40 tool calls with zero categories completed.
    """
    tiered = classify_component.classify("data-persistence", "", 5, "standard")
    floored = classify_component.classify("data-persistence", "", 5, "standard", file_count=24)

    assert tiered["max_turns"] == 22, "baseline moderate tier changed; update this test"
    assert floored["max_turns"] > 32, (
        f"24 files + 8 mandatory context reads = 32 reads, but the budget is "
        f"{floored['max_turns']} turns — the component cannot reach its first "
        "STRIDE category write"
    )
    assert "footprint" in floored["reason"]


def test_turn_budget_floor_is_capped_for_very_wide_components() -> None:
    """The floor must not scale unbounded — analyzers sample wide components."""
    huge = classify_component.classify("everything", "", 5, "standard", file_count=4000)
    assert huge["max_turns"] <= classify_component._FOOTPRINT_TURN_CAP


def test_turn_budget_unchanged_when_file_count_unknown() -> None:
    """Callers that do not supply a file count keep the previous behaviour."""
    for depth in ("quick", "standard", "thorough"):
        without = classify_component.classify("svc", "", 5, depth)
        explicit_zero = classify_component.classify("svc", "", 5, depth, file_count=0)
        assert without["max_turns"] == explicit_zero["max_turns"]


def test_auth_component_also_gets_the_footprint_floor() -> None:
    """auth-identity ignores footprint for RISK, but reading still costs turns."""
    auth = classify_component.classify("auth-service", "", 8, "standard", file_count=30)
    assert auth["complexity"] == "complex"
    assert auth["max_turns"] > 31, "auth tier budget must still be raised by footprint"


def test_harness_ceiling_exceeds_the_highest_derivable_budget() -> None:
    """The frontmatter maxTurns must stay above any budget the skill can emit.

    A soft target above the hard harness cap is unreachable by construction:
    the analyzer is killed at the frontmatter value regardless of what the
    manifest asked for.
    """
    import re

    text = (REPO_ROOT / "agents" / "appsec-stride-analyzer.md").read_text(encoding="utf-8")
    m = re.search(r"^maxTurns:\s*(\d+)", text, re.M)
    assert m, "maxTurns not found in analyzer frontmatter"
    ceiling = int(m.group(1))

    highest = max(
        classify_component._FOOTPRINT_TURN_CAP,
        max(b["complex"] for b in classify_component.TURN_BUDGETS.values()),
    )
    assert ceiling > highest, (
        f"harness ceiling {ceiling} does not exceed the highest derivable soft "
        f"budget {highest}; components at the top of the range cannot finish"
    )


# --------------------------------------------------------------------------
# D2b — pre-seed must be distinguishable from a genuine partial
# --------------------------------------------------------------------------


def _write_stride(tmp: Path, cid: str, **over) -> None:
    payload = {
        "component_id": cid,
        "component_name": cid,
        "analyzed_at": "2026-07-20T10:00:00Z",
        "partial": True,
        "skipped_categories": [
            "Spoofing",
            "Tampering",
            "Repudiation",
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege",
        ],
        "threats": [],
    }
    payload.update(over)
    (tmp / f".stride-{cid}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_stalled_preseed_reports_a_distinct_reason(tmp_path: Path) -> None:
    """A never-overwritten pre-seed must not read as a generic partial."""
    _write_stride(tmp_path, "data-persistence", seed_only=True)
    reason = waves.completion_error(tmp_path, "data-persistence")

    assert reason is not None
    assert reason != "partial is not false", (
        "a stalled pre-seed is reported identically to a genuine partial result, "
        "so the operator cannot tell that an unchanged retry is futile"
    )
    assert "pre-seed" in reason


def test_genuine_partial_keeps_the_original_reason(tmp_path: Path) -> None:
    """A component that ran and reported partial coverage is unchanged."""
    _write_stride(tmp_path, "svc", skipped_categories=["Spoofing"], threats=[])
    assert waves.completion_error(tmp_path, "svc") == "partial is not false"


def test_seed_only_validates_against_the_stride_schema(tmp_path: Path) -> None:
    """The sentinel must not break schema validation of the pre-seed."""
    from validate_intermediate import validate_stride

    payload = {
        "component_id": "x",
        "component_name": "x",
        "analyzed_at": "2026-07-20T10:00:00Z",
        "partial": True,
        "seed_only": True,
        "skipped_categories": ["Spoofing"],
        "threats": [],
    }
    ok, errors = validate_stride(payload)
    assert ok, f"seed_only broke stride schema validation: {errors}"


# --------------------------------------------------------------------------
# D1 — post_stage1 must diagnose blocked coverage, not blame missing artifacts
# --------------------------------------------------------------------------


def _blocked_run(tmp_path: Path) -> Path:
    """A run that correctly stopped before Analyst-B: no merge/triage artifacts."""
    out = tmp_path / "security"
    out.mkdir()
    (out / ".skill-config.json").write_text(
        json.dumps({"mode": "full", "output_dir": str(out), "assessment_depth": "standard"}),
        encoding="utf-8",
    )
    (out / ".recon-summary.md").write_text("# recon", encoding="utf-8")
    manifest = {
        "generated_at": "2026-07-20T09:00:00Z",
        "components": [
            {"component_id": "ok-svc", "max_turns": 22, "index_paths": {}},
            {"component_id": "stalled-svc", "max_turns": 22, "index_paths": {}},
        ],
    }
    (out / ".stride-dispatch-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    # Build the plan through the real constructor so the fingerprint and schema
    # match, then exhaust the retry budget for the stalled component.
    plan = waves.build_plan(manifest, 8)
    plan["attempts"] = {"ok-svc": 1, "stalled-svc": 2}
    (out / ".dispatch-waves.json").write_text(json.dumps(plan), encoding="utf-8")
    _write_stride(out, "ok-svc", partial=False, skipped_categories=[])
    _write_stride(out, "stalled-svc", seed_only=True)
    return out


def test_post_stage1_names_blocked_coverage_not_missing_artifacts(tmp_path: Path) -> None:
    """The orchestrator obeyed 'stop before Analyst-B'; say so.

    Before this fix post_stage1 checked the Analyst-B artifacts first and raised
    'Stage 1 did not produce required artifacts', which reads as orchestrator
    failure and pushes it into the cut-off recovery path. Running that recovery
    produces the artifacts and then the coverage gate hard-fails anyway — after
    a full merge+triage pass has been paid for.
    """
    out = _blocked_run(tmp_path)

    with pytest.raises(oc.ControllerError) as exc:
        oc.post_stage1(out)

    message = str(exc.value)
    assert "did not produce required artifacts" not in message, (
        "blocked coverage is still reported as missing artifacts; the orchestrator "
        "will follow the recovery path and pay for merge+triage before dying"
    )
    assert "stalled-svc" in message, "the blocking component must be named"
    assert "coverage" in message.lower()


# --------------------------------------------------------------------------
# D2a follow-up — the footprint count must see recursive path patterns
# --------------------------------------------------------------------------


def test_footprint_count_sees_bare_recursive_patterns(tmp_path: Path) -> None:
    """`Path.glob("routes/**")` yields directories, not the files inside.

    Component inventories use exactly that form, so the first version of the
    footprint floor counted zero for the widest components -- backend-api came
    out at 2 files instead of ~700 and got no floor at all, defeating the fix
    for precisely the components that need it most.
    """
    import build_stride_dispatch_manifest as bm  # noqa: PLC0415

    pkg = tmp_path / "routes"
    pkg.mkdir()
    for i in range(12):
        (pkg / f"r{i}.ts").write_text("x", encoding="utf-8")

    bare = len(bm._glob_files(tmp_path, ["routes/**"]))
    expanded = len(bm._glob_files(tmp_path, bm._expand_recursive(["routes/**"])))

    assert bare == 0, "pathlib behaviour changed; this guard may be obsolete"
    assert expanded == 12, f"recursive expansion counted {expanded} of 12 files"


def test_recursive_pattern_component_gets_a_raised_budget(tmp_path: Path) -> None:
    """A component declared as `models/**` must still earn its floor."""
    import build_stride_dispatch_manifest as bm  # noqa: PLC0415

    models = tmp_path / "models"
    models.mkdir()
    for i in range(24):
        (models / f"m{i}.ts").write_text("x", encoding="utf-8")

    turns = bm._component_max_turns(tmp_path, ["models/**"], 22)
    assert turns > 32, (
        f"a 24-file component declared with a recursive pattern got {turns} turns; "
        "24 source + 8 mandatory context reads leave nothing for the category writes"
    )


def test_expand_recursive_leaves_explicit_patterns_alone() -> None:
    import build_stride_dispatch_manifest as bm  # noqa: PLC0415

    out = bm._expand_recursive(["server.ts", "frontend/**/*.ts"])
    assert out == ["server.ts", "frontend/**/*.ts"]


# --------------------------------------------------------------------------
# D2c — complexity must rest on evidence, not on what the inventory named it
# --------------------------------------------------------------------------


def _auth_run(tmp_path: Path, files: list[str]) -> Path:
    (tmp_path / ".source-auth-findings.json").write_text(
        json.dumps({"findings": [{"file": f, "line": 1} for f in files]}), encoding="utf-8"
    )
    return tmp_path


def test_auth_evidence_raises_complexity_regardless_of_name(tmp_path: Path) -> None:
    """The floor must not depend on the component being called auth-something.

    2026-07-20: the component holding JWT signing, password hashing, login and
    2FA was named `auth-service` and rated *moderate* by the analyst inventory,
    where an earlier run of the same commit rated the same code *complex*. The
    smaller tier carried the smaller turn budget and it stalled. A naming rule
    cannot fix this — the next inventory may call it `identity-provider`.
    """
    import build_stride_dispatch_manifest as bm  # noqa: PLC0415

    out = _auth_run(tmp_path, ["lib/insecurity.ts"])
    auth = bm._auth_evidence_files(out)

    for name_agnostic_paths in (["lib/insecurity.ts"], ["lib/**"]):
        got, reason = bm._evidence_complexity_floor(name_agnostic_paths, auth, "moderate")
        assert got == "complex", f"{name_agnostic_paths} owns auth code but stayed {got}"
        assert "auth evidence" in reason


def test_components_without_auth_code_are_untouched(tmp_path: Path) -> None:
    """The floor must not inflate every component."""
    import build_stride_dispatch_manifest as bm  # noqa: PLC0415

    out = _auth_run(tmp_path, ["lib/insecurity.ts"])
    auth = bm._auth_evidence_files(out)
    got, reason = bm._evidence_complexity_floor(["frontend/**"], auth, "moderate")
    assert got == "moderate"
    assert reason == ""


def test_floor_never_lowers_a_claimed_complexity(tmp_path: Path) -> None:
    import build_stride_dispatch_manifest as bm  # noqa: PLC0415

    out = _auth_run(tmp_path, ["lib/insecurity.ts"])
    auth = bm._auth_evidence_files(out)
    got, _ = bm._evidence_complexity_floor(["lib/insecurity.ts"], auth, "complex")
    assert got == "complex"


def test_missing_scanner_artifact_is_not_fatal(tmp_path: Path) -> None:
    """Classification must survive a missing or corrupt evidence file."""
    import build_stride_dispatch_manifest as bm  # noqa: PLC0415

    assert bm._auth_evidence_files(tmp_path) == []
    (tmp_path / ".source-auth-findings.json").write_text("{ not json", encoding="utf-8")
    assert bm._auth_evidence_files(tmp_path) == []
    got, reason = bm._evidence_complexity_floor(["lib/**"], [], "moderate")
    assert got == "moderate" and reason == ""


def test_auth_prefix_rule_matches_its_documented_contract() -> None:
    """Secondary guard: the docstring's `auth-*` rule was only an enumeration.

    This is defence in depth for callers that classify without scanner evidence;
    the evidence floor above is the primary mechanism.
    """
    assert classify_component._to_canonical("auth-service") == "auth-identity"
    assert classify_component._to_canonical("auth-anything-new") == "auth-identity"
    assert classify_component._to_canonical("backend-api") == "backend-api"


def test_inventory_hint_cannot_opt_out_of_the_auth_floor() -> None:
    """A hint comes from the LLM inventory and must not bypass a safety floor."""
    got = classify_component.classify("auth-service", "", 5, "standard", canonical_id="auth-service")
    assert got["complexity"] == "complex"
