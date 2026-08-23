#!/usr/bin/env python3
"""Validate an LLM-authored fragment against its JSON schema.

Fragments are the ONLY way the orchestrator can influence the rendered
Markdown — the renderer then consumes the validated data. This script is
the hard gate that prevents malformed fragments from reaching the renderer.

Typical use (from the controller and compact stage runtimes):

    python3 validate_fragment.py verdict "$OUTPUT_DIR/.fragments/ms-verdict.json"

Bulk pre-render gate — validates all JSON fragments before compose runs:

    python3 validate_fragment.py pre-render-gate "$OUTPUT_DIR" [--json]

Exit codes:
    0 — fragment is valid (or all fragments passed the gate)
    1 — schema violation (or at least one fragment failed the gate)
    2 — usage / IO error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ms_component_refs
import yaml
from _atomic_io import atomic_write_json

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = PLUGIN_ROOT / "schemas" / "fragments"


def _normalize_ms_component_refs(output_dir: Path, fragments_dir: Path) -> None:
    """Repair slug component ids in MS fragments exactly as compose does.

    Best-effort: without a readable threat-model.yaml there is no slug -> C-NN
    mapping to apply, and the fragments are validated as they stand.
    """
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        return
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return
    _ms_component_refs.normalize_ms_fragments(fragments_dir, data.get("components"))


# Map fragment type → schema file. This is the single source of truth for
# which fragments validate against which schemas.
FRAGMENT_SCHEMAS: dict[str, str] = {
    "verdict": "verdict.schema.json",
    "critical-attack-tree": "critical-attack-tree.schema.json",
    "compound-chains": "compound-chains.schema.json",
    "operational-strengths-overrides": "operational-strengths-overrides.schema.json",
    "security-posture-attack-paths": "security-posture-attack-paths.schema.json",
    "anti-patterns": "anti-patterns.schema.json",
    "ai-exposure": "ai-exposure.schema.json",
    "ms-top-mitigations": "ms-top-mitigations.schema.json",
    # Substep 2 deterministic migration sidecars. These are INPUTS to
    # scripts/build_threat_model_yaml.py, NOT render fragments — they
    # live at $OUTPUT_DIR/.X.json (dot-prefix, repo root of output_dir)
    # rather than $OUTPUT_DIR/.fragments/X.json. They share the validator
    # because the underlying JSON-Schema machinery is identical; the
    # fragment_filename map below stays empty for them so the pre-render
    # gate keeps ignoring them.
    "components": "components.schema.json",
    "data-flows": "data-flows.schema.json",
    "assets": "assets.schema.json",
    "trust-boundaries": "trust-boundaries.schema.json",
    "trust-boundary-candidates": "trust-boundary-candidates.schema.json",
    "security-controls": "security-controls.schema.json",
    "attack-surface-overrides": "attack-surface-overrides.schema.json",
    "mitigation-overrides": "mitigation-overrides.schema.json",
    "tier-root-causes": "tier-root-causes.schema.json",
}

# Reverse map: schema file stem → fragment type (used by pre-render-gate to
# identify the type of each .json fragment found on disk).
_STEM_TO_TYPE: dict[str, str] = {v.replace(".schema.json", ""): k for k, v in FRAGMENT_SCHEMAS.items()}

# Shared with compose_threat_model._PRE_RENDER_REPAIR_MAX_ATTEMPTS: both write
# `.pre-render-repair-plan.json`, so the cap has to mean the same thing in both.
_PRE_RENDER_REPAIR_MAX_ATTEMPTS = 3

# Canonical fragment filenames used by the renderer (from sections-contract.yaml
# + data/sections-contract.yaml). Keyed by fragment type for reverse lookup.
# Substep-2 sidecars are intentionally NOT listed here — they are NOT render
# fragments, they are aggregator inputs (live at OUTPUT_DIR/.X.json).
_FRAGMENT_FILENAMES: dict[str, str] = {
    "verdict": "ms-verdict.json",
    "critical-attack-tree": "ms-critical-attack-tree.json",
    "compound-chains": "compound-chains.json",
    "operational-strengths-overrides": "operational-strengths-overrides.json",
    "security-posture-attack-paths": "security-posture-attack-paths.json",
    "anti-patterns": "ms-anti-patterns.json",
    "ai-exposure": "ms-ai-exposure.json",
    "ms-top-mitigations": "ms-top-mitigations.json",
}

_URL_OR_DRIVE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[A-Za-z][A-Za-z0-9+.-]*://)")


def _safe_repository_relative(value: Any) -> str | None:
    """Return one canonical POSIX repository path/glob, or ``None``."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    if "\\" in value or value.startswith(("/", "./")) or _URL_OR_DRIVE_RE.match(value):
        return None
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return value


def _repository_pattern_matches(repo_root: Path, pattern: str) -> bool:
    """Return whether a path/glob resolves to at least one contained entry."""
    patterns = [pattern]
    if pattern.endswith("**"):
        patterns.append(pattern + "/*")
    root = repo_root.resolve()
    for candidate_pattern in patterns:
        try:
            matches = root.glob(candidate_pattern)
            for index, candidate in enumerate(matches):
                if index >= 10_000:
                    break
                try:
                    candidate.resolve().relative_to(root)
                except (OSError, RuntimeError, ValueError):
                    continue
                try:
                    if candidate.exists():
                        return True
                except OSError:
                    continue
        except (OSError, RuntimeError, ValueError):
            return False
    return False


def _regular_repository_file(repo_root: Path, relative: str) -> Path | None:
    canonical = _safe_repository_relative(relative)
    if canonical is None or any(char in canonical for char in "*?[]{}!"):
        return None
    root = repo_root.resolve()
    try:
        candidate = (root / canonical).resolve()
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    try:
        return candidate if candidate.is_file() else None
    except OSError:
        return None


def repository_evidence_errors(
    values: Any,
    repo_root: Path,
    *,
    label: str = "evidence",
    require_line: bool = False,
) -> list[str]:
    """Validate contained regular-file evidence and optional one-based lines."""
    errors: list[str] = []
    line_counts: dict[Path, int] = {}
    rows = values if isinstance(values, list) else []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"{label}[{index}] is not an evidence object")
            continue
        relative = row.get("file")
        candidate = _regular_repository_file(repo_root, relative) if isinstance(relative, str) else None
        if candidate is None:
            errors.append(f"{label}[{index}] names a missing or unsafe file: {relative!r}")
            continue
        line = row.get("line")
        if line is None:
            if require_line:
                errors.append(f"{label}[{index}] has no line number")
            continue
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            errors.append(f"{label}[{index}] has an invalid line number: {line!r}")
            continue
        if candidate not in line_counts:
            try:
                with candidate.open("r", encoding="utf-8", errors="ignore") as handle:
                    line_counts[candidate] = sum(1 for _ in handle)
            except OSError:
                errors.append(f"{label}[{index}] cannot read {relative!r}")
                continue
        line_count = line_counts[candidate]
        if line > line_count:
            errors.append(f"{label}[{index}] line {line} exceeds {relative!r} ({line_count} lines)")
    return errors


def repository_path_errors(fragment_type: str, data: Any, repo_root: Path) -> list[str]:
    """Validate repository-backed paths that JSON Schema cannot resolve."""
    try:
        root = repo_root.resolve()
    except (OSError, RuntimeError) as exc:
        return [f"cannot resolve repository root {repo_root}: {exc}"]
    if not root.is_dir():
        return [f"repository root is not a directory: {repo_root}"]

    errors: list[str] = []
    if fragment_type == "components":
        components = data.get("components", []) if isinstance(data, dict) else []
        for component in components if isinstance(components, list) else []:
            if not isinstance(component, dict):
                continue
            component_id = str(component.get("id") or "<unknown>")
            errors.extend(_tier_contradiction_errors(component, component_id))
            paths = component.get("paths", [])
            for raw in paths if isinstance(paths, list) else []:
                canonical = _safe_repository_relative(raw)
                if canonical is None:
                    errors.append(f"component {component_id} has an unsafe or non-canonical path/glob: {raw!r}")
                elif not _repository_pattern_matches(root, canonical):
                    errors.append(f"component {component_id} path/glob matches no repository entry: {canonical!r}")
    elif fragment_type == "data-flows":
        flows = data.get("data_flows", []) if isinstance(data, dict) else []
        for flow in flows if isinstance(flows, list) else []:
            if not isinstance(flow, dict):
                continue
            flow_id = str(flow.get("id") or "<unknown>")
            evidence = flow.get("evidence", [])
            errors.extend(repository_evidence_errors(evidence, root, label=f"data flow {flow_id} evidence"))
    return errors


# Template engines that render on the SERVER. The browser receives their
# output, never the engine, so a component built on one belongs to the
# application tier. Deliberately excludes anything that also runs client-side
# (handlebars, mustache) and SSR frameworks that genuinely ship a client bundle
# (next, nuxt, remix) — a gate may not produce false positives.
_SERVER_SIDE_RENDERERS = frozenset(
    {
        "blade",
        "django-templates",
        "ejs",
        "erb",
        "facelets",
        "freemarker",
        "haml",
        "jade",
        "jinja",
        "jinja2",
        "jsf",
        "jsp",
        "mako",
        "pug",
        "razor",
        "slim",
        "smarty",
        "thymeleaf",
        "twig",
        "velocity",
    }
)


def _tier_contradiction_errors(component: dict, component_id: str) -> list[str]:
    """Reject a component whose own fields contradict its declared tier.

    `tier` is not a label. `build_stride_dispatch_manifest._is_frontend`
    returns True on `tier == "client"` before it looks at anything else, and
    that single bit adds the browser threat lens (`agents/shared/spa-threats.md`)
    and drives five further scoping decisions. A server-side template engine
    filed as `client` is therefore analysed with the wrong questions, and §2.3
    then places it in the "Untrusted Zone - Browser Client" subgraph, moving its
    findings into a trust zone they never occupied.

    The 2026-08-21 insecure-large-spring-app run shipped exactly that: a
    component carrying `framework: thymeleaf` and `description: Server-side HTML
    rendering layer using Thymeleaf templates` alongside `tier: client`. Nothing
    objected — every `tier` reference in `qa_checks.py` concerns diagram layout,
    and the output schema constrains only the enum.

    Only an unambiguous self-contradiction is an error here; a judgement call
    about where a component belongs stays the analyst's.
    """
    tier = str(component.get("tier") or "").strip().lower()
    if tier != "client":
        return []
    framework = str(component.get("framework") or "").strip().lower()
    if framework not in _SERVER_SIDE_RENDERERS:
        return []
    return [
        f"component {component_id} declares tier 'client' but framework "
        f"{framework!r} renders on the server — the browser receives its output, "
        f"not the engine. Use tier 'application', and split any genuinely "
        f"browser-side assets into their own component if they need modelling."
    ]


def _load_schema(fragment_type: str) -> dict:
    schema_name = FRAGMENT_SCHEMAS.get(fragment_type)
    if not schema_name:
        raise SystemExit(
            f"VALIDATE_FAILED: unknown fragment type {fragment_type!r}. "
            f"Known types: {', '.join(sorted(FRAGMENT_SCHEMAS))}"
        )
    schema_path = SCHEMAS_DIR / schema_name
    if not schema_path.is_file():
        raise SystemExit(f"VALIDATE_FAILED: schema file not found: {schema_path}")
    try:
        return json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"VALIDATE_FAILED: schema {schema_path} is not JSON: {e}")


def _load_fragment(path: Path) -> object:
    if not path.is_file():
        raise SystemExit(f"VALIDATE_FAILED: fragment not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(
            f"VALIDATE_FAILED: {path} is not valid JSON — the orchestrator "
            f"must emit a JSON object, not Markdown. Parse error: {e}"
        )


def validate(fragment_type: str, path: Path, *, repo_root: Path | None = None) -> int:
    schema = _load_schema(fragment_type)
    data = _load_fragment(path)
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        where = "/".join(str(p) for p in e.absolute_path) or "<root>"
        print(
            f"VALIDATE_FAILED: {path.name} ({fragment_type}) — schema violation at {where}: {e.message}",
            file=sys.stderr,
        )
        return 1
    if repo_root is not None:
        errors = repository_path_errors(fragment_type, data, repo_root)
        if errors:
            for error in errors:
                print(f"VALIDATE_FAILED: {path.name} ({fragment_type}) — {error}", file=sys.stderr)
            return 1
    print(f"VALIDATE_OK: {path.name} matches {fragment_type}")
    return 0


def _fragment_type_for_file(path: Path) -> str | None:
    """Identify the fragment type for a .json file in .fragments/.

    Uses the canonical filename map first; falls back to schema-stem matching.
    Returns None when the file is not a known JSON data fragment (e.g. prose .md,
    or an unrecognized json sidecar).
    """
    name = path.name
    for ftype, fname in _FRAGMENT_FILENAMES.items():
        if name == fname:
            return ftype
    # Fallback: strip ".json" and check if the stem matches a schema name.
    stem = name.removesuffix(".json")
    return _STEM_TO_TYPE.get(stem)


def run_pre_render_gate(
    output_dir: Path,
    emit_json: bool = False,
    write_repair_plan: bool = False,
) -> int:
    """Validate fragment presence + schema under output_dir/.fragments/ before
    the renderer runs.  Writes a .pre-render-report.json summary to output_dir.

    Returns 0 when all required fragments are present and schema-valid;
    1 when any fragment is missing or fails schema validation.

    Required fragment set (unconditional — they exist on every legitimate
    compose_threat_model.py run):

        ms-verdict.json
        system-overview.md
        architecture-diagrams.md
        attack-walkthroughs.md
        assets.md
        attack-surface.md
        security-architecture.md

    Missing `.fragments/` directory or absent required fragments count as a
    hard failure — the only way they can disappear mid-run is if the
    orchestrator took the inline-shortcut and bypassed compose_threat_model.py
    entirely, which is a policy violation. The legacy behaviour (skip when
    `.fragments/` absent) let that failure mode slip through Phase 11 silently.
    """
    # Unconditional fragment set — mirrors qa_checks.REQUIRED_FRAGMENTS.
    # Kept as a local tuple to avoid a circular import between the two
    # scripts (both are run standalone from the skill layer).
    required_fragments = (
        "ms-verdict.json",
        "system-overview.md",
        "architecture-diagrams.md",
        "attack-walkthroughs.md",
        "assets.md",
        "attack-surface.md",
        "security-architecture.md",
    )

    fragments_dir = output_dir / ".fragments"
    report: dict = {
        "passed": [],
        "failed": [],
        "missing_required": [],
        "skipped": [],
    }

    if not fragments_dir.is_dir():
        report["error"] = (
            f".fragments/ directory not found under {output_dir} — the "
            "orchestrator did not go through the fragment pipeline. "
            "Re-run Phase 8-11 with compose_threat_model.py; direct Write "
            "of threat-model.md is a policy violation."
        )
        report["missing_required"] = list(required_fragments)
        _write_report(output_dir, report)
        if write_repair_plan:
            _write_repair_plan(output_dir, report)
        if emit_json:
            print(json.dumps(report, indent=2))
        else:
            print(
                "PRE_RENDER_GATE: .fragments/ not found — hard fail. Orchestrator bypassed compose_threat_model.py.",
                file=sys.stderr,
            )
        return 1

    # Apply the same slug -> C-NN repair compose_threat_model performs before it
    # validates. Without it this gate is STRICTER than the composer it guards:
    # the renderer echoes the slug component ids it read from threat-model.yaml,
    # compose rewrites them and succeeds, but this gate — running first — failed
    # hard and consumed both repair retries (2026-08-22). Shared implementation
    # in _ms_component_refs so the two can no longer drift apart.
    _normalize_ms_component_refs(output_dir, fragments_dir)

    # Check required fragment presence before schema validation so a missing
    # file is reported as "missing_required" instead of an invalid file.
    present = {p.name for p in fragments_dir.iterdir() if p.is_file()}
    report["missing_required"] = [name for name in required_fragments if name not in present]

    for path in sorted(fragments_dir.glob("*.json")):
        ftype = _fragment_type_for_file(path)
        if ftype is None:
            report["skipped"].append(path.name)
            continue

        schema_name = FRAGMENT_SCHEMAS[ftype]
        schema_path = SCHEMAS_DIR / schema_name
        if not schema_path.is_file():
            report["skipped"].append(f"{path.name} (schema {schema_name} not found)")
            continue

        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            report["failed"].append({"file": path.name, "type": ftype, "error": str(e)})
            continue

        try:
            jsonschema.validate(instance=data, schema=schema)
            report["passed"].append(path.name)
        except jsonschema.ValidationError as e:
            where = "/".join(str(p) for p in e.absolute_path) or "<root>"
            report["failed"].append(
                {
                    "file": path.name,
                    "type": ftype,
                    "error": f"schema violation at {where}: {e.message}",
                }
            )

    _write_report(output_dir, report)

    failed = len(report["failed"])
    missing = len(report["missing_required"])
    passed = len(report["passed"])
    skipped = len(report["skipped"])

    if write_repair_plan and (failed or missing):
        _write_repair_plan(output_dir, report)

    if emit_json:
        print(json.dumps(report, indent=2))
    elif failed or missing:
        if missing:
            print(
                f"PRE_RENDER_GATE: {missing} required fragment(s) missing — "
                f"passed={passed} failed={failed} skipped={skipped}",
                file=sys.stderr,
            )
            for name in report["missing_required"]:
                print(f"  MISSING {name}", file=sys.stderr)
        if failed:
            print(
                f"PRE_RENDER_GATE: {failed} fragment(s) failed schema — "
                f"passed={passed} missing={missing} skipped={skipped}",
                file=sys.stderr,
            )
            for entry in report["failed"]:
                print(f"  FAILED {entry['file']} ({entry['type']}): {entry['error']}", file=sys.stderr)
    else:
        print(f"PRE_RENDER_GATE: all {passed} fragment(s) valid (skipped={skipped})")

    return 1 if (failed or missing) else 0


def _write_report(output_dir: Path, report: dict) -> None:
    try:
        atomic_write_json(
            output_dir / ".pre-render-report.json",
            report,
            indent=2,
            sort_keys=False,
        )
    except OSError:
        pass  # non-fatal — the gate result is printed to stderr regardless


def _write_repair_plan(output_dir: Path, report: dict) -> None:
    """Emit the pre-render repair plan so a gate failure is directly actionable
    instead of merely described.

    Writes `.pre-render-repair-plan.json` — the artifact `compose_threat_model.py`
    already emits for the same purpose one step later. Sharing the path rather
    than adding a second name means every existing consumer applies unchanged:
    the secarch/ms/threat renderers read it as their repair shortcut, compose
    deletes it after a successful render, `runtime_cleanup.py` reaps it, and
    `rebuild-wipe` clears it. It also shares compose's `attempt` counter, so the
    three-attempt cap counts both producers instead of each resetting the other.

    Only `failed[]` — schema violations of LLM-authored JSON fragments —
    becomes a repair action. A `missing_required` entry is deliberately NOT
    handed to a repair agent: that set is dominated by deterministic fragments
    `pregenerate_fragments.py` owns, and letting an LLM hand-author them would
    bypass their generator. That case emits an `actionable: false` plan, which
    the fixer answers with `REPAIR_SKIPPED` and which leaves the decision to
    the Stage-3 gates that already own the required-set check.
    """
    failed = report.get("failed") or []
    missing = report.get("missing_required") or []
    plan_path = output_dir / ".pre-render-repair-plan.json"
    prior_attempts = 0
    try:
        prior_attempts = int(json.loads(plan_path.read_text(encoding="utf-8")).get("attempt", 0) or 0)
    except (OSError, ValueError, TypeError, AttributeError):
        prior_attempts = 0
    attempt = prior_attempts + 1
    actions = [
        {
            "raw_issue": f"{entry['file']} ({entry['type']}): {entry['error']}",
            "type": "fragment_schema_violation",
            "section_id": "fragments",
            "fragments_to_rewrite": [f".fragments/{entry['file']}"],
            "remediation": (
                f"Re-author `.fragments/{entry['file']}` so it validates against "
                f"`schemas/fragments/{FRAGMENT_SCHEMAS[entry['type']]}`. The violation carries "
                "its exact JSON path — correct that field only and preserve every other value. "
                "The schema's own length and enum limits are authoritative over the prose "
                "examples in the authoring contract."
            ),
            "severity": "blocking",
        }
        for entry in failed
        if entry.get("type") in FRAGMENT_SCHEMAS
    ]
    exhausted = attempt > _PRE_RENDER_REPAIR_MAX_ATTEMPTS
    if exhausted:
        status = "exhausted"
    elif actions:
        status = "fail"
    else:
        status = "manual_review"
    plan: dict[str, Any] = {
        "output_dir": str(output_dir),
        "source": "validate_fragment.py pre-render-gate",
        "status": status,
        "actionable": bool(actions) and not exhausted,
        "attempt": attempt,
        "issue_count": len(failed) + len(missing),
        "action_count": len(actions),
        "actions": actions,
        "re_render_command": (
            "python3 $CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py --output-dir $OUTPUT_DIR --strict"
        ),
    }
    if not actions:
        plan["manual_review_items"] = [{"issue": f"required fragment missing: {name}"} for name in missing]
    try:
        atomic_write_json(
            plan_path,
            plan,
            indent=2,
            sort_keys=False,
        )
    except OSError:
        pass  # non-fatal — the gate exit code still blocks the caller


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    # Route by first token: "pre-render-gate" dispatches to the bulk gate;
    # anything else falls through to the legacy single-fragment interface.
    if args and args[0] == "pre-render-gate":
        gate_p = argparse.ArgumentParser(
            prog="validate_fragment.py pre-render-gate",
            description="Bulk-validate all known JSON fragments in "
            "<output_dir>/.fragments/. Writes .pre-render-report.json "
            "and exits 1 if any fragment fails.",
        )
        gate_p.add_argument("output_dir", type=Path, help="Path to $OUTPUT_DIR (must contain .fragments/).")
        gate_p.add_argument("--json", action="store_true", help="Print structured JSON report to stdout.")
        gate_p.add_argument(
            "--write-repair-plan",
            action="store_true",
            help="On failure also write .pre-render-repair-plan.json for the repair agents.",
        )
        gargs = gate_p.parse_args(args[1:])
        if not gargs.output_dir.is_dir():
            print(f"error: output_dir not a directory: {gargs.output_dir}", file=sys.stderr)
            return 2
        return run_pre_render_gate(
            gargs.output_dir,
            emit_json=gargs.json,
            write_repair_plan=gargs.write_repair_plan,
        )

    # Legacy positional mode — original single-fragment interface:
    #   validate_fragment.py <fragment_type> <path>
    legacy = argparse.ArgumentParser(
        prog="validate_fragment.py",
        description="Validate an LLM-authored data fragment against its "
        "JSON schema. Used as a hard gate before the renderer.",
    )
    legacy.add_argument(
        "fragment_type",
        choices=sorted(FRAGMENT_SCHEMAS),
        help="Fragment type (maps to a schema in schemas/fragments/).",
    )
    legacy.add_argument("path", type=Path, help="Path to the fragment file.")
    legacy.add_argument(
        "--repo-root",
        type=Path,
        help="Also validate repository-backed component paths or data-flow evidence.",
    )
    largs = legacy.parse_args(args)
    return validate(largs.fragment_type, largs.path, repo_root=largs.repo_root)


if __name__ == "__main__":
    sys.exit(main())
