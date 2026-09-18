"""The self-check must reject exactly what the deterministic gate rejects.

A relational invariant — one that relates two arrays of a fragment to each
other, or a fragment to its companion input — cannot be expressed in JSON
Schema. Before `validate_fragment.fragment_invariant_errors` existed, such rules
lived privately inside the deterministic consumer. The consequence was observed
on 2026-08-29: `.trust-boundary-candidates.json` named a candidate in a
disposition that did not itself declare coverage of that signal,
`validate_fragment` printed VALIDATE_OK, the authoring agent reported success,
and the run died in `promote_candidates` after four agents had already been paid
for.

The property that prevents a repeat is not "the rules are correct" but:

    what the gate rejects, the self-check rejects too

Each mutation below is a rule an LLM can plausibly get wrong. The test drives
every one through BOTH paths and requires them to agree. Adding a new invariant
means adding a mutation here; it will fail until the rule lives in the shared
registry — that is, until the authoring agent can see it.
"""

from __future__ import annotations

import json
import re
import sys
from copy import deepcopy
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_trust_boundary_assessment_input as boundary_input  # noqa: E402
import finalize_component_inventory as finalizer  # noqa: E402
import orchestration_controller as controller  # noqa: E402
import prepare_trust_boundary_context as prep  # noqa: E402
from validate_fragment import fragment_invariant_errors  # noqa: E402
from validate_intermediate import _check_export_trace_invariants  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "fragment_invariants"


# --------------------------------------------------------------------------
# Mutations — one per relational rule, named after the rule it violates.
# Each takes a valid document and returns an invalid one.
# --------------------------------------------------------------------------


def _mutual_coverage(doc: dict) -> dict:
    """A disposition names a candidate that does not declare the signal.

    The 2026-08-29 shape verbatim: modelling the crossing as a path of hops and
    naming every hop, while each candidate declares only its own signal.
    """
    covered = {c["candidate_key"]: c["covered_signal_ids"] for c in doc["candidates"]}
    for disposition in doc["dispositions"]:
        outsider = next(
            (key for key, signals in covered.items() if disposition["signal_id"] not in signals),
            None,
        )
        if outsider is not None:
            disposition["candidate_keys"] = [*disposition["candidate_keys"], outsider]
            return doc
    raise AssertionError("fixture offers no candidate that fails to cover a signal")


def _nonboundary_has_candidates(doc: dict) -> dict:
    """A non-`boundary` disposition keeps its candidate references."""
    for disposition in doc["dispositions"]:
        if disposition["disposition"] == "boundary" and disposition["candidate_keys"]:
            disposition["disposition"] = "same-trust"
            return doc
    raise AssertionError("fixture has no boundary disposition to flip")


def _extra_disposition(doc: dict) -> dict:
    """A disposition for a signal the assessment input never marked mandatory."""
    doc["dispositions"].append(
        {
            "signal_id": "signal-not-in-the-assessment-input",
            "disposition": "same-trust",
            "candidate_keys": [],
            "rationale": "An observation the analyst added on its own.",
        }
    )
    return doc


def _duplicate_candidate_key(doc: dict) -> dict:
    """Two candidates share one key."""
    doc["candidates"].append(deepcopy(doc["candidates"][0]))
    return doc


def _unreferenced_candidate(doc: dict) -> dict:
    """A candidate no boundary disposition points at."""
    orphan = deepcopy(doc["candidates"][0])
    orphan["candidate_key"] = "candidate-orphan"
    doc["candidates"].append(orphan)
    return doc


def _boundary_without_candidate(doc: dict) -> dict:
    """A `boundary` disposition that names nothing."""
    for disposition in doc["dispositions"]:
        if disposition["disposition"] == "boundary":
            disposition["candidate_keys"] = []
            return doc
    raise AssertionError("fixture has no boundary disposition to empty")


def _materialize_evidence(doc: dict, repo_root: Path) -> None:
    """Create the files the fixture cites.

    Promotion reads cited evidence to re-check crossing direction and to upgrade
    ingress confidence, and drops a citation it cannot read. Without the files
    the gate would reject a valid fixture for a reason that has nothing to do
    with the invariants under test.
    """
    longest: dict[str, int] = {}
    for candidate in doc["candidates"]:
        for item in candidate.get("evidence", []):
            name = item["file"]
            longest[name] = max(longest.get(name, 1), int(item.get("line") or 1))
    for name, lines in longest.items():
        path = repo_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// fixture evidence\n" * lines, encoding="utf-8")


def _duplicate_disposition(doc: dict) -> dict:
    """Two dispositions for one signal."""
    doc["dispositions"].append(deepcopy(doc["dispositions"][0]))
    return doc


def _unknown_endpoint(doc: dict) -> dict:
    """A candidate crosses to a component the assessment input does not know."""
    doc["candidates"][0]["to"] = "component-that-does-not-exist"
    return doc


def _covers_nothing(doc: dict) -> dict:
    """A candidate that accounts for neither a signal nor a flow."""
    doc["candidates"][0]["covered_signal_ids"] = []
    doc["candidates"][0]["covered_flow_ids"] = []
    return doc


def _unknown_signal(doc: dict) -> dict:
    """A candidate claims a signal the assessment input never raised."""
    doc["candidates"][0]["covered_signal_ids"] = [
        *doc["candidates"][0]["covered_signal_ids"],
        "signal-that-the-input-never-raised",
    ]
    return doc


def _gate_rejects_trust_boundary_candidates(doc: dict, context: dict, tmp_path: Path) -> bool:
    """Run the deterministic gate the way the controller runs it."""
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    _materialize_evidence(doc, tmp_path)
    candidates_path = out / ".trust-boundary-candidates.json"
    assessment_path = out / ".trust-boundary-assessment-input.json"
    candidates_path.write_text(json.dumps(doc), encoding="utf-8")
    assessment_path.write_text(json.dumps(context), encoding="utf-8")
    try:
        prep.promote_candidates(
            repo_root=tmp_path,
            output_dir=out,
            candidates_path=candidates_path,
            assessment_input_path=assessment_path,
            prior_model=None,
        )
    except ValueError:
        return True
    return False


def _interaction_targets_server(doc: dict) -> dict:
    """A human interaction points at a server instead of the client the human uses.

    The 2026-09-18 shape: "browser fetches the app bundle" modelled as
    `interaction: true` from the user straight to the backend. The self-check
    had no component tiers, printed VALIDATE_OK, and the architecture gate
    aborted the run after an 18-minute analyst dispatch.
    """
    for flow in doc["data_flows"]:
        if flow.get("interaction"):
            flow["to"] = "api"
            return doc
    raise AssertionError("fixture has no interaction flow to retarget")


def _flow_unknown_endpoint(doc: dict) -> dict:
    """A flow names a component the inventory does not contain."""
    doc["data_flows"][1]["to"] = "component-that-does-not-exist"
    return doc


def _self_flow(doc: dict) -> dict:
    """A flow starts and ends at the same component."""
    doc["data_flows"][2]["to"] = doc["data_flows"][2]["from"]
    return doc


def _duplicate_flow_id(doc: dict) -> dict:
    """Two flows share one ID."""
    doc["data_flows"][2]["id"] = doc["data_flows"][1]["id"]
    return doc


def _asset_unknown_component(doc: dict) -> dict:
    """An asset location names a component the inventory does not contain."""
    doc["assets"][0]["component_refs"][0]["component_id"] = "component-that-does-not-exist"
    return doc


def _cited_lines(node: object, found: dict[str, int]) -> dict[str, int]:
    if isinstance(node, dict):
        if isinstance(node.get("file"), str) and isinstance(node.get("line"), int):
            found[node["file"]] = max(found.get(node["file"], 1), node["line"])
        for value in node.values():
            _cited_lines(value, found)
    elif isinstance(node, list):
        for value in node:
            _cited_lines(value, found)
    return found


def _materialize_repository(components: list[dict], doc: dict, repo_root: Path) -> None:
    """Create each component directory and every cited file with code lines.

    Finalization requires every component glob to match an entry, and flow
    evidence must name an existing line.
    """
    for component in components:
        directory = repo_root / "src" / component["id"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "component.ts").write_text("export const component = true\n", encoding="utf-8")
    for name, lines in _cited_lines(doc, {}).items():
        path = repo_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("export const value = 1;\n" * lines, encoding="utf-8")


def _gate_rejects_data_flows(doc: dict, context: dict, tmp_path: Path) -> bool:
    """Run the Stage-1a gate steps that judge data flows, in the controller's order."""
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    _materialize_repository(context["components"], doc, repo)
    (out / ".components.json").write_text(json.dumps(context), encoding="utf-8")
    (out / ".data-flows.json").write_text(json.dumps(doc), encoding="utf-8")
    try:
        finalizer.finalize(repo, out)
        controller._bind_finalized_component_fingerprint(out, repo)
        boundary_input.build(repo, out, "standard")
    except (ValueError, controller.ControllerError):
        return True
    return False


def _gate_rejects_assets(doc: dict, context: dict, tmp_path: Path) -> bool:
    """The final-export trace check, the first gate that relates assets to components."""
    return bool(_check_export_trace_invariants({"assets": doc["assets"], "components": context["components"]}))


FRAGMENTS = {
    "trust-boundary-candidates": {
        "gate": _gate_rejects_trust_boundary_candidates,
        "mutations": {
            "mutual-coverage": _mutual_coverage,
            "nonboundary-has-candidates": _nonboundary_has_candidates,
            "extra-disposition": _extra_disposition,
            "duplicate-candidate-key": _duplicate_candidate_key,
            "unreferenced-candidate": _unreferenced_candidate,
            "boundary-without-candidate": _boundary_without_candidate,
            "duplicate-disposition": _duplicate_disposition,
            "unknown-endpoint": _unknown_endpoint,
            "covers-nothing": _covers_nothing,
            "unknown-signal": _unknown_signal,
        },
    },
    "data-flows": {
        "gate": _gate_rejects_data_flows,
        "mutations": {
            "interaction-targets-server": _interaction_targets_server,
            "unknown-endpoint": _flow_unknown_endpoint,
            "self-flow": _self_flow,
            "duplicate-flow-id": _duplicate_flow_id,
        },
    },
    "assets": {
        "gate": _gate_rejects_assets,
        "mutations": {"unknown-component": _asset_unknown_component},
    },
}


def _load(fragment_type: str) -> tuple[dict, dict]:
    base = FIXTURES / fragment_type
    context_path = base / "context.json"
    document = json.loads((base / "valid.json").read_text(encoding="utf-8"))
    context = json.loads(context_path.read_text(encoding="utf-8")) if context_path.is_file() else None
    return document, context


def _cases() -> list[tuple[str, str]]:
    return [(ftype, name) for ftype, spec in FRAGMENTS.items() for name in spec["mutations"]]


@pytest.mark.parametrize("fragment_type", sorted(FRAGMENTS))
def test_valid_fixture_passes_both_paths(fragment_type: str, tmp_path: Path):
    document, context = _load(fragment_type)

    assert fragment_invariant_errors(fragment_type, document, context=context) == []
    assert not FRAGMENTS[fragment_type]["gate"](document, context, tmp_path), (
        f"the {fragment_type} fixture is supposed to be valid but the gate rejected it"
    )


@pytest.mark.parametrize(("fragment_type", "mutation"), _cases())
def test_self_check_rejects_what_the_gate_rejects(fragment_type: str, mutation: str, tmp_path: Path):
    document, context = _load(fragment_type)
    spec = FRAGMENTS[fragment_type]
    broken = spec["mutations"][mutation](deepcopy(document))

    gate_rejects = spec["gate"](broken, context, tmp_path)
    self_check_rejects = bool(fragment_invariant_errors(fragment_type, broken, context=context))

    assert gate_rejects, (
        f"{fragment_type}/{mutation} no longer reaches a gate rejection — either the rule was "
        f"dropped or the mutation stopped violating it; fix the mutation, do not delete the case"
    )
    assert self_check_rejects, (
        f"{fragment_type}/{mutation} is rejected by the deterministic gate but accepted by "
        f"validate_fragment. The authoring agent cannot see this rule and will lose a whole run "
        f"to it. Move the check into fragment_invariant_errors instead of enforcing it only in "
        f"the consumer."
    )


def test_every_self_check_passes_the_context_its_rules_need():
    """A self-check without `--context` skips the rules that need it and passes silently."""
    needs_context = {ftype for ftype in FRAGMENTS if (FIXTURES / ftype / "context.json").is_file()}
    checked: set[str] = set()
    for prompt in sorted((REPO_ROOT / "agents").glob("*.md")):
        text = prompt.read_text(encoding="utf-8").replace("\\\n", " ")
        for line in text.splitlines():
            match = re.search(r"validate_fragment\.py\"?\s+([a-z-]+)\s", line)
            if match and match.group(1) in needs_context:
                checked.add(match.group(1))
                assert "--context" in line, f"{prompt.name}: the {match.group(1)} self-check omits --context"
    assert checked == needs_context
