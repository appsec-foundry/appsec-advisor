"""Scoped adapters for semantic stages owned by the assessment controller.

These functions own contracts, source checks and read-only projections. They
do not sequence stages, dispatch models, choose roles or publish reports.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from runtime.assessment_host import ExchangeError, Rejection
from shared.assessment_sources import source_key, source_rows
from validators.validate_assessment_architecture import validate_source

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = (
    "multi-repo-architecture.schema.json",
    "multi-repo-stride.schema.json",
    "multi-repo-controls.schema.json",
    "multi-repo-evidence-review.schema.json",
    "stride.schema.yaml",
    "threat-model.output.schema.yaml",
    "fragments/components.schema.json",
    "fragments/components-v2.schema.json",
    "fragments/data-flows-v2.schema.json",
    "fragments/assets.schema.json",
    "fragments/security-controls.schema.json",
    "threats-merged-v2.schema.json",
    "threats-merged.schema.yaml",
    "trust-boundary-assessment-input-v2.schema.json",
    "trust-boundary-assessment-input.schema.json",
    "fragments/trust-boundary-candidates-v2.schema.json",
    "fragments/trust-boundary-candidates.schema.json",
    "fragments/trust-boundaries-v3.schema.json",
    "fragments/trust-boundaries.schema.json",
    "trust-boundary-coverage-v2.schema.json",
    "trust-boundary-coverage.schema.json",
)
STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


def contract(name: str) -> dict:
    return copy.deepcopy(_contract(name))


def job_share(schema: dict, combined: str, *, jobs: int, used: dict[str, int] | None = None) -> dict:
    """A job schema whose top-level lists fit one equal share of the combined contract's limits.

    The controller concatenates the lists of several jobs into one document
    that the `combined` contract bounds. Each job alone may fit its own schema
    while the concatenation exceeds the combined limit, and no job could repair
    that afterwards. Bounding every job to its share instead turns an excess
    into contract feedback inside that job's exchange. `used` counts entries
    the controller already placed in a combined list.

    The share is rounded up, so while capacity remains every job may return at
    least one entry; each job's share never exceeds the capacity left, so the
    concatenation still fits. A floor share gave every early job of a large
    system zero entries, and a job that had to report one could not.
    """
    result = copy.deepcopy(schema)
    for field, spec in contract(combined).get("properties", {}).items():
        own = result.get("properties", {}).get(field)
        if not isinstance(own, dict) or not isinstance(spec, dict) or "maxItems" not in spec:
            continue
        share = -(-max(0, spec["maxItems"] - (used or {}).get(field, 0)) // max(1, jobs))
        own["maxItems"] = min(own.get("maxItems", share), share)
    return result


@lru_cache(maxsize=len(CONTRACTS))
def _contract(name: str) -> dict:
    """Resolve only known plugin contracts to a tool-host-compatible schema."""
    if name not in CONTRACTS:
        raise ExchangeError("Unknown multi-repository stage contract")
    documents = {n: yaml.safe_load((ROOT / "schemas" / n).read_text(encoding="utf-8")) for n in CONTRACTS}
    by_id = {document["$id"]: document for document in documents.values()}

    def expand(value, document, depth=0):
        if depth > 64:
            raise ExchangeError("Stage schema exceeds its reference-depth limit")
        if isinstance(value, list):
            return [expand(row, document, depth + 1) for row in value]
        if not isinstance(value, dict):
            return value
        if "$ref" in value:
            uri, _, fragment = value["$ref"].partition("#")
            target = by_id.get(uri) if uri else document
            if target is None:
                raise ExchangeError("Stage schema refers to an unavailable plugin contract")
            resource = target
            if fragment:
                if not fragment.startswith("/"):
                    raise ExchangeError("Stage schema uses an unsupported reference")
                for segment in fragment[1:].split("/"):
                    key = segment.replace("~1", "/").replace("~0", "~")
                    try:
                        resource = resource[int(key)] if isinstance(resource, list) else resource[key]
                    except (KeyError, IndexError, ValueError, TypeError):
                        raise ExchangeError("Stage schema contains an invalid local reference") from None
            resolved = expand(resource, target, depth + 1)
            siblings = expand({k: v for k, v in value.items() if k != "$ref"}, document, depth + 1)
            return {"allOf": [resolved, siblings]} if siblings else resolved
        return {k: expand(v, document, depth + 1) for k, v in value.items() if k not in ("$id", "$defs")}

    result = expand(documents[name], documents[name])
    Draft202012Validator.check_schema(result)
    return result


def source_selection(components: list[dict]) -> frozenset:
    return frozenset((row["repository_id"], row["path"]) for c in components for row in c["paths"])


def analysis_targets(scope, component: dict, architecture: dict, scanned: list[dict]) -> list[dict]:
    """Source-backed surfaces to examine, independent of finding counts or repository names.

    These are investigation leads, not vulnerabilities. Full route inventories
    and outbound call sites supplement authored topology, so a missing flow
    cannot also hide the call from STRIDE. Sources stay inside the finalized
    component; a scanner result never authorizes reading an unrelated file.
    """
    own = source_selection([component])
    repos = {r.repository_id: r for r in scope.repositories}
    targets = {}

    def add(evidence, kind):
        rid, path = evidence.get("repository_id"), evidence.get("file")
        if (rid, path) not in own:
            return
        line = evidence.get("line") or 1
        source = {
            "repository_id": rid,
            "file": path,
            "line": line,
            "sha256": hashlib.sha256(repos[rid].files[path]).hexdigest(),
        }
        validate_source(scope, source, path_key="file")
        key = (rid, path, line)
        if key not in targets:
            identifier = "surface-" + hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16]
            targets[key] = {"local_id": identifier, "evidence": source, "kinds": []}
        if kind not in targets[key]["kinds"]:
            targets[key]["kinds"].append(kind)

    for rid, inventory in architecture.get("route_inventories", {}).items():
        for route in inventory.get("routes", []):
            add({"repository_id": rid, "file": route.get("handler_file"), "line": route.get("handler_line")}, "route")
    for rid, destinations in architecture.get("egress_inventories", {}).items():
        for destination in destinations:
            for evidence in destination["evidence"]:
                add({**evidence, "repository_id": rid}, "outbound-call")
    for evidence in source_rows(component):
        add(evidence, "component-capability")
    for flow in architecture["data_flows"]["data_flows"]:
        for evidence in source_rows(flow):
            add(evidence, "data-flow")
    for finding in scanned:
        add(finding["evidence"], "scanner-lead")
    # Files without a detected surface still require source investigation;
    # neither a known route elsewhere nor an unsupported stack hides them.
    # A first-line lead does not claim to enumerate all mechanisms in a file.
    covered_files = {(rid, path) for rid, path, _ in targets}
    for rid, path in sorted(own - covered_files):
        if repos[rid].files[path].splitlines():
            add({"repository_id": rid, "file": path, "line": 1}, "component-source")
    if len(targets) > 20_000:
        raise ExchangeError("Component investigation exceeds the source-reference limit")
    return [targets[key] for key in sorted(targets)]


def known_llm_patterns(scope, component: dict) -> str:
    """Apply the single-repository LLM seed rule to the component's frozen sources.

    A strong AI-integration signal in an owned source file marks an LLM surface
    even when the component's name and authored fields do not; the summary then
    carries every owned signal kind for the agentic and retrieval lenses. Every
    owned file is read, so no repository-wide excerpt cap decides the result.
    The summary selects lenses only; it never establishes a capability or finding.
    """
    from orchestrator.build_stride_dispatch_manifest import _ai_signal_summary

    signals = _owned_ai_signals(scope, component)
    if not any(signal["strength"] == "strong" for signal in signals):
        return ""
    return _ai_signal_summary(signals)


def _owned_ai_signals(scope, component: dict) -> list[dict]:
    from analyzers.recon_patterns import cat13_line_signals
    from orchestrator.build_stride_dispatch_manifest import _is_ai_source_signal

    repos = {r.repository_id: r for r in scope.repositories}
    signals = []
    for rid, path in sorted(source_selection([component])):
        for number, line in enumerate(repos[rid].files[path].decode("utf-8", "replace").splitlines(), 1):
            for kind, strength in cat13_line_signals(line):
                signal = {
                    "subcategory": kind,
                    "strength": strength,
                    "repository_id": rid,
                    "file": path,
                    "line": number,
                    "text": line,
                }
                if _is_ai_source_signal(signal):
                    signals.append(signal)
    return signals


def model_integration_leads(scope, components: list[dict]) -> list[dict]:
    """Strong model-SDK or provider lines per component, as leads for the architecture job.

    A lead says the source names a model integration, not that it calls one or
    where the provider runs; the architecture job decides after reading it.
    Only lines the service-role evidence rule accepts are offered: an import,
    comment or blank line names the SDK but cannot evidence the call, and a
    lead on it invites a citation that rule rejects.
    """
    from validators.validate_fragment import _cited_line_problem

    repos = {r.repository_id: r for r in scope.repositories}
    leads = []
    for component in components:
        strong = []
        for row in _owned_ai_signals(scope, component):
            if row["strength"] != "strong":
                continue
            problem = _cited_line_problem(row["text"], allow_imports=False)
            if problem is None:
                strong.append(row)
            elif problem == "an import or dependency declaration":
                # An SDK is usually named only where it is imported; its call
                # carries the imported binding, not the provider's name.
                lines = repos[row["repository_id"]].files[row["file"]].decode("utf-8", "replace").splitlines()
                strong.extend(
                    {**row, "line": number}
                    for number in _binding_calls(lines, row["text"])
                    if _cited_line_problem(lines[number - 1], allow_imports=False) is None
                )
        if strong:
            evidence = list(dict.fromkeys((row["file"], row["line"]) for row in strong))[:8]
            leads.append(
                {
                    "component_id": component["id"],
                    "evidence": [{"file": file, "line": line} for file, line in evidence],
                }
            )
    return leads


_IMPORTED_NAMES = (
    # JS/TS: default, namespace and named imports; CommonJS require.
    re.compile(r"^import\s+(?:type\s+)?(\w+)?\s*,?\s*(?:\*\s+as\s+(\w+))?\s*(?:\{([^}]*)\})?\s*from\s"),
    re.compile(r"^(?:const|let|var)\s+(?:(\w+)|\{([^}]*)\})\s*=\s*(?:await\s+)?(?:require|import)\s*\("),
    # Python: `from x import a, b as c` and `import x as y`.
    re.compile(r"^from\s+\S+\s+import\s+\(?([^)#]*)"),
    re.compile(r"^import\s+([\w.]+(?:\s+as\s+\w+)?)\s*$"),
)


def _binding_calls(lines: list[str], import_line: str, limit: int = 4) -> list[int]:
    """One-based lines that call a binding the import line introduces, first occurrences first."""
    names = set()
    for pattern in _IMPORTED_NAMES:
        match = pattern.match(import_line.strip())
        if not match:
            continue
        for group in match.groups():
            for part in (group or "").split(","):
                words = part.replace(" as ", " : ").replace(":", " ").split()
                if words and words[-1].isidentifier() and words[-1] != "type":
                    names.add(words[-1].split(".")[-1])
        break
    if not names:
        return []
    call = re.compile(r"(?<![\w.$])(?:new\s+)?(?:" + "|".join(map(re.escape, sorted(names))) + r")\s*(?:\(|\.\w)")
    found = []
    for number, text in enumerate(lines, 1):
        if text.strip() != import_line.strip() and call.search(text):
            found.append(number)
            if len(found) >= limit:
                break
    return found


def model_integration_gaps(leads: list[dict], flows: dict) -> list[str]:
    """Component IDs with a model-integration lead but no flow to an LLM inference service."""
    inference = {
        entity["id"]
        for entity in flows.get("external_entities", [])
        if any(role.get("role") == "llm-inference" for role in entity.get("service_roles") or [])
    }
    connected = {
        end
        for flow in flows.get("data_flows", [])
        for end, other in ((flow.get("from"), flow.get("to")), (flow.get("to"), flow.get("from")))
        if other in inference
    }
    return [lead["component_id"] for lead in leads if lead["component_id"] not in connected]


def analysis_lenses(scope, component: dict) -> tuple[list[str], str]:
    """Resolve the existing lens selector only to fixed plugin-owned policy."""
    from orchestrator.build_stride_dispatch_manifest import _stride_lens_ids

    files = {
        "llm": "shared/owasp-llm-top10.md",
        "agentic": "shared/owasp-asi-top10.md",
        "rag": "stride-lenses/rag.md",
        "mcp": "stride-lenses/mcp.md",
        "spa": "shared/spa-threats.md",
        "mobile": "stride-lenses/mobile.md",
        "supply-chain": "shared/supply-chain-patterns.md",
    }
    selected = _stride_lens_ids(component, {"known_llm_patterns": known_llm_patterns(scope, component)})
    return selected, "\n\n".join((ROOT / "agents" / files[key]).read_text(encoding="utf-8") for key in selected)


def surface_evidence_normalizer(targets):
    """Insert each target's exact anchor into a decision that cites the target's file.

    A model that read the target's file seldom copies its 64-character hash; the
    controller knows the anchor and adds it. A decision citing another file
    gains nothing, and `validate_surface_coverage` still requires the read.
    """
    anchors = {target["local_id"]: target["evidence"] for target in targets}

    def normalize(artifact):
        for row in artifact.get("surface_coverage") or []:
            anchor = anchors.get(row.get("target_id"))
            evidence = row.get("evidence")
            if anchor is None or not isinstance(evidence, list) or anchor in evidence:
                continue
            same_file = [
                index
                for index, item in enumerate(evidence)
                if isinstance(item, dict)
                and item.get("repository_id") == anchor["repository_id"]
                and item.get("file") == anchor["file"]
            ]
            if same_file:
                if len(evidence) < 4:
                    evidence.append(dict(anchor))
                else:
                    evidence[same_file[0]] = dict(anchor)
        return artifact

    normalize.version = "surface-anchor-1"
    return normalize


def unresolved_targets(artifact, targets) -> list[str]:
    """Locations of targets a job read but left unresolved (MR-11)."""
    anchors = {target["local_id"]: target["evidence"] for target in targets}
    return [
        f"{anchor['repository_id']}/{anchor['file']}:{anchor['line']}"
        for row in artifact.get("surface_coverage") or []
        if row["disposition"] == "unresolved" and (anchor := anchors.get(row["target_id"]))
    ]


def validate_surface_coverage(artifact, ranges, targets):
    """No authored disposition can substitute for actually retrieving a target.

    A target the job read may stay `unresolved` with its reason; the run names it
    as a warning (MR-11). An unread target is always rejected.
    """
    expected = {target["local_id"]: target for target in targets}
    rows = artifact.get("surface_coverage", [])
    if len(rows) != len(expected) or {row["target_id"] for row in rows} != set(expected):
        raise ExchangeError("STRIDE surface coverage must decide every supplied target exactly once")
    findings = {row["local_id"] for row in artifact["threats"]}
    errors = []
    for row in rows:
        target = expected[row["target_id"]]["evidence"]
        location = f"{target['repository_id']}/{target['file']}:{target['line']}"
        read = any(
            r["repository_id"] == target["repository_id"]
            and r["path"] == target["file"]
            and r["sha256"] == target["sha256"]
            and r["start_line"] <= target["line"] <= r["end_line"]
            for r in ranges
        )
        if not read or target not in row["evidence"]:
            errors.append("Unexamined source target: " + location)
        if not set(row["finding_ids"]) <= findings:
            errors.append("Surface coverage refers to unknown findings")
        if row["disposition"] == "not-applicable" and row["finding_ids"]:
            errors.append("An inapplicable surface cannot carry findings")
    if errors:
        raise Rejection("STRIDE investigation is incomplete", errors[:3])


def component_stride_contract(jobs: int | None) -> dict:
    """The STRIDE contract of a component analysed in `jobs` bounded jobs (MR-12).

    Each job's own contract keeps its limit of findings; the combined document
    allows that many per job, so findings that every job returned within its
    limit never fail the combination after all jobs were paid. `None` checks a
    combined document whose job count is no longer known: its parts were
    already bounded when it was combined.
    """
    schema = contract("multi-repo-stride.schema.json")
    per_job = schema["properties"]["threats"]["maxItems"]
    for spec in (
        schema["properties"]["threats"],
        schema["properties"]["coverage"]["items"]["properties"]["finding_ids"],
    ):
        if jobs is None:
            spec.pop("maxItems")
        else:
            spec["maxItems"] = per_job * max(1, jobs)
    return schema


def combine_stride_parts(parts):
    """Fold bounded jobs into the existing one-document-per-component merge input.

    Per-surface decisions remain in each job's validated artifact and receipt.
    All finding IDs and category references are rewritten together; no finding
    is discarded to fit the component contract.
    """
    if len(parts) == 1:
        return parts[0]
    result = copy.deepcopy(parts[0])
    result.pop("surface_coverage", None)
    result["threats"] = []
    for index, part in enumerate(parts, 1):
        for finding in part["threats"]:
            finding = copy.deepcopy(finding)
            # Hash the local identity instead of truncating arbitrary IDs.
            finding["local_id"] = f"part-{index}-" + hashlib.sha256(finding["local_id"].encode()).hexdigest()[:16]
            result["threats"].append(finding)
    for coverage in result["coverage"]:
        category = coverage["category"]
        ids = [f["local_id"] for f in result["threats"] if f["stride"] == category]
        inputs = [next(c for c in part["coverage"] if c["category"] == category) for part in parts]
        dispositions = {c["disposition"] for c in inputs}
        coverage.update(
            finding_ids=ids,
            disposition="finding" if ids else (next(iter(dispositions)) if len(dispositions) == 1 else "no-evidence"),
            reason="Component analysis combines the recorded decisions of all source-target jobs.",
        )
    if not Draft202012Validator(component_stride_contract(len(parts))).is_valid(result):
        raise ExchangeError("Combined STRIDE investigation exceeds its component contract; no findings were dropped")
    return result


def connection_relays(flows: list[dict]) -> dict[str, set[str]]:
    """Map each reviewed connection to its relay nodes, such as a message broker.

    A relay receives one hop of a connection and sends the next one.
    """
    senders: dict[str, set[str]] = {}
    receivers: dict[str, set[str]] = {}
    for row in flows:
        if row.get("connection_id"):
            senders.setdefault(row["connection_id"], set()).add(row["from"])
            receivers.setdefault(row["connection_id"], set()).add(row["to"])
    return {key: senders[key] & receivers.get(key, set()) for key in senders}


def scope_relays(components: list[dict], flows: list[dict], connection_ids, keep=frozenset()) -> list[dict]:
    """Limit each relay's sources to the evidence of the given connections.

    A broker's paths are the producer and consumer evidence of every topic it
    carries. Granting all of them would let one topic's job read another
    topic's repositories. Components in ``keep`` remain unchanged.
    """
    relays = set().union(*connection_relays(flows).values()) - set(keep)
    evidence = {
        (row["repository_id"], row["file"])
        for flow in flows
        if flow.get("connection_id") in connection_ids
        for row in flow.get("evidence", [])
    }
    result = []
    for component in components:
        if component["id"] in relays:
            component = copy.deepcopy(component)
            component["paths"] = [p for p in component["paths"] if (p["repository_id"], p["path"]) in evidence]
            if component["paths"]:
                component["repository_ids"] = sorted({p["repository_id"] for p in component["paths"]})
        result.append(component)
    return result


def component_neighborhood(components: dict, flows: dict, component_id: str) -> list[dict]:
    """Include only finalized incident peers, including evidenced broker hops."""
    by_id = {row["id"]: row for row in components["components"]}
    if component_id not in by_id:
        raise ExchangeError("Analysis component is outside the finalized inventory")
    ids, connections = {component_id}, set()
    for row in flows["data_flows"]:
        if component_id in (row["from"], row["to"]):
            ids.update(endpoint for endpoint in (row["from"], row["to"]) if endpoint in by_id)
            if row.get("connection_id"):
                connections.add(row["connection_id"])
    # A broker is an incident peer, not an authorization to read every tenant
    # or consumer connected to that broker. Further hops need a scoped job.
    return scope_relays([by_id[key] for key in sorted(ids)], flows["data_flows"], connections, {component_id})


def validate_retrieved_sources(scope, artifact, ranges, allowed_sources):
    """Every evidence claim must cite bytes actually delivered to this job.

    The rejection names each unretrieved citation; a stateless correction turn
    cannot otherwise tell which claim to read or remove. Context anchors invite
    such citations, so the host also serves each authorized unread anchor
    before the correction turn.
    """
    missing, anchors = [], []
    for row in source_rows(artifact):
        validate_source(scope, row, path_key="file")
        key = (row["repository_id"], row["file"])
        location = f"{row['repository_id']}/{row['file']}:{row['line']}"
        if key not in allowed_sources:
            missing.append(location + " is outside this job's sources; remove the claim")
        elif not any(
            (r["repository_id"], r["path"]) == key
            and r["sha256"] == row["sha256"]
            and r["start_line"] <= row["line"] <= r["end_line"]
            for r in ranges
        ):
            missing.append(location + " was not read; read it or remove the claim")
            anchors.append((row["repository_id"], row["file"], row["line"]))
    if missing:
        # The correction feedback is capped at 2,000 characters; name the rest by count.
        unique = list(dict.fromkeys(missing))
        shown = unique[:12] + ([f"{len(unique) - 12} more unretrieved citations"] if len(unique) > 12 else [])
        raise Rejection(
            "Analysis evidence was not retrieved by its authorized job", shown, reads=list(dict.fromkeys(anchors))
        )


def validate_identity(scope, artifact, component_fingerprint):
    if artifact["source_scope_sha256"] != scope.inventory()["scope_sha256"]:
        raise ExchangeError("Analysis artifact belongs to another source scope")
    if artifact["component_inventory_fingerprint"] != component_fingerprint:
        raise ExchangeError("Analysis artifact refers to a stale component inventory")


def validate_controls(scope, components, component_fingerprint, artifact, ranges):
    if not Draft202012Validator(contract("multi-repo-controls.schema.json")).is_valid(artifact):
        raise ExchangeError("Controls violate their versioned contract")
    validate_identity(scope, artifact, component_fingerprint)
    allowed = source_selection(components)
    validate_retrieved_sources(scope, artifact, ranges, allowed)
    by_id = {row["id"]: row for row in components}
    for control in artifact["security_controls"]:
        if not set(control["component_ids"]) <= set(by_id):
            raise ExchangeError("Control refers to a component outside its authorized job")
        related = source_selection([by_id[key] for key in control["component_ids"]])
        if any((row["repository_id"], row["file"]) not in related for row in control["evidence"]):
            raise ExchangeError("Control evidence is not owned by its declared components")
    # The report gate requires a §6 place for every control. Apply the same
    # taxonomy normalization here, so an unplaceable domain becomes a
    # correction turn instead of a failed run after every model call.
    unplaced = _unplaced_controls(artifact["security_controls"])
    if unplaced:
        from renderers.pregenerate_fragments import describe_unplaced_controls

        raise ExchangeError(
            describe_unplaced_controls(unplaced) + ". Use one of these domains: " + "; ".join(_placeable_domains())
        )


def _unplaced_controls(controls: list[dict]) -> list[dict]:
    """Controls that no §6 section takes after the report's taxonomy normalization."""
    from model.enforce_control_taxonomy import enforce
    from renderers.pregenerate_fragments import unplaced_security_controls

    document = {"security_controls": copy.deepcopy(controls)}
    enforce(document)
    return unplaced_security_controls(document["security_controls"])


@lru_cache(maxsize=1)
def _placeable_domains() -> tuple[str, ...]:
    """The §6 titles a control can carry as its domain, derived from the placement rule itself."""
    from model.enforce_control_taxonomy import _section_titles

    probe = {"control": "Control", "effectiveness": "Weak", "component_ids": [], "evidence": [], "assessment": "-"}
    return tuple(title for title in sorted(_section_titles()) if not _unplaced_controls([{**probe, "domain": title}]))


def _reviewed_call_flows(repository_id, artifact, connections) -> list[str]:
    """Local flows that model a reviewed connection's call again as external.

    A service peer is not a role: a flow between a local component and a
    non-role external entity that cites a line of a reviewed connection in this
    repository duplicates that connection. Role flows may cite a served route.
    """
    reviewed = {
        (e["file"], e["line"]): flow["connection_id"]
        for flow in connections
        for e in flow["evidence"]
        if e["repository_id"] == repository_id
    }
    services = {e["id"] for e in artifact["external_entities"] if e["kind"] != "legitimate-role"}
    return sorted(
        {
            reviewed[(e["file"], e["line"])]
            for flow in artifact["data_flows"]
            if {flow.get("from_entity"), flow.get("to_entity")} & services
            for e in flow.get("evidence") or []
            if (e["file"], e["line"]) in reviewed
        }
    )


# A line that mounts or opens the browser UI; the first non-blank line otherwise.
_UI_ENTRY_LINE = re.compile(r"<body\b|\b(?:bootstrap\w*|createRoot|render|createApp|mount)\s*\(")


def client_entry_evidence(scope, repository_id: str, local_components: list[dict], units: list[dict]) -> dict:
    """Controller-attested evidence of each client component's browser entry point.

    A client component that lists an entry file of a client-app serving unit
    is cited at that file; other client components get none and keep their
    use with the model.
    """
    from analyzers.serving_units import carriers  # noqa: PLC0415

    repo = next(r for r in scope.repositories if r.repository_id == repository_id)
    evidence = {}
    for unit in units:
        if unit["kind"] != "client-app":
            continue
        for component in local_components:
            if component.get("tier") != "client" or component["id"] in evidence:
                continue
            view = {**component, "paths": [p["path"] for p in component["paths"]]}
            if not carriers(unit, [view]):
                continue
            path = next(rel for rel in unit["entry_files"] if rel in view["paths"])
            lines = scope.read(repository_id, path, 1, min(400, max(1, repo.files[path].count(b"\n") + 1)))["lines"]
            numbered = [(n, text) for n, text in enumerate(lines, 1) if text.strip()]
            line = next((n for n, text in numbered if _UI_ENTRY_LINE.search(text)), numbered[0][0] if numbered else 1)
            evidence[component["id"]] = {
                "file": path,
                "line": line,
                "repository_id": repository_id,
                "sha256": hashlib.sha256(repo.files[path]).hexdigest(),
            }
    return evidence


def add_client_use(artifact: dict, entries: dict) -> dict:
    """Add the sole regular role's use of each client that has none; idempotent.

    The flow invariants require a legitimate role to use every client. With
    exactly one regular (non-privileged) role the user is unambiguous, so the
    controller writes that interaction at the client's entry evidence. With
    several roles, which role uses which client stays with the model.
    """
    roles = [
        e["id"]
        for e in artifact["external_entities"]
        if e.get("kind") == "legitimate-role" and e.get("access") != "internet-priv-user"
    ]
    if len(roles) != 1:
        return artifact
    flows = artifact["data_flows"]
    for client in sorted(entries):
        if any(f.get("interaction") and f["to"] == client for f in flows):
            continue
        number = 1 + max((int(f["id"][3:]) for f in flows if str(f.get("id", "")).startswith("df-")), default=0)
        flows.append(
            {
                "id": f"df-{number:03d}",
                "from": "external",
                "from_entity": roles[0],
                "to": client,
                "label": "Browser uses the client application (human interaction)",
                "diagram_label": "Application use",
                "protocol": "HTTPS",
                "data_classification": "Public",
                "direction": "request-response",
                "interaction": True,
                "evidence": [dict(entries[client])],
                "provenance": "recon",
            }
        )
    return artifact


def local_architecture_normalizer(local_components: list[dict]):
    """Remove each `interaction` flag the local flow invariants can never accept.

    An interaction is a human legitimate role using a client component with no
    server authentication claim (validators.validate_fragment). A flag on any
    other flow says nothing the flow's endpoints and authentication do not, but
    its consumers skip the flow's route and authentication; without it the flow
    stays an ordinary, analyzed access. A repository without a client
    component can carry no interaction at all, which the model cannot see
    from a rejection alone.
    """
    from validators.validate_fragment import interaction_shape_holds, interaction_targets_client

    tiers = {row["id"]: row.get("tier") for row in local_components}

    def normalize(artifact):
        kinds = {row["id"]: row.get("kind") for row in artifact["external_entities"]}
        for flow in artifact["data_flows"]:
            if "interaction" in flow and not (
                flow["interaction"] and interaction_shape_holds(flow, kinds) and interaction_targets_client(flow, tiers)
            ):
                del flow["interaction"]
        return artifact

    normalize.version = "local-architecture-interaction-1"
    return normalize


def validate_local_architecture(
    scope, repository_id, components, receipt, artifact, ranges, connections=(), client_entries=None
):
    if not Draft202012Validator(contract("multi-repo-architecture.schema.json")).is_valid(artifact):
        raise ExchangeError("Local architecture violates its versioned contract")
    if (
        artifact["repository_id"] != repository_id
        or artifact["source_scope_sha256"] != components["source_scope_sha256"]
        or artifact["component_inventory_fingerprint"] != receipt["component_inventory_fingerprint"]
    ):
        raise ExchangeError("Local architecture changed its admitted input identity")
    local = [c for c in components["components"] if c["repository_ids"] == [repository_id]]
    local_ids = {c["id"] for c in local}
    allowed = source_selection(local)
    validate_retrieved_sources(scope, artifact, ranges, allowed)
    for flow in artifact["data_flows"]:
        if flow["from"] not in local_ids | {"external"} or flow["to"] not in local_ids | {"external"}:
            raise ExchangeError("Local architecture cannot create a cross-repository connection")
        if flow["from"] == flow["to"] == "external":
            raise ExchangeError("Local architecture must attach each flow to a selected component")
        if "connection_id" in flow:
            raise ExchangeError("Local architecture cannot mark a flow as a reviewed cross-repository connection")
    duplicated = _reviewed_call_flows(repository_id, artifact, connections)
    if duplicated:
        raise ExchangeError(
            "Local architecture models reviewed cross-repository connections again as external services: "
            + ", ".join(duplicated)
        )
    for asset in artifact["assets"]:
        if any(ref["component_id"] not in local_ids for ref in asset["component_refs"]):
            raise ExchangeError("Local asset refers to a component outside its repository")
    # The model needs at least one asset. Only a sole repository must supply
    # it; in a combined assessment another repository may hold the assets.
    if not artifact["assets"] and len(scope.repositories) == 1:
        raise ExchangeError(
            "Local architecture names no protected asset; name the data, credentials or capabilities "
            "these components store, process or guard, each with its component_refs"
        )
    # The combined flow handoff applies the single-root evidence guards later;
    # apply them here too, so this job can still correct its own result.
    from validators.validate_assessment_architecture import flow_invariant_errors, legacy_source_errors

    errors = legacy_source_errors(
        scope,
        "data-flows",
        {"data_flows": artifact["data_flows"], "external_entities": artifact["external_entities"]},
        repository_ids={repository_id},
    )
    if errors:
        raise Rejection("Local architecture violates repository evidence rules", errors)
    # The combined flow gate enforces these invariants too, but no job can
    # still correct its result there; checking them here lets the analyst
    # repair it in the exchange.
    # Flows the controller adds after the job count as present: the model is
    # never asked for a client use the controller writes itself.
    completed = add_client_use(copy.deepcopy(artifact), client_entries or {})
    errors = flow_invariant_errors(
        {"data_flows": completed["data_flows"], "external_entities": completed["external_entities"]},
        {"components": local},
    )
    if errors:
        raise Rejection("Local architecture violates flow invariants", errors)


def _comparison(value):
    if isinstance(value, dict):
        projected = {key: _comparison(child) for key, child in value.items() if key not in ("repository_id", "sha256")}
        if "file" in value:
            # Opaque comparison locators stay within legacy path-length
            # constraints. They are never used for rendering or file access.
            projected["file"] = "source-" + hashlib.sha256(source_key(value).encode()).hexdigest()
        return projected
    if isinstance(value, list):
        return [_comparison(row) for row in value]
    return value


def validate_stride(
    scope,
    component,
    neighborhood,
    flows,
    artifact,
    ranges,
    *,
    boundaries=(),
    allowed_requirement_ids=frozenset(),
    targets=None,
):
    """Preserve legacy policy/trace checks and scoped executable evidence.

    A finding may cite only requirement IDs of the catalog supplied to this job;
    without a catalog the allowed set is empty.
    """
    from validators.validate_fragment import repository_evidence_errors
    from validators.validate_intermediate import validate_stride as legacy_validate

    if not Draft202012Validator(contract("multi-repo-stride.schema.json")).is_valid(artifact):
        raise ExchangeError("STRIDE job violates its versioned contract")
    if artifact["component_id"] != component["id"] or artifact["component_name"] != component["name"]:
        raise ExchangeError("STRIDE job changed its component identity")
    if artifact["source_scope_sha256"] != scope.inventory()["scope_sha256"]:
        raise ExchangeError("STRIDE job belongs to another source scope")
    if artifact["component_inventory_fingerprint"] != flows["component_inventory_fingerprint"]:
        raise ExchangeError("STRIDE job refers to a stale component inventory")
    categories = artifact["coverage"]
    if {row["category"] for row in categories} != set(STRIDE_CATEGORIES) or len(categories) != 6:
        raise ExchangeError("STRIDE job must assess all six categories exactly once")
    identifiers = [row["local_id"] for row in artifact["threats"]]
    if len(identifiers) != len(set(identifiers)):
        raise ExchangeError("STRIDE finding identities are not unique")
    for row in categories:
        actual = {t["local_id"] for t in artifact["threats"] if t["stride"] == row["category"]}
        if set(row["finding_ids"]) != actual or bool(actual) != (row["disposition"] == "finding"):
            raise ExchangeError("STRIDE category coverage does not match its findings")
    allowed = source_selection(neighborhood)
    validate_retrieved_sources(scope, artifact, ranges, allowed)
    if targets is not None:
        validate_surface_coverage(artifact, ranges, targets)
    own = source_selection([component])
    if not any((row["repository_id"], row["path"]) in own for row in ranges):
        raise ExchangeError("STRIDE job did not retrieve its component's source")
    for finding in artifact["threats"]:
        anchor = finding["evidence"]
        if (anchor["repository_id"], anchor["file"]) not in own:
            raise ExchangeError("Finding evidence is not owned by the assessed component")
        if set(finding.get("violated_requirements") or ()) - set(allowed_requirement_ids):
            raise ExchangeError("Finding cites requirements absent from this job's catalog")
        trace = finding.get("mechanism_trace")
        if trace and trace["input"]["repository_id"] != anchor["repository_id"]:
            start = {
                c["id"]
                for c in neighborhood
                if (trace["input"]["repository_id"], trace["input"]["file"]) in source_selection([c])
            }
            reached = set(start)
            for _ in range(len(flows["data_flows"]) + 1):
                following = {f["to"] for f in flows["data_flows"] if f["from"] in reached}
                if following <= reached:
                    break
                reached.update(following)
            if component["id"] not in reached:
                raise ExchangeError("Cross-repository finding trace has no reviewed directional connection")
    projection = _comparison(artifact)
    projection.pop("schema_version", None)
    ok, errors = legacy_validate(projection)
    if not ok:
        raise Rejection("STRIDE job violates existing evidence, trace or remediation rules", errors)
    from contexts.prepare_trust_boundary_context import validate_finding_boundary_refs

    adjacent = {
        row["id"]
        for row in boundaries
        if component["id"] in (row.get("from"), row.get("to"))
        or component["id"] in (row.get("covers_components") or [])
    }
    for finding in projection["threats"]:
        if finding.get("boundary_refs"):
            refs, diagnostics = validate_finding_boundary_refs(
                finding,
                boundaries=_comparison(list(boundaries)),
                origin_component_id=component["id"],
                candidate_ids=adjacent,
                require_candidate=True,
                known_component_ids={row["id"] for row in neighborhood},
            )
            if diagnostics or len(refs) != len(finding["boundary_refs"]):
                raise Rejection(
                    f"Finding {finding.get('id')} refers to a boundary absent from its validated neighborhood "
                    f"(boundaries adjacent to this component: {', '.join(sorted(adjacent)) or 'none'})",
                    diagnostics,
                )
    evidence = list(source_rows(artifact))
    for repo in scope.repositories:
        own_evidence = [row for row in evidence if row["repository_id"] == repo.repository_id]
        if own_evidence:
            with scope.scanner_snapshot(repo.repository_id) as root:
                errors = repository_evidence_errors(own_evidence, root, require_line=True, require_code=True)
                if errors:
                    raise Rejection("STRIDE evidence does not cite an executable implementation", errors)


def evidence_batches(findings, *, max_windows, max_findings, window_lines):
    """Split one component's findings so each review can read every anchor.

    A verified decision must cite its own anchor, and one exchange serves a
    bounded number of slices; a batch therefore holds at most ``max_windows``
    distinct anchor windows. Findings sharing a window stay together.
    """

    def window(finding):
        anchor = finding["evidence"]
        line = 0 if anchor.get("kind") == "absence" else (anchor.get("line") or 1) // window_lines
        return (anchor["repository_id"], anchor["file"], line)

    batches: list[list[dict]] = []
    windows: set = set()
    for finding in sorted(findings, key=lambda row: (window(row), row["local_id"])):
        key = window(finding)
        if not batches or len(batches[-1]) >= max_findings or (key not in windows and len(windows) >= max_windows):
            batches.append([])
            windows = set()
        batches[-1].append(finding)
        windows.add(key)
    return batches


def validate_evidence_review(scope, findings, component_fingerprint, artifact, ranges, allowed_sources):
    if not Draft202012Validator(contract("multi-repo-evidence-review.schema.json")).is_valid(artifact):
        raise ExchangeError("Evidence review violates its versioned contract")
    validate_identity(scope, artifact, component_fingerprint)
    expected = {finding["local_id"] for finding in findings}
    supplied = [row["local_id"] for row in artifact["decisions"]]
    if len(supplied) != len(set(supplied)) or set(supplied) != expected:
        # Name the IDs: a bare count gives the correction turn nothing to fix.
        gaps = {
            "missing": sorted(expected - set(supplied)),
            "not supplied": sorted(set(supplied) - expected),
            "repeated": sorted({i for i in supplied if supplied.count(i) > 1}),
        }
        raise ExchangeError(
            "Evidence review must decide each finding exactly once; "
            + "; ".join(f"{label}: {', '.join(ids[:20])}" for label, ids in gaps.items() if ids)
        )
    validate_retrieved_sources(scope, artifact, ranges, allowed_sources)
    for decision in artifact["decisions"]:
        original = next(finding for finding in findings if finding["local_id"] == decision["local_id"])
        anchor = original["evidence"]
        # An absence has no line of its own: reading any retrieved range of
        # its anchor file is the independent reading.
        fields = ("repository_id", "file") if anchor.get("kind") == "absence" else ("repository_id", "file", "line")
        if decision["verdict"] == "verified" and not any(
            tuple(row[key] for key in fields) == tuple(anchor[key] for key in fields) for row in decision["evidence"]
        ):
            raise ExchangeError("Verified finding lacks an independent reading of its anchor")


def validate_boundary_candidates(scope, assessment, artifact, ranges, allowed_sources):
    from validators.validate_fragment import fragment_invariant_errors

    if not Draft202012Validator(contract("trust-boundary-assessment-input-v2.schema.json")).is_valid(assessment):
        raise ExchangeError("Crossing input violates its versioned contract")
    fingerprint_body = {k: v for k, v in assessment.items() if k != "assessment_input_fingerprint"}
    expected_input = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(fingerprint_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
    )
    if assessment["assessment_input_fingerprint"] != expected_input:
        raise ExchangeError("Crossing input fingerprint does not match its immutable contents")
    if not Draft202012Validator(contract("fragments/trust-boundary-candidates-v2.schema.json")).is_valid(artifact):
        raise ExchangeError("Boundary candidates violate their versioned contract")
    validate_identity(scope, artifact, assessment["component_inventory_fingerprint"])
    if artifact["assessment_input_fingerprint"] != assessment["assessment_input_fingerprint"]:
        raise ExchangeError("Boundary candidates belong to another immutable crossing input")
    validate_retrieved_sources(scope, artifact, ranges, allowed_sources)
    errors = fragment_invariant_errors(
        "trust-boundary-candidates", _comparison(artifact), context=_comparison(assessment)
    )
    if errors:
        raise Rejection("Boundary candidates violate existing coverage and crossing invariants", errors)
