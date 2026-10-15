"""Scoped adapters for semantic stages owned by the assessment controller.

These functions own contracts, source checks and read-only projections. They
do not sequence stages, dispatch models, choose roles or publish reports.
"""

from __future__ import annotations

import copy
import hashlib
import json
import posixpath
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator
from runtime.assessment_host import ExchangeError, Rejection, read_slice
from runtime.multi_repo_scope import ScopeError
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


def model_components(components: list[dict]) -> list[dict]:
    """Components as a model job sees them: each path without its content hash.

    A served slice carries its own hash, and acceptance checks citations
    against retrieved slices, never against these rows; a large client app's
    hashes otherwise fill a third of every packet that names it.
    """
    return [
        {**component, "paths": [{k: v for k, v in row.items() if k != "sha256"} for row in component["paths"]]}
        for component in components
    ]


def route_resource(path) -> str:
    """A route path up to its first parameter, so collection and item routes form one resource."""
    parts = []
    for part in str(path or "").split("/"):
        if not part:
            continue
        if part[0] in ":{<*(":
            break
        parts.append(part)
    return "/" + "/".join(parts)


@lru_cache(maxsize=1)
def _security_patterns():
    from analyzers.security_relevance_filter import SECURITY_PATTERNS

    return tuple(pattern for _, pattern in SECURITY_PATTERNS)


def has_security_signal(data: bytes) -> bool:
    """Whether the security keyword catalog matches a file's content (MR-13).

    Identifiers are also split at camelCase and snake_case joints, so
    ``checkPermission`` and ``custom_permission_check`` match the catalog's
    word-bounded ``permission`` like the plain word does.
    """
    text = data.decode("utf-8", "ignore")
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text).replace("_", " ")
    return any(pattern.search(text) or pattern.search(words) for pattern in _security_patterns())


# A grouped route target lists its routes for the model; the anchor alone
# names only the first. Bounded so one generated router cannot fill a packet.
MAX_TARGET_ROUTES = 32
MAX_TARGET_RELATED = 4


# A component's template named by a static path, relative to the component file.
_TEMPLATE_REF = re.compile(r"""\btemplateUrl\s*:\s*['"]([^'"\n]+\.html)['"]""")
_TEMPLATE_OWNERS = (".ts", ".js", ".mjs")


def template_pairs(scope, sources) -> dict[tuple, list[str]]:
    """Component files and the templates they name, in both directions (MR-13).

    Logic and markup together decide an output sink; a target in either file
    names the other as related. A template's owner is found among the given
    sources and the same-stem script beside each given template.
    """
    repos = {r.repository_id: r for r in scope.repositories}
    candidates = {(rid, path) for rid, path in sources if path.endswith(_TEMPLATE_OWNERS)}
    for rid, path in sources:
        if path.endswith(".html"):
            stem = path[: -len(".html")]
            candidates.update((rid, stem + suffix) for suffix in _TEMPLATE_OWNERS if stem + suffix in repos[rid].files)
    pairs: dict[tuple, list[str]] = {}
    for rid, path in sorted(candidates):
        for match in _TEMPLATE_REF.finditer(repos[rid].files[path].decode("utf-8", "ignore")):
            template = posixpath.normpath(posixpath.join(posixpath.dirname(path), match.group(1)))
            if template in repos[rid].files and template != path:
                pairs.setdefault((rid, path), []).append(template)
                pairs.setdefault((rid, template), []).append(path)
    return pairs


def analysis_targets(scope, component: dict, architecture: dict, scanned: list[dict]) -> list[dict]:
    """Source-backed surfaces to examine, independent of finding counts or repository names.

    These are investigation leads, not vulnerabilities. Full route inventories
    and outbound call sites supplement authored topology, so a missing flow
    cannot also hide the call from STRIDE. Targets stay inside the finalized
    component, and only a route's registration window or a component's
    template may lie outside it (`related_sources`); a scanner result never
    authorizes reading an unrelated file.

    Decision MR-13: routes sharing a registration file, a source window and
    their path up to the first parameter form one resource. A resource with a
    resolved handler module becomes a target in that module listing its
    routes, and every target in the module names the registration lines as
    ``related``, so its job reads handler and guards together; a resource
    without one stays a target at its registration lines. Ownership follows
    the handler: a component owning the handler module but not the
    registration file still decides the route, with the registration window
    as a related read; the registration file's component leaves a route whose
    handler another finalized component owns to that component. A scanner
    lead at a registration line joins the decision of the route registered
    there instead of becoming a second target. A target in a component file
    or in the template it names (`template_pairs`) reads the other file as
    related. A file without any
    other lead becomes a target only when
    the security keyword catalog matches it (`has_security_signal`);
    `unexamined_files` names the rest for the run report.

    Each anchor cites a line the STRIDE evidence rule accepts: the surface
    decision must cite it, so a comment or blank anchor, such as the license
    header of a file without a lead, would reject every answer. An anchor on
    such a line moves to the next accepted line, else the previous one; a file
    without one offers no target.
    """
    from runtime.assessment_host import MAX_SLICE_LINES
    from validators.validate_fragment import _cited_line_problem

    own = source_selection([component])
    repos = {r.repository_id: r for r in scope.repositories}
    targets = {}
    texts: dict[tuple, list[str]] = {}

    def code_line(rid, path, line):
        lines = texts.setdefault((rid, path), repos[rid].files[path].decode("utf-8", "ignore").splitlines())
        line = max(1, min(line, len(lines)))
        order = [*range(line, len(lines) + 1), *range(line - 1, 0, -1)]
        return next((n for n in order if _cited_line_problem(lines[n - 1], allow_imports=True) is None), None)

    def add(evidence, kind):
        rid, path = evidence.get("repository_id"), evidence.get("file")
        if (rid, path) not in own:
            return None
        line = code_line(rid, path, evidence.get("line") or 1)
        if line is None:
            return None
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
        return targets[key]

    def relate(target, window):
        related = target.setdefault("related", [])
        if list(window) not in related and len(related) < MAX_TARGET_RELATED:
            related.append(list(window))

    modules = architecture.get("route_handler_modules", {})
    owners = {
        (row["repository_id"], row["path"]): row_component["id"]
        for row_component in (architecture.get("components") or {}).get("components", [])
        for row in row_component["paths"]
    }

    def handler_of(rid, route):
        return modules.get(rid, {}).get(route.get("route_id"))

    def decided_elsewhere(rid, path, route):
        """Whether another finalized component owns this route's resolved handler module."""
        module = handler_of(rid, route)
        return module not in (None, path) and owners.get((rid, module)) not in (None, component["id"])

    groups: dict[tuple, list[tuple[int, dict]]] = {}
    for rid, inventory in architecture.get("route_inventories", {}).items():
        for route in inventory.get("routes", []):
            path = route.get("handler_file")
            if (rid, path) not in own and (rid, handler_of(rid, route)) not in own:
                continue
            if path not in repos[rid].files:
                continue
            line = code_line(rid, path, route.get("handler_line") or 1)
            if line is not None:
                key = (rid, path, line // MAX_SLICE_LINES, route_resource(route.get("path")))
                groups.setdefault(key, []).append((line, route))
    registrations: dict[tuple, list[tuple]] = {}
    # Registration lines whose route is decided at a handler target, or by
    # another component; a scanner lead on such a line joins that decision.
    registered: dict[tuple, list[dict]] = {}

    def list_routes(target, members):
        listed = target.setdefault("routes", [])
        listed.extend(
            {"method": route.get("method"), "path": route.get("path"), "line": line}
            for line, route in members[: max(0, MAX_TARGET_ROUTES - len(listed))]
        )

    for (rid, path, _, _), members in sorted(groups.items(), key=lambda item: item[0]):
        members.sort(key=lambda member: (member[0], str(member[1].get("method"))))
        # The registration's whole source window: every handler of one
        # registration file then shares the same one or two preloaded windows.
        start = max(1, members[0][0] // MAX_SLICE_LINES * MAX_SLICE_LINES)
        span = (rid, path, start, members[0][0] // MAX_SLICE_LINES * MAX_SLICE_LINES + MAX_SLICE_LINES - 1)
        handlers = sorted(
            module for module in {handler_of(rid, route) for _, route in members} - {None, path} if (rid, module) in own
        )
        # A resolved resource is decided at its handler, with the registration
        # lines (its guards) preloaded beside it; a registration without an own
        # handler module, such as a guard-only line, is decided where it stands.
        anchored = [(module, add({"repository_id": rid, "file": module, "line": 1}, "route")) for module in handlers]
        anchored = [(module, target) for module, target in anchored if target is not None]
        registered_here = (rid, path) in own
        for module, target in anchored:
            registrations.setdefault((rid, module), []).append(span)
            # Routes registered in another component's file are listed only at their own handler.
            listed = members if registered_here else [m for m in members if handler_of(rid, m[1]) == module]
            list_routes(target, listed)
            for line, _ in listed:
                registered.setdefault((rid, path, line), []).append(target)
        if not anchored and registered_here:
            for line, route in members:
                if decided_elsewhere(rid, path, route):
                    registered.setdefault((rid, path, line), [])
            remaining = [m for m in members if not decided_elsewhere(rid, path, m[1])]
            if remaining:
                target = add({"repository_id": rid, "file": path, "line": remaining[0][0]}, "route")
                if target is not None:
                    list_routes(target, remaining)
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
        evidence = finding["evidence"]
        rid, path = evidence.get("repository_id"), evidence.get("file")
        if (rid, path) in own and evidence.get("line"):
            joined = registered.get((rid, path, code_line(rid, path, evidence["line"])))
            if joined is not None:
                for target in joined:
                    if "scanner-lead" not in target["kinds"]:
                        target["kinds"].append("scanner-lead")
                continue
        add(evidence, "scanner-lead")
    # A file without a lead is investigated when it shows a security signal;
    # neither a known route elsewhere nor an unsupported stack hides it.
    # A first-code-line lead does not claim to enumerate all mechanisms in a file.
    covered_files = {(rid, path) for rid, path, _ in targets}
    for rid, path in sorted(own - covered_files):
        if has_security_signal(repos[rid].files[path]):
            add({"repository_id": rid, "file": path, "line": 1}, "component-source")
    pairs = template_pairs(scope, own | {(rid, path) for rid, path, _ in targets})
    for (rid, path, _), target in targets.items():
        for span in registrations.get((rid, path), []):
            relate(target, span)
        for other in pairs.get((rid, path), []):
            relate(target, (rid, other, 1, MAX_SLICE_LINES - 1))
    if len(targets) > 20_000:
        raise ExchangeError("Component investigation exceeds the source-reference limit")
    return [targets[key] for key in sorted(targets)]


def related_sources(targets: list[dict]) -> frozenset:
    """Files the targets' related ranges name, registrations and templates: a STRIDE job may read and cite them (MR-13)."""
    return frozenset((row[0], row[1]) for target in targets for row in target.get("related", []))


# Program code a STRIDE job could analyse; configuration, data and prose are not.
_PROGRAM_SUFFIXES = frozenset(
    ".py .js .jsx .ts .tsx .mjs .cjs .java .kt .kts .scala .go .rb .php .cs .rs .swift .c .cc .cpp .h .hpp "
    ".m .mm .dart .ex .exs .erl .lua .pl .pm .vue .svelte".split()
)
_TEST_SOURCE_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|e2e|cypress)(?:/|$)|\.(?:spec|test|cy)\.\w+$|(?:^|/)test_[^/]*$"
)


def unowned_sources(scope, components: list[dict]) -> list[tuple[str, str]]:
    """Admitted program files outside every component and outside tests: no job analyses them."""
    owned = source_selection(components)
    return sorted(
        (repo.repository_id, path)
        for repo in scope.repositories
        for path in repo.files
        if (repo.repository_id, path) not in owned
        and PurePosixPath(path).suffix.lower() in _PROGRAM_SUFFIXES
        and not _TEST_SOURCE_RE.search(path)
    )


def unowned_summary(scope, components: list[dict], qualify) -> dict | None:
    """``{files, by_directory}`` of ``unowned_sources``, grouped by top-level directory, or None.

    ``qualify(repository_id, path)`` gives the reported path, so a combined
    assessment names each repository's directories apart.
    """
    unowned = unowned_sources(scope, components)
    if not unowned:
        return None
    counts: dict[str, int] = {}
    for rid, path in unowned:
        prefix = qualify(rid, path)[: -len(path)]
        head, _, rest = path.partition("/")
        key = prefix + (head + "/" if rest else "(repository root)")
        counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:10]
    return {"files": len(unowned), "by_directory": [{"directory": d, "files": n} for d, n in ranked]}


def unexamined_files(component: dict, targets: list[dict]) -> list[tuple[str, str]]:
    """Component sources no target names; the run reports them (MR-13)."""
    named = {(t["evidence"]["repository_id"], t["evidence"]["file"]) for t in targets}
    return sorted(source_selection([component]) - named)


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
    # A flow to an external entity names it in `to_entity`/`from_entity`; its
    # `from`/`to` then read "external".
    connected = {
        end
        for flow in flows.get("data_flows", [])
        for end, others in (
            (flow.get("from"), (flow.get("to"), flow.get("to_entity"))),
            (flow.get("to"), (flow.get("from"), flow.get("from_entity"))),
        )
        if inference.intersection(others)
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
    """Insert each target's exact anchor into a decision that cites no evidence or the target's file.

    A model that read the target's file seldom copies its 64-character hash; the
    controller knows the anchor and adds it, and a decision may omit evidence
    entirely (MR-11). A decision citing only another file gains nothing, and
    `validate_surface_coverage` still requires the read. A decision that links a
    finding keeps no reason: the finding states it.
    """
    anchors = {target["local_id"]: target["evidence"] for target in targets}

    def normalize(artifact):
        for row in artifact.get("surface_coverage") or []:
            if row.get("disposition") == "examined" and row.get("finding_ids"):
                row.pop("reason", None)
            anchor = anchors.get(row.get("target_id"))
            if anchor is not None and not row.get("evidence"):
                row["evidence"] = [dict(anchor)]
                continue
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

    normalize.version = "surface-anchor-2"
    return normalize


# A title's trailing location, which the controller derives from the anchor (MR-17).
_TITLE_LOCATION = re.compile(r"\s*\([^()]*:\d+(?:-\d+)?\)\s*$")
TITLE_MAX = 80


def identity_normalizer(identity):
    """Set the job's identity fields instead of checking the model's copy (MR-17)."""

    def normalize(artifact):
        artifact.update(
            source_scope_sha256=identity["source_scope_sha256"],
            component_inventory_fingerprint=identity["component_inventory_fingerprint"],
        )
        return artifact

    normalize.version = "identity-1"
    return normalize


def stride_normalizer(targets, component, identity):
    """Derive what the controller knows instead of checking and returning it (MR-17).

    Identity fields come from the job; each category's ``finding_ids`` and
    whether it holds findings come from the threats, keeping the model's reason;
    a missing category is added as ``no-evidence``. A title's location bracket
    is the anchor's file and line, appended when the title stays within its
    limit. Coverage of investigation targets is normalized as before.
    """
    surface = surface_evidence_normalizer(targets)

    def normalize(artifact):
        artifact = surface(artifact)
        artifact.update(
            schema_version=2,
            source_scope_sha256=identity["source_scope_sha256"],
            component_inventory_fingerprint=identity["component_inventory_fingerprint"],
            component_id=component["id"],
            component_name=component["name"],
        )
        threats = [row for row in artifact.get("threats") or [] if isinstance(row, dict)]
        rows = {
            row.get("category"): row
            for row in reversed(artifact.get("coverage") or [])
            if isinstance(row, dict) and row.get("category") in STRIDE_CATEGORIES
        }
        coverage = []
        for category in STRIDE_CATEGORIES:
            row = dict(rows.get(category) or {"reason": "No finding was reported for this category."})
            ids = [t["local_id"] for t in threats if t.get("stride") == category and isinstance(t.get("local_id"), str)]
            row.update(category=category, finding_ids=ids)
            if ids:
                row["disposition"] = "finding"
            elif row.get("disposition") in (None, "finding"):
                row["disposition"] = "no-evidence"
            coverage.append(row)
        artifact["coverage"] = coverage
        for threat in threats:
            title, anchor = threat.get("title"), threat.get("evidence")
            if not isinstance(title, str):
                continue
            base = _TITLE_LOCATION.sub("", title).rstrip()
            if isinstance(anchor, dict) and isinstance(anchor.get("file"), str) and type(anchor.get("line")) is int:
                located = f"{base} ({posixpath.basename(anchor['file'])}:{anchor['line']})"
                threat["title"] = located if len(located) <= TITLE_MAX else base
            else:
                threat["title"] = base
        return artifact

    normalize.version = surface.version + "+stride-derive-1"
    return normalize


def unresolved_targets(artifact, targets, *, qualified: bool = True) -> list[str]:
    """`file: reason` of each target a job read but left unresolved (MR-11).

    The anchor line is omitted: a file-level target's anchor is only its first
    code line, and the reason names what is missing. ``qualified`` prefixes the
    repository, which only a combined assessment needs.
    """
    anchors = {target["local_id"]: target["evidence"] for target in targets}
    return [
        f"{anchor['repository_id'] + '/' if qualified else ''}{anchor['file']}: {row.get('reason') or 'no reason given'}"
        for row in artifact.get("surface_coverage") or []
        if row["disposition"] == "unresolved" and (anchor := anchors.get(row["target_id"]))
    ]


def validate_surface_coverage(artifact, ranges, targets):
    """No authored disposition can substitute for actually retrieving a target.

    A target the job read may stay `unresolved` with its reason; the run names it
    as a warning (MR-11). An unread target is always rejected. Only a decision
    that links a finding may omit its reason.
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
        if not read or target not in row.get("evidence", []):
            errors.append("Unexamined source target: " + location)
        if not set(row["finding_ids"]) <= findings:
            errors.append("Surface coverage refers to unknown findings")
        if row["disposition"] == "not-applicable" and row["finding_ids"]:
            errors.append("An inapplicable surface cannot carry findings")
        if not (row["disposition"] == "examined" and row["finding_ids"]) and not row.get("reason"):
            errors.append(f"Surface decision for {location} links no finding and needs a reason")
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
    validate_executable_evidence(scope, artifact, "Control evidence does not cite an executable implementation")


def controls_contract() -> dict:
    """The control job's contract with ``domain`` limited to the §6 titles that place a control (MR-17).

    `validate_controls` accepts nothing else, so the output tool enforces the
    choice instead of a correction turn.
    """
    schema = contract("multi-repo-controls.schema.json")
    item = schema["properties"]["security_controls"]["items"]
    item["properties"]["domain"] = {**item["properties"]["domain"], "enum": list(_placeable_domains())}
    return schema


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
    validate_executable_evidence(scope, artifact, "Architecture evidence does not cite an executable implementation")


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
    related=frozenset(),
):
    """Preserve legacy policy/trace checks and scoped executable evidence.

    A finding may cite only requirement IDs of the catalog supplied to this job;
    without a catalog the allowed set is empty. `related` names files outside
    the neighborhood that the job's targets read as route registrations; their
    lines may support a finding, whose own anchor stays in the component.
    """
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
    allowed = source_selection(neighborhood) | related
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
    validate_executable_evidence(scope, artifact, "STRIDE evidence does not cite an executable implementation")


def validate_executable_evidence(scope, artifact, summary, repository_id=None):
    """Every cited line must be code, not a blank line or comment (MR-15).

    Each role runs this as its last check: every earlier check passed, so
    naming each failing row lets the exchange ask for its line alone (MR-2).
    A citation accepted here is inherited by later jobs, which would
    otherwise each be rejected for it. A row without its own
    ``repository_id`` belongs to `repository_id`.
    """
    from validators.validate_fragment import repository_evidence_errors

    evidence = list(source_rows(artifact))
    for repo in scope.repositories:
        own_evidence = [row for row in evidence if row.get("repository_id", repository_id) == repo.repository_id]
        if own_evidence:
            with scope.scanner_snapshot(repo.repository_id) as root:
                check = dict(require_line=True, require_code=True)
                errors = repository_evidence_errors(own_evidence, root, **check)
                if errors:
                    anchors = [
                        (row, problem[0])
                        for row in own_evidence
                        if type(row.get("line")) is int
                        and (problem := repository_evidence_errors([row], root, **check))
                    ]
                    raise Rejection(summary, errors, anchors=anchors if len(anchors) == len(errors) else ())


def target_batches(
    scope, targets, *, room, max_targets, max_windows, window_lines, max_unserved, reserve_bytes=0, reserve_windows=0
):
    """Split one component's investigation targets into jobs that receive their source up front.

    Every target must be read, and the controller knows where: each job gets
    its targets' windows as preloaded slices instead of spending a call to
    request them. A job holds as many windows as fit `room` bytes together
    with its target list, at most `max_windows`, so the job count follows
    source size rather than a fixed small window count. A window the scope cannot serve in one slice, or larger than
    `room`, is left to the model's own reads, at most `max_unserved` per job. Targets sharing a window
    stay together up to `max_targets`. A target's ``related`` ranges (MR-13: a route's handler module,
    a handler's registration lines) are preloaded in the same job when they fit; one the job cannot
    hold is left to the model's reads. The first job keeps `reserve_bytes` and `reserve_windows` free for
    slices its caller adds, such as the lines the component's context cites. Returns ``(targets, preload)``
    pairs.
    """

    def window(target):
        anchor = target["evidence"]
        index = (anchor.get("line") or 1) // window_lines
        start = max(1, index * window_lines)
        return (anchor["repository_id"], anchor["file"], start, index * window_lines + window_lines - 1)

    def serve(key):
        try:
            piece = read_slice(scope, *key)
        except ScopeError:
            return None, 0
        size = len(json.dumps(piece, ensure_ascii=False).encode())
        return ((*key[:3], piece["end_line"]), size) if size <= room else (None, 0)

    grouped: dict[tuple, list[dict]] = {}
    for target in sorted(targets, key=lambda row: (window(row), row["local_id"])):
        grouped.setdefault(window(target), []).append(target)
    # A window with more targets than one job may decide is split; each part
    # receives the same window.
    chunks = [
        (key, members[start : start + max_targets])
        for key, members in grouped.items()
        for start in range(0, len(members), max_targets)
    ]
    batches: list[tuple[list[dict], list[tuple]]] = []
    used = unserved = 0
    cap = max_windows
    for key, members in chunks:
        primary, size = serve(key)
        size += len(json.dumps(members, ensure_ascii=False).encode())
        related = []
        for extra in dict.fromkeys(tuple(r) for member in members for r in member.get("related", [])):
            if extra[:3] != key[:3]:
                served, extra_size = serve(extra)
                if served is not None:
                    related.append((served, extra_size))

        def missing(batch):
            # A range inside a window the job already holds adds nothing.
            return [
                (k, n)
                for k, n in related
                if not any(p[:2] == k[:2] and p[2] <= k[2] and k[3] <= p[3] for p in batch[1])
            ]

        new = missing(batches[-1]) if batches else related
        full = batches and (
            len(batches[-1][0]) + len(members) > max_targets
            or used + size > room
            or (primary is not None and len(batches[-1][1]) >= cap)
            or (primary is None and unserved >= max_unserved)
        )
        if not batches or full:
            batches.append(([], []))
            used, cap = (reserve_bytes, max_windows - reserve_windows) if len(batches) == 1 else (0, max_windows)
            unserved = 0
            new = missing(([], [primary] if primary else []))
        batches[-1][0].extend(members)
        if primary is None:
            unserved += 1
        elif primary[:3] not in {k[:3] for k in batches[-1][1]}:
            batches[-1][1].append(primary)
        used += size
        if primary is not None:
            new = [(k, n) for k, n in new if not (k[:2] == primary[:2] and primary[2] <= k[2] and k[3] <= primary[3])]
        for extra, extra_size in new:
            if len(batches[-1][1]) < cap and used + extra_size <= room:
                batches[-1][1].append(extra)
                used += extra_size
    return batches


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


def evidence_preload(scope, evidence, allowed_sources, *, room, max_windows, before=30, after=90, max_lines=400):
    """Slices around the anchors a job is told to read, for its first packet.

    A boundary or control job otherwise spends a call only to request source
    the controller already cites. Ranges in one file merge when they overlap;
    an anchor outside ``allowed_sources``, a range the scope cannot serve, and
    whatever exceeds ``room`` bytes or ``max_windows`` slices is left to the
    model's own reads. Returns ``(repository_id, path, start, end)`` keys.
    """
    spans: dict[tuple, list[list[int]]] = {}
    for row in evidence:
        rid, path, line = row.get("repository_id"), row.get("file"), row.get("line")
        if (rid, path) not in allowed_sources or type(line) is not int or line < 1:
            continue
        spans.setdefault((rid, path), []).append([max(1, line - before), line + after])
    keys = []
    for (rid, path), ranges in sorted(spans.items()):
        ranges.sort()
        merged = [ranges[0]]
        for start, end in ranges[1:]:
            if start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        for start, end in merged:
            keys.extend((rid, path, s, min(end, s + max_lines - 1)) for s in range(start, end + 1, max_lines))
    preload, used = [], 0
    for key in keys:
        if len(preload) >= max_windows:
            break
        try:
            piece = read_slice(scope, *key)
        except ScopeError:
            continue
        size = len(json.dumps(piece, ensure_ascii=False).encode())
        if used + size > room:
            continue
        preload.append((*key[:3], piece["end_line"]))
        used += size
    return preload


def served_bytes(scope, keys) -> int:
    """Packet bytes the slices of `keys` occupy, measured as `evidence_preload` measures them."""
    return sum(len(json.dumps(read_slice(scope, *key), ensure_ascii=False).encode()) for key in keys)


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
    validate_executable_evidence(scope, artifact, "Review evidence does not cite an executable implementation")


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
    validate_executable_evidence(scope, artifact, "Boundary evidence does not cite an executable implementation")
