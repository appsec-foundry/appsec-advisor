#!/usr/bin/env python3
"""Build the Full-M1 STRIDE dispatch manifest from on-disk Stage-1 artifacts.

Hybrid handoff: this script assembles every per-component dispatch parameter
that IS deterministically derivable from disk (identity, paths, complexity,
max_turns, the per-component trust-boundary subset, the index/slice paths), and
merges the small set of CONTEXTUAL fields that only the analyst can supply
(interfaces, controls, known_*) from an optional analyst-context JSON. The
result, ``$OUTPUT_DIR/.stride-dispatch-manifest.json``, is validated by
``validate_dispatch_manifest.py`` and consumed by the skill's parallel
``appsec-stride-analyzer`` fan-out (Full-M1).

This minimises the LLM-authored surface to the contextual fields only — the
load-bearing identity/budget/path fields are deterministic and testable.

Usage:
    build_stride_dispatch_manifest.py <output_dir> --depth {quick,standard,thorough}
        [--analyst-context <path.json>] [--plugin-root <dir>]

The analyst-context JSON (optional) maps component_id → a dict of any of:
``interfaces``, ``controls``, ``known_secrets``, ``known_vulns``,
``known_llm_patterns``, ``supply_chain_findings``, ``estimated_threat_count``,
``focus_paths``, ``exclude_paths``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# max_turns per (depth, complexity) — single source of truth is
# resolve_config.DEPTH_PARAMS; imported when available, else a synced fallback
# (kept identical by tests/test_dispatch_manifest.py::test_depth_params_in_sync).
_FALLBACK_DEPTH_PARAMS = {
    "quick": {"simple": 10, "moderate": 15, "complex": 20},
    "standard": {"simple": 15, "moderate": 22, "complex": 31},
    "thorough": {"simple": 20, "moderate": 28, "complex": 35},
}


def _depth_params() -> dict:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from resolve_config import DEPTH_PARAMS  # type: ignore

        return DEPTH_PARAMS
    except Exception:
        return _FALLBACK_DEPTH_PARAMS


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _trust_boundaries_for(component_id: str, all_boundaries: list) -> str:
    """Deterministic per-component trust-boundary summary string."""
    hits = []
    for b in all_boundaries:
        if not isinstance(b, dict):
            continue
        touches = (
            component_id == b.get("from") or component_id == b.get("to") or component_id in (b.get("components") or [])
        )
        if touches:
            name = b.get("name", b.get("id", "boundary"))
            enf = b.get("crossing_enforcement", "")
            hits.append(f"{name}: {enf}".strip().rstrip(":").strip())
    return " | ".join(hits) if hits else "No trust boundary directly tied to this component."


# ---------------------------------------------------------------------------
# Criteria-derived STRIDE-component selection (replaces the hard-coded 3/5/8
# count). Depth selects which *predicates* are active; the component count is
# the EMERGENT result of applying them to the full inventory in .components.json.
#
# Exposure classes are derived from each component's deployment_zones[] (the
# access-zone vocabulary in data/actors/default-library.yaml). These sets are
# the selection *criteria*, not a count — defining "exposed" is policy that has
# to live somewhere; it is exactly the "general criteria" the count derives from.
# ---------------------------------------------------------------------------
EXPOSED_ZONES = frozenset({"internet", "dmz", "client-device", "mobile-device"})
CICD_ZONES = frozenset({"ci-cd-runtime", "ci-cd-secrets", "build-pipeline", "deployment-pipeline"})
# Pure runtime / where-it-runs zones carry NO internet-reachability signal. A
# component tagged ONLY with these is exposure-UNKNOWN for selection purposes
# and must hit the fail-safe inclusion branch, not be treated as "internal-only"
# and dropped. (2026-06-12: b2b-api — a JWT-protected /b2b/v2 REST API with a
# vm.runInContext RCE — was tagged only `docker-container` and silently excluded
# at standard depth, leaving the whole component unanalyzed.)
RUNTIME_ONLY_ZONES = frozenset(
    {
        "docker-container",
        "container",
        "kubernetes",
        "k8s",
        "pod",
        "vm",
        "virtual-machine",
        "serverless",
        "lambda",
        "function",
        "host",
        "process",
        "runtime",
    }
)
_AUTH_HINTS = ("auth", "identity", "login", "session", "jwt", "oauth", "iam", "2fa", "mfa")
_FRONTEND_HINTS = ("frontend", "spa", "web-client", "react", "angular", "vue")


def _component_text(c: dict) -> str:
    # Role detection matches id/name/type only — NOT description. The prose
    # description over-matches (a chatbot whose description mentions "session"
    # or "auth" would be mis-tagged auth); id+name+type are the stable labels.
    return " ".join(str(c.get(k, "")) for k in ("id", "name", "type")).lower()


def _zones(c: dict) -> set:
    z = c.get("deployment_zones") or []
    return {str(x).strip().lower() for x in z if str(x).strip()}


def _reachability_zones(c: dict) -> set:
    """Deployment zones that actually carry an internet-reachability signal.

    Runtime/where-it-runs tags (``RUNTIME_ONLY_ZONES``) are filtered out: a
    component tagged only with those is exposure-UNKNOWN, so the selection's
    fail-safe inclusion branch must fire rather than the "zones present →
    treat as internal-only" path that silently drops it.
    """
    return _zones(c) - RUNTIME_ONLY_ZONES


def _is_auth(c: dict) -> bool:
    t = _component_text(c)
    return any(h in t for h in _AUTH_HINTS)


def _is_frontend(c: dict) -> bool:
    if (c.get("tier") or "").lower() == "client":
        return True
    t = _component_text(c)
    return any(h in t for h in _FRONTEND_HINTS)


def _is_cicd(c: dict) -> bool:
    if _zones(c) & CICD_ZONES:
        return True
    t = _component_text(c)
    return "ci-cd" in t or "cicd" in t or "pipeline" in t


# Word-boundary matched — short tokens like "sse" must NOT match inside
# unrelated words ("a-sse-t service", "cla-sse-s"). Substring matching (as the
# pre-existing _is_auth/_is_cicd hints use) would spuriously mark a file-upload
# / asset component as a realtime role and suppress the realtime injection.
_REALTIME_RE = re.compile(
    r"\b(socket\.?io|web-?socket|real-?time|socket|stomp|sse|pub-?sub)\b", re.I
)


def _is_realtime(c: dict) -> bool:
    return bool(_REALTIME_RE.search(_component_text(c)))


def _is_exposed(c: dict) -> bool:
    return bool(_zones(c) & EXPOSED_ZONES)


def _is_crown_jewel(c: dict) -> bool:
    return bool(c.get("handles_sensitive_data"))


def _is_internal_only(c: dict) -> bool:
    """A component selected only for thorough completeness: it has explicit
    zones, none exposed/ci-cd, and it is not crown-jewel/auth/frontend. These
    are the ONLY components the operational ceiling may shed — everything that
    earned selection by a positive criterion (or exposure-unknown fail-safe) is
    never silently dropped."""
    if not _reachability_zones(c):
        return False  # exposure-unknown → fail-safe, never silently dropped
    return not (_is_exposed(c) or _is_cicd(c) or _is_crown_jewel(c) or _is_auth(c) or _is_frontend(c))


def _priority(c: dict) -> int:
    """Lower = kept first when an operational ceiling forces overflow drops."""
    if _is_auth(c):
        return 0  # M3.4 invariant — never drop
    if _is_frontend(c):
        return 1  # frontend attack-surface invariant — never drop
    if _is_exposed(c):
        return 2  # directly reachable by an external actor — never drop (cap lifts)
    if _is_crown_jewel(c):
        return 3
    if _is_cicd(c):
        return 4
    return 5  # internal-only / transitively-reachable — drop first


def _selection_reasons(c: dict, depth: str) -> list:
    reasons = []
    if _is_auth(c):
        reasons.append("auth (M3.4 mandatory)")
    if _is_frontend(c):
        reasons.append("frontend attack surface (mandatory)")
    if _is_exposed(c):
        reasons.append(f"internet-exposed ({','.join(sorted(_zones(c) & EXPOSED_ZONES))})")
    if depth != "quick" and _is_cicd(c):
        reasons.append("ci-cd / deployment (supply-chain boundary)")
    if depth != "quick" and _is_crown_jewel(c):
        reasons.append("crown-jewel (credentials/PII/payment/secrets)")
    if depth == "thorough" and not reasons:
        reasons.append("transitively reachable (thorough)")
    if not _reachability_zones(c) and not _is_auth(c) and not _is_frontend(c):
        reasons.append("exposure-unknown (fail-safe inclusion)")
    return reasons


def _in_scope(c: dict, depth: str) -> bool:
    # Role-floor: auth + frontend are mandatory at every depth.
    if _is_auth(c) or _is_frontend(c):
        return True
    if _is_exposed(c):
        return True
    if not _reachability_zones(c):
        # Exposure-unknown (no zones, or runtime-only zones like docker-container
        # that carry no reachability signal): fail-safe toward inclusion at EVERY
        # depth, including quick. A component whose reachability cannot be proven
        # internal could be an internet-facing door — the 2026-06-12 b2b-api RCE,
        # tagged only `docker-container`, is the canonical case, and runtime-only
        # tagging is the COMMON outcome in containerised/serverless repos, not an
        # edge case. Skipping it in quick would recreate the silent whole-component
        # blind spot. Only PROVEN-internal components (a reachability zone present,
        # none of them exposed) are dropped from the fast path below.
        return True
    if depth == "quick":
        # Quick = role-floor + directly-exposed + exposure-unknown (handled above).
        # Proven-internal / ci-cd / crown-jewel are deferred to standard+.
        return False
    # standard + thorough
    if _is_cicd(c) or _is_crown_jewel(c):
        return True
    # Reachability zones present but none exposed/cicd → internal-only: thorough only.
    return depth == "thorough"


# ---------------------------------------------------------------------------
# Enumeration-completeness reconciliation.
#
# Phase-3 component enumeration is LLM-authored and occasionally FOLDS a
# security-relevant deployable unit into a coarser parent (e.g. the auth
# surface, the real-time channel, and the CI/CD pipeline collapsed into one
# "backend" component) or drops it entirely. The deterministic selector can
# only act on what is enumerated, so a folded unit becomes a silent
# whole-component blind spot — never analyzed AND never surfaced as
# out-of-scope. This pass restores ROLE completeness: when hard repo evidence
# shows a security-relevant unit exists but no enumerated component carries
# that role, inject a minimal component so the selector (and the §1 scope
# rendering) can see it. Role-coverage, not path-coverage: an auth surface
# folded inside a backend's routes/** still earns its own component (dedicated
# STRIDE pass + the priority-0 auth floor that _is_auth would otherwise never
# fire for a generically-named monolith).
#
# Idempotent: a unit whose role is already carried by an enumerated component
# is never duplicated, so on a repo where Phase-3 already split it out (or on a
# re-run over an already-augmented inventory) this is a no-op.
# ---------------------------------------------------------------------------
_CI_GLOBS = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".circleci/config.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
)
_AUTH_FILE_RE = re.compile(
    r"(login|logout|register|signup|auth|oauth|jwt|session|2fa|mfa|otp|"
    r"reset.?password|forgot.?password|insecurity|identity|credential)",
    re.I,
)
_AUTH_SCAN_DIRS = ("routes", "lib", "src", "controllers", "middleware", "app", "api")
_SRC_SUFFIXES = (".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs", ".py", ".go", ".java", ".rb")


def _guess_repo_root(output_dir: Path) -> Path:
    """Best-effort repo root from the assessment output dir. Side-effect-free;
    detectors guard on file existence, so a wrong guess simply yields no
    injection (safe no-op)."""
    cur = output_dir.resolve()
    if cur.name == "security" and cur.parent.name == "docs":
        return cur.parent.parent  # conventional <repo>/docs/security layout
    for cand in (cur, *list(cur.parents)[:6]):
        if (cand / ".git").exists() or (cand / "package.json").is_file():
            return cand
    return cur


def _glob_files(repo_root: Path, patterns) -> list[str]:
    hits: set[str] = set()
    for pat in patterns:
        try:
            for p in repo_root.glob(pat):
                if p.is_file():
                    hits.add(p.relative_to(repo_root).as_posix())
        except (OSError, ValueError):
            continue
    return sorted(hits)


def _package_deps(repo_root: Path) -> dict:
    pj = repo_root / "package.json"
    if not pj.is_file():
        return {}
    try:
        data = json.loads(pj.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    deps: dict = {}
    for k in ("dependencies", "devDependencies", "optionalDependencies"):
        d = data.get(k)
        if isinstance(d, dict):
            deps.update(d)
    return deps


def _detect_cicd(repo_root: Path) -> dict | None:
    files = _glob_files(repo_root, _CI_GLOBS)
    if not files:
        return None
    paths: list[str] = []
    if any(f.startswith(".github/workflows/") for f in files):
        paths.append(".github/workflows/**")
    paths += [f for f in files if not f.startswith(".github/workflows/")]
    sample = ", ".join(files[:4]) + (", …" if len(files) > 4 else "")
    return {
        "id": "ci-cd-pipeline",
        "name": "CI/CD Pipeline",
        "description": (
            f"Continuous-integration / deployment workflows ({sample}). Build and "
            "release automation holding repository, registry and deploy credentials, "
            "with supply-chain reach into the produced artifact."
        ),
        "paths": paths or files,
        "tier": "application",
        "complexity": "simple",
        "framework": None,
        "deployment_zones": ["ci-cd-runtime", "build-pipeline"],
        "handles_sensitive_data": True,
        "origin": "reconciliation",
    }


def _detect_realtime(repo_root: Path) -> dict | None:
    deps = _package_deps(repo_root)
    # socket.io is the SERVER lib; socket.io-client is the browser side — a
    # client-only dependency is not its own server component, so ignore it.
    lib = next((d for d in ("socket.io", "ws", "@socket.io/admin-ui") if d in deps), None)
    if not lib:
        return None
    # Precise paths: the source files that actually wire the realtime server,
    # so the incremental dirty-set does not couple every lib/ change to it.
    needle = "socket.io" if lib in ("socket.io", "@socket.io/admin-ui") else lib
    sites: list[str] = []
    for rel in ("server.ts", "server.js", "app.ts", "app.js"):
        sites += _grep_paths(repo_root, rel, needle)
    for d in ("lib", "src"):
        sites += _grep_paths(repo_root, d, needle)
    paths = sorted(set(sites))[:12] or ["server.ts", "app.ts"]
    return {
        "id": "realtime-channel",
        "name": "Real-time WebSocket Channel",
        "description": (
            f"Server-side {lib} real-time channel pushing live events to connected "
            "browsers. Internet-facing WebSocket surface with its own connection "
            "auth/origin checks and message-handler trust boundary."
        ),
        "paths": paths,
        "tier": "application",
        "complexity": "simple",
        "framework": lib,
        "deployment_zones": ["internet", "dmz"],
        "handles_sensitive_data": False,
        "origin": "reconciliation",
    }


def _grep_paths(repo_root: Path, rel: str, needle: str, *, limit: int = 400) -> list[str]:
    """Relative paths of source files under ``rel`` whose content mentions
    ``needle``. Bounded scan; returns [] on any error or missing path."""
    base = repo_root / rel
    out: list[str] = []
    try:
        if base.is_file():
            cands = [base]
        elif base.is_dir():
            cands = [p for p in base.rglob("*") if p.is_file() and p.suffix.lower() in _SRC_SUFFIXES][:limit]
        else:
            return []
        for p in cands:
            try:
                if needle in p.read_text(encoding="utf-8", errors="ignore"):
                    out.append(p.relative_to(repo_root).as_posix())
            except OSError:
                continue
    except OSError:
        return []
    return out


def _detect_auth(repo_root: Path) -> dict | None:
    cands: set[str] = set()
    for d in _AUTH_SCAN_DIRS:
        base = repo_root / d
        if not base.is_dir():
            continue
        try:
            for p in base.rglob("*"):
                if p.is_file() and p.suffix.lower() in _SRC_SUFFIXES and _AUTH_FILE_RE.search(p.stem):
                    cands.add(p.relative_to(repo_root).as_posix())
        except OSError:
            continue
    paths = sorted(cands)[:25]
    if not paths:
        return None
    sample = ", ".join(paths[:4]) + (", …" if len(paths) > 4 else "")
    return {
        "id": "auth",
        "name": "Authentication & Session Surface",
        "description": (
            f"Login, token/session issuance, password-reset and MFA handlers ({sample}). "
            "The credential-bearing entry surface — the highest-value authentication "
            "boundary in the system."
        ),
        "paths": paths,
        "tier": "application",
        "complexity": "moderate",
        "framework": None,
        "deployment_zones": ["internet", "dmz"],
        "handles_sensitive_data": True,
        "origin": "reconciliation",
    }


# (role-predicate, detector) pairs. A detected unit is injected only when NO
# enumerated component already carries the role.
_RECONCILE_DETECTORS = (
    (_is_auth, _detect_auth),
    (_is_cicd, _detect_cicd),
    (_is_realtime, _detect_realtime),
)


def reconcile_inventory(components: list, repo_root: Path) -> tuple:
    """Inject security-relevant deployable units that hard repo evidence shows
    exist but Phase-3 did not enumerate as their own role-bearing component.

    Returns ``(augmented_components, injected)``. Idempotent: a role already
    carried by an enumerated (or already-injected) component is never added
    twice. Injected components carry ``origin: "reconciliation"`` for audit.
    """
    existing = [c for c in components if isinstance(c, dict)]
    augmented = list(existing)
    injected: list[dict] = []
    for role_pred, detect in _RECONCILE_DETECTORS:
        if any(role_pred(c) for c in augmented):
            continue  # role already covered — do not duplicate
        cand = detect(repo_root)
        if cand and not any(c.get("id") == cand.get("id") for c in augmented):
            augmented.append(cand)
            injected.append(cand)
    return augmented, injected


def select_stride_components(components: list, depth: str, ceiling: int | None = None) -> tuple:
    """Derive the STRIDE-analyzed subset from criteria — count is emergent.

    Returns ``(selected, report)``. ``report`` is a JSON-serializable dict with
    the included/excluded sets, their reasons, and whether an operational ceiling
    forced (logged) overflow drops.

    Back-compat / fail-safe: when NO component carries deployment_zones (an
    un-migrated .components.json — today's shape, already LLM-pre-selected), the
    predicate is skipped and ALL components pass through. This makes the change
    strictly non-regressive until the Phase-3 full-inventory authoring lands.
    """
    comps = [c for c in components if isinstance(c, dict) and c.get("id")]
    migrated = any(_zones(c) for c in comps)

    if not migrated:
        report = {
            "mode": "passthrough",
            "depth": depth,
            "reason": "no deployment_zones in .components.json — un-migrated",
            "selected": [c["id"] for c in comps],
            "excluded": [],
            "lifted": False,
            "ceiling": ceiling,
        }
        return comps, report

    selected = [c for c in comps if _in_scope(c, depth)]
    excluded = [c for c in comps if c not in selected]
    lifted = False
    overflow_dropped = []

    if ceiling and len(selected) > ceiling:
        # The ceiling may ONLY shed genuinely-internal components (selected at
        # thorough purely for completeness). Anything that earned its place by a
        # positive criterion — exposure, ci-cd/supply-chain, crown-jewel, auth,
        # frontend, or exposure-unknown fail-safe — is NEVER silently dropped;
        # the ceiling lifts (logged) instead. Dropping those would recreate the
        # whole-component blind spots this redesign exists to remove.
        internal = [c for c in selected if _is_internal_only(c)]
        n_over = len(selected) - ceiling
        overflow_dropped = internal[:n_over] if n_over > 0 else []
        selected = [c for c in selected if c not in overflow_dropped]
        lifted = len(selected) > ceiling  # earned set alone still exceeds ceiling
        excluded = excluded + overflow_dropped

    report = {
        "mode": "criteria",
        "depth": depth,
        "ceiling": ceiling,
        "lifted": lifted,
        "selected": [
            {"id": c["id"], "priority": _priority(c), "reasons": _selection_reasons(c, depth)} for c in selected
        ],
        "excluded": [
            {
                "id": c["id"],
                "reason": ("ceiling-overflow" if c in overflow_dropped else "out-of-scope at depth=" + depth),
            }
            for c in excluded
        ],
    }
    return selected, report


def build(output_dir: Path, depth: str, analyst_context: dict, plugin_root: Path, ceiling: int | None = None) -> dict:
    import datetime as _dt

    dp = _depth_params()
    turns = dp.get(depth, dp.get("standard"))

    cj = _read_json(output_dir / ".components.json", {})
    all_components = cj.get("components", cj) if isinstance(cj, dict) else cj
    if not isinstance(all_components, list):
        all_components = []

    # Enumeration-completeness reconciliation: restore security-relevant units
    # (auth / ci-cd / real-time) that Phase-3 folded into a coarser parent. The
    # augmented inventory is persisted so it is the single source of truth for
    # the selector here, the STRIDE fan-out, AND the downstream threat-model.yaml
    # / heatmap / §1 scope (build_threat_model_yaml reads .components.json).
    repo_root = _guess_repo_root(output_dir)
    all_components, injected = reconcile_inventory(all_components, repo_root)
    if injected:
        payload = dict(cj) if isinstance(cj, dict) else {}
        payload.setdefault("schema_version", 1)
        payload["components"] = all_components
        try:
            (output_dir / ".components.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError:
            pass
        sys.stderr.write(
            "RECONCILE: injected "
            + ", ".join(c["id"] for c in injected)
            + " — security-relevant unit(s) evidenced in repo but absent from "
            "Phase-3 enumeration (role-folded). Now in scope.\n"
        )

    components, selection_report = select_stride_components(all_components, depth, ceiling)
    # Persist the selection rationale so a run is auditable (which components were
    # analyzed and why) and so EXPOSURE_CAP_LIFT can be post-hoc verified.
    try:
        (output_dir / ".stride-selection.json").write_text(json.dumps(selection_report, indent=2), encoding="utf-8")
    except OSError:
        pass

    boundaries = (_read_json(output_dir / ".trust-boundaries.json", {}) or {}).get("trust_boundaries", [])

    out_components = []
    for c in components:
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        if not cid:
            continue
        ctx = analyst_context.get(cid, {}) if isinstance(analyst_context, dict) else {}
        complexity = (c.get("complexity") or "moderate").lower()

        def _idx(rel: str) -> str:
            p = output_dir / rel
            return str(p) if p.is_file() else "none"

        tax = output_dir / ".taxonomy-slices" / cid
        comp = {
            "component_id": cid,
            "component_name": c.get("name", cid),
            "component_description": c.get("description", ""),
            "component_paths": c.get("paths", []),
            "component_complexity": complexity if complexity in ("simple", "moderate", "complex") else "moderate",
            "max_turns": int(turns.get(complexity, turns.get("moderate", 22))),
            "trust_boundaries": _trust_boundaries_for(cid, boundaries),
            "taxonomy_slice_dir": str(tax) if tax.is_dir() else str(plugin_root / "data"),
            # Carry the selection-criteria inputs through to the manifest so the
            # selection is auditable downstream (and not silently dropped here).
            "deployment_zones": c.get("deployment_zones") or [],
            "handles_sensitive_data": bool(c.get("handles_sensitive_data", False)),
            "index_paths": {
                "prior_findings": _idx(f".dispatch-context/{cid}/prior-findings.json"),
                "known_threats": _idx(f".dispatch-context/{cid}/known-threats.json"),
                "cross_repo": _idx(f".dispatch-context/{cid}/cross-repo.json"),
                "requirements_violations": _idx(f".dispatch-context/{cid}/requirements-violations.json"),
                "relevant_actors": _idx(f".actors-for-{cid}.json"),
            },
        }
        # Merge contextual (analyst-supplied) fields when present. The analyst
        # is an LLM and sometimes emits a richer dict shape (e.g. controls as a
        # {control: description} map) where the manifest schema + the STRIDE
        # analyzer expect a flat text string. Normalize dict-shaped text fields
        # to "key: value; ..." here at the deterministic LLM→schema boundary so
        # validate_dispatch_manifest.py does not reject the manifest.
        for k in (
            "interfaces",
            "controls",
            "known_secrets",
            "known_vulns",
            "known_llm_patterns",
            "supply_chain_findings",
            "estimated_threat_count",
            "focus_paths",
            "exclude_paths",
        ):
            if k in ctx and ctx[k] not in (None, "", []):
                v = ctx[k]
                if isinstance(v, dict):
                    v = "; ".join(f"{kk}: {vv}" for kk, vv in v.items())
                # Schema requires estimated_threat_count as integer; the LLM
                # sometimes emits it as a string label ("low", "high", …).
                if k == "estimated_threat_count":
                    _etc_map = {"low": 3, "medium": 6, "high": 12, "very_high": 20}
                    if isinstance(v, int):
                        pass  # already correct type
                    elif isinstance(v, str):
                        label = v.lower().strip()
                        if label in _etc_map:
                            v = _etc_map[label]
                        else:
                            try:
                                v = int(label)
                            except ValueError:
                                v = 3
                    else:
                        try:
                            v = int(v)
                        except (TypeError, ValueError):
                            v = 3
                comp[k] = v
        out_components.append(comp)

    return {
        "schema_version": 1,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stride_profile": analyst_context.get("_stride_profile", "full")
        if isinstance(analyst_context, dict)
        else "full",
        "components": out_components,
    }


def format_selection_console(sel: dict) -> str:
    """Render the STRIDE component selection as a human-readable console block:
    which components are analyzed (and why) and which are skipped (and why).

    Reads the already-persisted ``.stride-selection.json`` shape, so it handles
    both ``mode=criteria`` (selected/excluded are reason-bearing dicts) and the
    ``mode=passthrough`` fail-safe (selected is a flat id list, excluded empty).
    """
    mode = sel.get("mode", "?")
    depth = sel.get("depth", "?")
    selected = sel.get("selected", []) or []
    excluded = sel.get("excluded", []) or []
    lines = [f"STRIDE component selection (depth={depth}, mode={mode}):"]

    if mode == "passthrough":
        ids = [s if isinstance(s, str) else s.get("id", "?") for s in selected]
        lines.append(f"  ANALYZED ({len(ids)}): " + (", ".join(ids) or "(none)"))
        lines.append(
            "  SKIPPED (0): per-component criteria unavailable — un-migrated "
            "inventory (no deployment_zones); all components analyzed."
        )
        return "\n".join(lines)

    lines.append(f"  ANALYZED ({len(selected)}):")
    for c in selected:
        reasons = "; ".join(c.get("reasons") or []) or "selected"
        lines.append(f"    - {c.get('id', '?')} — {reasons}")
    lines.append(f"  SKIPPED ({len(excluded)}):")
    if not excluded:
        lines.append("    (none)")
    for c in excluded:
        lines.append(f"    - {c.get('id', '?')} — {c.get('reason', 'excluded')}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="build_stride_dispatch_manifest.py")
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--depth", default="standard", choices=["quick", "standard", "thorough"])
    ap.add_argument("--analyst-context", type=Path, default=None)
    ap.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument(
        "--ceiling",
        type=int,
        default=None,
        help="Operational safety ceiling on the selected component count "
        "(merge/turn-budget guard). NOT the selection number — auth/"
        "frontend/exposed are never dropped (cap lifts with a log). "
        "Omit for unbounded (the recon hint cap already bounds the inventory).",
    )
    ns = ap.parse_args(argv)

    ctx = _read_json(ns.analyst_context, {}) if ns.analyst_context else {}
    manifest = build(ns.output_dir, ns.depth, ctx, ns.plugin_root, ceiling=ns.ceiling)
    if not manifest["components"]:
        print("ERROR: no components found in .components.json — nothing to dispatch.", file=sys.stderr)
        return 1
    sel = _read_json(ns.output_dir / ".stride-selection.json", {})
    out = ns.output_dir / ".stride-dispatch-manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(
        f"OK: wrote {out} ({len(manifest['components'])} components, depth={ns.depth}, "
        f"selection={sel.get('mode', '?')})"
    )
    print(format_selection_console(sel))
    if sel.get("lifted"):
        n_sel = len(sel.get("selected", []))
        n_drop = len([e for e in sel.get("excluded", []) if e.get("reason") == "ceiling-overflow"])
        tail = f"; dropped {n_drop} internal-only component(s)" if n_drop else ""
        print(
            f"EXPOSURE_CAP_LIFT: {n_sel} earned components exceed the operational ceiling "
            f"({ns.ceiling}) — analyzing all (no exposed/ci-cd/crown-jewel/auth/frontend "
            f"component dropped; STRIDE merge/turn-budget may be stressed){tail}."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
