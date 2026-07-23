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


def _cat13_supplement(output_dir: Path) -> str:
    """Return a deterministic `known_llm_patterns` supplement from Cat-13 recon findings.

    Reads `.recon-patterns.json` if present (written by Phase 2 Step 0 before
    STRIDE dispatch). Returns a "; "-joined string of "subcategory: file:line"
    entries, capped at 10, or "" when the file is absent or Cat-13 is empty.
    Used to enrich a sparse analyst-authored `known_llm_patterns` field so the
    STRIDE analyzer has concrete file:line anchors for every LLM code pattern.
    """
    rp = output_dir / ".recon-patterns.json"
    if not rp.is_file():
        return ""
    try:
        data = json.loads(rp.read_text(encoding="utf-8"))
        findings = data.get("categories", {}).get("13", {}).get("findings", [])
    except Exception:
        return ""
    # Prioritise the anchors the STRIDE analyzer actually needs: STRONG signals
    # (real SDK / framework / agent / model-id — the integration code) before
    # WEAK ones, and one anchor per file so a repo with many static prompt-data
    # lines (e.g. juice-shop's challenges.yml) cannot crowd out the genuine
    # routes/chat.ts integration point under the 10-entry cap.
    findings = sorted(findings, key=lambda f: 0 if f.get("strength") == "strong" else 1)
    parts, seen_files = [], set()
    for f in findings:
        fpath = f.get("file", "")
        if not fpath or fpath in seen_files:
            continue
        seen_files.add(fpath)
        subcat = f.get("subcategory", "llm-sdk")
        line = f.get("line", "")
        loc = f"{fpath}:{line}" if line else fpath
        parts.append(f"{subcat}: {loc}")
        if len(parts) >= 10:
            break
    return "; ".join(parts)


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
# Internet/client-reachable zones. The architecture phase emits these as free
# text, so the SAME exposure is labelled many ways — a juice-shop run tagged its
# Socket.IO channel and Multer file-upload handler `internet-facing` (and others
# `external` / `browser`), none of which matched the old narrow set, so both
# genuinely-exposed components were mis-classified internal-only and dropped at
# standard depth. Match the common synonyms, not just the canonical token.
EXPOSED_ZONES = frozenset(
    {
        "internet",
        "internet-facing",
        "internet-exposed",
        "public-internet",
        "public",
        "public-facing",
        "publicly-accessible",
        "externally-reachable",
        "external",
        "edge",
        "dmz",
        "client-device",
        "mobile-device",
        "browser",
        "web-browser",
    }
)
CICD_ZONES = frozenset({"ci-cd-runtime", "ci-cd-secrets", "build-pipeline", "deployment-pipeline"})
# Canonical NON-exposed placement zones from the access-zone vocabulary
# (data/actors/default-library.yaml / schemas/fragments/components.schema.json).
# A component tagged with one of these has a KNOWN internal placement — it is
# "proven-internal" (sheddable at the ceiling), NOT exposure-unknown.
INTERNAL_ZONES = frozenset({"internal-network", "peer-service", "prod-env", "prod-write-db"})
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


# Zone tokens that carry a RECOGNISED placement/reachability signal. A token
# outside this vocabulary tells us nothing about reachability and must NOT be
# read as "proven internal".
_REACHABILITY_VOCAB = EXPOSED_ZONES | CICD_ZONES | INTERNAL_ZONES


def _reachability_zones(c: dict) -> set:
    """Deployment zones that actually carry an internet-reachability signal.

    Only tokens in the canonical zone vocabulary count. Two kinds of token are
    filtered out so the selection's exposure-UNKNOWN fail-safe fires instead of
    the "zones present → treat as internal-only" path that silently drops a
    component:

    * runtime/where-it-runs tags (``RUNTIME_ONLY_ZONES``) — a component tagged
      only ``docker-container`` is exposure-unknown, not internal (2026-06-12
      b2b-api regression);
    * off-vocabulary labels the LLM invented (e.g. ``application-zone`` /
      ``data-zone`` / ``build-zone``) — these matched no zone set, so the whole
      zonal exposure/ci-cd signal was silently inert and an off-vocab component
      was mis-read as proven-internal (2026-07-23 spring-app regression).
    """
    return _zones(c) & _REACHABILITY_VOCAB


def _unknown_zone_tokens(c: dict) -> set:
    """Zone tokens matching no known vocabulary (neither a placement/reachability
    zone nor a runtime tag). These are analyst drift and make the zonal exposure
    signal silently inert — surfaced so the upstream output gets corrected."""
    return _zones(c) - _REACHABILITY_VOCAB - RUNTIME_ONLY_ZONES


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
_REALTIME_RE = re.compile(r"\b(socket\.?io|web-?socket|real-?time|socket|stomp|sse|pub-?sub)\b", re.I)


def _is_realtime(c: dict) -> bool:
    return bool(_REALTIME_RE.search(_component_text(c)))


# Web3 / wallet / NFT role. Matched against id/name/type only (via
# _component_text), so a generic backend that merely *mentions* web3 in its
# prose description does NOT count as carrying the role — only a component
# whose stable label is actually a web3/wallet/NFT unit suppresses injection.
_WEB3_HINTS = (
    "web3",
    "nft",
    "blockchain",
    "ethereum",
    "wallet",
    "smart-contract",
    "smartcontract",
    "dapp",
    "defi",
    "crypto-wallet",
)


def _is_web3(c: dict) -> bool:
    return any(h in _component_text(c) for h in _WEB3_HINTS)


# AI/LLM role. An LLM/AI-agent surface carries inherent OWASP-LLM-Top-10 risk
# (prompt injection, excessive agency, system-prompt leakage, unbounded
# consumption) regardless of deployment zone — an "internal" LLM endpoint is
# still reachable through the data it ingests. So an AI/LLM component is
# MANDATORY at every depth and is never shed as internal-only (2026-06-23:
# juice-shop's `llm-chat-service`, tagged zone=internal, was dropped at standard
# depth — "out-of-scope at depth=standard" — leaving the whole chatbot prompt-
# injection / tool-use surface unanalyzed; cf. the deterministic recon cat-13
# detector that now reliably identifies these components). Word-boundary matched
# against id/name/type AND the structured tech_stack[] (NOT the prose
# description, which over-matches — same rule as the other role predicates).
_LLM_RE = re.compile(
    r"\b(llm|chat-?bot|gen-?ai|generative-ai|openai|anthropic|langchain"
    r"|llama-?index|ollama|copilot|gpt-?[0-9]|claude-[0-9a-z]|gemini-[0-9]"
    r"|bedrock|vertex-ai|ai-(?:chat|agent|assistant|service|gateway))\b",
    re.I,
)


def _is_llm(c: dict) -> bool:
    # A populated `known_llm_patterns` is an affirmative analyst/recon flag that
    # this component carries an LLM surface — honour it even when id/name/type
    # and tech_stack name no LLM token. The enumerator sometimes FOLDS a chatbot
    # into a generically-named unit (e.g. juice-shop's chat route folded into
    # "express-backend"); the LLM signal then lives ONLY in known_llm_patterns.
    # Without this branch the mandatory floor, the OWASP-LLM-Top-10 dispatch
    # reason, and the Cat-13 supplement (all gated on _is_llm) silently skip the
    # folded component, dropping LLM07/LLM10 and the AI/LLM Exposure section.
    klp = c.get("known_llm_patterns")
    if klp and (klp if isinstance(klp, str) else " ".join(str(x) for x in klp)).strip():
        return True
    stack = " ".join(str(x) for x in (c.get("tech_stack") or []))
    return bool(_LLM_RE.search(_component_text(c)) or _LLM_RE.search(stack))


# File-upload / file-processing role. A unit that accepts and parses
# user-supplied files carries severe, zone-independent risk — unrestricted
# upload (CWE-434), zip/path traversal, XXE, archive bombs, parser/
# deserialization RCE — even when deployed "internally". Matched on id/name/type
# AND tech_stack[] (multer/busboy/formidable/multipart parsers); description is
# excluded for the same over-match reason as the other role predicates.
_FILE_UPLOAD_RE = re.compile(
    r"\b(file-?upload|upload(?:er|s)?|multer|busboy|formidable|multipart"
    r"|attachment|media-?upload|image-?upload|document-?upload|file-?(?:handler|processor|ingest))\b",
    re.I,
)


def _is_file_upload(c: dict) -> bool:
    stack = " ".join(str(x) for x in (c.get("tech_stack") or []))
    return bool(_FILE_UPLOAD_RE.search(_component_text(c)) or _FILE_UPLOAD_RE.search(stack))


# Data-store / persistence / secrets / queue role. A component that stores or
# brokers data carries STRIDE-relevant risk — SQL/NoSQL injection, tampering,
# information disclosure, and (for secrets stores / queues) credential exposure
# and message spoofing — REGARDLESS of the `handles_sensitive_data` flag. Recon
# under-tagging a SQL DB as non-sensitive must NOT drop it: a type-anchor exactly
# like _is_file_upload (CWE-434), independent of the crown-jewel flag. The real
# .components.json carries no `component_type`/`type` field, so the store signal
# lives in id/name (via _component_text) and the structured `framework` /
# `tech_stack` engine tokens — component_type is matched too for forward-compat
# with recon component-hints. Description is excluded (same over-match rule as
# the other role predicates). Word-boundary matched so short tokens (`db`, `mq`)
# do not fire inside unrelated words.
_DATASTORE_RE = re.compile(
    r"\b(store|datastore|data-?layer|data-?persistence|persistence|database|db"
    r"|message-?queue|mq|rabbitmq|kafka|sqs|secrets?-?(?:store|manager)|vault"
    r"|cache|redis|memcached|postgres(?:ql)?|mysql|mariadb|sqlite|mssql"
    r"|sql-?server|oracle-?db|mongo(?:db)?|dynamo(?:db)?|cassandra)\b",
    re.I,
)


def _is_datastore(c: dict) -> bool:
    structured = " ".join(
        str(x)
        for x in (
            *(c.get("tech_stack") or []),
            c.get("framework") or "",
            c.get("component_type") or "",
        )
    )
    return bool(_DATASTORE_RE.search(_component_text(c)) or _DATASTORE_RE.search(structured))


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
    return not (
        _is_exposed(c)
        or _is_cicd(c)
        or _is_crown_jewel(c)
        or _is_datastore(c)
        or _is_auth(c)
        or _is_frontend(c)
        or _is_llm(c)
        or _is_realtime(c)
        or _is_file_upload(c)
    )


def _priority(c: dict) -> int:
    """Lower = kept first when an operational ceiling forces overflow drops."""
    if _is_auth(c):
        return 0  # M3.4 invariant — never drop
    if _is_frontend(c):
        return 1  # frontend attack-surface invariant — never drop
    if _is_llm(c):
        return 2  # AI/LLM surface — OWASP LLM Top-10 risk, never drop
    if _is_exposed(c):
        return 2  # directly reachable by an external actor — never drop (cap lifts)
    if _is_crown_jewel(c) or _is_datastore(c):
        return 3  # crown-jewel / data-store — SQLi/tampering/info-disclosure, never drop
    if _is_file_upload(c) or _is_realtime(c):
        return 3  # untrusted-input entry point (upload parser / realtime channel) — never drop
    if _is_cicd(c):
        return 4
    return 5  # internal-only / transitively-reachable — drop first


def _selection_reasons(c: dict, depth: str) -> list:
    reasons = []
    if _is_auth(c):
        reasons.append("auth (M3.4 mandatory)")
    if _is_frontend(c):
        reasons.append("frontend attack surface (mandatory)")
    if _is_llm(c):
        reasons.append("AI/LLM surface (OWASP LLM Top-10 — prompt injection / excessive agency, mandatory)")
    if _is_exposed(c):
        reasons.append(f"internet-exposed ({','.join(sorted(_zones(c) & EXPOSED_ZONES))})")
    if depth != "quick" and _is_cicd(c):
        reasons.append("ci-cd / deployment (supply-chain boundary)")
    if depth != "quick" and _is_crown_jewel(c):
        reasons.append("crown-jewel (credentials/PII/payment/secrets)")
    if depth != "quick" and _is_datastore(c) and not _is_crown_jewel(c):
        reasons.append("data-store (SQLi/tampering/info-disclosure — type anchor, sensitive-flag-independent)")
    if depth != "quick" and _is_file_upload(c):
        reasons.append("file-upload surface (CWE-434 / zip-path traversal / XXE / parser RCE, mandatory)")
    if depth != "quick" and _is_realtime(c):
        reasons.append("real-time channel (message injection / channel authz, mandatory)")
    if depth == "thorough" and not reasons:
        reasons.append("transitively reachable (thorough)")
    if not _reachability_zones(c) and not _is_auth(c) and not _is_frontend(c):
        reasons.append("exposure-unknown (fail-safe inclusion)")
    return reasons


def _in_scope(c: dict, depth: str) -> bool:
    # Role-floor: auth + frontend + AI/LLM are mandatory at every depth.
    if _is_auth(c) or _is_frontend(c) or _is_llm(c):
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
    if _is_cicd(c) or _is_crown_jewel(c) or _is_datastore(c) or _is_file_upload(c) or _is_realtime(c):
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
# Supply-chain / build-config file surface owned by the ci-cd-pipeline
# component. These are the files the config/IaC scanner reports against and
# that merge_threats binds to component_id="ci-cd-pipeline"; the component's
# `paths` must glob them so those findings are not flagged as cross-component
# drift. See _detect_cicd().
_CICD_SUPPLYCHAIN_GLOBS = (
    "Dockerfile",
    "Dockerfile.*",
    "*.Dockerfile",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose*.yml",
    "compose*.yaml",
    ".dockerignore",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    ".npmrc",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    ".github/renovate.json",
    "renovate.json",
    ".renovaterc",
    ".renovaterc.json",
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


def _auth_evidence_files(output_dir: Path) -> list[str]:
    """Files the deterministic source-auth scanner flagged, or [] if unavailable."""
    try:
        raw = json.loads((output_dir / ".source-auth-findings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    findings = raw.get("findings", raw) if isinstance(raw, dict) else raw
    if not isinstance(findings, list):
        return []
    return sorted({f.get("file", "") for f in findings if isinstance(f, dict) and f.get("file")})


def _evidence_complexity_floor(paths: list, auth_files: list[str], claimed: str) -> tuple[str, str]:
    """Raise a component's complexity when it owns authentication code.

    The complexity that reaches this module comes from `.components.json`, which
    is authored by the analyst LLM -- so it is a judgement, not a measurement,
    and it drifts between runs of the same commit. On 2026-07-20 the component
    holding JWT signing, password hashing, login and 2FA was named `auth-service`
    and rated *moderate*; an earlier run of the same repo rated the same code
    *complex*. The smaller tier gave it the smaller turn budget, and it stalled.

    Naming rules cannot fix this: the next inventory may call it
    `identity-provider` or `session-manager`. `.source-auth-findings.json` is
    produced by a deterministic scanner during pre-flight, before any of this
    runs, so "does this component own authentication code" is answerable from
    evidence rather than from what the component was called.
    """
    if not auth_files or claimed == "complex":
        return claimed, ""
    owned = [f for f in auth_files if _path_owns(paths, f)]
    if not owned:
        return claimed, ""
    sample = ", ".join(owned[:2]) + (" …" if len(owned) > 2 else "")
    return "complex", f"auth evidence in {len(owned)} file(s) ({sample})"


def _component_max_turns(repo_root: Path, patterns, tier_turns: int) -> int:
    """Turn budget for one component: complexity tier raised by file footprint.

    Globbing is best-effort -- an unreadable or pathological pattern falls back
    to the tier budget rather than failing manifest construction.
    """
    try:
        import classify_component  # noqa: PLC0415

        file_count = len(_glob_files(repo_root, _expand_recursive(patterns or [])))
        floored, _ = classify_component._footprint_turn_floor(file_count, tier_turns)
        return int(floored)
    except Exception:
        return int(tier_turns)


def _expand_recursive(patterns) -> list[str]:
    """Rewrite a trailing bare ``**`` to ``**/*`` so files are counted.

    ``Path.glob("routes/**")`` yields only DIRECTORIES -- the recursive wildcard
    matches path segments, not the entries inside them. Since ``_glob_files``
    keeps only ``is_file()`` hits, a bare ``**`` pattern counts zero. Component
    inventories use exactly that form (``routes/**``, ``frontend/**``), so the
    footprint floor was blind to the widest components: backend-api counted 2
    files instead of ~700, frontend-spa 0 instead of 637.
    """
    expanded: list[str] = []
    for pattern in patterns:
        expanded.append(pattern)
        if pattern.endswith("**"):
            expanded.append(f"{pattern}/*")
    return expanded


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
    # The config/IaC scanner (config-iac-checks.yaml) emits its findings against
    # the build/supply-chain file surface — Dockerfile, container compose,
    # package manifests + lockfiles, and Dependabot/Renovate config — and
    # `merge_threats._config_finding_to_threat` hardcodes them to this
    # ci-cd-pipeline component. Without these globs in the component's `paths`,
    # every such finding tripped the `validate_intermediate` path-glob advisory
    # (evidence file vs component globs) AND `reclassify_components` could not
    # move it anywhere (no other component globs a root Dockerfile/package.json),
    # so the advisory was emitted on every run with no way to self-heal. The
    # ci-cd-pipeline component IS the supply-chain boundary, so these files
    # legitimately belong to it — declare them as part of its scope. Patterns
    # only (existence-independent); a glob matching nothing is a harmless no-op.
    for g in _CICD_SUPPLYCHAIN_GLOBS:
        if g not in paths:
            paths.append(g)
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


# Web3/wallet/NFT crypto-asset surface. A distinct, high-value security unit
# (on-chain key material, wallet-ownership proofs, NFT minting) that Phase-3
# routinely FOLDS into a generic backend at standard depth — the deterministic
# route inventory sees `/rest/web3/*` but no `web3` component is enumerated, so
# the selector has nothing to pick and a whole crypto surface is never analyzed
# (2026-06-21 juice-shop: standard missed the Critical hardcoded BIP-39 mnemonic
# in routes/checkKeys.ts; thorough carved out `web3-nft` and found it). Detected
# by a web3 dependency (ethers/web3/bip39/…) OR web3-signalling source content.
_WEB3_DEPS = (
    "ethers",
    "web3",
    "web3.js",
    "ethereumjs-wallet",
    "ethereumjs-tx",
    "ethereumjs-util",
    "bip39",
    "bip32",
    "hdkey",
    "@ethersproject/wallet",
    "hardhat",
    "solc",
    "merkletreejs",
    "keccak",
    "@openzeppelin/contracts",
)
# Content signal — word-boundary matched so a stray "ether" inside another word
# does not fire. Deliberately omits the bare token "wallet" (too broad in
# content) while keeping the specific web3Wallet/walletNFT identifiers.
_WEB3_CONTENT_RE = re.compile(
    r"\b(web3|ethers|nft|mnemonic|blockchain|ethereum|bip-?39|bip-?32|"
    r"web3wallet|walletnft|smart[- ]?contract)\b",
    re.I,
)
# Scan route-handler / contract dirs only — NOT shared `lib/` (where a web3
# token in e.g. lib/insecurity.ts would wrongly claim the auth component's file
# for web3-nft and create cross-component path overlap). The web3 surface is its
# route handlers; the dep signal already covers detection regardless of layout.
_WEB3_SCAN_DIRS = ("routes", "src", "contracts", "blockchain", "api")


def _detect_web3(repo_root: Path) -> dict | None:
    deps = _package_deps(repo_root)
    dep_lib = next((d for d in _WEB3_DEPS if d in deps), None)
    sites: set[str] = set()
    for d in _WEB3_SCAN_DIRS:
        base = repo_root / d
        if not base.is_dir():
            continue
        try:
            cands = [p for p in base.rglob("*") if p.is_file() and p.suffix.lower() in _SRC_SUFFIXES][:400]
        except OSError:
            continue
        for p in cands:
            try:
                if _WEB3_CONTENT_RE.search(p.read_text(encoding="utf-8", errors="ignore")):
                    sites.add(p.relative_to(repo_root).as_posix())
            except OSError:
                continue
    paths = sorted(sites)[:12]
    if not dep_lib and not paths:
        return None  # no evidence — safe no-op
    if not paths:
        paths = ["routes/**"]  # dep present but no source matched — broad fallback
    return {
        "id": "web3-nft",
        "name": "Web3 / Wallet / NFT Surface",
        "description": (
            "Blockchain/web3 endpoints handling wallet addresses, NFT minting, and "
            "on-chain key material"
            + (f" ({dep_lib})" if dep_lib else "")
            + ". Internet-facing crypto-asset surface with its own key-handling and "
            "ownership-verification trust boundary."
        ),
        "paths": paths,
        "tier": "application",
        "complexity": "moderate",
        "framework": dep_lib,
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
    (_is_web3, _detect_web3),
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


def _path_owns(paths: list, fpath: str) -> bool:
    """True when a component `paths` entry contains (or globs over) `fpath`.
    Glob tails are stripped to a directory prefix (``routes/**`` → ``routes``)."""
    fp = str(fpath).replace("\\", "/")
    for p in paths or []:
        pp = str(p).replace("\\", "/").rstrip("/")
        base = pp.split("*")[0].rstrip("/")
        if not base:
            continue
        if fp == base or fp.startswith(base + "/"):
            return True
    return False


def _seed_llm_role(components: list, output_dir: Path, analyst_context: dict) -> list:
    """Make the LLM role visible to the selection predicates BEFORE the analyst-
    context merge runs (build() merges `known_llm_patterns` only into the OUTPUT
    component, long after selection has already decided scope). Without this, a
    chatbot folded into a generically-named unit escapes the mandatory _is_llm
    floor, the OWASP-LLM-Top-10 dispatch reason, and the Cat-13 supplement.

    Two deterministic sources, in order:
      1. analyst_context[cid]['known_llm_patterns'] — the analyst's own flag.
      2. Cat-13 recon STRONG findings whose file falls under a component's
         `paths` — a code-traceable LLM surface even when the analyst omitted
         the flag. This is the fully deterministic bridge from recon to STRIDE.

    Mutates and returns `components`."""
    if isinstance(analyst_context, dict):
        for c in components:
            if isinstance(c, dict) and c.get("id"):
                klp = analyst_context.get(c["id"], {}).get("known_llm_patterns")
                if klp and not c.get("known_llm_patterns"):
                    c["known_llm_patterns"] = klp
    if any(isinstance(c, dict) and c.get("known_llm_patterns") for c in components):
        return components  # already flagged (analyst or prior seeding)
    data = _read_json(output_dir / ".recon-patterns.json", {})
    strong = [
        f
        for f in (data.get("categories", {}) or {}).get("13", {}).get("findings", [])
        if isinstance(f, dict) and f.get("strength") == "strong" and f.get("file")
    ]
    if not strong:
        return components
    for c in components:
        if not isinstance(c, dict):
            continue
        owned = [f for f in strong if _path_owns(c.get("paths") or [], f["file"])]
        if owned:
            c["known_llm_patterns"] = "; ".join(
                f"{f.get('subcategory', 'llm-sdk')}: {f['file']}:{f.get('line', '')}" for f in owned[:6]
            )
            break
    return components


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

    # Stamp the dispatched STRIDE reasoning model into the manifest so the
    # model that runs each component is auditable from the intermediates. The
    # .stride-<id>.json outputs carry no model field, and .stage-stats.jsonl is
    # LLM-extracted (unreliable under turn pressure), so this deterministic
    # record is the config→execution cross-check. Uniform across components for
    # a given run (read from the resolved skill-config; "unknown" if absent).
    stride_model = _read_json(output_dir / ".skill-config.json", {}).get("stride_model") or "unknown"

    # Enumeration-completeness reconciliation: restore security-relevant units
    # (auth / ci-cd / real-time) that Phase-3 folded into a coarser parent. The
    # augmented inventory is persisted so it is the single source of truth for
    # the selector here, the STRIDE fan-out, AND the downstream threat-model.yaml
    # / heatmap / §1 scope (build_threat_model_yaml reads .components.json).
    repo_root = _guess_repo_root(output_dir)
    auth_evidence = _auth_evidence_files(output_dir)
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

    # Seed the LLM role onto components from analyst-context / Cat-13 recon
    # BEFORE selection, so a folded chatbot is floored into STRIDE scope.
    all_components = _seed_llm_role(all_components, output_dir, analyst_context)

    # Actor slices depend on the finalized Phase-3 inventory, so Phase 2.7
    # cannot produce them correctly. Build them here, after reconciliation and
    # before the dispatch manifest resolves each relevant_actors path.
    if (output_dir / ".actors-resolved.json").is_file():
        try:
            import slice_actors

            slice_actors.write_actor_slices(
                str(plugin_root),
                str(output_dir),
                all_components,
                verbose=False,
            )
        except (OSError, ValueError, json.JSONDecodeError) as e:
            sys.stderr.write(f"ACTOR_SLICES: could not build actor slices: {e}\n")

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
        raw_paths = c.get("paths") or []
        # The claimed complexity is an LLM judgement and drifts between runs;
        # scanner evidence is not. A component that owns authentication code is
        # rated complex whatever the inventory called it.
        complexity, floor_reason = _evidence_complexity_floor(raw_paths, auth_evidence, complexity)
        if floor_reason:
            sys.stderr.write(f"FLOOR: {cid} → complex ({floor_reason})\n")
        if not raw_paths:
            sys.stderr.write(
                f"WARN: {cid} has no paths in .components.json — using ['**'] (broad fallback). "
                "Set explicit paths in the component inventory to narrow scope.\n"
            )
        drift_zones = _unknown_zone_tokens(c)
        if drift_zones:
            sys.stderr.write(
                f"ZONE_DRIFT: {cid} has off-vocabulary deployment_zones {sorted(drift_zones)} — "
                "not in the canonical access-zone vocabulary, so the zonal exposure/ci-cd signal "
                "is inert and the component is treated as exposure-unknown (fail-safe). Fix the "
                "recon/analyst output to use canonical zones (internet, dmz, internal-network, "
                "ci-cd-runtime, build-pipeline, prod-write-db, …).\n"
            )
        comp = {
            "component_id": cid,
            "component_name": c.get("name", cid),
            "component_description": c.get("description", ""),
            "component_paths": raw_paths or ["**"],
            "component_complexity": complexity if complexity in ("simple", "moderate", "complex") else "moderate",
            # Turn budget is max(complexity budget, file-footprint floor). The
            # complexity tier is a risk signal and says nothing about how many
            # files the analyzer has to read; a mid-size component whose paths
            # span more files than its tier allows turns for cannot finish. See
            # classify_component._footprint_turn_floor.
            "max_turns": _component_max_turns(
                repo_root,
                raw_paths,
                int(turns.get(complexity, turns.get("moderate", 22))),
            ),
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
        # P3 — Cat-13 deterministic supplement: when this is an LLM component
        # and the analyst-supplied `known_llm_patterns` is absent or a single
        # short sentence (< 120 chars), append file:line anchors from the
        # deterministic Cat-13 recon scan so the STRIDE analyzer has concrete
        # code locations beyond what the analyst summarized.
        if _is_llm(c):
            existing = comp.get("known_llm_patterns", "") or ""
            if isinstance(existing, str) and len(existing) < 120:
                supplement = _cat13_supplement(output_dir)
                if supplement:
                    comp["known_llm_patterns"] = (existing + "; " + supplement).lstrip("; ") if existing else supplement
        comp["model"] = stride_model
        out_components.append(comp)

    return {
        "schema_version": 1,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stride_model": stride_model,
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
    ap.add_argument(
        "--print-selection",
        action="store_true",
        help="Read the already-written .stride-selection.json and print the "
        "human-readable ANALYZED/SKIPPED console block, then exit. Does not "
        "rebuild — for re-surfacing the selection to the user.",
    )
    ns = ap.parse_args(argv)

    if ns.print_selection:
        sel = _read_json(ns.output_dir / ".stride-selection.json", {})
        if not sel:
            print("No .stride-selection.json yet — selection not computed.", file=sys.stderr)
            return 1
        print(format_selection_console(sel))
        return 0

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
