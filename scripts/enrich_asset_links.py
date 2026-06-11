#!/usr/bin/env python3
"""Deterministic asset.linked_threats enrichment.

Stage 1 Phase 5 (Asset Identification) is LLM-authored and routinely produces
`linked_threats` lists that have nothing to do with the asset they're attached
to. Observed on the 2026-05 juice-shop run:

    session-tokens   → [T-024 CORS, T-021 YAML bomb, T-022 Mass assignment]
       expected      → T-013 (JWT in localStorage) + T-002 / T-010 / T-011 (XSS findings)

    encryption-keys  → [T-020 rate-limit]
       expected      → T-018 (key directory traversal) + T-001 (committed RSA key)

The LLM had no semantic grounding mechanism — it picked threats by gut. This
emitter rebuilds `linked_threats` deterministically using two signals:

1. **CWE class affinity** — each asset class is associated with a curated
   set of CWE families that semantically affect it. A threat carrying one of
   those CWEs is considered relevant.
2. **Keyword overlap** — tokens in the asset's `name` + `description` are
   scored against the threat's `title` + `evidence.file` basename. ≥2 token
   overlap counts as relevant.

Either signal alone is enough to keep an existing link or add a missing one.
A link with NO supporting signal is flagged as `auto_pruned` in the asset's
`evidence_flags` and removed from `linked_threats`.

Idempotent — re-running on already-enriched yaml does not change content. A
threat that was hand-set (asset carries `manual: true` for that asset-threat
pair via the optional `linked_threats_manual[]` field) is preserved.

Usage:
    python3 enrich_asset_links.py <output_dir> [--report-only]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Asset class → relevant CWE families
# ---------------------------------------------------------------------------
# Each asset gets classified by name+description keyword. The classification
# decides which CWE families count as "relevant" for the asset. Conservative
# — every entry was selected so it would not generate false positives on the
# juice-shop reference run.

_ASSET_CLASS_CWES: dict[str, set[str]] = {
    # Credentials / passwords stored
    "credentials": {
        "CWE-79",
        "CWE-80",  # XSS that steals from forms
        "CWE-89",
        "CWE-90",  # SQL/NoSQL injection that dumps the table
        "CWE-307",
        "CWE-308",
        "CWE-799",  # weak / no rate limiting → cred stuffing
        "CWE-916",
        "CWE-759",
        "CWE-326",  # weak password storage
        "CWE-256",
        "CWE-257",
        "CWE-261",  # plaintext / weak password storage
        "CWE-522",  # insufficient password protection
    },
    # JWT / session tokens
    "session_token": {
        "CWE-79",
        "CWE-80",  # XSS that steals localStorage
        "CWE-312",
        "CWE-922",  # insecure client-side storage
        "CWE-287",
        "CWE-294",
        "CWE-345",  # broken auth / token bypass
        "CWE-347",  # signature verification
        "CWE-352",
        "CWE-1021",  # CSRF that hijacks the session
        "CWE-613",  # insufficient session expiration
    },
    # Crypto key material
    "key_material": {
        "CWE-798",
        "CWE-321",
        "CWE-312",  # hardcoded / cleartext keys
        "CWE-540",
        "CWE-538",  # info in source / file leak
        "CWE-22",  # path traversal that reads the key
        "CWE-200",  # information exposure
    },
    # Payment / financial data
    "payment_data": {
        "CWE-89",
        "CWE-79",  # SQLi / XSS that dumps cards
        "CWE-285",
        "CWE-639",
        "CWE-862",  # broken authorization / IDOR
        "CWE-311",
        "CWE-312",
        "CWE-319",  # cleartext storage / transmission
    },
    # PII / user profile data
    "pii": {
        "CWE-89",
        "CWE-79",  # injection / XSS dumps PII
        "CWE-285",
        "CWE-639",
        "CWE-862",  # broken authorization
        "CWE-200",
        "CWE-359",  # information exposure
        "CWE-915",  # mass assignment
    },
    # Order history / transactional data
    "order_data": {
        "CWE-89",  # SQLi
        "CWE-285",
        "CWE-639",
        "CWE-862",  # broken authorization
        "CWE-915",  # mass assignment
    },
    # Access logs / audit records
    "access_logs": {
        "CWE-200",
        "CWE-532",
        "CWE-548",  # log / dir exposure
        "CWE-117",  # log injection
        "CWE-285",
        "CWE-862",  # missing authorization
    },
    # FTP / static file directory
    "ftp_files": {
        "CWE-22",
        "CWE-548",  # directory traversal / listing
        "CWE-200",
        "CWE-538",  # information disclosure
        "CWE-285",
        "CWE-862",  # missing authorization
    },
    # Uploaded files (untrusted input)
    "uploaded_files": {
        "CWE-22",
        "CWE-23",  # path traversal in archives
        "CWE-611",  # XXE
        "CWE-434",  # unrestricted file upload
        "CWE-776",  # YAML / XML bomb
        "CWE-78",
        "CWE-94",
        "CWE-95",  # command / code injection via file
    },
    # Product catalog / public content
    "product_data": {
        "CWE-79",  # stored XSS in description
        "CWE-89",  # injection in search
        "CWE-915",  # mass assignment from admin API
    },
    # Challenge state / non-sensitive
    "challenge_state": set(),  # explicitly empty — no real risk surface
}


# Asset-class detection rules: substring match against name+description,
# lower-cased. First match wins. Conservative — only triggers on terms that
# unambiguously identify the asset class.
_ASSET_CLASS_RULES: list[tuple[str, tuple[str, ...]]] = [
    # Order matters — first match wins. Rules are arranged so the most
    # specific terms win over broader ones. Examples that justify each
    # ordering decision:
    #   - "key_material" before "session_token": an asset named "Encryption
    #     Keys Directory" mentioning "JWT public key" should classify as
    #     key_material (storage of crypto material), not session_token
    #     (the runtime credential carried in a request).
    #   - "credentials" first: "user credentials" is unambiguous, never
    #     overlaps with token / key classes.
    #   - "ftp_files" before "uploaded_files": juice-shop's `/ftp` is
    #     accidental directory disclosure, not user-uploaded content.
    ("credentials", ("credential", "password", "users table", "user table")),
    (
        "key_material",
        (
            "private key",
            "rsa key",
            "encryption key",
            "signing key",
            "secret key",
            "/encryptionkeys",
            "premium.key",
            "key material",
        ),
    ),
    ("session_token", ("session token", "bearer token", "auth token", "jwt token", "auth session", "token storage")),
    ("payment_data", ("payment", "card data", "credit card", "wallet", "stripe", "paypal")),
    (
        "pii",
        (
            "pii",
            "personally identifiable",
            "personal data",
            "profile data",
            "email address",
            "phone number",
            "address book",
        ),
    ),
    ("order_data", ("order history", "basket", "cart", "checkout", "purchase history")),
    ("access_logs", ("access log", "audit log", "morgan", "log file", "log archive")),
    ("ftp_files", ("ftp", "/ftp", "acquisitions", "kdbx", "package backup", "ftp directory")),
    ("uploaded_files", ("uploaded file", "user-uploaded", "user upload", "uploads directory")),
    ("product_data", ("product catalog", "product description", "catalog item", "product list")),
    ("challenge_state", ("ctf state", "challenge state", "challenge progress")),
]


# ---------------------------------------------------------------------------
# Keyword tokenisation (asset name/description ↔ threat title/file basename)
# ---------------------------------------------------------------------------

_STOPWORDS: frozenset[str] = frozenset(
    {
        # Generic English filler
        "a",
        "an",
        "the",
        "of",
        "and",
        "or",
        "for",
        "in",
        "on",
        "with",
        "to",
        "by",
        "is",
        "are",
        "was",
        "were",
        "be",
        "as",
        "at",
        "via",
        "using",
        "from",
        # Generic security/CS filler that adds no signal
        "data",
        "file",
        "files",
        "user",
        "users",
        "system",
        "service",
        "server",
        "client",
        "store",
        "stored",
        "list",
        "value",
        "values",
        "controller",
        "component",
        "module",
        "handler",
        "endpoint",
        "endpoints",
        "based",
        "where",
        "which",
        "what",
        "how",
    }
)


def _tokens(text: str) -> set[str]:
    """Lower-cased tokens, ≥3 chars, stop-words filtered."""
    if not text:
        return set()
    raw = re.split(r"[^a-zA-Z0-9]+", text.lower())
    return {tok for tok in raw if len(tok) >= 3 and tok not in _STOPWORDS}


def _basename_tokens(path: str) -> set[str]:
    """Tokens from a file basename — splits camelCase + dot/dash separators."""
    if not path:
        return set()
    base = path.rsplit("/", 1)[-1]
    base = re.sub(r"\.\w+$", "", base)  # drop extension
    # camelCase split: insert dash before any uppercase preceded by lowercase
    base = re.sub(r"([a-z])([A-Z])", r"\1-\2", base)
    return _tokens(base)


# ---------------------------------------------------------------------------
# Core enrichment
# ---------------------------------------------------------------------------


def _classify_asset(asset: dict) -> str:
    """Return the asset class slug for CWE matching, or '' if unclassified."""
    haystack = " ".join(
        (
            str(asset.get("name") or ""),
            str(asset.get("id") or ""),
            str(asset.get("description") or ""),
        )
    ).lower()
    for cls, hints in _ASSET_CLASS_RULES:
        if any(h in haystack for h in hints):
            return cls
    return ""


def _threat_relevance(asset: dict, asset_cls: str, threat: dict) -> tuple[bool, str]:
    """Return (is_relevant, reason). Threat is relevant if:
    1. CWE matches one of asset_cls' relevant CWEs, OR
    2. Keyword overlap between asset name/description and threat title/file ≥ 2.
    """
    if not isinstance(threat, dict):
        return False, ""
    cwe = (threat.get("cwe") or "").strip().upper()
    relevant_cwes = _ASSET_CLASS_CWES.get(asset_cls, set())
    if cwe and cwe in relevant_cwes:
        return True, f"cwe_match:{cwe}"

    # Keyword overlap
    asset_tokens = _tokens(asset.get("name") or "") | _tokens(asset.get("description") or "")
    title_tokens = _tokens(threat.get("title") or "")
    ev = threat.get("evidence") or {}
    if isinstance(ev, dict):
        file_tokens = _basename_tokens(ev.get("file") or "")
    elif isinstance(ev, list) and ev and isinstance(ev[0], dict):
        file_tokens = _basename_tokens(ev[0].get("file") or "")
    else:
        file_tokens = set()
    threat_tokens = title_tokens | file_tokens
    overlap = asset_tokens & threat_tokens
    if len(overlap) >= 2:
        return True, f"keyword_overlap:{','.join(sorted(overlap))}"
    return False, ""


def enrich(data: dict) -> tuple[dict, dict]:
    """Mutate `data` in place. Return (data, summary) where summary tracks
    per-asset add / prune / keep counts."""
    assets = data.get("assets") or []
    threats = data.get("threats") or []
    if not isinstance(assets, list) or not isinstance(threats, list):
        return data, {}

    threats_by_id = {(t.get("id") or t.get("t_id") or ""): t for t in threats if isinstance(t, dict)}

    summary: dict[str, dict[str, int | list[str]]] = {}
    for a in assets:
        if not isinstance(a, dict):
            continue
        asset_id = a.get("id") or a.get("name") or "<anon>"
        cls = _classify_asset(a)
        if not cls:
            # Unclassified — keep whatever Stage 1 wrote, no enrichment.
            summary[asset_id] = {"class": "unclassified", "kept": len(a.get("linked_threats") or [])}
            continue

        # Preserve manual entries (asset carries `linked_threats_manual: true`
        # for an explicit override).
        manual_pins = set(a.get("linked_threats_manual") or [])
        prior_links = list(a.get("linked_threats") or [])

        # Score every threat against this asset.
        relevant: list[tuple[str, str]] = []
        for tid, t in threats_by_id.items():
            is_rel, reason = _threat_relevance(a, cls, t)
            if is_rel:
                relevant.append((tid, reason))

        # Final linked_threats = union(manual_pins, relevant) intersected with
        # known threat ids, preserving prior ordering where possible.
        new_set = manual_pins | {tid for tid, _ in relevant}
        new_links: list[str] = []
        # Re-emit prior links that survived the filter (preserves Stage-1
        # ordering when it was correct).
        for tid in prior_links:
            if tid in new_set and tid not in new_links:
                new_links.append(tid)
        # Append newly-discovered relevant threats (alphabetical for stable
        # output across runs).
        for tid, _ in sorted(relevant):
            if tid not in new_links:
                new_links.append(tid)

        pruned = [tid for tid in prior_links if tid not in new_set]
        added = [tid for tid in new_links if tid not in prior_links]

        a["linked_threats"] = new_links
        if pruned:
            flags = list(a.get("evidence_flags") or [])
            tag = f"auto_pruned_threats:{','.join(pruned)}"
            if tag not in flags:
                flags.append(tag)
            a["evidence_flags"] = flags

        summary[asset_id] = {
            "class": cls,
            "kept": len([tid for tid in prior_links if tid in new_set]),
            "added": added,
            "pruned": pruned,
        }

    return data, summary


def _format_summary(summary: dict) -> str:
    """Pretty-print enrichment summary for stderr."""
    lines = []
    n_added = sum(len(v.get("added") or []) for v in summary.values())
    n_pruned = sum(len(v.get("pruned") or []) for v in summary.values())
    n_kept = sum(int(v.get("kept") or 0) for v in summary.values())
    lines.append(
        f"enrich_asset_links: {len(summary)} asset(s) processed · +{n_added} added · -{n_pruned} pruned · {n_kept} kept"
    )
    for aid, s in summary.items():
        cls = s.get("class", "?")
        if s.get("added") or s.get("pruned"):
            added = ",".join(s.get("added") or []) or "—"
            pruned = ",".join(s.get("pruned") or []) or "—"
            lines.append(f"  {aid} [{cls}]: +{added}  -{pruned}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Enrich assets[].linked_threats from CWE + keyword heuristics.")
    ap.add_argument("output_dir", help="Path to threat-model output dir")
    ap.add_argument("--report-only", action="store_true", help="Compute changes but do not write yaml")
    args = ap.parse_args(argv)

    output_dir = Path(args.output_dir)
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"enrich_asset_links: no yaml at {yaml_path}", file=sys.stderr)
        return 1

    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"enrich_asset_links: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print(f"enrich_asset_links: {yaml_path} did not parse to a mapping", file=sys.stderr)
        return 1

    data, summary = enrich(data)

    if not args.report_only:
        yaml_path.write_text(
            yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False),
            encoding="utf-8",
        )

    print(_format_summary(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
