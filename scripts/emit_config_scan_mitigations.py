"""Auto-emit `kind: fix` mitigations for config-scan threats (M-RCA-2026-05).

Background. Phase 2.5 `appsec-config-scanner` produces findings for
configuration / IaC issues (CORS wildcard, missing CSP, lockfile integrity,
GHA permissions block, …). `scripts/merge_threats.py:_config_finding_to_threat`
ingests them into `.threats-merged.json` with `source="config-scan"` but
without `mitigation_ids[]` and without a `remediation` block — neither
field is on the scanner's actual output schema. As a result,
`scripts/build_threat_model_yaml.py:build_mitigations` (which only emits
M-NNN cards for threats carrying `mitigation_ids[]`) never produces a fix
card for these threats, and the §8 Findings Register renders an empty
**Fix:** cell.

This emitter closes the gap deterministically:

1. Scan `threat-model.yaml → threats[]` for `source: config-scan` rows that
   carry no `mitigation_ids` (i.e. no fix card was emitted upstream).
2. Resolve a remediation prose, in priority order:
   a. `config_check_id` matches an entry in `data/config-iac-checks.yaml`
      → use that entry's canonical `remediation` text.
   b. `check` slug matches one of the built-in scanner-synthesised checks
      (CORS / CSP / HSTS / FTP listing / secrets-in-source / lockfile /
      workflow permissions / unsafe-perm) → use the curated remediation
      from the `_BUILTIN_REMEDIATIONS` map below.
   c. Fallback: generic "Review the named configuration setting and tighten
      it to the framework default" — never empty.
3. Allocate the next available `M-NNN` (above all existing IDs).
4. Append a mitigation card with `kind: "fix"`, `auto_emitted: true`,
   `auto_source: "config-scan"`, and link it back to the threat via
   `threat.mitigation_ids = [M-NNN]`.

The script is idempotent — it strips prior `auto_source: "config-scan"`
entries from `mitigations[]` and clears the corresponding `mitigation_ids`
back-references before re-computing, so re-running produces the same
output regardless of run history.

Usage:
    python3 emit_config_scan_mitigations.py <output_dir>

Exit codes: 0 always (best-effort emitter; failures are warnings on stderr).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_M_ID_RE = re.compile(r"\bM-(\d{3,})\b")

# Severity → priority (mirrors the table in emit_review_mitigations.py and the
# build_threat_model_yaml.py:build_mitigations risk_order convention).
_SEV_TO_PRI = {
    "Critical": "P1",
    "High": "P2",
    "Medium": "P3",
    "Low": "P4",
    "Informational": "P4",
}

# Built-in remediation prose for scanner-synthesised check slugs that have no
# matching entry in data/config-iac-checks.yaml. Keep entries concise (single
# short sentence) — the full guidance belongs in the linked §7 control section.
_BUILTIN_REMEDIATIONS: dict[str, dict[str, str]] = {
    # Express middleware / runtime config (NOT covered by IaC yaml)
    "cors-wildcard": {
        "title": "Restrict CORS to an explicit origin allow-list",
        "how": (
            "Replace `app.use(cors())` with `cors({ origin: <allow-list>, credentials: true })` "
            "and reject any other origin. Enumerate the actual frontend origins (production + "
            "staging) rather than echoing `req.headers.origin`."
        ),
    },
    "csp-missing": {
        "title": "Configure a strict Content-Security-Policy header",
        "how": (
            "Add a global CSP via Helmet (`helmet.contentSecurityPolicy({ directives: { … } })`) "
            "with a `default-src 'self'`, `script-src 'self'` baseline and explicit allow-list for "
            "third-party hosts. Remove any `'unsafe-inline'` / `'unsafe-eval'` directives that exist."
        ),
    },
    "hsts-missing": {
        "title": "Enable HSTS to enforce HTTPS",
        "how": (
            "Add `app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }))` "
            "so browsers refuse plain-HTTP downgrade. Verify the deployment terminates TLS before HSTS "
            "is enabled."
        ),
    },
    "ftp-directory-listing": {
        "title": "Disable public directory listing",
        "how": (
            "Remove `serveIndex(…)` from any publicly-reachable route, or move the route behind an "
            "authenticated middleware. Audit the listed directory for files that should not be "
            "shippable (keys, M&A docs, backup files) and gate them separately."
        ),
    },
    "secrets-in-source": {
        "title": "Move secrets out of source into a managed secret store",
        "how": (
            "Delete the hardcoded value from source, rotate the secret (every credential that ever sat "
            "in source is compromised), and reload it at runtime from environment / Vault / KMS. Add a "
            "pre-commit secret-scan (gitleaks / trufflehog) to prevent regression."
        ),
    },
    "package-lock-disabled": {
        "title": "Re-enable npm lockfile integrity",
        "how": (
            "Remove `package-lock=false` from `.npmrc` and commit a fresh `package-lock.json`. The "
            "lockfile pins each transitive dependency to a specific resolved tarball + integrity hash, "
            "blocking silent supplier substitution."
        ),
    },
    "gha-no-permissions-block": {
        "title": "Add a top-level GITHUB_TOKEN permissions block",
        "how": (
            "Add `permissions: {}` (or `permissions: read-all`) at the workflow root, then grant only "
            "the specific scopes individual jobs require. Defaults grant broad write access — explicit "
            "minimisation closes the lateral-movement window if a step is compromised."
        ),
    },
    "dockerfile-unsafe-perm": {
        "title": "Remove `--unsafe-perm` from `npm install`",
        "how": (
            "Drop the `--unsafe-perm` flag and let postinstall scripts run as the unprivileged user "
            "added by the `USER` directive. If a package legitimately needs root, add a dedicated "
            "build stage rather than running every install as root."
        ),
    },
}

# Generic fallback when neither IAC yaml nor _BUILTIN_REMEDIATIONS has an entry.
_GENERIC_REMEDIATION = {
    "title": "Review and tighten the flagged configuration",
    "how": (
        "Treat the flagged setting as a deviation from the framework default. Compare against the "
        "library's hardening guide, choose the strictest setting compatible with the deployment, and "
        "add a regression test (lint rule / CI gate) so the weak setting cannot be reintroduced."
    ),
}


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def _load_iac_checks(plugin_root: Path) -> dict[str, dict]:
    """Index data/config-iac-checks.yaml by check id (`IAC-NNN`)."""
    path = plugin_root / "data" / "config-iac-checks.yaml"
    try:
        y = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError:
        return {}
    out: dict[str, dict] = {}
    for c in y.get("checks") or []:
        if isinstance(c, dict) and c.get("id"):
            out[c["id"]] = c
    return out


def _scan_max_m_id(data: dict) -> int:
    """Highest M-NNN already in use across mitigations[]."""
    max_n = 0
    for m in data.get("mitigations") or []:
        if not isinstance(m, dict):
            continue
        mid = (m.get("id") or "").strip()
        mt = _M_ID_RE.fullmatch(mid)
        if mt:
            max_n = max(max_n, int(mt.group(1)))
    return max_n


def _allocate_next_m_id(state: dict) -> str:
    state["counter"] += 1
    return f"M-{state['counter']:03d}"


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False),
        encoding="utf-8",
    )


def _clear_prior_auto_mitigations(data: dict) -> set[str]:
    """Drop prior auto_source="config-scan" cards and return their IDs.

    The caller uses the returned set to scrub stale back-references from
    threat.mitigation_ids[] so re-runs produce clean output."""
    items = data.get("mitigations") or []
    if not isinstance(items, list):
        return set()
    stale_ids = {
        m.get("id")
        for m in items
        if isinstance(m, dict)
        and m.get("auto_emitted") is True
        and m.get("auto_source") == "config-scan"
        and m.get("id")
    }
    if stale_ids:
        data["mitigations"] = [m for m in items if not (isinstance(m, dict) and m.get("id") in stale_ids)]
    return stale_ids


def _clear_stale_threat_refs(data: dict, stale_ids: set[str]) -> None:
    """Strip any stale M-IDs from threats[].mitigation_ids[]."""
    if not stale_ids:
        return
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        existing = t.get("mitigation_ids") or []
        if not existing:
            continue
        kept = [mid for mid in existing if mid not in stale_ids]
        if kept != existing:
            t["mitigation_ids"] = kept


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _resolve_remediation(threat: dict, iac_index: dict[str, dict]) -> tuple[str, str]:
    """Return (title, how) for the threat. Never returns empty strings."""
    # Path 1 — canonical IAC entry by config_check_id
    cid = threat.get("config_check_id")
    if cid and cid in iac_index:
        entry = iac_index[cid]
        title = entry.get("name") or f"Apply IAC fix {cid}"
        rem = (entry.get("remediation") or "").strip()
        rationale = (entry.get("rationale") or "").strip()
        if rem:
            how = rem if not rationale else f"{rem} — {rationale}"
            return title, how

    # Path 2 — built-in remediation by scanner check slug
    # The scanner emits `check` as a slug, picked up by merge_threats.py and
    # stored on the threat under several possible field names depending on
    # the slice of code that ingested it.  Try them in order.
    slug = threat.get("config_check_slug") or threat.get("check") or ""
    if slug not in _BUILTIN_REMEDIATIONS:
        # The current merger drops the scanner's `check` slug, so we have to
        # recover it from the threat narrative. Match against the union of
        # title + scenario + cwe so loose LLM rewrites ("Config Issue" with
        # an HSTS scenario, "Missing Content Security Policy", etc.) still
        # resolve to the right builtin.
        haystack = " ".join(str(threat.get(k) or "") for k in ("title", "scenario", "cwe", "config_scan_ref")).lower()
        # Each slug → list of OR'd keyword-groups; a group matches when
        # every keyword in it is present in the haystack. The first slug
        # whose ANY group matches wins.
        slug_patterns: list[tuple[str, list[list[str]]]] = [
            ("cors-wildcard", [["cors"]]),
            ("csp-missing", [["csp"], ["content-security-policy"], ["content security policy"]]),
            ("hsts-missing", [["hsts"], ["strict transport"], ["https enforcement"]]),
            ("ftp-directory-listing", [["directory listing"], ["serveindex"], ["/ftp"]]),
            (
                "secrets-in-source",
                [["hardcoded", "key"], ["hardcoded", "secret"], ["hardcoded", "credential"], ["rsa private"]],
            ),
            ("package-lock-disabled", [["package-lock"], ["lockfile"], ["package lock"]]),
            (
                "gha-no-permissions-block",
                [["workflow", "permissions"], ["github_token"], ["github-actions", "permissions"]],
            ),
            ("dockerfile-unsafe-perm", [["unsafe-perm"], ["unsafe perm"]]),
        ]
        for candidate, groups in slug_patterns:
            for kws in groups:
                if all(kw in haystack for kw in kws):
                    slug = candidate
                    break
            if slug == candidate:
                break
    if slug in _BUILTIN_REMEDIATIONS:
        entry = _BUILTIN_REMEDIATIONS[slug]
        return entry["title"], entry["how"]

    # Path 3 — generic fallback
    return _GENERIC_REMEDIATION["title"], _GENERIC_REMEDIATION["how"]


# ---------------------------------------------------------------------------
# Synthesis
# ---------------------------------------------------------------------------


def _synthesize_fix_mitigations(data: dict, state: dict, iac_index: dict[str, dict]) -> list[dict]:
    new_cards: list[dict] = []
    threats = data.get("threats") or []
    for t in threats:
        if not isinstance(t, dict):
            continue
        if (t.get("source") or "") != "config-scan":
            continue
        if t.get("mitigation_ids"):
            # Already has a fix card from an upstream source — do nothing.
            continue
        tid = (t.get("id") or "").strip()
        if not tid:
            continue

        title, how = _resolve_remediation(t, iac_index)
        sev = t.get("risk") or "Medium"
        mid = _allocate_next_m_id(state)
        new_cards.append(
            {
                "id": mid,
                "title": title,
                "kind": "fix",
                "priority": _SEV_TO_PRI.get(sev, "P3"),
                "severity": sev,
                "threat_ids": [tid],
                "how": how,
                "effort": "Low",
                "auto_emitted": True,
                "auto_source": "config-scan",
            }
        )
        # Link the mitigation back to the threat (the field name is
        # `mitigation_ids` per threat-model.output.schema.yaml — historical
        # `mitigations` shape on the threat side is not part of the output
        # schema; the renderer accepts both as a back-compat read but new
        # auto-emitters MUST write the canonical name).
        t.setdefault("mitigation_ids", []).append(mid)

    return new_cards


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: emit_config_scan_mitigations.py <output_dir>", file=sys.stderr)
        return 0

    out_dir = Path(sys.argv[1])
    yaml_path = out_dir / "threat-model.yaml"
    if not yaml_path.exists():
        print(f"emit_config_scan_mitigations: no {yaml_path} — skipping", file=sys.stderr)
        return 0

    # Resolve the plugin root (this file's grandparent).
    plugin_root = Path(__file__).resolve().parent.parent
    iac_index = _load_iac_checks(plugin_root)

    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"emit_config_scan_mitigations: failed to load yaml: {exc}", file=sys.stderr)
        return 0

    if not isinstance(data, dict):
        print("emit_config_scan_mitigations: yaml root is not a mapping — skipping", file=sys.stderr)
        return 0

    stale_ids = _clear_prior_auto_mitigations(data)
    _clear_stale_threat_refs(data, stale_ids)

    state = {"counter": _scan_max_m_id(data)}
    new_cards = _synthesize_fix_mitigations(data, state, iac_index)
    if not new_cards:
        if stale_ids:
            _write_yaml(yaml_path, data)
        print("emit_config_scan_mitigations: no config-scan threats needing a fix card", file=sys.stderr)
        return 0

    # Append cards. The yaml builder sorted mitigations by id ascending; we
    # preserve that ordering by extending and re-sorting.
    existing = data.get("mitigations") or []
    existing.extend(new_cards)

    def _sort_key(m: dict) -> tuple[int, str]:
        mid = (m.get("id") or "") if isinstance(m, dict) else ""
        mt = _M_ID_RE.fullmatch(mid)
        return (int(mt.group(1)) if mt else 99999, mid)

    data["mitigations"] = sorted(existing, key=_sort_key)

    _write_yaml(yaml_path, data)

    iac_hits = sum(
        1
        for c in new_cards
        if c["how"].startswith(_GENERIC_REMEDIATION["how"][:20]) is False
        and any(c["title"] == iac_index[k].get("name") for k in iac_index)
    )
    builtin_hits = sum(1 for c in new_cards if c["title"] in {e["title"] for e in _BUILTIN_REMEDIATIONS.values()})
    generic_hits = sum(1 for c in new_cards if c["title"] == _GENERIC_REMEDIATION["title"])

    print(
        f"emit_config_scan_mitigations: appended {len(new_cards)} fix card(s) "
        f"(iac={iac_hits} · builtin={builtin_hits} · generic={generic_hits}); "
        f"cleared {len(stale_ids)} stale auto-card(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
