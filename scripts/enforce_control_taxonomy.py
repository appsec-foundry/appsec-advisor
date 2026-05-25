#!/usr/bin/env python3
"""enforce_control_taxonomy.py — deterministic taxonomy guard for
``threat-model.yaml.security_controls[]``.

Two related Stage-1 drift modes addressed:

  RC-1  Control NAME is non-canonical. Stage 1 sometimes writes algorithm
        names or token-format-only strings into ``security_controls[].control``
        (e.g. ``"JWT RS256 Authentication"`` instead of the canonical
        ``"JWT Bearer Authentication"``). The §7.2 QA gate
        ``check_subcontrol_naming_canonical`` later flags this — but only
        after Stage 2 has composed the document around the bad name and
        downstream cross-references have hard-coded the bad anchor. Fixing
        the canonical name in yaml BEFORE the renderer sees it eliminates
        the entire cascade.

  RC-6  Control DOMAIN is mis-assigned. Stage 1 sometimes places a control
        whose name belongs to §7.2 IAM (e.g. ``"Rate limiting on password
        reset + 2FA"``) into the §7.12 "Real-time and Not Applicable
        Controls" bucket. The §7.1 overview-table row then claims
        ``1 adequate control(s)`` in §7.12 while the §7.12 body says
        ``Not applicable``. Re-routing to the domain whose ``method_whitelist``
        the control name tokenises into fixes the inconsistency.

Idempotent. Empty changes set when yaml is already canonical.

Hooked into the create-threat-model skill's auto-emitter pass between
``enforce_yaml_invariants.py`` (stride/cwe drift) and ``emit_meta_findings.py``,
i.e. after Stage 1's yaml write and before any fragment pre-generation —
the renderer must see a taxonomy-clean yaml on its first read.

Usage:
    python3 enforce_control_taxonomy.py <output_dir>
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Deterministic name rewrites (RC-1)
# ---------------------------------------------------------------------------
#
# Each entry is a regex matched against the lowercased control name; on hit,
# the original name is rewritten to the entry's `canonical` form. Tokens that
# are pure transport / algorithm details (RS256, HS256, ES256, PS256) are
# stripped because they describe HOW signing happens, not the mechanism by
# which identity is established.
#
# Keep this list narrow — every entry must be (1) clearly wrong in the input
# form, (2) clearly right in the output form, (3) sourced from
# data/architectural-controls.yaml or data/sections-contract.yaml's
# method_whitelist. New entries are additive.
_NAME_REWRITE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # JWT + algorithm-name conflation: "JWT RS256 Authentication" → "JWT Bearer Authentication".
    # The §7.2 method_whitelist accepts {jwt, bearer token} but the
    # forbidden_heading_patterns hard-rejects the format-only "JWT-RS256" /
    # "JWT RS256 Signing Flow" shapes.
    (
        re.compile(r"^jwt\s+(rs|hs|es|ps)\d{3}\s+authentication$", re.IGNORECASE),
        "JWT Bearer Authentication",
    ),
    (
        re.compile(r"^jwt\s+(rs|hs|es|ps)\d{3}\s+signing$", re.IGNORECASE),
        "Session Token Signing (JWT Based)",
    ),
    (
        re.compile(r"^jwt\s+(rs|hs|es|ps)\d{3}\s+verification$", re.IGNORECASE),
        "Session Token Validation (JWT Based)",
    ),
    # Bare token-format names — keep "JWT Bearer" as the canonical
    # mechanism string used in §7.2.
    (re.compile(r"^jwt\s*-?\s*rs\d{3}$", re.IGNORECASE), "JWT Bearer Authentication"),
    (re.compile(r"^jwt\s+library$", re.IGNORECASE), "JWT Bearer Authentication"),
)


def _canonicalize_name(name: str) -> str | None:
    """Return the canonical form when ``name`` matches a known drift pattern,
    or ``None`` when no rewrite is needed."""
    if not isinstance(name, str):
        return None
    stripped = name.strip()
    if not stripped:
        return None
    for pattern, canonical in _NAME_REWRITE_RULES:
        if pattern.match(stripped):
            if stripped == canonical:
                return None  # already canonical
            return canonical
    return None


# ---------------------------------------------------------------------------
# Domain re-routing (RC-6)
# ---------------------------------------------------------------------------
#
# Each §7.X section has a method_whitelist in sections-contract.yaml. We
# build an inverse index (token → canonical domain string) from a curated
# subset that covers the cases observed in production drift. The mapping
# uses the domain STRING that ends up in security_controls[].domain — the
# §7.X title minus the leading "7.X ".
#
# Token semantics: case-insensitive; multi-word tokens require ALL words
# present in the control name's token set. Single-word tokens match any
# control whose token set contains them.

_DOMAIN_TOKEN_INDEX: tuple[tuple[tuple[str, ...], str], ...] = (
    # §7.2 IAM — authentication mechanisms + auth-flow rate limiting
    (("password", "login"), "Identity and Authentication Controls"),
    (("user", "registration"),  "Identity and Authentication Controls"),
    (("oauth",),                "Identity and Authentication Controls"),
    (("oidc",),                 "Identity and Authentication Controls"),
    (("openid",),               "Identity and Authentication Controls"),
    (("saml",),                 "Identity and Authentication Controls"),
    (("sso",),                  "Identity and Authentication Controls"),
    (("totp",),                 "Identity and Authentication Controls"),
    (("mfa",),                  "Identity and Authentication Controls"),
    (("2fa",),                  "Identity and Authentication Controls"),
    (("passkey",),              "Identity and Authentication Controls"),
    (("webauthn",),             "Identity and Authentication Controls"),
    (("password", "reset"),     "Identity and Authentication Controls"),
    (("password", "hashing"),   "Identity and Authentication Controls"),
    (("magic", "link"),         "Identity and Authentication Controls"),
    (("login", "throttling"),   "Identity and Authentication Controls"),
    (("brute", "force"),        "Identity and Authentication Controls"),
    (("rate", "limiting"),      "Identity and Authentication Controls"),
    (("authentication", "rate"),"Identity and Authentication Controls"),
    (("mtls",),                 "Identity and Authentication Controls"),
    (("mutual", "tls"),         "Identity and Authentication Controls"),
    (("api", "key"),            "Identity and Authentication Controls"),
    (("hmac",),                 "Identity and Authentication Controls"),
    # §7.3 Session and Token Controls — token LIFECYCLE only.
    # Note: bare "JWT Bearer Authentication" is intentionally routed to §7.2
    # (matched by the ("jwt",) entry below) since the §7.2 method_whitelist
    # explicitly accepts "jwt" as a mechanism. §7.3 only catches the lifecycle
    # primitives: storage, revocation, expiry, sign+validate pairs.
    (("session", "token"),      "Session and Token Controls"),
    (("token", "storage"),      "Session and Token Controls"),
    (("token", "revocation"),   "Session and Token Controls"),
    (("token", "blacklist"),    "Session and Token Controls"),
    (("token", "blocklist"),    "Session and Token Controls"),
    (("token", "expiry"),       "Session and Token Controls"),
    (("session", "expiry"),     "Session and Token Controls"),
    (("session", "token", "signing"),    "Session and Token Controls"),
    (("session", "token", "validation"), "Session and Token Controls"),
    # JWT used as a mechanism token → §7.2 IAM (matches method_whitelist).
    (("jwt",),                  "Identity and Authentication Controls"),
    # §7.4 Authorization
    (("role", "based", "access"),     "Authorization Controls"),
    (("rbac",),                       "Authorization Controls"),
    (("abac",),                       "Authorization Controls"),
    (("authorization", "middleware"), "Authorization Controls"),
    (("isauthorized",),               "Authorization Controls"),
    # §7.5 Query Construction / Data Access
    (("sequelize",),    "Query Construction and Data Access Controls"),
    (("orm",),          "Query Construction and Data Access Controls"),
    (("parameterized",), "Query Construction and Data Access Controls"),
    (("prepared", "statement"), "Query Construction and Data Access Controls"),
    # §7.6 Input Boundary Validation
    (("input", "validation"),       "Input Boundary Validation Controls"),
    (("schema", "validation"),      "Input Boundary Validation Controls"),
    (("joi",),                      "Input Boundary Validation Controls"),
    (("zod",),                      "Input Boundary Validation Controls"),
    # §7.7 Output Encoding
    (("output", "encoding"),    "Output Encoding and Rendering Controls"),
    (("html", "sanitization"),  "Output Encoding and Rendering Controls"),
    (("dompurify",),            "Output Encoding and Rendering Controls"),
    # §7.8 Browser / Cross-Origin
    (("cors",),                 "Browser and Cross-Origin Controls"),
    (("csp",),                  "Browser and Cross-Origin Controls"),
    (("content", "security", "policy"), "Browser and Cross-Origin Controls"),
    (("helmet",),               "Browser and Cross-Origin Controls"),
    (("frameguard",),           "Browser and Cross-Origin Controls"),
    # §7.9 Cryptography / Secrets / Data Protection
    (("encryption",),           "Cryptography Secrets and Data Protection"),
    (("secret", "management"),  "Cryptography Secrets and Data Protection"),
    (("kms",),                  "Cryptography Secrets and Data Protection"),
    # §7.10 File Parser / Outbound
    (("file", "upload"),    "File Parser and Outbound Request Controls"),
    (("ssrf",),             "File Parser and Outbound Request Controls"),
    # §7.11 Operations / Supply Chain
    (("distroless",),       "Operations Runtime and Supply Chain Controls"),
    (("codeql",),           "Operations Runtime and Supply Chain Controls"),
    (("dependabot",),       "Operations Runtime and Supply Chain Controls"),
    (("renovate",),         "Operations Runtime and Supply Chain Controls"),
    (("npm", "audit"),      "Operations Runtime and Supply Chain Controls"),
    # §7.12 Real-time / Not Applicable — ONLY when explicitly real-time
    (("websocket",),    "Real-time and Not Applicable Controls"),
    (("socket", "io"),  "Real-time and Not Applicable Controls"),
    (("realtime",),     "Real-time and Not Applicable Controls"),
)


def _tokenise(text: str) -> set[str]:
    """Tokenise into lower-case alphanumeric tokens, matching the
    sections-contract.yaml convention."""
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _infer_domain(control_name: str) -> str | None:
    """Return the canonical domain for ``control_name`` per the token index,
    or ``None`` when no entry matches deterministically."""
    if not isinstance(control_name, str) or not control_name.strip():
        return None
    tokens = _tokenise(control_name)
    if not tokens:
        return None
    # Prefer the most specific (longest tuple) match — multi-word entries
    # win over single-word entries when both apply.
    best: tuple[int, str] | None = None
    for token_tuple, domain in _DOMAIN_TOKEN_INDEX:
        if all(t in tokens for t in token_tuple):
            length = len(token_tuple)
            if best is None or length > best[0]:
                best = (length, domain)
    return best[1] if best else None


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def enforce(data: dict) -> tuple[dict, list[dict], list[dict]]:
    """Mutate ``data['security_controls']`` in place. Returns
    ``(data, name_changes, domain_changes)`` — both change lists carry
    audit dicts ``{"id", "from", "to", "control"}``."""
    controls = data.get("security_controls")
    if not isinstance(controls, list) or not controls:
        return data, [], []

    name_changes: list[dict] = []
    domain_changes: list[dict] = []

    for c in controls:
        if not isinstance(c, dict):
            continue
        cid = c.get("id") or "<anon>"

        # ----- RC-1: canonical name rewrite -----
        old_name = c.get("control")
        canonical = _canonicalize_name(old_name) if isinstance(old_name, str) else None
        if canonical:
            c["control"] = canonical
            name_changes.append({"id": cid, "from": old_name, "to": canonical})
            # Track in evidence_flags-style audit field on the control itself.
            flags = list(c.get("audit_flags") or [])
            token = "control_name_canonicalised"
            if token not in flags:
                flags.append(token)
            c["audit_flags"] = flags

        # ----- RC-6: domain re-routing -----
        # Use the (possibly already rewritten) canonical name for inference.
        current_domain = (c.get("domain") or "").strip()
        inferred = _infer_domain(c.get("control") or "")
        if inferred and current_domain and inferred != current_domain:
            # Only re-route AWAY from "Real-time and Not Applicable Controls"
            # or when the current domain has no relationship to the inferred
            # one. We intentionally do NOT shuffle controls between adjacent
            # IAM-flavour buckets (§7.2 IAM vs §7.3 Session) — those are
            # legitimately ambiguous and the LLM's choice is often the
            # preferable narrative grouping.
            #
            # The high-confidence re-route cases are:
            #   (a) current == "Real-time and Not Applicable Controls" and
            #       the control name has any token match anywhere else.
            #       This is the SC-011 / juice-shop 2026-05 case where Stage 1
            #       parked auth-rate-limit in §7.12.
            #   (b) current matches NO known domain string AND inferred is a
            #       known §7.X title — recovers from typo / shorthand domains.
            # Normalise the current domain by stripping/adding the trailing
            # " Controls" suffix — Stage 1 sometimes writes the §7 short
            # form ("Identity and Authentication") and we treat that as
            # equivalent to the canonical form ("Identity and Authentication
            # Controls"). The §7 title list lives in sections-contract.yaml.
            known_domain_strings = {d for _, d in _DOMAIN_TOKEN_INDEX}
            current_norm = current_domain
            if current_norm and not current_norm.endswith(" Controls"):
                if (current_norm + " Controls") in known_domain_strings:
                    # Stage 1 wrote a short form of a known §7 domain. Treat
                    # this as a stylistic (not semantic) drift — normalise
                    # the suffix in place but do not re-route to a different
                    # §7 section.
                    c["domain"] = current_norm + " Controls"
                    domain_changes.append({
                        "id": cid,
                        "from": current_domain,
                        "to": current_norm + " Controls",
                        "control": c.get("control"),
                    })
                    flags = list(c.get("audit_flags") or [])
                    token = "control_domain_suffix_normalised"
                    if token not in flags:
                        flags.append(token)
                    c["audit_flags"] = flags
                    continue
            if (
                current_norm == "Real-time and Not Applicable Controls"
                or current_norm not in known_domain_strings
            ):
                c["domain"] = inferred
                domain_changes.append({
                    "id": cid,
                    "from": current_domain or "<unset>",
                    "to": inferred,
                    "control": c.get("control"),
                })
                flags = list(c.get("audit_flags") or [])
                token = f"control_domain_reclassified_from_{current_domain or 'unset'}"
                if token not in flags:
                    flags.append(token)
                c["audit_flags"] = flags

    return data, name_changes, domain_changes


def _now() -> str:
    import datetime as _dt
    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(output_dir: Path, msg: str) -> None:
    # Severity is INFO (not WARN) because these drifts are deterministic
    # alias-map normalisations — Stage-1 LLM emits a domain name like
    # `'Identity and Authentication'`, the canonical form (per
    # `data/architectural-controls.yaml`) is
    # `'Identity and Authentication Controls'`, this script normalises.
    # That is by-design behaviour, not a failure signal — surfacing each
    # one as WARN produces 4-8 false alarms in the audit trail per run.
    # Promote to WARN if the drift indicates an UNKNOWN domain (i.e. a
    # real Stage-1 misclassification rather than a routine suffix fix).
    log = output_dir / ".agent-run.log"
    try:
        with log.open("a", encoding="utf-8") as f:
            f.write(f"{_now()}  [--------]  INFO   skill  CONTROL_TAXONOMY_DRIFT  {msg}\n")
    except OSError:
        pass


def main(argv: list[str]) -> int:
    if len(argv) < 1:
        print("Usage: enforce_control_taxonomy.py <output_dir> [--report-only]", file=sys.stderr)
        return 2
    report_only = "--report-only" in argv[1:]
    output_dir = Path(argv[0])
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"enforce_control_taxonomy: no yaml at {yaml_path}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"enforce_control_taxonomy: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print(f"enforce_control_taxonomy: {yaml_path} did not parse to a mapping", file=sys.stderr)
        return 1

    data, name_changes, domain_changes = enforce(data)

    if name_changes or domain_changes:
        if not report_only:
            yaml_path.write_text(
                yaml.safe_dump(
                    data,
                    sort_keys=False,
                    allow_unicode=True,
                    width=4096,
                    default_flow_style=False,
                ),
                encoding="utf-8",
            )
        # Audit messages
        for c in name_changes:
            _log(output_dir, f"name {c['id']}: {c['from']!r} -> {c['to']!r}")
        for c in domain_changes:
            _log(
                output_dir,
                f"domain {c['id']} ({c['control']!r}): {c['from']!r} -> {c['to']!r}",
            )
        summary = (
            f"enforce_control_taxonomy: canonicalised {len(name_changes)} "
            f"name(s); reclassified {len(domain_changes)} domain(s)"
        )
        if name_changes:
            details = ", ".join(f"{c['id']}:{c['from']!r}->{c['to']!r}" for c in name_changes[:4])
            summary += f" [names: {details}]"
        if domain_changes:
            details = ", ".join(f"{c['id']}:{c['from']!r}->{c['to']!r}" for c in domain_changes[:4])
            summary += f" [domains: {details}]"
        print(summary)
    else:
        print("enforce_control_taxonomy: no taxonomy drift — security_controls clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
