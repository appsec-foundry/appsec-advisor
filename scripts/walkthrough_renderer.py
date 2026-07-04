"""Deterministic §3 Attack Walkthroughs renderer.

Single-pass, no-LLM, no-iteration generator for `.fragments/attack-walkthroughs.md`.

Inputs: parsed `threat-model.yaml` + per-CWE template files under
`data/walkthrough-templates/`. Output: full §3 fragment that satisfies the
`attack_walkthroughs` contract (sections-contract.yaml) by construction —
no repair loop, no QA-fixer pass.

§3 is a flat list of per-Critical walkthroughs (`### 3.1`, `### 3.2`, …).
The §3.1 "Attack Chain Overview" cross-finding view (graph LR kill-chains)
was retired — the cross-finding/strategic picture is the standalone
`## Critical Attack Tree` section above §1, so attack paths are not narrated
in two competing places.

Contract (see `data/sections-contract.yaml → sections.attack_walkthroughs`):

  * Each Critical finding gets a `### 3.<n> <title>` heading; the owning
    T-NNN is named on the `**Source:** [T-NNN]` line below the heading.
  * Each §3.x body is ≥ 5 lines and contains a `sequenceDiagram`.
  * Labelled sections in fixed order (bold-header form):
    Attack Steps, Sequence Diagram, Defense in Depth.

The forbidden placeholder `WALKTHROUGH_FILL` MUST NOT appear in the
output (every slot is substituted at render time).
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Constants — bound the output and pin contract-required strings.
# ---------------------------------------------------------------------------

# 2026-05 iteration 3: walkthroughs are now short and concise. Only
# Criticals get a walkthrough; Highs are covered by their §8 Threat
# Register row.
MAX_HIGH_WALKTHROUGHS = 0

# Hard ceiling on the number of §3 walkthroughs (2026-07-02). A report with
# many Criticals otherwise renders one deep-dive narrative per Critical, which
# explodes §3 into dozens of near-identical blocks and buries the worst risks.
# §3 is the editorial "here are the attacks that matter most" section; the
# EXHAUSTIVE per-finding record (evidence, fix, classification) lives in §8,
# which carries every finding regardless of this cap. So capping §3 loses no
# information — only the narrative walkthrough for lower-priority Criticals,
# which are selected out by _walkthrough_priority (chain anchors + smallest
# breach-distance win). Kept intentionally small (reader feedback: 5–8 is
# digestible, >10 is a wall). Override via .skill-config.json `max_walkthroughs`
# (clamped to [1, MAX_WALKTHROUGHS_CEILING]).
DEFAULT_MAX_WALKTHROUGHS = 8
MAX_WALKTHROUGHS_CEILING = 10

# Minimums for the bullet lists feeding the walkthrough body. Set low —
# the renderer no longer pads with generic boilerplate to hit a body-line
# floor; the contract floor is 5 lines and the labelled-form sections plus
# a short intro already exceed that by construction.
MIN_PREREQS = 0
MIN_ATTACK_STEPS = 3
MIN_DETECTION_SIGNALS = 0

# Severity-phrase table feeding the Business Impact paragraph. Severity is
# taken from `threat.risk` (falls back to `threat.impact`).
# Severity → criticality dot, matching the composer's _SEV_ICON_TBL. The §3
# `**Source:**` finding ref carries this dot so it matches the dotted F-refs in
# §8/§10 and the asset/component tables; it is emitted here (not retrofitted by
# the composer's global F-dot pass) because the ref is `[T-NNN]` at this point
# and only becomes `[F-NNN]` after main()'s T→F display rewrite, which preserves
# the leading dot.
SEVERITY_DOT: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}

SEVERITY_PHRASES: dict[str, str] = {
    "critical": (
        "Critical impact — exploitation enables full bypass or extraction with "
        "minimal attacker effort and no compensating control intervenes"
    ),
    "high": (
        "High impact — exploitation meaningfully weakens a control or exposes a "
        "confidential surface; some prerequisites apply"
    ),
    "medium": ("Medium impact — exploitation is bounded in blast radius or requires non-trivial chained conditions"),
    "low": ("Low impact — limited blast radius, substantial prerequisites, or strong compensating controls in place"),
}

# Vektor-derived Attacker Profile narrative. Picked by `threat.vektor`.
ATTACKER_PROFILES: dict[str, str] = {
    "internet-anon": (
        "An anonymous internet attacker reaches the application over plain HTTP. "
        "No account, no credentials, no insider knowledge is required; tooling is "
        "`curl`, `httpie`, or any HTTP client."
    ),
    "internet-user": (
        "An authenticated user of the application reaches the vulnerable path "
        "through a logged-in session. Account acquisition is the only "
        "prerequisite beyond network reachability."
    ),
    "victim-required": (
        "An anonymous attacker crafts the payload, but execution requires a "
        "victim (authenticated user or admin) to interact with the malicious "
        "content — typically by visiting a link or loading a page while signed "
        "in."
    ),
    "repo-read": (
        "An attacker with read access to the public source repository extracts "
        "the sensitive material from version control. No application-level "
        "access is required for the extraction step; the extracted artefact is "
        "then used in a follow-up request against the live application."
    ),
}

# Suffix appended to the `internet-user` profile when self-registration is
# open — collapses the practical prerequisite to network reachability.
OPEN_REG_SUFFIX = (
    " Self-registration via `POST /api/Users` is open, so the attacker creates "
    "a fresh account in seconds; the practical prerequisite collapses to "
    "'reach the application'."
)

# Vektor-derived Prerequisites bullet list (used when the per-finding
# `attack_surface[].auth_required` lookup yields no concrete policy).
PREREQS: dict[str, list[str]] = {
    "internet-anon": [
        "HTTP/HTTPS access to the application",
        "No authentication state required",
    ],
    "internet-user": [
        "Authenticated session (valid JWT or session cookie)",
        "HTTP/HTTPS access to the endpoint exposed by `{file}`",
    ],
    "victim-required": [
        "Ability to deliver the payload to a victim (link, embedded content, hosted page)",
        "Victim must load the malicious content while authenticated",
    ],
    "repo-read": [
        "Read access to the public source repository (clone, blob view, or git history)",
        "Network reachability of the application to use the extracted artefact",
    ],
}

# Heuristic regex set used to recover a concrete HTTP endpoint URL from the
# free-text `scenario` field for the `{endpoint_guess}` substitution.
_ENDPOINT_RX = re.compile(r"\b(?:POST|GET|PUT|DELETE|PATCH)\s+(/[A-Za-z0-9_./-]+)")

# Default template-library location relative to the repo root.
DEFAULT_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "data" / "walkthrough-templates"

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _anchor(t_id: str) -> str:
    """Lowercase the T-/M-/F- identifier for in-document anchor links."""

    return (t_id or "").strip().lower()


def _to_fid(ref: str) -> str:
    """Merged-stage ``T-NNN`` id → the document-wide visible ``F-NNN`` id.

    The reader only ever sees ``F-NNN`` — §8 Findings Register headings, the
    Critical Attack Tree, every cross-reference; ``T-NNN`` is the internal
    merge-stage id with no visible heading. The composer's global pass rewrites
    bare ``[T-NNN](#t-nnn)`` markdown LINKS to ``F-NNN`` but cannot reach
    plain-text prose, alt/else labels inside a ```mermaid fence, or a link whose
    text carries a prefix (``[§8 T-NNN]``) — so the §3 walkthroughs shipped
    visible ``T-NNN`` the reader could not find (user report 2026-06).

    Use this for DISPLAY only — never for index lookups: the mitigation / chain
    / peer indexes are keyed by the merged ``T-NNN`` id. §8 emits a dual
    ``<a id="t-nnn"></a><a id="f-nnn"></a>`` anchor, so ``#f-nnn`` always
    resolves. Non ``T-NNN`` refs (already ``F-NNN``, ``M-NNN``, …) pass through.
    """
    return re.sub(r"^T-(\d+)$", r"F-\1", (ref or "").strip())


# Monochrome fill-ramp priority glyphs (● P1 full … ○ P4 empty). Mirrors
# compose_threat_model.py:_PRIO_RAMP_TBL — kept in sync so a linked measure
# in §3 carries the same dark→light priority ramp as the composer-rendered
# M-NNN links (2026-07-04 user request, restored over the ❶❷❸❹ digit form).
_PRIO_RAMP_TBL = {"p1": "●", "p2": "◕", "p3": "◑", "p4": "○"}


def _short_title(title: str, limit: int = 70) -> str:
    """Trim a finding title to fit a single-line Mermaid label.

    Paren-aware: a parenthesised suffix such as ``(lib/insecurity.ts:24)`` is
    treated as atomic — either fully retained or fully dropped. Truncating
    mid-paren would leave an unbalanced ``(`` in the label which Mermaid's
    flowchart parser interprets as the start of round-rect node syntax
    ``(text)`` inside ``[...]`` and aborts the diagram. The historical
    2026-05-24 juice-shop run shipped 10 broken chain-overview diagrams
    because of this.
    """

    title = (title or "").strip()
    if len(title) <= limit:
        return title
    truncated = title[: limit - 1].rstrip()
    # If the truncation cut mid-paren, drop the whole unbalanced suffix.
    if truncated.count("(") > truncated.count(")"):
        truncated = re.sub(r"\s*\([^)]*$", "", truncated).rstrip()
    return truncated + "…"


def _weakness_class(title: str) -> str:
    """The weakness-class portion of a finding title.

    Finding titles follow the contract ``<weakness class> — <file[:line]>``
    (em-dash separator). §3 walkthrough headings show only the class; the
    concrete ``file:line`` is carried on the **Source:** line just below.

    Keeping the ``— file:line`` tail OUT of the heading also keeps the
    heading's GitHub anchor free of the em-dash. GitHub slugifies ` — ` to a
    DOUBLE hyphen (``…object-reference--routesaddressts11``) while the
    composer's link target collapses it to a single (`…-routesaddressts11`):
    that mismatch broke every §3 ToC link (2026-06 user report). A clean
    class-only heading slugifies identically across GitHub, VS Code, and
    pandoc, so the anchor is renderer-stable.
    """
    return re.split(r"\s+—\s+", (title or "").strip(), maxsplit=1)[0].strip()


_TARGET_LABEL_WORD_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z]|$)")

# Framework dot-suffixes stripped from a stem so `oauth.component.ts` → "Oauth"
# and `auth.guard.ts` → "Auth" read as the FEATURE, not the file's role.
_FEATURE_STRIP_SUFFIXES = {
    "component",
    "service",
    "module",
    "guard",
    "interceptor",
    "controller",
    "middleware",
    "model",
    "models",
    "route",
    "routes",
    "startup",
    "config",
}
# Non-feature stems — infrastructure, security libs, and framework plumbing that
# name no user-facing feature. These fall back to the component zone rather than
# emitting "in Insecurity" / "in Server" / "in Register Websocket Events".
_GENERIC_FILE_STEMS = {
    "index",
    "server",
    "app",
    "main",
    "constants",
    "utils",
    "util",
    "helpers",
    "helper",
    "types",
    "common",
    "core",
    "setup",
    "insecurity",
    "security",
    "verify",
    "startup",
    "middleware",
    "models",
    "model",
    "database",
    "db",
    "handler",
    "handlers",
    "routes",
    "route",
    "api",
    "config",
    "bootstrap",
}


def _feature_from_file(file_hint: str) -> str:
    """Prettified FEATURE label from an evidence file: `routes/login.ts` →
    "Login", `changePassword.ts` → "Change Password". Returns "" — so the caller
    falls back to the component zone — for non-feature infra stems (`server`,
    `insecurity`, …) and for verbose (>2-word) stems (`registerWebsocketEvents`)
    that read better as the curated zone name than as a mangled file label."""
    stem = Path(file_hint).stem  # login.ts → login ; oauth.component.ts → oauth.component
    parts = stem.split(".")
    while len(parts) > 1 and parts[-1].lower() in _FEATURE_STRIP_SUFFIXES:
        parts.pop()
    stem = ".".join(parts)
    if stem.lower() in _GENERIC_FILE_STEMS:
        return ""
    words = _TARGET_LABEL_WORD_RE.findall(stem)
    if not words or len(words) > 2:  # empty or verbose → prefer the zone name
        return ""
    return " ".join(_FEATURE_ACRONYMS.get(w.lower(), w.capitalize()) for w in words)


# Known acronyms rendered in their canonical casing rather than Title-cased.
_FEATURE_ACRONYMS = {
    "oauth": "OAuth",
    "jwt": "JWT",
    "sql": "SQL",
    "xss": "XSS",
    "csrf": "CSRF",
    "ssrf": "SSRF",
    "url": "URL",
    "id": "ID",
    "api": "API",
    "sso": "SSO",
    "totp": "TOTP",
    "otp": "OTP",
    "2fa": "2FA",
    "mfa": "MFA",
}


def _anchor_stable_label(label: str) -> str:
    """Normalise a §3-heading target so its GitHub anchor is renderer-stable.

    The heading's slug must be identical whether produced by ``github_slug``
    (the link-target generator, which collapses whitespace to a single hyphen)
    or ``github_render_slug`` (what GitHub/pandoc actually render, which maps
    each space to a hyphen with no collapse). The two DIVERGE exactly when the
    text carries punctuation-surrounded-by-whitespace — ``" & "``, ``" / "``,
    ``" — "`` — because stripping the punctuation leaves two adjacent spaces
    that ``github_render_slug`` turns into ``--`` but ``github_slug`` turns into
    ``-`` (the 2026-07-03 §3 ToC breakage: a component-name fallback of
    "Authentication & Session Surface" produced an unresolvable ToC anchor).

    This is the same anchor-stability guarantee ``_weakness_class`` already
    enforces by dropping the ``— file:line`` tail; here we neutralise the
    remaining separators in the feature/component fallback: ``&`` → "and",
    other stray punctuation → space, then collapse to single spaces.
    """
    label = (label or "").strip()
    label = re.sub(r"\s*&\s*", " and ", label)
    # Any residual non-word / non-space / non-hyphen char (e.g. "/", "—") would
    # slugify unstably when surrounded by whitespace; drop it and let the
    # whitespace collapse below close the gap.
    label = re.sub(r"[^\w\s-]", " ", label)
    label = re.sub(r"\s+", " ", label).strip()
    return label


def _attack_target_label(threat: dict, yaml_data: dict) -> str:
    """Human-readable attack TARGET for the §3 heading (juice-shop 2026-07-03
    user request): headings must name the concrete FEATURE under attack —
    "SQL Injection against Login" — not the broad component zone
    ("… against Authentication & Identity"), which the user flagged as sperrig
    und unklar.

    Prefers the FEATURE derived from the evidence file (``routes/login.ts`` →
    "Login"), which is both specific and reader-legible, and stays distinct
    across same-weakness findings that live in different files. Falls back to
    the component's curated zone name only when the file yields no feature
    (generic infra stem), then a generic label.

    Every return path is routed through ``_anchor_stable_label`` so the
    resulting §3 heading anchor resolves identically on GitHub, VS Code, and
    pandoc regardless of ``&`` / ``/`` in a component name.
    """
    evidence = (threat.get("evidence") or [{}])[0] or {}
    file_hint = (evidence.get("file") or "").strip()
    if file_hint:
        feature = _feature_from_file(file_hint)
        if feature:
            return _anchor_stable_label(feature)
    comp_id = (threat.get("component") or "").strip()
    if comp_id:
        for c in yaml_data.get("components") or []:
            if isinstance(c, dict) and c.get("id") == comp_id:
                name = (c.get("name") or "").strip()
                if name:
                    return _anchor_stable_label(name)
    return "the Application"


def _mermaid_safe(label: str) -> str:
    """Strip Mermaid-hostile characters from a node label.

    Mermaid node labels in `[...]` form cannot contain unescaped pipes,
    quotes, brackets, or backticks without confusing the parser. We replace
    them with safe ASCII equivalents so the renderer never emits a chain
    block that breaks `mermaid_syntax`.
    """

    label = (label or "").strip()
    label = label.replace("`", "")
    label = label.replace("|", "/")
    label = label.replace("[", "(").replace("]", ")")
    label = label.replace('"', "'")
    return label


def _split_sentences(text: str) -> list[str]:
    """Sentence split for the Attack Steps path.

    Robust against the two real-scenario failure modes (user report 2026-06,
    §3.8 example): abbreviations like ``e.g.`` / ``i.e.`` splitting mid-clause,
    and code / SQL payloads (full of ``.``, ``,``, parens, ``--``) being torn
    across two steps so each reads as a broken fragment.

    Strategy: (1) mask backtick code spans so their internal punctuation can
    never trigger a split; (2) split ONLY at a ``.!?`` followed by whitespace
    AND a real new-sentence opener — an uppercase letter, an opening quote /
    paren / bracket, or a (masked) code span. A lowercase continuation
    (``e.g. union select …``) is therefore NOT a boundary; (3) restore the
    code spans. A naive ``(?<=[.!?])\\s+`` split (the previous behaviour) broke
    on every ``e.g.`` and on payload periods.
    """
    text = (text or "").strip()
    if not text:
        return []
    # (1) Mask inline code spans → sentinel so internal '.'/'?' never split.
    spans: list[str] = []

    def _mask(m: re.Match[str]) -> str:
        spans.append(m.group(0))
        return f"\x00{len(spans) - 1}\x00"

    masked = re.sub(r"`[^`\n]+`", _mask, text)
    # (2) Split at terminator + whitespace + sentence opener only.
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z\"'(\[\x00])", masked)

    def _restore(s: str) -> str:
        return re.sub(r"\x00(\d+)\x00", lambda m: spans[int(m.group(1))], s)

    return [_restore(p).strip().rstrip(".") for p in parts if p.strip()]


def _sentences_per_line(paragraph: str) -> list[str]:
    """Split a paragraph string into one sentence per line.

    Markdown still renders these joined as a single paragraph (a single
    intra-paragraph newline collapses to a space) — but each sentence becomes
    a non-blank line, which is what the walkthrough_depth contract counts.
    """

    sents = _split_sentences(paragraph)
    if not sents:
        return [paragraph.strip()] if paragraph.strip() else []
    return [f"{s.rstrip('.')}." for s in sents]


def _excerpt(evidence: dict | None, limit: int = 120) -> str:
    """Return a single-line code-fenced excerpt suitable for `{excerpt}`."""

    if not evidence:
        return ""
    raw = (evidence.get("excerpt") or "").strip()
    raw = raw.replace("\n", " ").replace("\r", " ")
    if len(raw) > limit:
        raw = raw[: limit - 1].rstrip() + "…"
    return raw


_INJECTION_VECTOR_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bsearch\b.*\b(query|param|input|term)\b|\?q=", re.IGNORECASE),
        "Crafted search query (HTML payload in `q=` parameter)",
    ),
    (
        re.compile(r"\bregister(?:ation)?\b.*\bemail\b|\bemail\b.*\bpayload\b", re.IGNORECASE),
        "Stored attacker-controlled email at registration (HTML payload)",
    ),
    (
        re.compile(r"\bfeedback\b.*\bcomment\b|\bcomment\b.*\b(submit|post)\b|\buser feedback\b", re.IGNORECASE),
        "Stored feedback / comment submission (HTML payload)",
    ),
    (
        re.compile(r"\bproduct\b.*\b(description|name|review)\b", re.IGNORECASE),
        "Stored product description / review (HTML payload)",
    ),
    (re.compile(r"\bprofile\b.*\b(image|name|bio)\b", re.IGNORECASE), "Stored profile field (HTML payload)"),
    (re.compile(r"\b(stored|persisted)\b", re.IGNORECASE), "Stored attacker-controlled content (HTML payload)"),
    (
        re.compile(r"\b(reflected|url|querystring)\b", re.IGNORECASE),
        "Reflected attacker-controlled input (HTML payload)",
    ),
)


def _endpoint_guess(scenario: str, fallback: str = "Crafted HTTP request to the affected endpoint") -> str:
    """Recover a concrete `METHOD /path` phrase from the scenario text.

    When the scenario lacks an explicit `METHOD /path` token, fall back
    to a vector-class hint derived from keyword patterns in the scenario
    (search query, registration email, feedback comment, etc.). Without
    the keyword fallback, every XSS / CSRF template renders the same
    generic "Crafted HTTP request to the affected endpoint" line, which
    reads as boilerplate template padding across 3+ distinct findings
    (verified juice-shop T-005/6/7 2026-05-25 run).
    """
    if not scenario:
        return fallback
    m = _ENDPOINT_RX.search(scenario)
    if m:
        verb = m.group(0).split()[0].upper()
        path = m.group(1)
        return f"{verb} {path}"
    for pattern, hint in _INJECTION_VECTOR_HINTS:
        if pattern.search(scenario):
            return hint
    return fallback


# ---------------------------------------------------------------------------
# Template loading
# ---------------------------------------------------------------------------


def load_templates(template_dir: Path) -> dict[str, dict]:
    """Load all CWE templates from disk into an in-memory dict keyed by CWE.

    The `_generic.yaml` fallback is keyed as ``"_generic"`` so callers can
    look it up cheaply when a finding's CWE has no dedicated template.
    """

    out: dict[str, dict] = {}
    if not template_dir.is_dir():
        return out
    for path in sorted(template_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(data, dict):
            continue
        key = (data.get("cwe") or "").strip().upper() or path.stem.upper()
        if path.stem.startswith("_"):
            key = path.stem  # `_generic`
        out[key] = data
    return out


def _template_for(cwe: str, templates: dict[str, dict], threat: dict | None = None) -> dict:
    """Resolve the per-CWE walkthrough template, with content-aware variants.

    CWE-327 (Broken / Risky Crypto Algorithm) covers two structurally
    distinct attack flows:
      - **Password-hashing**: dump → offline crack → reuse credentials
      - **JWT algorithm confusion**: HS256-vs-RS256 swap, alg=none
    A single template produces a wrong-narrative sequence diagram for
    the other half (verified juice-shop T-003 2026-05-25 run). When the
    threat title contains JWT-specific tokens, prefer the JWT variant
    template if one is loaded (`CWE-327-JWT`).
    """
    cwe_key = (cwe or "").upper()
    title = ((threat or {}).get("title") or "").lower()
    if cwe_key == "CWE-327" and ("jwt" in title or "algorithm confusion" in title or "alg confusion" in title):
        variant = templates.get("CWE-327-JWT")
        if variant:
            return variant
    return templates.get(cwe_key) or templates.get("_generic") or {}


# ---------------------------------------------------------------------------
# Index builders — derived once and reused per walkthrough.
# ---------------------------------------------------------------------------


def _mitigations_by_threat(yaml_data: dict) -> dict[str, list[dict]]:
    """Invert `mitigations[].threat_ids` into a `tid -> [mit]` map."""

    out: dict[str, list[dict]] = defaultdict(list)
    for m in yaml_data.get("mitigations") or []:
        if not isinstance(m, dict):
            continue
        for tid in m.get("threat_ids") or []:
            out[str(tid)].append(m)
    return dict(out)


def _assets_by_threat(yaml_data: dict) -> dict[str, list[dict]]:
    """Invert `assets[].linked_threats` into a `tid -> [asset]` map."""

    out: dict[str, list[dict]] = defaultdict(list)
    for a in yaml_data.get("assets") or []:
        if not isinstance(a, dict):
            continue
        for tid in a.get("linked_threats") or []:
            out[str(tid)].append(a)
    return dict(out)


def _attack_surface_by_path(yaml_data: dict) -> dict[str, dict]:
    """Index `attack_surface[]` by `entry_point` for prerequisite enrichment."""

    out: dict[str, dict] = {}
    for s in yaml_data.get("attack_surface") or []:
        if isinstance(s, dict) and s.get("entry_point"):
            out[str(s["entry_point"])] = s
    return out


def _peers_by_cwe(critical_threats: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for t in critical_threats:
        out[(t.get("cwe") or "").upper()].append(str(t.get("id") or ""))
    return dict(out)


# ---------------------------------------------------------------------------
# Threat selection (deterministic ordering).
# ---------------------------------------------------------------------------


_RISK_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _risk_of(t: dict) -> str:
    return (t.get("risk") or t.get("impact") or "").strip().lower()


def _sort_key(t: dict) -> tuple[int, str]:
    return _RISK_RANK.get(_risk_of(t), 9), str(t.get("id") or "")


def _walkthrough_priority(t: dict) -> tuple:
    """Most-important-first ordering for the capped §3 selection. Lower sorts
    earlier. Compound-chain anchors come first (they are the entry point of a
    code-verified abuse chain), then findings closest to a breach
    (smaller ``breach_distance``), then stable ``id`` order for determinism."""
    is_anchor = bool(t.get("compound_chain_ids")) or (
        (t.get("chain_role") or "").strip().lower() in {"anchor", "entry_point", "initial_access", "entry"}
    )
    bd = t.get("breach_distance")
    bd = bd if isinstance(bd, (int, float)) else 999
    return (0 if is_anchor else 1, bd, str(t.get("id") or ""))


def resolve_walkthrough_cap(yaml_data: dict | None = None, config: dict | None = None) -> int:
    """Resolve the §3 walkthrough cap: ``max_walkthroughs`` from skill-config
    when present (clamped to [1, MAX_WALKTHROUGHS_CEILING]), else the default."""
    cap = DEFAULT_MAX_WALKTHROUGHS
    if isinstance(config, dict):
        raw = config.get("max_walkthroughs")
        if isinstance(raw, int) and raw > 0:
            cap = raw
    return max(1, min(cap, MAX_WALKTHROUGHS_CEILING))


def select_walkthrough_picks(yaml_data: dict, cap: int | None = None) -> list[dict]:
    """The ``cap`` highest-priority Criticals (chain anchors + smallest
    breach-distance first) + a small budget of Highs. Capping keeps §3 from
    exploding when a report has many Criticals; every finding — walked through
    or not — still has its full §8 Findings Register row."""

    if cap is None:
        cap = DEFAULT_MAX_WALKTHROUGHS
    cap = max(1, min(int(cap), MAX_WALKTHROUGHS_CEILING))
    threats = [t for t in (yaml_data.get("threats") or []) if isinstance(t, dict)]
    crit = sorted([t for t in threats if _risk_of(t) == "critical"], key=_walkthrough_priority)
    high = sorted([t for t in threats if _risk_of(t) == "high"], key=_sort_key)
    return (crit + high[:MAX_HIGH_WALKTHROUGHS])[:cap]


# ---------------------------------------------------------------------------
# Slot renderers — each pure, snapshot-testable.
# ---------------------------------------------------------------------------


def render_attacker_profile(
    threat: dict,
    yaml_meta: dict,
    template: dict,
) -> str:
    """Single-paragraph profile picked by `threat.vektor`."""

    vektor = (threat.get("vektor") or "internet-user").strip()
    profile = ATTACKER_PROFILES.get(vektor, ATTACKER_PROFILES["internet-user"])
    if vektor == "internet-user" and yaml_meta.get("open_user_registration"):
        profile = profile + OPEN_REG_SUFFIX
    overrides = template.get("attacker_profile_overrides") or {}
    if isinstance(overrides, dict) and vektor in overrides and overrides[vektor]:
        profile = str(overrides[vektor]).strip()
    return profile


def render_prerequisites(
    threat: dict,
    attack_surface_by_path: dict[str, dict],
    file_hint: str,
) -> list[str]:
    """Vektor-template list, optionally enriched with concrete auth policy.

    Returns the genuine prerequisites only — no boilerplate padding. The
    caller is responsible for handling the empty-list case (the current
    layout does not render this section at all).
    """

    vektor = (threat.get("vektor") or "internet-user").strip()
    items = list(PREREQS.get(vektor, PREREQS["internet-user"]))
    out = [b.replace("{file}", file_hint or "<unknown>") for b in items]
    # Enrich with the concrete auth policy of the matching attack-surface entry.
    for entry, surface in attack_surface_by_path.items():
        if not entry:
            continue
        if file_hint and file_hint.endswith(entry.lstrip("/")):
            auth_required = surface.get("auth_required")
            if auth_required:
                out.append(f"Endpoint policy at `{entry}` requires: {auth_required}")
                break
    return out


# Code-token formatters for attack-step prose. apply_prose_fixes (post-compose)
# already backticks HTTP method+route, bare filenames, function calls and dotted
# API tokens; these cover the gaps it cannot: inline `path/file.ext:line`
# evidence refs, quoted injection payloads (`param="…"`), and UPPERCASE SQL
# statements. SQL keywords are matched case-SENSITIVELY so English words
# ("the attacker can update …", "users select …") are never mistaken for SQL.
_STEP_FILELINE_RE = re.compile(r"(?<![`\w])([\w][\w./-]*\.[A-Za-z]{1,6}:\d+(?:-\d+)?)(?![`\w:])")
_STEP_PAYLOAD_ASSIGN_RE = re.compile(r'(?<![`\w])([A-Za-z_]\w*="[^"]{0,100}")(?![`])')
_STEP_SQL_RE = re.compile(
    r"(?<![`\w])((?:UNION\s+)?(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^…`;,.]*?)"
    r"(?=\s+(?:which|yielding|queries|query|attack|and the|to|extracts?|can|dumps?|"
    r"returns?|exposes?|reveals?|enables?|allows?|succeeds?|payload|against|in the)\b"
    r"|[…;,.]|$)"
)
# A matched SELECT/UPDATE/… span is only REAL SQL (worth backticking) when it
# carries a structural SQL signal. Without this gate the regex wrapped prose
# that merely opens with a SQL verb — "UNION SELECT payload (e.g" and
# "SELECT from Users extracts all email addresses…" both shipped as code spans
# (user report 2026-06).
_STEP_SQL_SIGNAL_RE = re.compile(r"\b(FROM|WHERE|INTO|VALUES|SET|JOIN)\b|\*|--|,\s*\d", re.IGNORECASE)
# Trailing-prose trim — cut a matched SQL span at the first prose connector so
# "SELECT from Users extracts all …" backticks only "SELECT from Users".
_STEP_SQL_PROSE_CUT_RE = re.compile(
    r"\s+(?:which|yielding|queries|query|attack|and the|to|extracts?|can|dumps?|"
    r"returns?|exposes?|reveals?|enables?|allows?|succeeds?|payload|against|in the)\b.*$",
    re.IGNORECASE,
)


def _wrap_step_sql(m: re.Match[str]) -> str:
    sql = m.group(1).strip()
    sql = _STEP_SQL_PROSE_CUT_RE.sub("", sql).strip()
    if sql and _STEP_SQL_SIGNAL_RE.search(sql):
        return f"`{sql}`"
    return m.group(0)


# Code function call — a dotted member-call (`crypto.createHash('md5')`,
# `vm.runInContext()`, `libxmljs2.parseXml()`) OR a simple empty-arg call
# (`safeEval()`). Both are unambiguous code the LLM scenario routinely leaves
# un-backticked. The callee word must abut the `(` (no space), so prose like
# "gains access (admin)" never matches.
_STEP_CALL_RE = re.compile(
    r"(?<![`\w])("
    r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\([^()]{0,80}\)"  # dotted call
    r"|[A-Za-z_]\w*\(\)"  # bare empty-arg call
    r")(?!`)"
)
# `X`.member / `X`-NNN splits left behind when the LLM backticked only the
# head of a dotted path or a file:line range. Merge the trailing continuation
# back INTO the code span so the whole token is one consistent span.
_STEP_DOTTED_MERGE_RE = re.compile(r"`([^`\n]+)`\.([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)")
_STEP_RANGE_MERGE_RE = re.compile(r"`([^`\n]+:\d+)`-(\d+)\b")
# `file:?` — the {line} template slot when the evidence line is unknown. The
# `:?` placeholder is noise; collapse the span to the bare file.
_STEP_UNKNOWN_LINE_RE = re.compile(r"`([\w./-]+):\?`")


def _format_step_code(step: str) -> str:
    """Normalise code formatting in one attack step.

    Two passes: (1) backtick code tokens the downstream prose-fixer does not
    cover (file:line, payload assignment, SQL, function calls), leaving
    existing backtick spans untouched; (2) repair inconsistent LLM-authored
    spans — merge split dotted-paths / file:line ranges back into one span
    and drop the `:?` unknown-line placeholder. Idempotent."""
    out: list[str] = []
    for chunk in re.split(r"(`[^`\n]+`)", step):
        if chunk.startswith("`"):
            out.append(chunk)
            continue
        chunk = _STEP_FILELINE_RE.sub(r"`\1`", chunk)
        chunk = _STEP_PAYLOAD_ASSIGN_RE.sub(r"`\1`", chunk)
        chunk = _STEP_SQL_RE.sub(_wrap_step_sql, chunk)
        chunk = _STEP_CALL_RE.sub(r"`\1`", chunk)
        out.append(chunk)
    joined = "".join(out)
    # Repair pass on the joined string (operates across the span boundaries).
    joined = _STEP_DOTTED_MERGE_RE.sub(r"`\1.\2`", joined)
    joined = _STEP_RANGE_MERGE_RE.sub(r"`\1-\2`", joined)
    joined = _STEP_UNKNOWN_LINE_RE.sub(r"`\1`", joined)
    return joined


def render_attack_steps(threat: dict, template: dict) -> list[str]:
    """Source-of-truth: `threat.scenario`. Fallback to template skeleton.

    Returns short, concrete attack steps derived from the threat's
    `scenario` field; falls back to the CWE template when scenario is
    empty. Capped at MIN_ATTACK_STEPS+1 so the section stays readable —
    no generic boilerplate padding.
    """

    # Strip trailing `CWE: CWE-NNN[.]` sentence the threat-analyst agent
    # routinely appends to the `scenario` field — it is metadata that
    # belongs in the `cwe` field, not narrative. When carried through
    # sentence-splitting it surfaces as a junk Attack Step like
    # "5. CWE: CWE-89." that confuses readers and adds zero attacker
    # context. Drop it BEFORE _split_sentences so the trailing item from
    # the YAML never becomes a numbered step.
    raw_scenario = (threat.get("scenario") or "").strip()
    raw_scenario = re.sub(
        r"\s*(?:^|\.\s)CWE:\s*CWE-\d+\.?\s*$",
        "",
        raw_scenario,
        flags=re.IGNORECASE,
    )
    # Also drop a BARE trailing-metadata run the analyst appends after the
    # narrative — a plain `CWE-89` (no `CWE:` prefix) and/or an evidence
    # `routes/login.ts:34` file:line. Both are register fields, not steps;
    # uncaught they surface as nonsense steps ("2. CWE-89.",
    # "3. routes/login.ts:34.").
    raw_scenario = (
        re.sub(
            r"(?:\s*(?:CWE-\d+|[\w./-]+\.[A-Za-z]{1,6}:\d+)\s*\.?\s*)+$",
            "",
            raw_scenario,
            flags=re.IGNORECASE,
        )
        .rstrip(". ")
        .strip()
    )
    # Normalise dot-runs ("AND password... yielding") to a single ellipsis
    # char BEFORE sentence-splitting. `_split_sentences` breaks on `.!?` + space
    # but NOT on `…`, so an ellipsis stays a stylistic pause instead of carving
    # off a dangling lower-case fragment ("2. yielding the first row (admin).").
    # `…` also preserves intra-code elisions (`<script>…</script>`,
    # `SELECT … LIKE`) that a comma would have mangled.
    raw_scenario = re.sub(r"\.{2,}", "…", raw_scenario)
    sentences = _split_sentences(raw_scenario)
    # Defensive: drop any residual sentence that is ONLY a CWE tagline or a
    # bare file:line token (covers mid-string metadata the strips above missed).
    sentences = [
        s
        for s in sentences
        if not re.match(r"^\s*(?:CWE\s*:?\s*)?CWE-\d+\.?\s*$", s, flags=re.IGNORECASE)
        and not re.match(r"^[\w./-]+\.[A-Za-z]{1,6}:\d+\.?\s*$", s)
    ]
    template_steps = list(
        template.get("attack_steps_template")
        or [
            # Attacker-action voice (juice-shop 2026-07-03): the attacker is the
            # subject of each step, not the code. Generic fallback used only when
            # a CWE template has no `attack_steps_template` and the scenario is short.
            "The attacker crafts a request targeting the weak spot at `{file}:{line}`.",
            "The attacker sends it; the missing control never rejects the crafted input.",
            "The attacker reads the response and confirms the bypass succeeded.",
        ]
    )

    evidence = (threat.get("evidence") or [{}])[0] or {}
    mapping = {
        "file": (evidence.get("file") or "<unknown>"),
        "line": str(evidence.get("line") or "?"),
        "component": (threat.get("component") or "the application").strip() or "the application",
        "cwe": (threat.get("cwe") or "").strip() or "the weakness class",
        "title": _short_title(threat.get("title") or "", 120),
        "tid": _to_fid(str(threat.get("id") or "")),
    }
    template_steps = [_format_template_string(s, mapping) for s in template_steps]

    body: list[str] = []
    body.extend(sentences[:MIN_ATTACK_STEPS])
    if not body:
        body.extend(template_steps)
    else:
        # Pad up to MIN_ATTACK_STEPS with template_steps (template-specific,
        # with `{file}` / `{line}` already substituted) — no generic
        # boilerplate. PREPEND the missing steps rather than appending them:
        # a template step describes a stage the free-authored `scenario`
        # prose typically already assumes happened (e.g. cwe-89's template
        # opens with "Identify the vulnerable input parameter…", a
        # reconnaissance step) — appending it after real scenario sentences
        # put "identify the parameter" AFTER "submit the exploit payload",
        # reversing attack chronology (juice-shop 2026-07-03 user report:
        # Attack Steps must read in a clear, attacker-followable order).
        missing = [s for s in template_steps if s not in body]
        needed = MIN_ATTACK_STEPS - len(body)
        if needed > 0:
            body = missing[:needed] + body
    return [f"{i + 1}. {_format_step_code(s.rstrip('.'))}." for i, s in enumerate(body[:MIN_ATTACK_STEPS])]


def _format_template_string(raw: str, mapping: dict) -> str:
    """Safe template substitution that tolerates missing keys."""

    class _SafeDict(dict):
        def __missing__(self, key):  # pragma: no cover - obvious fallback
            return "{" + key + "}"

    try:
        return raw.format_map(_SafeDict(mapping))
    except (IndexError, ValueError):
        return raw


def _diagram_actors(diagram: str) -> tuple[str, str]:
    """Return (attacker, target) participant names declared in a sequenceDiagram.

    Attacker = first ``actor``; target = first ``participant`` (falling back to
    a second ``actor``, then literal ``App``). Reusing declared names keeps the
    injected alt/else arrows mermaid-valid.
    """
    actors: list[str] = []
    participants: list[str] = []
    for line in diagram.splitlines():
        m = re.match(r"\s*(actor|participant)\s+([A-Za-z0-9_]+)", line)
        if m:
            (actors if m.group(1) == "actor" else participants).append(m.group(2))
    attacker = actors[0] if actors else "Attacker"
    target = participants[0] if participants else (actors[1] if len(actors) > 1 else "App")
    return attacker, target


def _ensure_alt_else_block(diagram: str, tid: str, mid: str, mit_title: str) -> str:
    """Guarantee a QA-Check-8e alt/else/end block labelled
    ``alt Current state — T-NNN`` / ``else After M-NNN — <mitigation>``.

    The per-CWE templates render flat sequence diagrams (no alt/else), so
    without this every §3 walkthrough is re-flagged by the QA reviewer on
    each thorough run and burns a REPAIR_MODE iteration. Deterministic from
    yaml; reuses the diagram's declared participants so the result renders.
    """
    short = (mit_title or "").split(" — ", 1)[0].strip()[:60] or "the documented fix"
    # `;` is a Mermaid statement terminator — a mitigation title like
    # "Remove hardcoded RSA private key; rotate to env vars" splits the alt/else
    # label mid-clause and fails the authoritative parser (2026-06 REPAIR_MODE
    # trigger). Normalise statement-breaking punctuation in the label; `_mermaid_safe`
    # only guards `[...]`-node labels, not alt/else labels, so handle them here.
    short = short.replace(";", ",").replace("#", "").replace("\n", " ").strip()
    # Display the visible F-NNN id (T-NNN is internal — `tid` here is used only
    # for the alt label and the "exploiting <id>" arrow, both display).
    tid = _to_fid(tid)
    alt_label = f"alt Current state — {tid}" if tid else "alt Current state"
    mid_ref = mid if (mid or "").startswith("M-") else (mid or "mitigation")
    else_label = f"else After {mid_ref} — {short}"

    if re.search(r"^\s*alt\b", diagram, re.M):
        # Generic-fallback path already has an alt block — just relabel.
        diagram = re.sub(r"^(\s*)alt\b.*$", lambda m: f"{m.group(1)}{alt_label}", diagram, count=1, flags=re.M)
        diagram = re.sub(r"^(\s*)else\b.*$", lambda m: f"{m.group(1)}{else_label}", diagram, count=1, flags=re.M)
        return diagram

    attacker, target = _diagram_actors(diagram)
    block_lines = [
        f"    {alt_label}",
        f"        {attacker}->>{target}: The attacker sends the exploit for {tid or 'the weakness'}",
        f"        {target}-->>{attacker}: Exploit succeeds",
        f"    {else_label}",
        f"        {attacker}->>{target}: The attacker retries the same request after the fix",
        f"        {target}-->>{attacker}: Request rejected",
        "    end",
    ]
    lines = diagram.splitlines()
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip() == "```":
            lines[i:i] = block_lines
            break
    out = "\n".join(lines)
    return out + "\n" if diagram.endswith("\n") else out


def render_sequence_diagram(
    threat: dict,
    template: dict,
    mitigation_primary_id: str,
    mitigation_primary_title: str = "",
) -> str:
    """Substitute the per-CWE Mermaid template against the threat's evidence."""

    raw = template.get("sequence_diagram") or ""
    if not raw.strip():
        # Generic last-resort fallback — should not happen if `_generic.yaml`
        # exists, but keeps the renderer robust in degraded environments.
        raw = (
            "```mermaid\n"
            "sequenceDiagram\n"
            "    autonumber\n"
            "    actor Attacker\n"
            "    participant App\n"
            "    Note over App: {component} — {file}:{line}\n"
            "    alt Current state\n"
            "        Attacker->>App: Crafted request exploits the weakness at {file} line {line}\n"
            "        App-->>Attacker: Response confirms exploitation\n"
            "    else After {mitigation_primary}\n"
            "        Attacker->>App: Same request\n"
            "        App-->>Attacker: Request rejected\n"
            "    end\n"
            "```\n"
        )
    evidence = (threat.get("evidence") or [{}])[0] or {}
    mapping = {
        "tid": _to_fid(str(threat.get("id") or "")),
        "title": _short_title(threat.get("title") or "", 120),
        "component": (threat.get("component") or "the application").strip() or "the application",
        "file": (evidence.get("file") or "<unknown>"),
        "line": str(evidence.get("line") or "?"),
        "excerpt": _excerpt(evidence),
        "cwe": (threat.get("cwe") or "").strip() or "the weakness class",
        "endpoint_guess": _endpoint_guess(threat.get("scenario") or ""),
        "mitigation_primary": mitigation_primary_id or "the recommended fix",
    }
    diagram = _format_template_string(raw, mapping).rstrip() + "\n"
    diagram = _ensure_alt_else_block(
        diagram,
        str(threat.get("id") or ""),
        mitigation_primary_id,
        mitigation_primary_title,
    )
    return diagram


def render_business_impact(threat: dict, asset_ids: list[str]) -> str:
    """Severity-phrase + exposed-asset citation; one paragraph."""

    severity = _risk_of(threat) or "high"
    phrase = SEVERITY_PHRASES.get(severity, SEVERITY_PHRASES["high"])
    component = (threat.get("component") or "the affected component").strip()
    asset_phrase = ""
    if asset_ids:
        rendered = ", ".join(f"`{a}`" for a in asset_ids[:3])
        asset_phrase = f" Exposed assets: {rendered}."
    return f"{phrase}.{asset_phrase} Containment is at `{component}`."


def render_detection_signals(threat: dict, template: dict) -> list[str]:
    """CWE-keyed bullet list with `{component}` / `{file}` substitution.

    Returns just the CWE-template signals (no generic SIEM padding). The
    current layout no longer renders this section by default; the helper
    is kept so future callers can opt into it without rewriting it.
    """

    raw_bullets = list(template.get("detection_signals") or [])
    if not raw_bullets:
        return []
    evidence = (threat.get("evidence") or [{}])[0] or {}
    mapping = {
        "component": (threat.get("component") or "the application").strip(),
        "file": evidence.get("file") or "<unknown>",
        "line": str(evidence.get("line") or "?"),
        "cwe": (threat.get("cwe") or "").strip() or "the weakness class",
    }
    return [_format_template_string(b, mapping) for b in raw_bullets]


def render_defense_in_depth(threat: dict, mitigations_by_threat: dict[str, list[dict]]) -> tuple[list[str], str]:
    """Primary + layered mitigations. Returns (bullets, primary_id) tuple.

    ``primary_id`` is the string inserted into the sequence-diagram template's
    `else After {mitigation_primary}` line. To satisfy the QA regex
    ``^\\s*else\\s+After\\s+(?:mitigation|M-\\d{3,4})``, the fallback when no
    `M-NNN` is linked is the literal word ``mitigation`` (not "the recommended
    fix" or any other free-form phrase).
    """

    tid = str(threat.get("id") or "")
    mits = mitigations_by_threat.get(tid, [])
    if not mits:
        bullets = [
            "Primary mitigation: **not yet defined** — add an entry to `threat-model.yaml → mitigations[]` "
            "referencing this threat ID and re-run the assessment.",
            "Compensating control: until a primary mitigation is defined, "
            "monitoring on the affected code path is the only remaining layer.",
        ]
        return bullets, "mitigation"
    bullets: list[str] = []
    for i, m in enumerate(mits):
        label = "Primary mitigation" if i == 0 else "Defence in depth"
        mid = str(m.get("id") or "")
        title = (m.get("title") or "").strip()
        if not title:
            title = "mitigation entry"
        # Parens form: `[M-001](#m-001) (Upgrade JWT libraries …)`. Inline-
        # prose context where the em-dash form would be downgraded to a
        # hyphen by _normalize_emdashes (the bullet starts with "Primary
        # mitigation:" not "- [M-…", so the whitelist there doesn't fire).
        # Short-label rule mirrors RenderContext.linkify_with_short_label:
        # drop the ` — <file>` Stage-1-LLM tail.
        short_title = title.split(" — ", 1)[0].strip()[:160]
        # Leading monochrome priority circle (● P1 … ○ P4) so a linked measure
        # in §3 carries the same dark→light rollout-priority ramp as every other
        # M-NNN link (MS Top-Mitigations, §8 Fix cells). Fill-ramp, 2026-07-04.
        prio = str(m.get("priority") or "").strip().lower()
        digit = _PRIO_RAMP_TBL.get(prio, "")
        prefix = f"{digit} " if digit else ""
        bullets.append(f"{label}: {prefix}[{mid}](#{_anchor(mid)}) ({short_title})")
    # No padding bullet — bullets list is intentionally short when only one
    # mitigation is linked. The Detection Signals subsection below already
    # provides the layered-defense complement; appending a generic
    # "compensating control" sentence here is filler that erodes signal.
    return bullets, str(mits[0].get("id") or "mitigation")


def render_cross_references(
    threat: dict,
    chain_membership: dict[str, list[int]],
    peers_by_cwe: dict[str, list[str]],
) -> list[str]:
    """Always returns ≥ 3 bullets so the section carries enough density."""

    tid = str(threat.get("id") or "")
    cwe = (threat.get("cwe") or "").upper()
    bullets: list[str] = []
    chains = chain_membership.get(tid, [])
    if chains:
        chain_links = ", ".join(f"[Chain {n}](#chain-{n})" for n in chains)
        bullets.append(f"§3.1 chain membership: {chain_links}")
    else:
        bullets.append("§3.1 chain membership: this finding is treated as a standalone walkthrough — no compound chain")
    bullets.append(f"§8 Findings Register: [{_to_fid(tid)}](#{_anchor(_to_fid(tid))})")
    siblings = [p for p in peers_by_cwe.get(cwe, []) if p != tid][:2]
    if siblings:
        sib_links = ", ".join(f"[{_to_fid(p)}](#{_anchor(_to_fid(p))})" for p in siblings)
        bullets.append(f"Sibling findings (same CWE class): {sib_links}")
    else:
        bullets.append(f"Sibling findings (same CWE class): none — {cwe or 'this class'} is unique in this assessment")
    bullets.append(
        f"§7 Security Architecture coverage for `{(threat.get('component') or 'the affected component').strip()}`"
    )
    return bullets


# ---------------------------------------------------------------------------
# (§3.1 Attack Chain Overview was retired — the Critical Attack Tree above
# §1 is the single cross-finding/strategic view. The deterministic chain
# catalogue, its label helpers, and the per-chain renderer were removed with
# it; §3 now renders only the per-finding walkthroughs below.)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Top-level rendering — assemble the final §3 fragment.
# ---------------------------------------------------------------------------


def _render_walkthrough_block(
    threat: dict,
    yaml_data: dict,
    indexes: dict,
    templates: dict[str, dict],
    chain_membership: dict[str, list[int]],
    peers_by_cwe: dict[str, list[str]],
    walkthrough_index: int,
) -> str:
    """Render one `### 3.<n> T-NNN — <title>` walkthrough block."""

    tid = str(threat.get("id") or "")
    fid = _to_fid(tid)  # visible id (T-NNN → F-NNN); `tid` stays for index lookups
    title = (threat.get("title") or "untitled finding").strip()
    cwe = (threat.get("cwe") or "").upper()
    template = _template_for(cwe, templates, threat)

    evidence = (threat.get("evidence") or [{}])[0] or {}
    file_hint = (evidence.get("file") or "").strip()

    mit_bullets, primary_mit_id = render_defense_in_depth(threat, indexes["mitigations"])
    _primary_mits = indexes["mitigations"].get(tid, [])
    primary_mit_title = (_primary_mits[0].get("title") or "") if _primary_mits else ""

    steps = render_attack_steps(threat, template)
    diagram = render_sequence_diagram(threat, template, primary_mit_id, primary_mit_title)

    # Heading HARD RULE (per agents/phases/phase-group-finalization.md §3
    # heading-format contract): NO T-NNN prefix, ≤80 chars (check_heading_hygiene
    # warns >80, errors >100). The T-NNN appears once in the **Source:** line
    # below — wrapping it into the heading inflates the line and trips the gate.
    # Format is "<Weakness> in <Feature>" (juice-shop 2026-07-03 user request):
    # concise, feature-scoped, reader-legible, and consistent with §7 finding
    # titles ("SQL Injection in Login"). The earlier "<Weakness> Attack against
    # <broad component zone>" form was flagged as sperrig/unklar; the connector
    # is neutral "in" rather than "against" because the left side is a WEAKNESS
    # class (a noun phrase by contract, e.g. "Insecure Direct Object Reference"),
    # not an attack — "against" would over-claim it as one. The target names the
    # concrete FEATURE (login, search), not the zone, and keeps same-weakness
    # findings in different files distinct. The `— file:line`
    # tail from the finding title stays OUT of the heading (see _weakness_class):
    # it carries no info the **Source:** line lacks and its em-dash made the
    # GitHub heading anchor diverge from the composer's link target.
    # Truncate the WEAKNESS class, not the combined string — some weakness
    # classes are long verb-phrases ("Mass assignment privileged field
    # accepted from request") that would otherwise eat the budget and leave
    # "… Attack against Back…" (target cut mid-word). The target is always
    # short (a curated component name or a 1-4 word file label) and is the
    # part that actually differentiates same-weakness headings, so it must
    # survive intact; the weakness class tolerates abbreviation.
    _target = _attack_target_label(threat, yaml_data)
    _connector = " in "
    _weakness_budget = max(20, 78 - len(_connector) - len(_target))
    heading = f"### 3.{walkthrough_index} {_short_title(_weakness_class(title), _weakness_budget)}{_connector}{_target}"

    lines: list[str] = []
    lines.append(heading)
    lines.append("")
    _sev_key = (threat.get("effective_severity") or threat.get("risk") or "").strip().lower()
    _dot = SEVERITY_DOT.get(_sev_key, "")
    _dot_prefix = f"{_dot} " if _dot else ""
    lines.append(
        f"**Source:** {_dot_prefix}[{fid}](#{_anchor(fid)}) — `{file_hint or '<unknown>'}:{evidence.get('line') or '?'}`"
    )
    lines.append("")
    lines.append(
        f"Severity **{(threat.get('risk') or 'High').strip()}** "
        f"({cwe or 'CWE-?'}). STRIDE: {threat.get('stride') or 'n/a'}. "
        f"See [§8 {fid}](#{_anchor(fid)}) for the full register row."
    )
    lines.append("")

    lines.append("**Attack Steps**")
    lines.append("")
    lines.extend(steps)
    lines.append("")

    lines.append("**Sequence Diagram**")
    lines.append("")
    lines.append(diagram.rstrip())
    lines.append("")
    # QA Check 8.0 — every §3 Mermaid block must be followed by a
    # **Key takeaway:** sentence. Deterministic from yaml so the reviewer
    # does not re-flag and force a REPAIR_MODE iteration on thorough runs.
    # Emit the mitigation as a real `[M-NNN](#m-nnn)` link (not bare text) so
    # the composer's global priority-circle pass annotates it (❶ P1 … ❹ P4) and
    # a later qa_checks autofix linkify pass finds it already complete. A bare
    # `M-NNN` here would be linkified by autofix WITHOUT the circle (the autofix
    # linkifier has no priority data), leaving an un-annotated §3 ref.
    if str(primary_mit_id).startswith("M-"):
        _kt_mit = f"[{primary_mit_id}](#{primary_mit_id.lower()})"
    else:
        _kt_mit = "a defined mitigation"
    _kt_short = (primary_mit_title or "").split(" — ", 1)[0].strip()[:60]
    lines.append(
        f"**Key takeaway:** Until {_kt_mit}"
        f"{f' ({_kt_short})' if _kt_short else ''} lands, {fid} is exploitable at "
        f"`{file_hint or '<unknown>'}:{evidence.get('line') or '?'}` "
        f"({(threat.get('risk') or 'High').strip()}-severity, {cwe or 'CWE-?'})."
    )
    lines.append("")

    lines.append("**Defense in Depth**")
    lines.append("")
    for b in mit_bullets:
        lines.append(f"- {b}")

    return "\n".join(lines)


def render_attack_walkthroughs_md(
    yaml_data: dict,
    *,
    template_dir: Path | None = None,
) -> str:
    """Build the complete `.fragments/attack-walkthroughs.md` body.

    The returned string starts with the H2 `## 3. Attack Walkthroughs`
    heading and contains every contract-required sub-section.
    """

    templates = load_templates(template_dir or DEFAULT_TEMPLATE_DIR)
    picks = select_walkthrough_picks(yaml_data)
    _all_threats = [t for t in (yaml_data.get("threats") or []) if isinstance(t, dict)]
    _n_critical_total = sum(1 for t in _all_threats if _risk_of(t) == "critical")
    _n_walked = sum(1 for t in picks if _risk_of(t) == "critical")
    _capped = _n_critical_total > _n_walked

    indexes = {
        "mitigations": _mitigations_by_threat(yaml_data),
        "assets": _assets_by_threat(yaml_data),
        "attack_surface": _attack_surface_by_path(yaml_data),
    }

    crit_picks = [t for t in picks if _risk_of(t) == "critical"]
    peers_by_cwe = _peers_by_cwe(crit_picks + [t for t in picks if _risk_of(t) == "high"])

    out: list[str] = []
    out.append("## 3. Attack Walkthroughs")
    out.append("")

    # No walkthrough picks (zero Criticals, since Highs are not walked through
    # — MAX_HIGH_WALKTHROUGHS=0). Render an honest stub instead of the generic
    # "one walkthrough per Critical" intro, which would promise sub-sections
    # that never follow. The contract's `sequenceDiagram` requirement is gated
    # on `has_authored_walkthroughs`, so this stub passes validation.
    if not picks:
        out.append(
            "_No Critical findings were identified in this assessment, so there "
            "are no per-Critical attack walkthroughs. See the "
            "[§8 Findings Register](#8-findings-register) for finding-level "
            "detail on every finding._"
        )
        out.append("")
        out.append("<!-- generated:walkthrough_renderer -->")
        return "\n".join(out).rstrip() + "\n"

    if _capped:
        intro = (
            f"This section walks through how the highest-risk findings are "
            f"exploited. To keep the section focused, it covers the "
            f"**{_n_walked} highest-priority of {_n_critical_total} Critical "
            f"findings** (chain entry points and the findings closest to a "
            f"breach); every remaining Critical still has a full "
            f"[§8 Findings Register](#8-findings-register) row with the same "
            f"evidence, impact, and fix. Each walkthrough has attack steps, a "
            f"focused sequence diagram, and the primary mitigation."
        )
    else:
        intro = (
            "This section walks through how the highest-risk findings are "
            "exploited — one short walkthrough per Critical, each with attack "
            "steps, a focused sequence diagram, and the primary mitigation."
        )
    out.append(
        intro + " The cross-finding view (which weaknesses combine toward the "
        "worst-case goal, and where one fix severs several paths) is in the "
        "[Critical Attack Tree](#critical-attack-tree). Full per-finding "
        "context — severity rationale, assets, detection signals — is in the "
        "[§8 Findings Register](#8-findings-register) row for each finding."
    )
    out.append("")

    # §3.1+ per-finding walkthroughs (the cross-finding chain overview was
    # retired — the Critical Attack Tree above §1 is the single strategic view).
    for i, threat in enumerate(picks, start=1):
        block = _render_walkthrough_block(
            threat,
            yaml_data,
            indexes,
            templates,
            {},  # chain_membership retired with §3.1
            peers_by_cwe,
            walkthrough_index=i,
        )
        out.append(block)
        out.append("")

    out.append("<!-- generated:walkthrough_renderer -->")
    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Convenience adapter for the pregenerate_fragments.py GENERATORS dict.
# ---------------------------------------------------------------------------


def gen_attack_walkthroughs(yaml_data: dict) -> str:
    """Adapter matching the `(yaml_data) -> str` generator signature."""

    return render_attack_walkthroughs_md(yaml_data)


__all__ = [
    "render_attack_walkthroughs_md",
    "gen_attack_walkthroughs",
    "select_walkthrough_picks",
    "load_templates",
    "render_attacker_profile",
    "render_prerequisites",
    "render_attack_steps",
    "render_sequence_diagram",
    "render_business_impact",
    "render_detection_signals",
    "render_defense_in_depth",
    "render_cross_references",
]
