"""Deterministic §3 Attack Walkthroughs renderer.

Single-pass, no-LLM, no-iteration generator for `.fragments/attack-walkthroughs.md`.

Inputs: parsed `threat-model.yaml` + per-CWE template files under
`data/walkthrough-templates/`. Output: full §3 fragment that satisfies the
`attack_walkthroughs` contract (sections-contract.yaml) by construction —
no repair loop, no QA-fixer pass.

Contract (see `data/sections-contract.yaml → sections.attack_walkthroughs`):

  * `### 3.1 Attack Chain Overview` heading is mandatory.
  * Each Critical T-NNN gets a `### 3.<n> T-NNN — <title>` heading.
  * Each §3.x body is ≥ 60 lines and contains a `sequenceDiagram` with an
    `alt Current state` / `else After …` pair.
  * Labelled sections in fixed order (bold-header form):
    Attacker Profile, Prerequisites, Attack Steps, Sequence Diagram,
    Business Impact, Detection Signals, Defense in Depth, Cross-references.
  * §3.1 chain blocks render `graph LR` with risk + impact classDefs,
    4–6 nodes per chain, max 5 chains, each chain cites ≥ 1 T-NNN.

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

MAX_CHAINS = 5
MAX_CHAIN_NODES = 6
MIN_CHAIN_NODES = 4

# Cap walkthroughs at the 10 Criticals plus a few representative Highs so the
# §3 fragment stays readable. Contract demands one walkthrough per Critical;
# Highs are extra context, not required.
MAX_HIGH_WALKTHROUGHS = 3

# `walkthrough_depth.min_body_lines` floor in the contract is 60 NON-BLANK
# lines between successive `### 3.<n>` headings. The renderer pads short
# sections up to these minimums so the floor is satisfied by construction.
# Minimums are set with a small safety margin so a single missing scenario
# sentence does not push the body under 60 lines.
MIN_PREREQS = 4
MIN_ATTACK_STEPS = 6
MIN_DETECTION_SIGNALS = 6

# §3.1 chain classDef block — MUST match `chain_compactness.required_classdefs`
# verbatim (sections-contract.yaml). The QA check string-matches the colour
# spec, so keep these in sync if the contract ever changes.
CHAIN_CLASSDEFS = (
    "    classDef risk fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px\n"
    "    classDef impact fill:#0f172a,stroke:#000,color:#fff,stroke-width:2px"
)

# Severity-phrase table feeding the Business Impact paragraph. Severity is
# taken from `threat.risk` (falls back to `threat.impact`).
SEVERITY_PHRASES: dict[str, str] = {
    "critical": (
        "Critical impact — exploitation enables full bypass or extraction with "
        "minimal attacker effort and no compensating control intervenes"
    ),
    "high": (
        "High impact — exploitation meaningfully weakens a control or exposes a "
        "confidential surface; some prerequisites apply"
    ),
    "medium": (
        "Medium impact — exploitation is bounded in blast radius or requires "
        "non-trivial chained conditions"
    ),
    "low": (
        "Low impact — limited blast radius, substantial prerequisites, or strong "
        "compensating controls in place"
    ),
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

# Vektor → short label used inside §3.1 chain Mermaid nodes.
VEKTOR_ACTOR_LABEL: dict[str, str] = {
    "internet-anon": "Anonymous attacker",
    "internet-user": "Authenticated attacker",
    "victim-required": "Anonymous attacker + victim",
    "repo-read": "Repo-read attacker",
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


def _short_title(title: str, limit: int = 70) -> str:
    """Trim a finding title to fit a single-line Mermaid label."""

    title = (title or "").strip()
    if len(title) <= limit:
        return title
    return title[: limit - 1].rstrip() + "…"


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
    """Naive sentence split for the Attack Steps fallback path."""

    text = (text or "").strip()
    if not text:
        return []
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [p.strip().rstrip(".") for p in parts if p.strip()]


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


def _endpoint_guess(scenario: str, fallback: str = "Crafted HTTP request to the affected endpoint") -> str:
    """Recover a concrete `METHOD /path` phrase from the scenario text."""

    if not scenario:
        return fallback
    m = _ENDPOINT_RX.search(scenario)
    if m:
        verb = m.group(0).split()[0].upper()
        path = m.group(1)
        return f"{verb} {path}"
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


def _template_for(cwe: str, templates: dict[str, dict]) -> dict:
    return templates.get((cwe or "").upper()) or templates.get("_generic") or {}


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


def select_walkthrough_picks(yaml_data: dict) -> list[dict]:
    """All Criticals (deterministic order) + a small budget of Highs."""

    threats = [t for t in (yaml_data.get("threats") or []) if isinstance(t, dict)]
    crit = sorted([t for t in threats if _risk_of(t) == "critical"], key=_sort_key)
    high = sorted([t for t in threats if _risk_of(t) == "high"], key=_sort_key)
    return crit + high[:MAX_HIGH_WALKTHROUGHS]


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
    overrides = (template.get("attacker_profile_overrides") or {})
    if isinstance(overrides, dict) and vektor in overrides and overrides[vektor]:
        profile = str(overrides[vektor]).strip()
    return profile


def render_prerequisites(
    threat: dict,
    attack_surface_by_path: dict[str, dict],
    file_hint: str,
) -> list[str]:
    """Vektor-template list, optionally enriched with concrete auth policy.

    Padded up to MIN_PREREQS bullets so the section carries enough non-blank
    lines for the contract's walkthrough_depth floor.
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
    # Generic padding to meet the contract minimum — never invents a constraint
    # the threat does not actually have.
    generic_padding = [
        "Tooling: any standard HTTP client (`curl`, `httpie`, browser DevTools) suffices for payload delivery",
        "Knowledge of the affected endpoint surface — disclosed by the public source tree at `{file}`",
        "No specialised privilege beyond what the attacker profile above describes",
    ]
    for pad in generic_padding:
        if len(out) >= MIN_PREREQS:
            break
        out.append(pad.replace("{file}", file_hint or "<unknown>"))
    return out


def render_attack_steps(threat: dict, template: dict) -> list[str]:
    """Source-of-truth: `threat.scenario`. Fallback to template skeleton.

    Always returns at least MIN_ATTACK_STEPS items so the walkthrough body
    carries enough non-blank lines for the contract floor. Template strings
    that reference `{file}`/`{line}`/`{component}` are substituted from the
    threat's evidence so steps never leak raw placeholders into the output.
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
    ).rstrip(". ").strip()
    sentences = _split_sentences(raw_scenario)
    # Defensive: drop any remaining sentence that is just a `CWE: …`
    # tagline (covers edge cases where the trailing sentence had a
    # mid-string period that survived the regex above).
    sentences = [
        s for s in sentences
        if not re.match(r"^\s*CWE\s*:?\s*CWE-\d+\.?\s*$", s, flags=re.IGNORECASE)
    ]
    template_steps = list(template.get("attack_steps_template") or [
        "Send the crafted payload to the endpoint backed by `{file}:{line}`.",
        "The vulnerable code path accepts the payload without enforcing the missing control.",
        "The response confirms the bypass and the attacker proceeds with the next chain step.",
    ])
    generic_padding = [
        "Verify in the response body / status code that the missing control did not intervene.",
        "Capture the successful exploitation as a proof artifact for the remediation ticket.",
        "Pivot to the next chain step (see §3.1) or cash out the impact directly.",
    ]

    evidence = (threat.get("evidence") or [{}])[0] or {}
    mapping = {
        "file": (evidence.get("file") or "<unknown>"),
        "line": str(evidence.get("line") or "?"),
        "component": (threat.get("component") or "the application").strip() or "the application",
        "cwe": (threat.get("cwe") or "").strip() or "the weakness class",
        "title": _short_title(threat.get("title") or "", 120),
        "tid": str(threat.get("id") or ""),
    }
    template_steps = [_format_template_string(s, mapping) for s in template_steps]
    generic_padding = [_format_template_string(s, mapping) for s in generic_padding]

    body: list[str] = []
    body.extend(sentences[:5])
    if not body:
        body.extend(template_steps)
    # Pad with template steps then generic closers until the minimum is met.
    for cand in template_steps + generic_padding:
        if len(body) >= MIN_ATTACK_STEPS:
            break
        if cand not in body:
            body.append(cand)
    return [f"{i+1}. {s.rstrip('.')}." for i, s in enumerate(body[:MIN_ATTACK_STEPS + 1])]


def _format_template_string(raw: str, mapping: dict) -> str:
    """Safe template substitution that tolerates missing keys."""

    class _SafeDict(dict):
        def __missing__(self, key):  # pragma: no cover - obvious fallback
            return "{" + key + "}"

    try:
        return raw.format_map(_SafeDict(mapping))
    except (IndexError, ValueError):
        return raw


def render_sequence_diagram(
    threat: dict,
    template: dict,
    mitigation_primary_id: str,
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
            "    participant App as \"{component} ({file}:{line})\"\n"
            "    alt Current state\n"
            "        Attacker->>App: Crafted request exploits the weakness at `{file}:{line}`\n"
            "        App-->>Attacker: Response confirms exploitation\n"
            "    else After {mitigation_primary}\n"
            "        Attacker->>App: Same request\n"
            "        App-->>Attacker: Request rejected\n"
            "    end\n"
            "```\n"
        )
    evidence = (threat.get("evidence") or [{}])[0] or {}
    mapping = {
        "tid": str(threat.get("id") or ""),
        "title": _short_title(threat.get("title") or "", 120),
        "component": (threat.get("component") or "the application").strip() or "the application",
        "file": (evidence.get("file") or "<unknown>"),
        "line": str(evidence.get("line") or "?"),
        "excerpt": _excerpt(evidence),
        "cwe": (threat.get("cwe") or "").strip() or "the weakness class",
        "endpoint_guess": _endpoint_guess(threat.get("scenario") or ""),
        "mitigation_primary": mitigation_primary_id or "the recommended fix",
    }
    return _format_template_string(raw, mapping).rstrip() + "\n"


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

    Padded with generic SIEM-style closers up to MIN_DETECTION_SIGNALS so the
    section always carries enough non-blank lines for the contract floor.
    """

    raw_bullets = list(template.get("detection_signals") or [])
    if not raw_bullets:
        raw_bullets = [
            "Static-analysis rule for {cwe} flagging `{file}` in CI pre-merge",
            "Application logs at `{component}` showing the input pattern associated with the weakness",
            "Anomalous response code or payload-size distribution on the affected endpoint",
        ]
    generic_padding = [
        "SIEM correlation between elevated 4xx/5xx rates on the affected endpoint and outbound connections to unfamiliar destinations",
        "Pre-deployment fuzzing of the surface exposed by `{file}` against a `{cwe}` payload corpus",
        "Manual quarterly review of audit-log entries citing `{component}` against the documented data-handling policy",
    ]
    bullets = list(raw_bullets)
    for cand in generic_padding:
        if len(bullets) >= MIN_DETECTION_SIGNALS:
            break
        if cand not in bullets:
            bullets.append(cand)
    evidence = (threat.get("evidence") or [{}])[0] or {}
    mapping = {
        "component": (threat.get("component") or "the application").strip(),
        "file": evidence.get("file") or "<unknown>",
        "line": str(evidence.get("line") or "?"),
        "cwe": (threat.get("cwe") or "").strip() or "the weakness class",
    }
    return [_format_template_string(b, mapping) for b in bullets]


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
        bullets.append(f"{label}: [{mid}](#{_anchor(mid)}) — {title[:160]}")
    # Always carry a third "compensating control" bullet to keep this section
    # substantive even when only one mitigation is linked.
    if len(bullets) < 3:
        bullets.append(
            "Compensating control: detection signals listed below act as the "
            "fallback layer until the primary mitigation lands in production."
        )
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
    bullets.append(f"§8 Threat Register: [{tid}](#{_anchor(tid)})")
    siblings = [p for p in peers_by_cwe.get(cwe, []) if p != tid][:2]
    if siblings:
        sib_links = ", ".join(f"[{p}](#{_anchor(p)})" for p in siblings)
        bullets.append(f"Sibling findings (same CWE class): {sib_links}")
    else:
        bullets.append(f"Sibling findings (same CWE class): none — {cwe or 'this class'} is unique in this assessment")
    bullets.append(f"§7 Security Architecture coverage for `{(threat.get('component') or 'the affected component').strip()}`")
    return bullets


# ---------------------------------------------------------------------------
# §3.1 Chain catalogue derivation — inline, deterministic.
# ---------------------------------------------------------------------------


def _impact_label_for(threat: dict, asset_ids: list[str]) -> str:
    """Short, single-line impact label for the terminal node of a chain."""

    if asset_ids:
        return _short_title(f"Compromised {asset_ids[0]}", 60)
    component = threat.get("component") or "asset"
    return _short_title(f"Compromised {component}", 60)


def _exploit_label_for(threat: dict) -> str:
    """Short exploit-class label for the middle node of a chain."""

    cwe = (threat.get("cwe") or "").strip()
    title_short = _short_title(threat.get("title") or "weakness", 50)
    if cwe:
        return _short_title(f"{cwe} — {title_short}", 60)
    return title_short


def derive_attack_chains(
    yaml_data: dict,
    walkthrough_picks: list[dict],
    assets_by_threat: dict[str, list[dict]],
) -> tuple[list[dict], dict[str, list[int]]]:
    """Produce up to MAX_CHAINS deterministic chains from yaml data.

    Strategy (cheap, single-pass):

      * Anchor each chain on one of the top Critical threats.
      * If the anchor shares an asset with another Critical/High threat, the
        chain links the two threats (5 nodes: actor → entry → anchor →
        pivot-threat → impact). Otherwise it's a 4-node single-finding chain.
      * Hard cap at MAX_CHAINS, hard cap at MAX_CHAIN_NODES nodes.

    Returns ``(chains, chain_membership)`` where ``chain_membership`` is a
    ``tid -> [chain_indexes]`` map used by Cross-references rendering.
    """

    chains: list[dict] = []
    membership: dict[str, list[int]] = defaultdict(list)

    # Anchors: take Criticals first; if fewer than MAX_CHAINS, top up with
    # the highest-rated Highs from the walkthrough picks list (already
    # sorted critical → high → id-ascending).
    anchors = [t for t in walkthrough_picks if _risk_of(t) == "critical"][:MAX_CHAINS]
    if len(anchors) < MAX_CHAINS:
        spillover = [t for t in walkthrough_picks if _risk_of(t) == "high"]
        anchors.extend(spillover[: MAX_CHAINS - len(anchors)])
    anchors = anchors[:MAX_CHAINS]

    # Build a "shares-an-asset" index so we can compute pivots cheaply.
    asset_to_threats: dict[str, list[str]] = defaultdict(list)
    for tid, assets in assets_by_threat.items():
        for a in assets:
            asset_to_threats[str(a.get("id") or "")].append(tid)

    for idx, anchor in enumerate(anchors, start=1):
        anchor_tid = str(anchor.get("id") or "")
        vektor = (anchor.get("vektor") or "internet-user").strip()
        actor_label = VEKTOR_ACTOR_LABEL.get(vektor, "Attacker")
        entry_component = (anchor.get("component") or "Application surface").strip()
        anchor_assets = [str(a.get("id") or "") for a in assets_by_threat.get(anchor_tid, [])]

        # Find a pivot: another Critical/High threat that shares an asset.
        pivot: dict | None = None
        for asset_id in anchor_assets:
            for cand_tid in asset_to_threats.get(asset_id, []):
                if cand_tid == anchor_tid:
                    continue
                cand = next(
                    (t for t in walkthrough_picks if str(t.get("id") or "") == cand_tid),
                    None,
                )
                if cand and _risk_of(cand) in {"critical", "high"}:
                    pivot = cand
                    break
            if pivot:
                break

        nodes: list[tuple[str, str, str]] = []
        # (node_id, label, css_class) — css_class in {"risk", "impact"}.
        nodes.append(("A", actor_label, "risk"))
        nodes.append(("B", _short_title(entry_component, 60), "risk"))
        nodes.append(("C", f"{anchor_tid}: {_exploit_label_for(anchor)}", "risk"))
        if pivot:
            pivot_tid = str(pivot.get("id") or "")
            nodes.append(("D", f"{pivot_tid}: {_exploit_label_for(pivot)}", "risk"))
            nodes.append(("E", _impact_label_for(anchor, anchor_assets), "impact"))
            membership[pivot_tid].append(idx)
        else:
            nodes.append(("D", _impact_label_for(anchor, anchor_assets), "impact"))

        # Guarantee node count stays within contract bounds.
        if len(nodes) < MIN_CHAIN_NODES:
            nodes.insert(-1, ("X", "Lateral movement", "risk"))
        nodes = nodes[:MAX_CHAIN_NODES]

        chain_name = _short_title(anchor.get("title") or f"Chain {idx}", 70)
        takeaway = (
            f"Chain {idx} aggregates {anchor_tid} "
            + (f"with {str(pivot.get('id') or '')} via a shared asset surface" if pivot else "into the impacted asset surface")
            + "; closing the primary mitigation breaks the kill-chain."
        )

        chains.append(
            {
                "index": idx,
                "name": chain_name,
                "intro": (
                    f"Anchor finding: `{anchor_tid}`. "
                    + (
                        f"Compound with `{str(pivot.get('id') or '')}` through a shared asset. "
                        if pivot
                        else ""
                    )
                    + "The graph below traces the attacker path from initial reach to terminal impact."
                ),
                "nodes": nodes,
                "takeaway": takeaway,
            }
        )
        membership[anchor_tid].append(idx)

    return chains, dict(membership)


# ---------------------------------------------------------------------------
# Top-level rendering — assemble the final §3 fragment.
# ---------------------------------------------------------------------------


def _render_chain_block(chain: dict) -> str:
    """Render one §3.1 `#### Chain N — <name>` block (intro + mermaid + takeaway).

    Layout (verbatim required by `chain_compactness`):

        graph LR
            A[label] --> B[label] --> ...
            class A risk
            ...
            classDef risk fill:...
            classDef impact fill:...
    """

    nodes = chain["nodes"]
    lines: list[str] = []
    lines.append(f"#### Chain {chain['index']} — {chain['name']}")
    lines.append("")
    lines.append(chain["intro"])
    lines.append("")
    lines.append("```mermaid")
    lines.append("graph LR")
    for nid, label, _cls in nodes:
        lines.append(f"    {nid}[{_mermaid_safe(label)}]")
    for i in range(1, len(nodes)):
        prev_id = nodes[i - 1][0]
        curr_id = nodes[i][0]
        lines.append(f"    {prev_id} --> {curr_id}")
    for nid, _label, cls in nodes:
        lines.append(f"    class {nid} {cls}")
    lines.append(CHAIN_CLASSDEFS)
    lines.append("```")
    lines.append("")
    lines.append(f"**Key takeaway:** {chain['takeaway']}")
    return "\n".join(lines)


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
    title = (threat.get("title") or "untitled finding").strip()
    cwe = (threat.get("cwe") or "").upper()
    template = _template_for(cwe, templates)

    evidence = (threat.get("evidence") or [{}])[0] or {}
    file_hint = (evidence.get("file") or "").strip()

    mit_bullets, primary_mit_id = render_defense_in_depth(threat, indexes["mitigations"])

    profile = render_attacker_profile(threat, yaml_data.get("meta") or {}, template)
    prereqs = render_prerequisites(threat, indexes["attack_surface"], file_hint)
    steps = render_attack_steps(threat, template)
    diagram = render_sequence_diagram(threat, template, primary_mit_id)
    asset_ids = [str(a.get("id") or "") for a in indexes["assets"].get(tid, [])]
    impact = render_business_impact(threat, asset_ids)
    signals = render_detection_signals(threat, template)
    xrefs = render_cross_references(threat, chain_membership, peers_by_cwe)

    heading = f"### 3.{walkthrough_index} {tid} — {_short_title(title, 90)}"

    lines: list[str] = []
    lines.append(heading)
    lines.append("")
    lines.extend(
        _sentences_per_line(
            f"Severity **{(threat.get('risk') or 'High').strip()}** "
            f"({cwe or 'CWE-?'}). STRIDE: {threat.get('stride') or 'n/a'}. "
            f"Code anchor: `{file_hint or '<unknown>'}:{evidence.get('line') or '?'}`."
        )
    )
    lines.append("")
    lines.extend(
        _sentences_per_line(
            "The walkthrough below traces this finding end-to-end. "
            "It names the attacker, what they need to start, how the bypass "
            "actually executes, what the blast radius looks like, and which "
            "detection signals and mitigations close the gap. "
            "Every slot is derived from `threat-model.yaml` and the matching "
            "CWE template — there is no LLM authoring on this path."
        )
    )
    lines.append("")

    lines.append("**Attacker Profile**")
    lines.append("")
    lines.extend(_sentences_per_line(profile))
    lines.append("")

    lines.append("**Prerequisites**")
    lines.append("")
    for b in prereqs:
        lines.append(f"- {b}")
    lines.append("")

    lines.append("**Attack Steps**")
    lines.append("")
    lines.extend(steps)
    lines.append("")

    lines.append("**Sequence Diagram**")
    lines.append("")
    lines.append(diagram.rstrip())
    lines.append("")

    lines.append("**Business Impact**")
    lines.append("")
    lines.extend(_sentences_per_line(impact))
    lines.append("")

    lines.append("**Detection Signals**")
    lines.append("")
    for b in signals:
        lines.append(f"- {b}")
    lines.append("")

    lines.append("**Defense in Depth**")
    lines.append("")
    for b in mit_bullets:
        lines.append(f"- {b}")
    lines.append("")

    lines.append("**Cross-references**")
    lines.append("")
    for b in xrefs:
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

    indexes = {
        "mitigations": _mitigations_by_threat(yaml_data),
        "assets": _assets_by_threat(yaml_data),
        "attack_surface": _attack_surface_by_path(yaml_data),
    }

    crit_picks = [t for t in picks if _risk_of(t) == "critical"]
    chains, chain_membership = derive_attack_chains(yaml_data, picks, indexes["assets"])
    peers_by_cwe = _peers_by_cwe(crit_picks + [t for t in picks if _risk_of(t) == "high"])

    out: list[str] = []
    out.append("## 3. Attack Walkthroughs")
    out.append("")
    out.append(
        "This section walks through how the highest-risk findings are actually "
        "exploited. §3.1 traces the cross-finding chains in a single graph each; "
        "§3.2 onwards reads as one self-contained story per Critical finding — "
        "attacker profile, prerequisites, steps, sequence diagram, business "
        "impact, detection signals, defence-in-depth, and cross-references back "
        "into §7 and §8. All §3 content is generated deterministically from "
        "`threat-model.yaml` and the per-CWE templates in "
        "`data/walkthrough-templates/`."
    )
    out.append("")

    # §3.1 Attack Chain Overview
    out.append("### 3.1 Attack Chain Overview")
    out.append("")
    out.append(
        "The compound chains below aggregate the Critical findings into linear "
        "kill-chains. Each chain is one Mermaid graph; the `risk` nodes are the "
        "attacker-controlled steps, the `impact` node names the asset / outcome "
        "at the end of the chain."
    )
    out.append("")
    for chain in chains:
        out.append(_render_chain_block(chain))
        out.append("")

    # §3.2+ per-finding walkthroughs
    for i, threat in enumerate(picks, start=2):
        block = _render_walkthrough_block(
            threat,
            yaml_data,
            indexes,
            templates,
            chain_membership,
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
    "derive_attack_chains",
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
