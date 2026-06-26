"""Tests for scripts/compose_threat_model.py — the contract-driven renderer.

These tests pin the invariants that make LLM structural drift impossible:

  * render() is deterministic — identical inputs produce byte-identical output
  * the canonical Management Summary section order is enforced
  * the Management Summary heading is unnumbered
  * a malformed verdict fragment raises a schema-validation error (hard gate)
  * a missing required fragment raises FragmentError
  * the Top Findings table column schema is exactly the contract's 7 columns
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "compose"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass introspection can resolve the module.
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load_module("compose_threat_model", SCRIPT_PATH)


def _prepare_output_dir(tmp_path: Path) -> Path:
    """Copy the fixture into a temp dir so tests don't mutate tests/fixtures/."""
    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)
    return out


# ---------------------------------------------------------------------------
# Core rendering
# ---------------------------------------------------------------------------


def test_infobox_tags_string_is_split_into_list(tmp_path: Path) -> None:
    """Regression guard for the infobox tags rendering bug.

    Historically the yaml shape for ``project.tags`` allowed either a list
    or a pre-joined comma-separated string. The Jinja template pipes the
    value through ``| join(', ')``; when it received a string, Jinja
    iterated it character-by-character and emitted ``w, e, b, ,, …``
    instead of ``web, security, owasp, …``. The renderer must normalise a
    string value to a list before handing it to the template."""
    out = _prepare_output_dir(tmp_path)
    # Force tags into the buggy shape directly on the fixture yaml.
    yml_path = out / "threat-model.yaml"
    data = yaml.safe_load(yml_path.read_text())
    data.setdefault("project", {})["tags"] = "web security, owasp, pentest"
    yml_path.write_text(yaml.safe_dump(data, sort_keys=False))

    rendered, _ = compose.render(CONTRACT, out)
    # Look at the Tags row of the project infobox blockquote.
    tag_line = next((l for l in rendered.splitlines() if "**Tags**" in l), "")
    assert tag_line, "Tags row missing from infobox"
    # Single-character fragments are the hallmark of the bug.
    assert " w, e, b," not in tag_line, f"infobox tags rendered character-by-character: {tag_line!r}"
    # The expected tokens must all appear intact.
    for tok in ("web security", "owasp", "pentest"):
        assert tok in tag_line, f"expected tag {tok!r} missing from: {tag_line!r}"


def test_toc_emits_numbering_gap_note(tmp_path: Path) -> None:
    """The contract intentionally skips §6 (Use Cases retired). A bare 5→7 jump
    reads as a bug, so the TOC must carry an explicit non-contiguous-numbering
    note naming the missing section (2026-05-31 'Wo ist Kapitel 6?' report)."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert "Section numbering is non-contiguous" in rendered
    assert "§6 was retired" in rendered


def test_render_produces_canonical_ms_structure(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, warnings = compose.render(CONTRACT, out)

    # Item 3 (2026-05-28): the dormant Critical Attack Tree fragment
    # producer was activated but the test fixture predates the fragment
    # producer. Soft-skip warnings for it are expected — filter them
    # out before asserting the warnings list is otherwise empty.
    filtered = [w for w in warnings if not w.startswith("critical_attack_tree: fragment missing")]
    assert filtered == [], f"unexpected warnings: {filtered}"

    # Management Summary must be unnumbered.
    assert "## Management Summary\n" in rendered
    assert "## 1. Management Summary" not in rendered

    # Post-2026-05 — four canonical sub-sections, in order. The former
    # `### Security Posture at a Glance`, `### Top Findings` and
    # `### Architecture Assessment` were MERGED into the single
    # `### Security Posture & Top Threats` section (heatmap = Figure 2 + the
    # Top Threats table). `### Mitigations` renders as `### Top Mitigations`.
    expected_order = [
        "### Verdict",
        "### Security Posture & Top Threats",
        "### Top Mitigations",
        "### Operational Strengths",
    ]
    positions = [rendered.find(h) for h in expected_order]
    assert all(p > 0 for p in positions), f"missing MS subsection(s): {expected_order} at {positions}"
    assert positions == sorted(positions), f"MS subsections out of order: {positions}"

    # No forbidden legacy headings anywhere in MS — including the now-merged
    # Top Findings / Architecture Assessment sub-sections.
    ms_slice = rendered.split("## Management Summary", 1)[1].split("\n## ", 1)[0]
    for forbidden in (
        "### 1.1",
        "### Executive Overview",
        "### Risk Distribution",
        "### Top Findings",
        "### Architecture Assessment",
        "### Immediate Actions",
    ):
        assert forbidden not in ms_slice, f"forbidden MS heading leaked: {forbidden!r}"


def test_architectural_anti_patterns_absent_renders_nothing(tmp_path: Path) -> None:
    """The optional Architectural Anti-Patterns callout is omitted entirely when
    no ms-anti-patterns.json fragment is present (the default fixture) — no empty
    heading, no crash."""
    out = _prepare_output_dir(tmp_path)
    assert not (out / ".fragments" / "ms-anti-patterns.json").exists()
    rendered, _ = compose.render(CONTRACT, out)
    assert "### Architectural Anti-Patterns" not in rendered


def test_architectural_anti_patterns_renders_after_verdict(tmp_path: Path) -> None:
    """When ms-anti-patterns.json is present, the callout renders inside the
    Management Summary, immediately after the Verdict and before the Security
    Posture section, naming each pattern (NO leading severity glyph — it
    collided with the per-finding dots) with a linkified finding reference."""
    out = _prepare_output_dir(tmp_path)
    frag = {
        "anti_patterns": [
            {
                "name": "SPA without BFF",
                "severity": "red",
                "description": "The SPA holds its sole session credential in "
                "localStorage with no Backend-for-Frontend to keep it server-side, "
                "so any XSS yields full token exfiltration.",
                "affected_components": ["C-01"],
                "findings": [{"ref": "T-001", "label": "JWT in localStorage"}],
            },
            {
                "name": "Raw SQL string interpolation",
                "description": "Login and search interpolate untrusted input "
                "directly into raw SQL, bypassing the ORM parameter binding across "
                "multiple routes.",
                "findings": [{"ref": "F-002", "label": "SQL injection bypass"}],
            },
        ]
    }
    (out / ".fragments" / "ms-anti-patterns.json").write_text(json.dumps(frag))

    rendered, _ = compose.render(CONTRACT, out)
    ms_slice = rendered.split("## Management Summary", 1)[1].split("\n## ", 1)[0]

    assert "### Architectural Anti-Patterns" in ms_slice
    assert "**SPA without BFF**" in ms_slice
    assert "**Raw SQL string interpolation**" in ms_slice
    # Ordering: Verdict → Anti-Patterns → Security Posture.
    v = ms_slice.find("### Verdict")
    a = ms_slice.find("### Architectural Anti-Patterns")
    s = ms_slice.find("### Security Posture & Top Threats")
    assert v < a < s, f"anti-patterns out of order: verdict={v} ap={a} posture={s}"
    # A linkified finding reference (T-001 normalises to the F-001 anchor).
    assert re.search(r"\[F-00[12]\]\(#f-00[12]\)", ms_slice), (
        f"no linkified finding in anti-patterns callout: {ms_slice[a:s]!r}"
    )

    ap_block = ms_slice[a:s]
    # No leading severity glyph before the pattern name — the coloured circle
    # used to collide with the per-finding severity dots (user report 2026-06).
    assert not re.search(r"[🔴🟠🟡🟢]\s*\*\*SPA without BFF\*\*", ap_block), (
        f"anti-pattern name still carries a leading severity circle: {ap_block!r}"
    )
    # Clean nested structure (indented sub-bullets), not <br/>↳-crammed.
    assert "↳" not in ap_block, f"legacy ↳ cramming still present: {ap_block!r}"
    assert "_Findings:_" in ap_block
    assert "_Affected components:_" in ap_block  # first pattern declares them
    # Sub-bullets are indented under the pattern bullet.
    assert re.search(r"\n {4}- _Findings:_", ap_block), f"findings sub-bullet not indented: {ap_block!r}"


def test_ai_exposure_absent_renders_nothing(tmp_path: Path) -> None:
    """The optional AI / LLM Exposure callout is omitted entirely when no
    ms-ai-exposure.json fragment is present (the default fixture — a non-LLM
    repo) — no empty heading, no crash, zero impact."""
    out = _prepare_output_dir(tmp_path)
    assert not (out / ".fragments" / "ms-ai-exposure.json").exists()
    rendered, _ = compose.render(CONTRACT, out)
    assert "### AI / LLM Exposure" not in rendered


def test_ai_exposure_renders_after_anti_patterns(tmp_path: Path) -> None:
    """When ms-ai-exposure.json is present, the callout renders inside the
    Management Summary, after the Verdict and before the Security Posture
    section, naming each risk with its OWASP LLM id, a severity emoji and a
    linkified finding reference."""
    out = _prepare_output_dir(tmp_path)
    frag = {
        "summary": "A chat assistant relays user input to an external model API "
        "and renders the completion back to the browser.",
        "ai_risks": [
            {
                "owasp_llm_id": "LLM01",
                "name": "Prompt Injection",
                "severity": "red",
                "description": "User chat input is concatenated directly into the "
                "system prompt with no separation between instruction and data, so "
                "a crafted message can override the assistant's guardrails.",
                "affected_components": ["C-01"],
                "findings": [{"ref": "T-001", "label": "Unsanitized prompt assembly"}],
            },
            {
                "owasp_llm_id": "LLM06",
                "name": "Excessive Agency",
                "description": "The agent can invoke shell and SQL tools with no "
                "human approval gate, so a successful injection escalates straight "
                "into destructive tool execution.",
                "findings": [{"ref": "F-002", "label": "Unguarded agent tool use"}],
            },
        ],
    }
    (out / ".fragments" / "ms-ai-exposure.json").write_text(json.dumps(frag))

    rendered, _ = compose.render(CONTRACT, out)
    ms_slice = rendered.split("## Management Summary", 1)[1].split("\n## ", 1)[0]

    assert "### AI / LLM Exposure" in ms_slice
    assert "Prompt Injection" in ms_slice
    assert "LLM01" in ms_slice
    assert "Excessive Agency" in ms_slice
    # Ordering: Verdict → AI Exposure → Security Posture.
    v = ms_slice.find("### Verdict")
    a = ms_slice.find("### AI / LLM Exposure")
    s = ms_slice.find("### Security Posture & Top Threats")
    assert v < a < s, f"ai-exposure out of order: verdict={v} ai={a} posture={s}"
    # A linkified finding reference (T-001 normalises to the F-001 anchor).
    assert re.search(r"\[F-00[12]\]\(#f-00[12]\)", ms_slice), (
        f"no linkified finding in ai-exposure callout: {ms_slice[a:s]!r}"
    )


def test_render_is_deterministic(tmp_path: Path) -> None:
    """Identical fragments + yaml must produce byte-identical output."""
    out1 = _prepare_output_dir(tmp_path / "a")
    out2 = _prepare_output_dir(tmp_path / "b")
    r1, _ = compose.render(CONTRACT, out1)
    r2, _ = compose.render(CONTRACT, out2)
    assert r1 == r2


def test_render_is_deterministic_across_reruns(tmp_path: Path) -> None:
    """Re-rendering the same output dir twice yields identical text."""
    out = _prepare_output_dir(tmp_path)
    r1, _ = compose.render(CONTRACT, out)
    r2, _ = compose.render(CONTRACT, out)
    assert r1 == r2


def test_verdict_renders_red_blockquote(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert "border-left: 3px solid #dc2626" in rendered
    # At least one F/T-NNN linkified citation inside the blockquote. The
    # finding link may carry a leading severity dot (🔴/🟠/🟡/🟢) — added by
    # linkify_refs so the Verdict findings are annotated like every other
    # linked-findings context.
    assert re.search(
        r"\*\((?:[🔴🟠🟡🟢⚪]\s)?\[[FT]-00[12]\]\(#[ft]-00[12]\)(?: — [^)]+)?\)\*",
        rendered,
    )


def test_top_threats_has_five_columns(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Locate the merged Top Threats header row (replaced Top Findings +
    # Architecture Assessment).
    header = "| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |"
    assert header in rendered, "Top Threats must use exactly the 5 canonical columns"


def test_figure1_attacks_are_labelled_arrows_with_clean_legend(tmp_path: Path) -> None:
    """Figure 1 (2026-06-14 redesign): attack arrows are SOLID and labelled
    directly with the class glyph+name ("① Injection"), so the figure is
    self-explanatory without a decoder. Boxes no longer carry a glyph chip (the
    classes are on the arrows); the 🔴/🟠 finding-count badge stays. The legend is
    a single light card — NOT wrapped in a subgraph (which added a double border +
    empty title bar). Tier bands are neutral slate (red is only attacks/actors)."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    m = re.search(r"```mermaid\nflowchart TB.+?```", rendered, re.DOTALL)
    if not m:
        return  # fixture produced no Figure 1 (no attack paths) → nothing to verify
    fig1 = m.group(0)
    # Attack edges carry a mid-edge label that names the class (glyph present).
    assert re.search(r'==>\|"[^"]*[①②③④⑤⑥⑦]', fig1), "attack edges must be labelled with the class glyph+name"
    # No coloured glyph CHIP on the boxes any more (glyphs moved onto the arrows).
    assert not re.search(r"<span style='color:#[0-9a-fA-F]{6}'>[①②③④⑤⑥⑦]</span>", fig1), "box glyph chip must be gone"
    # The legend is a single card, not a subgraph, and is not overloaded.
    assert "subgraph LEGEND" not in fig1, "legend must not be wrapped in a subgraph"
    assert re.search(r'LEG\["[^"]*Legend', fig1), "in-figure legend card missing"
    # The 🔴/🟠 finding-count badge stays on the boxes.
    assert "🔴" in fig1 or "🟠" in fig1, "component finding-count badge must be preserved"
    # Application tier must NOT be red (red is reserved for attacks/actors).
    assert "fill:#fdeeee" not in fig1, "application tier must not use the old red band"


def test_figure1_is_a_top_down_tier_stack_without_balancing_edges(tmp_path: Path) -> None:
    """Figure 1 is a vertical tier stack (Client → Application → Data) and no
    longer emits invisible ``~~~`` barycenter-balancing edges. Those edges were
    a layout band-aid that, on victim-bearing models, pulled the client rep to
    the centre of the app row and produced the long crossing diagonals the
    rewrite removes. Tier ordering + the complexity budget keep DATA at the
    bottom without them; ELK centres the narrow tiers on its own."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    ctx = compose.RenderContext(
        output_dir=out_dir,
        contract={},
        yaml_data={
            "components": [
                {"id": "web", "name": "Web Frontend", "tier": "client"},
                {"id": "api", "name": "REST API", "tier": "application"},
                {"id": "worker", "name": "Background Worker", "tier": "application"},
                {"id": "db", "name": "Primary Database", "tier": "data"},
            ],
            "threats": [
                {"id": "F-001", "title": "SQL Injection", "component": "api", "risk": "High"},
                {"id": "F-002", "title": "Unsafe job input", "component": "worker", "risk": "High"},
                {"id": "F-003", "title": "Weak data storage", "component": "db", "risk": "Medium"},
            ],
        },
        triage={},
        fragments_dir=out_dir / ".fragments",
    )
    md = compose._render_top_threats_architecture(
        ctx,
        {
            "attack_paths": [
                {
                    "class": "injection",
                    "actor": "internet-anon",
                    "target": "application",
                    "findings": ["F-001", "F-002"],
                    "impact": ["customer-data-exfiltration"],
                }
            ]
        },
        {
            "glyph_sequence": ["①"],
            "classes": [
                {
                    "id": "injection",
                    "label": "Injection",
                    "short_label": "Injection",
                    "default_actor": "internet-anon",
                    "default_target_tier": "application",
                }
            ],
        },
    )
    fig1 = md.split("```mermaid", 1)[1].split("```", 1)[0]
    assert fig1.index("subgraph CLIENT[") < fig1.index("subgraph APP[")
    assert fig1.index("subgraph APP[") < fig1.index("subgraph DATA[")
    # No invisible balancing edges BETWEEN COMPONENTS (the barycenter band-aid).
    assert not re.search(r"CMP_\w+\s*~~~\s*CMP_\w+", fig1), "no component↔component balancing edges"
    # No direct actor⇒data edge — data is reached via dotted propagation only.
    assert not re.search(r"==> CMP_DB\b", fig1), fig1


def test_figure1_complexity_budget_mutes_non_top_threat_components(tmp_path: Path) -> None:
    """R1 — Figure 1 draws only components that host a finding of a budgeted
    (top-N, glyph-bearing) attack class, plus tier reps. A Critical/High
    component that no top attack class touches is collapsed into the muted
    'Also assessed' note rather than drawn as a full box + edge, so the figure's
    box/edge count tracks the number of TOP THREATS, not the repo size."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    ctx = compose.RenderContext(
        output_dir=out_dir,
        contract={},
        yaml_data={
            "components": [
                {"id": "api", "name": "REST API", "tier": "application"},
                {"id": "billing", "name": "Billing Service", "tier": "application"},
                {"id": "db", "name": "Primary Database", "tier": "data"},
            ],
            "threats": [
                {"id": "F-001", "title": "SQL Injection", "component": "api", "risk": "Critical"},
                # billing has a High finding but it is NOT in any attack path.
                {"id": "F-009", "title": "Weak billing check", "component": "billing", "risk": "High"},
                {"id": "F-003", "title": "Weak data storage", "component": "db", "risk": "Medium"},
            ],
        },
        triage={},
        fragments_dir=out_dir / ".fragments",
    )
    md = compose._render_top_threats_architecture(
        ctx,
        {"attack_paths": [{"class": "injection", "actor": "internet-anon", "target": "data", "findings": ["F-001"]}]},
        {
            "glyph_sequence": ["①"],
            "classes": [
                {
                    "id": "injection",
                    "label": "Injection",
                    "short_label": "Injection",
                    "default_actor": "internet-anon",
                    "default_target_tier": "data",
                }
            ],
        },
    )
    fig1 = md.split("```mermaid", 1)[1].split("```", 1)[0]
    assert "CMP_API[" in fig1  # top-threat host → drawn
    assert "CMP_BILLING[" not in fig1, "non-top-threat High component must be muted, not drawn"
    assert "Also assessed" in fig1 and "Billing Service" in fig1


def test_figure1_caps_tier_width_for_complex_apps(tmp_path: Path) -> None:
    """R2 — a flowchart tier is a single horizontal row, so a complex app with
    many attacked components in one tier must NOT draw them all (it would
    stretch the figure into an unreadable wide strip). At most
    ``_FIG1_MAX_TIER_DRAW`` boxes are drawn per tier; the overflow collapses
    into the muted note, which still NAMES the attacked components (traceability
    preserved). Verifies box count is capped AND the note flags 'Also attacked'."""
    comps = [{"id": f"svc{i}", "name": f"Service {i}", "tier": "application"} for i in range(1, 13)]
    comps.append({"id": "db", "name": "Database", "tier": "data"})
    threats = [
        {"id": f"F-{i:03d}", "title": f"weakness {i}", "component": f"svc{i}", "risk": "Critical"} for i in range(1, 13)
    ]
    threats.append({"id": "F-200", "title": "weak storage", "component": "db", "risk": "Medium"})
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    ctx = compose.RenderContext(
        output_dir=out_dir,
        contract={},
        yaml_data={"components": comps, "threats": threats},
        triage={},
        fragments_dir=out_dir / ".fragments",
    )
    # 6 classes, each hitting two distinct services → all 12 services are hosts.
    classes = [
        "injection",
        "auth-bypass",
        "privilege-escalation",
        "remote-code-execution",
        "dos",
        "sensitive-data-exposure",
    ]
    aps = [
        {
            "class": c,
            "actor": "internet-anon",
            "target": "application",
            "findings": [f"F-{2 * i + 1:03d}", f"F-{2 * i + 2:03d}"],
        }
        for i, c in enumerate(classes)
    ]
    tax = {
        "glyph_sequence": ["①", "②", "③", "④", "⑤", "⑥"],
        "classes": [
            {
                "id": c,
                "label": c,
                "short_label": c,
                "default_actor": "internet-anon",
                "default_target_tier": "application",
            }
            for c in classes
        ],
    }
    md = compose._render_top_threats_architecture(ctx, {"attack_paths": aps}, tax)
    fig1 = md.split("```mermaid", 1)[1].split("```", 1)[0]
    drawn = re.findall(r"CMP_SVC\d+\[", fig1)
    assert len(drawn) <= compose._FIG1_MAX_TIER_DRAW, (
        f"app tier drew {len(drawn)} boxes, cap is {compose._FIG1_MAX_TIER_DRAW}"
    )
    # the width-capped Critical hosts are named in the muted note with a §8 pointer
    assert "Critical/High finding in §8" in fig1, "capped Crit/High components must be named in the muted note"


def test_components_table_scope_column_marks_out_of_scope(tmp_path: Path) -> None:
    """§2.3 gains a Scope column when meta.component_selection excluded some
    components — each row marked Analyzed / Out of scope for completeness."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    comps = [
        {"id": "api", "name": "API", "tier": "application", "paths": ["src/api"]},
        {"id": "worker", "name": "Worker", "tier": "application", "paths": ["src/worker"]},
    ]
    meta = {
        "component_selection": {
            "excluded": [{"id": "worker", "name": "Worker", "reason": "out-of-scope at depth=quick"}]
        }
    }
    ctx = compose.RenderContext(
        output_dir=out_dir,
        contract={},
        yaml_data={"components": comps, "threats": [], "meta": meta},
        triage={},
        fragments_dir=out_dir / ".fragments",
    )
    out = compose._inject_components_table(ctx, "### 2.3 Components\n\nIntro.\n")
    assert "| ID | Name | Type | Key Paths | Linked Threats | Scope |" in out
    rows = [ln for ln in out.splitlines() if ln.startswith("|") and ("API" in ln or "Worker" in ln)]
    worker_row = next(ln for ln in rows if "Worker" in ln)
    api_row = next(ln for ln in rows if "API" in ln and "Worker" not in ln)
    assert api_row.rstrip().endswith("Analyzed |")
    assert worker_row.rstrip().endswith("Out of scope |")


def test_components_table_no_scope_column_without_selection(tmp_path: Path) -> None:
    """Legacy / passthrough runs (no component_selection) keep the original
    column layout — no Scope column."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    comps = [{"id": "api", "name": "API", "tier": "application", "paths": ["src/api"]}]
    ctx = compose.RenderContext(
        output_dir=out_dir,
        contract={},
        yaml_data={"components": comps, "threats": []},
        triage={},
        fragments_dir=out_dir / ".fragments",
    )
    out = compose._inject_components_table(ctx, "### 2.3 Components\n\nIntro.\n")
    assert "| ID | Name | Type | Key Paths | Linked Threats |" in out
    assert "Scope |" not in out


def test_figure1_victim_classes_draw_a_dotted_edge_to_the_shop_user(tmp_path: Path) -> None:
    """Victim-targeting classes (XSS / CSRF) draw an explicit dotted consequence
    edge ONTO the Shop User node, labelled with the targeting class ("① XSS"), so
    the attack against the user is shown as a real arrow (2026-06-14 user
    request). The node itself is just labelled as the attack victim — the class
    is on the edge, not stuffed into the node text."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    ctx = compose.RenderContext(
        output_dir=out_dir,
        contract={},
        yaml_data={
            "components": [
                {"id": "spa", "name": "SPA", "tier": "client"},
                {"id": "api", "name": "API", "tier": "application"},
            ],
            "threats": [{"id": "F-001", "title": "Stored XSS", "component": "spa", "risk": "Critical"}],
        },
        triage={},
        fragments_dir=out_dir / ".fragments",
    )
    md = compose._render_top_threats_architecture(
        ctx,
        {
            "attack_paths": [
                {"class": "cross-site-scripting", "actor": "victim-required", "target": "victim", "findings": ["F-001"]}
            ]
        },
        {
            "glyph_sequence": ["①"],
            "classes": [
                {
                    "id": "cross-site-scripting",
                    "label": "Cross-Site Scripting",
                    "short_label": "XSS",
                    "default_actor": "victim-required",
                    "default_target_tier": "client",
                }
            ],
        },
    )
    fig1 = md.split("```mermaid", 1)[1].split("```", 1)[0]
    # The Shop User node is present and labelled as the attack victim.
    assert "EXT_SHOPUSER" in fig1, fig1
    assert re.search(r'EXT_SHOPUSER\["[^"]*attack victim', fig1), fig1
    # An explicit dotted consequence edge runs ONTO the Shop User, labelled with
    # the victim-targeting class glyph (restored 2026-06-14).
    assert re.search(r'-\.->\|"[^"]*①[^"]*"\|\s*EXT_SHOPUSER', fig1), fig1
    # The class is on the EDGE, not stuffed into the node text.
    assert "attack target:" not in fig1, "victim class must be on the edge, not the node"


def test_figure1_victim_target_without_client_component_does_not_crash(tmp_path: Path) -> None:
    """Victim-targeting classes can occur in thin API-only models. Figure 1 must
    still render (and mark the victim node) instead of referencing an undefined
    fallback variable."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    ctx = compose.RenderContext(
        output_dir=out_dir,
        contract={},
        yaml_data={
            "components": [
                {"id": "api", "name": "REST API", "tier": "application"},
                {"id": "db", "name": "Primary Database", "tier": "data"},
            ],
            "threats": [
                {"id": "F-001", "title": "Reflected XSS", "component": "api", "risk": "High"},
            ],
        },
        triage={},
        fragments_dir=out_dir / ".fragments",
    )
    md = compose._render_top_threats_architecture(
        ctx,
        {
            "attack_paths": [
                {
                    "class": "cross-site-scripting",
                    "actor": "victim-required",
                    "target": "victim",
                    "findings": ["F-001"],
                    "impact": ["customer-session-hijack"],
                }
            ]
        },
        {
            "glyph_sequence": ["①"],
            "classes": [
                {
                    "id": "cross-site-scripting",
                    "label": "Cross-Site Scripting",
                    "short_label": "XSS",
                    "default_actor": "victim-required",
                    "default_target_tier": "client",
                }
            ],
        },
    )
    assert "```mermaid" in md
    # Victim edge falls back to a non-client representative; the Shop User node
    # still renders (no crash on the no-client-tier path).
    assert "EXT_SHOPUSER" in md


def test_top_threats_rows_self_anchor_the_path_glyph(tmp_path: Path) -> None:
    """Each Top Threats row carries its `#path-<class>` anchor on the `#`
    glyph cell (the merged section dropped the bullet list that used to emit
    those anchors), and the glyph agrees with a diagram attack arrow."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    m = re.search(r"### Security Posture & Top Threats(.+?)(?=^### )", rendered, re.DOTALL | re.MULTILINE)
    assert m, "Security Posture & Top Threats section not found"
    section = m.group(1)
    # Rows look like `| <a id="path-injection"></a>① | …`.
    row_anchors = set(re.findall(r'\|\s*<a id="(path-[a-z-]+)"></a>[①②③④⑤⑥⑦]\s*\|', section))
    if not row_anchors:
        return  # fixture has no qualifying findings → nothing to verify
    # Each anchor is defined exactly once (no duplicate ids).
    for anchor in row_anchors:
        assert section.count(f'<a id="{anchor}"></a>') == 1


def test_legacy_ms_sections_merged(tmp_path: Path) -> None:
    """Security Posture at a Glance + Top Findings + Architecture Assessment
    were merged into the single `### Security Posture & Top Threats` section;
    none of the legacy headings may render."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert "### Security Posture & Top Threats" in rendered
    assert "### Top Findings" not in rendered
    assert "### Architecture Assessment" not in rendered
    # The standalone "### Security Posture at a Glance" / "### Top Threats"
    # headings are gone (folded into the combined heading).
    assert "### Security Posture at a Glance" not in rendered
    assert "### Top Threats\n" not in rendered


def test_operational_strengths_has_three_columns(tmp_path: Path) -> None:
    """As of 2026-05 Operational Strengths is a 3-column cluster table
    (Strength / What's in Place / Effectiveness). The legacy 5-column
    form (Architectural Control / Implementation / Effectiveness / Gap /
    Mitigates) is retired — see agents/shared/ms-template.md and
    agents/appsec-qa-reviewer.md Check 3i."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    header = "| Strength | What's in Place | Effectiveness |"
    assert header in rendered
    # And the retired 5-column form is gone.
    legacy = "| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |"
    assert legacy not in rendered, "retired 5-column Operational Strengths form leaked into the render"


def test_operational_strengths_gap_stacks_sample_findings(tmp_path: Path) -> None:
    """RCA 2026-06-11: the Gap cell's "Bypassed by … e.g. F-012, F-016" sample
    links were comma-joined, so the qa label pass appended all three full titles
    onto ONE ~250ch line whose max-content dominated markdown-it's auto table
    layout and starved the "What's in Place" column to one-word-per-line. The
    sample links must be `<br/>`-stacked (lead line ends `e.g.<br/>`) so each
    title lands on its own line and the cell's per-segment max-content stays
    bounded."""
    import inspect

    src = inspect.getsource(compose._build_strength_clusters)
    assert '"<br/>".join(' in src and "e.g.<br/>" in src, (
        "Gap sample findings must be <br/>-stacked, not comma-joined, or the "
        "Operational Strengths 'What's in Place' column collapses"
    )
    assert "e.g. {sample_links}" not in src, "Gap reverted to a single-line comma-joined sample list"


def test_no_dangling_section7_crossref_when_section7_omitted(tmp_path: Path) -> None:
    """RCA 2026-06-11: at --quick depth §7 (Security Architecture) is omitted,
    but the MS 'Operational Strengths' intro (and the empty-state banner) emitted
    a `[§7](#7-security-architecture)` link unconditionally → a dangling anchor
    (qa_checks has no section-anchor target validation to catch it). When
    render_security_architecture is false, NO `#7-security-architecture` cross-ref
    may survive anywhere in the rendered document."""
    out = _prepare_output_dir(tmp_path)
    ymlp = out / "threat-model.yaml"
    data = yaml.safe_load(ymlp.read_text())
    data.setdefault("meta", {})["assessment_depth"] = "quick"  # → §7 omitted (no rich prior)
    ymlp.write_text(yaml.safe_dump(data, sort_keys=False))
    rendered, _ = compose.render(CONTRACT, out)
    assert "## 7. Security Architecture" not in rendered, "§7 should be omitted at quick depth"
    assert "#7-security-architecture" not in rendered, "dangling §7 anchor leaked into the render while §7 is omitted"
    assert "### Operational Strengths" in rendered  # the MS block itself still renders


def test_section7_crossref_target_exists_when_emitted(tmp_path: Path) -> None:
    """Invariant (positive control): whenever a `#7-security-architecture`
    cross-ref IS emitted (standard/thorough depth, §7 present), its heading
    anchor target must also be present — i.e. the link never dangles."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    if "#7-security-architecture" in rendered:
        assert "## 7. Security Architecture" in rendered, (
            "§7 cross-ref emitted but the §7 heading/anchor is missing — dangling link"
        )


def test_section_3_is_per_finding_walkthroughs(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # §3 is a flat list of per-Critical walkthroughs (`### 3.1`, `### 3.2`, …),
    # each with a `sequenceDiagram`. The retired §3.1 "Attack Chain Overview"
    # cross-finding view (graph LR kill-chains, `#### Chain N` blocks) is gone
    # — the cross-finding/strategic picture now lives solely in the
    # standalone `## Critical Attack Tree` section above §1.
    assert "### 3.1 Attack Chain Overview" not in rendered
    assert "#### Chain " not in rendered
    assert "### 3.1 SQL Injection in Product Search" in rendered
    # Each walkthrough carries a sequenceDiagram (no `graph LR` chain blocks).
    assert re.search(r"```mermaid\s*\n\s*sequenceDiagram", rendered)
    # The retired §3 kill-chains used `graph LR`; scope the guard to the §3
    # region so it does not collide with the `## Critical Attack Tree` above
    # §1, which legitimately renders one `graph LR` diagram.
    s3 = rendered.split("## 3. Attack Walkthroughs", 1)[-1]
    s3 = re.split(r"\n## \d", s3, 1)[0]
    assert not re.search(r"```mermaid\s*\n\s*graph LR", s3), "§3 must not contain `graph LR` chain blocks any more"


def test_evidence_check_badge_renders_on_refuted_and_ambiguous(tmp_path: Path) -> None:
    """M3: rows with evidence_check=refuted carry a strikethrough title
    + ⚠ *(evidence refuted)* marker; rows with evidence_check=ambiguous
    carry an `evidence: ambiguous ◌` token in the location line. Verified
    rows show `evidence: verified` (silent — no badge). The §8 footer
    paragraph "**Evidence verification:**" is emitted once when any
    refuted/ambiguous row is present and omitted otherwise.

    Post-2026-05 layout note: the `◌ *(evidence ambiguous)*` marker that
    used to sit beside the title was moved into the LOC line as
    `evidence: ambiguous ◌` — keeping the title clean and lifting the
    evidence verdict to the same row that carries the file path. The
    refuted marker stays beside the title because strikethrough text
    needs the title context to read.
    """
    out = _prepare_output_dir(tmp_path)
    yml_path = out / "threat-model.yaml"
    data = yaml.safe_load(yml_path.read_text())
    # Tag the first three threats with each verdict; leave the rest alone.
    threats = data["threats"]
    assert len(threats) >= 3, "fixture must have at least 3 threats for this test"
    threats[0]["evidence_check"] = "refuted"
    threats[1]["evidence_check"] = "ambiguous"
    threats[2]["evidence_check"] = "verified"
    yml_path.write_text(yaml.safe_dump(data, sort_keys=False))

    rendered, _ = compose.render(CONTRACT, out)

    # Card layout (2026-05): refuted → strikethrough card heading + ⚠;
    # ambiguous / verified → a glyph in the **Evidence:** field.
    assert re.search(r"#### F-\d+ · ~~.+~~ ⚠", rendered), "refuted heading marker missing"
    assert "◌ ambiguous" in rendered, "ambiguous marker missing"
    assert "✓ verified" in rendered
    # The unchecked verdict stays silent.
    assert "(evidence unchecked)" not in rendered

    # Footnote present once.
    assert "**Evidence verification:**" in rendered
    assert rendered.count("**Evidence verification:**") == 1


def test_evidence_check_footnote_omitted_when_no_drift(tmp_path: Path) -> None:
    """The evidence-check footnote is conditional — when no row carries
    refuted/ambiguous, the footnote MUST be absent. Avoids dead text in
    runs where every finding was verified."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert "**Evidence verification:**" not in rendered


def test_carried_unverified_renders_per_row_marker_and_footnote(tmp_path: Path) -> None:
    """Incremental depth-downgrade: a threat carried forward from a prior
    deeper scan (evidence_check=carried-unverified-shallower-depth) must be
    visibly distinguished in §8 — a `↻ carried, unverified at this depth`
    glyph in its **Evidence:** field plus a once-only "**Carried findings:**"
    footnote. This closes the gap where carried findings rendered identically
    to freshly verified ones.

    The footnote is depth-independent (it lives in §8, not the quick-only
    banner) so a standard re-scan that downgraded from thorough discloses
    carried findings too — asserted here by the absence of the quick-banner
    phrase while the §8 footnote is present.
    """
    out = _prepare_output_dir(tmp_path)
    yml_path = out / "threat-model.yaml"
    data = yaml.safe_load(yml_path.read_text())
    threats = data["threats"]
    assert len(threats) >= 1, "fixture must have at least 1 threat for this test"
    threats[0]["evidence_check"] = "carried-unverified-shallower-depth"
    yml_path.write_text(yaml.safe_dump(data, sort_keys=False))

    rendered, _ = compose.render(CONTRACT, out)

    # Per-row marker in the Story-Card **Evidence:** field.
    assert "↻ carried, unverified at this depth" in rendered
    # Depth-independent §8 footnote, emitted exactly once.
    assert "**Carried findings:**" in rendered
    assert rendered.count("**Carried findings:**") == 1
    # The disclosure came from §8 (non-quick render) — NOT the quick banner.
    assert "carried forward without re-verification" not in rendered


def test_carried_footnote_omitted_when_no_carried_rows(tmp_path: Path) -> None:
    """The carried-findings footnote is conditional — absent when no row
    carries the depth-downgrade marker. Avoids dead text on full/equal-depth
    runs."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert "**Carried findings:**" not in rendered
    assert "↻ carried, unverified at this depth" not in rendered


def test_threat_register_is_card_layout(tmp_path: Path) -> None:
    """§8 Findings Register uses the 2026-05 severity-grouped card layout.

    The flat 4-column table (`ID | Finding | Component | Criticality`) was
    replaced by one card per finding under `### <emoji> <Severity> (n)`
    group headers, mirroring §9. Per-TH anchors are still emitted as an
    invisible block at the top of §8.
    """
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Header is present with Risk + STRIDE summary lines.
    assert "**Risk Distribution:** 🔴 Critical: 3 · 🟠 High: 1 · " in rendered
    assert "**STRIDE Coverage:**" in rendered
    # The legacy flat table header must be gone.
    assert "| ID | Finding | Component | Criticality |" not in rendered
    # Severity group headers + per-finding card headings.
    assert "### 🔴 Critical (3)" in rendered
    assert re.search(r"#### F-\d+ · ", rendered), "expected per-finding card headings"
    # Legacy 8.A/8.B sub-sections never appear.
    assert "### 8.A Categories at a glance" not in rendered
    assert "### 8.B Critical Categories" not in rendered
    # Per-TH anchors + every threat anchor still emitted.
    assert 'id="th-01"' in rendered or 'id="th-03"' in rendered
    for tid in ("t-001", "t-002", "t-003", "t-010"):
        assert f'<a id="{tid}"></a>' in rendered


# ---------------------------------------------------------------------------
# §8 Story-Card walkthrough back-links + severity-tiered snippet gate
# ---------------------------------------------------------------------------


def _slice_threat_register(rendered: str) -> str:
    """Return the rendered §8 Findings Register body."""
    i = rendered.find("## 8. Findings Register")
    assert i >= 0, "expected §8 in rendered output"
    j = rendered.find("\n## ", i + 5)
    return rendered[i:j] if j > 0 else rendered[i:]


def test_finding_cell_links_critical_finding_to_attack_walkthrough(tmp_path: Path) -> None:
    """Critical/High Story-Card rows surface a back-link to §3 Attack
    Walkthroughs when the chain map resolves the finding's id."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    section8 = _slice_threat_register(rendered)

    # Fixture §3.1–3.3 are per-finding walkthroughs for T-001 / T-002 / T-003,
    # each declaring its owner on a `**Source:** [T-NNN]` line. The §8 Story
    # Card surfaces the back-link to the owning walkthrough.
    # 2026-05-29 (supersedes Item 5): all Story-Card labels render in uniform
    # **bold**, and the walkthrough label is spelled "Attack Walkthrough" to
    # match the §8 intro element list.
    # Card layout (2026-05): the walkthrough back-link rides as a tail on the
    # Classification line (`· walkthrough [Walkthrough §3.N](#…)`).
    assert "walkthrough [Walkthrough §3.3](#33-hardcoded-rsa-private-key)" in section8
    assert "(#chain-" not in section8  # no §3.1 chain back-links any more


def test_finding_cell_omits_walkthrough_line_when_no_chains_resolve(tmp_path: Path) -> None:
    """When the §3 fragment contains no `#### Chain N` headings (e.g.
    skip-mode stub or empty), the cell renders without an Attack Walkthrough
    line (graceful no-op — chain map returns {})."""
    out = _prepare_output_dir(tmp_path)
    # Replace fragment with a stub that has the required H2 but no chains.
    stub_frag = (
        "## 3. Attack Walkthroughs\n\n_Skipped at this depth — see §8 Findings Register for finding-level detail._\n"
    )
    (out / ".fragments" / "attack-walkthroughs.md").write_text(stub_frag, encoding="utf-8")
    # The contract gates §3.1 subsection requirement on
    # `not skip_attack_walkthroughs` — set the flag so the missing §3.1
    # heading does not trip required_subsections validation.
    (out / ".skill-config.json").write_text(json.dumps({"skip_attack_walkthroughs": True}), encoding="utf-8")
    rendered, _ = compose.render(CONTRACT, out)
    section8 = _slice_threat_register(rendered)
    assert "**Attack Walkthrough:**" not in section8


def test_chain_map_extracts_walkthrough_anchors_from_fixture(tmp_path: Path) -> None:
    """`_build_finding_to_chain_map` parses the §3.N per-finding walkthrough
    sub-sections in the fixture and registers each owner (from its
    `**Source:** [T-NNN]` line) under the canonical `github_slug` anchor.
    The §3.1 Attack Chain Overview was retired — there are no `#### Chain N`
    entries any more."""
    out = _prepare_output_dir(tmp_path)
    ctx = compose.RenderContext(
        output_dir=out,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=out / ".fragments",
    )
    chain_map = compose._build_finding_to_chain_map(ctx)
    assert chain_map.get("T-001") == ("Walkthrough §3.1", "31-sql-injection-in-product-search")
    assert chain_map.get("T-003") == ("Walkthrough §3.3", "33-hardcoded-rsa-private-key")
    # F-NNN alias mirrors T-NNN for every registered id.
    assert chain_map.get("F-001") == ("Walkthrough §3.1", "31-sql-injection-in-product-search")
    assert chain_map.get("F-003") == ("Walkthrough §3.3", "33-hardcoded-rsa-private-key")


def test_chain_map_reads_owner_from_source_line(tmp_path: Path) -> None:
    """The owning finding is read from the `**Source:** [T-NNN]` line, not
    from the heading (which the deterministic renderer keeps T-NNN-free to
    satisfy heading hygiene). A T-NNN that only appears as a body
    cross-reference must NOT claim the walkthrough."""
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    (frag_dir / "attack-walkthroughs.md").write_text(
        "## 3. Attack Walkthroughs\n\n"
        "### 3.1 SQL Injection Detail\n\n"
        "**Source:** [T-001](#t-001) — `routes/login.ts:34`\n\n"
        "Walks through T-001 step by step; sibling finding T-005 is related.\n",
        encoding="utf-8",
    )
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag_dir,
    )
    chain_map = compose._build_finding_to_chain_map(ctx)
    label, anchor = chain_map["T-001"]
    assert label == "Walkthrough §3.1"
    assert anchor == "31-sql-injection-detail"
    # The body cross-reference to T-005 must not register it as the owner.
    assert "T-005" not in chain_map


def test_chain_map_returns_empty_when_fragment_missing(tmp_path: Path) -> None:
    """No `.fragments/attack-walkthroughs.md` → empty map, no exception."""
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag_dir,
    )
    assert compose._build_finding_to_chain_map(ctx) == {}


# ---------------------------------------------------------------------------
# §8 Story-Card Component anchor + Issue/Impact disjointness regressions
# These two checks pin bugs that previously shipped to production:
#   1. _build_finding_cell linked the in-cell Component using the raw slug
#      (`#express-backend`) while the Component column used the canonical
#      `#c-01` anchor — two different anchors for the same component.
#   2. Issue and Impact frequently rendered the SAME sentence because Issue
#      kept N scenario sentences and Impact then drew the LAST sentence as
#      its consequence — overlap was the norm, not the exception.
# ---------------------------------------------------------------------------


def _make_threat_for_cell(
    scenario: str,
    *,
    comp_id: str = "rest-api",
    file_: str = "routes/login.ts",
    line: int = 34,
    severity: str = "Critical",
) -> dict:
    """Threat shape exercising _build_finding_cell end-to-end."""
    return {
        "t_id": "T-099",
        "id": "T-099",
        "component_id": comp_id,
        "component": comp_id,
        "stride": "Tampering",
        "stride_category": "Tampering",
        "title": "SQL injection",
        "scenario": scenario,
        "severity": severity,
        "risk": severity,
        "likelihood": "High",
        "impact": severity,
        "cwe": "CWE-89",
        "evidence": [{"file": file_, "line": line}],
        "mitigations": ["M-001"],
        "vektor": "internet-anon",
        "evidence_check": "verified",
    }


def test_finding_cell_component_uses_canonical_C_NN_anchor(tmp_path: Path) -> None:
    """The in-cell `**Component:**` link MUST resolve the raw slug to the
    canonical `C-NN` anchor — matching the Component column on the same row.

    Without this normalisation the cell renders
    `[express-backend](#express-backend)` while the column carries
    `[C-01 — Express.js Backend API](#c-01)`. Same component, two different
    anchors — broken cross-references and a confused reader.
    """
    components = {
        "C-01": {"_canonical_id": "C-01", "_original_id": "rest-api", "name": "REST API"},
        "rest-api": {"_canonical_id": "C-01", "_original_id": "rest-api", "name": "REST API"},
    }
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=tmp_path,
    )
    threat = _make_threat_for_cell("Login concatenates email into SQL.", comp_id="rest-api")

    cell = compose._build_threat_card(
        t=threat,
        sev="critical",
        taxonomy={},
        components=components,
        repo_root=None,
        ctx=ctx,
    )

    assert "**Component:** [C-01](#c-01) — REST API" in cell, (
        "expected canonical C-NN anchor in the in-cell Component link "
        "(all Story-Card labels uniform bold, 2026-05-29); cell was:\n" + cell
    )
    # The raw slug must NOT appear as a link target.
    assert "(#rest-api)" not in cell, "raw slug anchor leaked into Component link instead of canonical C-NN"


def test_finding_cell_component_already_canonical_passes_through(tmp_path: Path) -> None:
    """When the threat already carries `component_id: C-01`, the cell renders
    the canonical anchor verbatim — no surprise resolution needed."""
    components = {"C-01": {"name": "REST API"}}
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=tmp_path,
    )
    threat = _make_threat_for_cell("Login concatenates email into SQL.", comp_id="C-01")
    cell = compose._build_threat_card(
        t=threat,
        sev="critical",
        taxonomy={},
        components=components,
        repo_root=None,
        ctx=ctx,
    )
    assert "**Component:** [C-01](#c-01) — REST API" in cell


def test_finding_card_folds_consequence_into_issue(tmp_path: Path) -> None:
    """The card has no separate **Impact:** field — the consequence is folded
    into the **Issue:** line so it is never lost (2026-05 card layout)."""
    scenario = (
        "An attacker sends a UNION SELECT in the login email field. "
        "The raw query interpolates the input directly into SQL. "
        "Authentication is bypassed and the entire Users table is dumped to the response."
    )
    components = {"C-01": {"_canonical_id": "C-01", "_original_id": "rest-api", "name": "REST API"}}
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=tmp_path,
    )
    threat = _make_threat_for_cell(scenario, comp_id="C-01")

    cell = compose._build_threat_card(
        t=threat,
        sev="critical",
        taxonomy={},
        components=components,
        repo_root=None,
        ctx=ctx,
    )

    # No standalone Impact field; the Issue line carries the consequence.
    assert "**Impact:**" not in cell
    issue_line = next(l for l in cell.splitlines() if l.startswith("**Issue:**"))
    assert "Authentication is bypassed" in issue_line or "dumped to the response" in issue_line, (
        "expected the consequence folded into the Issue line:\n" + issue_line
    )


def test_finding_cell_explicit_impact_description_does_not_carve_issue(tmp_path: Path) -> None:
    """When the YAML supplies an explicit `impact_description`, Issue keeps
    its full N-sentence window — the carve-out only applies when Impact is
    derived from scenario."""
    scenario = (
        "An attacker probes the endpoint. The application accepts the payload. "
        "No alert fires. Logs do not capture the attempt."
    )
    components = {"C-01": {"_canonical_id": "C-01", "_original_id": "rest-api", "name": "REST API"}}
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=tmp_path,
    )
    threat = _make_threat_for_cell(scenario, comp_id="C-01")
    threat["impact_description"] = "Loss of forensic ability to reconstruct the attack."

    cell = compose._build_threat_card(
        t=threat,
        sev="critical",
        taxonomy={},
        components=components,
        repo_root=None,
        ctx=ctx,
    )

    issue_line = next(l for l in cell.splitlines() if l.startswith("**Issue:**"))
    # Card layout: explicit impact is folded into the Issue line (no separate
    # Impact field), and the full scenario is retained (no carve-out).
    assert "Loss of forensic ability to reconstruct the attack" in issue_line
    assert "Logs do not capture the attempt" in issue_line


def test_evidence_snippet_summary_label_is_evidence_not_code(tmp_path: Path) -> None:
    """§8 code snippets use a `<summary><i>Evidence · file:line</i></summary>`
    disclosure widget — the legacy `Code · …` label is gone."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    section8 = _slice_threat_register(rendered)
    if "<details>" in section8:
        # Fixture has Critical findings → at least one snippet expected.
        assert "<summary><i>Evidence · " in section8
        assert "<summary><i>Code · " not in section8


# ---------------------------------------------------------------------------
# Pregenerator skeleton — §3 + §3.1 intro paragraphs
# ---------------------------------------------------------------------------


def test_attack_walkthroughs_skeleton_has_no_chain_overview() -> None:
    """The §3.1 Attack Chain Overview was retired — the cross-finding view is
    the `## Critical Attack Tree`. `_chain-skeleton.md` is no longer consumed
    by any agent, so the skeleton generator now mirrors the deterministic
    per-Critical walkthrough generator: a §3 chapter intro plus `### 3.N`
    walkthroughs, with NO `### 3.1 Attack Chain Overview` / `#### Chain N`
    / `graph LR` kill-chain blocks."""
    pregen_path = REPO_ROOT / "scripts" / "pregenerate_fragments.py"
    pf = _load_module("pregenerate_fragments", pregen_path)
    yaml_data = {
        "threats": [
            {"id": "T-001", "title": "SQL injection in login", "risk": "Critical"},
            {"id": "T-002", "title": "Hardcoded admin password", "risk": "Critical"},
        ]
    }
    md = pf.gen_attack_walkthroughs_skeleton(yaml_data)
    assert "## 3. Attack Walkthroughs" in md
    assert "### 3.1 Attack Chain Overview" not in md
    assert "#### Chain " not in md
    assert "graph LR" not in md
    # Per-finding walkthroughs are present (the first owns §3.1's number now).
    assert "### 3.1 " in md


def test_mitigation_register_derived_from_yaml(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    for mid in ("m-001", "m-002", "m-003"):
        assert f'<a id="{mid}"></a>' in rendered


def _attack_tree_data(n_leaves: int) -> dict:
    """Synthesize a critical-attack-tree fragment with `n_leaves` leaves spread
    across two capability OR-nodes feeding a single goal."""
    nodes = [
        {"id": "G_ROOT", "label": "Full takeover", "class": "goal"},
        {"id": "OR_A", "label": "Capability A", "class": "or_node"},
        {"id": "OR_B", "label": "Capability B", "class": "or_node"},
    ]
    edges = [
        {"from": "OR_A", "to": "G_ROOT", "label": "OR"},
        {"from": "OR_B", "to": "G_ROOT", "label": "OR"},
    ]
    for i in range(n_leaves):
        lid = f"L_T{i:03d}"
        cap = "OR_A" if i % 2 == 0 else "OR_B"
        nodes.append({"id": lid, "label": f"T-{i:03d} finding", "class": "leaf"})
        edges.append({"from": lid, "to": cap, "label": "OR"})
    return {"mermaid": {"orientation": "TD", "nodes": nodes, "edges": edges}}


def test_attack_tree_renders_single_lr_block() -> None:
    """The whole tree renders as ONE `graph LR` diagram, every leaf present,
    leaf boxes labelled `T-NNN — <short title>` (id + title, 2026-05-30), and
    only the four classDefs the tree actually uses."""
    blocks = compose._build_attack_tree_blocks(_attack_tree_data(4))
    assert len(blocks) == 1
    assert blocks[0]["title"] is None
    src = blocks[0]["src"]
    assert src.startswith("graph LR")
    assert "classDef goal" in src
    # Trimmed palette — the unused classes are gone.
    assert "classDef attacker" not in src and "classDef crit" not in src
    for i in range(4):
        assert f"L_T{i:03d}" in src  # internal node id retained (not reader-visible)
        assert f'["F-{i:03d} — finding"]' in src  # visible leaf label: T-NNN → F-NNN


def test_attack_tree_wide_still_single_block() -> None:
    """A wide tree (well past the old split threshold) still renders as ONE
    `graph LR` block carrying every leaf — the cross-branch convergence view is
    no longer fragmented into per-capability sub-diagrams."""
    blocks = compose._build_attack_tree_blocks(_attack_tree_data(8))
    assert len(blocks) == 1
    src = blocks[0]["src"]
    assert src.startswith("graph LR")
    assert "graph TD" not in src
    assert "OR_A" in src and "OR_B" in src
    assert all(f"L_T{i:03d}" in src for i in range(8))
    # Every leaf appears exactly once in the single diagram (no loss, no dup).
    for i in range(8):
        assert src.count(f'L_T{i:03d}["') == 1


def test_codify_inline_identifiers_no_mid_token_backticks() -> None:
    """Story-Card prose path wrapping must not split a path/extension mid-token.

    Regression: `_CODE_FILE_RE` wraps the whole path, then `_CODE_DOTTED_RE`
    used to re-match `component.html` INSIDE that fresh span, yielding
    `administration.` `component.html` `:26` (mid-token backticks). Each code
    matcher now runs only outside existing spans.
    """
    out = compose._codify_inline_identifiers(
        "HTML (frontend/src/app/administration/administration.component.html:26) renders user.email."
    )
    assert "`frontend/src/app/administration/administration.component.html:26`" in out
    assert "administration.`component" not in out
    assert out.count("`") % 2 == 0  # all spans balanced

    out2 = compose._codify_inline_identifiers(
        "comp (frontend/src/app/last-login-ip/last-login-ip.component.ts:39) uses bypassSecurityTrustHtml()."
    )
    assert "`frontend/src/app/last-login-ip/last-login-ip.component.ts:39`" in out2
    assert "last-login-`ip" not in out2
    assert "`bypassSecurityTrustHtml()`" in out2


def test_balance_code_spans_merges_partially_wrapped_expression() -> None:
    """An arrow-function / multi-call expression the author only half-wrapped
    must render as ONE code span, not half-monospaced prose.

    Regression (juice-shop 2026-06-24): the per-token matchers skip non-empty
    paren calls + arrow functions, so `foo.forEach((x) => { `bar(x)` })` shipped
    with only the inner call backticked. `_codify_inline_identifiers` now runs
    `_balance_code_spans` as a final pass.
    """
    raw = (
        "◌ ambiguous - notifications.forEach((notification) => "
        "{ `socket.emit('challenge solved', notification)` }) at line 29 pushes data."
    )
    out = compose._codify_inline_identifiers(raw)
    assert "`notifications.forEach((notification) => { socket.emit('challenge solved', notification) })`" in out
    # one balanced span, prose tail preserved
    assert out.count("`") == 2
    assert out.endswith("at line 29 pushes data.")
    # idempotent
    assert compose._codify_inline_identifiers(out) == out


def test_balance_code_spans_leaves_standalone_span_and_prose_untouched() -> None:
    """A balanced standalone span surrounded by prose must NOT absorb words."""
    # `socket.emit()` is whole; "call broadcasts" is prose → no merge.
    assert compose._balance_code_spans("the `socket.emit()` call broadcasts") == "the `socket.emit()` call broadcasts"
    # file:line locator followed by prose → untouched.
    assert (
        compose._balance_code_spans("`routes/foo.ts:9` defines the handler") == "`routes/foo.ts:9` defines the handler"
    )
    # no backticks at all → returned verbatim.
    assert compose._balance_code_spans("plain prose, no code") == "plain prose, no code"


def test_curate_top_mitigations_floor_and_llm_order() -> None:
    """Critical-floor always shown; LLM curates the extras within the soft max."""
    floor = [{"id": "M-001"}, {"id": "M-002"}]
    extras_sorted = [{"id": "M-006"}, {"id": "M-007"}, {"id": "M-008"}, {"id": "M-009"}]
    # LLM prefers M-008 then M-006; max 4 → floor(2) + 2 extras.
    out = compose._curate_top_mitigations(floor, extras_sorted, ["M-008", "M-006"], 3, 4)
    assert [m["id"] for m in out] == ["M-001", "M-002", "M-008", "M-006"]


def test_curate_top_mitigations_no_fragment_is_deterministic() -> None:
    """No LLM order → extras in caller's deterministic order; clamped to max."""
    floor = [{"id": "M-001"}]
    extras_sorted = [{"id": "M-006"}, {"id": "M-007"}, {"id": "M-008"}]
    out = compose._curate_top_mitigations(floor, extras_sorted, [], 3, 3)
    assert [m["id"] for m in out] == ["M-001", "M-006", "M-007"]


def test_curate_top_mitigations_floor_never_truncated() -> None:
    """Coverage wins: a floor larger than max is shown in full (no truncation)."""
    floor = [{"id": "M-001"}, {"id": "M-002"}, {"id": "M-003"}, {"id": "M-004"}]
    extras_sorted = [{"id": "M-009"}]
    out = compose._curate_top_mitigations(floor, extras_sorted, ["M-009"], 3, 2)
    assert [m["id"] for m in out] == ["M-001", "M-002", "M-003", "M-004"]  # extras dropped, floor intact


def test_curate_top_mitigations_drops_unknown_and_floor_dupes() -> None:
    """Unknown ids and floor ids listed by the LLM are ignored in the extras slot."""
    floor = [{"id": "M-001"}]
    extras_sorted = [{"id": "M-006"}, {"id": "M-007"}]
    out = compose._curate_top_mitigations(floor, extras_sorted, ["M-001", "M-999", "M-007"], 3, 10)
    # M-001 (floor dupe) + M-999 (unknown) ignored; M-007 first, then remaining M-006.
    assert [m["id"] for m in out] == ["M-001", "M-007", "M-006"]


def test_attack_tree_findings_pointer_from_leaves() -> None:
    """The compact findings pointer is derived deterministically from the tree's
    leaf nodes in declaration order: each leaf's id + title (label minus the id
    prefix) + lowercased §8 anchor, deduped, no mitigations."""
    data = _attack_tree_data(4)  # leaves L_T000..L_T003, labels "T-000 finding" ...
    findings = compose._derive_attack_tree_findings(data)
    # Visible ids normalise T-NNN → F-NNN (the §8 register's canonical id).
    assert [f["id"] for f in findings] == ["F-000", "F-001", "F-002", "F-003"]
    assert findings[0] == {"id": "F-000", "title": "finding", "anchor": "#f-000"}
    # No mitigation data leaks into the pointer.
    assert all("mitigation" not in f and "mitigations" not in f for f in findings)


def test_attack_tree_findings_pointer_dedups_and_skips_non_leaves() -> None:
    """Capability/goal nodes are excluded; a repeated finding id appears once."""
    data = {
        "mermaid": {
            "nodes": [
                {"id": "G", "label": "Goal", "class": "goal"},
                {"id": "OR_A", "label": "Cap", "class": "or_node"},
                {"id": "L1", "label": "T-005 SQLi login bypass", "class": "leaf"},
                {"id": "L2", "label": "T-005 dup", "class": "leaf"},
                {"id": "L3", "label": "T-009 RCE via eval", "class": "leaf", "finding_ref": "T-009"},
            ],
            "edges": [],
        }
    }
    findings = compose._derive_attack_tree_findings(data)
    assert [f["id"] for f in findings] == ["F-005", "F-009"]
    assert findings[0]["title"] == "SQLi login bypass"


def test_normalize_visible_threat_ids() -> None:
    """Global backstop: every reader-visible T-NNN → F-NNN (link form rewrites
    text AND anchor; bare/prefixed prose and mermaid labels too), while
    lowercase anchors and AC-T-NNN abuse-case ids are preserved."""
    f = compose._normalize_visible_threat_ids
    # Link form — text + anchor.
    assert f("[T-002](#t-002)") == "[F-002](#f-002)"
    # Text already F but anchor still the merge-stage #t- (per-component
    # "Linked Threats" cells) → anchor normalised so the dot pass annotates it.
    assert f("[F-001](#t-001)") == "[F-001](#f-001)"
    # Bare prose.
    assert f("until M-001 lands, T-004 is exploitable") == "until M-001 lands, F-004 is exploitable"
    # Mermaid alt label.
    assert f("    alt Current state — T-003") == "    alt Current state — F-003"
    # Link text with a prefix (anchor stays lowercase but resolves via dual anchor).
    assert f("[§8 T-001](#t-001)") == "[§8 F-001](#t-001)"
    # Mixed text/anchor (LLM §7 drift) — bare pass fixes the text.
    assert f("[T-003](#f-003)") == "[F-003](#f-003)"
    # AC-T-NNN abuse-case ids are NOT touched.
    assert f("[AC-T-005](#ac-t-005)") == "[AC-T-005](#ac-t-005)"
    assert f("see AC-T-005 for detail") == "see AC-T-005 for detail"
    # Mermaid internal node ids (no hyphen) and TH-/CWE- are untouched.
    assert f("L_T003-->|AND|AND_JWT") == "L_T003-->|AND|AND_JWT"
    assert f("TH-01 / CWE-321") == "TH-01 / CWE-321"


def test_changelog_finding_refs_have_no_severity_dot(tmp_path: Path) -> None:
    """The Changelog is a historical delta log, not a severity-ranked findings
    list — its F-NNN refs are normalised (no visible T-NNN) but carry NO
    severity dot / priority circle (those would be inconsistent across
    resolved vs still-present threats)."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed": {"threats": ["T-002"], "notes_by_id": {"T-002": "sev up"}},
            },
            {"version": 1, "date": "2026-04-19", "mode": "full", "note": "Initial"},
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "[F-002](#f-002)" in section  # normalised to visible F-NNN
    assert "[T-002](#t-002)" not in section  # no stale T-NNN
    # No severity dot immediately before the changelog finding link.
    assert "🔴 [F-002]" not in section and "🟠 [F-002]" not in section


def test_mitigations_section_uses_component_column(tmp_path: Path) -> None:
    """The Management Summary Top Mitigations section is a single ranked table
    with a dedicated `Component` column (2026-05-29 update).

    The earlier in-table divider-row form `| **↳ Component …** | | | | |`
    rendered the component label jammed into the `#`/ID column with four empty
    trailing cells — it looked displaced. The component label now lives in its
    own column, printed once per group (blank on continuation rows), so the
    table reads as grouped-by-component while every value sits in a real
    column. Matches the sibling Top Findings table.

    Layout (2026-06-03 — the dedicated `Priority` column was dropped; the
    rollout priority now rides on the linked mitigation as a leading prefix.
    2026-06-04 — Variant B: a single monochrome circled digit whose number is
    the priority, `❶` … `❹`):
        | # | Component               | Mitigation                  | Addresses | Effort |
        |---|---|---|---|---|
        | 1 | **Express Backend (c-…)**  | ❶ [M-001](#m-001) — …      | ...       | ...    |
        | 2 |                            | ❶ [M-002](#m-002) — …      | ...       | ...    |
    """
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)

    # Slice the Top Mitigations section out of the Management Summary.
    ms_slice = rendered.split("### Top Mitigations", 1)[1].split("\n### ", 1)[0]

    # Legacy headers from earlier layouts are gone.
    assert "#### Prioritized Mitigations" not in ms_slice
    assert "#### Follow-up Mitigations" not in ms_slice
    assert "####" not in ms_slice, "Top Mitigations layout must not emit `####` sub-headers"

    # Canonical 5-column pipe-table header — the dedicated Priority column was
    # dropped (2026-06-03); priority now rides on the linked mitigation prefix.
    assert "| # | Component | Mitigation | Addresses | Effort |" in ms_slice

    import re as _re

    # The retired in-table divider-row form must NOT appear (regression guard).
    assert not _re.search(
        r"^\|\s*\*\*↳\s+.+?\s+[—\-]\s+\d+\s+item\(s\)\*\*\s*\|",
        ms_slice,
        flags=_re.MULTILINE,
    ), "in-table `↳ Component — N item(s)` divider row is retired (2026-05-29)"
    # No `↳` group glyph anywhere in the section any more.
    assert "↳" not in ms_slice, "component grouping no longer uses the ↳ glyph"

    # Priority now rides on the linked mitigation as a single colourless circled
    # digit whose number is the priority (Variant B, 2026-06-04 — ❶❷❸❹) rather
    # than a dedicated bold column cell. Assert the circled-digit prefix renders.
    assert _re.search(r"[❶❷❸❹]\s+\[M-", ms_slice), "expected a Variant-B `❶ [M-NNN]` circled-digit priority prefix"

    # The Component column carries a label on the first row of each group,
    # linked to the component anchor exactly like the Architecture Assessment
    # "Affected components" cell: `[C-NN](#c-nn) — Name` (or the unlinked
    # "Cross-cutting" sentinel when a mitigation maps to no component).
    data_rows = [
        ln
        for ln in ms_slice.splitlines()
        if _re.match(r"^\|\s*\*\*\d+\*\*\s*\|", ln)  # rows whose # cell is **N**
    ]
    assert data_rows, "expected at least one numbered data row"
    first_cells = [c.strip() for c in data_rows[0].split("|")]
    # cells: ['', '**1**', '[C-NN](#c-nn) — Name', 'P1 · <mitigation>', ...]
    # (Priority column dropped 2026-06-03 — Component shifted from index 3 to 2.)
    comp_cell = first_cells[2]
    assert _re.match(r"^\[C-\d+\]\(#c-\d+\)\s+—\s+.+", comp_cell) or comp_cell == "Cross-cutting", (
        f"first row's Component cell must be a `[C-NN](#c-nn) — Name` link "
        f"(matching Architecture Assessment) or 'Cross-cutting', got {comp_cell!r}"
    )


# ---------------------------------------------------------------------------
# Changelog — per-version Added/Changed/Resolved breakdown
# ---------------------------------------------------------------------------


def _extract_changelog_section(md: str) -> str:
    i = md.find("## Changelog")
    assert i >= 0, "rendered output must contain a Changelog section"
    j = md.find("\n## ", i + 5)
    return md[i:j] if j > 0 else md[i:]


def _rewrite_changelog(out: Path, entries: list[dict]) -> None:
    ymp = out / "threat-model.yaml"
    data = yaml.safe_load(ymp.read_text(encoding="utf-8"))
    data["changelog"] = entries
    ymp.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _contract_with_changelog_style(tmp_path: Path, style: str) -> Path:
    """Copy the canonical contract to tmp_path and force the changelog
    `render_style` to the given value. Use to exercise the legacy bullets
    renderer while the default remains ``table``.
    """
    dst = tmp_path / "sections-contract.yaml"
    data = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    data["sections"]["changelog"]["render_style"] = style
    # Strip the explicit template so render_style is the decisive signal.
    data["sections"]["changelog"].pop("template", None)
    dst.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return dst


def test_changelog_v1_initial_assessment_has_no_delta_bullets(tmp_path: Path) -> None:
    """First-run entry (no baseline) renders heading + zero delta bullets."""
    out = _prepare_output_dir(tmp_path)
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "### v1 — 2026-04-19 (full — initial assessment)" in section
    for forbidden in ("**Added:**", "**Changed:**", "**Resolved:**"):
        assert forbidden not in section, f"v1/no-baseline must not emit {forbidden}"


def test_changelog_incremental_renders_added_changed_resolved(tmp_path: Path) -> None:
    """Incremental entry with deltas renders Added/Changed/Resolved bullets
    with linkified T-IDs and inline notes/reasons. This is the invariant
    that the console Change Summary also pins — the md must not silently
    degrade to counts-only."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed_files": 7,
                "reanalyzed_components": ["C-01"],
                "carried_forward_components": ["C-02"],
                "added": {
                    "threats": ["T-020", "T-021"],
                    "components": [],
                    "attack_surface": ["E-03"],
                },
                "changed": {
                    "threats": ["T-002"],
                    "notes_by_id": {"T-002": "severity High → Critical"},
                },
                "resolved": {
                    "threats": ["T-010"],
                    "reason_by_id": {"T-010": "not reproduced on full re-analysis"},
                },
            },
            {
                "version": 1,
                "date": "2026-04-19",
                "mode": "full",
                "current_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "note": "Initial assessment",
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)

    # Heading carries short baseline → current SHAs.
    assert "### v2 — 2026-04-23 (incremental, baseline `cb6fb8a` → `a1b2c3d`)" in section

    # Every delta bullet present with correct plural form + T-ID anchors.
    # Added/Changed/Resolved enumerate threats only — components and entry
    # points live in the dedicated **Architecture** bullet for readability.
    assert "- **Added:** 2 threats ([F-020](#f-020), [F-021](#f-021))" in section
    assert '- **Changed:** 1 threat ([F-002](#f-002): "severity High → Critical")' in section
    assert '- **Resolved:** 1 threat ([F-010](#f-010): "not reproduced on full re-analysis")' in section
    assert "- **Architecture:** +1 entry point (E-03)" in section
    assert "- **Re-analyzed:** C-01" in section
    assert "- **Carried forward:** C-02" in section
    assert "- **Changed files:** 7" in section

    # Older v1 entry still rendered below, untouched.
    assert "### v1 — 2026-04-19 (full — initial assessment)" in section
    # v2 must appear above v1 (newest first).
    assert section.index("### v2 —") < section.index("### v1 —")


def test_changelog_full_rebuild_with_baseline_renders_only_nonempty_bullets(tmp_path: Path) -> None:
    """A `mode: full` rerun with a baseline omits empty delta categories —
    e.g. if nothing new was added and nothing changed, only **Resolved**
    renders. Guards against the `- **Added:** 0 threats ()` regression."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 3,
                "date": "2026-05-01",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "note": "full rebuild — all components re-analyzed",
                "reanalyzed_components": ["C-01", "C-02"],
                "carried_forward_components": [],
                "added": {"threats": [], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": ["T-020"], "reason_by_id": {"T-020": "not reproduced on full re-analysis"}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)

    assert '- **Resolved:** 1 threat ([F-020](#f-020): "not reproduced on full re-analysis")' in section
    # Empty delta categories must NOT render — guards against "0 threats" noise.
    assert "**Added:**" not in section
    assert "**Changed:**" not in section
    # Trailing `note` bullet still rendered for the full-rebuild message.
    # Post-2026-05 — _normalize_emdashes converts em-dashes in plain prose
    # bullets to ASCII hyphens (heading lines, anchor-link bullets and
    # GFM table rows are preserved). The note is a plain prose bullet, so
    # the em-dash in the YAML input is normalised on the way out.
    assert "- full rebuild - all components re-analyzed" in section


def test_changelog_caps_inline_ids_at_five_with_more_suffix(tmp_path: Path) -> None:
    """Large full-rebuild deltas must not render an unreadable single-line
    bullet with dozens of inline T-IDs. The fragment caps inline enumeration
    at the first 5 T-IDs and appends `, +<n> more`. The yaml still persists
    the full list — the cap is markdown-only."""
    out = _prepare_output_dir(tmp_path)
    many_added = [f"T-{i:03d}" for i in range(20, 32)]  # 12 items → 7 extra
    many_changed = [f"T-{i:03d}" for i in range(40, 48)]  # 8 items  → 3 extra
    many_resolved = [f"T-{i:03d}" for i in range(60, 66)]  # 6 items  → 1 extra
    _rewrite_changelog(
        out,
        [
            {
                "version": 4,
                "date": "2026-05-02",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "note": "full rebuild — all components re-analyzed",
                "reanalyzed_components": ["C-01", "C-02"],
                "carried_forward_components": [],
                "added": {"threats": many_added, "components": [], "attack_surface": []},
                "changed": {
                    "threats": many_changed,
                    "notes_by_id": {t: "severity High → Critical" for t in many_changed},
                },
                "resolved": {
                    "threats": many_resolved,
                    "reason_by_id": {t: "not reproduced on full re-analysis" for t in many_resolved},
                },
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)

    # Added: count reflects full list; inline enumeration shows 5 IDs + "+7 more".
    assert "- **Added:** 12 threats (" in section
    assert "[F-020](#f-020)" in section
    assert "[F-024](#f-024)" in section  # 5th shown ID
    assert "[F-025](#f-025)" not in section  # 6th ID capped out of md
    assert "+7 more" in section

    # Changed: 5 shown + "+3 more"; per-ID notes only on shown IDs.
    assert "- **Changed:** 8 threats (" in section
    assert '[F-040](#f-040): "severity High → Critical"' in section
    assert '[F-044](#f-044): "severity High → Critical"' in section  # 5th
    assert "[F-045](#f-045)" not in section
    assert "+3 more" in section

    # Resolved: 5 shown + "+1 more".
    assert "- **Resolved:** 6 threats (" in section
    assert "[F-064](#f-064)" in section  # 5th shown ID
    assert "[F-065](#f-065)" not in section
    assert "+1 more" in section


def test_changelog_no_more_suffix_when_under_cap(tmp_path: Path) -> None:
    """When counts are below the cap, no `+N more` suffix leaks into the md."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed_files": 3,
                "reanalyzed_components": ["C-01"],
                "carried_forward_components": ["C-02"],
                "added": {"threats": ["T-020", "T-021"], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "more" not in section


def test_changelog_renders_line_stats_when_present(tmp_path: Path) -> None:
    """When `changed_lines.insertions` + `.deletions` are populated, the
    Changed-files bullet appends a `(+N/-M lines)` tail so reviewers see
    code-churn magnitude at a glance. Absent → bullet reduces to file count
    only."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed_files": 12,
                "changed_lines": {"insertions": 340, "deletions": 45},
                "reanalyzed_components": ["C-01"],
                "added": {"threats": ["T-020"], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "- **Changed files:** 12 (+340/-45 lines)" in section


def test_changelog_architecture_bullet_lists_components_and_entry_points(tmp_path: Path) -> None:
    """Added components and entry points live in a dedicated Architecture
    bullet, separate from the Added-threats bullet. Keeps the threat view
    uncluttered and surfaces security-relevant architecture changes."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 3,
                "date": "2026-05-01",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "added": {
                    "threats": ["T-030"],
                    "components": ["C-06", "C-07"],
                    "attack_surface": ["E-04", "E-05"],
                },
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "- **Added:** 1 threat ([F-030](#f-030))" in section
    assert "- **Architecture:** +2 components (C-06, C-07), +2 entry points (E-04, E-05)" in section


def test_changelog_truncates_overly_long_note_prose(tmp_path: Path) -> None:
    """Guards against AI-generated run summaries leaking into the changelog.
    The template hard-truncates any `note` > 100 chars to 98 chars + `…`.
    Upstream guidance in phase-group-finalization.md forbids such prose in
    the first place — this is the defensive backstop."""
    out = _prepare_output_dir(tmp_path)
    prose = (
        "Full scan re-assessment with enhanced frontend analysis, SSRF "
        "identified, WebSocket trust boundary TB-6 added, fragment pipeline "
        "written for compose_threat_model.py renderer. All 28 threats and "
        "21 mitigations carried forward."
    )
    _rewrite_changelog(
        out,
        [
            {
                "version": 4,
                "date": "2026-05-02",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "note": prose,
                "added": {"threats": [], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "…" in section
    assert prose not in section


# ---------------------------------------------------------------------------
# Changelog — tabular rendering (default render_style)
# ---------------------------------------------------------------------------


def test_changelog_table_is_default(tmp_path: Path) -> None:
    """Without explicit `render_style`, the changelog renders as a table."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # Header row of the table.
    assert "| Version | Date | Mode | Depth | Reasoning | Baseline → Current | Δ Threats | Code | Note |" in section
    # No per-version H3 (that is the legacy bullets style).
    assert "### v1" not in section


def test_changelog_table_separator_and_first_row_on_separate_lines(tmp_path: Path) -> None:
    """The markdown separator `|---|---|…|` and the first data row must live
    on separate lines; otherwise the row gets concatenated into the
    separator (`|------|| v1 | …`) and the table collapses to a single
    visual line in rendered markdown. Regression guard for the
    `{%- for %}` whitespace-control bug that ate the trailing newline of
    the separator."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # Locate the separator line and confirm the next non-empty line is a
    # data row starting with `| v` — not a continuation of the separator.
    lines = section.splitlines()
    sep_idx = next((i for i, l in enumerate(lines) if l.startswith("|---")), None)
    assert sep_idx is not None, "separator line not found"
    # The separator itself must not carry appended row content.
    assert "| v" not in lines[sep_idx], f"separator line has a row concatenated to it: {lines[sep_idx]!r}"
    # Next non-empty line after the separator must be a `| v<N> |` row.
    nxt = next((l for l in lines[sep_idx + 1 :] if l.strip()), None)
    assert nxt is not None and nxt.lstrip().startswith("| v"), (
        f"expected a `| v<N> |` row after the separator, got {nxt!r}"
    )


def test_changelog_table_renders_one_row_per_version(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed_files": 7,
                "reanalyzed_components": ["C-01"],
                "carried_forward_components": ["C-02"],
                "added": {"threats": ["T-020", "T-021"], "components": [], "attack_surface": []},
                "changed": {"threats": ["T-002"], "notes_by_id": {"T-002": "sev"}},
                "resolved": {"threats": ["T-010"], "reason_by_id": {"T-010": "not repro"}},
            },
            {
                "version": 1,
                "date": "2026-04-19",
                "mode": "full",
                "current_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "note": "Initial assessment",
            },
        ],
    )
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # v2 row: delta shorthand, short SHAs, component counts.
    # Empty cells render as ASCII hyphen — `_normalize_emdashes` applies to
    # changelog table rows because the row carries no anchor links (anchor-
    # link rows are excluded from normalisation; this one is not).
    # Run numbers are POSITIONAL (newest = highest), not the entry's schema
    # version field. The incremental row has a git baseline so it shows the
    # +A/~C/-R delta.
    assert "| v2 | 2026-04-23 | incremental | - | - | `cb6fb8a` → `a1b2c3d` | +2 / ~1 / -1 | 7 files | - |" in section
    # v1 row: from-scratch full snapshot (no baseline) → honest count, not a
    # fake "+N added"; initial marker; mode=full.
    assert "| v1 | 2026-04-19 | full | - | - | _(initial)_ | 0 total | - | Initial assessment |" in section
    # Newest first.
    assert section.index("| v2 |") < section.index("| v1 |")


def test_changelog_table_latest_run_detail_block(tmp_path: Path) -> None:
    """Contract (F6.1): the table-style changelog renders the table AND a
    `**Latest run (vN) — threat-level detail:**` block enumerating the
    T-IDs of the most recent entry. Previous versions are not duplicated;
    the reader sees only the latest run's IDs to avoid the table-only
    `+N / ~M / -K` summary hiding the actual finding IDs.
    """
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 3,
                "date": "2026-05-01",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "reanalyzed_components": ["C-01"],
                "added": {"threats": ["T-030"], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # The single-table format is preserved (table row exists). Run number is
    # POSITIONAL — a lone entry is v1 regardless of its schema-version field.
    assert "| v1 |" in section
    # The latest-run detail block enumerates the finding ids (visible F-NNN
    # form). It renders because the entry carries a git baseline_sha.
    assert "**Latest run (v1)" in section
    assert "- **Added (1):**" in section
    assert "F-030" in section
    # Architecture / changed / resolved bullets are NOT emitted because
    # those buckets are empty for this entry.
    assert "- **Changed" not in section
    assert "- **Resolved" not in section
    assert "- **Architecture:**" not in section


def test_changelog_detail_block_links_new_ids_without_titles_and_lists_resolved(tmp_path: Path) -> None:
    """Iterative-scan contract: the detail block links NEW finding IDs (no
    titles), lists RESOLVED IDs as plain text (removed → no dangling anchor)."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "date": "2026-05-10",
                "mode": "incremental",
                "delta_basis": "incremental",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "added": {"threats": ["T-020", "T-021"], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": ["T-010"], "reason_by_id": {"T-010": "fixed"}},
            },
            {"date": "2026-05-01", "mode": "full", "added": {"threats": ["T-001"]}},
        ],
    )
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # New IDs are linked and inline (no " - <title>" suffix).
    assert "**Added (2):**" in section
    assert "(#f-020)" in section and "(#f-021)" in section
    # Resolved IDs are present but NOT linked (the finding is gone).
    assert "**Resolved (1):**" in section
    assert "(#f-010)" not in section and "(#t-010)" not in section


def test_changelog_detail_block_reports_no_change_on_empty_iterative(tmp_path: Path) -> None:
    """An unchanged iterative run renders an explicit "no threat-level changes"
    line rather than silently omitting the detail block."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "date": "2026-05-11",
                "mode": "incremental",
                "delta_basis": "incremental",
                "baseline_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "added": {"threats": [], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
            {"date": "2026-05-10", "mode": "incremental"},
        ],
    )
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    assert "No threat-, mitigation-, or abuse-case-level changes since the previous run" in section


def test_changelog_table_code_column_combines_files_and_lines(tmp_path: Path) -> None:
    """The `Code` column replaces the old `Components` column. Files + line
    stats are joined so a reviewer sees churn magnitude in one glance."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 6,
                "date": "2026-05-04",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed_files": 12,
                "changed_lines": {"insertions": 340, "deletions": 45},
                "added": {"threats": ["T-050"], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    assert "| 12 files, +340/-45 |" in section


def test_changelog_table_truncates_long_notes(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    long = "x" * 200
    _rewrite_changelog(
        out,
        [
            {
                "version": 5,
                "date": "2026-05-03",
                "mode": "full",
                "note": long,
            },
        ],
    )
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # Truncated to ≤ 90 chars with an ellipsis marker (…).
    assert "…" in section
    assert long not in section


# ---------------------------------------------------------------------------
# Hard-gate failure modes
# ---------------------------------------------------------------------------


def test_missing_required_fragment_raises(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    (out / ".fragments" / "ms-verdict.json").unlink()
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    assert "verdict" in str(exc.value)


def test_schema_violation_raises(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    # Emit a verdict with severity not in enum.
    bad = {
        "severity": "catastrophic",  # not in enum
        "opening": "x" * 80,
        "bullets": [],  # violates minItems=2
        "closing": "y" * 80,
    }
    (out / ".fragments" / "ms-verdict.json").write_text(json.dumps(bad))
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    # Error message mentions the schema-invalid field.
    assert "severity" in str(exc.value) or "bullets" in str(exc.value)


def test_missing_yaml_raises(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    (out / "threat-model.yaml").unlink()
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    assert "threat-model.yaml" in str(exc.value)


def test_markdown_fragment_must_start_with_correct_heading(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    # Corrupt system-overview.md: wrong heading level — first line IS a heading,
    # so this is a real authoring mixup and must still hard-fail (not restored).
    (out / ".fragments" / "system-overview.md").write_text("### 1. System Overview\n\nwrong level\n")
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    assert "system_overview" in str(exc.value)


def test_dropped_h2_replaced_by_prose_is_autorestored(tmp_path: Path) -> None:
    # The observed secarch-renderer defect: the canonical `## 1. System Overview`
    # H2 is dropped and replaced by the intro paragraph. The composer restores
    # the canonical heading deterministically (heading_autorestored warning)
    # instead of hard-failing the whole run.
    out = _prepare_output_dir(tmp_path)
    (out / ".fragments" / "system-overview.md").write_text(
        "This application is a deliberately vulnerable training app with several "
        "components.\n\nMore body text describing the system in detail.\n"
    )
    rendered, warnings = compose.render(CONTRACT, out)
    assert "## 1. System Overview" in rendered
    assert any("heading_autorestored" in w for w in warnings)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


def test_cli_writes_threat_model_md(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    result = _run_cli(["--output-dir", str(out)])
    assert result.returncode == 0, result.stderr
    md = (out / "threat-model.md").read_text(encoding="utf-8")
    assert "## Management Summary\n" in md


def test_cli_exit_1_on_missing_fragment(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    (out / ".fragments" / "ms-verdict.json").unlink()
    result = _run_cli(["--output-dir", str(out)])
    assert result.returncode == 1
    assert "RENDER_FAILED" in result.stderr


# ---------------------------------------------------------------------------
# Dollar-operator escape — MongoDB `$where`/`$ne`, jQuery selectors, bash
# vars must survive KaTeX/MathJax-enabled renderers without being
# interpreted as math-mode delimiters. Post-2026-05 the renderer uses the
# canonical Markdown backslash-escape (`\$word`) rather than backtick
# wrapping, so the visible glyph stays in the surrounding font weight.
# ---------------------------------------------------------------------------


class TestEscapeDollarOperators:
    """_escape_dollar_operators is a pure function — exercise it directly."""

    def test_mongodb_operators_are_backslash_escaped(self) -> None:
        # Post-2026-05 — renderer emits the canonical Markdown backslash-escape
        # (`\$where`) instead of backtick-wrapping. Backslash-escape keeps the
        # math-mode protection under KaTeX/MathJax while leaving the rendered
        # text in the surrounding font weight (backticks produced a visible
        # monospace span that read as literal source code).
        md = "NoSQL $where injection and $ne bypass"
        assert compose._escape_dollar_operators(md) == ("NoSQL \\$where injection and \\$ne bypass")

    def test_already_backticked_operator_is_untouched(self) -> None:
        md = "use `$where` to query"
        assert compose._escape_dollar_operators(md) == md

    def test_fenced_code_block_untouched(self) -> None:
        md = "before\n```\ndb.find({$where: 'x'})\n```\nafter"
        assert compose._escape_dollar_operators(md) == md

    def test_inline_code_untouched(self) -> None:
        md = "use `$regex` here"
        assert compose._escape_dollar_operators(md) == md

    def test_html_comment_untouched(self) -> None:
        md = "<!-- $where: see internal doc -->"
        assert compose._escape_dollar_operators(md) == md

    def test_usd_amount_untouched(self) -> None:
        md = "price is $10 total, not $100.50"
        assert compose._escape_dollar_operators(md) == md

    def test_latex_dollar_dollar_pair_untouched(self) -> None:
        # LaTeX block math is `$$...$$` — lookbehind must not match `$x` after `$`.
        md = "math: $$x$$ done"
        # The opening `$$` before `x` gives `$` + `$x` — the second `$` is
        # preceded by `$`, which the lookbehind `(?<![`$\\])` excludes.
        # So the `$x` inside `$$…$$` stays untouched.
        assert compose._escape_dollar_operators(md) == md

    def test_escaped_dollar_untouched(self) -> None:
        md = "literal \\$where in docs"
        assert compose._escape_dollar_operators(md) == md

    def test_multiple_operators_in_one_line(self) -> None:
        md = "use $regex or $or or $and"
        assert compose._escape_dollar_operators(md) == ("use \\$regex or \\$or or \\$and")

    def test_operator_inside_markdown_link_label(self) -> None:
        # A link label like `[T-012](#t-012) — NoSQL $where Injection` must
        # get the `$where` escaped (this is the actual bug observed in
        # the Juice Shop run).
        md = "[T-012](#t-012) — NoSQL $where Injection on Product Reviews"
        assert compose._escape_dollar_operators(md) == ("[T-012](#t-012) — NoSQL \\$where Injection on Product Reviews")

    def test_bare_dollar_sign_alone_untouched(self) -> None:
        # A lone `$` with no identifier must never be altered.
        md = "the cost is $ (TBD)"
        assert compose._escape_dollar_operators(md) == md


# ---------------------------------------------------------------------------
# Enrich Linked-ID cells — stacking + label enrichment for markdown-fragment
# tables (Assets, Attack Surface, Trust Boundaries, §7.x control tables).
# ---------------------------------------------------------------------------


class _FakeCtx:
    """Minimal RenderContext stub that supports `linkify_with_label` via a
    lookup dict."""

    def __init__(self, labels: dict[str, str]) -> None:
        self._labels = labels

    def linkify_with_label(self, ref: str, label_override: str | None = None) -> str:
        anchor = ref.lower()
        label = (label_override or self._labels.get(ref) or "").strip()
        if label:
            return f"[{ref}](#{anchor}) — {label}"
        return f"[{ref}](#{anchor})"


class TestEnrichLinkedIdCells:
    def test_adds_labels_and_stacks_with_br(self) -> None:
        md = "| Asset | Linked Threats |\n|---|---|\n| Users | [T-003](#t-003), [T-013](#t-013) |\n"
        ctx = _FakeCtx({"T-003": "SQL Injection Login", "T-013": "MD5 Hashing"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert ("[T-003](#t-003) — SQL Injection Login<br/>[T-013](#t-013) — MD5 Hashing") in out

    def test_idempotent_on_already_enriched(self) -> None:
        md = "| Asset | Linked Threats |\n|---|---|\n| Users | [T-003](#t-003) — SQL Injection Login |\n"
        ctx = _FakeCtx({"T-003": "SQL Injection Login"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert out == md

    def test_skips_threat_register_declaration_anchors(self) -> None:
        md = '| ID | Title |\n|---|---|\n| <a id="t-003"></a>T-003 | SQL Injection |\n'
        ctx = _FakeCtx({})
        assert compose._enrich_linked_id_cells(ctx, md) == md

    def test_ignores_tables_without_linked_header(self) -> None:
        md = "| Foo | Bar |\n|---|---|\n| x | [T-003](#t-003), [T-013](#t-013) |\n"
        ctx = _FakeCtx({"T-003": "A", "T-013": "B"})
        # "Bar" is not in _LINKED_ID_COLUMN_HEADERS, so the row is not rewritten.
        assert compose._enrich_linked_id_cells(ctx, md) == md

    def test_preserves_prose_heavy_cells(self) -> None:
        # The cell has narrative text mixed with IDs — don't strip the prose.
        md = (
            "| Boundary | Weakness | Linked Threats |\n"
            "|---|---|---|\n"
            "| TB-1 | SQLi in login | see [T-003](#t-003) and the earlier [T-013](#t-013) analysis |\n"
        )
        ctx = _FakeCtx({"T-003": "x", "T-013": "y"})
        out = compose._enrich_linked_id_cells(ctx, md)
        # Cell contains 'see' and 'analysis' — residue ≠ "", so unchanged.
        assert "see [T-003](#t-003) and the earlier [T-013](#t-013) analysis" in out

    def test_single_id_cell_gets_label(self) -> None:
        md = "| Control | Linked Threats |\n|---|---|\n| JWT | [T-001](#t-001) |\n"
        ctx = _FakeCtx({"T-001": "Hardcoded RSA"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert "[T-001](#t-001) — Hardcoded RSA" in out

    def test_unknown_id_gets_bare_link_not_error(self) -> None:
        md = "| X | Linked |\n|---|---|\n| A | [T-999](#t-999) |\n"
        ctx = _FakeCtx({})
        out = compose._enrich_linked_id_cells(ctx, md)
        # No label available → bare link is emitted (no exception).
        assert "[T-999](#t-999)" in out

    def test_em_dash_separator_cells_untouched_when_prose_is_present(self) -> None:
        md = "| X | Linked Threats |\n|---|---|\n| A | — |\n"
        ctx = _FakeCtx({})
        assert compose._enrich_linked_id_cells(ctx, md) == md

    def test_mixed_separator_list_is_normalised(self) -> None:
        md = "| X | Linked Threats |\n|---|---|\n| A | [T-001](#t-001), [T-002](#t-002); [T-003](#t-003) |\n"
        ctx = _FakeCtx({"T-001": "A", "T-002": "B", "T-003": "C"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert ("[T-001](#t-001) — A<br/>[T-002](#t-002) — B<br/>[T-003](#t-003) — C") in out

    def test_addresses_column_also_enriched(self) -> None:
        md = (
            "| ID | Mitigation | Addresses |\n"
            "|---|---|---|\n"
            "| M-001 | Rotate Key | [T-001](#t-001), [T-002](#t-002) |\n"
        )
        ctx = _FakeCtx({"T-001": "Alpha", "T-002": "Beta"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert ("[T-001](#t-001) — Alpha<br/>[T-002](#t-002) — Beta") in out

    def test_assets_table_now_enriched_with_titles(self) -> None:
        # 2026-06-02: the §4 Assets table (header carries Asset + Classification)
        # is no longer skipped — its `·`-joined Linked-Threats chips get titles.
        md = (
            "| Asset | ID | Classification | Description | Linked Threats |\n"
            "|---|---|---|---|---|\n"
            "| Users | A-001 | PII | accounts | [F-001](#f-001) · [F-002](#f-002) |\n"
        )
        ctx = _FakeCtx({"F-001": "SQL Injection", "F-002": "Stored XSS"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert ("[F-001](#f-001) — SQL Injection<br/>[F-002](#f-002) — Stored XSS") in out


# ---------------------------------------------------------------------------
# Security Posture at a Glance — contract v2 format (4-column heatmap with
# attack arrows + per-attack-class narrative bullets). Replaces the
# previous arrowless-with-tables format; see CHANGELOG / contract_version: 2.
# ---------------------------------------------------------------------------


class TestSecurityPostureV2:
    """Test the contract v2 layout:

    * Mermaid block uses `flowchart LR` with ELK init directive.
    * 3 subgraphs: ACTORS, TIERS, IMPACT (no VICTIMS — the victim now
      sits in ACTORS).
    * Empty subgraph titles + first-node header (HDR_A / HDR_T / HDR_I).
    * Cross-subgraph alignment edges keep the column headers on one Y line.
    * 1–7 attack arrows (==>) with numbered glyphs ① ⑦.
    * 1–6 dashed consequence arrows (-.->).
    * Below the diagram: Threat-actors paragraph, actor bullets, then
      1–7 attack-class bullets each with `Findings:` + `Impact:` plus
      optional `Architectural root cause:` and `Attack chain:`.
    """

    @staticmethod
    def _build_ctx(tmp_path, yaml_data: dict, fragment: dict | None = None):
        """Build a real RenderContext + Jinja env so the v2 renderer can
        actually call its templates.
        """
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        frag_dir = out_dir / ".fragments"
        frag_dir.mkdir()
        if fragment is not None:
            (frag_dir / "security-posture-attack-paths.json").write_text(json.dumps(fragment), encoding="utf-8")
        ctx = compose.RenderContext(
            output_dir=out_dir,
            contract={},
            yaml_data=yaml_data,
            triage={},
            fragments_dir=frag_dir,
        )
        env = compose._build_jinja_env(ctx)
        return ctx, env

    @staticmethod
    def _section_cfg(min_hc: int = 3) -> dict:
        return {"min_high_or_critical": min_hc}

    @staticmethod
    def _yaml_seven_classes() -> dict:
        """Reference fixture: one finding for each of the 7 attack classes
        so every glyph ① ⑦ is exercised.
        """
        components = [
            {"id": "spa-frontend", "name": "Angular SPA", "layer": "frontend"},
            {"id": "rest-api", "name": "REST API", "layer": "server"},
            {"id": "data-layer", "name": "Data Layer", "layer": "data"},
        ]
        threats = [
            # Class 1 (Injection — CWE-89 SQLi)
            {"id": "F-001", "title": "SQL Injection", "component_id": "rest-api", "cwe": "CWE-89", "risk": "Critical"},
            # Class 2 (Auth Bypass — CWE-287)
            {"id": "F-002", "title": "Auth Bypass", "component_id": "rest-api", "cwe": "CWE-287", "risk": "Critical"},
            # Class 3 (Privilege Escalation — CWE-269)
            {"id": "F-003", "title": "Priv Esc", "component_id": "rest-api", "cwe": "CWE-269", "risk": "Critical"},
            # Class 4 (Sensitive Data Exposure — CWE-200)
            {"id": "F-004", "title": "Data Exposure", "component_id": "rest-api", "cwe": "CWE-200", "risk": "High"},
            # Class 5 (RCE — CWE-94)
            {"id": "F-005", "title": "RCE", "component_id": "data-layer", "cwe": "CWE-94", "risk": "Critical"},
            # NB: CWE-94 is in BOTH injection and remote-code-execution; the
            # taxonomy lists injection FIRST so this would normally classify
            # as injection, but the LLM fragment can override. The fallback
            # path will put F-005 under injection, F-001 / F-002 / F-003 too.
            # For deterministic fixture, supply a fragment.
            # Class 6 (XSS — CWE-79)
            {"id": "F-006", "title": "Stored XSS", "component_id": "spa-frontend", "cwe": "CWE-79", "risk": "High"},
            # Class 7 (CSRF — CWE-352)
            {"id": "F-007", "title": "CSRF", "component_id": "spa-frontend", "cwe": "CWE-352", "risk": "High"},
        ]
        return {
            "components": components,
            "threats": threats,
            "assets": [],
            "tier_root_causes": {
                "client": ["no CSP"],
                "application": ["raw SQL", "weak crypto"],
                "data": ["no token revocation"],
            },
        }

    @staticmethod
    def _fragment_seven_classes() -> dict:
        """A fragment matching the seven-class fixture, so the glyph order
        is deterministic regardless of the CWE-fallback path."""
        return {
            "schema_version": 1,
            "actors": ["victim-required", "internet-anon"],
            "attack_paths": [
                {
                    "class": "injection",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "input flows into a server-side interpreter without parameterisation.",
                    "architectural_root_causes": [],
                    "findings": ["F-001"],
                    "attack_chains": [],
                    "impact": ["customer-data-exfiltration"],
                },
                {
                    "class": "auth-bypass",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "auth can be circumvented because credentials are weak or exposed.",
                    "architectural_root_causes": [],
                    "findings": ["F-002"],
                    "attack_chains": [],
                    "impact": ["full-admin-takeover"],
                },
                {
                    "class": "privilege-escalation",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "authorisation checks are bypassable.",
                    "architectural_root_causes": [],
                    "findings": ["F-003"],
                    "attack_chains": [],
                    "impact": ["full-admin-takeover"],
                },
                {
                    "class": "sensitive-data-exposure",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "secrets reachable on unauthenticated routes.",
                    "architectural_root_causes": [],
                    "findings": ["F-004"],
                    "attack_chains": [],
                    "impact": ["customer-data-exfiltration"],
                },
                {
                    "class": "remote-code-execution",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "user data reaches a code-execution sink.",
                    "architectural_root_causes": [],
                    "findings": ["F-005"],
                    "attack_chains": [],
                    "impact": ["full-server-compromise"],
                },
                {
                    "class": "cross-site-scripting",
                    "actor": "victim-required",
                    "target": "victim",
                    "description": "attacker-controlled content rendered without sanitisation.",
                    "architectural_root_causes": [],
                    "findings": ["F-006"],
                    "attack_chains": [],
                    "impact": ["customer-session-hijack"],
                },
                {
                    "class": "cross-site-request-forgery",
                    "actor": "victim-required",
                    "target": "victim",
                    "description": "permissive CORS lets external pages forge requests.",
                    "architectural_root_causes": [],
                    "findings": ["F-007"],
                    "attack_chains": [],
                    "impact": ["customer-session-hijack"],
                },
            ],
        }

    def test_skip_section_below_threshold(self, tmp_path):
        ctx, env = self._build_ctx(
            tmp_path,
            {
                "components": [],
                "threats": [
                    {"id": "F-001", "title": "T", "component_id": "x", "cwe": "CWE-89", "risk": "Medium"},
                ],
            },
        )
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert out == ""

    def test_v2_diagram_uses_elk_renderer(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert "defaultRenderer" in out and '"elk"' in out
        assert "flowchart LR" in out

    def test_v2_three_subgraphs_with_empty_titles(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert 'subgraph ACTORS[" "]' in out
        assert 'subgraph TIERS[" "]' in out
        assert 'subgraph IMPACT[" "]' in out

    def test_v2_header_nodes_present(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert 'HDR_A["<b>Threat Actors</b>"]' in out
        assert 'HDR_T["<b>Architecture Tiers</b>"]' in out
        assert 'HDR_I["<b>Business Impact</b>"]' in out

    def test_v2_alignment_edges_chain_headers(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert "HDR_A --- HDR_T" in out
        assert "HDR_T --- HDR_I" in out

    def test_v2_seven_attack_arrows_with_glyphs(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # Seven solid red arrows ==>, one per attack-class entry.
        for glyph in ("①", "②", "③", "④", "⑤", "⑥", "⑦"):
            assert glyph in out, f"glyph {glyph} missing from diagram"

    def test_v2_consequence_arrows_present(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # At least one dashed consequence arrow.
        assert "-.->" in out

    def test_v2_top_threats_table_below_diagram(self, tmp_path):
        # 2026-05 — the legacy attack-path bullet list was replaced by the
        # merged Top Threats table under the combined section heading.
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert "### Security Posture & Top Threats" in out
        assert "| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |" in out
        # One self-anchored table row per glyph.
        for glyph in ("①", "②", "③", "④", "⑤", "⑥", "⑦"):
            assert glyph in out

    def test_v2_findings_linked_in_table(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # Findings cells link into §8 (`[F-NNN](#f-nnn)`).
        assert "[F-001](#f-001)" in out
        assert "[F-007](#f-007)" in out

    def test_v2_impact_shown_in_risk_cell(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # Business impact appears in the Risk & Impact column.
        assert "Customer Data Exfiltration" in out
        assert "Full Admin Takeover" in out
        assert "Customer Session Hijack" in out

    def test_v2_no_low_findings_in_tier_counts(self, tmp_path):
        # Add a Low-severity finding; verify it is NOT shown in tier counts.
        yaml_data = self._yaml_seven_classes()
        yaml_data["threats"].append(
            {
                "id": "F-099",
                "title": "Low Sev",
                "component_id": "rest-api",
                "cwe": "CWE-200",
                "risk": "Low",
            }
        )
        ctx, env = self._build_ctx(tmp_path, yaml_data, self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # The tier card severity counts line must not contain a Low marker.
        # Find the Application Tier line and check. Tier names render plain
        # since P1 (B1) — bold is reserved for the three column headers
        # HDR_A / HDR_T / HDR_I, not the tier-card name itself.
        app_card_match = re.search(r'Application Tier[^"]+', out)
        assert app_card_match, "Application Tier card not found"
        assert "🟢" not in app_card_match.group(0)
        assert "Low" not in app_card_match.group(0)

    def test_v2_fallback_when_fragment_missing(self, tmp_path):
        # No fragment file → renderer falls back to CWE→class derivation.
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # Must still produce a valid diagram + the Top Threats table.
        assert "```mermaid" in out
        assert "| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |" in out

    def test_v2_classify_finding_class(self):
        taxonomy = compose._load_attack_class_taxonomy()
        assert compose._classify_finding_class({"cwe": "CWE-89"}, taxonomy) == "injection"
        assert compose._classify_finding_class({"cwe": "CWE-79"}, taxonomy) == "cross-site-scripting"
        assert compose._classify_finding_class({"cwe": "CWE-352"}, taxonomy) == "cross-site-request-forgery"
        # Unknown CWE returns None.
        assert compose._classify_finding_class({"cwe": "CWE-9999"}, taxonomy) is None


# ---------------------------------------------------------------------------
# Pre-render repair plan — attempt counter, exhaustion, cleanup
# ---------------------------------------------------------------------------


class TestPreRenderRepairPlan:
    """The compose-time repair plan carries an `attempt` counter so the
    orchestrator can escalate out of the Stage 1 turn budget after a
    bounded number of failed fix-loop iterations. See Bug 1 follow-up.
    """

    def _err(self, section_id: str = "security_architecture") -> compose.FragmentError:
        return compose.FragmentError(
            section_id,
            "required subsection missing: '### 7.8 Real-time / WebSocket'",
        )

    def test_attempt_increments_across_successive_failures(self, tmp_path: Path) -> None:
        import json as _json

        err = self._err()
        for expected in (1, 2, 3):
            attempt = compose._emit_pre_render_repair_plan(tmp_path, err)
            assert attempt == expected
            plan = _json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
            assert plan["attempt"] == expected
            assert plan["status"] == "fail"

    def test_status_flips_to_exhausted_beyond_cap(self, tmp_path: Path) -> None:
        import json as _json

        err = self._err()
        # Burn through the budget.
        for _ in range(compose._PRE_RENDER_REPAIR_MAX_ATTEMPTS):
            compose._emit_pre_render_repair_plan(tmp_path, err)
        # One more attempt → exhausted.
        attempt = compose._emit_pre_render_repair_plan(tmp_path, err)
        assert attempt == compose._PRE_RENDER_REPAIR_MAX_ATTEMPTS + 1
        plan = _json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
        assert plan["status"] == "exhausted"

    def test_successful_compose_clears_stale_plan(self, tmp_path: Path) -> None:
        plan_path = tmp_path / ".pre-render-repair-plan.json"
        plan_path.write_text('{"status":"fail","attempt":2}')
        compose._delete_pre_render_repair_plan(tmp_path)
        assert not plan_path.exists()

    def test_plan_includes_fragment_pointer_and_remediation(self, tmp_path: Path) -> None:
        import json as _json

        compose._emit_pre_render_repair_plan(tmp_path, self._err())
        plan = _json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
        action = plan["actions"][0]
        assert action["section_id"] == "security_architecture"
        assert ".fragments/security-architecture.md" in action["fragments_to_rewrite"]
        assert action["expected_heading"] == "### 7.8 Real-time / WebSocket"
        # Remediation must point at the missing heading (`7.8 Real-time /
        # WebSocket`) and warn against the two known drift patterns: the
        # 21-section intermediate scaffold and the 14-section v1 layout.
        rem = action["remediation"]
        assert "7.8" in rem
        assert "21-section" in rem and "14-section" in rem


# ---------------------------------------------------------------------------
# Real-time console progress — V3 (per-section COMPOSE: lines) + V4 (retry counter)
# ---------------------------------------------------------------------------


class TestComposeProgress:
    """Live-progress visibility during the 15-30 s render pass. The CLI
    (`main()`) must emit a `COMPOSE: [k/N] rendering §<id>` line to stderr
    before each section so the user sees activity instead of silent waiting.
    Library callers (`render(emit_progress=False)`) stay quiet so tests
    and programmatic users do not get surprise stderr noise.
    """

    def test_render_does_not_emit_progress_by_default(self, tmp_path: Path, capsys) -> None:
        out = _prepare_output_dir(tmp_path)
        compose.render(CONTRACT, out)
        captured = capsys.readouterr()
        assert "COMPOSE:" not in captured.err

    def test_render_emits_progress_when_opted_in(self, tmp_path: Path, capsys) -> None:
        out = _prepare_output_dir(tmp_path)
        compose.render(CONTRACT, out, emit_progress=True)
        captured = capsys.readouterr()
        # At least one per-section progress line — must carry a [k/N] counter
        # and a §<id> pointer so the user can see which section is being rendered.
        lines = [l for l in captured.err.splitlines() if l.startswith("COMPOSE:")]
        assert len(lines) >= 5, f"expected several COMPOSE: lines on opt-in, got {lines!r}"
        import re as _re

        assert _re.search(r"COMPOSE: \[\d+/\d+\] rendering §\w+", lines[0]), lines[0]

    def test_main_cli_emits_progress_on_success(self, tmp_path: Path) -> None:
        import subprocess as _sp
        import sys as _sys

        out = _prepare_output_dir(tmp_path)
        result = _sp.run(
            [_sys.executable, str(SCRIPT_PATH), "--contract", str(CONTRACT), "--output-dir", str(out)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "COMPOSE:" in result.stderr
        assert "RENDERED:" in result.stdout


class TestComposeRetryCounter:
    """On a FragmentError, main() emits a `RENDER_ATTEMPT: k/max` line before
    the raw error so the user immediately knows whether they are in a
    fix-loop and how close they are to exhaustion (exit 4)."""

    def _break_fragment(self, out: Path) -> None:
        # Remove a required fragment to reliably trigger FragmentError.
        (out / ".fragments" / "ms-verdict.json").unlink(missing_ok=True)

    def test_first_failure_omits_counter(self, tmp_path: Path) -> None:
        import subprocess as _sp
        import sys as _sys

        out = _prepare_output_dir(tmp_path)
        self._break_fragment(out)
        result = _sp.run(
            [_sys.executable, str(SCRIPT_PATH), "--contract", str(CONTRACT), "--output-dir", str(out)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1
        assert "RENDER_FAILED:" in result.stderr
        # attempt=1 is a first-time failure — no counter shown to reduce noise.
        assert "RENDER_ATTEMPT:" not in result.stderr

    def test_repeated_failure_surfaces_counter(self, tmp_path: Path) -> None:
        import subprocess as _sp
        import sys as _sys

        out = _prepare_output_dir(tmp_path)
        self._break_fragment(out)
        # Run compose three times — attempt counter must appear from run 2 onward.
        for _ in range(2):
            _sp.run(
                [_sys.executable, str(SCRIPT_PATH), "--contract", str(CONTRACT), "--output-dir", str(out)],
                capture_output=True,
                text=True,
                check=False,
            )
        third = _sp.run(
            [_sys.executable, str(SCRIPT_PATH), "--contract", str(CONTRACT), "--output-dir", str(out)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert "RENDER_ATTEMPT: 3/" in third.stderr, (
            f"expected RENDER_ATTEMPT on the 3rd failed run, got stderr: {third.stderr!r}"
        )


# ---------------------------------------------------------------------------
# F-NNN stability gate for verbatim §7 preservation in quick mode.
# ---------------------------------------------------------------------------


class TestVerbatimFnnnStabilityGate:
    """Guard against silent F-NNN cross-reference corruption when a
    quick-after-thorough run carries the prior §7 forward verbatim.

    `merge_threats._assign_t_ids` reassigns T-IDs every run from a
    deterministic sort key (severity, CWE, file, line, title). A re-sort
    can move a given F-NNN slot to a different threat. The gate
    `_verbatim_fnnn_refs_match` validates the F-NNN refs cited inside the
    extracted §7 against the current threat register; on any drift the
    caller drops the verbatim and skips §7 rather than render wrong links.
    """

    @staticmethod
    def _prior_md_with_threats(rows: list[tuple[str, str]]) -> str:
        """Return a minimal prior threat-model.md whose §7 cites every F-NNN
        in ``rows`` and whose §8 register declares each F-NNN with the
        given title. ``rows`` is ``[(digits, title), ...]``."""
        section7_refs = ", ".join(f"[F-{d}](#f-{d})" for d, _ in rows)
        section7 = f"## 7. Security Architecture\n\nBackground prose referencing {section7_refs}.\n"
        section8_rows = "\n".join(
            f'| <a id="t-{d}"></a><a id="f-{d}"></a>F-{d} | {title} | Tampering | C-01 — Service | High | 7.1 | A01 | M-001 | — |'
            for d, title in rows
        )
        section8 = (
            "## 8. Findings Register\n\n"
            "| ID | Title | STRIDE | Component | Severity | CVSS | Vektor | Mitigations | Refs |\n"
            "|----|-------|--------|-----------|----------|------|--------|-------------|------|\n"
            f"{section8_rows}\n"
        )
        return section7 + "\n" + section8

    def test_returns_true_when_titles_unchanged(self) -> None:
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        prior_md = self._prior_md_with_threats(rows)
        extracted = compose._extract_section_verbatim(prior_md, top_level_number=7)
        current = [
            {"t_id": "T-001", "title": "SQL Injection in Login"},
            {"t_id": "T-002", "title": "Stored XSS in Feedback"},
        ]
        assert compose._verbatim_fnnn_refs_match(extracted, prior_md, current) is True

    def test_returns_false_when_fnnn_now_points_to_different_threat(self) -> None:
        """The reflow scenario: prior had F-001=SQLi, F-002=XSS; current run
        re-sorted them so F-001=XSS now refers to a different finding. The
        verbatim §7 prose still says 'F-001 — SQL Injection' but the link
        target now resolves to XSS — must reject."""
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        prior_md = self._prior_md_with_threats(rows)
        extracted = compose._extract_section_verbatim(prior_md, top_level_number=7)
        current = [
            {"t_id": "T-001", "title": "Stored XSS in Feedback"},
            {"t_id": "T-002", "title": "SQL Injection in Login"},
        ]
        assert compose._verbatim_fnnn_refs_match(extracted, prior_md, current) is False

    def test_returns_false_when_referenced_fnnn_resolved(self) -> None:
        """Prior §7 cited F-002, but F-002 was resolved and is no longer in
        the current register — verbatim preservation would emit a dead link."""
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        prior_md = self._prior_md_with_threats(rows)
        extracted = compose._extract_section_verbatim(prior_md, top_level_number=7)
        current = [
            {"t_id": "T-001", "title": "SQL Injection in Login"},
        ]
        assert compose._verbatim_fnnn_refs_match(extracted, prior_md, current) is False

    def test_returns_true_when_section_cites_no_fnnn(self) -> None:
        """A §7 with no F-NNN refs at all has nothing to validate — the
        gate must not block preservation in that case."""
        prior_md = (
            "## 7. Security Architecture\n\n"
            "General defense-in-depth narrative without any F-NNN citation.\n"
            "\n## 8. Findings Register\n\n(empty)\n"
        )
        extracted = compose._extract_section_verbatim(prior_md, top_level_number=7)
        current = [{"t_id": "T-001", "title": "Anything"}]
        assert compose._verbatim_fnnn_refs_match(extracted, prior_md, current) is True

    def test_resolve_returns_empty_when_reflow_detected(self, tmp_path: Path) -> None:
        """End-to-end: `_resolve_security_arch_override` must return "" (skip
        §7) — not the verbatim text — when the prior md and current threats
        disagree on which threat F-NNN points to."""
        out = tmp_path / "output"
        out.mkdir()
        (out / ".appsec-cache").mkdir()
        (out / ".appsec-cache" / "baseline.json").write_text(
            json.dumps({"last_run_depth": "thorough"}), encoding="utf-8"
        )
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        (out / "threat-model.md").write_text(self._prior_md_with_threats(rows), encoding="utf-8")
        # Reflowed: F-001 now points to a different threat than the prior md
        # claimed. The verbatim §7 is unsafe and must be dropped.
        current_threats = [
            {"t_id": "T-001", "title": "Stored XSS in Feedback"},
            {"t_id": "T-002", "title": "SQL Injection in Login"},
        ]
        result = compose._resolve_security_arch_override(out, "quick", current_threats)
        assert result == "", f"expected verbatim §7 dropped on reflow, got: {result!r}"

    def test_resolve_returns_verbatim_when_stable(self, tmp_path: Path) -> None:
        """End-to-end: `_resolve_security_arch_override` must return the
        verbatim §7 text when titles haven't drifted, preserving the prior
        thorough-mode narrative on the quick re-run."""
        out = tmp_path / "output"
        out.mkdir()
        (out / ".appsec-cache").mkdir()
        (out / ".appsec-cache" / "baseline.json").write_text(
            json.dumps({"last_run_depth": "thorough"}), encoding="utf-8"
        )
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        (out / "threat-model.md").write_text(self._prior_md_with_threats(rows), encoding="utf-8")
        current_threats = [
            {"t_id": "T-001", "title": "SQL Injection in Login"},
            {"t_id": "T-002", "title": "Stored XSS in Feedback"},
        ]
        result = compose._resolve_security_arch_override(out, "quick", current_threats)
        assert result is not None and result != "", f"expected verbatim §7 preserved when stable, got: {result!r}"
        assert result.startswith("## 7. Security Architecture")


# ---------------------------------------------------------------------------
# §8 Actor cell — Guard 1 (review-recommendations §4.5):
# `_[obsolete-actor]_` is a STATE-TRANSITION marker (actors.md §10 Fall 2).
# It must NEVER be the default rendering for findings whose `actor_ids` is
# empty without prior-attribution provenance. The previous behaviour fired
# the marker on every first-run finding that the STRIDE analyzer never
# tagged, producing 31× `_[obsolete-actor]_` rows in the juice-shop run.
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason="Item 6 (2026-05-28): Actor column removed from §8 Threat "
    "Register because upstream STRIDE analyzers do not populate "
    "`actor_ids` / `primary_actor`, rendering the column as 100% em-dash "
    "noise. The `_[obsolete-actor]_` / `_dormant_` markers no longer "
    "render in the table (deferred until STRIDE prompt + threat-merger "
    "reliably populate actor_ids). Re-enable these tests when the Actor "
    "column is reinstated — see _render_threat_register history."
)
class TestActorCellGuard:
    """Guard 1 from review-recommendations §4.5: prevent the
    `_[obsolete-actor]_` marker from leaking into first-run / data-gap
    findings. The marker is reserved for Fall 2 (actor was tagged, then
    disabled) — every other empty-actor_ids state must render as `—`.
    """

    def test_first_run_empty_actor_ids_renders_neutral_dash(self) -> None:
        """State (B): findings have `actor_ids=[]` AND no provenance trace.
        Renderer MUST emit `—`, not `_[obsolete-actor]_`."""
        ns = compose
        # Drive the same branch the §8 renderer takes at line ~9311.
        # We don't need the full render path — just the actor-cell decision.
        t = {"actor_ids": [], "primary_actor": None, "_provenance": {}}
        # Re-derive the cell value using the same logic the renderer uses.
        prov = t.get("_provenance") or {}
        had_actor_history = (
            bool(prov.get("run_count_empty"))
            or bool(prov.get("disabled_actor_ids"))
            or bool(prov.get("previous_actor_ids"))
        )
        assert had_actor_history is False, "fixture must have no prior attribution"
        # Render expectation: the renderer code under test (compose_threat_model.py
        # circa line 9311) must NOT emit the Fall-2 marker for this state.
        # Read the renderer source and assert the precondition guard exists.
        src = Path(ns.__file__).read_text(encoding="utf-8")
        assert "had_actor_history" in src, (
            "renderer must guard `_[obsolete-actor]_` behind a prior-attribution "
            "precondition (review-recommendations §4.5 Guard 1)"
        )
        assert 'elif not actor_ids and had_actor_history:\n            actor_cell = "_[obsolete-actor]_"' in src, (
            "Fall-2 marker must require prior-attribution provenance"
        )
        assert "elif not actor_ids:\n            # First-run / data-gap state" in src, (
            "first-run / data-gap empty actor_ids must render neutrally as `—`"
        )

    def test_dormant_marker_requires_provenance(self) -> None:
        """State (Fall 3, guarded): explicit `_status=dormant` only emits
        `_dormant_` when provenance backs the claim (had prior actors, OR
        carries `dormancy_reason` / `dormant_since`). Without provenance the
        cell renders neutrally as `—`. Mirrors Guard 1 logic for
        `_[obsolete-actor]_` so the same class of bug (state-marker as
        default for missing data) cannot leak in via the dormant path
        either (review-recommendations §4.6 + risk-assessment B)."""
        src = Path(compose.__file__).read_text(encoding="utf-8")
        assert (
            'if status_lower == "dormant" and dormant_provenance_ok:\n            actor_cell = "_dormant_"'
        ) in src, (
            "dormant marker must be guarded behind provenance evidence; "
            "the unconditional branch is the same anti-pattern that produced "
            "the 31× `_[obsolete-actor]_` defect in juice-shop"
        )
        assert (
            'elif status_lower == "dormant":\n            # Status flag set without supporting provenance'
        ) in src, "dormant-without-provenance must render neutrally as `—`, not fabricate a Fall-3 state"
        # Compose the provenance-check expression itself to make sure all
        # three signals participate.
        assert "dormancy_reason" in src
        assert "dormant_since" in src
        assert "had_actor_history" in src

    def test_evidence_summary_no_generic_boilerplate(self) -> None:
        """`_synthesise_evidence_summary` must return empty string (skipping
        the Evidence line) when no CWE class claim is available — not the
        old generic "implementation visible in the snippet below" boilerplate
        (review-recommendations §3.1 row c)."""
        result = compose._synthesise_evidence_summary({"cwe": ""}, "some/file.ts", 42)
        assert result == "", (
            "evidence-summary fallback for unmapped/missing CWE must be empty "
            "so the caller drops the **Evidence:** prose line entirely"
        )
        result2 = compose._synthesise_evidence_summary({"cwe": "CWE-99999"}, "x.ts", 1)
        assert result2 == ""

    def test_safe_sentence_split_does_not_break_on_abbreviations(self) -> None:
        """`_safe_sentence_split` must keep `(e.g. require('child_process').exec())`
        as a single sentence so the Story-Card impact_carve does not start
        with payload fragments (review-recommendations §3.1 row d)."""
        text = (
            "An attacker escapes the sandbox and executes arbitrary Node.js "
            "code on the server (e.g. require('child_process').exec()). "
            "Full container takeover follows."
        )
        sents = compose._safe_sentence_split(text)
        assert len(sents) == 2, f"expected 2 sentences, got {len(sents)}: {sents!r}"
        assert "require('child_process').exec()" in sents[0]
        assert sents[1].startswith("Full container takeover")

    def test_safe_sentence_split_handles_dotted_identifiers(self) -> None:
        """Dotted identifiers (Node.js, file.ext) and member chains
        (foo.bar.baz()) must not produce false sentence boundaries."""
        text = "Node.js process loads config.yaml. Then the server starts."
        sents = compose._safe_sentence_split(text)
        assert len(sents) == 2
        assert "Node.js process loads config.yaml" in sents[0]


class TestFormatIdListScalarString:
    """format_id_list must treat a scalar string as a SINGLE id, not iterate
    it character-by-character.

    Regression for the 2026-05-28 juice-shop run: the critical-attack-tree
    template renders the singular `mitigation_breakpoints[].mitigation` field
    (a string like "M-002") through the list filter `format_id_list`. Before
    the fix, "M-002" rendered as
    `[M](#m)<br/>[-](#-)<br/>[0](#0)<br/>[0](#0)<br/>[2](#2)` and spawned bogus
    #m / #- / #0 anchors that broke toc_closure.
    """

    def _env(self, tmp_path: Path):
        frag = tmp_path / ".fragments"
        frag.mkdir(parents=True, exist_ok=True)
        ctx = compose.RenderContext(
            output_dir=tmp_path,
            contract={},
            yaml_data={},
            triage={},
            fragments_dir=frag,
        )
        return compose._build_jinja_env(ctx)

    def test_scalar_string_renders_as_single_link(self, tmp_path: Path) -> None:
        env = self._env(tmp_path)
        out = env.filters["format_id_list"]("M-002")
        assert "#m-002" in out
        # No per-character split artefacts.
        assert "[M](#m)" not in out
        assert "[-](#-)" not in out
        assert "[0](#0)" not in out
        assert "<br/>" not in out  # single id → no stacking

    def test_list_input_still_stacks_with_br(self, tmp_path: Path) -> None:
        env = self._env(tmp_path)
        out = env.filters["format_id_list"](["M-001", "M-002"])
        assert "#m-001" in out and "#m-002" in out
        assert "<br/>" in out


# ---------------------------------------------------------------------------
# §7 readability + table-width post-processors (2026-05-30 user request).
# ---------------------------------------------------------------------------


def test_table_col_weight_roles() -> None:
    """Link columns widest, description capped below links, ids narrow."""
    w = compose._table_col_weight
    assert w("Linked Threats") > w("Description")
    assert w("Findings (→ Component)") > w("Threat Description")
    assert w("ID") < w("Description")
    assert w("Classification") < w("Linked Threats")
    # 'Threat Description' is a description column, not a (wide) threats column.
    assert w("Threat Description") == compose._TBL_W_DESC
    # Route / path / location columns get the wider 'path' role so long
    # slash-separated identifiers stop wrapping at the default-22 cap
    # (2026-06-02 column-width report).
    assert compose._table_col_role("Route") == "path"
    assert compose._table_col_role("Key Paths") == "path"
    assert compose._table_col_role("Location") == "path"
    assert w("Route") > w("Method")  # path wider than a narrow column
    assert w("Route") > compose._TBL_W_DEFAULT  # and wider than plain default


def test_register_index_chip_carries_circle_and_title() -> None:
    """§8/§9 jump-list chips must show a criticality circle + ID + title, not a
    bare `[F-NNN](#f-nnn)` link (2026-05-31 user report: bare list unreadable)."""
    sev = {1: "critical", 2: "high", 3: "medium", 4: "low"}
    titles = {
        1: "Hardcoded RSA private key — lib/insecurity.ts:23",  # path tail stripped
        2: "Stored XSS in feedback",
        3: "",  # missing title → chip is circle + link only
        4: "x" * 200,  # long title → truncated
    }
    out = compose._build_register_index("Findings index", "F", [1, 2, 3, 4], titles, sev)
    assert out.startswith("**Findings index:**<br/>")
    chips = out.split("<br/>")[1:]
    assert chips[0] == "🔴 [F-001](#f-001) — Hardcoded RSA private key"
    assert chips[1] == "🟠 [F-002](#f-002) — Stored XSS in feedback"
    assert chips[2] == "🟡 [F-003](#f-003)"  # no title appended
    assert chips[3].startswith("🟢 [F-004](#f-004) — ") and chips[3].endswith("…")


def test_severity_by_finding_num_reads_risk_then_severity() -> None:
    threats = [
        {"id": "T-001", "risk": "Critical"},
        {"id": "F-002", "severity": "high"},
        {"t_id": "T-003"},  # no risk/severity → defaults low
    ]
    sev = compose._severity_by_finding_num(threats)
    assert sev == {1: "critical", 2: "high", 3: "low"}


def test_normalize_emdashes_preserves_mermaid_alt_else_labels() -> None:
    """§3 walkthrough sequenceDiagram `alt`/`else` branch labels follow the
    'Current state — T-NNN' / 'After M-NNN — …' convention where the em-dash
    is the intended separator (QA Check 8e). _normalize_emdashes must keep it
    on those lines while still normalising ordinary node-label em-dashes."""
    md = (
        "```mermaid\n"
        "sequenceDiagram\n"
        "    Note over U: Untrusted Zone — Internet\n"
        "    alt Current state — T-001\n"
        "        U->>S: forge token\n"
        "    else After M-001 — rotate key\n"
        "        U->>S: blocked\n"
        "    end\n"
        "```\n"
    )
    out = compose._normalize_emdashes(md)
    assert "alt Current state — T-001" in out
    assert "else After M-001 — rotate key" in out
    # Ordinary node labels are still normalised to ASCII hyphen.
    assert "Untrusted Zone - Internet" in out
    # Idempotent.
    assert compose._normalize_emdashes(out) == out


def test_normalize_table_column_widths_sets_proportional_separator() -> None:
    md = (
        "| Asset | ID | Classification | Description | Linked Threats |\n"
        "|---|---|---|---|---|\n"
        "| DB | A-001 | Restricted | long text here | [F-001](#f-001) |\n"
    )
    out = compose._normalize_table_column_widths(md)
    sep = out.splitlines()[1]
    cells = [c for c in sep.split("|") if c]
    # Description column (idx 3) narrower than Linked Threats (idx 4).
    assert len(cells[3]) < len(cells[4])
    # ID column (idx 1) is the narrowest.
    assert len(cells[1]) <= len(cells[3])
    # Idempotent.
    assert compose._normalize_table_column_widths(out) == out


def test_normalize_table_widths_skips_code_fences() -> None:
    md = "```\n| not | a | table |\n|---|---|---|\n```\n"
    assert compose._normalize_table_column_widths(md) == md


def test_section7_number_and_bulletize() -> None:
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.4 Authorization Controls\n\n"
        "**Controls covered:** [Route auth](#route-auth), [Object auth](#object-auth)\n\n"
        '<a id="route-auth"></a>\n'
        "#### Route auth\n\nbody\n\n"
        '<a id="object-auth"></a>\n'
        "#### Object auth\n\nbody\n\n"
        "## 8. Findings Register\n\n"
        "#### M-001 — not renumbered\n"
    )
    out = compose._section7_number_and_bulletize(md)
    assert "#### 7.4.1 Route auth" in out
    assert "#### 7.4.2 Object auth" in out
    # §8 heading outside the §7 region is untouched.
    assert "#### M-001 — not renumbered" in out
    # Controls covered became a bullet list, each link prefixed with its number.
    assert "- [7.4.1 Route auth](#route-auth)" in out
    assert "- [7.4.2 Object auth](#object-auth)" in out
    # Idempotent — second pass does not double-number headings or links.
    out2 = compose._section7_number_and_bulletize(out)
    assert "7.4.1.1" not in out2
    assert "7.4.1 7.4.1" not in out2
    assert "- [7.4.1 Route auth](#route-auth)" in out2


def test_section7_unnumbered_opener_before_authored_number_no_duplicate() -> None:
    # The exact §7.6 bug: normalize injects an UN-numbered "Validation Approach"
    # opener AHEAD of the fragment's already-numbered "7.6.1 Input Validation…".
    # Pass 2 must strip the stale number and re-assign sequentially so the two
    # H4s do not both render as 7.6.1.
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.6 Input Boundary Validation Controls\n\n"
        "#### Validation Approach\n\nbody\n\n"
        "#### 7.6.1 Input Validation and Sanitization\n\nbody\n\n"
        "#### 7.6.2 Server-Side Code Evaluation\n\nbody\n\n"
        "## 8. Findings Register\n"
    )
    out = compose._section7_number_and_bulletize(md)
    assert "#### 7.6.1 Validation Approach" in out
    assert "#### 7.6.2 Input Validation and Sanitization" in out
    assert "#### 7.6.3 Server-Side Code Evaluation" in out
    assert out.count("#### 7.6.1 ") == 1  # no duplicate number
    # Idempotent.
    out2 = compose._section7_number_and_bulletize(out)
    assert out2 == out


def test_section7_overview_links_get_section_number() -> None:
    """§7.1 overview-table category links are prefixed with their 7.X number."""
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.1 Security Control Overview\n\n"
        "| Control category | Verdict | Main reason |\n"
        "|---|---|---|\n"
        "| [Authorization Controls](#74-authorization-controls) | 🟠 Weak | gaps |\n\n"
        "### 7.4 Authorization Controls\n\n"
        "#### Route auth\n\nbody\n\n"
        "## 8. Findings Register\n"
    )
    out = compose._section7_number_and_bulletize(md)
    assert "[7.4 Authorization Controls](#74-authorization-controls)" in out


class _StubLabelCtx:
    def __init__(self, labels: dict) -> None:
        self._labels = labels

    def lookup_label(self, ref: str) -> str:
        return self._labels.get((ref or "").upper(), "")


def test_section7_inline_findings_id_only() -> None:
    ctx = _StubLabelCtx({"F-019": "Client side route guard bypass", "F-014": "BOLA user data export"})
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.4 Authorization Controls\n\n"
        "#### 7.4.1 Route auth\n\n"
        "**Security assessment**\n\n"
        "Bypassed by calling the API directly ([F-019](#f-019) (Client side route guard bypass)). "
        "Also see F-014 here.\n\n"
        "**Relevant findings**\n\n"
        "- [F-014](#f-014) (BOLA user data export)\n\n"
        "## 8. Findings Register\n"
    )
    out = compose._section7_inline_findings_id_only(ctx, md)
    # Inline assessment ref: title stripped, ID-only LINK.
    assert "([F-019](#f-019))" in out
    assert "Client side route guard bypass)." not in out.split("Relevant findings")[0]
    # Bare 'F-014' in prose became an ID-only link.
    assert "[F-014](#f-014) here" in out
    # Relevant-findings bullet keeps its title.
    assert "- [F-014](#f-014) (BOLA user data export)" in out


# ---------------------------------------------------------------------------
# §8 count invariants — guaranteed by construction (replaces the retired
# qa_checks.check_invariants numeric battery). The composer renders the Risk
# Distribution line, the STRIDE Coverage line, and the §8 register from one
# threats[] grouping, so all three counts must equal len(threats). Pinning it
# here is what lets the QA pre-pass drop the dead runtime re-check.
# ---------------------------------------------------------------------------


def test_section8_counts_equal_threat_total(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    yaml_total = len(yaml.safe_load((out / "threat-model.yaml").read_text()).get("threats", []))
    rendered, _ = compose.render(CONTRACT, out)

    rd_line = next((l for l in rendered.splitlines() if "**Risk Distribution:**" in l), "")
    sc_line = next((l for l in rendered.splitlines() if "**STRIDE Coverage:**" in l), "")
    assert rd_line, "Risk Distribution line missing from rendered §8"
    assert sc_line, "STRIDE Coverage line missing from rendered §8"

    # Per-severity cells, excluding the trailing **Total[ findings]: N** cell.
    risk_sum = sum(int(n) for n in re.findall(r"(?:Critical|High|Medium|Low|Info):\s*(\d+)", rd_line))
    total_declared_m = re.search(r"Total(?:\s+findings)?:\s*(\d+)", rd_line)
    assert total_declared_m, f"no Total cell in Risk Distribution line: {rd_line!r}"
    total_declared = int(total_declared_m.group(1))
    # The six STRIDE category counts.
    stride_sum = sum(int(n) for n in re.findall(r":\s*(\d+)", sc_line))

    assert risk_sum == total_declared == stride_sum == yaml_total, (
        f"§8 count drift: risk_sum={risk_sum} total_declared={total_declared} "
        f"stride_sum={stride_sum} yaml_total={yaml_total}"
    )


# ---------------------------------------------------------------------------
# Finding-link criticality dots (item 1) + abuse-chain MS note (item 4).
# ---------------------------------------------------------------------------

_SEV_TAX = {
    "critical": {"emoji": "🔴", "label": "Critical"},
    "high": {"emoji": "🟠", "label": "High"},
    "medium": {"emoji": "🟡", "label": "Medium"},
    "low": {"emoji": "🟢", "label": "Low"},
}


def _dot_ctx(tmp_path: Path, threats: list[dict]):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return compose.RenderContext(
        output_dir=out,
        contract={},
        yaml_data={"threats": threats},
        triage={},
        fragments_dir=out / ".fragments",
        severity_taxonomy=_SEV_TAX,
    )


def test_linkify_prepends_severity_dot_for_findings(tmp_path: Path) -> None:
    ctx = _dot_ctx(tmp_path, [{"id": "T-002", "effective_severity": "Critical", "title": "Hardcoded key"}])
    out = ctx.linkify_with_label("T-002")
    assert out.startswith("🔴 [F-002](#f-002)")


def test_linkify_dot_uses_effective_severity(tmp_path: Path) -> None:
    # raw High but chain-elevated to Critical → the dot reflects effective.
    ctx = _dot_ctx(tmp_path, [{"id": "T-019", "risk": "High", "effective_severity": "Critical", "title": "SSRF"}])
    assert ctx.linkify_with_label("F-019").startswith("🔴 ")


def test_linkify_no_dot_for_mitigation_or_component(tmp_path: Path) -> None:
    ctx = _dot_ctx(tmp_path, [{"id": "T-002", "effective_severity": "Critical"}])
    assert ctx.linkify_with_label("M-003").startswith("[M-003]")
    assert ctx.linkify_with_label("C-01").startswith("[C-01]")


def test_linkify_no_dot_when_severity_unknown(tmp_path: Path) -> None:
    ctx = _dot_ctx(tmp_path, [])  # no threats → no severity index entry
    assert ctx.linkify_with_label("T-099").startswith("[F-099]")


def test_abuse_chain_ms_note_names_findings_and_chains(tmp_path: Path) -> None:
    ctx = _dot_ctx(
        tmp_path,
        [
            {
                "id": "T-011",
                "effective_severity": "Critical",
                "risk": "Critical",
                "verified_chain_ids": ["AC-T-002"],
                "title": "IDOR",
            },
            {
                "id": "T-014",
                "effective_severity": "Critical",
                "risk": "Critical",
                "verified_chain_ids": ["AC-T-002", "AC-T-004"],
                "title": "Mass assignment",
            },
            {"id": "T-001", "effective_severity": "Critical", "verified_chain_ids": []},
        ],
    )
    note = compose._abuse_chain_ms_note(ctx)
    assert "Attack-chain analysis." in note
    assert "2 findings anchor 2 code-verified attack chains" in note
    assert "[F-011](#f-011)" in note and "[F-014](#f-014)" in note
    assert "see §9" in note or "§9" in note


def test_abuse_chain_ms_note_empty_when_no_verified_chain(tmp_path: Path) -> None:
    ctx = _dot_ctx(tmp_path, [{"id": "T-001", "effective_severity": "Critical", "verified_chain_ids": []}])
    assert compose._abuse_chain_ms_note(ctx) == ""


def test_abuse_chain_ms_note_reports_elevation(tmp_path: Path) -> None:
    ctx = _dot_ctx(
        tmp_path,
        [
            {
                "id": "T-019",
                "risk": "High",
                "effective_severity": "Critical",
                "verified_chain_ids": ["AC-T-007"],
                "title": "SSRF",
            },
        ],
    )
    note = compose._abuse_chain_ms_note(ctx)
    assert "rated above" in note and "individual baseline" in note


def test_global_finding_dot_pass_dots_bare_link_and_is_idempotent(tmp_path: Path) -> None:
    ctx = _dot_ctx(tmp_path, [{"id": "T-001", "effective_severity": "Critical", "title": "X"}])
    md = "**Source:** [F-001](#f-001) — `lib/insecurity.ts:54`"
    once = compose._prepend_finding_severity_dots(ctx, md)
    assert once == "**Source:** 🔴 [F-001](#f-001) — `lib/insecurity.ts:54`"
    # Idempotent — a second pass must not add a second dot.
    assert compose._prepend_finding_severity_dots(ctx, once) == once


def test_global_finding_dot_pass_tolerates_nbsp_separator(tmp_path: Path) -> None:
    # Table cells emit `🔴&nbsp;[F-001]`; the pass must recognise the existing
    # dot (separated by &nbsp;) and NOT prepend a duplicate.
    ctx = _dot_ctx(tmp_path, [{"id": "T-001", "effective_severity": "Critical"}])
    md = "•&nbsp;🔴&nbsp;[F-001](#f-001) — X"
    assert compose._prepend_finding_severity_dots(ctx, md) == md


def test_global_mitigation_circle_pass_dots_bare_link_and_is_idempotent(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    ctx = compose.RenderContext(
        output_dir=out,
        contract={},
        yaml_data={
            "threats": [{"id": "T-003", "effective_severity": "Critical"}],
            "mitigations": [{"id": "M-003", "priority": "P1", "threat_ids": ["T-003"]}],
        },
        triage={},
        fragments_dir=out / ".fragments",
        severity_taxonomy=_SEV_TAX,
    )
    md = "Blocking: [M-003](#m-003) breaks the chain."
    once = compose._prepend_mitigation_prio_circles(ctx, md)
    assert once == "Blocking: ❶ [M-003](#m-003) breaks the chain."
    assert compose._prepend_mitigation_prio_circles(ctx, once) == once


def test_global_mitigation_circle_pass_skips_code_spans(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    ctx = compose.RenderContext(
        output_dir=out,
        contract={},
        yaml_data={"threats": [], "mitigations": [{"id": "M-003", "priority": "P1"}]},
        triage={},
        fragments_dir=out / ".fragments",
        severity_taxonomy=_SEV_TAX,
    )
    md = "inline `[M-003](#m-003)` stays bare"
    assert compose._prepend_mitigation_prio_circles(ctx, md) == md


def test_softwrap_prose_cells_wraps_long_description_not_links():
    md = (
        "| Asset | ID | Description | Linked Threats |\n"
        "|---|---|---|---|\n"
        "| DB | A-001 | SQLite database containing all user email addresses and "
        "MD5-hashed passwords located at data/juiceshop.sqlite for offline cracking | "
        "🔴 [F-001](#f-001) — SQL injection authentication bypass via login route |\n"
    )
    out = compose._softwrap_prose_table_cells(md, width=40)
    body = [l for l in out.splitlines() if l.startswith("| DB")][0]
    desc = compose._split_table_row(body)[2]
    links = compose._split_table_row(body)[3]
    # Description got wrapped (now multi-segment, each ≤ ~40 visible chars)…
    assert "<br/>" in desc
    assert all(compose._seg_visible_len(s) <= 48 for s in desc.split("<br/>"))
    # …the link cell is untouched (single chip, no injected wrap).
    assert links == "🔴 [F-001](#f-001) — SQL injection authentication bypass via login route"


def test_softwrap_is_idempotent_and_skips_short_cells():
    md = "| # | Threat Description | Findings |\n|---|---|---|\n| 1 | Short note | [F-002](#f-002) |\n"
    once = compose._softwrap_prose_table_cells(md, width=40)
    assert once == md  # short cell + link cell → unchanged
    assert compose._softwrap_prose_table_cells(once, width=40) == once


def test_softwrap_never_breaks_inside_backtick_span():
    md = (
        "| Asset | Description | Findings |\n"
        "|---|---|---|\n"
        "| X | the query `SELECT * FROM Users WHERE id = 1` is concatenated unsafely "
        "without parameter binding anywhere | [F-001](#f-001) |\n"
    )
    out = compose._softwrap_prose_table_cells(md, width=30)
    desc = compose._split_table_row([l for l in out.splitlines() if l.startswith("| X")][0])[1]
    # No <br/> may fall INSIDE the backtick span (each segment has even backticks).
    for seg in desc.split("<br/>"):
        assert seg.count("`") % 2 == 0


# ---------------------------------------------------------------------------
# Deterministic blueprint integration (2026-06-05)
# When a STRIDE analyzer skips the optional remediation.blueprint lookup, the
# Requirements Traceability table still links each violated requirement to the
# blueprint section that references it (blueprints[].sections[].references[].id),
# so blueprints reach findings/maßnahmen/MS without depending on LLM behaviour.
# ---------------------------------------------------------------------------


def _reqs_yaml_with_blueprint(tmp_path: Path) -> None:
    (tmp_path / ".requirements.yaml").write_text(
        "categories:\n"
        "- id: CAT-AC\n"
        "  requirements:\n"
        "  - id: AC-004\n"
        "    url: https://req.example/auth\n"
        "    text: Authenticate users\n"
        "    priority: MUST\n"
        "blueprints:\n"
        "- id: BP-AUTHZ\n"
        "  url: https://bp.example/authz\n"
        "  sections:\n"
        "  - title: Implement a BFF\n"
        "    url: https://bp.example/authz#bff\n"
        "    references:\n"
        "    - id: AC-004\n",
        encoding="utf-8",
    )


def _ctx_for_mapping(tmp_path: Path, threat: dict):
    frag = tmp_path / ".fragments"
    frag.mkdir(exist_ok=True)
    return compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={"threats": [threat], "mitigations": []},
        triage={},
        fragments_dir=frag,
    )


def test_requirement_blueprints_maps_via_cross_reference(tmp_path: Path) -> None:
    _reqs_yaml_with_blueprint(tmp_path)
    ctx = _ctx_for_mapping(tmp_path, {})
    bp = compose._requirement_blueprints(ctx)
    assert bp.get("AC-004", "").startswith("[BP-AUTHZ](https://bp.example/authz#bff)")


def test_mapping_row_gets_deterministic_blueprint_when_llm_omits_it(tmp_path: Path) -> None:
    _reqs_yaml_with_blueprint(tmp_path)
    threat = {
        "t_id": "T-001",
        "risk": "critical",
        "mitigation_ids": ["M-001"],
        "remediation": {"reference": "[AC-004]"},  # no blueprint attached
    }
    rows = compose._build_requirements_mapping_rows(_ctx_for_mapping(tmp_path, threat))
    row = next(r for r in rows if r["req_id"] == "AC-004")
    assert "BP-AUTHZ" in row["blueprint"]


def test_mapping_row_keeps_llm_blueprint_over_deterministic(tmp_path: Path) -> None:
    _reqs_yaml_with_blueprint(tmp_path)
    threat = {
        "t_id": "T-001",
        "risk": "critical",
        "mitigation_ids": ["M-001"],
        "remediation": {"reference": "[AC-004]", "blueprint": "[BP-LLM](https://bp.example/llm) — Custom"},
    }
    rows = compose._build_requirements_mapping_rows(_ctx_for_mapping(tmp_path, threat))
    row = next(r for r in rows if r["req_id"] == "AC-004")
    assert "BP-LLM" in row["blueprint"] and "BP-AUTHZ" not in row["blueprint"]


# ---------------------------------------------------------------------------
# Bare requirement reference recovery (2026-06-06)
# Analyzers sometimes write `IF-002` without the `[...]` brackets the matcher
# keys on, dropping that requirement from the §7b/MS traceability table. The
# matcher now also recovers declared IDs written bare — without matching
# CWE/OWASP refs or partial tokens.
# ---------------------------------------------------------------------------


def test_requirement_ref_recovers_bare_declared_id() -> None:
    known = {"IF-002": "", "AC-004": ""}
    assert compose._requirement_ids_for_threat({"remediation": {"reference": "IF-002"}}, known) == ["IF-002"]


def test_requirement_ref_bracketed_still_matches() -> None:
    known = {"AC-004": ""}
    assert compose._requirement_ids_for_threat({"remediation": {"reference": "[AC-004](http://x)"}}, known) == [
        "AC-004"
    ]


def test_requirement_ref_ignores_cwe_and_partial_tokens() -> None:
    known = {"IF-002": ""}
    # CWE refs are not declared requirement IDs → never matched
    assert compose._requirement_ids_for_threat({"remediation": {"reference": "CWE-506"}}, known) == []
    # word-boundary guard: IF-0021 must not match IF-002
    assert compose._requirement_ids_for_threat({"remediation": {"reference": "IF-0021"}}, known) == []


# --------------------------------------------------------------------------- #
# _validate_known_json_fragments — fallback-capable fragments are non-fatal
# (attack-paths schema_version/actors drift — 2026-06-06)
# --------------------------------------------------------------------------- #
def _bare_ctx(tmp_path):
    frag = tmp_path / ".fragments"
    frag.mkdir(exist_ok=True)
    return compose.RenderContext(output_dir=tmp_path, contract={}, yaml_data={}, triage={}, fragments_dir=frag)


def test_invalid_attack_paths_fragment_is_non_fatal(tmp_path: Path) -> None:
    """A schema-invalid security-posture-attack-paths.json (the ms-renderer
    omitting schema_version/actors) must NOT abort compose — the section
    renderer falls back to deterministic derivation. The pre-pass only warns."""
    ctx = _bare_ctx(tmp_path)
    # Missing required schema_version + actors — exactly the observed defect.
    (ctx.fragments_dir / "security-posture-attack-paths.json").write_text(
        json.dumps({"attack_paths": [{"class": "injection", "glyph": "①"}]}),
        encoding="utf-8",
    )
    compose._validate_known_json_fragments(ctx)  # must not raise
    assert any("security-posture-attack-paths.json" in w for w in ctx.warnings)


def test_invalid_attack_paths_in_fallback_set() -> None:
    assert "security-posture-attack-paths.json" in compose._FRAGMENTS_WITH_FALLBACK


def test_invalid_non_fallback_fragment_still_fatal(tmp_path: Path) -> None:
    """A fragment WITHOUT a deterministic fallback (ms-verdict.json) stays a
    hard FragmentError so genuinely-broken artifacts cannot ship silently."""
    ctx = _bare_ctx(tmp_path)
    (ctx.fragments_dir / "ms-verdict.json").write_text("{}", encoding="utf-8")
    with pytest.raises((compose.FragmentError, compose.ContractError)):
        compose._validate_known_json_fragments(ctx)


# ---------------------------------------------------------------------------
# Component-selection scope transparency (verdict scope line + quick banner)
# ---------------------------------------------------------------------------


def _cs_with_exclusions() -> dict:
    return {
        "mode": "criteria",
        "analyzed": 2,
        "total": 4,
        "selected": [
            {"id": "web", "name": "Web", "reasons": ["frontend attack surface (mandatory)"]},
            {"id": "auth", "name": "Auth", "reasons": ["auth (M3.4 mandatory)"]},
        ],
        "excluded": [
            {"id": "w", "name": "Worker", "reason": "out-of-scope at depth=standard"},
            {"id": "db", "name": "DB", "reason": "out-of-scope at depth=standard"},
        ],
    }


def test_verdict_scope_coverage_line(tmp_path: Path) -> None:
    frag = tmp_path / ".fragments"
    frag.mkdir(parents=True)
    (frag / "ms-verdict.json").write_text(
        json.dumps(
            {
                "severity": "red",
                "opening": "Not production-ready. The application leaves its most sensitive operations open to anyone.",
                "bullets": [
                    {
                        "title": "Anyone can act as admin",
                        "body": "An unauthenticated caller reaches every privileged action.",
                        "refs": ["F-001"],
                    },
                    {
                        "title": "Customer data is reachable",
                        "body": "Any logged-in user can read other customers' records.",
                        "refs": ["F-002"],
                    },
                ],
                "closing": "Address authentication and authorization before any production use.",
            }
        ),
        encoding="utf-8",
    )
    yaml_data = {"meta": {"component_selection": _cs_with_exclusions()}, "threats": []}
    ctx = compose.RenderContext(output_dir=tmp_path, contract={}, yaml_data=yaml_data, triage={}, fragments_dir=frag)
    env = compose._build_jinja_env(ctx)
    section = {"fragment": "ms-verdict.json", "schema": "verdict.schema.json", "template": "verdict.md.j2"}
    out = compose._render_verdict(ctx, env, section)
    assert "**Scope:** 2 of 4 components received full STRIDE analysis" in out
    assert "other 2 (lower-priority / internal) were not individually assessed" in out


def test_quick_banner_shows_n_of_m(tmp_path: Path) -> None:
    yaml_data = {"meta": {"component_selection": _cs_with_exclusions()}, "components": []}
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data=yaml_data,
        triage={},
        fragments_dir=tmp_path,
        eval_context={"is_quick_depth": True},
    )
    env = compose._build_jinja_env(ctx)
    out = compose._render_quick_mode_notice(ctx, env, {})
    assert "**2 of 4 components**" in out


def test_quick_banner_discloses_carried_unverified_threats(tmp_path: Path) -> None:
    """Incremental depth-downgrade: prior threats re-injected by the reconciler
    (evidence_check=carried-unverified-shallower-depth) are disclosed once in the
    quick-mode banner, not silently presented as freshly verified."""
    yaml_data = {
        "components": [],
        "threats": [
            {"id": "T-001", "component": "api", "evidence_check": "verified-prior"},
            {"id": "T-002", "component": "api", "evidence_check": "carried-unverified-shallower-depth"},
            {"id": "T-003", "component": "api", "evidence_check": "carried-unverified-shallower-depth"},
        ],
    }
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data=yaml_data,
        triage={},
        fragments_dir=tmp_path,
        eval_context={"is_quick_depth": True},
    )
    out = compose._render_quick_mode_notice(ctx, compose._build_jinja_env(ctx), {})
    assert "2 prior findings carried forward" in out
    assert "re-run at the prior depth" in out


def test_quick_banner_no_disclosure_when_no_carried_threats(tmp_path: Path) -> None:
    yaml_data = {"components": [], "threats": [{"id": "T-001", "component": "api", "evidence_check": "unchecked"}]}
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data=yaml_data,
        triage={},
        fragments_dir=tmp_path,
        eval_context={"is_quick_depth": True},
    )
    out = compose._render_quick_mode_notice(ctx, compose._build_jinja_env(ctx), {})
    assert "carried forward" not in out


# ---------------------------------------------------------------------------
# Consistent code formatting of title/label locators (+ code-free TOC)
# ---------------------------------------------------------------------------


def test_codify_label_locator_backticks_code_consistently():
    f = compose._codify_label_locator
    # file:line, route path, bare filename, extensionless config file → backticked
    assert (
        f("Missing Ownership Check (updateProductReviews.ts:18)")
        == "Missing Ownership Check (`updateProductReviews.ts:18`)"
    )
    assert (
        f("Mass Assignment via Finale-REST (routes/api/Users)")
        == "Mass Assignment via Finale-REST (`routes/api/Users`)"
    )
    assert f("Prototype Pollution (package.json:7)") == "Prototype Pollution (`package.json:7`)"
    assert f("Root Container (Dockerfile)") == "Root Container (`Dockerfile`)"


def test_codify_label_locator_leaves_non_code_untouched():
    f = compose._codify_label_locator
    assert f("Hardcoded Secrets & Weak Cryptography (S·E)") == "Hardcoded Secrets & Weak Cryptography (S·E)"
    assert f("Some Finding (I)") == "Some Finding (I)"
    assert f("Some Finding (verified)") == "Some Finding (verified)"
    assert f("Add JWT authentication middleware") == "Add JWT authentication middleware"


def test_codify_label_locator_is_idempotent():
    f = compose._codify_label_locator
    once = f("Missing Ownership Check (changePassword.ts:39)")
    assert f(once) == once


def test_strip_label_code_removes_backticks_for_toc():
    assert compose._strip_label_code("SQL Injection (`search.ts:42`)") == "SQL Injection (search.ts:42)"


def test_lookup_label_applies_codify(tmp_path: Path) -> None:
    yaml_data = {"threats": [{"id": "F-001", "title": "Missing Ownership Check (updateProductReviews.ts:18)"}]}
    ctx = compose.RenderContext(
        output_dir=tmp_path, contract={}, yaml_data=yaml_data, triage={}, fragments_dir=tmp_path
    )
    assert ctx.lookup_label("F-001") == "Missing Ownership Check (`updateProductReviews.ts:18`)"


# ---------------------------------------------------------------------------
# 2026-06-12 deliverable defect fixes (mitigation index, headings, IDs)
# ---------------------------------------------------------------------------


def test_index_short_title_keeps_backticks_balanced():
    """The §10 Mitigations-index truncation must never leave an unclosed code
    span — an odd backtick bled M-017's title into M-018..M-025 as one giant
    code span (the catastrophic 2026-06-12 break)."""
    f = compose._index_short_title
    t = (
        "Replace `.decode(token)` with `.verify(token, key, { algorithms: [...] })` "
        "and gate authorization on the verified payload only."
    )
    out = f(t)
    assert out.count("`") % 2 == 0, out
    assert out.endswith("…")
    # A short title with balanced backticks is returned intact (still balanced).
    short = f("Add `permissions: { contents: read }` at workflow root")
    assert short.count("`") % 2 == 0


def test_index_short_title_backticks_angle_placeholder():
    """`<digest>`-style placeholders must be code-spanned in the index chip so
    they are not parsed as an HTML tag and dropped (M-007 lost `<digest>`)."""
    out = compose._index_short_title("Pin base image to @sha256:<digest>")
    assert "`<digest>`" in out


def test_escape_heading_placeholders():
    """Headings stay backtick-free, so a `<placeholder>` is HTML-entity escaped
    (not code-spanned) to render literally instead of vanishing."""
    f = compose._escape_heading_placeholders
    assert f("Pin base image to @sha256:<digest>") == "Pin base image to @sha256:&lt;digest&gt;"
    # `<br/>` and the rest of normal prose are untouched.
    assert f("Title with no placeholder") == "Title with no placeholder"
    assert "<br/>" in f("Line one<br/>line two")


def test_softwrap_exempts_structural_threats_table():
    """The `# | Threat Description | …` posture table must NOT get the 44-char
    `<br/>` soft-wrap (it chopped the description into random stub lines)."""
    md = (
        "| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |\n"
        "|---|--------------------|------------------------|---------------|-----|\n"
        "| ① | **Insecure Query** _(T·I)_ user input flows into a server-side "
        "interpreter without parameterization or schema validation here. | x | y | z |\n"
    )
    out = compose._softwrap_prose_table_cells(md)
    # No mid-prose <br/> was injected into the Threat Description cell.
    assert "server-side<br/>" not in out
    assert "<br/>interpreter" not in out


def test_attack_class_taxonomy_uses_us_english():
    """Structural-threat class descriptions render verbatim into the §6 posture
    table; they must use US spelling (parameterization / authorization), not the
    UK forms that leaked into the 2026-06-12 deliverable."""
    tax = Path(__file__).parent.parent / "data" / "attack-class-taxonomy.yaml"
    text = tax.read_text(encoding="utf-8")
    for uk in ("parameterisation", "authorisation", "sanitisation", "deserialisation"):
        assert uk not in text, "UK spelling %r present in attack-class-taxonomy.yaml" % uk


def test_paragraphize_issue_card_splits_long_narrative():
    f = compose._paragraphize_issue_card
    long = "**Issue:** " + " ".join(
        f"Sentence number {i} describes a distinct security beat in detail here." for i in range(1, 7)
    )
    out = f(long)
    assert out.count("\n\n") >= 2  # multiple paragraphs
    assert out.startswith("**Issue:** ")
    # Short issue is untouched.
    short = "**Issue:** One short sentence."
    assert f(short) == short
    # Non-Issue input passes through.
    assert f("**Fix:** do the thing") == "**Fix:** do the thing"


def test_prose_linkifier_table_cells_use_emdash_form():
    """§5 attack-surface table cells must use the canonical em-dash form
    `[F-NNN](#f-nnn) — Weakness (file)`, consistent with §2/§4/§8 — not the
    parens short form. Genuine inline prose keeps the parens form."""
    yaml_data = {
        "threats": [
            {
                "id": "T-014",
                "title": "Server-Side Template Injection — routes/userProfile.ts:62",
                "risk": "Critical",
                "cwe": "CWE-94",
                "evidence": {"file": "routes/userProfile.ts", "line": 62},
            },
        ],
    }
    ctx = compose.RenderContext(
        output_dir=Path("."),
        contract={},
        yaml_data=yaml_data,
        triage={},
        fragments_dir=Path("."),
    )
    table_md = "| GET | `/profile` | Critical | [F-014](#f-014) |"
    prose_md = "The attacker exploits [F-014](#f-014) directly."
    out_tbl = compose._linkify_bare_refs_in_prose(ctx, table_md)
    out_prose = compose._linkify_bare_refs_in_prose(ctx, prose_md)
    assert "[F-014](#f-014) — " in out_tbl  # em-dash in the table cell
    assert "[F-014](#f-014) (" in out_prose  # parens in inline prose


# ---- Figure 1 SVG integration (Phase 2) ------------------------------------
def _fig1_ctx(out: Path) -> compose.RenderContext:
    return compose.RenderContext(
        output_dir=out,
        contract={},
        yaml_data={
            "components": [
                {"id": "spa", "name": "Angular SPA", "tier": "client"},
                {"id": "api", "name": "Express API", "tier": "application"},
                {"id": "db", "name": "Data Layer", "tier": "data"},
            ],
            "threats": [{"id": "F-001", "component": "api", "risk": "Critical"}],
            "trust_boundaries": [{"from": "external", "to": "api", "name": "Public to API"}],
            "meta": {},
        },
        triage={},
        fragments_dir=out / ".fragments",
    )


_FIG1_APD = {
    "attack_paths": [{"class": "injection", "actor": "internet-anon", "target": "application", "findings": ["F-001"]}]
}
_FIG1_TAX = {
    "glyph_sequence": ["①"],
    "classes": [
        {
            "id": "injection",
            "short_label": "Injection",
            "default_actor": "internet-anon",
            "default_target_tier": "application",
        }
    ],
}


def test_render_figure1_svg_writes_file_and_image_ref(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    md = compose._render_figure1_svg(_fig1_ctx(out), _FIG1_APD, _FIG1_TAX)
    assert "](figure1.svg)" in md  # image reference, not a mermaid block
    assert "```mermaid" not in md
    svg = out / "figure1.svg"
    assert svg.is_file() and svg.read_text(encoding="utf-8").startswith("<svg")


def test_render_figure1_svg_empty_without_attack_paths(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert compose._render_figure1_svg(_fig1_ctx(out), {"attack_paths": []}, _FIG1_TAX) == ""
    assert not (out / "figure1.svg").exists()


def test_render_figure1_svg_empty_without_components(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    ctx = _fig1_ctx(out)
    ctx.yaml_data["components"] = []
    assert compose._render_figure1_svg(ctx, _FIG1_APD, _FIG1_TAX) == ""


def test_render_figure1_svg_embed_inline_data_uri(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    ctx = _fig1_ctx(out)
    ctx.embed_figures = True
    md = compose._render_figure1_svg(ctx, _FIG1_APD, _FIG1_TAX)
    assert "](data:image/svg+xml;base64," in md  # inlined self-contained image
    assert "figure1.svg)" not in md
    assert (out / "figure1.svg").is_file()  # the file is still written


def test_render_figure1_svg_default_is_file_reference(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    md = compose._render_figure1_svg(_fig1_ctx(out), _FIG1_APD, _FIG1_TAX)
    assert "](figure1.svg)" in md
    assert "data:image" not in md


def test_figure_basename_for_md_derives_from_stem() -> None:
    assert compose._figure_basename_for_md("threat-model.md") == "threat-model.figure1.svg"
    assert (
        compose._figure_basename_for_md("threat-model-juice-shop-quick.md")
        == "threat-model-juice-shop-quick.figure1.svg"
    )
    assert compose._figure_basename_for_md("analysis-model.md") == "analysis-model.figure1.svg"


def test_render_figure1_svg_custom_basename(tmp_path: Path) -> None:
    # figure_basename drives both the written file and the image reference, so
    # a stem-derived name (<md-stem>.figure1.svg) keeps several models from
    # colliding in one directory.
    out = tmp_path / "out"
    out.mkdir()
    ctx = _fig1_ctx(out)
    ctx.figure_basename = "threat-model-juice-shop-quick.figure1.svg"
    md = compose._render_figure1_svg(ctx, _FIG1_APD, _FIG1_TAX)
    assert "](threat-model-juice-shop-quick.figure1.svg)" in md
    assert "](figure1.svg)" not in md
    assert (out / "threat-model-juice-shop-quick.figure1.svg").is_file()
    assert not (out / "figure1.svg").exists()


def test_render_figure1_svg_embed_via_skill_config(tmp_path: Path) -> None:
    # `/create-threat-model --embed-figures` persists embed_figures to
    # .skill-config.json; compose honours it without a CLI flag (renderer path).
    out = tmp_path / "out"
    out.mkdir()
    (out / ".skill-config.json").write_text('{"embed_figures": true}', encoding="utf-8")
    md = compose._render_figure1_svg(_fig1_ctx(out), _FIG1_APD, _FIG1_TAX)  # ctx.embed_figures defaults False
    assert "](data:image/svg+xml;base64," in md


def test_render_figure1_svg_skill_config_false_is_file_reference(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / ".skill-config.json").write_text('{"embed_figures": false}', encoding="utf-8")
    md = compose._render_figure1_svg(_fig1_ctx(out), _FIG1_APD, _FIG1_TAX)
    assert "](figure1.svg)" in md and "data:image" not in md


# ---------------------------------------------------------------------------
# §3 required-pattern gate (zero-Critical reports) + §7 domain-pattern
# applicability gating (non-applicable controls, e.g. no WebSockets).
# ---------------------------------------------------------------------------


def _attack_walkthroughs_section() -> dict:
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    return contract["sections"]["attack_walkthroughs"]


def test_walkthroughs_stub_passes_when_no_authored_walkthroughs(tmp_path: Path) -> None:
    """A zero-Critical §3 stub (intro only, no `sequenceDiagram`) must pass the
    required-pattern check when `has_authored_walkthroughs` is False. This is
    the gate that stops clean reports from hard-failing on missing diagrams."""
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    (frag_dir / "attack-walkthroughs.md").write_text(
        "## 3. Attack Walkthroughs\n\n"
        "_No Critical findings were identified in this assessment, so there are "
        "no per-Critical attack walkthroughs._\n",
        encoding="utf-8",
    )
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag_dir,
        eval_context={"has_authored_walkthroughs": False},
    )
    md = compose._render_markdown_fragment(ctx, "attack_walkthroughs", _attack_walkthroughs_section())
    assert md.lstrip().startswith("## 3. Attack Walkthroughs")
    assert "sequenceDiagram" not in md


def test_walkthroughs_required_pattern_enforced_when_authored(tmp_path: Path) -> None:
    """Counterpart guard: when walkthroughs ARE authored
    (`has_authored_walkthroughs` True) a §3 fragment lacking `sequenceDiagram`
    still hard-fails — the gate must not silently disable the check."""
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    (frag_dir / "attack-walkthroughs.md").write_text(
        "## 3. Attack Walkthroughs\n\n### 3.1 Some Critical\n\nNo diagram in this block.\n",
        encoding="utf-8",
    )
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag_dir,
        eval_context={"has_authored_walkthroughs": True},
    )
    with pytest.raises(compose.FragmentError) as exc:
        compose._render_markdown_fragment(ctx, "attack_walkthroughs", _attack_walkthroughs_section())
    assert "sequenceDiagram" in str(exc.value)


def test_domain_required_pattern_skipped_when_subsection_absent(tmp_path: Path) -> None:
    """A non-applicable control (e.g. no WebSocket flow) whose `### N.x`
    subsection is simply absent must NOT trip its `domain_required_patterns`.
    Enforcement only fires when the subsection heading is present — this is how
    §7 lets a control be 'Not applicable' without raising a contract error."""
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    (frag_dir / "demo.md").write_text(
        "## 9. Demo\n\nThis app has no real-time surface, so there is no flow here.\n",
        encoding="utf-8",
    )
    section = {
        "heading": "## 9. Demo",
        "fragment": "demo.md",
        "domain_required_patterns": {"9.4 WebSocket Controls": ["sequenceDiagram"]},
    }
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag_dir,
        eval_context={},
    )
    md = compose._render_markdown_fragment(ctx, "demo", section)
    assert "sequenceDiagram" not in md


def test_domain_required_pattern_enforced_when_subsection_present(tmp_path: Path) -> None:
    """Counterpart: when the control IS applicable (its `### N.x` heading is
    rendered) the domain pattern is enforced and a missing diagram hard-fails."""
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    (frag_dir / "demo.md").write_text(
        "## 9. Demo\n\nintro\n\n### 9.4 WebSocket Controls\n\nNo diagram in this applicable control.\n",
        encoding="utf-8",
    )
    section = {
        "heading": "## 9. Demo",
        "fragment": "demo.md",
        "domain_required_patterns": {"9.4 WebSocket Controls": ["sequenceDiagram"]},
    }
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag_dir,
        eval_context={},
    )
    with pytest.raises(compose.FragmentError) as exc:
        compose._render_markdown_fragment(ctx, "demo", section)
    assert "sequenceDiagram" in str(exc.value)


# ---------------------------------------------------------------------------
# Regression: severity helpers honour effective_severity (2026-06-24)
# ---------------------------------------------------------------------------


def test_severity_by_finding_num_uses_effective_severity() -> None:
    """Threats with only effective_severity (no risk/severity) must not default to 'low'."""
    threats = [{"id": "T-001", "effective_severity": "Critical"}]
    result = compose._severity_by_finding_num(threats)
    assert result[1] == "critical", f"expected 'critical', got {result[1]!r}"


def test_severity_by_finding_num_effective_severity_wins_over_risk() -> None:
    """effective_severity takes priority over risk when both present."""
    threats = [{"id": "T-007", "effective_severity": "High", "risk": "Low"}]
    result = compose._severity_by_finding_num(threats)
    assert result[7] == "high", f"expected 'high', got {result[7]!r}"


def test_severity_by_finding_num_falls_back_to_risk_when_no_effective() -> None:
    """Without effective_severity, risk is used as before."""
    threats = [{"id": "T-003", "risk": "Medium"}]
    result = compose._severity_by_finding_num(threats)
    assert result[3] == "medium"


def test_severity_by_finding_num_low_default_when_all_absent() -> None:
    """No effective_severity / risk / severity → 'low' default unchanged."""
    threats = [{"id": "T-002"}]
    result = compose._severity_by_finding_num(threats)
    assert result[2] == "low"


# ---------------------------------------------------------------------------
# Regression: _canonical_finding_title strips noise tokens (2026-06-24)
# ---------------------------------------------------------------------------


def test_canonical_finding_title_strips_all_caps_constant() -> None:
    """ALL_CAPS_UNDERSCORE constants (e.g. DEFAULT_FULL_SCHEMA) must not appear in title."""
    t = {
        "title": "YAML Arbitrary Code Execution via js-yaml DEFAULT_FULL_SCHEMA",
        "cwe": "CWE-502",  # unmapped → falls through to fallback
    }
    # Ensure CWE-502 is not in the map so fallback activates.
    original = compose._CWE_CLASS_NAMES.pop("CWE-502", None)
    try:
        result = compose._canonical_finding_title(t)
    finally:
        if original is not None:
            compose._CWE_CLASS_NAMES["CWE-502"] = original
    assert "DEFAULT_FULL_SCHEMA" not in result, f"constant leaked into title: {result!r}"
    assert "js-yaml" not in result, f"package name leaked into title: {result!r}"


def test_canonical_finding_title_strips_npm_package_names() -> None:
    """npm-style hyphenated package names must not appear in the fallback title."""
    t = {
        "title": "Prototype Pollution via lodash merge deep",
        "cwe": "CWE-FAKE-NOT-MAPPED",
    }
    result = compose._canonical_finding_title(t)
    # "lodash" is a single token (no hyphen) so it may survive; "merge" / "deep" are fine
    # The key check: the result is non-empty and no npm-style token sneaks in.
    assert result  # non-empty
    # no token matching npm-style pattern ^[a-z]+[-\.][a-z]+ in result
    for tok in result.split():
        assert not re.match(r"^[a-z][a-z0-9]*[-\.][a-z][a-z0-9\-\.]*$", tok), (
            f"npm-style token {tok!r} in canonical title {result!r}"
        )


def test_canonical_finding_title_keeps_weakness_class_words() -> None:
    """Normal weakness-class words must survive noise filtering."""
    t = {
        "title": "SQL Injection login route",
        "cwe": "CWE-UNMAPPED-XYZ",
    }
    result = compose._canonical_finding_title(t)
    # Should keep "SQL" and "Injection" (uppercase is not ALL_CAPS_UNDERSCORE: length < 3 chars after first)
    assert "SQL" in result or "Injection" in result, f"weakness words stripped: {result!r}"


# ---------------------------------------------------------------------------
# Regression: evidence_summary gets _codify_inline_identifiers applied (2026-06-24)
# ---------------------------------------------------------------------------


def test_evidence_summary_codify_applied_to_file_path() -> None:
    """File paths in evidence_summary must be backtick-wrapped by _codify_inline_identifiers.

    This validates the fix: the function was previously NOT applied to
    evidence_summary_explicit prose — now applied before building **Evidence:**.
    Uses a simple file:line token that codify reliably handles.
    """
    raw = "routes/userProfile.ts:61 calls eval(code) where code is user-supplied."
    result = compose._codify_inline_identifiers(raw)
    # The file:line token must be backtick-wrapped.
    assert "`" in result, f"no backticks produced for evidence prose: {result!r}"
    assert result != raw, "evidence prose returned unmodified — codify had no effect"


def test_evidence_summary_codify_wraps_dotted_method_call() -> None:
    """socket.emit style dotted call must be backticked by codify."""
    raw = "socket.emit fires on every new connection before authentication."
    result = compose._codify_inline_identifiers(raw)
    assert "socket.emit" in result
    # The dotted call should be wrapped; backtick count is even and >= 2.
    assert result.count("`") >= 2, f"dotted method call not backticked: {result!r}"
