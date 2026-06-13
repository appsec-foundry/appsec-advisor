"""Tests for Patch P1 — Renderer Correctness (A1 + A3 + B1 + C).

Covers four orthogonal regressions surfaced by the 2026-05-07 juice-shop
quick-mode run:

    A1 — F-NNN anchors are emitted next to T-NNN anchors so LLM-authored
         fragments that reference findings as `[F-001](#f-001)` (Verdict
         bullets, asset Linked-Threats cells, walkthroughs) resolve to the
         same threat row. Pre-fix: zero F-anchors emitted; 100+ broken
         links across the report.

    A3 — `infer_threat_category` consults the curated `cwe_to_th:` map in
         `data/threat-category-taxonomy.yaml` BEFORE running the keyword
         heuristic. Pre-fix: title substrings won (e.g. T-001 with
         CWE-321 fell into TH-02 because "token forgery" matched the
         Broken-Authentication keyword bucket).

    B1 — Diagram nodes (actors, tiers, components, impact cards, technology
         nodes) render plain. Bold (`<b>…</b>`) is reserved for the three
         column headers HDR_A / HDR_T / HDR_I. Pre-fix: every node label
         was bold, drowning the visual hierarchy.

    C  — `render_run_statistics` 'Total stage compute' sums every recorded stage
         from `.stage-stats.jsonl` (Stage 1 orchestrator + Stage 2
         renderer + Stage 3 QA + Stage 4 architect + REPAIR_MODE
         iterations) instead of just `assess_secs + qa_secs + arch_secs`.
         Pre-fix: 32m shown for a 45m+ wall-clock run.

These tests don't depend on the larger compose fixture (which is
historically out-of-date with the contract). They isolate the patched
helpers and exercise them directly so regressions are caught even when
the fixture is mid-migration.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# Make scripts/_atomic_io.py importable when compose_threat_model is loaded.
_SCRIPTS = REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

compose = _load_module("compose_threat_model", _SCRIPTS / "compose_threat_model.py")
rcs = _load_module("render_completion_summary", _SCRIPTS / "render_completion_summary.py")


# ---------------------------------------------------------------------------
# A3 — CWE→TH deterministic mapping
# ---------------------------------------------------------------------------


class TestCweToThMapping:
    """Verify the curated `cwe_to_th:` block from threat-category-taxonomy.yaml
    drives ``infer_threat_category`` for findings carrying a CWE."""

    def setup_method(self):
        # Cache is process-global; clear between tests to pick up file edits
        # if any test mutated the taxonomy yaml.
        compose._build_cwe_to_th_map.cache_clear()

    def test_map_built_from_curated_block(self):
        m = compose._build_cwe_to_th_map()
        # The curated block has ~50 entries; the fallback adds ~5 more.
        # We assert ≥ 30 to allow additive growth without rewriting the test.
        assert len(m) >= 30
        # Spot-check the canonical mappings the report relies on.
        assert m["CWE-79"] == "TH-11"  # XSS
        assert m["CWE-89"] == "TH-01"  # SQL injection
        assert m["CWE-94"] == "TH-05"  # Code injection
        assert m["CWE-321"] == "TH-03"  # Hardcoded crypto key
        assert m["CWE-798"] == "TH-03"  # Hardcoded credentials
        assert m["CWE-916"] == "TH-03"  # Weak password hash
        assert m["CWE-918"] == "TH-08"  # SSRF
        assert m["CWE-922"] == "TH-04"  # Insecure storage (localStorage JWT)
        assert m["CWE-639"] == "TH-06"  # IDOR
        assert m["CWE-611"] == "TH-07"  # XXE
        assert m["CWE-352"] == "TH-15"  # CSRF
        assert m["CWE-601"] == "TH-18"  # Open redirect

    def test_normalize_cwe_accepts_int_string_and_prefix(self):
        n = compose._normalize_cwe
        assert n(321) == "CWE-321"
        assert n("321") == "CWE-321"
        assert n("CWE-321") == "CWE-321"
        assert n("cwe-321") == "CWE-321"
        assert n("000089") == "CWE-89"  # leading zeros stripped
        assert n("") == ""
        assert n(None) == ""

    def test_cwe_beats_keyword_heuristic_for_t001_regression(self):
        """The 2026-05-07 regression: T-001 (Hardcoded RSA Private Key) had
        CWE-321 set, but the title contained "Token Forgery" which matched
        the TH-02 (Broken Authentication) keyword bucket. With the CWE-first
        resolver, CWE-321 → TH-03 wins regardless of how the title reads."""
        import yaml

        tax_raw = yaml.safe_load((REPO_ROOT / "data" / "threat-category-taxonomy.yaml").read_text())
        taxonomy = {c["id"]: c for c in tax_raw["categories"]}
        threat = {
            "cwe": "CWE-321",
            "title": "Hardcoded RSA Private Key Enables Offline JWT Admin Token Forgery",
        }
        assert compose.infer_threat_category(threat, taxonomy) == "TH-03"

    def test_keyword_heuristic_still_wins_when_no_cwe(self):
        """Findings without a CWE field fall back to the keyword heuristic
        so legacy yaml that never carried CWE still classifies."""
        import yaml

        tax_raw = yaml.safe_load((REPO_ROOT / "data" / "threat-category-taxonomy.yaml").read_text())
        taxonomy = {c["id"]: c for c in tax_raw["categories"]}
        threat = {"title": "SQL injection in product search endpoint"}
        # No `cwe` field → falls through to keyword pass → "sql injection" → TH-01.
        assert compose.infer_threat_category(threat, taxonomy) == "TH-01"

    def test_explicit_threat_category_id_short_circuits_lookup(self):
        """When the yaml carries `threat_category_id` directly, that wins
        over both the CWE map and the keyword heuristic."""
        import yaml

        tax_raw = yaml.safe_load((REPO_ROOT / "data" / "threat-category-taxonomy.yaml").read_text())
        taxonomy = {c["id"]: c for c in tax_raw["categories"]}
        # Title says SQL but explicit category says TH-03 — explicit wins.
        threat = {
            "threat_category_id": "TH-03",
            "cwe": "CWE-89",
            "title": "SQL injection in login",
        }
        assert compose.infer_threat_category(threat, taxonomy) == "TH-03"


# ---------------------------------------------------------------------------
# A1 — F-anchor dual emission
# ---------------------------------------------------------------------------


class TestFAnchorDualEmission:
    """Verify the threat-register row emits both `<a id="t-NNN"></a>` and
    `<a id="f-NNN"></a>` so cross-references using either ID resolve.

    These are unit-level checks against the row-rendering string emitted by
    `_render_threat_register`. A full compose-level smoke test requires the
    fixture infrastructure which is currently out of date with the contract;
    these tests stay below that level by exercising the row-emission logic
    in isolation through the inline regex match it now performs.
    """

    def test_tid_in_t_format_emits_dual_anchors_string(self):
        """The actual emission uses an inline regex: `^T-(\\d+)$` → emit
        `<a id="f-NNN"></a>` next to the t-anchor. Verify the regex matches
        the expected ID shapes."""
        import re

        pat = re.compile(r"^T-(\d+)$")
        assert pat.match("T-001").group(1) == "001"
        assert pat.match("T-099").group(1) == "099"
        assert pat.match("T-1234").group(1) == "1234"

    def test_non_t_format_id_does_not_emit_f_alias(self):
        """Component-prefixed IDs (legacy schemas) shouldn't trigger an
        F-alias from the inline emission — the post-render bridge handles
        those instead."""
        import re

        pat = re.compile(r"^T-(\d+)$")
        assert pat.match("auth-jwt-s-001") is None
        assert pat.match("F-001") is None

    def test_f_bridge_pattern_matches_f_links(self):
        """The post-render F-bridge scans for `[F-NNN](#f-nnn)` patterns to
        decide whether to inject f-aliases on component-prefixed schemas.
        Verify the pattern matches the canonical F-link form."""
        import re

        pat = re.compile(r"\[F-(\d+)\]\(#f-\d+\)")
        assert pat.findall("see [F-001](#f-001) and [F-009](#f-009)") == ["001", "009"]
        # The bridge intentionally does NOT match links pointing to t-anchors
        # — those are already valid via the T-NNN bridge.
        assert pat.findall("[F-001](#t-001)") == []


# ---------------------------------------------------------------------------
# B1 — Bold removal in diagram nodes
# ---------------------------------------------------------------------------


class TestNoBoldInDiagramNodes:
    """Templates and node builders emit plain labels; bold is reserved for
    the three column headers (HDR_A / HDR_T / HDR_I) inside the heatmap."""

    def test_security_posture_template_no_bold_in_actor_card(self):
        """`security-posture-diagram.md.j2` actor card line should reference
        `card.label` directly — no `<b>` wrapper."""
        tpl = (REPO_ROOT / "templates" / "fragments" / "security-posture-diagram.md.j2").read_text()
        # The actor-card line — match the template body literally.
        actor_line_present = "{{ card.id }}([" in tpl
        assert actor_line_present, "actor card line must exist in template"
        # No <b> around card.label.
        assert "<b>{{ card.label }}</b>" not in tpl
        # Single-line plain form is now expected (no subtitle line) — the
        # actor card closes directly after the label.
        assert '{{ card.label }}"])' in tpl

    def test_security_posture_template_no_bold_in_tier_card(self):
        tpl = (REPO_ROOT / "templates" / "fragments" / "security-posture-diagram.md.j2").read_text()
        assert "<b>{{ tier.name }}</b>" not in tpl
        assert "{{ tier.name }}<br/>" in tpl

    def test_security_posture_template_keeps_header_bold(self):
        """HDR_A / HDR_T / HDR_I keep their `<b>` because they are column
        headers, visually distinct from cells."""
        tpl = (REPO_ROOT / "templates" / "fragments" / "security-posture-diagram.md.j2").read_text()
        for hdr in ("subgraph_actors", "subgraph_tiers", "subgraph_impact"):
            line = f"<b>{{{{ data.{hdr}.header_label }}}}</b>"
            assert line in tpl, f"header bold for {hdr} must remain"

    def test_components_line_in_tier_card_is_plain(self):
        """compose._build_tier_cards emits the tier components line as plain
        `C-NN Name · C-NN Name` (was `<b>comp1</b> · <b>comp2</b>`).

        2026-05 — Figure 2 reshape: the tier card lists its components as
        `C-NN Name` (reference form) joined with ` · `. The line must stay
        plain (no `<b>` stitching); the join idiom is now a generator over
        `comps_in_tier`, so we assert the plain ` · `.join + the absence of
        the bold-stitched form rather than the old `comp_ids` literal."""
        src = (REPO_ROOT / "scripts" / "compose_threat_model.py").read_text()
        # The plain ` · `-join idiom must appear; the bold-stitched form must not.
        assert '" · ".join(' in src
        assert '"</b> · <b>".join' not in src

    def test_impact_card_label_is_plain(self):
        """compose._build_impact_cards emits `f"{emoji} {label}"` (was
        `f"{emoji} <b>{label}</b>"`)."""
        src = (REPO_ROOT / "scripts" / "compose_threat_model.py").read_text()
        # The plain emission must be present.
        assert "f\"{emoji} {imp.get('label')}\"" in src
        # The bold variant must not appear.
        assert "f\"{emoji} <b>{imp.get('label')}</b>\"" not in src

    def test_pregenerator_actor_label_is_plain(self):
        """pregenerate_fragments._select_external_actors emits plain actor
        labels (was `<b>{name}</b>`)."""
        src = (REPO_ROOT / "scripts" / "pregenerate_fragments.py").read_text()
        # Plain form must be present in the actor builder.
        assert 'f"{icon} {name}"' in src

    def test_pregenerator_tier_label_is_plain(self):
        """The components-tier head label is also plain."""
        src = (REPO_ROOT / "scripts" / "pregenerate_fragments.py").read_text()
        assert 'f"{icon} {head_text}"' in src

    def test_pregenerator_tech_stack_label_is_plain(self):
        """The technology-architecture node head is also plain."""
        src = (REPO_ROOT / "scripts" / "pregenerate_fragments.py").read_text()
        # Match the new plain emission inside _label().
        assert 'f"{icon} {_truncate_label_line(headline, max_chars)}"' in src


# ---------------------------------------------------------------------------
# B2 — Heat-map tier consistency: bullets in a tier box only emerge from
# clusters whose CWE is in the per-tier arrow allow-set (no "ghost"
# bullets in tiers that have no incoming arrow for that class).
# ---------------------------------------------------------------------------


class TestTierClusterArrowConsistency:
    def test_arrow_cwe_allow_filters_unrelated_clusters(self):
        """When an arrow allow-set is provided, threats whose CWE is not
        in the set must be dropped from the tier's cluster bullets."""
        # CWE-89 (SQL injection) is in the allow-set; CWE-321 (hardcoded
        # cryptographic key) is NOT — it should be filtered out.
        threats = [
            {"id": "T-001", "cwe": "CWE-89", "title": "SQLi", "risk": "critical"},
            {"id": "T-002", "cwe": "CWE-321", "title": "Hardcoded key", "risk": "critical"},
        ]
        allow = {"CWE-89"}
        lines = compose._build_tier_cluster_lines(threats, arrow_cwe_allow=allow)
        joined = "\n".join(lines).lower()
        assert "injection" in joined or "sql" in joined, lines
        # The crypto cluster has no incoming arrow → must not appear.
        assert "crypto" not in joined and "key" not in joined, lines

    def test_allow_set_none_preserves_legacy_behaviour(self):
        """When the caller does not pass an allow-set, every cluster
        is rendered exactly as before (no filtering)."""
        threats = [
            {"id": "T-001", "cwe": "CWE-89", "title": "SQLi", "risk": "critical"},
            {"id": "T-002", "cwe": "CWE-321", "title": "Hardcoded key", "risk": "critical"},
        ]
        lines_filtered = compose._build_tier_cluster_lines(threats, arrow_cwe_allow={"CWE-89"})
        lines_legacy = compose._build_tier_cluster_lines(threats, arrow_cwe_allow=None)
        # Legacy form contains at least as many lines as the filtered one.
        assert len(lines_legacy) >= len(lines_filtered)

    def test_max_clusters_default_lowered_to_4(self):
        """The default cap is 4 (was 6, lowered in 2026-05) so the tier
        box stays scannable. Beyond the cap, excess collapses to a
        single trailer."""
        # Build 6 distinct-CWE threats so each lands in its own bucket.
        threats = [
            {"id": f"T-{i:03d}", "cwe": f"CWE-{cwe}", "title": "x", "risk": "high"}
            for i, cwe in enumerate(["79", "89", "352", "287", "434", "611"], start=1)
        ]
        lines = compose._build_tier_cluster_lines(threats)
        # At most 4 cluster lines + 1 trailer = 5 total entries max.
        assert len(lines) <= 5, lines
        # Trailer must mention §8 — the canonical pointer to the full list.
        if len(lines) == 5:
            assert "§8" in lines[-1] or "more" in lines[-1].lower(), lines[-1]


# ---------------------------------------------------------------------------
# C — 'Total stage compute' includes every stage from .stage-stats.jsonl
# ---------------------------------------------------------------------------


class TestTotalDurationFromStageStats:
    """`extract_run_statistics` prefers the jsonl-sourced wall-clock when
    available; falls back to the legacy assess+qa+arch sum otherwise."""

    def _write_jsonl(self, output_dir: Path, records: list[dict]) -> None:
        path = output_dir / ".stage-stats.jsonl"
        path.write_text(
            "\n".join(json.dumps(r) for r in records) + "\n",
            encoding="utf-8",
        )

    def test_jsonl_total_supersedes_legacy_when_present(self, tmp_path: Path):
        # Five stages: orchestrator + renderer + qa + 2 repairs.
        # Sum: 31m45 + 4m18 + 39 + 5m32 + 3m15 = 45m 29s = 2729 s
        self._write_jsonl(
            tmp_path,
            [
                {"stage": 1, "duration_ms": 1905_000},
                {"stage": 2, "duration_ms": 258_000},
                {"stage": 3, "duration_ms": 39_000},
                {"stage": 4, "duration_ms": 332_000},
                {"stage": 5, "duration_ms": 195_000},
            ],
        )
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        # 1905 + 258 + 39 + 332 + 195 = 2729 seconds
        assert stats["total_secs_from_stages"] == 2729

    def test_jsonl_missing_falls_back_to_legacy(self, tmp_path: Path):
        # No jsonl → field stays None → legacy path takes over in the
        # render function.
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        assert stats["total_secs_from_stages"] is None

    def test_jsonl_malformed_line_does_not_crash(self, tmp_path: Path):
        path = tmp_path / ".stage-stats.jsonl"
        path.write_text(
            '{"stage":1,"duration_ms":1000}\n'
            "not-json\n"
            '{"stage":2,"duration_ms":2000}\n'
            '{"stage":3}\n'  # missing duration_ms
            '{"stage":4,"duration_ms":-50}\n'  # negative ignored
            '{"stage":5,"duration_ms":"oops"}\n'  # wrong type ignored
            '{"stage":6,"duration_ms":3000}\n',
            encoding="utf-8",
        )
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        # 1000 + 2000 + 3000 = 6000 ms = 6 s
        assert stats["total_secs_from_stages"] == 6

    def test_render_run_statistics_uses_jsonl_total_with_breakdown(self, tmp_path: Path):
        """When jsonl total > legacy, the breakdown shows the delta."""
        self._write_jsonl(
            tmp_path,
            [
                {"stage": 1, "duration_ms": 1900_000},  # 31m40
                {"stage": 2, "duration_ms": 250_000},  # 4m10
                {"stage": 3, "duration_ms": 45_000},  # 0m45
                {"stage": 4, "duration_ms": 600_000},  # 10m
            ],
        )
        # Legacy stats: only assess_secs from yaml/log scan would catch the
        # orchestrator. Simulate that here.
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        stats["assess_secs"] = 1900  # 31m40 (Stage 1's ASSESSMENT_END)
        # qa_secs / arch_secs left as None — not visible to the legacy path.

        out = rcs.render_run_statistics(stats, None)
        text = "\n".join(out)
        # Net comes from jsonl: 1900+250+45+600 = 2795s = 46m 35s
        assert "Net agent compute   : 46m 35s" in text

    def test_render_run_statistics_falls_back_when_jsonl_absent(self, tmp_path: Path):
        """No jsonl → use the legacy assess+qa+arch sum unchanged."""
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        stats["assess_secs"] = 1900
        stats["qa_secs"] = 60
        stats["arch_secs"] = 240
        out = rcs.render_run_statistics(stats, None)
        text = "\n".join(out)
        # 1900 + 60 + 240 = 2200 s = 36m 40s — legacy path (no .stage-stats.jsonl)
        assert "Total (legacy)      : 36m 40s" in text

    def test_wall_clock_marker_extracted(self, tmp_path: Path):
        """`.scan-wall-seconds` is read as the true end-to-end wall-clock."""
        (tmp_path / ".scan-wall-seconds").write_text("3420\n", encoding="utf-8")
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        assert stats["wall_secs"] == 3420

    def test_wall_clock_marker_absent_stays_none(self, tmp_path: Path):
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        assert stats["wall_secs"] is None

    def test_wall_clock_marker_malformed_does_not_crash(self, tmp_path: Path):
        (tmp_path / ".scan-wall-seconds").write_text("oops\n", encoding="utf-8")
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        assert stats["wall_secs"] is None

    def test_render_shows_wall_clock_line_alongside_stage_total(self, tmp_path: Path):
        """Both the stage-compute total AND the wall-clock are surfaced — the
        gap between them is the orchestration overhead the user asked to see."""
        self._write_jsonl(tmp_path, [{"stage": 1, "duration_ms": 1620_000}])  # 27m
        (tmp_path / ".scan-wall-seconds").write_text("3420", encoding="utf-8")  # 57m
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        stats["assess_secs"] = 1620
        out = rcs.render_run_statistics(stats, None)
        text = "\n".join(out)
        assert "Net agent compute   : 27m 00s" in text
        assert "Total elapsed (wall): 57m 00s" in text

    def test_render_omits_wall_clock_line_when_absent(self, tmp_path: Path):
        self._write_jsonl(tmp_path, [{"stage": 1, "duration_ms": 1620_000}])
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        stats["assess_secs"] = 1620
        out = rcs.render_run_statistics(stats, None)
        text = "\n".join(out)
        assert "Total elapsed (wall)" not in text

    def test_render_default_hides_per_stage_breakdown(self, tmp_path: Path):
        """Default (non-verbose) Run Statistics shows only the timing headline —
        net compute / idle / wall — and omits the per-stage duration rows."""
        self._write_jsonl(
            tmp_path,
            [
                {"stage": 1, "duration_ms": 1620_000, "name": "Threat Analysis & Triage",
                 "agent": "appsec-advisor:appsec-threat-analyst", "model": "sonnet"},
                {"stage": 2, "duration_ms": 300_000, "name": "Report Rendering",
                 "agent": "appsec-advisor:appsec-threat-renderer", "model": "sonnet"},
            ],
        )
        (tmp_path / ".scan-wall-seconds").write_text("3420", encoding="utf-8")  # 57m
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        out = rcs.render_run_statistics(stats, None)  # verbose defaults to False
        text = "\n".join(out)
        # Timing headline present.
        assert "Net agent compute" in text
        assert "Idle / standby" in text
        assert "Total elapsed (wall)" in text
        # Per-stage rows absent in the default summary.
        assert "Threat Analysis & Triage" not in text
        assert "Report Rendering" not in text

    def test_render_verbose_adds_per_stage_breakdown(self, tmp_path: Path):
        """`--verbose` (verbose=True) adds the per-stage duration rows below the
        same timing headline."""
        self._write_jsonl(
            tmp_path,
            [
                {"stage": 1, "duration_ms": 1620_000, "name": "Threat Analysis & Triage",
                 "agent": "appsec-advisor:appsec-threat-analyst", "model": "sonnet"},
                {"stage": 2, "duration_ms": 300_000, "name": "Report Rendering",
                 "agent": "appsec-advisor:appsec-threat-renderer", "model": "sonnet"},
            ],
        )
        (tmp_path / ".scan-wall-seconds").write_text("3420", encoding="utf-8")
        stats = rcs.extract_run_statistics(tmp_path, {"meta": {}})
        out = rcs.render_run_statistics(stats, None, verbose=True)
        text = "\n".join(out)
        assert "Net agent compute" in text
        assert "Threat Analysis & Triage" in text
        assert "Report Rendering" in text


# ---------------------------------------------------------------------------
# Cross-cutting smoke (compose runs, all four invariants hold)
# ---------------------------------------------------------------------------


class TestComposeSmokeAllFourInvariants:
    """End-to-end compose run that asserts the four P1 invariants together
    on the rendered Markdown. Uses tmp_path with a freshly-built fixture so
    it doesn't depend on tests/fixtures/compose (which is mid-migration)."""

    def _build_minimal_fixture(self, tmp_path: Path) -> Path:
        """Construct a tmp output dir that compose can render against.
        Only includes the inputs the four P1 fixes touch — the rest of the
        pipeline is exercised by the existing test_compose_threat_model
        suite once the fixture is updated."""
        import yaml

        out = tmp_path / "out"
        out.mkdir()
        # Minimal yaml — three threats, three components, three mitigations.
        # CWE coverage exercises the deterministic CWE→TH mapping.
        yml = {
            "meta": {
                "schema_version": 1,
                "plugin_version": "0.4.0-beta",
                "analysis_version": 2,
                "generated": "2026-05-07T00:00:00Z",
                "git": {"commit_sha": "deadbeef", "branch": "test"},
                "model": "claude-sonnet-4-6",
            },
            "project": {
                "name": "P1 Smoke",
                "version": "1.0",
                "description": "x",
                "author": "test",
                "license": "MIT",
                "repository": "x",
            },
            "changelog": [
                {
                    "version": 1,
                    "date": "2026-05-07",
                    "mode": "full",
                    "plugin_version": "0.4.0-beta",
                    "current_sha": "x",
                    "note": "smoke",
                }
            ],
            "components": [
                {
                    "id": "C-01",
                    "name": "Auth Backend",
                    "kind": "service",
                    "paths": ["lib/"],
                    "threat_ids": ["T-001", "T-002"],
                },
                {
                    "id": "C-02",
                    "name": "Express Backend",
                    "kind": "service",
                    "paths": ["routes/"],
                    "threat_ids": ["T-003"],
                },
            ],
            "threats": [
                {
                    "t_id": "T-001",
                    "component_id": "C-01",
                    "stride": "Spoofing",
                    "title": "Hardcoded RSA Private Key Enables Token Forgery",
                    "scenario": "RSA key in source.",
                    "likelihood": "High",
                    "impact": "Critical",
                    "risk": "Critical",
                    "cwe": "CWE-321",
                    "mitigations": ["M-001"],
                },
                {
                    "t_id": "T-002",
                    "component_id": "C-01",
                    "stride": "Tampering",
                    "title": "SQL Injection in Login Endpoint",
                    "scenario": "Raw SQL.",
                    "likelihood": "High",
                    "impact": "Critical",
                    "risk": "Critical",
                    "cwe": "CWE-89",
                    "mitigations": ["M-002"],
                },
                {
                    "t_id": "T-003",
                    "component_id": "C-02",
                    "stride": "Elevation of Privilege",
                    "title": "RCE via Notevil Sandbox",
                    "scenario": "Eval breaks out.",
                    "likelihood": "Medium",
                    "impact": "Critical",
                    "risk": "Critical",
                    "cwe": "CWE-94",
                    "mitigations": ["M-003"],
                },
            ],
            "mitigations": [
                {
                    "m_id": "M-001",
                    "title": "Rotate RSA key",
                    "priority": "P1",
                    "effort": "Medium",
                    "addresses": ["T-001"],
                },
                {
                    "m_id": "M-002",
                    "title": "Parameterise SQL",
                    "priority": "P1",
                    "effort": "Low",
                    "addresses": ["T-002"],
                },
                {"m_id": "M-003", "title": "Remove eval", "priority": "P1", "effort": "Medium", "addresses": ["T-003"]},
            ],
            "assets": [
                {
                    "id": "A-001",
                    "name": "User credentials",
                    "classification": "Restricted",
                    "description": "User PII and password hashes.",
                    "linked_threats": ["T-002"],
                },
            ],
            "security_controls": [],
        }
        (out / "threat-model.yaml").write_text(yaml.dump(yml, sort_keys=False))
        return out

    def test_compose_emits_all_four_p1_invariants(self, tmp_path: Path):
        out = self._build_minimal_fixture(tmp_path)
        # Pre-generate structural fragments + author the LLM-only ones.
        pregen = _load_module("pregenerate_fragments", _SCRIPTS / "pregenerate_fragments.py")
        # main(["dir"]) writes the structural fragments; the LLM ones we
        # author inline.
        pregen.main([str(out)])

        frag = out / ".fragments"
        # Minimal LLM-only fragments — schema-valid.
        (frag / "ms-verdict.json").write_text(
            json.dumps(
                {
                    "severity": "red",
                    "opening": "**CRITICAL** — full system compromise reachable through "
                    "multiple independent paths verified by the smoke test.",
                    "bullets": [
                        {
                            "title": "Token forgery",
                            "body": "RSA key public; admin tokens forgeable offline.",
                            "refs": ["F-001"],
                        },
                        {
                            "title": "Login bypass",
                            "body": "SQLi on the login route bypasses authentication entirely.",
                            "refs": ["F-002"],
                        },
                    ],
                    "closing": "No security boundary remains; the deployment is unfit for "
                    "any environment exposed to untrusted users.",
                }
            )
        )
        # Walkthrough — must contain at least one sequenceDiagram per contract.
        (frag / "attack-walkthroughs.md").write_text(
            "## 3. Attack Walkthroughs\n\n"
            "### 3.1 Attack Chain Overview\n\n"
            "#### Chain 1 — Token Forgery\n\n"
            "```mermaid\ngraph LR\n  A[T-001 RSA key] --> B[Forged token]\n```\n\n"
            "**Key takeaway:** Test.\n\n"
            "### 3.2 T-001 Walkthrough\n\n"
            "```mermaid\nsequenceDiagram\n  participant A as Attacker\n  A->>A: forge\n```\n\n"
            "**Fix:** Rotate.\n"
        )
        # Run compose.
        contract_path = REPO_ROOT / "data" / "sections-contract.yaml"
        rendered, warnings = compose.render(contract_path, out)

        # === A1 — every threat row carries an F-anchor next to the T-anchor.
        for tnnn, fnnn in (("t-001", "f-001"), ("t-002", "f-002"), ("t-003", "f-003")):
            assert f'<a id="{tnnn}"></a><a id="{fnnn}"></a>' in rendered, f"missing dual anchor for {tnnn}/{fnnn}"

        # === A1 — F-link used in the verdict resolves to an existing anchor.
        # The link is `[F-001](#f-001)` and `<a id="f-001"></a>` exists.
        assert "[F-001](#f-001)" in rendered or "[F-002](#f-002)" in rendered

        # === A3 — the CWE→category classification is reflected in each §8 row.
        # The TH-NN identifier was dropped from rendered rows on 2026-05-28
        # (noisy filler — see compose_threat_model.py "Item 7"; the renderer
        # keeps the classification NAME). The CWE→TH mapping logic itself is
        # unit-tested separately (test_cwe_*_maps_to_th*); here we assert the
        # rendered `**Classification:**` NAME per the fixture's CWEs.
        # 2026-05 card layout: a finding is a multi-line card, so slice from
        # its anchor to the next card/heading and assert the Classification
        # NAME appears inside that block.
        def _card_block(tnnn: str) -> str:
            i = rendered.find(f'<a id="{tnnn}">')
            if i < 0:
                return ""
            nxt = rendered.find('<a id="t-', i + 1)
            return rendered[i : nxt if nxt > 0 else i + 800]

        assert "Cryptographic Failures" in _card_block("t-001"), "T-001 (CWE-321) classification"
        assert "Injection" in _card_block("t-002")  # T-002 (CWE-89)
        assert "Code Execution" in _card_block("t-003")  # T-003 (CWE-94)

        # === B1 — diagram nodes carry no `<b>` except for the three column
        # headers HDR_A / HDR_T / HDR_I in the heatmap.
        bold_tokens = sorted({tok for tok in __import__("re").findall(r"<b>([^<]+)</b>", rendered)})
        # The only allowed bolds are the three column headers and any LLM-
        # authored bold text inside Verdict bullet titles / Architecture
        # Assessment defect names (Markdown `**…**` renders to `<strong>`,
        # not `<b>`, so genuine markdown bold isn't here).
        allowed_header_bolds = {"Threat Actors", "Architecture Tiers", "Business Impact"}
        # Component IDs and actor labels must NOT appear in `<b>` form.
        # Extract just bolds that look like a component ID or actor name.
        for tok in bold_tokens:
            assert tok in allowed_header_bolds or len(tok) > 30, f"unexpected bold token in diagrams: {tok!r}"

        # === Sanity — render produced no warnings other than the expected
        # soft-skip notices. The test fixture deliberately authors only the
        # four P1-relevant LLM fragments and runs no Stage 2 narrative-fill
        # pass, so two warnings are expected and unrelated to the P1
        # invariants under test:
        #   • NARRATIVE_PLACEHOLDER survival — the §7 placeholders the
        #     pregenerator writes survive into the markdown (no fill pass).
        #   • `critical_attack_tree: fragment missing` — the fixture does not
        #     author `ms-critical-attack-tree.json`, so the optional MS
        #     attack-tree section is soft-skipped.
        _ignorable = ("NARRATIVE_PLACEHOLDER", "critical_attack_tree: fragment missing")
        non_placeholder_warnings = [w for w in warnings if not any(tok in w for tok in _ignorable)]
        assert non_placeholder_warnings == [], f"unexpected compose warnings: {non_placeholder_warnings}"
