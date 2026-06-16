"""Coverage-pushing tests for scripts/compose_threat_model.py (round 3).

Targets the largest still-uncovered render/helper branches. Test files ONLY;
pins current behavior. Companion to test_compose_threat_model_cov{,2}.py.
"""

from __future__ import annotations

import importlib.util
import json as _json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


compose = _load_module("compose_threat_model", SCRIPT_PATH)


def _mk_ctx(tmp_path, **kw):
    out_dir = tmp_path / "out"
    out_dir.mkdir(exist_ok=True)
    frag = out_dir / ".fragments"
    frag.mkdir(exist_ok=True)
    defaults = dict(
        output_dir=out_dir,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag,
    )
    defaults.update(kw)
    return compose.RenderContext(**defaults)


# ---------------------------------------------------------------------------
# _component_max_severity
# ---------------------------------------------------------------------------


class TestComponentMaxSeverity:
    def test_no_threats_returns_none(self):
        key, counts = compose._component_max_severity("api", {})
        assert key == "none"
        assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}

    def test_picks_highest_present(self):
        by_comp = {
            "api": [
                {"risk": "Medium"},
                {"severity": "Critical"},
                {"risk": "low"},
                {"risk": "bogus"},  # not in counts -> ignored
            ]
        }
        key, counts = compose._component_max_severity("api", by_comp)
        assert key == "critical"
        assert counts["critical"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1

    def test_high_when_no_critical(self):
        key, counts = compose._component_max_severity("api", {"api": [{"risk": "high"}, {"risk": "medium"}]})
        assert key == "high"


# ---------------------------------------------------------------------------
# _format_finding_link
# ---------------------------------------------------------------------------


class TestFormatFindingLink:
    def test_none_no_fid(self):
        assert compose._format_finding_link(None) == ""

    def test_with_title(self):
        out = compose._format_finding_link({"id": "F-001", "title": "SQLi"})
        assert out == "[F-001 — SQLi](#f-001)"

    def test_title_pipe_and_newline_escaped(self):
        out = compose._format_finding_link({"id": "F-002", "title": "a|b\nc"})
        assert out == "[F-002 — a\\|b c](#f-002)"

    def test_no_title_falls_back(self):
        out = compose._format_finding_link({"t_id": "F-003"})
        assert out == "[F-003](#f-003)"

    def test_scenario_short_used_as_title(self):
        out = compose._format_finding_link({"id": "F-004", "scenario_short": "Recon"})
        assert out == "[F-004 — Recon](#f-004)"

    def test_explicit_fid_arg_wins(self):
        out = compose._format_finding_link({}, fid="F-009")
        assert out == "[F-009](#f-009)"


# ---------------------------------------------------------------------------
# _build_ms_abuse_chain_line
# ---------------------------------------------------------------------------


class TestBuildMsAbuseChainLine:
    def test_no_file(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        assert compose._build_ms_abuse_chain_line(ctx) == ""

    def test_malformed_json(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.fragments_dir / "abuse-cases.json").write_text("{bad", encoding="utf-8")
        assert compose._build_ms_abuse_chain_line(ctx) == ""

    def test_no_actionable_verdicts(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.fragments_dir / "abuse-cases.json").write_text(
            _json.dumps({"abuse_cases": [{"id": "AC-1", "chain_verdict": "blocked"}]}),
            encoding="utf-8",
        )
        assert compose._build_ms_abuse_chain_line(ctx) == ""

    def test_viable_and_partial(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.fragments_dir / "abuse-cases.json").write_text(
            _json.dumps(
                {
                    "abuse_cases": [
                        {"id": "AC-1", "chain_verdict": "fully_viable"},
                        {"id": "AC-2", "chain_verdict": "partially_blocked"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        out = compose._build_ms_abuse_chain_line(ctx)
        assert "Verified attack chains" in out
        assert "1 fully viable" in out
        assert "1 partially blocked" in out
        assert "[AC-1](#ac-1)" in out
        assert "§9 Abuse Cases" in out


# ---------------------------------------------------------------------------
# _render_title — fallback to meta plugin_version when live meta unreadable
# ---------------------------------------------------------------------------


class TestRenderTitleMetaFallback:
    def test_meta_plugin_version_used(self, tmp_path, monkeypatch):
        monkeypatch.setattr(compose, "_read_live_plugin_meta", lambda: (None, None))
        ctx = _mk_ctx(
            tmp_path,
            contract={"document": {"title_template": "TM — {{ project.name }}"}},
            yaml_data={
                "project": {"name": "Acme"},
                "meta": {"plugin_version": "9.9.9", "analysis_version": 2},
            },
        )
        out = compose._render_title(ctx)
        assert out.startswith("# TM — Acme")
        assert "appsec-advisor v9.9.9" in out
        assert "analysis v2" in out

    def test_no_plugin_version_title_only(self, tmp_path, monkeypatch):
        monkeypatch.setattr(compose, "_read_live_plugin_meta", lambda: (None, None))
        ctx = _mk_ctx(
            tmp_path,
            contract={"document": {"title_template": "TM"}},
            yaml_data={"meta": {}},
        )
        out = compose._render_title(ctx)
        assert out == "# TM\n"

    def test_live_meta_exception_swallowed(self, tmp_path, monkeypatch):
        def _boom():
            raise RuntimeError("nope")

        monkeypatch.setattr(compose, "_read_live_plugin_meta", _boom)
        ctx = _mk_ctx(
            tmp_path,
            contract={"document": {"title_template": "TM"}},
            yaml_data={"meta": {"plugin_version": "1.2.3"}},
        )
        out = compose._render_title(ctx)
        assert "appsec-advisor v1.2.3" in out


# ---------------------------------------------------------------------------
# _render_identified_actors — inputs_questioned + discovery file branches
# ---------------------------------------------------------------------------


class TestRenderIdentifiedActorsExtra:
    def test_inputs_questioned_section(self, tmp_path):
        ctx = _mk_ctx(
            tmp_path,
            yaml_data={"threats": [{"component": "API", "actor_ids": ["ACT-01"]}]},
        )
        (ctx.output_dir / ".actors-resolved.json").write_text(
            _json.dumps(
                {
                    "resolved_actors": [
                        {
                            "id": "ACT-01",
                            "label": "User",
                            "_provenance": {"active": True, "layer": "client"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (ctx.output_dir / ".actors-discovered.json").write_text(
            _json.dumps(
                {
                    "inputs_questioned": [
                        {
                            "id": "ACT-QQ",
                            "reason": "no plausible reach",
                            "recommendation": "disable",
                        },
                        {"id": "ACT-RR", "reason": "unused"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        out = compose._render_identified_actors(ctx, None, {})
        assert "Actors flagged for review" in out
        assert "ACT-QQ" in out
        assert "(recommendation: disable)" in out
        assert "ACT-RR" in out

    def test_discovery_file_malformed_swallowed(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"threats": []})
        (ctx.output_dir / ".actors-resolved.json").write_text(
            _json.dumps({"resolved_actors": [{"id": "ACT-01", "label": "U", "_provenance": {"active": True}}]}),
            encoding="utf-8",
        )
        (ctx.output_dir / ".actors-discovered.json").write_text("{bad", encoding="utf-8")
        out = compose._render_identified_actors(ctx, None, {})
        # Malformed discovery file -> no "flagged for review" section but render OK.
        assert "Actors flagged for review" not in out
        assert "ACT-01" in out


# ---------------------------------------------------------------------------
# _render_operational_strengths — legacy per-control fallback path
# ---------------------------------------------------------------------------


_REQ_YAML = "categories:\n  - name: Auth\n    requirements:\n      - id: SEC-AUTH-1\n        url: https://ex/1\n"


class TestOperationalStrengthsLegacyPath:
    def _ctx_env(self, tmp_path, **kw):
        ctx = _mk_ctx(tmp_path, **kw)
        env = compose._build_jinja_env(ctx)
        return ctx, env

    def test_legacy_rows_with_gap_and_mitigates(self, tmp_path, monkeypatch):
        # Force the legacy (non-cluster) branch.
        monkeypatch.setattr(compose, "_build_strength_clusters", lambda *a, **k: [])
        contract = {
            "sections": {
                "operational_strengths": {
                    "table": {"rows": {"max": 8}},
                }
            }
        }
        yaml_data = {
            "security_controls": [
                {
                    "architectural_control": "Rate Limiting",
                    "implementation": "express-rate-limit on /rest/user/login only",
                    "effectiveness": "partial",
                    "mitigates_findings": ["T-001"],
                },
                {
                    "control": "Input Validation",
                    "implementation": {"description": "joi schema on body"},
                    "effectiveness": "adequate",
                    "gap": "None — fully covered",
                },
            ],
            "threats": [
                {"id": "T-001", "title": "Brute force login", "risk": "high"},
            ],
        }
        ctx, env = self._ctx_env(tmp_path, contract=contract, yaml_data=yaml_data)
        ctx.eval_context["verdict_severity"] = "red"
        out = compose._render_operational_strengths(ctx, env, {})
        # Gap derived from the "only" qualifier in the implementation string.
        assert "Only" in out or "only" in out.lower()
        assert "Rate Limiting" in out

    def test_legacy_implementation_fallback_chain(self, tmp_path, monkeypatch):
        monkeypatch.setattr(compose, "_build_strength_clusters", lambda *a, **k: [])
        contract = {"sections": {"operational_strengths": {"table": {"rows": {"max": 8}}}}}
        yaml_data = {
            "security_controls": [
                {
                    "architectural_control": "Logging",
                    # No implementation -> falls back to description -> evidence.
                    "description": "structured audit log",
                    "effectiveness": "weak",
                }
            ],
            "threats": [],
        }
        ctx, env = self._ctx_env(tmp_path, contract=contract, yaml_data=yaml_data)
        out = compose._render_operational_strengths(ctx, env, {})
        assert "Logging" in out


# ---------------------------------------------------------------------------
# _build_requirements_mapping_rows — evidence-fid override path (§7b table)
# ---------------------------------------------------------------------------


class TestRequirementsMappingEvidencePath:
    def test_compliance_fragment_supplies_finding_edge(self, tmp_path):
        ctx = _mk_ctx(
            tmp_path,
            yaml_data={
                "threats": [
                    {
                        "id": "T-001",
                        "risk": "Critical",
                        "violated_requirements": ["SEC-AUTH-1"],
                        "mitigations": ["M-001"],
                    },
                    {
                        "id": "T-002",
                        "risk": "High",
                        "mitigation_ids": ["M-009"],
                    },
                ],
                "mitigations": [{"id": "M-002", "fulfills_requirements": ["SEC-AUTH-1"]}],
            },
        )
        (ctx.output_dir / ".requirements.yaml").write_text(_REQ_YAML, encoding="utf-8")
        # Compliance fragment table citing F-002 for SEC-AUTH-1 -> evidence edge
        # overrides the threat-derived finding row (7864-7882 path).
        frag = "| Requirement | Status | Evidence |\n| --- | --- | --- |\n| SEC-AUTH-1 | FAIL | F-002 |\n"
        (ctx.fragments_dir / "requirements-compliance.md").write_text(frag, encoding="utf-8")
        rows = compose._build_requirements_mapping_rows(ctx)
        assert rows
        r = rows[0]
        assert r["req_id"] == "SEC-AUTH-1"
        # Evidence-cited finding wins over violated_requirements link.
        assert ("F-002", "high") in r["findings"]
        # Reverse mitigation link re-applied after evidence correction.
        assert "M-002" in r["measures"]


# ---------------------------------------------------------------------------
# _escape_dot_tld_identifiers — all three substitution branches
# ---------------------------------------------------------------------------


class TestEscapeDotTldIdentifiers:
    def test_known_name_backslash_escaped(self):
        out = compose._escape_dot_tld_identifiers("Runs on Node.js here.")
        # Known brand → backslash-escape the dot (not backticks).
        assert "Node\\.js" in out

    def test_file_extension_left_alone(self):
        out = compose._escape_dot_tld_identifiers("see config.py for details")
        assert "config.py" in out
        assert "`config.py`" not in out

    def test_unknown_cctld_backtick_wrapped(self):
        out = compose._escape_dot_tld_identifiers("token sanitizer.by leaks")
        assert "`sanitizer.by`" in out

    def test_fenced_and_inline_code_skipped(self):
        md = "```\nNode.js\n```\nand `req.bo` inline"
        out = compose._escape_dot_tld_identifiers(md)
        # Inside fence / existing inline code → untouched (idempotent).
        assert "```\nNode.js\n```" in out
        assert "`req.bo`" in out


# ---------------------------------------------------------------------------
# _inject_security_architecture_links.linkify_line — all ref-count branches
# ---------------------------------------------------------------------------


class TestInjectSecurityArchitectureLinks:
    def test_none_marker_replaced(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        out = compose._inject_security_architecture_links(ctx, "**Linked threats:** (none)\n")
        assert "None identified." in out

    def test_single_ref_linkified(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"threats": [{"id": "T-001", "title": "X"}]})
        out = compose._inject_security_architecture_links(ctx, "**Linked threats:** T-001\n")
        assert "#" in out  # linkified anchor present
        assert "- [" not in out  # single ref → no bullet list

    def test_multi_ref_bullet_list(self, tmp_path):
        ctx = _mk_ctx(
            tmp_path,
            yaml_data={"threats": [{"id": "T-001", "title": "A"}, {"id": "T-002", "title": "B"}]},
        )
        out = compose._inject_security_architecture_links(ctx, "**Linked threats:** T-001, T-002\n")
        assert "- [" in out  # bullet list form

    def test_no_ids_line_unchanged(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        src = "**Linked threats:** see appendix\n"
        out = compose._inject_security_architecture_links(ctx, src)
        # No F/T/M-NNN ids → line preserved verbatim.
        assert "see appendix" in out


# ---------------------------------------------------------------------------
# _render_markdown_fragment — forbidden subsection strip
# ---------------------------------------------------------------------------


class TestRenderMarkdownFragmentForbidden:
    def test_forbidden_subsection_stripped(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        frag_body = (
            "## 2. System Decomposition\n\n"
            "Intro prose.\n\n"
            "### 2.5 Security Architecture Assessment\n\n"
            "This belongs in section 7.\n\n"
            "### 2.6 Trust Boundaries\n\n"
            "Boundary prose.\n"
        )
        (ctx.fragments_dir / "decomposition.md").write_text(frag_body, encoding="utf-8")
        section = {
            "fragment": "decomposition.md",
            "heading": "## 2. System Decomposition",
            "forbidden_subsection_patterns": [r"2\.5 Security Architecture"],
        }
        out = compose._render_markdown_fragment(ctx, "decomposition", section)
        assert "Security Architecture Assessment" not in out
        assert "This belongs in section 7." not in out
        # Sibling content preserved.
        assert "2.6 Trust Boundaries" in out
        assert any("stripped forbidden subsection" in w for w in ctx.warnings)

    def test_heading_mismatch_raises(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.fragments_dir / "bad.md").write_text("## Wrong Heading\n\nbody\n", encoding="utf-8")
        section = {"fragment": "bad.md", "heading": "## 2. System Decomposition"}
        with pytest.raises(compose.FragmentError):
            compose._render_markdown_fragment(ctx, "decomposition", section)


# ---------------------------------------------------------------------------
# _toc_children_for_section — required_subsections + pattern-scan branch
# ---------------------------------------------------------------------------


class TestTocChildrenForSection:
    def test_required_subsections_and_tier_filter(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        frag = ctx.fragments_dir / "sec.md"
        frag.write_text(
            "## 7. Security Architecture\n\n### 7.1 Validation\n\nbody\n",
            encoding="utf-8",
        )
        sec = {
            "fragment": "sec.md",
            "required_subsections": [
                "management_summary",  # string → skipped
                {"title": "7.1 Validation"},
                {"title": "7.9 Tier-B Thing", "tier": "b"},  # absent in frag → dropped
            ],
        }
        children = compose._toc_children_for_section(ctx, "security_architecture", sec)
        titles = [c["title"] for c in children]
        assert any("Validation" in t for t in titles)
        assert not any("Tier-B" in t for t in titles)

    def test_required_subsection_patterns_scan(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        frag = ctx.fragments_dir / "sec.md"
        frag.write_text(
            "## 7. Security Architecture\n\n"
            "### 7.13 Defense-in-Depth (cross-cutting)\n\nbody\n"
            "### 7.99 Unmatched Heading\n\nbody\n",
            encoding="utf-8",
        )
        sec = {
            "fragment": "sec.md",
            "required_subsection_patterns": [
                {"level": 3, "pattern": r"7\.13 Defense-in-Depth"},
            ],
        }
        children = compose._toc_children_for_section(ctx, "security_architecture", sec)
        titles = [c["title"] for c in children]
        assert any("Defense-in-Depth" in t for t in titles)
        assert not any("Unmatched" in t for t in titles)

    def test_threat_register_sub_sections(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        sec = {
            "sub_sections": [
                {"heading": "## 8.A Categories at a glance"},
                {"heading": "## 8.E Low Categories ({count})", "conditional": "has_low"},
            ]
        }
        ctx.eval_context["has_low"] = False
        children = compose._toc_children_for_section(ctx, "threat_register", sec)
        titles = [c["title"] for c in children]
        assert any("Categories at a glance" in t for t in titles)
        # Conditional 8.E dropped (has_low False).
        assert not any("Low Categories" in t for t in titles)


# ---------------------------------------------------------------------------
# _wrap_inline_code — trailing-punctuation + keep-chunk branches
# ---------------------------------------------------------------------------


class TestWrapInlineCode:
    def test_empty_passthrough(self):
        assert compose._wrap_inline_code("") == ""

    def test_existing_inline_code_kept_verbatim(self):
        src = "Run `npm install foo` now"
        assert compose._wrap_inline_code(src) == src

    def test_http_method_path_wrapped_with_trailing_punct(self):
        out = compose._wrap_inline_code("Send POST /rest/user/login.")
        # Token wrapped; trailing period pushed outside the code span.
        assert "`POST /rest/user/login`." in out

    def test_file_extension_dot_kept_inside(self):
        out = compose._wrap_inline_code("See lib/insecurity.ts here")
        assert "`lib/insecurity.ts`" in out

    def test_fenced_block_untouched(self):
        src = "```\nPOST /x\n```\nthen safeEval here"
        out = compose._wrap_inline_code(src)
        assert "```\nPOST /x\n```" in out
        assert "`safeEval`" in out


# ---------------------------------------------------------------------------
# _compute_top_findings_rows — scenario-fallback title + name-resolved comp
# ---------------------------------------------------------------------------


def _top_findings_contract():
    return {"sections": {"top_findings": {"table": {"rows": {"max": 5}}}}}


class TestComputeTopFindingsScenarioFallback:
    def test_scenario_first_sentence_title_and_name_component(self, tmp_path):
        threats = [
            {
                "id": "T-010",
                # No title/scenario_short -> scenario first sentence used.
                "scenario": "Attacker forges a token. Then escalates.",
                "component": "Auth Service",  # bare-string -> name lookup
                "risk": "Critical",
            }
        ]
        components = [{"id": "C-07", "name": "Auth Service"}]
        ctx = _mk_ctx(
            tmp_path,
            contract=_top_findings_contract(),
            yaml_data={"threats": threats, "components": components},
        )
        rows, total = compose._compute_top_findings_rows(ctx)
        assert total == 1
        r = rows[0]
        assert "Attacker forges a token" in r["finding_title"]
        assert r["component_name"] == "Auth Service"

    def test_scenario_empty_falls_back_to_tid(self, tmp_path):
        threats = [{"id": "T-011", "risk": "High"}]
        ctx = _mk_ctx(
            tmp_path,
            contract=_top_findings_contract(),
            yaml_data={"threats": threats},
        )
        rows, total = compose._compute_top_findings_rows(ctx)
        assert total == 1
        # No title and no scenario -> tid used as the title.
        assert "T-011" in rows[0]["finding_title"] or rows[0]["finding_id"] == "F-011"

    def test_mitigation_title_freetext_fallback(self, tmp_path):
        threats = [
            {
                "id": "T-012",
                "title": "Open redirect",
                "risk": "High",
                "mitigation_title": "Validate the redirect target against an allowlist",
            }
        ]
        ctx = _mk_ctx(
            tmp_path,
            contract=_top_findings_contract(),
            yaml_data={"threats": threats},
        )
        rows, total = compose._compute_top_findings_rows(ctx)
        assert total == 1
        # Free-text mitigation_title surfaced in the mitigations cell.
        actions = [m.get("action", "") for m in rows[0]["mitigations"]]
        assert any("allowlist" in a for a in actions)


# ---------------------------------------------------------------------------
# _load_attack_paths_fragment — valid-fragment success/reconcile path
# ---------------------------------------------------------------------------


class TestLoadAttackPathsFragmentSuccess:
    def test_valid_fragment_loaded_and_reconciled(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        frag = {
            "schema_version": 1,
            "actors": ["internet-anon"],
            "attack_paths": [
                {
                    "class": "injection",
                    "actor": "internet-anon",
                    "target": "data",
                    "description": "Injection lets an attacker reach and read the application database.",
                    "impact": ["customer-data-exfiltration"],
                    "findings": ["F-001"],
                }
            ],
        }
        (ctx.fragments_dir / "security-posture-attack-paths.json").write_text(_json.dumps(frag), encoding="utf-8")
        taxonomy = compose._load_attack_class_taxonomy()
        out = compose._load_attack_paths_fragment(ctx, taxonomy, [])
        # Returned the LLM fragment (not the derived fallback): preserves
        # the _llm_target stamp and the actors list.
        assert out["attack_paths"]
        assert out["attack_paths"][0].get("_llm_target") == "data"
        assert "actors" in out

    def test_malformed_json_falls_back(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.fragments_dir / "security-posture-attack-paths.json").write_text("{bad", encoding="utf-8")
        taxonomy = compose._load_attack_class_taxonomy()
        out = compose._load_attack_paths_fragment(ctx, taxonomy, [])
        # Fallback is a dict with attack_paths key.
        assert isinstance(out, dict)
        assert "attack_paths" in out

    def test_schema_invalid_falls_back(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        # attack_paths present but items miss required fields -> schema fail.
        frag = {"schema_version": 1, "actors": ["internet-anon"], "attack_paths": [{"foo": "bar"}]}
        (ctx.fragments_dir / "security-posture-attack-paths.json").write_text(_json.dumps(frag), encoding="utf-8")
        taxonomy = compose._load_attack_class_taxonomy()
        out = compose._load_attack_paths_fragment(ctx, taxonomy, [])
        assert isinstance(out, dict)
        assert "attack_paths" in out


# ---------------------------------------------------------------------------
# _render_infobox — derive_name fallback chain (remote_url / output_dir)
# ---------------------------------------------------------------------------


class TestRenderInfoboxDeriveName:
    def test_remote_url_slug_name(self, tmp_path):
        ctx = _mk_ctx(
            tmp_path,
            yaml_data={
                "project": {},
                "meta": {"git": {"remote_url": "git@github.com:acme/cool-app.git"}},
            },
        )
        env = compose._build_jinja_env(ctx)
        out = compose._render_infobox(ctx, env, {})
        assert "cool-app" in out

    def test_output_dir_fallback_name(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"project": {}, "meta": {}})
        env = compose._build_jinja_env(ctx)
        out = compose._render_infobox(ctx, env, {})
        # Parent dir of the output dir is used when nothing else resolves.
        assert ctx.output_dir.parent.name in out or "Unknown Project" in out
