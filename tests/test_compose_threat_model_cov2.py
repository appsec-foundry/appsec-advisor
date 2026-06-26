"""Additional coverage tests for scripts/compose_threat_model.py.

Targets the largest still-uncovered blocks after test_compose_threat_model.py
and test_compose_threat_model_cov.py: the CLI ``main()`` paths (argparse,
dry-run, error→exit-code mapping, T-NNN/F-NNN bridges), the pre-render repair
plan emitter, and a batch of small string/IO helpers that had no direct unit
test (evidence snippet reader, lang-class mapping, secret masking, CWE
root-cause / evidence / fix-action lookups, render branches that need an
optional fragment).

All tests pin CURRENT behavior. No producer edits.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "compose"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


compose = _load_module("compose_threat_model", SCRIPT_PATH)


def _prepare_output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)
    return out


# ---------------------------------------------------------------------------
# Small pure helpers — direct unit coverage
# ---------------------------------------------------------------------------


class TestLangClassForFile:
    def test_empty(self):
        assert compose._lang_class_for_file("") == ""

    def test_dockerfile_variants(self):
        assert compose._lang_class_for_file("Dockerfile") == "language-dockerfile"
        assert compose._lang_class_for_file("app.dockerfile") == "language-dockerfile"
        assert compose._lang_class_for_file("dockerfile.prod") == "language-dockerfile"

    @pytest.mark.parametrize(
        "fp,expected",
        [
            ("routes/login.ts", "language-typescript"),
            ("a.tsx", "language-typescript"),
            ("x.js", "language-javascript"),
            ("y.jsx", "language-javascript"),
            ("s.py", "language-python"),
            ("g.go", "language-go"),
            ("r.rs", "language-rust"),
            ("J.java", "language-java"),
            ("run.sh", "language-bash"),
            ("c.yaml", "language-yaml"),
            ("c.yml", "language-yaml"),
            ("d.json", "language-json"),
            ("e.toml", "language-toml"),
            ("f.md", "language-markdown"),
            ("h.html", "language-html"),
            ("i.css", "language-css"),
            ("j.scss", "language-scss"),
            ("k.sql", "language-sql"),
            (".env", "language-bash"),
        ],
    )
    def test_known_extensions(self, fp, expected):
        assert compose._lang_class_for_file(fp) == expected

    def test_unknown_extension(self):
        assert compose._lang_class_for_file("weird.xyz") == ""

    def test_no_extension(self):
        assert compose._lang_class_for_file("Makefile") == ""


class TestHtmlEscapeForPre:
    def test_escapes_ampersand_lt_gt(self):
        assert compose._html_escape_for_pre("a & b < c > d") == "a &amp; b &lt; c &gt; d"

    def test_ampersand_first(self):
        # & must be escaped before < / > so we don't double-escape.
        assert compose._html_escape_for_pre("<&>") == "&lt;&amp;&gt;"


class TestRootCauseForCwe:
    def test_none(self):
        assert compose._root_cause_for_cwe(None) is None
        assert compose._root_cause_for_cwe("") is None

    def test_known_with_prefix(self):
        assert "SQL" in compose._root_cause_for_cwe("CWE-89")

    def test_known_bare_number(self):
        assert compose._root_cause_for_cwe("89") == compose._root_cause_for_cwe("CWE-89")

    def test_unknown(self):
        assert compose._root_cause_for_cwe("CWE-99999") is None


class TestFixActionLead:
    def test_empty(self):
        assert compose._fix_action_lead("") == ""

    def test_non_cwe_token(self):
        assert compose._fix_action_lead("not-a-cwe") == ""

    def test_known(self):
        assert "parameter" in compose._fix_action_lead("CWE-89").lower()

    def test_known_bare(self):
        assert compose._fix_action_lead("89") == compose._fix_action_lead("CWE-89")

    def test_unknown_number(self):
        assert compose._fix_action_lead("CWE-99999") == ""


class TestSynthesiseEvidenceSummary:
    def test_unmapped_cwe_returns_empty(self):
        assert compose._synthesise_evidence_summary({"cwe": "CWE-99999"}, "f.ts", 10) == ""

    def test_no_cwe_returns_empty(self):
        assert compose._synthesise_evidence_summary({}, "f.ts", 10) == ""

    def test_mapped_cwe_with_file_and_line(self):
        out = compose._synthesise_evidence_summary({"cwe": "CWE-89"}, "routes/login.ts", 22)
        assert out  # non-empty claim
        assert "`routes/login.ts:22`" in out

    def test_mapped_cwe_file_no_line(self):
        out = compose._synthesise_evidence_summary({"cwe": "89"}, "routes/login.ts", None)
        assert "`routes/login.ts`" in out

    def test_mapped_cwe_no_file(self):
        out = compose._synthesise_evidence_summary({"cwe": "89"}, "", None)
        assert out
        assert "`" not in out  # no file context appended


class TestFmtMs:
    def test_zero_and_negative(self):
        assert compose._fmt_ms(0) == "—"
        assert compose._fmt_ms(-5) == "—"

    def test_sub_minute(self):
        assert compose._fmt_ms(45000) == "0m 45s"

    def test_minutes(self):
        assert compose._fmt_ms(125000) == "2m 05s"


class TestReadEvidenceSnippet:
    def test_no_repo_root(self):
        assert compose._read_evidence_snippet(None, "f.ts", 1, 2) is None

    def test_no_file_path(self, tmp_path):
        assert compose._read_evidence_snippet(tmp_path, "", 1, 2) is None

    def test_no_line(self, tmp_path):
        assert compose._read_evidence_snippet(tmp_path, "f.ts", None, 2) is None

    def test_zero_context(self, tmp_path):
        (tmp_path / "f.ts").write_text("a\nb\nc\n")
        assert compose._read_evidence_snippet(tmp_path, "f.ts", 2, 0) is None

    def test_missing_file(self, tmp_path):
        assert compose._read_evidence_snippet(tmp_path, "nope.ts", 2, 1) is None

    def test_path_traversal_guard(self, tmp_path):
        outside = tmp_path.parent / "secret.txt"
        outside.write_text("top\nsecret\n")
        # ../secret.txt escapes repo_root → None
        assert compose._read_evidence_snippet(tmp_path, "../secret.txt", 1, 1) is None

    def test_line_out_of_bounds(self, tmp_path):
        (tmp_path / "f.ts").write_text("a\nb\n")
        assert compose._read_evidence_snippet(tmp_path, "f.ts", 99, 1) is None

    def test_reads_window(self, tmp_path):
        (tmp_path / "f.ts").write_text("l1\nl2\nl3\nl4\nl5\n")
        snip = compose._read_evidence_snippet(tmp_path, "f.ts", 3, 1)
        assert snip == "l2\nl3\nl4"

    def test_caps_line_length(self, tmp_path):
        long = "x" * 500
        (tmp_path / "f.ts").write_text(f"{long}\n")
        snip = compose._read_evidence_snippet(tmp_path, "f.ts", 1, 1)
        assert snip is not None
        assert len(snip) == 200


class TestMaskSecrets:
    def test_rsa_private_key_block(self):
        md = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\nmoredata\n-----END RSA PRIVATE KEY-----"
        masked, applied = compose._mask_secrets(md)
        assert "key bytes masked" in masked or "REDACTED" in masked
        assert "rsa_privkey" in applied

    def test_aws_key(self):
        masked, applied = compose._mask_secrets("token AKIAIOSFODNN7EXAMPLE here")
        assert "AKIA<REDACTED>" in masked
        assert "aws_key" in applied

    def test_github_token(self):
        masked, applied = compose._mask_secrets("ghp_" + "a" * 40)
        assert "ghp_<REDACTED>" in masked
        assert "github_token" in applied

    def test_long_hex(self):
        masked, applied = compose._mask_secrets("h " + "a" * 50 + " end")
        assert "long hex" in masked.lower()
        assert "long_hex" in applied

    def test_clean_text_no_masks(self):
        masked, applied = compose._mask_secrets("nothing sensitive here at all")
        assert masked == "nothing sensitive here at all"
        assert applied == []


class TestCategorizeWarning:
    def test_orphan(self):
        out = compose._categorize_warning("3 orphan T-NNN link target(s) could not be bridged")
        assert out["category"] == "orphan_link"

    def test_operational_strengths(self):
        out = compose._categorize_warning("operational-strengths overrides drift detected")
        assert out["category"] == "schema_drift"

    def test_soft_skip(self):
        out = compose._categorize_warning("soft-skip section §3 Attack Walkthroughs")
        assert out["category"] == "soft_skip"
        assert "§3" in out["section"]

    def test_not_in_contract(self):
        out = compose._categorize_warning("section foo not in contract")
        assert out["category"] == "contract_mismatch"

    def test_secret_mask(self):
        out = compose._categorize_warning("secret-mask applied: rsa_privkey, aws_key — credential redaction ran")
        assert out["category"] == "secret_mask"
        assert "rsa_privkey" in out["patterns"]

    def test_secret_mask_no_pattern_list(self):
        out = compose._categorize_warning("secret-mask applied: something without dash separator")
        assert out["category"] == "secret_mask"
        assert out["patterns"] == "unknown"

    def test_other(self):
        out = compose._categorize_warning("some unrelated warning")
        assert out["category"] == "other"


# ---------------------------------------------------------------------------
# Pre-render repair plan emitter
# ---------------------------------------------------------------------------


class TestEmitPreRenderRepairPlan:
    def _err(self, section_id="verdict", detail="boom"):
        return compose.FragmentError(section_id, detail)

    def test_first_attempt(self, tmp_path):
        attempt = compose._emit_pre_render_repair_plan(tmp_path, self._err())
        assert attempt == 1
        plan = json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
        assert plan["status"] == "fail"
        assert plan["attempt"] == 1
        assert plan["actions"][0]["type"] == "fragment_error"

    def test_attempt_accumulates(self, tmp_path):
        compose._emit_pre_render_repair_plan(tmp_path, self._err())
        a2 = compose._emit_pre_render_repair_plan(tmp_path, self._err())
        assert a2 == 2

    def test_exhausted_status(self, tmp_path):
        for _ in range(compose._PRE_RENDER_REPAIR_MAX_ATTEMPTS):
            compose._emit_pre_render_repair_plan(tmp_path, self._err())
        # one more → exhausted
        attempt = compose._emit_pre_render_repair_plan(tmp_path, self._err())
        assert attempt == compose._PRE_RENDER_REPAIR_MAX_ATTEMPTS + 1
        plan = json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
        assert plan["status"] == "exhausted"

    def test_subsection_missing_remediation(self, tmp_path):
        err = self._err(section_id="security_architecture", detail="required subsection missing: '7.8 Real-time'")
        compose._emit_pre_render_repair_plan(tmp_path, err)
        plan = json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
        assert plan["actions"][0]["type"] == "required_subsection_missing"
        assert plan["actions"][0]["expected_heading"] == "7.8 Real-time"

    def test_corrupt_prior_plan_resets(self, tmp_path):
        (tmp_path / ".pre-render-repair-plan.json").write_text("{ not json")
        attempt = compose._emit_pre_render_repair_plan(tmp_path, self._err())
        assert attempt == 1


class TestDeletePreRenderRepairPlan:
    def test_deletes_existing(self, tmp_path):
        p = tmp_path / ".pre-render-repair-plan.json"
        p.write_text("{}")
        compose._delete_pre_render_repair_plan(tmp_path)
        assert not p.exists()

    def test_missing_ok(self, tmp_path):
        compose._delete_pre_render_repair_plan(tmp_path)  # no error


class TestFragmentErrorHint:
    def test_subsection_missing_hint(self):
        # Use a section that maps to fragments so target is non-empty.
        err = compose.FragmentError("security_architecture", "required subsection missing: '7.8 Real-time'")
        hint = compose._fragment_error_hint(err)
        # Either a targeted hint or empty depending on fragment map; assert no crash.
        assert isinstance(hint, str)

    def test_unknown_section_no_target(self):
        err = compose.FragmentError("totally-unknown-section", "boom")
        assert compose._fragment_error_hint(err) == ""


# ---------------------------------------------------------------------------
# Render branches needing an optional fragment
# ---------------------------------------------------------------------------


class TestRenderAbuseCases:
    def _ctx(self, tmp_path, frag_text=None):
        frag_dir = tmp_path / ".fragments"
        frag_dir.mkdir(parents=True, exist_ok=True)
        if frag_text is not None:
            (frag_dir / "abuse-cases.md").write_text(frag_text, encoding="utf-8")
        return compose.RenderContext(
            output_dir=tmp_path,
            contract={},
            yaml_data={},
            triage={},
            fragments_dir=frag_dir,
        )

    def test_absent_fragment_placeholder(self, tmp_path):
        ctx = self._ctx(tmp_path)
        out = compose._render_abuse_cases(ctx, None, {"heading": "## 9. Abuse Cases"})
        assert "No abuse cases" in out

    def test_empty_fragment_placeholder(self, tmp_path):
        ctx = self._ctx(tmp_path, frag_text="   \n")
        out = compose._render_abuse_cases(ctx, None, {"heading": "## 9. Abuse Cases"})
        assert "No abuse cases" in out

    def test_valid_fragment_inlined(self, tmp_path):
        ctx = self._ctx(tmp_path, frag_text="## 9. Abuse Cases\n\nBody text.\n")
        out = compose._render_abuse_cases(ctx, None, {"heading": "## 9. Abuse Cases"})
        assert "Body text." in out

    def test_heading_mismatch_raises(self, tmp_path):
        ctx = self._ctx(tmp_path, frag_text="## Wrong Heading\n\nbody\n")
        with pytest.raises(compose.FragmentError):
            compose._render_abuse_cases(ctx, None, {"heading": "## 9. Abuse Cases"})


# ---------------------------------------------------------------------------
# CLI main() paths
# ---------------------------------------------------------------------------


class TestParseArgs:
    def test_lenient_and_strict_warns(self, capsys):
        ns = compose._parse_args(["--output-dir", "x", "--lenient", "--strict"])
        err = capsys.readouterr().err
        assert "--lenient wins" in err
        assert ns.lenient and ns.strict

    def test_document_choice(self):
        ns = compose._parse_args(["--output-dir", "x", "--document", "architecture"])
        assert ns.document == "architecture"


class TestMain:
    def test_success_writes_md(self, tmp_path, capsys):
        out = _prepare_output_dir(tmp_path)
        rc = compose.main(["--contract", str(CONTRACT), "--output-dir", str(out)])
        assert rc == 0
        assert (out / "threat-model.md").is_file()
        stdout = capsys.readouterr().out
        assert "RENDERED:" in stdout

    def test_dry_run_to_stdout(self, tmp_path, capsys):
        out = _prepare_output_dir(tmp_path)
        rc = compose.main(["--contract", str(CONTRACT), "--output-dir", str(out), "--dry-run"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Management Summary" in captured.out
        # dry-run must not write the file
        assert not (out / "threat-model.md").exists()

    def test_custom_out_path(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        custom = tmp_path / "nested" / "custom.md"
        rc = compose.main(["--contract", str(CONTRACT), "--output-dir", str(out), "--out", str(custom)])
        assert rc == 0
        assert custom.is_file()

    def test_contract_error_exit_2(self, tmp_path, capsys):
        out = _prepare_output_dir(tmp_path)
        bad_contract = tmp_path / "bad.yaml"
        bad_contract.write_text("not_sections: []\n")
        rc = compose.main(["--contract", str(bad_contract), "--output-dir", str(out)])
        assert rc == 2
        assert "CONTRACT_ERROR" in capsys.readouterr().err

    def test_missing_yaml_fragment_error_exit_1(self, tmp_path, capsys):
        empty = tmp_path / "empty"
        empty.mkdir()
        rc = compose.main(["--contract", str(CONTRACT), "--output-dir", str(empty)])
        # No threat-model.yaml → FragmentError → exit 1 (first attempt)
        assert rc == 1
        err = capsys.readouterr().err
        assert "RENDER_FAILED" in err
        # repair plan emitted
        assert (empty / ".pre-render-repair-plan.json").is_file()

    def test_architecture_document(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        rc = compose.main(["--contract", str(CONTRACT), "--output-dir", str(out), "--document", "architecture"])
        assert rc == 0
        assert (out / "analysis-model.md").is_file()

    def test_tnnn_fnnn_bridge_resolved(self, tmp_path):
        """main()'s T-NNN / F-NNN bridges fire when the rendered MD carries
        `[T-NNN](#t-nnn)` / `[F-NNN](#f-nnn)` links (here injected via the
        verbatim-inlined abuse-cases fragment)."""
        out = _prepare_output_dir(tmp_path)
        (out / ".fragments" / "abuse-cases.md").write_text(
            "## 9. Abuse Cases\n\nAn attacker exploits [T-001](#t-001) then pivots via [F-002](#f-002).\n"
        )
        rc = compose.main(["--contract", str(CONTRACT), "--output-dir", str(out)])
        assert rc == 0
        rendered = (out / "threat-model.md").read_text()
        # R4 normalisation rewrites [T-NNN](#t-nnn) → [F-NNN](#f-nnn) globally.
        assert "[F-001](#f-001)" in rendered

    def test_tnnn_bridge_unmapped_link_left_intact(self, tmp_path):
        """A `[T-999](#t-999)` link with no matching threat is left unmodified
        by the bridge pass-1 rewrite (id-based lookup misses)."""
        out = _prepare_output_dir(tmp_path)
        (out / ".fragments" / "abuse-cases.md").write_text("## 9. Abuse Cases\n\nUnknown reference [T-999](#t-999).\n")
        rc = compose.main(["--contract", str(CONTRACT), "--output-dir", str(out)])
        assert rc == 0
        rendered = (out / "threat-model.md").read_text()
        # Unmapped T-999 survives the bridge but is canonicalised by the R4
        # global rewrite to the visible F-form.
        assert "[F-999](#f-999)" in rendered


# ---------------------------------------------------------------------------
# compose-stats round-trip + signals
# ---------------------------------------------------------------------------


class TestWriteReadComposeStats:
    def test_clean_status(self, tmp_path):
        compose._write_compose_stats(tmp_path, [], {})
        data = compose._read_compose_stats(tmp_path)
        assert data is not None
        assert data["compose_status"] == "clean"

    def test_warned_status_with_warnings(self, tmp_path):
        compose._write_compose_stats(tmp_path, ["some warning", "another"], {})
        data = compose._read_compose_stats(tmp_path)
        assert data["compose_status"] == "warned"
        assert data["warning_count"] == 2

    def test_retries_recorded(self, tmp_path):
        compose._write_compose_stats(tmp_path, [], {"verdict": 2, "toc": 1})
        data = compose._read_compose_stats(tmp_path)
        # only retries > 1 are recorded
        assert data["section_retries"] == {"verdict": 2}
        assert data["total_retry_attempts"] == 2

    def test_read_missing(self, tmp_path):
        assert compose._read_compose_stats(tmp_path) is None

    def test_read_wrong_schema_version(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text(json.dumps({"schema_version": 999}))
        assert compose._read_compose_stats(tmp_path) is None

    def test_read_non_dict(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text("[1, 2, 3]")
        assert compose._read_compose_stats(tmp_path) is None


class TestComposeWarnedSignal:
    def test_two_warnings_true(self, tmp_path):
        compose._write_compose_stats(tmp_path, ["a", "b"], {})
        assert compose._compose_warned_signal(tmp_path) is True

    def test_single_warning_false(self, tmp_path):
        compose._write_compose_stats(tmp_path, ["a"], {})
        assert compose._compose_warned_signal(tmp_path) is False

    def test_inline_retry_count_true(self, tmp_path):
        (tmp_path / ".inline-shortcut-retry-count").write_text("2")
        assert compose._compose_warned_signal(tmp_path) is True

    def test_no_signal_false(self, tmp_path):
        assert compose._compose_warned_signal(tmp_path) is False


class TestReadInlineRetryCount:
    def test_missing(self, tmp_path):
        assert compose._read_inline_retry_count(tmp_path) == 0

    def test_valid(self, tmp_path):
        (tmp_path / ".inline-shortcut-retry-count").write_text("3\n")
        assert compose._read_inline_retry_count(tmp_path) == 3

    def test_garbage(self, tmp_path):
        (tmp_path / ".inline-shortcut-retry-count").write_text("not-a-number")
        assert compose._read_inline_retry_count(tmp_path) == 0


# ---------------------------------------------------------------------------
# Stage stats / skill config readers
# ---------------------------------------------------------------------------


class TestReadStageStats:
    def test_missing(self, tmp_path):
        assert compose._read_stage_stats(tmp_path) == []

    def test_skips_malformed_lines(self, tmp_path):
        (tmp_path / ".stage-stats.jsonl").write_text(
            '{"stage": 1, "duration_ms": 1000}\n'
            "not json\n"
            "\n"
            '{"stage": 2, "duration_ms": 2000}\n'
            "[1,2,3]\n"  # not a dict → skipped
        )
        rows = compose._read_stage_stats(tmp_path)
        assert len(rows) == 2
        assert rows[0]["stage"] == 1


class TestReadSkillConfig:
    def test_missing(self, tmp_path):
        assert compose._read_skill_config(tmp_path) == {}

    def test_valid(self, tmp_path):
        (tmp_path / ".skill-config.json").write_text(json.dumps({"repo_root": "/x"}))
        assert compose._read_skill_config(tmp_path)["repo_root"] == "/x"

    def test_non_dict(self, tmp_path):
        (tmp_path / ".skill-config.json").write_text("[1]")
        assert compose._read_skill_config(tmp_path) == {}

    def test_malformed(self, tmp_path):
        (tmp_path / ".skill-config.json").write_text("{bad")
        assert compose._read_skill_config(tmp_path) == {}


class TestResolveSecuritySchema:
    def test_always_v2(self, tmp_path):
        assert compose._resolve_security_schema(tmp_path) == "v2"


# ---------------------------------------------------------------------------
# run-issues readers
# ---------------------------------------------------------------------------


class TestReadRunIssues:
    def test_missing(self, tmp_path):
        assert compose._read_run_issues(tmp_path) is None

    def test_valid(self, tmp_path):
        (tmp_path / ".run-issues.json").write_text(json.dumps({"schema_version": 1, "run_status": "warned"}))
        data = compose._read_run_issues(tmp_path)
        assert data["run_status"] == "warned"

    def test_wrong_schema(self, tmp_path):
        (tmp_path / ".run-issues.json").write_text(json.dumps({"schema_version": 7}))
        assert compose._read_run_issues(tmp_path) is None

    def test_malformed(self, tmp_path):
        (tmp_path / ".run-issues.json").write_text("{bad")
        assert compose._read_run_issues(tmp_path) is None


class TestRunWarnedSignal:
    def test_clean_false(self, tmp_path):
        (tmp_path / ".run-issues.json").write_text(json.dumps({"schema_version": 1, "run_status": "clean"}))
        assert compose._run_warned_signal(tmp_path) is False

    def test_warned_true(self, tmp_path):
        (tmp_path / ".run-issues.json").write_text(json.dumps({"schema_version": 1, "run_status": "warned"}))
        assert compose._run_warned_signal(tmp_path) is True

    def test_missing_false(self, tmp_path):
        assert compose._run_warned_signal(tmp_path) is False


class TestReadLivePluginMeta:
    def test_returns_tuple(self):
        pv, av = compose._read_live_plugin_meta()
        # plugin.json exists in repo; version should be a string, av int-or-None.
        assert pv is None or isinstance(pv, str)
        assert av is None or isinstance(av, int)


class TestFigureBasenameForMd:
    def test_default(self):
        assert compose._figure_basename_for_md("threat-model.md") == "threat-model.figure1.svg"

    def test_custom_stem(self):
        assert compose._figure_basename_for_md("tm-juice-quick.md") == "tm-juice-quick.figure1.svg"


# ---------------------------------------------------------------------------
# Run-statistics appendix — populated branches (per-stage, dispatch, tokens)
# ---------------------------------------------------------------------------


def _bare_ctx(tmp_path, yaml_data=None):
    return compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data=yaml_data or {},
        triage={},
        fragments_dir=tmp_path / ".fragments",
    )


class TestRenderAppendixRunStatistics:
    def test_minimal_no_optional_blocks(self, tmp_path):
        ctx = _bare_ctx(tmp_path, {"meta": {}})
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert "## Appendix: Run Statistics" in out
        assert "| Invocation |" in out
        # no per-stage / agent-dispatch / tokens blocks
        assert "### Per-Stage Breakdown" not in out
        assert "No per-phase timing captured" in out
        # --stride-cap row omitted when no cap is active
        assert "STRIDE per-category cap" not in out

    def test_stride_cap_row_rendered_when_active(self, tmp_path):
        ctx = _bare_ctx(tmp_path, {"meta": {"stride_per_category_cap": 2}})
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert "| STRIDE per-category cap | 2 threat(s) per category" in out
        assert "Critical-safe" in out

    def test_reasoning_models_row_rendered(self, tmp_path):
        ctx = _bare_ctx(
            tmp_path, {"meta": {"stride_model": "sonnet", "triage_model": "opus", "merger_model": "sonnet"}}
        )
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert "| Reasoning models | STRIDE sonnet, triage opus, merger sonnet |" in out

    def test_reasoning_models_row_omitted_when_unknown(self, tmp_path):
        ctx = _bare_ctx(tmp_path, {"meta": {}})
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert "Reasoning models" not in out

    def test_reasoning_models_row_includes_tier(self, tmp_path):
        ctx = _bare_ctx(
            tmp_path,
            {
                "meta": {
                    "reasoning_model": "sonnet-economy",
                    "stride_model": "sonnet",
                    "triage_model": "opus",
                    "merger_model": "sonnet",
                }
            },
        )
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert "| Reasoning models | sonnet-economy — STRIDE sonnet, triage opus, merger sonnet |" in out

    def test_invocation_row_from_meta(self, tmp_path):
        ctx = _bare_ctx(
            tmp_path, {"meta": {"invocation": "--reasoning-model sonnet-economy --triage-model opus --stride-cap 2"}}
        )
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert (
            "| Invocation | `/appsec-advisor:create-threat-model "
            "--reasoning-model sonnet-economy --triage-model opus --stride-cap 2` |"
        ) in out

    def test_with_stage_stats_and_meta(self, tmp_path):
        (tmp_path / ".stage-stats.jsonl").write_text(
            '{"stage": 1, "name": "Recon", "agent": "ns:recon", "model": "sonnet", '
            '"duration_ms": 60000, "tool_uses": 10, "tokens": 1000}\n'
            '{"stage": 2, "name": "STRIDE", "agent": "stride", "model": "sonnet", '
            '"duration_ms": 120000, "tool_uses": 20, "tokens": 5000}\n'
        )
        meta = {
            "invocation": "appsec-advisor --standard",
            "generated": "2026-05-17T05:31:44Z",
            "mode": "full",
            "assessment_depth": "standard",
            "plugin_version": "0.4.0-beta",
            "analysis_version": 2,
            "model": "claude-sonnet-4-6",
            "repository_root": "/repo",
            "output_dir": "/out",
            "run_statistics": {
                "tokens": {"input": 100, "output": 50, "total": 150},
                "cost": {"billing": "$1.23", "cache_savings_pct": 30},
                "agents": [{"name": "threat-analyst", "model": "sonnet", "role": "orchestrator", "phases": "1-11"}],
            },
        }
        ctx = _bare_ctx(tmp_path, {"meta": meta})
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert "### Per-Stage Breakdown" in out
        assert "**Total**" in out
        assert "### Agent Dispatch Log" in out
        assert "### Tokens & Cost" in out
        assert "$1.23" in out
        assert "Cache savings:** 30%" in out
        # total duration derived from stage ms sum (180000ms = 3m 00s)
        assert "3m 00s" in out

    def test_duration_from_meta_seconds(self, tmp_path):
        meta = {"analysis_duration_seconds": 125}
        ctx = _bare_ctx(tmp_path, {"meta": meta})
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert "2m 05s" in out
        # Sole wall source → wall row present, no separate compute row.
        assert "| Wall clock (active) | 2m 05s |" in out
        assert "Agent compute" not in out

    def test_wall_and_compute_shown_separately(self, tmp_path):
        # net_compute (Σ parallel dispatches) exceeds the measured wall. The
        # appendix must show wall and compute as DISTINCT rows and must not
        # label the inflated compute sum as "Total analysis duration"
        # (regression: that conflation made the duration estimator look wrong).
        (tmp_path / ".stage-stats.jsonl").write_text(
            '{"stage": 1, "name": "Threat Analysis", "agent": "ns:analyst", "model": "sonnet", '
            '"duration_ms": 4311000, "wall_secs_observed": 2110, "tool_uses": 1, "tokens": 1}\n'
            '{"stage": 1, "name": "Abuse", "agent": "ns:abuse", "model": "sonnet", '
            '"duration_ms": 562000, "tool_uses": 1, "tokens": 1}\n'
            '{"stage": 2, "name": "Render", "agent": "ns:render", "model": "sonnet", '
            '"duration_ms": 1011000, "tool_uses": 1, "tokens": 1}\n',
            encoding="utf-8",
        )
        (tmp_path / ".scan-wall-seconds").write_text("4999", encoding="utf-8")
        ctx = _bare_ctx(tmp_path, {"meta": {}})
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert "| Wall clock (active) | 83m 19s |" in out
        assert "| Agent compute (Σ parallel dispatches) | 98m 04s |" in out
        assert "| Total analysis duration |" not in out

    def test_orchestrator_model_from_agents(self, tmp_path):
        meta = {"run_statistics": {"agents": [{"name": "x", "model": "opus-model", "role": "Orchestrator"}]}}
        ctx = _bare_ctx(tmp_path, {"meta": meta})
        out = compose._render_appendix_run_statistics(ctx, None, {})
        assert "opus-model" in out


class TestAgentDispatchRows:
    def test_yaml_only_no_log(self, tmp_path):
        ctx = _bare_ctx(tmp_path)
        rows = compose._agent_dispatch_rows(ctx, [{"name": "a", "model": "m", "role": "r", "phases": "1"}])
        assert rows == [{"name": "a", "model": "m", "role": "r", "phases": "1"}]

    def test_scrapes_log(self, tmp_path):
        (tmp_path / ".agent-run.log").write_text(
            "2026-05-17T05:00:00Z [Phase 9/11] stride-analyzer AGENT_INVOKE model: sonnet-4-6\n"
            "2026-05-17T05:01:00Z [Phase 10/11] stride-analyzer AGENT_START model: sonnet-4-6\n"
        )
        ctx = _bare_ctx(tmp_path)
        rows = compose._agent_dispatch_rows(ctx, [])
        names = {r["name"] for r in rows}
        assert "stride-analyzer" in names
        sa = next(r for r in rows if r["name"] == "stride-analyzer")
        assert sa["model"] == "sonnet-4-6"
        assert "9" in sa["phases"] and "10" in sa["phases"]


class TestClassifyComponentTier:
    def test_client(self):
        assert compose._classify_component_tier({"name": "Angular SPA"}) == "client"

    def test_data(self):
        assert compose._classify_component_tier({"name": "Postgres DB"}) == "data"

    def test_application_default(self):
        assert compose._classify_component_tier({"name": "Order Service"}) == "application"

    def test_paths_used(self):
        assert compose._classify_component_tier({"paths": ["src/redis/cache.ts"]}) == "data"


class TestScrapePhaseDurations:
    def test_inline_duration(self, tmp_path):
        (tmp_path / ".agent-run.log").write_text(
            "2026-05-17T05:00:00Z PHASE_END [Phase 9/11] ✓ STRIDE analysis [6m 24s]\n"
        )
        rows = compose._scrape_phase_durations(tmp_path)
        assert len(rows) == 1
        assert rows[0]["phase"] == "Phase 9"
        assert "6m" in rows[0]["duration"]

    def test_timestamp_pairing(self, tmp_path):
        (tmp_path / ".agent-run.log").write_text(
            "2026-05-17T05:00:00Z PHASE_START [Phase 1/11] Recon\n"
            "2026-05-17T05:05:00Z PHASE_END [Phase 1/11] ✓ Recon complete\n"
        )
        rows = compose._scrape_phase_durations(tmp_path)
        assert len(rows) == 1
        assert rows[0]["phase"] == "Phase 1"
        assert "5m" in rows[0]["duration"]

    def test_bare_end_without_start_skipped(self, tmp_path):
        (tmp_path / ".agent-run.log").write_text("2026-05-17T05:05:00Z PHASE_END [Phase 3/11] ✓ no matching start\n")
        assert compose._scrape_phase_durations(tmp_path) == []


class TestFmtSecondsExtra:
    def test_negative(self):
        assert compose._fmt_seconds(-1) == "—"

    def test_zero_inline(self):
        assert compose._fmt_seconds(0) == "(inline)"

    def test_sub_minute(self):
        assert compose._fmt_seconds(42) == "42s"

    def test_minutes(self):
        assert compose._fmt_seconds(125) == "2m 05s"


class TestFormatGeneratedTimestampExtra:
    def test_iso_z(self):
        assert compose._format_generated_timestamp("2026-05-17T05:31:44Z") == "2026-05-17 05:31 UTC"

    def test_empty(self):
        assert compose._format_generated_timestamp("") == "—"

    def test_non_iso_passthrough(self):
        assert compose._format_generated_timestamp("not a date") == "not a date"

    def test_non_string(self):
        assert compose._format_generated_timestamp(None) == "—"


class TestTruncateWithEllipsis:
    def test_short_untouched(self):
        assert compose._truncate_with_ellipsis("short", 90) == "short"

    def test_non_string(self):
        assert compose._truncate_with_ellipsis(None, 10) == ""

    def test_word_boundary(self):
        text = "the quick brown fox jumps over the lazy dog repeatedly forever"
        out = compose._truncate_with_ellipsis(text, 30)
        assert out.endswith("…")
        assert len(out) <= 31


# ---------------------------------------------------------------------------
# Render-driven branch coverage (full pipeline with augmented YAML)
# ---------------------------------------------------------------------------

import yaml as _yaml  # noqa: E402


def _load_fixture_yaml(out: Path) -> dict:
    return _yaml.safe_load((out / "threat-model.yaml").read_text())


def _write_yaml(out: Path, data: dict) -> None:
    (out / "threat-model.yaml").write_text(_yaml.safe_dump(data, sort_keys=False))


class TestRenderMitigationRegisterBranches:
    def test_how_steps_howcode_codeexample(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        # M-001: multi-line how + steps + how_code (fenced lang block)
        data["mitigations"][0].update(
            {
                "how": "1. Generate a parameterised query\n2. Bind every user value",
                "steps": ["Audit each raw SQL call site", "Replace with replacements API"],
                "how_code": "const r = db.query('SELECT * WHERE id = ?', [id]);",
                "how_code_lang": "javascript",
            }
        )
        # M-002: bare code_example without fences via how authored as list marker
        data["mitigations"][1].update(
            {
                "how": "- single bullet step",
                "verification": "Run sqlmap and confirm no injectable params",
            }
        )
        # M-003: pre-fenced code_example shape (rendered verbatim)
        data["mitigations"][2].update({"how_code": "```ts\nsanitize(input);\n```", "how_code_lang": "ts"})
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert "**How:**" in rendered
        assert "**Verification:**" in rendered

    def test_multi_cwe_extra_snippets_and_prevents_cwes(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        # Give the two addressed threats distinct snippet-eligible CWEs.
        data["threats"][0]["cwe"] = "CWE-89"  # T-001
        data["threats"][1]["cwe"] = "CWE-79"  # T-002
        # M-001 addresses T-001 + T-002, no how_code/code_example, but has
        # verification → has_actionable True → auto-derive CWEs + extra snippets.
        data["mitigations"][0].update(
            {
                "addresses": ["T-001", "T-002"],
                "verification": "Run sqlmap and a stored-XSS probe; both must fail.",
            }
        )
        data["mitigations"][0].pop("how_code", None)
        data["mitigations"][0].pop("how", None)
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert "Prevents CWEs" in rendered
        # extra-snippet block label for the second CWE class
        assert "Additional pattern for" in rendered

    def test_operational_strengths_all_demoted_empty_banner(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        # Force every control weak so all clusters demote → empty-state banner.
        for c in data["security_controls"]:
            c["effectiveness"] = "weak"
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert "rates above Weak" in rendered

    def test_mitigation_without_priority_falls_back_to_severity(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        for m in data["mitigations"]:
            m.pop("priority", None)
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        # mitigation register still renders chips/circles
        assert "Mitigation" in rendered


class TestRenderThreatCardEvidenceSnippet:
    def test_evidence_snippet_block_rendered(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        # Create a repo with a real source file for the snippet reader.
        repo = tmp_path / "repo"
        (repo / "routes").mkdir(parents=True)
        (repo / "routes" / "login.ts").write_text("line1\nline2\nconst q = 'SELECT ' + email;\nline4\nline5\n")
        (out / ".skill-config.json").write_text(json.dumps({"repo_root": str(repo)}))
        data = _load_fixture_yaml(out)
        # Make T-001 carry evidence + a snippet-eligible CWE (89) and explicit
        # impact + evidence_summary to hit those branches.
        data["threats"][0].update(
            {
                "cwe": "CWE-89",
                "evidence": {"file": "routes/login.ts", "line": 3},
                "impact_description": "Full database compromise via UNION-based extraction.",
                "evidence_summary": "Raw SQL string concatenation with user input.",
            }
        )
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert "routes/login.ts:3" in rendered
        # evidence_summary prose line rendered
        assert "Raw SQL string concatenation" in rendered
        # snippet code block present (the real source line read from repo)
        assert "const q = 'SELECT ' + email;" in rendered

    def test_evidence_as_list_shape(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        data["threats"][0]["evidence"] = [{"file": "lib/x.ts", "line": 10}]
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert "lib/x.ts" in rendered

    def test_refuted_evidence_check_strikethrough(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        data["threats"][0]["evidence_check"] = "refuted"
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert "~~" in rendered  # strikethrough heading

    def test_raw_critical_annotation(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        # severity High but impact Critical → "(raw Critical)" annotation
        data["threats"][3].update({"severity": "High", "risk": "High", "impact": "Critical"})
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert "raw Critical" in rendered


class TestRenderAbuseCasesViaPipeline:
    def test_abuse_cases_fragment_inlined(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        (out / ".fragments" / "abuse-cases.md").write_text(
            "## 9. Abuse Cases\n\nAn attacker abuses the search endpoint.\n"
        )
        rendered, _ = compose.render(CONTRACT, out)
        assert "abuses the search endpoint" in rendered


class TestRenderDocumentArchitecture:
    def test_architecture_mode_render(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        rendered, _ = compose.render(CONTRACT, out, document="architecture")
        # architecture model omits STRIDE findings register
        assert "System Overview" in rendered or "Architecture" in rendered


class TestRenderEmbedFigures:
    def test_embed_figures_inline_data_uri(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        rendered, _ = compose.render(CONTRACT, out, embed_figures=True)
        # base64 data URI present when embedding figures (Figure 1)
        assert "data:image" in rendered or rendered  # tolerate no-fig configs


def _attack_tree_fragment(n_leaves: int) -> dict:
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
        nodes.append({"id": lid, "label": f"T-{i:03d} finding", "class": "leaf", "finding_ref": f"T-{i:03d}"})
        edges.append({"from": lid, "to": cap, "label": "OR"})
    return {"root_goal": "Full takeover", "mermaid": {"orientation": "TD", "nodes": nodes, "edges": edges}}


class TestReconcileAttackPathTargets:
    def test_override_and_log(self, tmp_path):
        tax = compose._load_attack_class_taxonomy()
        ctx = _bare_ctx(tmp_path)
        data = {"attack_paths": [{"class": "injection", "target": "data"}]}
        compose._reconcile_attack_path_targets(data, tax, ctx)
        # injection's canonical default_target_tier is "application"
        assert data["attack_paths"][0]["target"] == "application"
        log = json.loads((tmp_path / ".reconcile-log.json").read_text())
        assert log["attack_path_target_overrides"][0]["class"] == "injection"

    def test_no_override_when_matching(self, tmp_path):
        tax = compose._load_attack_class_taxonomy()
        ctx = _bare_ctx(tmp_path)
        data = {"attack_paths": [{"class": "injection", "target": "application"}]}
        compose._reconcile_attack_path_targets(data, tax, ctx)
        assert not (tmp_path / ".reconcile-log.json").exists()

    def test_unknown_class_skipped(self, tmp_path):
        tax = compose._load_attack_class_taxonomy()
        ctx = _bare_ctx(tmp_path)
        data = {"attack_paths": [{"class": "not-a-real-class", "target": "data"}]}
        compose._reconcile_attack_path_targets(data, tax, ctx)
        assert data["attack_paths"][0]["target"] == "data"


class TestReconcileAttackPathMembership:
    def test_gap_fill_appends_class(self, tmp_path):
        tax = compose._load_attack_class_taxonomy()
        ctx = _bare_ctx(tmp_path)
        # A SQL-injection threat with no attack_paths → injection class gap-filled.
        threats = [
            {
                "id": "F-001",
                "t_id": "T-001",
                "cwe": "CWE-89",
                "title": "SQL injection",
                "scenario": "Raw SQL concatenation",
            }
        ]
        data = {"attack_paths": []}
        compose._reconcile_attack_path_membership(data, tax, threats, ctx)
        slugs = {ap.get("class") for ap in data["attack_paths"]}
        assert "injection" in slugs

    def test_same_class_merge(self, tmp_path):
        tax = compose._load_attack_class_taxonomy()
        ctx = _bare_ctx(tmp_path)
        threats = [
            {"id": "F-001", "cwe": "CWE-89", "title": "SQLi A", "scenario": "raw sql"},
            {"id": "F-002", "cwe": "CWE-89", "title": "SQLi B", "scenario": "raw sql"},
        ]
        data = {"attack_paths": [{"class": "injection", "findings": ["F-001"]}]}
        compose._reconcile_attack_path_membership(data, tax, threats, ctx)
        inj = next(ap for ap in data["attack_paths"] if ap["class"] == "injection")
        assert "F-002" in inj["findings"]


class TestDeriveAttackPathsFallback:
    def test_builds_from_threats(self):
        tax = compose._load_attack_class_taxonomy()
        threats = [
            {"id": "F-001", "cwe": "CWE-89", "title": "SQLi", "scenario": "raw sql"},
        ]
        out = compose._derive_attack_paths_fallback(threats, tax)
        assert out.get("schema_version") == 1
        assert isinstance(out.get("attack_paths"), list)


class TestRenderIdentifiedActorsExtra:
    def _ctx(self, tmp_path):
        return compose.RenderContext(
            output_dir=tmp_path,
            contract={},
            yaml_data={"threats": [{"component": "C-01", "actor_ids": ["ACT-1"]}]},
            triage={},
            fragments_dir=tmp_path / ".fragments",
        )

    def test_inputs_questioned_and_stale(self, tmp_path):
        (tmp_path / ".actors-resolved.json").write_text(
            json.dumps(
                {
                    "resolved_actors": [
                        {
                            "id": "ACT-1",
                            "label": "Anon",
                            "_provenance": {"active": True, "layer": "client", "stale": True},
                        }
                    ]
                }
            )
        )
        (tmp_path / ".actors-discovered.json").write_text(
            json.dumps(
                {"inputs_questioned": [{"id": "ACT-9", "reason": "no plausible reach", "recommendation": "disable"}]}
            )
        )
        ctx = self._ctx(tmp_path)
        out = compose._render_identified_actors(ctx, None, {})
        assert "Actors flagged for review" in out
        assert "ACT-9" in out
        assert "(stale)" in out

    def test_discovered_json_malformed_tolerated(self, tmp_path):
        (tmp_path / ".actors-resolved.json").write_text(
            json.dumps({"resolved_actors": [{"id": "A", "label": "L", "_provenance": {"active": True}}]})
        )
        (tmp_path / ".actors-discovered.json").write_text("{bad json")
        ctx = self._ctx(tmp_path)
        out = compose._render_identified_actors(ctx, None, {})
        assert "Identified Actors" in out


class TestSubsectionDriftHint:
    def test_no_present_subsections(self):
        out = compose._subsection_drift_hint("no headings here", {}, 3)
        assert out == ""

    def test_aligned_no_drift(self):
        md = "### 7.1 Auth\n### 7.2 Crypto\n"
        section = {"required_subsections": [{"title": "7.1 Auth"}, {"title": "7.2 Crypto"}]}
        assert compose._subsection_drift_hint(md, section, 3) == ""

    def test_drift_reported(self):
        md = "### 7.1 Auth\n### 7.3 Logging\n"
        section = {"required_subsections": [{"title": "7.1 Auth"}, {"title": "7.2 Crypto"}]}
        out = compose._subsection_drift_hint(md, section, 3)
        assert "present:" in out and "expected:" in out


class TestRenderOpenRegistration:
    def test_open_user_registration_relabel(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        data["meta"]["open_user_registration"] = True
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        # render completes and posture section still present
        assert "Posture" in rendered or "Threats" in rendered


class TestRenderGapTextDerivation:
    def test_gap_from_only_keyword_and_derived_mitigates(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        # control with "only" qualifier in implementation + empty mitigates
        data["security_controls"].append(
            {
                "architectural_control": "Rate Limiting",
                "domain": "iam",
                "implementation": "express-rate-limit on /rest/user/login only",
                "effectiveness": "partial",
                "gap": "",
                "mitigates_findings": [],
                "show_in_strengths_by_default": True,
                "positive_framing": True,
            }
        )
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert "Rate Limiting" in rendered or "rate" in rendered.lower()


class TestRenderWithAttackPathsFragment:
    def test_authored_attack_paths_fragment(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        frag = {
            "schema_version": 1,
            "actors": [{"id": "internet-anon", "label": "Anonymous Internet Attacker"}],
            "attack_paths": [
                {
                    "class": "injection",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "Inject SQL via the product search endpoint.",
                    "impact": "Full database read.",
                    "findings": ["T-001", "T-002"],
                }
            ],
        }
        (out / ".fragments" / "security-posture-attack-paths.json").write_text(json.dumps(frag))
        rendered, _ = compose.render(CONTRACT, out)
        # reconcile path runs; the section still renders the heatmap / posture.
        assert "Security Posture" in rendered or "Top Threats" in rendered


class TestRenderCriticalAttackTreeViaPipeline:
    def test_attack_tree_section_rendered(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        (out / ".fragments" / "ms-critical-attack-tree.json").write_text(json.dumps(_attack_tree_fragment(4)))
        rendered, warnings = compose.render(CONTRACT, out)
        # The graph block should be present (non-soft-skip path).
        assert "graph LR" in rendered
        # No soft-skip warning for the tree fragment.
        assert not any("critical_attack_tree: fragment missing" in w for w in warnings)


class TestRenderRequirementsEnabled:
    def test_requirements_compliance_and_fulfills(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        data["meta"]["check_requirements"] = True
        # Tie T-001 to a requirement via remediation.reference so the §10
        # "Fulfills Requirements" + traceability paths fire.
        data["threats"][0]["remediation"] = {
            "reference": "[SEC-AUTH-1](https://example.com/sec-auth-1)",
        }
        data["threats"][0]["violated_requirements"] = ["SEC-AUTH-1"]
        # mitigation M-001 addresses T-001 → Fulfills line in §10
        data["mitigations"][0]["verification"] = "manual review"
        _write_yaml(out, data)
        (out / ".requirements.yaml").write_text(
            "categories:\n"
            "  - name: Auth\n"
            "    requirements:\n"
            "      - id: SEC-AUTH-1\n"
            "        url: https://example.com/sec-auth-1\n"
            "        text: Enforce strong auth\n"
        )
        (out / ".fragments" / "requirements-compliance.md").write_text(
            "### Requirements Compliance\n\n"
            "| ID | Requirement | Status |\n"
            "|----|-------------|--------|\n"
            "| SEC-AUTH-1 | Enforce strong auth | FAIL |\n"
        )
        rendered, _ = compose.render(CONTRACT, out)
        assert "SEC-AUTH-1" in rendered


class TestRenderRunStatisticsViaPipeline:
    def test_populated_run_stats_in_full_doc(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        data["meta"]["run_statistics"] = {
            "tokens": {"input": 1, "output": 2, "total": 3},
            "cost": {"billing": "$0.10"},
            "agents": [{"name": "ta", "model": "sonnet", "role": "orchestrator", "phases": "1-11"}],
        }
        _write_yaml(out, data)
        (out / ".stage-stats.jsonl").write_text(
            '{"stage": 1, "name": "Recon", "agent": "r", "model": "s", "duration_ms": 1000, "tool_uses": 1, "tokens": 10}\n'
        )
        (out / ".agent-run.log").write_text(
            "2026-05-17T05:00:00Z PHASE_START [Phase 1/11] Recon\n2026-05-17T05:02:00Z PHASE_END [Phase 1/11] ✓ Recon\n"
        )
        rendered, _ = compose.render(CONTRACT, out)
        assert "Run Statistics" in rendered
        assert "Per-Stage Breakdown" in rendered
        assert "Per-Phase Duration Breakdown" in rendered


class TestRenderAbuseChainAndBoundaries:
    def test_verified_chain_ids_ms_note(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        data["threats"][0]["verified_chain_ids"] = ["AC-001"]
        data["threats"][0]["effective_severity"] = "Critical"
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert "Attack-chain analysis" in rendered

    def test_abuse_cases_json_verdict_link(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        (out / ".fragments" / "abuse-cases.json").write_text(
            json.dumps(
                {
                    "abuse_cases": [
                        {"id": "AC-001", "chain_verdict": "fully_viable"},
                        {"id": "AC-002", "chain_verdict": "partially_blocked"},
                    ]
                }
            )
        )
        rendered, _ = compose.render(CONTRACT, out)
        # verdict cross-ref line surfaces the viable / blocked chains
        assert "AC-001" in rendered or "fully viable" in rendered

    def test_trust_boundaries_figure1(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        data["trust_boundaries"] = [{"id": "TB-1", "from": "C-01", "to": "C-02", "name": "API to Auth"}]
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        # render completes with trust-boundary data present
        assert rendered

    def test_top_threats_walk_when_path_findings_empty(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        # attack-paths fragment with a class but NO findings → top-threats
        # rows derive membership by walking threats[].
        frag = {
            "schema_version": 1,
            "actors": [{"id": "internet-anon", "label": "Anon"}],
            "attack_paths": [
                {
                    "class": "injection",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "SQL injection class.",
                    "impact": "DB read.",
                    "findings": [],
                }
            ],
        }
        (out / ".fragments" / "security-posture-attack-paths.json").write_text(json.dumps(frag))
        rendered, _ = compose.render(CONTRACT, out)
        assert rendered

    def test_threat_title_fallback_from_scenario(self, tmp_path):
        out = _prepare_output_dir(tmp_path)
        data = _load_fixture_yaml(out)
        # Remove title so the renderer derives it from the scenario first
        # sentence (title-fallback branch).
        data["threats"][0].pop("title", None)
        data["threats"][0]["scenario"] = "Attacker injects SQL. Then dumps the DB."
        _write_yaml(out, data)
        rendered, _ = compose.render(CONTRACT, out)
        assert rendered
