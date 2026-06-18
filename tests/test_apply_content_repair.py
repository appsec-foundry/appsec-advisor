"""Unit tests for scripts/apply_content_repair.py — Sprint 3A (M3.5)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "apply_content_repair.py"


def _load():
    if "apply_content_repair" in sys.modules:
        return sys.modules["apply_content_repair"]
    spec = importlib.util.spec_from_file_location("apply_content_repair", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["apply_content_repair"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


acr = _load()


def _setup_output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    (out / ".fragments").mkdir(parents=True)
    return out


def _write_fragment(out: Path, name: str, content: str) -> Path:
    p = out / ".fragments" / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _validate_plan
# ---------------------------------------------------------------------------


class TestValidatePlan:
    def test_minimal_plan_validates(self):
        plan = {
            "schema_version": 1,
            "actions": [],
        }
        assert acr._validate_plan(plan) == []

    def test_plan_must_be_object(self):
        errs = acr._validate_plan("not an object")  # type: ignore[arg-type]
        assert errs and "JSON object" in errs[0]

    def test_wrong_schema_version_flagged(self):
        plan = {"schema_version": 99, "actions": []}
        errs = acr._validate_plan(plan)
        assert any("schema_version" in e for e in errs)

    def test_actions_must_be_list(self):
        plan = {"schema_version": 1, "actions": "nope"}
        errs = acr._validate_plan(plan)
        assert any("actions` must be a list" in e for e in errs)

    def test_action_missing_required_fields(self):
        plan = {
            "schema_version": 1,
            "actions": [{"check": "1"}],  # missing type, fragment, operation
        }
        errs = acr._validate_plan(plan)
        assert any("missing field 'type'" in e for e in errs)
        assert any("missing field 'fragment'" in e for e in errs)
        assert any("missing field 'operation'" in e for e in errs)

    def test_unknown_op_flagged(self):
        plan = {
            "schema_version": 1,
            "actions": [
                {
                    "check": "1",
                    "type": "other",
                    "fragment": ".fragments/x.md",
                    "operation": {"op": "frobnicate"},
                }
            ],
        }
        errs = acr._validate_plan(plan)
        assert any("unknown" in e and "frobnicate" in e for e in errs)

    def test_flat_operation_string_rejected(self):
        """Producer-drift guard: the QA reviewer historically emitted the flat
        form (`operation: "replace_string"` + sibling search_text/replace_text).
        The validator must reject it at plan level (not crash in apply_plan)."""
        plan = {
            "schema_version": 1,
            "actions": [
                {
                    "check": "diagram_key_takeaway",
                    "type": "other",
                    "fragment": ".fragments/architecture-diagrams.md",
                    "operation": "append_after",
                    "search_text": "```",
                    "replace_text": "**Key takeaway:** ...",
                }
            ],
        }
        errs = acr._validate_plan(plan)
        assert any("must be a JSON object" in e and "flat form" in e for e in errs)

    def test_apply_plan_does_not_crash_on_flat_operation(self, tmp_path):
        """Belt-and-suspenders: even if the validator is bypassed, apply_plan
        must skip a non-dict operation gracefully rather than raise
        AttributeError ('str' object has no attribute 'get')."""
        out = _setup_output_dir(tmp_path)
        _write_fragment(out, "architecture-diagrams.md", "```\nx\n```\n")
        plan = {
            "schema_version": 1,
            "actions": [
                {
                    "check": "diagram_key_takeaway",
                    "type": "other",
                    "fragment": ".fragments/architecture-diagrams.md",
                    "operation": "append_after",
                    "search_text": "```",
                    "replace_text": "**Key takeaway:** ...",
                }
            ],
        }
        report = acr.apply_plan(plan, out)  # must not raise
        assert report["exit_code"] == 1
        assert report["applied"] == []
        assert report["skipped"] and "not an object" in report["skipped"][0]["reason"]


# ---------------------------------------------------------------------------
# _resolve_fragment_path — security boundary
# ---------------------------------------------------------------------------


class TestResolveFragmentPath:
    def test_valid_fragment_path_resolves(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        _write_fragment(out, "ok.md", "x")
        p = acr._resolve_fragment_path(out, ".fragments/ok.md")
        assert p == (out / ".fragments" / "ok.md").resolve()

    def test_path_outside_fragments_rejected(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        with pytest.raises(acr.ApplyError, match="must start with"):
            acr._resolve_fragment_path(out, "threat-model.md")

    def test_traversal_to_parent_rejected(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        # Even with the right prefix, a traversal that escapes the jail
        # must be rejected.
        with pytest.raises(acr.ApplyError, match="must start with|escapes the jail|does not exist"):
            acr._resolve_fragment_path(out, ".fragments/../../etc/passwd")

    def test_missing_file_rejected(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        with pytest.raises(acr.ApplyError, match="does not exist"):
            acr._resolve_fragment_path(out, ".fragments/nope.md")


# ---------------------------------------------------------------------------
# _op_replace_string — exact-substring single-shot
# ---------------------------------------------------------------------------


class TestOpReplaceString:
    def test_unique_match_replaced(self):
        text = "before NEEDLE after"
        out = acr._op_replace_string(text, {"find": "NEEDLE", "replace": "XXX"})
        assert out == "before XXX after"

    def test_zero_matches_raises(self):
        with pytest.raises(acr.ApplyError, match="needle not found"):
            acr._op_replace_string("nothing here", {"find": "X", "replace": "Y"})

    def test_ambiguous_match_raises(self):
        text = "X\nX\nX"
        with pytest.raises(acr.ApplyError, match="ambiguous"):
            acr._op_replace_string(text, {"find": "X", "replace": "Y"})

    def test_whitespace_mismatch_fuzzy_hits(self):
        # Fragment has a <br/> + collapsed spaces where the plan's `find`
        # used single literal spaces — exact match fails, fuzzy match wins.
        # This is the §7.1 crypto-row scenario (rendered MD vs fragment source).
        text = "| [Crypto](#79-x)<br/>  row anchor |"
        out = acr._op_replace_string(
            text,
            {"find": "[Crypto](#79-x) row anchor", "replace": "[7.9 Crypto](#79-y) row anchor"},
        )
        assert out == "| [7.9 Crypto](#79-y) row anchor |"

    def test_fuzzy_match_is_idempotent_on_rerun(self):
        text = "Crypto<br/> row #a"
        once = acr._op_replace_string(text, {"find": "Crypto row #a", "replace": "Crypto row #b"})
        assert once == "Crypto row #b"
        # Re-running the same action no longer matches (fix already applied).
        with pytest.raises(acr.ApplyError, match="needle not found"):
            acr._op_replace_string(once, {"find": "Crypto row #a", "replace": "Crypto row #b"})

    def test_fuzzy_ambiguous_raises(self):
        text = "X<br/>Y and X  Y"
        with pytest.raises(acr.ApplyError, match="ambiguous"):
            acr._op_replace_string(text, {"find": "X Y", "replace": "Z"})


# ---------------------------------------------------------------------------
# _op_append_after / _op_insert_before
# ---------------------------------------------------------------------------


class TestOpAppendAndInsert:
    def test_append_after(self):
        text = "## Heading\n\nbody\n"
        out = acr._op_append_after(text, {"anchor": "## Heading", "content": "extra"})
        assert "## Heading\nextra\n" in out

    def test_append_after_missing_anchor_raises(self):
        with pytest.raises(acr.ApplyError, match="anchor not found"):
            acr._op_append_after("x", {"anchor": "Y", "content": "z"})

    def test_insert_before(self):
        text = "## Heading\n\nbody\n"
        out = acr._op_insert_before(text, {"anchor": "## Heading", "content": "PRE"})
        assert out.startswith("PRE\n## Heading")

    def test_insert_before_missing_anchor_raises(self):
        with pytest.raises(acr.ApplyError, match="anchor not found"):
            acr._op_insert_before("x", {"anchor": "Y", "content": "z"})


# ---------------------------------------------------------------------------
# _op_regex_replace
# ---------------------------------------------------------------------------


class TestOpRegexReplace:
    def test_basic_replace(self):
        out = acr._op_regex_replace(
            "foo123bar",
            {"op": "regex_replace", "pattern": r"\d+", "replacement": "X"},
        )
        assert out == "fooXbar"

    def test_zero_match_raises(self):
        with pytest.raises(acr.ApplyError, match="matched 0 times"):
            acr._op_regex_replace(
                "abc",
                {"op": "regex_replace", "pattern": r"\d+", "replacement": "X"},
            )

    def test_max_substitutions_caps_replacements(self):
        out = acr._op_regex_replace(
            "1 2 3 4 5",
            {"op": "regex_replace", "pattern": r"\d", "replacement": "X", "max_substitutions": 2},
        )
        assert out == "X X 3 4 5"

    def test_invalid_pattern_raises(self):
        with pytest.raises(acr.ApplyError, match="invalid pattern"):
            acr._op_regex_replace(
                "x",
                {"op": "regex_replace", "pattern": "[", "replacement": "y"},
            )


# ---------------------------------------------------------------------------
# apply_plan — end-to-end
# ---------------------------------------------------------------------------


class TestApplyPlanEndToEnd:
    def test_empty_plan_is_noop(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        report = acr.apply_plan({"schema_version": 1, "actions": []}, out)
        assert report["exit_code"] == 0
        assert report["applied"] == []
        assert report["fragments_touched"] == []

    def test_successful_action_applies_and_writes(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        frag = _write_fragment(out, "test.md", "hello PLACEHOLDER world")
        plan = {
            "schema_version": 1,
            "actions": [
                {
                    "check": "6",
                    "type": "remove_placeholder",
                    "fragment": ".fragments/test.md",
                    "operation": {
                        "op": "replace_string",
                        "find": "PLACEHOLDER",
                        "replace": "REPLACED",
                    },
                }
            ],
        }
        report = acr.apply_plan(plan, out)
        assert report["exit_code"] == 0
        assert report["applied"] == [0]
        assert ".fragments/test.md" in report["fragments_touched"]
        assert frag.read_text() == "hello REPLACED world"

    def test_failed_action_does_not_block_subsequent_actions(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        frag = _write_fragment(out, "a.md", "good NEEDLE here")
        plan = {
            "schema_version": 1,
            "actions": [
                {
                    "check": "1",
                    "type": "other",
                    "fragment": ".fragments/a.md",
                    "operation": {
                        "op": "replace_string",
                        "find": "DOES_NOT_EXIST",
                        "replace": "X",
                    },
                },
                {
                    "check": "2",
                    "type": "other",
                    "fragment": ".fragments/a.md",
                    "operation": {
                        "op": "replace_string",
                        "find": "NEEDLE",
                        "replace": "FIXED",
                    },
                },
            ],
        }
        report = acr.apply_plan(plan, out)
        assert report["exit_code"] == 1, "first action failed → exit 1"
        assert report["applied"] == [1], "second action still applied"
        assert len(report["skipped"]) == 1
        assert report["skipped"][0]["index"] == 0
        assert "FIXED" in frag.read_text()

    def test_jail_violation_is_skipped_not_crashed(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        plan = {
            "schema_version": 1,
            "actions": [
                {
                    "check": "1",
                    "type": "other",
                    "fragment": "threat-model.md",  # outside the jail
                    "operation": {"op": "replace_string", "find": "x", "replace": "y"},
                }
            ],
        }
        report = acr.apply_plan(plan, out)
        assert report["exit_code"] == 1
        assert report["applied"] == []
        assert len(report["skipped"]) == 1

    def test_actions_grouped_by_fragment_write_once(self, tmp_path):
        """Multiple actions on the same fragment must produce ONE write
        (read once + apply both + write once) — verified by checking
        that fragments_touched lists the file once even with two
        successful actions on it."""
        out = _setup_output_dir(tmp_path)
        _write_fragment(out, "f.md", "AAA BBB CCC")
        plan = {
            "schema_version": 1,
            "actions": [
                {
                    "check": "1",
                    "type": "other",
                    "fragment": ".fragments/f.md",
                    "operation": {"op": "replace_string", "find": "AAA", "replace": "1"},
                },
                {
                    "check": "2",
                    "type": "other",
                    "fragment": ".fragments/f.md",
                    "operation": {"op": "replace_string", "find": "CCC", "replace": "3"},
                },
            ],
        }
        report = acr.apply_plan(plan, out)
        assert report["exit_code"] == 0
        assert report["applied"] == [0, 1]
        assert report["fragments_touched"] == [".fragments/f.md"]


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------


class TestCli:
    def test_no_plan_present_returns_zero(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        rc = acr.main([str(out)])
        assert rc == 0

    def test_invalid_plan_returns_three(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        plan_path = out / ".qa-content-repair-plan.json"
        plan_path.write_text(json.dumps({"schema_version": 99, "actions": []}))
        rc = acr.main([str(out)])
        assert rc == 3

    def test_dry_run_does_not_write(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        frag = _write_fragment(out, "x.md", "OLD")
        plan = {
            "schema_version": 1,
            "actions": [
                {
                    "check": "1",
                    "type": "other",
                    "fragment": ".fragments/x.md",
                    "operation": {"op": "replace_string", "find": "OLD", "replace": "NEW"},
                }
            ],
        }
        (out / ".qa-content-repair-plan.json").write_text(json.dumps(plan))
        rc = acr.main([str(out), "--dry-run"])
        assert rc == 0
        assert frag.read_text() == "OLD", "dry-run must not modify files"


# ---------------------------------------------------------------------------
# heading_rename_cascade (RC-2)
# ---------------------------------------------------------------------------


class TestHeadingRenameCascade:
    """RC-2 — H4 rename must cascade to all mechanical references:
    anchor tag, `**Controls covered:**` link, §7.1 overview-table row."""

    _FRAGMENT = (
        "### 7.1 Security Control Overview\n"
        "\n"
        "| Control category | Verdict | Main reason |\n"
        "|---|---|---|\n"
        "| [IAM](#72-iam) | 🟠 Weak | catalogued (e.g. JWT RS256 Authentication). |\n"
        "\n"
        "### 7.2 Identity and Authentication Controls\n"
        "\n"
        "**Controls covered:** [JWT RS256 Authentication](#jwt-rs256-authentication).\n"
        "\n"
        "**Implemented controls:** JWT RS256 signing via express-jwt.\n"
        "\n"
        '<a id="jwt-rs256-authentication"></a>\n'
        "\n"
        "#### 7.2.1 JWT RS256 Authentication\n"
        "\n"
        "**Security assessment**\n"
        "\n"
        "Broken because of T-001.\n"
    )

    def _make_plan(self, old: str = "JWT RS256 Authentication", new: str = "JWT Bearer Authentication") -> dict:
        return {
            "schema_version": 1,
            "actions": [
                {
                    "check": "subcontrol_naming_canonical",
                    "type": "heading_rename_cascade",
                    "fragment": ".fragments/security-architecture.md",
                    "operation": {
                        "op": "heading_rename_cascade",
                        "old_name": old,
                        "new_name": new,
                    },
                }
            ],
        }

    def test_cascade_updates_all_four_targets(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        frag = _write_fragment(out, "security-architecture.md", self._FRAGMENT)
        (out / ".qa-content-repair-plan.json").write_text(json.dumps(self._make_plan()))
        rc = acr.main([str(out)])
        assert rc == 0
        result = frag.read_text()
        # 1. H4 heading renamed
        assert "#### 7.2.1 JWT Bearer Authentication" in result
        assert "JWT RS256 Authentication" not in result.split("**Implemented controls:**")[0]
        # 2. anchor tag updated
        assert '<a id="jwt-bearer-authentication"></a>' in result
        assert '<a id="jwt-rs256-authentication"></a>' not in result
        # 3. `**Controls covered:**` link cascade
        assert "[JWT Bearer Authentication](#jwt-bearer-authentication)" in result
        # 4. §7.1 overview-table row mention
        assert "(e.g. JWT Bearer Authentication)" in result
        # narrative prose unchanged — RS256 in `**Implemented controls:**` is
        # a real algorithm name, not a mechanism heading.
        assert "JWT RS256 signing via express-jwt" in result

    def test_cascade_preserves_blank_line_after_heading(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        frag = _write_fragment(out, "security-architecture.md", self._FRAGMENT)
        (out / ".qa-content-repair-plan.json").write_text(json.dumps(self._make_plan()))
        acr.main([str(out)])
        result = frag.read_text()
        # The blank line between the H4 heading and **Security assessment**
        # must survive the rename — `\s*$` regex would eat the trailing newline.
        assert "JWT Bearer Authentication\n\n**Security assessment**" in result

    def test_cascade_rerun_is_noop_idempotent_via_new_plan(self, tmp_path):
        """A re-run of the SAME plan (old=RS256) must fail because the
        H4 needle has already been consumed. A plan with the NEW name as
        `old_name` should also no-op (old==new short-circuits)."""
        out = _setup_output_dir(tmp_path)
        frag = _write_fragment(out, "security-architecture.md", self._FRAGMENT)
        (out / ".qa-content-repair-plan.json").write_text(json.dumps(self._make_plan()))
        acr.main([str(out)])
        snapshot = frag.read_text()
        # Same plan again: H4 needle gone → action skipped, file untouched.
        rc2 = acr.main([str(out)])
        assert rc2 == 1  # action skipped because needle missing
        assert frag.read_text() == snapshot
        # Plan with old==new is a no-op.
        identity_plan = self._make_plan(old="JWT Bearer Authentication", new="JWT Bearer Authentication")
        (out / ".qa-content-repair-plan.json").write_text(json.dumps(identity_plan))
        rc3 = acr.main([str(out)])
        assert rc3 == 0
        assert frag.read_text() == snapshot

    def test_cascade_missing_heading_raises(self, tmp_path):
        out = _setup_output_dir(tmp_path)
        # Fragment has no `#### N.M.X JWT RS256 Authentication` heading.
        _write_fragment(out, "security-architecture.md", "### 7.2 IAM\n\nSome prose without the target heading.\n")
        (out / ".qa-content-repair-plan.json").write_text(json.dumps(self._make_plan()))
        rc = acr.main([str(out)])
        # action skipped → exit code 1
        assert rc == 1


# ---------------------------------------------------------------------------
# kebab helper
# ---------------------------------------------------------------------------


class TestKebabHelper:
    def test_kebab_basic(self):
        assert acr._kebab("JWT Bearer Authentication") == "jwt-bearer-authentication"

    def test_kebab_collapses_punctuation(self):
        assert acr._kebab("Foo / Bar:Baz") == "foo-bar-baz"

    def test_kebab_strips_edges(self):
        assert acr._kebab("--Foo--") == "foo"

    def test_kebab_numeric_preserved(self):
        assert acr._kebab("7.2.1 JWT Bearer") == "7-2-1-jwt-bearer"


# ---------------------------------------------------------------------------
# op-handler ↔ schema enum parity (TG-2, audit 2026-06-11)
# ---------------------------------------------------------------------------


def test_op_handlers_match_schema_op_consts():
    """Every `op` const the repair-plan schema declares must have a handler, and
    vice-versa — otherwise apply_content_repair silently rejects a valid plan or
    accepts an op the schema forbids. qa-content-repair-plan.schema.json was
    validated by no test until this audit."""
    schema = json.loads((REPO_ROOT / "schemas" / "qa-content-repair-plan.schema.json").read_text())
    declared: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            op = node.get("properties", {}).get("op", {})
            if isinstance(op, dict) and "const" in op:
                declared.add(op["const"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    assert declared == set(acr._OP_HANDLERS), (declared, set(acr._OP_HANDLERS))
