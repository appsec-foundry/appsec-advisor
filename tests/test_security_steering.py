"""
Tests for scripts/security_steering.py

The script reads JSON from stdin and writes JSON to stdout.
We test it as a subprocess to match its real execution context.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "security_steering.py"


def run_steering(prompt: str, env_override: dict | None = None) -> dict:
    """Run the security steering script with the given prompt, return parsed stdout.

    By default the coach is force-enabled via APPSEC_COACH=1 (the shipped config
    defaults to disabled — opt-in). Pass ``env_override`` to test activation
    behaviour explicitly (e.g. ``env_override={"APPSEC_COACH": "0"}`` for off).
    """
    payload = json.dumps({"prompt": prompt})
    env = os.environ.copy()
    env["APPSEC_COACH"] = "1"
    if env_override is not None:
        for k, v in env_override.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, f"Script exited {result.returncode}: {result.stderr}"
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Prompts that SHOULD trigger injection
# ---------------------------------------------------------------------------

# Strong keywords (single match triggers)
STRONG_KEYWORD_PROMPTS = [
    "review this authentication code",
    "fix the sql injection vulnerability",
    "implement JWT token validation",
    "encrypt the password before storing",
    "check this endpoint for security issues",
    "scan for vulnerabilities in this function",
    "is this oauth flow secure",
    "review the threat model",
    "run stride analysis",
    "appsec review of the auth module",
    "help me implement the login function",
]

# Code keywords (2+ matches trigger)
CODE_KEYWORD_PROMPTS = [
    "refactor the database query",
    "create a docker config",
    "write the api endpoint",
    "build the middleware function",
    "fix this http request handler",
    "review the controller code",
    "add upload function to the api",
]

# ---------------------------------------------------------------------------
# Prompts that should NOT trigger injection
# ---------------------------------------------------------------------------

CONVERSATIONAL_PROMPTS = [
    "hello, how are you?",
    "thanks for your help",
    "what time is it",
    "tell me a joke",
    "summarize this meeting",
    "what is the capital of france",
    "good morning",
    "can you explain this concept",
]

# Generic action keywords alone should not trigger
FALSE_POSITIVE_PROMPTS = [
    "create a README",
    "build the project",
    "write a poem",
    "add a comment to the issue",
    "fix the typo in the document",
    "review the meeting notes",
    "refactor the paragraph",
    "create a summary of last week",
]


class TestSecuritySteering:
    @pytest.mark.parametrize("prompt", STRONG_KEYWORD_PROMPTS)
    def test_strong_keyword_triggers_injection(self, prompt):
        out = run_steering(prompt)
        assert "hookSpecificOutput" in out, f"Expected injection for prompt: {prompt!r}\nGot: {out}"

    @pytest.mark.parametrize("prompt", CODE_KEYWORD_PROMPTS)
    def test_code_keyword_combo_triggers_injection(self, prompt):
        out = run_steering(prompt)
        assert "hookSpecificOutput" in out, f"Expected injection for prompt: {prompt!r}\nGot: {out}"

    @pytest.mark.parametrize("prompt", CONVERSATIONAL_PROMPTS)
    def test_conversational_prompt_does_not_trigger(self, prompt):
        out = run_steering(prompt)
        assert out == {}, f"Expected empty dict for prompt: {prompt!r}\nGot: {out}"

    @pytest.mark.parametrize("prompt", FALSE_POSITIVE_PROMPTS)
    def test_generic_action_alone_does_not_trigger(self, prompt):
        out = run_steering(prompt)
        assert out == {}, f"Expected no trigger for generic prompt: {prompt!r}\nGot: {out}"

    def test_triggered_output_has_correct_structure(self):
        out = run_steering("review this auth code")
        assert "hookSpecificOutput" in out
        hook = out["hookSpecificOutput"]
        assert hook.get("hookEventName") == "UserPromptSubmit"
        assert "additionalContext" in hook
        assert isinstance(hook["additionalContext"], str)
        assert len(hook["additionalContext"]) > 0

    def test_triggered_output_has_system_message(self):
        out = run_steering("fix this security issue")
        assert "systemMessage" in out
        assert isinstance(out["systemMessage"], str)

    def test_triggered_context_mentions_secure_defaults(self):
        out = run_steering("implement the login endpoint")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "secure" in context.lower()

    def test_triggered_context_mentions_input_validation(self):
        out = run_steering("review the api endpoint for auth")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert any(term in context.lower() for term in ["untrusted", "authenticat", "privilege", "secret"])

    def test_empty_prompt_does_not_crash(self):
        out = run_steering("")
        assert isinstance(out, dict)

    def test_malformed_stdin_does_not_crash(self):
        """Script must not crash on non-JSON input."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input="this is not json",
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

    def test_case_insensitive_matching(self):
        """Keyword detection must be case-insensitive (prompt is lowercased in script)."""
        out_lower = run_steering("check the AUTH module")
        out_upper = run_steering("CHECK THE AUTH MODULE")
        assert ("hookSpecificOutput" in out_lower) == ("hookSpecificOutput" in out_upper)

    def test_output_is_valid_json(self):
        """Stdout must always be valid JSON, even for non-triggering prompts."""
        for prompt in ["hello world", "review auth code"]:
            payload = json.dumps({"prompt": prompt})
            result = subprocess.run(
                [sys.executable, str(SCRIPT)],
                input=payload,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0
            json.loads(result.stdout)  # must not raise


# ---------------------------------------------------------------------------
# Tiered keyword logic tests
# ---------------------------------------------------------------------------


class TestTieredKeywords:
    def test_single_strong_keyword_triggers(self):
        """A single strong keyword like 'security' is enough to trigger."""
        out = run_steering("how does security work")
        assert "hookSpecificOutput" in out

    def test_single_code_keyword_does_not_trigger(self):
        """A single code keyword like 'api' is not enough alone."""
        out = run_steering("what is an api")
        assert out == {}

    def test_two_code_keywords_trigger(self):
        """Two code keywords together trigger."""
        out = run_steering("deploy the docker container")
        assert "hookSpecificOutput" in out

    def test_action_plus_code_triggers(self):
        """One action keyword + one code keyword triggers."""
        out = run_steering("create an api")
        assert "hookSpecificOutput" in out

    def test_single_action_keyword_does_not_trigger(self):
        """A single action keyword alone must not trigger."""
        out = run_steering("create something nice")
        assert out == {}

    def test_two_action_keywords_do_not_trigger(self):
        """Multiple action keywords without code/strong keywords must not trigger."""
        out = run_steering("create and build and review")
        assert out == {}

    def test_prompt_missing_data_field_treated_as_empty(self):
        """If JSON has no 'prompt' key, treat as empty and do not inject."""
        payload = json.dumps({"other": "value"})
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=payload,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        out = json.loads(result.stdout)
        assert out == {}


# ---------------------------------------------------------------------------
# Topic-specific guidance and requirements injection
# ---------------------------------------------------------------------------


class TestTopicGuidance:
    def test_auth_prompt_injects_auth_guidance(self):
        out = run_steering("how should I handle jwt refresh")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "[auth]" in context
        # Auth-specific hints
        assert any(term in context.lower() for term in ["jwt", "session", "token"])

    def test_injection_prompt_injects_injection_guidance(self):
        out = run_steering("build a sql query from user input")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "[injection]" in context
        assert "parameterized" in context.lower()

    def test_crypto_prompt_injects_crypto_guidance(self):
        out = run_steering("which algorithm to hash the password")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "[crypto]" in context
        assert any(term in context.lower() for term in ["argon2", "bcrypt"])

    def test_xss_csrf_prompt_injects_xss_guidance(self):
        out = run_steering("configure csp headers for this endpoint")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "[xss_csrf]" in context
        assert "csp" in context.lower()

    def test_iac_prompt_injects_iac_guidance(self):
        out = run_steering("write the dockerfile with non-root user")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "[iac]" in context
        assert any(term in context.lower() for term in ["non-root", "capabilities", "privileged"])

    def test_llm_prompt_injects_llm_guidance(self):
        out = run_steering("defend the agent against prompt injection")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "[llm]" in context
        assert "owasp llm" in context.lower()

    def test_multiple_topics_aggregate(self):
        out = run_steering("review the jwt token and the sql query code")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "[auth]" in context
        assert "[injection]" in context

    def test_general_topic_has_no_guidance_block(self):
        """General keywords trigger but do not add a topic section — only baseline."""
        out = run_steering("review this for vulnerabilities")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "[general]" not in context
        # Baseline still injected
        assert "secure" in context.lower()

    def test_system_message_lists_matched_topics(self):
        out = run_steering("encrypt the password with aes")
        msg = out.get("systemMessage", "")
        assert "crypto" in msg


# ---------------------------------------------------------------------------
# Requirements resolution from YAML
# ---------------------------------------------------------------------------


class TestRequirementsInjection:
    """Verify that configured topic.requirements resolve against the bundled
    fallback YAML and are rendered into the injected context."""

    def test_injection_topic_resolves_sec_sql(self):
        out = run_steering("write a parameterized sql query")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "Applicable requirements:" in context
        assert "SEC-SQL" in context

    def test_xss_topic_resolves_sec_csp(self):
        out = run_steering("set strict csp headers on the controller")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "SEC-CSP" in context or "SEC-ANTI-CSRF" in context or "SEC-CORS" in context

    def test_crypto_topic_resolves_sec_tls(self):
        out = run_steering("configure tls on the endpoint")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "SEC-TLS" in context

    def test_requirement_includes_priority(self):
        out = run_steering("prevent sql injection")
        context = out["hookSpecificOutput"]["additionalContext"]
        # Priority is rendered in parentheses after the ID
        assert "SEC-SQL" in context and "(" in context and ")" in context

    def test_topic_without_requirements_omits_block(self):
        """IaC topic has no requirements listed — the 'Applicable requirements:'
        header must not appear for an IaC-only hit."""
        out = run_steering("harden the dockerfile")
        context = out["hookSpecificOutput"]["additionalContext"]
        assert "[iac]" in context
        # No requirements configured for iac, and no other topic fired
        assert "Applicable requirements:" not in context


# ---------------------------------------------------------------------------
# Activation / opt-in behaviour
# ---------------------------------------------------------------------------


class TestActivation:
    """The coach is opt-in: disabled by default, activated via env var or config.

    The shipped steering_keywords.json sets ``"enabled": false``. Activation
    sources (in precedence order): APPSEC_COACH env var, then config.enabled.
    """

    # A prompt that WOULD trigger if the coach were active (auth topic).
    ACTIVE_PROMPT = "review the jwt token validation"

    def test_default_disabled_no_trigger(self):
        """With neither env nor truthy config, a security prompt must not trigger."""
        # Unset APPSEC_COACH (the helper sets it to "1" by default)
        out = run_steering(self.ACTIVE_PROMPT, env_override={"APPSEC_COACH": None})
        assert out == {}, f"Coach fired while disabled: {out}"

    def test_env_var_truthy_activates(self):
        for value in ("1", "true", "yes", "on", "enabled"):
            out = run_steering(self.ACTIVE_PROMPT, env_override={"APPSEC_COACH": value})
            assert "hookSpecificOutput" in out, f"APPSEC_COACH={value!r} did not activate the coach: {out}"

    def test_env_var_falsy_keeps_off(self):
        for value in ("0", "false", "no", "off", "disabled"):
            out = run_steering(self.ACTIVE_PROMPT, env_override={"APPSEC_COACH": value})
            assert out == {}, f"APPSEC_COACH={value!r} did not disable the coach: {out}"

    def test_env_var_falsy_overrides_config_true(self, tmp_path, monkeypatch):
        """Env var precedence: explicit off wins over config enabled=true."""
        # Write a config that has enabled=true, via a temporary CLAUDE_PLUGIN_ROOT.
        root = tmp_path
        (root / "hooks").mkdir(parents=True)
        # Copy shipped config content minus 'enabled' to keep triggers intact
        real_cfg = json.loads((Path(__file__).parent.parent / "hooks" / "steering_keywords.json").read_text())
        real_cfg["enabled"] = True
        (root / "hooks" / "steering_keywords.json").write_text(json.dumps(real_cfg))

        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps({"prompt": self.ACTIVE_PROMPT}),
            capture_output=True,
            text=True,
            env={**os.environ, "CLAUDE_PLUGIN_ROOT": str(root), "APPSEC_COACH": "0"},
        )
        assert result.returncode == 0
        assert json.loads(result.stdout) == {}, "env=0 must override config enabled=true"

    def test_config_enabled_true_activates_without_env(self, tmp_path):
        """Without env var, config.enabled=true alone activates the coach."""
        root = tmp_path
        (root / "hooks").mkdir(parents=True)
        real_cfg = json.loads((Path(__file__).parent.parent / "hooks" / "steering_keywords.json").read_text())
        real_cfg["enabled"] = True
        (root / "hooks" / "steering_keywords.json").write_text(json.dumps(real_cfg))

        env = {k: v for k, v in os.environ.items() if k != "APPSEC_COACH"}
        env["CLAUDE_PLUGIN_ROOT"] = str(root)

        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps({"prompt": self.ACTIVE_PROMPT}),
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0
        out = json.loads(result.stdout)
        assert "hookSpecificOutput" in out, f"config enabled=true did not activate the coach: {out}"

    def test_system_message_names_activation_source(self):
        """Once active, the systemMessage must state which source enabled it."""
        out = run_steering(self.ACTIVE_PROMPT, env_override={"APPSEC_COACH": "1"})
        msg = out.get("systemMessage", "")
        assert "via env" in msg, f"source 'env' not surfaced in systemMessage: {msg!r}"


class TestOrgProfileActivation:
    """The coach activates when an active org profile sets
    ``security_coach.enabled_by_default``, even without APPSEC_COACH or
    ``hooks/steering_keywords.json`` enabled=true."""

    ACTIVE_PROMPT = "review the authentication code"

    def _stage_plugin_root(self, tmp_path: Path, profile_enabled: bool) -> Path:
        """Build a fake plugin root with hooks/, config.json, and a profile
        that enables (or not) the coach by default."""
        root = tmp_path / "plugin"
        (root / "hooks").mkdir(parents=True)
        # Hook config disabled — coach must not activate via the static file.
        static = json.loads(
            (Path(__file__).parent.parent / "hooks" / "steering_keywords.json").read_text()
        )
        static["enabled"] = False
        (root / "hooks" / "steering_keywords.json").write_text(json.dumps(static))
        # Stage the org profile + config.json pointer.
        (root / "org-profile" / "context").mkdir(parents=True)
        (root / "org-profile" / "context" / "sso.md").write_text(
            "---\nid: x\ntype: ecosystem_context\n---\n\n# X\n"
        )
        profile = {
            "api_version": "appsec-advisor.org-profile/v1",
            "organization": {"id": "acme", "name": "Acme", "profile_version": "test"},
            "compatibility": {"core": ">=0.0 <999.0"},
            "default_preset": "ci-standard",
            "security_coach": {
                "enabled_by_default": profile_enabled,
                "max_requirements_per_topic": 2,
            },
            "presets": {
                "ci-standard": {"base_mode": "standard"},
            },
        }
        import yaml
        (root / "org-profile" / "org-profile.yaml").write_text(yaml.safe_dump(profile))
        (root / "config.json").write_text(
            json.dumps({
                "external_context": {"enabled": False, "rest_url": None},
                "organization_profile": {
                    "enabled": True,
                    "path": "org-profile/org-profile.yaml",
                    "default_preset": None,
                },
            })
        )
        return root

    def _run(self, plugin_root: Path, *, force_env: str | None) -> dict:
        env = {k: v for k, v in os.environ.items() if k != "APPSEC_COACH"}
        env["CLAUDE_PLUGIN_ROOT"] = str(plugin_root)
        if force_env is not None:
            env["APPSEC_COACH"] = force_env
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps({"prompt": self.ACTIVE_PROMPT}),
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def test_org_profile_default_activates_coach(self, tmp_path):
        root = self._stage_plugin_root(tmp_path, profile_enabled=True)
        out = self._run(root, force_env=None)
        assert "hookSpecificOutput" in out, out
        assert "via org-profile" in out.get("systemMessage", "")

    def test_org_profile_default_off_keeps_coach_inactive(self, tmp_path):
        root = self._stage_plugin_root(tmp_path, profile_enabled=False)
        out = self._run(root, force_env=None)
        assert out == {}, out

    def test_env_kill_switch_beats_org_profile_default(self, tmp_path):
        root = self._stage_plugin_root(tmp_path, profile_enabled=True)
        out = self._run(root, force_env="0")
        assert out == {}, out


def test_steering_falls_back_to_bestpractices_baseline(tmp_path):
    """Gap B: with no company catalog present, the steering hook resolves BP-*
    requirement text from the bundled best-practices baseline. The xss_csrf topic
    lists SEC-* ids FIRST, so this also proves the filter-then-cap fix (cap-first
    would have injected zero under a baseline-only catalog)."""
    import shutil

    repo = Path(__file__).parent.parent
    root = tmp_path / "plugin"
    (root / "hooks").mkdir(parents=True)
    (root / "data").mkdir(parents=True)

    sk = json.loads((repo / "hooks" / "steering_keywords.json").read_text())
    sk["enabled"] = True
    (root / "hooks" / "steering_keywords.json").write_text(json.dumps(sk))
    # Only the baseline catalog is reachable under this plugin root.
    shutil.copy(
        repo / "data" / "appsec-bestpractices-baseline.yaml",
        root / "data" / "appsec-bestpractices-baseline.yaml",
    )

    env = os.environ.copy()
    env["APPSEC_COACH"] = "1"
    env["CLAUDE_PLUGIN_ROOT"] = str(root)
    payload = json.dumps(
        {"prompt": "add a content-security-policy header and fix the xss output encoding"}
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "")
    assert "BP-" in ctx, f"expected a BP-* requirement injected, got:\n{ctx}"
    assert "- SEC-" not in ctx, f"no SEC-* line should appear under baseline-only:\n{ctx}"
