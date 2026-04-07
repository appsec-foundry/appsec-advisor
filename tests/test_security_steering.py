"""
Tests for plugin/scripts/security_steering.py

The script reads JSON from stdin and writes JSON to stdout.
We test it as a subprocess to match its real execution context.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "plugin" / "scripts" / "security_steering.py"


def run_steering(prompt: str) -> dict:
    """Run the security steering script with the given prompt, return parsed stdout."""
    payload = json.dumps({"prompt": prompt})
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=payload,
        capture_output=True,
        text=True,
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
        assert "hookSpecificOutput" in out, (
            f"Expected injection for prompt: {prompt!r}\nGot: {out}"
        )

    @pytest.mark.parametrize("prompt", CODE_KEYWORD_PROMPTS)
    def test_code_keyword_combo_triggers_injection(self, prompt):
        out = run_steering(prompt)
        assert "hookSpecificOutput" in out, (
            f"Expected injection for prompt: {prompt!r}\nGot: {out}"
        )

    @pytest.mark.parametrize("prompt", CONVERSATIONAL_PROMPTS)
    def test_conversational_prompt_does_not_trigger(self, prompt):
        out = run_steering(prompt)
        assert out == {}, (
            f"Expected empty dict for prompt: {prompt!r}\nGot: {out}"
        )

    @pytest.mark.parametrize("prompt", FALSE_POSITIVE_PROMPTS)
    def test_generic_action_alone_does_not_trigger(self, prompt):
        out = run_steering(prompt)
        assert out == {}, (
            f"Expected no trigger for generic prompt: {prompt!r}\nGot: {out}"
        )

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
                input=payload, capture_output=True, text=True,
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
            input=payload, capture_output=True, text=True,
        )
        assert result.returncode == 0
        out = json.loads(result.stdout)
        assert out == {}
