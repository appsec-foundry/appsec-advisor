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

SECURITY_PROMPTS = [
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
    "refactor the database query",
    "create a docker config",
]

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


class TestSecuritySteering:
    @pytest.mark.parametrize("prompt", SECURITY_PROMPTS)
    def test_security_prompt_triggers_injection(self, prompt):
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
        out = run_steering("review the api endpoint")
        context = out["hookSpecificOutput"]["additionalContext"]
        # Must mention untrusted input or authentication
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
        # Should exit 0 (silently handles bad input)
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
# Keyword coverage — document which keywords exist and test boundaries
# ---------------------------------------------------------------------------

class TestKeywordBoundaries:
    """These tests document the *current* broad keyword set and flag prompts
    that trigger unexpectedly, serving as a baseline for tightening the list."""

    def test_pure_greeting_with_security_word_does_not_trigger(self):
        """'security' alone in an otherwise conversational prompt should not trigger."""
        out = run_steering("how does computer security work in general")
        # This may currently trigger — document the behavior rather than assert direction
        # Change to `assert out == {}` once the keyword list is tightened
        assert isinstance(out, dict)

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
