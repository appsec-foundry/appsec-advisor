"""Shared pytest fixtures for the appsec-advisor test suite.

Historically every test file defined its own threat-dict builder, subprocess
runner, and hook-event factory. The resulting duplication (four variants of
`_run_<xxx>`, two variants of `_threat` / `_stride_threat`, inline
`make_pre_tool_event` / `make_post_tool_event`) made it hard to change any
shared pattern without touching half the suite.

This conftest centralizes those helpers as pytest fixtures. It is additive —
existing tests continue to work unchanged because their local helpers are
still present. New tests, and incrementally-migrated old tests, should prefer
these fixtures over redefining local copies.

Fixtures defined here:
    threat_factory       — build a threat dict with overridable fields
    run_plugin_script    — subprocess.run wrapper for any scripts/*.py
    hook_event           — build a PreToolUse / PostToolUse / Stop event dict
    output_dir           — tmp_path with docs/security/ pre-created
    plugin_root          — absolute Path to the plugin directory
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

# ---------------------------------------------------------------------------
# Resolved paths (module-level constants, cheap to compute once)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_ROOT = _REPO_ROOT
_PLUGIN_SCRIPTS = _PLUGIN_ROOT / "scripts"

if str(_PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SCRIPTS))


# ---------------------------------------------------------------------------
# plugin_root — absolute Path to the plugin directory
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def plugin_root() -> Path:
    """Absolute Path to appsec-advisor/.

    Useful for tests that need to resolve scripts, config, or agent definitions
    by path. Session-scoped because the location never changes during a run.
    """
    return _PLUGIN_ROOT


# ---------------------------------------------------------------------------
# output_dir — tmp_path with docs/security/ pre-created
# ---------------------------------------------------------------------------
@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    """Isolated OUTPUT_DIR with the canonical docs/security/ layout pre-created.

    Many tests need a writable directory that looks like a repo's
    `docs/security/` folder (so agent_logger and friends can drop log files
    there). This fixture returns that directory, with the parent repo
    layout rooted at tmp_path:

        <tmp_path>/
          docs/
            security/          ← returned as the fixture value
    """
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    return out


# ---------------------------------------------------------------------------
# threat_factory — build a threat dict with overridable fields
# ---------------------------------------------------------------------------
@pytest.fixture
def threat_factory() -> Callable[..., dict[str, Any]]:
    """Build a threat dict suitable for STRIDE / merger / triage fixtures.

    The defaults match the structure that `merge_threats.py`,
    `validate_intermediate.py`, and the STRIDE analyzer expect. Override any
    field via keyword argument:

        threat = threat_factory(t_id="T-042", severity="Critical")

    The factory returns a new dict on every call — modifying the return value
    does not leak into subsequent calls.

    Aliased fields:
        Some callers want the `title/cwe/stride/risk` skeleton (merge-tests),
        others want the `id/source/evidence` skeleton (cvss-eligibility).
        Both are populated by default; callers pass only the fields they
        actually assert on and ignore the rest.
    """

    def _build(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            # Identity — both styles
            "t_id": "T-001",
            "id": "T-001",
            # STRIDE classification
            "title": "SQL Injection in login handler",
            "cwe": "CWE-89",
            "stride": "Tampering",
            # Risk scoring
            "risk": "High",
            "severity": "High",
            "likelihood": "High",
            "impact": "High",
            # Evidence
            "evidence": {"file": "src/auth/login.py", "line": 42},
            # Provenance
            "source": "stride",
            "architectural_violation": False,
        }
        base.update(overrides)
        return base

    return _build


# ---------------------------------------------------------------------------
# run_plugin_script — subprocess wrapper for scripts/*.py
# ---------------------------------------------------------------------------
@pytest.fixture
def run_plugin_script() -> Callable[..., subprocess.CompletedProcess[str]]:
    """Run a script under scripts/ as a subprocess.

    Replaces the per-file `_run_cli` / `_run_pm` / `_run_bs` / `_run` helpers
    that just wrap `subprocess.run([python, <script>, *args])`.

    Usage:
        result = run_plugin_script("plugin_meta.py", "get", "plugin_version")
        assert result.returncode == 0
        assert "0.9" in result.stdout

        # Pass stdin (for hook scripts that read JSON from stdin)
        result = run_plugin_script("agent_logger.py", stdin={"tool_name": "..."})

        # Override cwd / env
        result = run_plugin_script("stride_progress.py", "/tmp/out", "3",
                                   cwd=my_tmp_path,
                                   env={"CLAUDE_PLUGIN_ROOT": str(plugin_root)})

    Arguments:
        script_name : file name under scripts/ (e.g. "plugin_meta.py").
                      Absolute paths are accepted as-is.
        *args       : positional CLI arguments.
        stdin       : optional dict → JSON-encoded as stdin; or a str → as-is.
        cwd         : working directory for the subprocess. Defaults to None.
        env         : dict of env vars. Merged onto os.environ if `env_extra=True`.
        env_extra   : if True (default), `env` is merged onto os.environ; if
                      False, `env` fully replaces it (useful for hermetic tests).
        check       : if True, raise on non-zero exit. Defaults to False.
    """

    def _run(
        script_name: str,
        *args: str,
        stdin: dict | str | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        env_extra: bool = True,
        check: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        script_path = Path(script_name)
        if not script_path.is_absolute():
            script_path = _PLUGIN_SCRIPTS / script_name
        if not script_path.exists():
            raise FileNotFoundError(f"plugin script not found: {script_path}")

        import os

        if env is None:
            effective_env = None
        elif env_extra:
            effective_env = {**os.environ, **env}
        else:
            effective_env = env

        payload: str | None = None
        if isinstance(stdin, dict):
            payload = json.dumps(stdin)
        elif isinstance(stdin, str):
            payload = stdin

        return subprocess.run(
            [sys.executable, str(script_path), *args],
            input=payload,
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else None,
            env=effective_env,
            check=check,
        )

    return _run


# ---------------------------------------------------------------------------
# hook_event — build a PreToolUse / PostToolUse / Stop / SubagentStop payload
# ---------------------------------------------------------------------------
@pytest.fixture
def hook_event() -> Callable[..., dict[str, Any]]:
    """Build a Claude Code hook event dict.

    Replaces the local `make_pre_tool_event` / `make_post_tool_event`
    helpers in test_agent_logger.py.

    Usage:
        event = hook_event("PreToolUse", tool="Bash", input={"command": "ls"})
        event = hook_event("PostToolUse", tool="Write",
                           input={"file_path": "/x"}, response="ok")
        event = hook_event("Stop", session_id="abc12345")

    The event shape follows Claude Code's hook payload contract:
        PreToolUse  → hook_event_name, session_id, tool_name, tool_input
        PostToolUse → above + tool_response, is_error
        Stop        → hook_event_name, session_id (+ optional stop_reason)

    Arguments:
        event_name : "PreToolUse" | "PostToolUse" | "Stop" | "SubagentStop" |
                     "UserPromptSubmit" | "SessionStart" | "Notification"
        tool       : tool_name value (only used for PreToolUse / PostToolUse)
        input      : tool_input dict (only used for PreToolUse / PostToolUse)
        response   : tool_response string (PostToolUse only)
        is_error   : error flag (PostToolUse only, default False)
        session_id : session identifier (default "testsid1")
        **extra    : any additional top-level fields (overrides the above)
    """

    def _build(
        event_name: str,
        *,
        tool: str | None = None,
        input: dict | None = None,
        response: str = "",
        is_error: bool = False,
        session_id: str = "testsid1",
        **extra: Any,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "hook_event_name": event_name,
            "session_id": session_id,
        }
        if event_name in {"PreToolUse", "PostToolUse"}:
            event["tool_name"] = tool or ""
            event["tool_input"] = input or {}
        if event_name == "PostToolUse":
            event["tool_response"] = response
            event["is_error"] = is_error
        event.update(extra)
        return event

    return _build


# ---------------------------------------------------------------------------
# Convenience: a pre-configured run_logger fixture built on top of
# run_plugin_script + output_dir, since agent_logger is the most-tested script
# ---------------------------------------------------------------------------
@pytest.fixture
def run_logger(
    run_plugin_script: Callable,
    output_dir: Path,
    plugin_root: Path,
) -> Callable[..., tuple[int, str]]:
    """Run agent_logger.py with a hook event; return (returncode, log_content).

    Bundles the three most common moving parts — output_dir, plugin_root env,
    and a stdin-fed hook event — into a single call. Replaces the
    `run_logger` helper duplicated at the top of test_agent_logger.py.

    Usage:
        rc, log = run_logger(hook_event("PreToolUse", tool="Bash",
                                        input={"command": "ls"}))
        assert rc == 0
        assert "PreToolUse" in log or "BASH_WARN" in log

    Returns:
        (returncode, log_file_content_or_empty_string)
    """

    def _run(event: dict[str, Any]) -> tuple[int, str]:
        # docs/security is already created by output_dir fixture; subprocess
        # runs with cwd = repo-root (the parent of docs/)
        repo_root = output_dir.parent.parent
        result = run_plugin_script(
            "agent_logger.py",
            stdin=event,
            cwd=repo_root,
            env={"CLAUDE_PLUGIN_ROOT": str(plugin_root)},
        )
        log_file = output_dir / ".hook-events.log"
        content = log_file.read_text() if log_file.exists() else ""
        return result.returncode, content

    return _run


# ---------------------------------------------------------------------------
# Small utility: assert that a log contains an event + key/value pair, with
# a diagnostic message that dumps the full log on failure (much better than
# the default `assert "X" in log` failure output which prints nothing useful).
# ---------------------------------------------------------------------------
def assert_log_has(log: str, *needles: str) -> None:
    """Assert every needle appears in the log; include full log on failure.

    Not a fixture — a plain helper importable via
    `from conftest import assert_log_has`. Kept in conftest (rather than a
    separate helper module) so the test suite has exactly one place for
    shared utility state.
    """
    missing = [n for n in needles if n not in log]
    if missing:
        raise AssertionError(
            f"log is missing {len(missing)} expected substring(s): "
            f"{missing!r}\n"
            f"--- full log ---\n{log or '(empty)'}\n--- end log ---"
        )
