#!/usr/bin/env python3
"""Offline stand-in for the `claude` CLI that the assessment controller launches.

The controller starts every tool-less model exchange as `claude -p ...` through
`ClaudeCliTransport`. This stub answers those calls with the contract-valid
replies of the test suite's `FullHost`, in the CLI's own `json` or
`stream-json` result format, so `scripts/run-headless.sh` and the controller
run end to end as separate processes without network access or cost.

It never runs outside tests: the caller points `APPSEC_CLAUDE_EXECUTABLE` at it.
Its own variables avoid the `APPSEC_` prefix, which the transport strips.

Environment:
  FAKE_CLAUDE_REPOS   os.pathsep-separated checkouts the run assesses.
  FAKE_CLAUDE_OUTPUT  The run's output directory.
  FAKE_CLAUDE_STATE   Directory for the call log (`calls.jsonl`) and fault counters.
  FAKE_CLAUDE_FAULTS  Comma-separated `<role|*>:<kind>:<count>` entries. The
                             first <count> calls of the role (or of any role for `*`)
                             fail with <kind>: rate_limit, server_error, no_result,
                             text, auth.

The role of a call is read from its private host directory, which the
controller names `<role>-<random>/work`.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

FAULT_KINDS = ("rate_limit", "server_error", "no_result", "text", "auth")


def _option(argv: list[str], name: str) -> str | None:
    return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else None


def _role() -> str:
    return Path.cwd().parent.name.rsplit("-", 1)[0]


def _state() -> Path:
    state = Path(os.environ["FAKE_CLAUDE_STATE"])
    state.mkdir(parents=True, exist_ok=True)
    return state


def _fault(role: str) -> str | None:
    """Consume one planned failure for this role, if any remain."""
    plan = [entry.split(":") for entry in os.environ.get("FAKE_CLAUDE_FAULTS", "").split(",") if entry]
    with open(_state() / "faults.lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        counters_path = _state() / "faults.json"
        counters = json.loads(counters_path.read_text()) if counters_path.exists() else {}
        chosen = None
        for index, (target, kind, count) in enumerate(plan):
            if kind not in FAULT_KINDS:
                raise SystemExit(f"fake claude: unknown fault kind {kind}")
            key = f"{index}:{target}:{kind}"
            if target in ("*", role) and counters.get(key, 0) < int(count):
                counters[key] = counters.get(key, 0) + 1
                chosen = kind
                break
        counters_path.write_text(json.dumps(counters))
    return chosen


def _log(row: dict) -> None:
    with open(_state() / "calls.jsonl", "a", encoding="utf-8") as sink:
        fcntl.flock(sink, fcntl.LOCK_EX)
        sink.write(json.dumps(row) + "\n")


def _answer(role: str, system: str, prompt: str, schema: dict) -> dict:
    from runtime import multi_repo_scope

    from tests.test_multi_repo_assessment import FullHost

    host = FullHost()
    repos = [path for path in os.environ["FAKE_CLAUDE_REPOS"].split(os.pathsep) if path]
    host.scope = multi_repo_scope.admit(repos, os.environ["FAKE_CLAUDE_OUTPUT"], minimum=1)
    return host.invoke(role, system, prompt, schema, 600, lambda: False).payload


def _result(role: str, kind: str | None, payload: dict | None) -> tuple[dict, str | None]:
    """The CLI's result event, and the error code its assistant message carries."""
    base = {"type": "result", "subtype": "success", "is_error": False, "total_cost_usd": 0.01, "num_turns": 1}
    if kind is None:
        return {**base, "result": "", "structured_output": payload}, None
    if kind == "text":
        return {**base, "result": "I could not produce the requested JSON."}, None
    status, code = {
        "rate_limit": (429, "rate_limit"),
        "server_error": (529, "server_error"),
        "auth": (401, "authentication_failed"),
    }[kind]
    return {**base, "is_error": True, "total_cost_usd": 0.0, "api_error_status": status, "result": "API error"}, code


def main(argv: list[str]) -> int:
    if argv[:2] == ["auth", "status"]:
        print(json.dumps({"loggedIn": True, "authMethod": "fake"}, indent=2))
        return 0
    if "-p" not in argv:
        print("fake claude: only -p and auth status are supported", file=sys.stderr)
        return 2
    role = _role()
    prompt = sys.stdin.read()
    schema = json.loads(_option(argv, "--json-schema") or "{}")
    system = _option(argv, "--system-prompt") or ""
    kind = _fault(role)
    _log({"role": role, "model": _option(argv, "--model"), "fault": kind})
    if kind == "no_result":
        return 1
    payload = _answer(role, system, prompt, schema) if kind is None else None
    result, code = _result(role, kind, payload)
    if _option(argv, "--output-format") == "stream-json":
        print(json.dumps({"type": "system", "subtype": "init", "model": _option(argv, "--model")}))
        assistant = {"type": "assistant", "message": {"content": []}}
        if code:
            assistant["error"] = code
        print(json.dumps(assistant))
        print(json.dumps(result))
    else:
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
