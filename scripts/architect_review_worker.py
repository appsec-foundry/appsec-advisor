"""One tool-free architect model call with externally enforced process bounds.

This transport is not an orchestrator: its caller owns admission, run identity,
packet selection, total stage allowance, result validation, and publication.
No target paths or model-authored strings become process arguments or commands.
"""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from architect_review import MAX_PROPOSAL_BYTES, ReviewError
from build_architect_context import _contracts, packet_bytes
from jsonschema import Draft202012Validator

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
MAX_TRANSPORT_BYTES = 524_288
_REQUIRED_FLAGS = ("--safe-mode", "--tools", "--strict-mcp-config", "--no-session-persistence", "--system-prompt")


@dataclass(frozen=True)
class WorkerResult:
    """Finite transport outcome; raw diagnostics never enter model artifacts."""

    status: str
    output: bytes = b""


def _terminate(process: subprocess.Popen) -> None:
    # The worker owns the complete session/process group. Kill even after the
    # leader exits: a child may retain a pipe or continue a model request.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _run_bounded(argv: list[str], payload: bytes, *, cwd: Path, timeout_seconds: float) -> WorkerResult:
    """Drain bounded pipes and stop the process group on every exit path."""
    if os.name != "posix":
        raise ReviewError("architect worker requires process-group termination")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ReviewError("architect worker has no remaining deadline")
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            start_new_session=True,
            close_fds=True,
            # This is the controller's bounded print-mode worker, not another
            # interactive session. Retain authentication and managed policy.
            env={key: value for key, value in os.environ.items() if key != "CLAUDECODE"},
        )
    except OSError:
        return WorkerResult("unavailable")
    output = bytearray()
    received = 0
    offset = 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            if payload:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return WorkerResult("deadline_exceeded")
                for key, _ in selector.select(min(remaining, 0.1)):
                    stream = key.fileobj
                    if stream is process.stdin:
                        try:
                            offset += os.write(stream.fileno(), payload[offset : offset + 8192])
                        except BrokenPipeError:
                            offset = len(payload)
                        if offset == len(payload):
                            selector.unregister(stream)
                            stream.close()
                        continue
                    data = os.read(stream.fileno(), 8192)
                    if not data:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    received += len(data)
                    if received > MAX_TRANSPORT_BYTES:
                        return WorkerResult("output_limit_exceeded")
                    if stream is process.stdout:
                        output.extend(data)
            try:
                code = process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                return WorkerResult("deadline_exceeded")
            if time.monotonic() > deadline:
                return WorkerResult("deadline_exceeded")
            return WorkerResult("completed", bytes(output)) if code == 0 else WorkerResult("failed")
    finally:
        _terminate(process)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def run_packet(
    packet: dict, *, model: str, timeout_seconds: float, telemetry: dict | None = None
) -> tuple[str, dict | None]:
    """Record elapsed time for successful and failed calls without raw diagnostics."""
    started = time.monotonic()
    if telemetry is not None:
        telemetry.clear()
    try:
        return _run_packet(packet, model=model, timeout_seconds=timeout_seconds, telemetry=telemetry)
    finally:
        if telemetry is not None:
            telemetry["wall_seconds"] = time.monotonic() - started


def _run_packet(
    packet: dict, *, model: str, timeout_seconds: float, telemetry: dict | None = None
) -> tuple[str, dict | None]:
    """Run one admitted packet; never retry or use a fallback model.

    A fresh private directory and safe mode exclude repository instructions and
    installed customizations. The host disables tools, skills and MCP entirely.
    Unsupported hosts fail closed. Subscription authentication is retained.
    The caller's deadline includes capability probing and request startup.
    """
    schema, _, _, registry = _contracts()
    validator = Draft202012Validator({"$ref": schema["$id"] + "#/$defs/packet"}, registry=registry)
    if not validator.is_valid(packet) or len(packet_bytes(packet)) > 131_072:
        raise ReviewError("invalid architect worker packet")
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}", model):
        raise ReviewError("invalid architect worker model")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ReviewError("invalid architect worker deadline")
    executable = shutil.which("claude")
    if executable is None or not Path(executable).is_absolute():
        return "unavailable", None
    try:
        executable = str(Path(executable).resolve(strict=True))
    except OSError:
        return "unavailable", None
    deadline = time.monotonic() + timeout_seconds
    prompt = (PLUGIN_ROOT / "agents/shared/architect-semantic-review.md").read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="appsec-architect-") as directory:
        cwd = Path(directory)
        capabilities = _run_bounded([executable, "--help"], b"", cwd=cwd, timeout_seconds=min(5, timeout_seconds))
        if capabilities.status != "completed" or any(
            flag.encode() not in capabilities.output for flag in _REQUIRED_FLAGS
        ):
            return "unsupported_host", None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "deadline_exceeded", None
        result = _run_bounded(
            [
                executable,
                "--print",
                "--safe-mode",
                "--tools",
                "",
                "--strict-mcp-config",
                "--mcp-config",
                '{"mcpServers":{}}',
                "--disable-slash-commands",
                "--no-session-persistence",
                "--no-chrome",
                "--setting-sources",
                "",
                "--permission-mode",
                "dontAsk",
                "--output-format",
                "json",
                "--model",
                model,
                "--system-prompt",
                prompt,
            ],
            packet_bytes(packet),
            cwd=cwd,
            timeout_seconds=remaining,
        )
    if result.status != "completed":
        return result.status, None
    try:
        response = json.loads(result.output)
        if isinstance(response, dict) and response.get("is_error") is True:
            return "failed", None
        if not isinstance(response, dict) or response.get("is_error") is not False:
            return "invalid_response", None
        if telemetry is not None:
            for field in ("duration_ms", "duration_api_ms", "num_turns"):
                value = response.get(field)
                if type(value) is int and 0 <= value < 2**63:
                    telemetry[field] = value
            cost = response.get("total_cost_usd")
            if type(cost) in (float, int) and 0 <= cost < 1_000_000:
                telemetry["total_cost_usd"] = cost
            usage = response.get("usage")
            if isinstance(usage, dict):
                telemetry["usage"] = {
                    field: usage[field]
                    for field in (
                        "input_tokens",
                        "output_tokens",
                        "cache_creation_input_tokens",
                        "cache_read_input_tokens",
                    )
                    if type(usage.get(field)) is int and 0 <= usage[field] < 2**63
                }
            models = response.get("modelUsage")
            if isinstance(models, dict) and len(models) <= 16:
                telemetry["model_ids"] = sorted(
                    name
                    for name in models
                    if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}", name)
                )
        raw = response.get("result")
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_PROPOSAL_BYTES:
            return "invalid_response", None
        proposal = json.loads(raw)
        if not isinstance(proposal, dict):
            return "invalid_response", None
    except (UnicodeError, ValueError, RecursionError):
        return "invalid_response", None
    return "completed", proposal
