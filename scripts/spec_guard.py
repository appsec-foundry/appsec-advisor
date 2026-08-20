#!/usr/bin/env python3
"""Ask before an identifiable tool call mutates a protected specification path.

The project requirements say that specifications change only with operator
approval. This Claude Code ``PreToolUse`` hook reinforces that rule for native
file writes, recognizable shell writes, and recognizable MCP mutations.

The protected file or directory is required through ``--protected-path`` so the
hook registration owns the protected surface. Reads and recognized read-only
shell calls are left alone. Writer detection is conservative: prompting for a
command that could mutate the protected path is preferable to silently missing
the mutation.

Malformed relevant input and internal resolution failures fail closed. The hook
cannot infer an opaque program's hidden writes; project instructions and diff
review remain necessary for those calls.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

WRITE_TOOLS = {
    "Write": "file_path",
    "Edit": "file_path",
    "MultiEdit": "file_path",
    "NotebookEdit": "notebook_path",
}

SHELL_WRITES = re.compile(
    r"""
      (?<! [<>] ) (?: [0-9]+ )? >>? (?! [>&] )
    | << -? \s* [\"']? [A-Za-z_]
    | \b tee \b
    | \b sponge \b
    | \b sed \b [^\n|]* -i
    | \b dd \b [^\n|;&]* \b of \s* =
    | \b (?: rm | mv | cp | install | truncate | touch | mkdir | ln | chmod ) \b
    | \b (?: rsync | unzip ) \b
    | \b git \s+ (?: checkout | restore | apply | rm | mv | clean | clone ) \b
    | \b curl \b [^\n|;&]* \s (?: -o | --output ) \b
    | \b tar \b [^\n|;&]* \s (?: -[A-Za-z]*x[A-Za-z]* | --extract ) \b
    | \b find \b [^\n|;&]* \s -delete \b
    | \b (?: python3? | perl | ruby | node ) \b [^\n]* \s (?: -c | -e ) \s
    """,
    re.VERBOSE,
)

POWERSHELL_WRITES = re.compile(
    r"""
      \b (?:
        Add-Content | Clear-Content | Copy-Item | Move-Item | New-Item |
        Out-File | Remove-Item | Rename-Item | Set-Content | Tee-Object
      ) \b
    | \b Invoke-WebRequest \b [^\n|;]* (?<! \w ) -OutFile \b
    """,
    re.IGNORECASE | re.VERBOSE,
)

MCP_MUTATION = re.compile(
    r"(?:^|_)(?:append|apply|copy|create|delete|edit|mkdir|move|patch|remove|rename|"
    r"save|touch|truncate|update|upload|write)(?:_|$)",
    re.IGNORECASE,
)

PATH_KEYS = {
    "dest",
    "destination",
    "directory",
    "dir",
    "file",
    "file_path",
    "filepath",
    "new_path",
    "notebook_path",
    "old_path",
    "path",
    "paths",
    "source_path",
    "target",
    "target_path",
}

REASON = (
    "This call would change {target}, which can affect the protected specification "
    "{protected_path}. The project requirements require the user's explicit "
    "approval. Describe the proposed specification change and let the user decide. "
    "Reading protected files needs no approval."
)


class InvalidPayload(ValueError):
    """A matched hook call cannot be interpreted safely."""


class InvalidConfiguration(ValueError):
    """The hook did not identify a safe protected path."""


def parse_protected_path(argv: Sequence[str]) -> Path:
    """Return the required absolute protected file or directory."""
    if len(argv) != 2 or argv[0] != "--protected-path" or not argv[1]:
        raise InvalidConfiguration("expected --protected-path with one path")
    candidate = Path(argv[1]).expanduser()
    if not candidate.is_absolute():
        raise InvalidConfiguration("protected path must be absolute")
    protected_path = candidate.resolve()
    if protected_path == Path(protected_path.anchor):
        raise InvalidConfiguration("protected path must not be a filesystem root")
    if not protected_path.exists():
        raise InvalidConfiguration("protected path does not exist")
    return protected_path


def expand_known_roots(value: str, cwd: Path) -> str:
    """Expand only Claude/PWD path spellings needed for target resolution."""
    replacements = {"${PWD}": str(cwd), "$PWD": str(cwd)}
    project_tokens = (
        "${env:CLAUDE_PROJECT_DIR}",
        "${CLAUDE_PROJECT_DIR}",
        "%CLAUDE_PROJECT_DIR%",
        "$env:CLAUDE_PROJECT_DIR",
        "$CLAUDE_PROJECT_DIR",
    )
    if any(token in value for token in project_tokens):
        configured_root = os.environ.get("CLAUDE_PROJECT_DIR")
        if not configured_root:
            raise InvalidPayload("CLAUDE_PROJECT_DIR is required to resolve the target")
        project_dir = Path(configured_root).expanduser()
        if not project_dir.is_absolute():
            raise InvalidPayload("CLAUDE_PROJECT_DIR must be absolute")
        replacements.update({token: str(project_dir.resolve()) for token in project_tokens})
    for token, replacement in replacements.items():
        value = value.replace(token, replacement)
    return value


def touches_protected(
    path: str,
    protected_path: Path,
    base: Path,
    *,
    include_ancestors: bool = False,
) -> bool:
    """Return whether ``path`` can identify or contain the protected path."""
    if not path:
        return False
    candidate = Path(expand_known_roots(path, base)).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    resolved = candidate.resolve()
    if resolved == protected_path:
        return True
    if protected_path.is_dir() and protected_path in resolved.parents:
        return True
    return include_ancestors and resolved in protected_path.parents


def payload_cwd(payload: Mapping[str, object]) -> Path:
    """Return the absolute working directory reported by Claude Code."""
    value = payload.get("cwd")
    if not isinstance(value, str) or not value:
        raise InvalidPayload("cwd must be a non-empty string")
    cwd = Path(value).expanduser()
    if not cwd.is_absolute():
        raise InvalidPayload("cwd must be absolute")
    return cwd.resolve()


def protected_path_reference(protected_path: Path) -> re.Pattern[str]:
    """Match embedded paths containing the protected path's basename."""
    name = re.escape(protected_path.name)
    return re.compile(r"(?<![\w.-])(?:[A-Za-z]:)?(?:[~.\w-]*[\\/])*" + name + r"(?:[\\/][\w.~ -]*)?")


def path_candidates(command: str, cwd: Path, protected_path: Path) -> Iterator[str]:
    """Yield shell tokens and embedded references to the protected path."""
    expanded = expand_known_roots(command, cwd)
    try:
        words = shlex.split(expanded, comments=False)
    except ValueError:
        words = expanded.split()
    for word in words:
        cleaned = word.strip("'\"`,;()[]{}<>")
        if cleaned:
            yield cleaned
        if "=" in cleaned:
            value = cleaned.split("=", 1)[1]
            if value:
                yield value.strip("'\"")
    pattern = protected_path_reference(protected_path)
    yield from (match.group(0) for match in pattern.finditer(expanded))


def shell_targets(command: str, cwd: Path, tool_name: str, protected_path: Path) -> list[str]:
    """Return protected paths named by a recognizable shell writer."""
    writes = SHELL_WRITES.search(command)
    if tool_name == "PowerShell":
        writes = writes or POWERSHELL_WRITES.search(command)
    if not writes:
        return []
    targets = {
        candidate
        for candidate in path_candidates(command, cwd, protected_path)
        if touches_protected(candidate, protected_path, cwd, include_ancestors=True)
    }
    return sorted(targets)


def string_values(value: object) -> Iterator[str]:
    """Yield strings from a path-valued MCP field without inspecting content."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            yield from string_values(item)


def mcp_path_values(value: object) -> Iterator[str]:
    """Yield values from recursively nested MCP fields that are path-shaped."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in PATH_KEYS or normalized.endswith(("_path", "_paths")):
                yield from string_values(child)
            else:
                yield from mcp_path_values(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in value:
            yield from mcp_path_values(child)


def mcp_targets(
    tool_name: str,
    tool_input: Mapping[str, object],
    cwd: Path,
    protected_path: Path,
) -> list[str]:
    """Return protected targets from a recognizably mutating MCP tool."""
    action = tool_name.rsplit("__", 1)[-1]
    if not MCP_MUTATION.search(action):
        return []
    return sorted(
        {
            path
            for path in mcp_path_values(tool_input)
            if touches_protected(path, protected_path, cwd, include_ancestors=True)
        }
    )


def decide(payload: dict, protected_path: Path) -> dict | None:
    """Return an ask decision for a protected mutation, otherwise ``None``."""
    if payload.get("hook_event_name") != "PreToolUse":
        raise InvalidPayload("expected a PreToolUse payload")
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_name, str) or not isinstance(tool_input, dict):
        raise InvalidPayload("tool_name and tool_input are required")
    cwd = payload_cwd(payload)

    if tool_name in WRITE_TOOLS:
        path = tool_input.get(WRITE_TOOLS[tool_name])
        if not isinstance(path, str) or not path:
            raise InvalidPayload(f"{tool_name} requires a path")
        if not touches_protected(path, protected_path, cwd):
            return None
        target = path
    elif tool_name in {"Bash", "PowerShell"}:
        command = tool_input.get("command")
        if not isinstance(command, str) or not command:
            raise InvalidPayload(f"{tool_name} requires a command")
        targets = shell_targets(command, cwd, tool_name, protected_path)
        if not targets:
            return None
        target = ", ".join(targets)
    elif tool_name.startswith("mcp__"):
        targets = mcp_targets(tool_name, tool_input, cwd, protected_path)
        if not targets:
            return None
        target = ", ".join(targets)
    else:
        return None

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": REASON.format(target=target, protected_path=protected_path),
        }
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    raw = sys.stdin.read()
    try:
        protected_path = parse_protected_path(argv)
        payload = json.loads(raw or "{}")
        if not isinstance(payload, dict):
            raise InvalidPayload("hook payload must be an object")
        response = decide(payload, protected_path)
    except (json.JSONDecodeError, InvalidConfiguration, InvalidPayload) as exc:
        print(f"spec guard: invalid input ({exc}); blocking", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 -- hook failures must fail closed.
        print(f"spec guard: internal {type(exc).__name__}; blocking", file=sys.stderr)
        return 2
    if response:
        print(json.dumps(response))
    return 0


if __name__ == "__main__":
    sys.exit(main())
