"""Shell snippets in agent docs assign every prompt-provided path they use.

The dispatch prompt carries OUTPUT_DIR, REPO_ROOT and CLAUDE_PLUGIN_ROOT as
text, and every Bash call starts a fresh shell, so a snippet that reads one of
them without assigning it in the same command runs with an empty value. Agents
copy these snippets verbatim: on juice-shop 2026-09-11 progress and log lines
went to `/scripts/agent_progress.sh` and `/.agent-run.log` that way.
"""

from __future__ import annotations

import re
from pathlib import Path

AGENTS = Path(__file__).resolve().parent.parent / "agents"
PROMPT_PATHS = ("OUTPUT_DIR", "REPO_ROOT", "CLAUDE_PLUGIN_ROOT")
_SHELL_FENCE_RE = re.compile(r"```(?:bash|sh)\n(.*?)```", re.S)
_ANY_FENCE_RE = re.compile(r"```[^\n]*\n.*?```", re.S)
# A code span cannot cross a blank line, so backticks pair within a paragraph;
# pairing across the document lets one stray backtick hide every later span.
_PARAGRAPH_RE = re.compile(r"(?:[^\n]*\S[^\n]*(?:\n|$))+")
_INLINE_RE = re.compile(r"`([^`]+)`")
_COMMAND_RE = re.compile(r"(?:^|[;&]\s*)(?:python3|bash|sh|cat)\s")


def _uses(name: str, code: str) -> bool:
    return re.search(rf"\$\{{?{name}\b", code) is not None


def _assigns(name: str, code: str) -> bool:
    # A statement, not a command prefix: `X=1 cmd "$X"` expands "$X" before X is set.
    statement = rf"(?:^\s*|[;&]\s*)(?:export\s+)?{name}=(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s;&|]*)\s*(?:[;&]|$)"
    return re.search(statement, code, re.M) is not None


def _snippets():
    for path in sorted(AGENTS.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        for match in _SHELL_FENCE_RE.finditer(text):
            yield path, text.count("\n", 0, match.start()) + 1, match.group(1)
        prose = _ANY_FENCE_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
        for paragraph in _PARAGRAPH_RE.finditer(prose):
            for match in _INLINE_RE.finditer(paragraph.group(0)):
                if _COMMAND_RE.search(match.group(1)):
                    yield path, prose.count("\n", 0, paragraph.start() + match.start()) + 1, match.group(1)


def test_agent_shell_snippets_assign_the_prompt_paths_they_use() -> None:
    offenders = []
    for path, line, snippet in _snippets():
        code = "\n".join(row for row in snippet.splitlines() if not row.lstrip().startswith("#"))
        missing = [name for name in PROMPT_PATHS if _uses(name, code) and not _assigns(name, code)]
        if missing:
            offenders.append(f"{path.relative_to(AGENTS.parent)}:{line} {', '.join(missing)}")
    assert not offenders, "assign these in the same snippet:\n" + "\n".join(offenders)


def test_prefix_assignment_does_not_count() -> None:
    assert not _assigns("OUTPUT_DIR", 'OUTPUT_DIR=/x python3 tool.py "$OUTPUT_DIR"')
    assert _assigns("OUTPUT_DIR", 'OUTPUT_DIR="<the OUTPUT_DIR value from your prompt>"\npython3 tool.py')
    assert _assigns("OUTPUT_DIR", '  export OUTPUT_DIR=/x; python3 tool.py "$OUTPUT_DIR"')
