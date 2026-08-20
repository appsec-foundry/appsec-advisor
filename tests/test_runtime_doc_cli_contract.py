"""The runtime docs are the only caller of most scripts — so their argv is a contract.

The thin runtimes are executed by a model, not by a shell script, so a flag that
drifted out of a script's parser fails at *run* time and nowhere earlier. On the
2026-08-20 run `SKILL-thin-completion.md` described the final step in prose
("the resolved mode, model, and depth plus the true/false pairs for WRITE_YAML")
while `render_completion_summary.py` had long since required `--repo-root` and
renamed `--model`/`--depth` to `--reasoning-model`/`--assessment-depth`. The
call aborted with exit 2 at the last step of a 151-minute assessment; only an
interactive session could recover it.

`tests/test_render_completion_summary.py` never caught it because it drives
internal functions and never once calls `main([...])` — the CLI surface the
runtime actually uses was untested.

This test reads every fenced Bash block in the runtime docs, extracts the flags
each `scripts/*.py` invocation passes, and asserts the script's own parser
accepts them. Prose is not checked: a literal, copy-pasteable block is what a
runtime doc owes its caller, and this test only binds the blocks that exist.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS = REPO_ROOT / "skills"
SCRIPTS = REPO_ROOT / "scripts"

_BASH_BLOCK = re.compile(r"```bash\n(.*?)```", re.DOTALL)
# The escaped-newline branch must come first: `[^\n]` would otherwise consume
# the trailing backslash of a line continuation and strand the rest of a
# multi-line invocation — which silently dropped the very doc this test exists
# for, because its first line carries no flags at all.
#
# `|` ends the invocation: the runtime docs pipe one script into the next, and
# the downstream flags belong to the downstream parser.
_SCRIPT_CALL = re.compile(r"scripts/([a-z0-9_]+\.py)(?P<args>(?:\\\n|[^\n`|])*)")
_FLAG = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")
_ARGPARSE_HELP = re.compile(r"^(?:options|optional arguments|positional arguments):", re.MULTILINE)


# The script path is usually quoted, so the closing quote sits between the
# path and the subcommand: `.../qa_checks.py" gate "$OUTPUT_DIR"`.
_SUBCOMMAND = re.compile(r"^[\"']?\s*([a-z][a-z0-9-]*)(?![\w=/.-])")


def _documented_invocations() -> list[tuple[Path, str, str, frozenset[str]]]:
    """(doc, script, subcommand, flags) for every scripted invocation in a doc."""
    found: list[tuple[Path, str, str, frozenset[str]]] = []
    for doc in sorted(SKILLS.rglob("SKILL*.md")):
        text = doc.read_text(encoding="utf-8")
        for block in _BASH_BLOCK.findall(text):
            for match in _SCRIPT_CALL.finditer(block):
                script = match.group(1)
                if not (SCRIPTS / script).exists():
                    continue
                args = match.group("args")
                # Several scripts dispatch on a subcommand and hang their flags
                # off the subparser, where a bare `--help` cannot see them.
                sub = _SUBCOMMAND.match(args)
                subcommand = sub.group(1) if sub else ""
                flags = frozenset(_FLAG.findall(args))
                if flags:
                    found.append((doc, script, subcommand, flags))
    return found


def _accepted_flags(script: str, subcommand: str) -> frozenset[str] | None:
    """Flags the script's own parser advertises, or None if it has no CLI help."""
    argv = [sys.executable, str(SCRIPTS / script)]
    if subcommand:
        argv.append(subcommand)
    argv.append("--help")
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60, cwd=str(REPO_ROOT))
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    # Only an argparse-rendered help enumerates the accepted flags. A few
    # scripts hand-roll their parsing and print a prose usage block that lists a
    # subset; asserting against that would report drift where there is none.
    if not _ARGPARSE_HELP.search(result.stdout):
        return None
    return frozenset(_FLAG.findall(result.stdout))


INVOCATIONS = _documented_invocations()


def test_the_runtime_docs_actually_invoke_scripts():
    """A guard over an empty set is not a guard."""
    assert INVOCATIONS, "no scripted invocation found in any runtime doc — the extractor is broken"


@pytest.mark.parametrize(
    "doc, script, subcommand, flags",
    INVOCATIONS,
    ids=[f"{doc.name}:{script}{':' + sub if sub else ''}" for doc, script, sub, flags in INVOCATIONS],
)
def test_documented_flags_exist_in_the_scripts_parser(doc: Path, script: str, subcommand: str, flags: frozenset[str]):
    accepted = _accepted_flags(script, subcommand)
    if accepted is None:
        pytest.skip(f"{script} {subcommand} exposes no parseable --help")
    unknown = sorted(flags - accepted)
    assert not unknown, (
        f"{doc.relative_to(REPO_ROOT)} tells the runtime to pass {unknown} to {script}, "
        f"but its parser does not accept them — the run would abort at this step"
    )
