"""A script handed an empty output dir must refuse, not write to the cwd.

An unset `$OUTPUT_DIR` reaches a script as an empty argument, and `Path("")` is
`PosixPath('.')` — under an agent that is the *scanned repository's* root. Six
writers were reproducing their artifacts there: `.agent-run.log`,
`.appsec-checkpoint`, `.run-issues.json` and `.run-metrics.json` all appeared in
a foreign working directory when the variable was empty. Two of them carried an
`is_dir()` check that cannot help, because `'.'` is always a directory.

`scripts/log_event.py` had the right guard since f6183f85 (2026-08-16), but it
was written inline and never generalised, so every writer added after it
shipped without one. This test is the generalisation: it drives each script's
real CLI with an empty path in an empty directory and asserts the two
properties that matter — a non-zero exit, and nothing written.

`test_no_script_writes_into_the_cwd_on_an_empty_output_dir` discovers its own
subjects, so a writer added later is covered the day it lands. That is what
stops this guard from rotting for the next writer, the way the 2026-06-21
OUTPUT_DIR fix rotted by covering exactly one agent. INVOCATIONS adds the
stronger per-script check that the guard is actually reached rather than the
CLI stopping earlier on a missing flag.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"

# script -> extra args that make the CLI otherwise valid, so the run reaches
# the guard instead of failing on a missing required flag.
INVOCATIONS: dict[str, list[str]] = {
    "log_event.py": ["info", "EVENT", "detail"],
    "log_agent_end.py": ["agent", "model", "0"],
    "batch_checkpoint.py": ["--phase", "p", "--step", "s", "--status", "x"],
    "aggregate_run_issues.py": [],
    "measure_run.py": [],
    "skill_watchdog.py": [],
    "runtime_cleanup.py": [],
    "stall_notice.py": [],
    "render_editorial_receipt.py": [],
    "render_qa_receipt.py": [],
}

_POSITIONAL_OUTPUT_DIR = re.compile(r"""add_argument\(\s*["']output_dir["']""")


def _scripts_with_positional_output_dir() -> set[str]:
    found = set()
    for path in sorted(SCRIPTS.glob("*.py")):
        if _POSITIONAL_OUTPUT_DIR.search(path.read_text(encoding="utf-8")):
            found.add(path.name)
    return found


@pytest.mark.parametrize("script", sorted(INVOCATIONS))
def test_empty_output_dir_refuses_and_writes_nothing(script, tmp_path):
    target = SCRIPTS / script
    assert target.exists(), f"missing script: {target}"

    proc = subprocess.run(
        [sys.executable, str(target), "", *INVOCATIONS[script]],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )

    leftovers = sorted(p.name for p in tmp_path.iterdir())
    assert not leftovers, (
        f"{script} wrote {leftovers} into the working directory when given an "
        f"empty output_dir — under an agent that directory is the scanned repo"
    )
    assert proc.returncode != 0, f"{script} accepted an empty output_dir (exit 0); it must refuse"
    assert "Traceback" not in proc.stderr, f"{script} crashed instead of refusing cleanly:\n{proc.stderr[-500:]}"


@pytest.mark.parametrize("script", sorted(INVOCATIONS))
def test_option_shaped_output_dir_refuses(script, tmp_path):
    """An option in the path slot means the arguments shifted."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / script), "--repo-root", *INVOCATIONS[script]],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    leftovers = sorted(p.name for p in tmp_path.iterdir())
    assert not leftovers, f"{script} wrote {leftovers} for an option-shaped path"
    assert proc.returncode != 0, f"{script} accepted an option as its output_dir"


@pytest.mark.parametrize("script", sorted(_scripts_with_positional_output_dir()))
def test_no_script_writes_into_the_cwd_on_an_empty_output_dir(script, tmp_path):
    """The property that must hold for every script, not just the listed ones.

    Discovery is automatic, so a writer added later is covered the day it lands
    — this is the part that cannot rot. A script that stops on a missing
    required flag also writes nothing and passes here; INVOCATIONS above adds
    the stronger check that the guard itself is reached for the writers.

    Found this way and fixed with it: assess_supply_chain_controls.py
    (.supply-chain-assessment.json), build_stride_dispatch_manifest.py
    (.stride-selection.json) and section_integrity.py (.section-integrity.json)
    all created their artifact in the working directory.
    """
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / script), "", *INVOCATIONS.get(script, [])],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=90,
    )
    leftovers = sorted(p.name for p in tmp_path.iterdir())
    assert not leftovers, (
        f"{script} wrote {leftovers} into the working directory when given an "
        f"empty output_dir — under an agent that is the scanned repository"
    )
    assert "Traceback" not in proc.stderr, f"{script} crashed instead of refusing cleanly:\n{proc.stderr[-500:]}"
