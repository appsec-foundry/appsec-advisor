"""The shared "does this catalog declare requirements?" predicate.

File presence is not configuration. A run with the requirements check switched
off still writes ``fetch_requirements._SKIPPED_STUB``, so a consumer gated on
``is_file()`` reads "nobody asked for requirements" as "catalog configured".
``emit_requirement_trace_to_model.py`` did exactly that and failed the run
*after* ``threat-model.md`` was already composed — the 2026-08-29 juice-shop
run, which had ``check_requirements=false``. These tests pin the predicate and
the emitter's exit on every catalog shape a run can produce.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import _requirements_gate  # noqa: E402
import fetch_requirements  # noqa: E402

CATALOG = ".requirements.yaml"


def _catalog(tmp_path: Path, body: str) -> Path:
    (tmp_path / CATALOG).write_text(body, encoding="utf-8")
    return tmp_path


def test_the_shipped_skipped_stub_declares_nothing(tmp_path):
    """Pinned against the stub the writer actually emits, not a copy of it."""
    _catalog(tmp_path, fetch_requirements._SKIPPED_STUB)

    assert _requirements_gate.catalog_declares_requirements(tmp_path) is False


def test_an_absent_catalog_declares_nothing(tmp_path):
    assert _requirements_gate.catalog_declares_requirements(tmp_path) is False


def test_an_empty_category_list_declares_nothing(tmp_path):
    _catalog(tmp_path, yaml.safe_dump({"source": "https://example.test/reqs", "categories": []}))

    assert _requirements_gate.catalog_declares_requirements(tmp_path) is False


def test_a_populated_catalog_declares_requirements(tmp_path):
    _catalog(
        tmp_path,
        yaml.safe_dump(
            {
                "source": "https://example.test/reqs",
                "categories": [{"name": "AuthN", "requirements": [{"id": "R-1", "url": "https://example.test/1"}]}],
            }
        ),
    )

    assert _requirements_gate.catalog_declares_requirements(tmp_path) is True


def test_the_bundled_baseline_still_has_requirements_to_trace(tmp_path):
    """Unlike `load_requirements`, which reports only *custom* catalogs, the
    baseline counts here: the trace emitter has real edges to write for it.
    """
    _catalog(
        tmp_path,
        yaml.safe_dump(
            {
                "source": "bundled-bestpractices",
                "categories": [{"name": "Crypto", "requirements": [{"id": "B-1"}]}],
            }
        ),
    )

    assert _requirements_gate.catalog_declares_requirements(tmp_path) is True


def test_a_corrupt_catalog_declares_nothing_instead_of_raising(tmp_path):
    _catalog(tmp_path, "{not: [valid")

    assert _requirements_gate.catalog_declares_requirements(tmp_path) is False


def test_a_non_mapping_catalog_declares_nothing(tmp_path):
    _catalog(tmp_path, yaml.safe_dump(["R-1", "R-2"]))

    assert _requirements_gate.catalog_declares_requirements(tmp_path) is False


def _run_emitter(output_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "emit_requirement_trace_to_model.py"), str(output_dir)],
        capture_output=True,
        text=True,
    )


def test_emitter_succeeds_on_a_run_that_never_requested_requirements(tmp_path):
    """The regression itself: this exit 1 blocked a finished report."""
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump({"meta": {}, "mitigations": []}), encoding="utf-8")
    _catalog(tmp_path, fetch_requirements._SKIPPED_STUB)

    result = _run_emitter(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "nothing to do" in (result.stdout + result.stderr)


def test_emitter_succeeds_when_no_catalog_exists_at_all(tmp_path):
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump({"meta": {}, "mitigations": []}), encoding="utf-8")

    result = _run_emitter(tmp_path)

    assert result.returncode == 0, result.stderr
