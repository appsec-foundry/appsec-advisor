"""Unit tests for scripts/_artifact_stamp.py.

The rule under test: an artifact a context-v2 boundary regenerates and then
receipts must keep its previous timestamp while nothing else about it moved, so
the boundary can repeat the action it already issued. A real content change
still gets the time it was produced.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "_artifact_stamp.py"


@pytest.fixture(scope="module")
def stamp():
    scripts_dir = str(SCRIPT_PATH.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location("_artifact_stamp", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_artifact_stamp"] = module
    spec.loader.exec_module(module)
    return module


PRIOR = {"version": 1, "generated_at": "2026-01-01T00:00:00Z", "threats": [{"t_id": "T-001"}]}


def _write(path: Path, payload) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_identical_content_keeps_the_prior_stamp(stamp, tmp_path):
    path = tmp_path / "artifact.json"
    _write(path, PRIOR)
    fresh = {**PRIOR, "generated_at": "2026-08-18T09:00:00Z"}

    assert stamp.carry_generated_at(path, fresh)["generated_at"] == "2026-01-01T00:00:00Z"


def test_changed_content_keeps_the_fresh_stamp(stamp, tmp_path):
    path = tmp_path / "artifact.json"
    _write(path, PRIOR)
    fresh = {**PRIOR, "generated_at": "2026-08-18T09:00:00Z", "threats": [{"t_id": "T-002"}]}

    assert stamp.carry_generated_at(path, fresh)["generated_at"] == "2026-08-18T09:00:00Z"


@pytest.mark.parametrize(
    "prior",
    [
        None,  # no prior artifact at all — the first write of the run
        "{ truncated",  # a torn or hand-edited file
        '["not", "an", "object"]',
        '{"version": 1, "threats": []}',  # prior without the field
        '{"version": 1, "generated_at": 17, "threats": []}',  # field of the wrong type
    ],
    ids=["absent", "unparseable", "not-an-object", "field-absent", "field-not-a-string"],
)
def test_unusable_prior_leaves_the_fresh_stamp(stamp, tmp_path, prior):
    path = tmp_path / "artifact.json"
    if prior is not None:
        path.write_text(prior, encoding="utf-8")
    fresh = {**PRIOR, "generated_at": "2026-08-18T09:00:00Z"}

    assert stamp.carry_generated_at(path, fresh)["generated_at"] == "2026-08-18T09:00:00Z"


def test_the_carried_field_is_selectable(stamp, tmp_path):
    path = tmp_path / "artifact.json"
    _write(path, {"scanned_at": "2026-01-01T00:00:00Z", "findings": []})
    fresh = {"scanned_at": "2026-08-18T09:00:00Z", "findings": []}

    assert stamp.carry_generated_at(path, fresh, field="scanned_at")["scanned_at"] == "2026-01-01T00:00:00Z"
