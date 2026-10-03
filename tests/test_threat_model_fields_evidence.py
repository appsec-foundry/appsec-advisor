"""Evidence locators: line 0 is never a location, and an absence says what was searched."""

from __future__ import annotations

import pytest
from shared._threat_model_fields import evidence_description, evidence_locator


@pytest.mark.parametrize(
    ("entry", "locator"),
    [
        ({"file": "app.py", "line": 7}, "app.py:7"),
        ({"file": "app.py", "line": 0}, "app.py"),
        ({"file": "app.py", "line": None}, "app.py"),
        ({"file": "app.py", "line": True}, "app.py"),
        ({"file": ""}, ""),
        ("not-a-dict", ""),
    ],
)
def test_locator_cites_only_real_lines(entry, locator):
    assert evidence_locator(entry) == locator


def test_absence_description_names_the_searched_files():
    entry = {
        "file": ".github/workflows/*.yml",
        "line": 0,
        "kind": "absence",
        "searched_files": ["a.yml", "b.yml", "c.yml", "d.yml"],
        "searched_file_count": 4,
    }
    assert (
        evidence_description(entry)
        == ".github/workflows/*.yml: not found in 4 searched file(s) (a.yml, b.yml, c.yml, …)"
    )
    assert evidence_description({"file": "package-lock.json", "line": 0, "kind": "absence", "searched_files": []}) == (
        "package-lock.json: not found"
    )
    assert evidence_description({"file": "app.py", "line": 3}) == "app.py:3"
