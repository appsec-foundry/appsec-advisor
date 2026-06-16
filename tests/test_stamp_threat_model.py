"""Tests for scripts/stamp_threat_model.py — postfix-stamped copy-ready sets."""

import re
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "stamp_threat_model.py"


def _seed_model(d: Path) -> None:
    (d / "threat-model.md").write_text("# Threat Model\n\n![Figure 1](threat-model.figure1.svg)\n", encoding="utf-8")
    (d / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    (d / "threat-model.figure1.svg").write_text("<svg/>\n", encoding="utf-8")


def _run(*args: str):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_explicit_slug_stamps_set_and_rewrites_figure_ref(tmp_path):
    _seed_model(tmp_path)
    r = _run("--output-dir", str(tmp_path), "--slug", "a3f9")
    assert r.returncode == 0, r.stderr
    md = tmp_path / "threat-model-a3f9.md"
    assert (tmp_path / "threat-model-a3f9.yaml").is_file()
    assert (tmp_path / "threat-model-a3f9.figure1.svg").is_file()
    # Figure reference inside the stamped md points at the stamped svg.
    assert "threat-model-a3f9.figure1.svg" in md.read_text(encoding="utf-8")
    assert "threat-model.figure1.svg" not in md.read_text(encoding="utf-8")
    # Canonical files are left untouched.
    assert (tmp_path / "threat-model.md").is_file()
    assert (tmp_path / "threat-model.figure1.svg").is_file()


def test_default_slug_is_random_hex(tmp_path):
    _seed_model(tmp_path)
    r = _run("--output-dir", str(tmp_path))
    assert r.returncode == 0, r.stderr
    stamped = list(tmp_path.glob("threat-model-*.md"))
    assert len(stamped) == 1
    slug = re.fullmatch(r"threat-model-([0-9a-f]{4})\.md", stamped[0].name)
    assert slug, stamped[0].name


def test_missing_model_errors(tmp_path):
    r = _run("--output-dir", str(tmp_path), "--slug", "x")
    assert r.returncode == 2
    assert "not found" in r.stderr


def test_dest_directory(tmp_path):
    _seed_model(tmp_path)
    dest = tmp_path / "collection"
    r = _run("--output-dir", str(tmp_path), "--slug", "b2", "--dest", str(dest))
    assert r.returncode == 0, r.stderr
    assert (dest / "threat-model-b2.md").is_file()
    assert (dest / "threat-model-b2.figure1.svg").is_file()
