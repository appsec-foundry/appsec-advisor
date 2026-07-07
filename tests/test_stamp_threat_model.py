"""Tests for scripts/stamp_threat_model.py — postfix-stamped copy-ready sets."""

import re
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "stamp_threat_model.py"


def _seed_model(d: Path, *, figure2: bool = True, optional_outputs: bool = False) -> None:
    md = "# Threat Model\n\n![Figure 1](threat-model.figure1.svg)\n"
    if figure2:
        md += "\n![Figure 2](threat-model.figure2.svg)\n"
    (d / "threat-model.md").write_text(md, encoding="utf-8")
    (d / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    (d / "threat-model.figure1.svg").write_text("<svg/>\n", encoding="utf-8")
    if figure2:
        (d / "threat-model.figure2.svg").write_text("<svg/>\n", encoding="utf-8")
    if optional_outputs:
        (d / "threat-model.pdf").write_bytes(b"%PDF\n")
        (d / "threat-model.html").write_text("<html></html>\n", encoding="utf-8")
        (d / "threat-model.sarif.json").write_text('{"version":"2.1.0"}\n', encoding="utf-8")


def _run(*args: str):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_explicit_slug_stamps_set_and_rewrites_figure_ref(tmp_path):
    _seed_model(tmp_path)
    r = _run("--output-dir", str(tmp_path), "--slug", "a3f9")
    assert r.returncode == 0, r.stderr
    md = tmp_path / "threat-model-a3f9.md"
    assert (tmp_path / "threat-model-a3f9.yaml").is_file()
    assert (tmp_path / "threat-model-a3f9.figure1.svg").is_file()
    assert (tmp_path / "threat-model-a3f9.figure2.svg").is_file()
    # Figure references inside the stamped md point at the stamped svgs.
    text = md.read_text(encoding="utf-8")
    assert "threat-model-a3f9.figure1.svg" in text
    assert "threat-model-a3f9.figure2.svg" in text
    assert "threat-model.figure1.svg" not in text
    assert "threat-model.figure2.svg" not in text
    # Canonical files are left untouched.
    assert (tmp_path / "threat-model.md").is_file()
    assert (tmp_path / "threat-model.figure1.svg").is_file()
    assert (tmp_path / "threat-model.figure2.svg").is_file()


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
    assert (dest / "threat-model-b2.figure2.svg").is_file()


def test_optional_deliverables_are_stamped(tmp_path):
    _seed_model(tmp_path, optional_outputs=True)
    r = _run("--output-dir", str(tmp_path), "--slug", "bundle")
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "threat-model-bundle.pdf").is_file()
    assert (tmp_path / "threat-model-bundle.html").is_file()
    assert (tmp_path / "threat-model-bundle.sarif.json").is_file()


def test_same_slug_overwrites_previous_stamped_set(tmp_path):
    _seed_model(tmp_path)
    assert _run("--output-dir", str(tmp_path), "--slug", "repeat").returncode == 0

    (tmp_path / "threat-model.md").write_text(
        "# Threat Model\n\nchanged\n\n![Figure 1](threat-model.figure1.svg)\n",
        encoding="utf-8",
    )
    (tmp_path / "threat-model.yaml").write_text("meta:\n  rerun: true\n", encoding="utf-8")
    r = _run("--output-dir", str(tmp_path), "--slug", "repeat")
    assert r.returncode == 0, r.stderr
    assert "changed" in (tmp_path / "threat-model-repeat.md").read_text(encoding="utf-8")
    assert "rerun: true" in (tmp_path / "threat-model-repeat.yaml").read_text(encoding="utf-8")


def test_missing_figure_file_does_not_rewrite_reference(tmp_path):
    _seed_model(tmp_path, figure2=False)
    (tmp_path / "threat-model.md").write_text(
        "# Threat Model\n\n![Figure 2](threat-model.figure2.svg)\n",
        encoding="utf-8",
    )
    r = _run("--output-dir", str(tmp_path), "--slug", "nofig")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "threat-model-nofig.figure2.svg").exists()
    assert "threat-model.figure2.svg" in (tmp_path / "threat-model-nofig.md").read_text(encoding="utf-8")


def test_invalid_slug_rejected(tmp_path):
    _seed_model(tmp_path)
    r = _run("--output-dir", str(tmp_path), "--slug", "bad/slug")
    assert r.returncode == 2
    assert "slug" in r.stderr.lower()
