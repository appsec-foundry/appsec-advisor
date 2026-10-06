"""Tests for scripts/validators/ground_truth_recall.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import validators.ground_truth_recall as gtr  # noqa: E402

SOURCE = """\
def a():
    # vuln-mark start alphaBug betaBug
    x = 1
    run(query + x)  # vuln-mark vuln-line alphaBug
    y = 2
    # vuln-mark end alphaBug betaBug

# vuln-mark start gammaBug
z = 3
# vuln-mark end gammaBug
"""


def _git_repo(root: Path, files: dict[str, str]) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)


def _threat_model(path: Path, threats: list[dict]) -> Path:
    path.write_text(yaml.safe_dump({"threats": threats}), encoding="utf-8")
    return path


def test_extract_from_text_ranges_and_vuln_lines():
    found, warnings = gtr.extract_from_text("src/app.py", SOURCE, "vuln-mark")
    assert warnings == []
    assert found["alphaBug"][0].start == 2 and found["alphaBug"][0].end == 6
    assert found["alphaBug"][0].vuln_lines == [4]
    assert found["betaBug"][0].vuln_lines == []
    assert (found["gammaBug"][0].start, found["gammaBug"][0].end) == (8, 10)


def test_extract_skips_unbalanced_and_prose_mentions():
    text = "See the `vuln-mark start someKey` block.\n# vuln-mark start openKey\n# vuln-mark end otherKey\n"
    found, warnings = gtr.extract_from_text("README.md", text, "vuln-mark")
    assert found == {}
    assert not any("someKey" in w for w in warnings)
    assert any("start without end for openKey" in w for w in warnings)
    assert any("end without start for otherKey" in w for w in warnings)


def test_extract_respects_marker_prefix(tmp_path):
    other = SOURCE.replace("vuln-mark", "known-flaw")
    _git_repo(tmp_path, {"one.py": SOURCE, "two.py": other, "untracked_ignored.txt": ""})
    doc, _ = gtr.extract(tmp_path, "known-flaw")
    assert [i["id"] for i in doc["items"]] == ["alphaBug", "betaBug", "gammaBug"]
    assert {loc["file"] for i in doc["items"] for loc in i["locations"]} == {"two.py"}


def test_score_levels(tmp_path):
    gt = tmp_path / "gt.yaml"
    gt.write_text(
        yaml.safe_dump(
            {
                "items": [
                    {"id": "near", "locations": [{"file": "a.py", "lines": [10, 30], "vuln_lines": [20]}]},
                    {"id": "inside", "locations": [{"file": "a.py", "lines": [40, 60], "vuln_lines": [41]}]},
                    {"id": "fileonly", "locations": [{"file": "b.py", "lines": [1, 5], "vuln_lines": [3]}]},
                    {"id": "norange", "locations": [{"file": "c.py", "lines": [5, 9], "vuln_lines": []}]},
                    {"id": "missed", "locations": [{"file": "d.py", "lines": [1, 2], "vuln_lines": [1]}]},
                ]
            }
        ),
        encoding="utf-8",
    )
    tm = _threat_model(
        tmp_path / "tm.yaml",
        [
            {"id": "T-1", "evidence": [{"file": "./a.py", "line": 22}]},
            {"id": "T-2", "evidence": [{"file": "a.py", "line": 55}]},
            {"id": "T-3", "evidence": [{"file": "x.py", "line": 1}], "affected_files": ["b.py"]},
            {"id": "T-4", "evidence": [{"file": "c.py", "line": 7}]},
        ],
    )
    report = gtr.score(gtr.load_ground_truth(gt), [("run", tm)], tolerance=3)
    items = report["runs"]["run"]["items"]
    assert items["near"] == {"level": "line", "threats": ["T-1"]}
    assert items["inside"]["level"] == "range"
    assert items["fileonly"]["level"] == "file"
    assert items["norange"]["level"] == "line"
    assert items["missed"] == {"level": "miss", "threats": []}
    assert report["runs"]["run"]["counts"] == {"line": 2, "range": 1, "file": 1, "miss": 1}


def test_tolerance_boundary(tmp_path):
    gt = tmp_path / "gt.yaml"
    gt.write_text(
        yaml.safe_dump(
            {
                "items": [
                    {"id": "k", "locations": [{"file": "a.py", "lines": [1, 100], "vuln_lines": [50]}]},
                ]
            }
        ),
        encoding="utf-8",
    )
    tm = _threat_model(tmp_path / "tm.yaml", [{"id": "T-1", "evidence": [{"file": "a.py", "line": 54}]}])
    loaded = gtr.load_ground_truth(gt)
    assert gtr.score(loaded, [("r", tm)], tolerance=3)["runs"]["r"]["items"]["k"]["level"] == "range"
    assert gtr.score(loaded, [("r", tm)], tolerance=4)["runs"]["r"]["items"]["k"]["level"] == "line"


def test_cli_errors_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("items: nope\n", encoding="utf-8")
    tm = _threat_model(tmp_path / "tm.yaml", [])
    assert gtr.main(["score", "--ground-truth", str(bad), "--run", f"r={tm}"]) == 2
    assert gtr.main(["score", "--ground-truth", str(bad), "--run", f"r={tm}", "--tolerance", "-1"]) == 2
    _git_repo(tmp_path / "repo", {"a.py": "print(1)\n"})
    assert (
        gtr.main(
            [
                "extract",
                "--repo-root",
                str(tmp_path / "repo"),
                "--marker",
                "vuln-mark",
                "--output",
                str(tmp_path / "gt.yaml"),
            ]
        )
        == 2
    )
    assert "error" in capsys.readouterr().err


def test_cli_score_prints_comparison(tmp_path, capsys):
    gt = tmp_path / "gt.yaml"
    gt.write_text(
        yaml.safe_dump(
            {
                "items": [
                    {"id": "k", "locations": [{"file": "a.py", "lines": [1, 9], "vuln_lines": [5]}]},
                ]
            }
        ),
        encoding="utf-8",
    )
    hit = _threat_model(tmp_path / "hit.yaml", [{"id": "T-1", "evidence": [{"file": "a.py", "line": 5}]}])
    miss = _threat_model(tmp_path / "miss.yaml", [])
    out_json = tmp_path / "r.json"
    rc = gtr.main(
        ["score", "--ground-truth", str(gt), "--run", f"one={hit}", "--run", f"two={miss}", "--json", str(out_json)]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "one: 1 threats" in out and "two: 0 threats" in out
    assert out_json.exists()
