"""Tests for detect_impl_strategy.py (P2 implementation-strategy axis) and the
merge_threats reconciler's use of the strategy signal."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import detect_impl_strategy as dis  # noqa: E402
import merge_threats as mt  # noqa: E402


def _repo(tmp_path: Path, deps: dict, files: dict) -> Path:
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": deps}), encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    for name, body in files.items():
        (src / name).write_text(body, encoding="utf-8")
    return tmp_path


def test_vetted_lib_no_bespoke_is_standard_vetted(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"argon2": "^0.30", "@prisma/client": "^5"},
                {"app.ts": "import argon2 from 'argon2'\nprisma.user.findUnique()\n"})
    m = dis.build_strategy_map(repo)
    assert m["weak_crypto"]["strategy"] == "standard-vetted"
    assert m["injection"]["strategy"] == "standard-vetted"


def test_bespoke_no_lib_is_home_grown(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {}, {"h.js": "crypto.createHash('md5').update(pw)\n"})
    m = dis.build_strategy_map(repo)
    assert m["weak_crypto"]["strategy"] == "home-grown"


def test_lib_plus_bespoke_is_standard_misused(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"bcrypt": "^5"}, {"x.js": "crypto.createHash('md5')\n"})
    m = dis.build_strategy_map(repo)
    assert m["weak_crypto"]["strategy"] == "standard-misused"


def test_none_omitted_from_map(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {}, {"x.js": "const x = 1\n"})
    m = dis.build_strategy_map(repo)
    assert "weak_crypto" not in m  # no signal → omitted


def test_cli_writes_sidecar(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"argon2": "^0.30"}, {"a.ts": "import argon2 from 'argon2'\n"})
    out = tmp_path / "out"
    rc = dis._main(["--repo-root", str(repo), "--output-dir", str(out)])
    assert rc == 0
    doc = json.loads((out / ".impl-strategy.json").read_text())
    assert doc["strategies"]["weak_crypto"]["strategy"] == "standard-vetted"


# --- reconciler use of the strategy signal (P2.3 / §4b Fall B, §4e) ---------


def _design_signal(wclass="injection", component=None):
    ds = {"weakness_class": wclass, "absent_control_signal": [{"hit_count": 0}],
          "statement": "no central control"}
    if component:
        ds["component"] = component
    return ds


def test_standard_vetted_suppresses_pure_design_gap() -> None:
    # Fall B — a vetted central control means the design gap is not real.
    w = mt.build_weakness_register([], [_design_signal()], {"injection": "standard-vetted"})
    assert w == []


def test_standard_vetted_lowers_confirmed_severity() -> None:
    threats = [{"t_id": "T-001", "source": "stride", "cwe": "CWE-89", "component_id": "a",
                "risk": "High", "evidence": {"file": "a.ts", "line": 1}}]
    w = mt.build_weakness_register(threats, [_design_signal()], {"injection": "standard-vetted"})
    assert len(w) == 1
    assert w[0]["severity"] == "Medium"  # High → Medium (exculpated)
    assert w[0]["implementation_strategy"] == "standard-vetted"


def test_home_grown_pervasive_is_critical() -> None:
    signals = [_design_signal("weak_crypto", "a"), _design_signal("weak_crypto", "b")]
    w = mt.build_weakness_register([], signals, {"weak_crypto": "home-grown"})
    assert w[0]["severity"] == "Critical"
    assert w[0]["implementation_strategy"] == "home-grown"


def test_design_signal_strategy_wins_over_detector() -> None:
    signals = [{**_design_signal(), "implementation_strategy": "home-grown"}]
    w = mt.build_weakness_register([], signals, {"injection": "standard-vetted"})
    # The per-signal strategy (home-grown) takes precedence → not suppressed.
    assert len(w) == 1
    assert w[0]["implementation_strategy"] == "home-grown"
