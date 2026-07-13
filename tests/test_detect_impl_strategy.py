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
    repo = _repo(
        tmp_path,
        {"argon2": "^0.30", "@prisma/client": "^5"},
        {"app.ts": "import argon2 from 'argon2'\nprisma.user.findUnique()\n"},
    )
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
    ds = {"weakness_class": wclass, "absent_control_signal": [{"hit_count": 0}], "statement": "no central control"}
    if component:
        ds["component"] = component
    return ds


def test_standard_vetted_suppresses_pure_design_gap() -> None:
    # Fall B — a vetted central control means the design gap is not real.
    w = mt.build_weakness_register([], [_design_signal()], {"injection": "standard-vetted"})
    assert w == []


def test_standard_vetted_does_not_lower_confirmed_severity() -> None:
    # R1: a weakness never hides an instance's severity. A standard-vetted
    # control may soften a design-risk gap, but NOT a `confirmed` weakness —
    # a proven High sink stays High regardless of a vetted baseline elsewhere.
    threats = [
        {
            "t_id": "T-001",
            "source": "stride",
            "cwe": "CWE-89",
            "component_id": "a",
            "risk": "High",
            "evidence": {"file": "a.ts", "line": 1},
        }
    ]
    w = mt.build_weakness_register(threats, [_design_signal()], {"injection": "standard-vetted"})
    assert len(w) == 1
    assert w[0]["severity_basis"] == "confirmed"
    assert w[0]["severity"] == "High"  # NOT lowered — proven instance preserved
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


# --- Gap-A: home-grown central control → evidence-backed design signal --------


def test_bespoke_evidence_carries_file_line(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {}, {"view.js": "const x=1\nel.innerHTML = userInput\n"})
    m = dis.build_strategy_map(repo)
    assert m["output_xss_csp"]["strategy"] == "home-grown"
    ev = m["output_xss_csp"]["bespoke_evidence"]
    assert ev and ev[0]["file"] == "src/view.js" and ev[0]["line"] == 2


def test_impl_design_signal_emitted_for_home_grown_central_control(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {}, {"view.js": "el.innerHTML = userInput\n"})
    sigs = dis.build_impl_design_signals(dis.build_strategy_map(repo))
    xss = [s for s in sigs if s["weakness_class"] == "output_xss_csp"]
    assert len(xss) == 1
    s = xss[0]
    assert s["implementation_strategy"] == "home-grown"
    ac = s["absent_control_signal"][0]
    assert ac["hit_count"] >= 1 and ac["example"].endswith(":1")


def test_impl_design_signal_not_emitted_for_vetted() -> None:
    # standard-vetted → the vetted control IS the control → no design signal.
    strat = {"output_xss_csp": {"strategy": "standard-vetted", "bespoke_evidence": []}}
    assert dis.build_impl_design_signals(strat) == []


def test_impl_design_signal_skips_domain_without_central_control() -> None:
    # weak_crypto has no `central_control` (covered by crypto-checks.yaml) →
    # never surfaced by this path even when home-grown, to avoid double-emission.
    strat = {"weak_crypto": {"strategy": "home-grown", "bespoke_evidence": [{"file": "h.js", "line": 1}]}}
    assert dis.build_impl_design_signals(strat) == []


def test_home_grown_central_control_surfaces_design_weakness_without_instances() -> None:
    # The Gap-A payoff: a hand-rolled sink with NO confirmed instance still
    # becomes a design-risk weakness (kind: design, no CVSS).
    strat = {"injection": {"strategy": "home-grown", "bespoke_evidence": [{"file": "routes/a.ts", "line": 3}]}}
    signals = dis.build_impl_design_signals(strat)
    assert len(signals) == 1
    w = mt.build_weakness_register([], signals, {"injection": "home-grown"})
    assert len(w) == 1
    assert w[0]["weakness_class"] == "injection"
    assert w[0]["kind"] == "design"
    assert w[0]["severity_basis"] == "design-risk"
    assert w[0].get("instances") in (None, [])


def test_home_grown_central_control_pervasive_is_systemic() -> None:
    # Sinks across ≥2 directories → systemic → Critical (spread × home-grown).
    strat = {
        "injection": {
            "strategy": "home-grown",
            "bespoke_evidence": [{"file": "routes/a.ts", "line": 1}, {"file": "lib/b.ts", "line": 2}],
        }
    }
    signals = dis.build_impl_design_signals(strat)
    assert sorted(signals[0]["affected_components"]) == ["lib", "routes"]
    w = mt.build_weakness_register([], signals, {"injection": "home-grown"})
    assert w[0]["severity"] == "Critical"


def test_cli_writes_impl_design_signals_sidecar(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {}, {"view.js": "el.innerHTML = userInput\n"})
    out = tmp_path / "out"
    rc = dis._main(["--repo-root", str(repo), "--output-dir", str(out)])
    assert rc == 0
    doc = json.loads((out / ".impl-design-signals.json").read_text())
    classes = {s["weakness_class"] for s in doc["design_signals"]}
    assert "output_xss_csp" in classes
