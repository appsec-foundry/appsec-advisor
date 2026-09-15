"""Tests for detect_impl_strategy.py (P2 implementation-strategy axis) and the
merge_threats reconciler's use of the strategy signal."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

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
    repo = _repo(tmp_path, {"bcrypt": "^5"}, {"x.js": "crypto.createHash('md5').update(password)\n"})
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


def test_library_inventory_does_not_suppress_observed_design_gap() -> None:
    # A dependency inventory does not establish enforcement at the affected path.
    w = mt.build_weakness_register([], [_design_signal()], {"injection": "standard-vetted"})
    assert len(w) == 1
    assert w[0]["severity"] == "Medium"


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
    assert s["mechanism_id"] == "frontend-output-encoding"
    assert s["title"] == "Frontend rendering lacks enforced output encoding"
    assert s["practice_evidence"] == [{"file": "src/view.js", "line": 1}]
    assert "absent_control_signal" not in s


def test_impl_design_signal_not_emitted_for_vetted() -> None:
    # standard-vetted → the vetted control IS the control → no design signal.
    strat = {"output_xss_csp": {"strategy": "standard-vetted", "bespoke_evidence": []}}
    assert dis.build_impl_design_signals(strat) == []


def test_impl_design_signal_skips_domain_without_central_control() -> None:
    # weak_crypto has no `central_control` (covered by crypto-checks.yaml) →
    # never surfaced by this path even when home-grown, to avoid double-emission.
    strat = {"weak_crypto": {"strategy": "home-grown", "bespoke_evidence": [{"file": "h.js", "line": 1}]}}
    assert dis.build_impl_design_signals(strat) == []


def test_observed_sink_surfaces_implementation_weakness_without_instances() -> None:
    # A sink proves the observed practice, not absence of an application-wide control.
    strat = {"injection": {"strategy": "home-grown", "bespoke_evidence": [{"file": "routes/a.ts", "line": 3}]}}
    signals = dis.build_impl_design_signals(strat)
    assert len(signals) == 1
    w = mt.build_weakness_register([], signals, {"injection": "home-grown"})
    assert len(w) == 1
    assert w[0]["weakness_class"] == "injection"
    assert w[0]["kind"] == "implementation"
    assert w[0]["severity_basis"] == "observed-practice"
    assert w[0].get("instances") in (None, [])


def test_directories_do_not_invent_components_or_critical_design_risk() -> None:
    # Directory names are not component identities or proof of systemic absence.
    strat = {
        "injection": {
            "strategy": "home-grown",
            "bespoke_evidence": [{"file": "routes/a.ts", "line": 1}, {"file": "lib/b.ts", "line": 2}],
        }
    }
    signals = dis.build_impl_design_signals(strat)
    assert signals[0]["affected_components"] == []
    w = mt.build_weakness_register([], signals, {"injection": "home-grown"})
    assert w[0]["severity"] == "Medium"
    assert w[0]["kind"] == "implementation"


@pytest.mark.parametrize(
    "body",
    [
        "sequelize.query('SELECT * FROM entries WHERE id = :id', { replacements: { id: request.query.id } })",
        "sequelize.query('SELECT * FROM reports WHERE owner = $owner', { bind: { owner: principalId } })",
        "element.innerHTML = DOMPurify.sanitize(value)",
        "element.innerHTML = '<p>Fixed</p>'",
        "// element.innerHTML = request.body.text",
        "const explanation = 'element.innerHTML = userInput'",
        "const header = jwt.decode(token)",
        "const requestId = Math.random()",
        "crypto.createHash('md5').update(assetBytes)",
        "database.query(`SELECT ${1 + 2}`)",
        "graph.query(`query ${operation}`)",
        "client.query('filter=' + expression)",
    ],
)
def test_safe_operations_do_not_emit_weaknesses(tmp_path, body):
    repo = _repo(tmp_path, {"sequelize": "1", "dompurify": "1"}, {"handler.ts": body + "\n"})
    assert dis.build_impl_design_signals(dis.build_strategy_map(repo)) == []


@pytest.mark.parametrize(
    "body",
    [
        "db.query(`SELECT * FROM entries WHERE id = ${request.query.id}`)",
        """pool.query("SELECT * FROM records WHERE owner = '" + accountName)""",
        "database.query(\n  `SELECT * FROM reports WHERE id = ${value}`\n)",
    ],
)
def test_query_interpolation_retains_concrete_evidence(tmp_path, body):
    repo = _repo(tmp_path, {}, {"lookup.ts": body + "\n"})
    signals = dis.build_impl_design_signals(dis.build_strategy_map(repo))
    assert [s["mechanism_id"] for s in signals] == ["database-query-concatenation"]
    assert signals[0]["practice_evidence"] == [{"file": "src/lookup.ts", "line": 1}]


@pytest.mark.parametrize("location", ["tests/view.ts", "src/view.spec.ts", "examples/ui.js"])
def test_nonproduction_code_does_not_supply_strategy_evidence(tmp_path, location):
    path = tmp_path / location
    path.parent.mkdir(parents=True)
    path.write_text("element.innerHTML = userInput\n")
    assert dis.build_strategy_map(tmp_path) == {}


def test_authentication_library_does_not_establish_authorization(tmp_path):
    repo = _repo(
        tmp_path,
        {"express-jwt": "1", "@nestjs/passport": "1", "helmet": "1"},
        {"edit.ts": "record.update(request.body)\n"},
    )
    strategies = dis.build_strategy_map(repo)
    assert "missing_authz" not in strategies
    assert "output_xss_csp" not in strategies
    assert "server_side_exposure" not in strategies


def test_cli_writes_impl_design_signals_sidecar(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {}, {"view.js": "el.innerHTML = userInput\n"})
    out = tmp_path / "out"
    rc = dis._main(["--repo-root", str(repo), "--output-dir", str(out)])
    assert rc == 0
    doc = json.loads((out / ".impl-design-signals.json").read_text())
    classes = {s["weakness_class"] for s in doc["design_signals"]}
    assert "output_xss_csp" in classes


@pytest.mark.parametrize(
    "body",
    [
        "const clean = DOMPurify.sanitize(input); element.innerHTML = clean;",
        "const rendered = sanitizeHtml(raw);\nnode.innerHTML = rendered;",
        "if (req.user.role === 'admin') { next(); }",
    ],
)
def test_safe_local_controls_do_not_emit_weaknesses(tmp_path, body):
    repo = _repo(tmp_path, {}, {"view.ts": body})
    assert dis.build_impl_design_signals(dis.build_strategy_map(repo)) == []


def test_reassigned_sanitizer_result_is_not_exculpatory(tmp_path):
    repo = _repo(
        tmp_path, {}, {"view.ts": "let clean = DOMPurify.sanitize(input); clean = raw; element.innerHTML = clean;"}
    )
    assert dis.build_impl_design_signals(dis.build_strategy_map(repo))


def test_refuted_source_site_does_not_resurface_as_practice(tmp_path):
    repo = _repo(tmp_path, {}, {"query.ts": "db.query(`select * from entries where id=${value}`)"})
    out = tmp_path / "run"
    out.mkdir()
    threat = {
        "t_id": "T-001",
        "cwe": "CWE-89",
        "evidence_check": "refuted",
        "evidence": {"file": "src/query.ts", "line": 1},
    }
    _, signals = dis.emit_artifacts(repo, out, [threat])
    assert signals == []


def test_components_and_instances_require_the_observed_location(tmp_path):
    repo = _repo(tmp_path, {}, {"query.ts": "db.query(`select * from entries where id=${value}`)\notherOperation()"})
    out = tmp_path / "run"
    out.mkdir()
    threat = {
        "t_id": "T-001",
        "cwe": "CWE-89",
        "component_id": "unrelated",
        "evidence": {"file": "src/query.ts", "line": 2},
    }
    _, signals = dis.emit_artifacts(repo, out, [threat])
    assert signals[0]["affected_components"] == []
    assert signals[0]["instance_ids"] == []


def test_refuted_other_cwe_at_same_site_does_not_hide_source_observation(tmp_path):
    repo = _repo(tmp_path, {}, {"query.ts": "db.query(`select * from entries where id=${value}`)"})
    out = tmp_path / "run"
    out.mkdir()
    threat = {
        "t_id": "T-001",
        "cwe": "CWE-94",
        "evidence_check": "refuted",
        "evidence": {"file": "src/query.ts", "line": 1},
    }
    _, signals = dis.emit_artifacts(repo, out, [threat])
    assert len(signals) == 1
    assert signals[0]["cwe"] == "CWE-89"
