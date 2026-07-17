"""Tests for scripts/summarize_threat_model.py.

Drives the module via its public API plus CLI smoke tests. Fixtures write
minimal ``threat-model.yaml`` files to a tmp OUTPUT_DIR so each test
exercises the extraction + rendering contract in isolation.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "summarize_threat_model.py"


def _load_module():
    if "summarize_threat_model" in sys.modules:
        return sys.modules["summarize_threat_model"]
    spec = importlib.util.spec_from_file_location("summarize_threat_model", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["summarize_threat_model"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


stm = _load_module()


def _write_model(output_dir: Path, body: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "threat-model.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


SAMPLE = """\
    meta:
      schema_version: 1
      plugin_version: "0.4.0-beta"
      generated: "2026-04-19T13:06:37Z"
      mode: full
      assessment_depth: standard
      model: "claude-sonnet-4-6"
      git:
        commit_sha: "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f"
        branch: master
    project:
      name: "Demo App"
      version: "1.2.3"
    components:
      - id: C-01
        name: API
      - id: C-02
        name: Auth
    threats:
      - t_id: T-001
        component: API
        severity: Critical
        title: "SQLi in search"
        vektor: "Internet Anon"
      - t_id: T-002
        component: Auth
        severity: High
        title: "Weak JWT"
      - t_id: T-003
        component: API
        risk: Critical
        title: "Hardcoded key"
      - t_id: T-004
        component: API
        severity: Medium
        title: "Verbose errors"
    mitigations:
      - id: M-001
      - id: M-002
    security_controls:
      - id: SC-01
"""


# ---------------------------------------------------------------------------
# Summary extraction
# ---------------------------------------------------------------------------


def test_severity_counts_and_totals(tmp_path):
    import yaml

    _write_model(tmp_path, SAMPLE)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)

    assert summary["severity_counts"]["Critical"] == 2  # severity + risk fallback
    assert summary["severity_counts"]["High"] == 1
    assert summary["severity_counts"]["Medium"] == 1
    assert summary["totals"] == {
        "threats": 4,
        "components": 2,
        "mitigations": 2,
        "controls": 1,
    }


def test_severity_uses_effective_severity_precedence(tmp_path):
    import yaml

    # effective_severity is the capped/canonical value the report ranks by; it
    # must win over a differing raw `risk` (composer precedence).
    body = """\
        meta: {project: {name: Demo}}
        threats:
          - {t_id: T-001, effective_severity: High, risk: Critical, title: capped down}
          - {t_id: T-002, risk: Medium, title: risk fallback only}
    """
    _write_model(tmp_path, body)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    assert summary["severity_counts"]["High"] == 1  # effective_severity wins
    assert summary["severity_counts"]["Critical"] == 0
    assert summary["severity_counts"]["Medium"] == 1  # risk used when no effective_severity
    assert summary["criticals"] == []


def test_worst_case_from_curated_critical_findings(tmp_path):
    import yaml

    body = """\
        meta: {project: {name: Demo}}
        threats:
          - {t_id: T-001, effective_severity: Critical, component: auth, title: secret}
          - {t_id: T-002, effective_severity: High, component: api, title: sqli}
        mitigations:
          - {id: M-001, priority: P1}
          - {id: M-002, priority: P2}
        critical_findings:
          - {threat_id: T-002, summary: attacker dumps users table, mitigation_id: M-002}
          - {threat_id: T-001, summary: full account takeover, mitigation_id: M-001}
          - {threat_id: T-404, summary: gone, mitigation_id: M-000}
    """
    _write_model(tmp_path, body)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    wc = summary["worst_case"]
    # unresolved threat dropped; Critical before High
    assert [w["id"] for w in wc] == ["T-001", "T-002"]
    assert wc[0]["summary"] == "full account takeover"  # verbatim
    assert wc[0]["mitigation_id"] == "M-001" and wc[0]["priority"] == "P1"

    out = stm.render_text(summary, None, show_all=False)
    assert "Worst case if nothing changes" in out
    assert "full account takeover" in out
    assert "→ M-001 (P1)" in out


def test_worst_case_falls_back_to_top_severity(tmp_path):
    import yaml

    # no critical_findings -> degrade to top Critical/High threats
    _write_model(tmp_path, SAMPLE)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    wc = summary["worst_case"]
    assert all(w["severity"] in ("Critical", "High") for w in wc)
    assert all(w["mitigation_id"] == "" for w in wc)  # no curated mitigation link
    assert "T-004" not in {w["id"] for w in wc}  # the Medium finding


def test_backlog_and_coverage(tmp_path):
    import yaml

    body = """\
        meta: {project: {name: Demo}}
        threats:
          - {t_id: T-001, risk: Critical, mitigation_ids: [M-001]}
          - {t_id: T-002, risk: High, mitigation_ids: [M-002]}
          - {t_id: T-003, risk: Medium}
        mitigations:
          - {id: M-001, priority: P1}
          - {id: M-002, priority: P2}
          - {id: M-003, priority: P2}
          - {id: M-004}
    """
    _write_model(tmp_path, body)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    assert summary["backlog"] == {"P1": 1, "P2": 2, "P3": 0}
    # two of three findings carry mitigation_ids
    assert summary["coverage"] == {"with_mitigation": 2, "uncovered": 1}

    out = stm.render_text(summary, None, show_all=False)
    assert "Backlog    1× P1 · 2× P2" in out
    assert "Coverage   2/3 findings have a mitigation · 1 without" in out


def test_control_posture_summary(tmp_path):
    import yaml

    body = """\
        meta: {project: {name: Demo}}
        threats:
          - {t_id: T-001, risk: High}
        security_controls:
          - {domain: Authorization, control: RBAC, effectiveness: Missing}
          - {domain: Crypto, control: TLS, effectiveness: Adequate}
          - {domain: Crypto, control: Secrets, effectiveness: Weak}
          - {domain: Logging, control: Audit, effectiveness: Partial}
    """
    _write_model(tmp_path, body)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    posture = summary["control_posture"]
    assert posture["effectiveness_counts"] == {"Missing": 1, "Adequate": 1, "Weak": 1, "Partial": 1}
    # weakest-first domains whose weakest control is Missing/Weak
    assert posture["weak_domains"] == ["Authorization", "Crypto"]

    out = stm.render_text(summary, None, show_all=False)
    assert "Controls   4 assessed · Missing 1 · Weak 1 · Partial 1 · Adequate 1" in out
    assert "Weakest    Authorization · Crypto" in out


def test_backlog_line_omitted_when_no_priorities(tmp_path):
    import yaml

    # SAMPLE mitigations carry no priority -> backlog all zero -> no Backlog line
    _write_model(tmp_path, SAMPLE)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    assert summary["backlog"] == {"P1": 0, "P2": 0, "P3": 0}
    out = stm.render_text(summary, None, show_all=False)
    assert "Backlog" not in out
    # coverage still renders: SAMPLE threats carry no mitigation_ids
    assert "Coverage   0/4 findings have a mitigation · 4 without" in out


def test_criticals_only_and_sorted(tmp_path):
    import yaml

    _write_model(tmp_path, SAMPLE)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)

    crit_ids = [c["id"] for c in summary["criticals"]]
    assert crit_ids == ["T-001", "T-003"]
    # threats_by_severity is severity-ordered then by id
    order = [t["severity"] for t in summary["threats_by_severity"]]
    assert order == ["Critical", "Critical", "High", "Medium"]


def test_scan_identity_extracted(tmp_path):
    import yaml

    _write_model(tmp_path, SAMPLE)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    assert summary["scan"]["commit_sha"] == "cb6fb8a"
    assert summary["scan"]["branch"] == "master"
    assert summary["scan"]["assessment_depth"] == "standard"
    assert summary["project"] == {"name": "Demo App", "version": "1.2.3"}


def test_project_nested_in_meta(tmp_path):
    """Tolerate project carried under meta as a string or dict."""
    summary = stm.build_summary({"meta": {"project": "Legacy Name"}}, tmp_path)
    assert summary["project"]["name"] == "Legacy Name"
    summary2 = stm.build_summary({"meta": {"project": {"name": "Nested"}}}, tmp_path)
    assert summary2["project"]["name"] == "Nested"


def test_missing_project_defaults(tmp_path):
    summary = stm.build_summary({}, tmp_path)
    assert summary["project"]["name"] == "(unnamed project)"
    assert summary["totals"]["threats"] == 0


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_text_compact(tmp_path):
    import yaml

    _write_model(tmp_path, SAMPLE)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    out = stm.render_text(summary, None, show_all=False)
    assert "Threat Model — Demo App (1.2.3)" in out
    assert "Top Critical (2)" in out
    # compact mode does not expand the full by-severity grouping (that is --all)
    assert "High (1)" not in out
    assert "Medium (1)" not in out
    assert "depth standard (full)" in out


def test_render_text_all_groups(tmp_path):
    import yaml

    _write_model(tmp_path, SAMPLE)
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    out = stm.render_text(summary, None, show_all=True)
    assert "Critical (2)" in out
    assert "High (1)" in out
    assert "Medium (1)" in out
    assert "T-002" in out  # full list includes non-critical


def test_render_status_line_folds_freshness():
    fresh = {"verdict": "FRESH", "reason": "no relevant changes", "recommend": "noop"}
    lines = stm.render_status_line(fresh)
    assert "✓ FRESH" in lines[0]
    assert "no relevant changes" in lines[0]
    assert "up to date" in lines[1]


def test_render_status_line_stale_recommends_full():
    lines = stm.render_status_line({"verdict": "STALE", "recommend": "full"})
    assert "⚠ STALE" in lines[0]
    assert "--full" in lines[1]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _run(args, stdin=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
        input=stdin,
    )


def test_cli_missing_model_exit_1(tmp_path):
    res = _run(["--output-dir", str(tmp_path)])
    assert res.returncode == 1
    assert "No threat model found" in res.stdout


def test_cli_missing_model_json(tmp_path):
    res = _run(["--output-dir", str(tmp_path), "--json"])
    assert res.returncode == 1
    assert json.loads(res.stdout)["verdict"] == "NO_MODEL"


def test_cli_renders_and_json(tmp_path):
    _write_model(tmp_path, SAMPLE)
    res = _run(["--output-dir", str(tmp_path)])
    assert res.returncode == 0
    assert "Findings   4 threats across 2 components" in res.stdout

    resj = _run(["--output-dir", str(tmp_path), "--json"])
    payload = json.loads(resj.stdout)
    assert payload["severity_counts"]["Critical"] == 2


def test_cli_health_json_via_stdin(tmp_path):
    _write_model(tmp_path, SAMPLE)
    health = json.dumps({"freshness": {"verdict": "FRESH", "recommend": "noop"}})
    res = _run(["--output-dir", str(tmp_path), "--health-json", "-"], stdin=health)
    assert res.returncode == 0
    assert "✓ FRESH" in res.stdout


def test_cli_empty_file_treated_as_no_model(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "threat-model.yaml").write_text("", encoding="utf-8")
    res = _run(["--output-dir", str(tmp_path)])
    assert res.returncode == 1
    assert "No threat model found" in res.stdout
    resj = _run(["--output-dir", str(tmp_path), "--json"])
    assert resj.returncode == 1
    assert json.loads(resj.stdout)["verdict"] == "NO_MODEL"


def test_render_zero_findings_points_to_create(tmp_path):
    import yaml

    _write_model(tmp_path, "meta: {project: {name: Clean}}\nthreats: []\n")
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    summary = stm.build_summary(data, tmp_path)
    out = stm.render_text(summary, None, show_all=False)
    assert "Findings   0 threats" in out
    assert "create-threat-model to (re)scan" in out
    # no noise blocks when there is nothing to summarize
    assert "Critical" not in out and "Backlog" not in out


def test_cli_unparseable_yaml_exit_2(tmp_path):
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "threat-model.yaml").write_text("- just\n- a\n- list\n", encoding="utf-8")
    res = _run(["--output-dir", str(tmp_path)])
    assert res.returncode == 2
    assert "not a mapping" in res.stderr


def test_cli_against_repo_fixture():
    """The committed compose fixture renders without error."""
    fixture = REPO_ROOT / "tests" / "fixtures" / "compose"
    res = _run(["--output-dir", str(fixture)])
    assert res.returncode == 0
    assert "Threat Model —" in res.stdout
