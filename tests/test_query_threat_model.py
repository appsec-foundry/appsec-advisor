"""Tests for scripts/query_threat_model.py.

Drives the module via its public API plus CLI smoke tests. Fixtures write
minimal ``threat-model.yaml`` files to a tmp OUTPUT_DIR so each test exercises
the extraction / lookup / render contract in isolation.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "query_threat_model.py"


def _load_module():
    if "query_threat_model" in sys.modules:
        return sys.modules["query_threat_model"]
    spec = importlib.util.spec_from_file_location("query_threat_model", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["query_threat_model"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


qtm = _load_module()


def _write_model(output_dir: Path, body: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "threat-model.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


SAMPLE = """\
    meta:
      project: Demo App
      model: claude-sonnet-4-6
      assessment_depth: standard
      generated: "2026-04-19T13:06:37Z"
      plugin_version: "0.4.0-beta"
      mode: full
      check_requirements: false
      compliance_scope: []
      git:
        commit_sha: cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f
        branch: master
    threats:
      - id: T-001
        stride: Tampering
        component: api
        severity: Critical
        title: "SQL Injection (routes/login.ts:34)"
        scenario: "Attacker submits a crafted email parameter to bypass auth."
        cwe: CWE-89
        evidence:
          - {file: routes/login.ts, line: 34}
        mitigation_ids: [M-001]
      - id: T-002
        stride: Elevation of Privilege
        component: auth
        risk: High
        title: "Missing Authorization Check (api/orders.ts:12)"
        scenario: "A user reads another user's orders by changing the id."
        cwe: CWE-862
        mitigation_ids: [M-002]
    mitigations:
      - id: M-001
        priority: P1
        title: "Parameterize the login query"
        description: "Use bound parameters instead of string concatenation."
      - id: M-002
        priority: P2
        title: "Enforce per-object authorization"
    critical_findings:
      - threat_id: T-001
        summary: "Auth bypass via SQL injection in login."
        mitigation_id: M-001
    security_controls:
      - domain: Authentication
        effectiveness: Weak
    weaknesses:
      - id: W-001
        weakness_class: missing_authz
        kind: design
        severity: High
        severity_basis: design-risk
        title: "Systemic missing object-level authorization"
        statement: "Authorization is not enforced at the data-access layer."
        affected_components: [auth, api]
        instances:
          - {id: T-002}
"""


# --------------------------------------------------------------------------
# build_facts — extraction, severity precedence, display-id mapping
# --------------------------------------------------------------------------


def _facts(grep=None):
    import yaml

    data = yaml.safe_load(textwrap.dedent(SAMPLE))
    return qtm.build_facts(data, grep)


def test_project_name_from_string_meta():
    assert _facts()["project"]["name"] == "Demo App"


def test_display_id_maps_t_to_f():
    ids = [f["id"] for f in _facts()["findings"]]
    assert ids == ["F-001", "F-002"]  # severity-sorted: Critical then High
    assert _facts()["findings"][0]["raw_id"] == "T-001"


def test_severity_precedence_risk_used_when_no_severity():
    f2 = next(f for f in _facts()["findings"] if f["id"] == "F-002")
    assert f2["severity"] == "High"  # taken from `risk`


def test_totals_count_all_axes():
    t = _facts()["totals"]
    assert t["findings"] == 2
    assert t["by_severity"] == {"Critical": 1, "High": 1}
    assert t["mitigations"] == 2
    assert t["weaknesses"] == 1
    assert t["controls"] == 1


def test_location_from_first_evidence():
    f1 = next(f for f in _facts()["findings"] if f["id"] == "F-001")
    assert f1["location"] == "routes/login.ts:34"


def test_provenance_scalars_bool_and_skip_empty():
    prov = _facts()["provenance"]
    assert prov["plugin_version"] == "0.4.0-beta"
    assert prov["mode"] == "full"
    assert prov["check_requirements"] == "no"  # bool -> yes/no
    assert "compliance_scope" not in prov  # empty list skipped
    assert "team_owner" not in prov  # absent field skipped


def test_provenance_rendered_in_digest():
    out = qtm.render_text(_facts())
    assert "META (how this model was generated)" in out
    assert "Plugin:" in out and "0.4.0-beta" in out


def test_worst_case_from_curated_critical_findings():
    wc = _facts()["worst_case"]
    assert wc[0]["id"] == "F-001"
    assert wc[0]["summary"] == "Auth bypass via SQL injection in login."
    assert wc[0]["mitigation_id"] == "M-001"


def test_worst_case_is_global_not_narrowed_by_grep():
    # Even a grep that excludes F-001, the verdict stays global.
    facts = _facts(grep="authorization")
    assert [f["id"] for f in facts["findings"]] == ["F-002"]
    assert facts["worst_case"][0]["id"] == "F-001"


def test_worst_case_falls_back_to_top_findings_when_uncurated():
    import yaml

    data = yaml.safe_load(textwrap.dedent(SAMPLE))
    data.pop("critical_findings")
    wc = qtm.build_facts(data, None)["worst_case"]
    assert wc[0]["id"] == "F-001"  # top severity-ranked finding


def test_worst_case_rendered_as_quick_verdict():
    assert "TOP RISK" in qtm.render_text(_facts())


# --------------------------------------------------------------------------
# grep — topic filtering, histogram stays global
# --------------------------------------------------------------------------


def test_grep_filters_findings_but_keeps_global_counts():
    facts = _facts(grep="authorization")
    assert [f["id"] for f in facts["findings"]] == ["F-002"]
    assert facts["matched_findings"] == 1
    # Histogram is over ALL findings, not just the matched subset.
    assert facts["totals"]["findings"] == 2


def test_grep_matches_via_mitigation_text():
    # "parameterize" appears only in M-001's title, not in F-001's own fields.
    facts = _facts(grep="parameterize")
    assert "F-001" in [f["id"] for f in facts["findings"]]


def test_grep_matches_weakness_class():
    facts = _facts(grep="missing_authz")
    assert [w["id"] for w in facts["weaknesses"]] == ["W-001"]


# --------------------------------------------------------------------------
# lookup_id — precise resolution + cross-links
# --------------------------------------------------------------------------


def test_lookup_finding_resolves_with_fix_and_parent():
    focus = qtm.lookup_id(_facts(), "F-002")
    assert focus["found"] and focus["kind"] == "finding"
    assert [m["id"] for m in focus["mitigations"]] == ["M-002"]
    assert [w["id"] for w in focus["parent_weaknesses"]] == ["W-001"]


def test_lookup_accepts_t_prefix_and_zero_pad():
    assert qtm.lookup_id(_facts(), "T-1")["finding"]["id"] == "F-001"
    assert qtm.lookup_id(_facts(), "f-001")["finding"]["id"] == "F-001"


def test_lookup_mitigation_lists_covered_findings():
    focus = qtm.lookup_id(_facts(), "M-001")
    assert focus["kind"] == "mitigation"
    assert [f["id"] for f in focus["covers"]] == ["F-001"]


def test_lookup_weakness_lists_instances():
    focus = qtm.lookup_id(_facts(), "W-001")
    assert focus["kind"] == "weakness"
    assert [f["id"] for f in focus["instances"]] == ["F-002"]


def test_lookup_unknown_id_is_found_false_not_error():
    assert qtm.lookup_id(_facts(), "F-999")["found"] is False


def test_lookup_non_id_returns_none_kind():
    focus = qtm.lookup_id(_facts(), "hello")
    assert focus["found"] is False and focus["kind"] is None


# --------------------------------------------------------------------------
# CLI smoke — exit codes and modes
# --------------------------------------------------------------------------


def _run(args):
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


def test_cli_default_digest(tmp_path):
    _write_model(tmp_path, SAMPLE)
    r = _run(["--output-dir", str(tmp_path)])
    assert r.returncode == 0
    assert "F-001" in r.stdout and "MITIGATIONS" in r.stdout


def test_cli_id_lookup(tmp_path):
    _write_model(tmp_path, SAMPLE)
    r = _run(["--output-dir", str(tmp_path), "--id", "F-001"])
    assert r.returncode == 0
    assert r.stdout.startswith("F-001 (T-001)")


def test_cli_json_is_valid(tmp_path):
    _write_model(tmp_path, SAMPLE)
    r = _run(["--output-dir", str(tmp_path), "--json"])
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert payload["totals"]["findings"] == 2


def test_cli_no_model_exit_1(tmp_path):
    r = _run(["--output-dir", str(tmp_path)])
    assert r.returncode == 1
    assert "create-threat-model" in r.stdout


def test_cli_empty_model_exit_1(tmp_path):
    (tmp_path / "threat-model.yaml").write_text("", encoding="utf-8")
    r = _run(["--output-dir", str(tmp_path)])
    assert r.returncode == 1


def test_cli_non_mapping_exit_2(tmp_path):
    (tmp_path / "threat-model.yaml").write_text("- a\n- b\n", encoding="utf-8")
    r = _run(["--output-dir", str(tmp_path)])
    assert r.returncode == 2
    assert "not a mapping" in r.stderr


def test_cli_grep_and_id_mutually_exclusive(tmp_path):
    _write_model(tmp_path, SAMPLE)
    r = _run(["--output-dir", str(tmp_path), "--grep", "x", "--id", "F-1"])
    assert r.returncode == 2  # argparse usage error


# --------------------------------------------------------------------------
# Custom requirements — the compliance lane
#
# When a team wires up their own requirement catalog at scan time
# (create-threat-model --requirements), asking "which requirements do we
# break?" must be answerable here. Before this, the facts index carried only
# meta's "Requirements checked: yes" — and `--grep REQ-AUTH-01` returned ZERO
# findings even when one violated exactly that id, which reads as a truthful
# "nothing matches" while being false.
# --------------------------------------------------------------------------


REQ_SAMPLE = """\
    meta:
      project: Req App
      check_requirements: true
    threats:
      - id: T-001
        stride: Tampering
        component: api
        severity: Critical
        title: "SQL Injection"
        violated_requirements: [REQ-AUTH-01]
      - id: T-002
        stride: Spoofing
        component: api
        severity: High
        title: "Weak cipher"
        requirement_id: REQ-CRYPTO-03
      - id: T-003
        stride: Spoofing
        component: api
        severity: Low
        title: "Unrelated finding"
"""

_CATALOG = {
    "source": "https://intern.example.com/appsec.yaml",
    "categories": [
        {
            "name": "Auth",
            "requirements": [
                {"id": "REQ-AUTH-01", "url": "https://intern.example.com/#auth-01"},
                {"id": "REQ-CRYPTO-03", "url": ""},
                {"id": "REQ-UNUSED-99", "url": ""},
            ],
        }
    ],
}


def _write_catalog(output_dir: Path, doc: dict) -> None:
    import yaml

    (output_dir / ".requirements.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")


def _req_facts(tmp_path: Path, catalog: dict | None = _CATALOG, grep=None) -> dict:
    import yaml

    _write_model(tmp_path, REQ_SAMPLE)
    if catalog is not None:
        _write_catalog(tmp_path, catalog)
    data = yaml.safe_load(textwrap.dedent(REQ_SAMPLE))
    return qtm.build_facts(data, grep, tmp_path)


def test_requirements_violations_are_indexed(tmp_path):
    reqs = _req_facts(tmp_path)["requirements"]
    assert reqs["integrated"] is True
    assert reqs["declared"] == 3
    assert reqs["violated"] == [
        {"id": "REQ-AUTH-01", "findings": ["F-001"]},
        {"id": "REQ-CRYPTO-03", "findings": ["F-002"]},
    ]
    # A declared-but-unbroken requirement is not reported as violated.
    assert "REQ-UNUSED-99" not in {v["id"] for v in reqs["violated"]}


def test_requirement_id_singular_field_is_picked_up(tmp_path):
    """A finding may carry `requirement_id` instead of the plural array."""
    facts = _req_facts(tmp_path)
    f2 = next(f for f in facts["findings"] if f["id"] == "F-002")
    assert f2["violated_requirements"] == ["REQ-CRYPTO-03"]


def test_grep_matches_a_requirement_id(tmp_path):
    """The regression: grepping a requirement id must find the finding that
    breaks it, not silently return an empty result."""
    facts = _req_facts(tmp_path, grep="REQ-AUTH-01")
    assert [f["id"] for f in facts["findings"]] == ["F-001"]


def test_requirements_survive_a_grep_narrowed_read(tmp_path):
    """Compliance is a global fact, like the severity histogram: a topic filter
    must not make violations disappear from the answer surface."""
    reqs = _req_facts(tmp_path, grep="cipher")["requirements"]
    assert [v["id"] for v in reqs["violated"]] == ["REQ-AUTH-01", "REQ-CRYPTO-03"]


def test_no_catalog_means_no_requirement_signal(tmp_path):
    assert _req_facts(tmp_path, catalog=None)["requirements"]["integrated"] is False


def test_bundled_baseline_is_not_a_custom_requirement(tmp_path):
    """The zero-config OWASP fallback must never be presented as a team's own
    requirement catalog — same gate review-threat-model applies."""
    bundled = dict(_CATALOG, source="bundled-bestpractices")
    assert _req_facts(tmp_path, catalog=bundled)["requirements"]["integrated"] is False


def test_skipped_stub_is_not_a_custom_requirement(tmp_path):
    stub = dict(_CATALOG, source="skipped")
    assert _req_facts(tmp_path, catalog=stub)["requirements"]["integrated"] is False


def test_check_requirements_off_suppresses_everything(tmp_path):
    """Catalog present but the run had the check off — report nothing."""
    import yaml

    _write_model(tmp_path, REQ_SAMPLE)
    _write_catalog(tmp_path, _CATALOG)
    data = yaml.safe_load(textwrap.dedent(REQ_SAMPLE))
    data["meta"]["check_requirements"] = False
    assert qtm.build_facts(data, None, tmp_path)["requirements"]["integrated"] is False


def test_cli_renders_the_requirements_block(tmp_path):
    _write_model(tmp_path, REQ_SAMPLE)
    _write_catalog(tmp_path, _CATALOG)
    r = _run(["--output-dir", str(tmp_path)])
    assert r.returncode == 0
    assert "REQUIREMENTS — 3 custom requirement(s) checked" in r.stdout
    assert "REQ-AUTH-01" in r.stdout and "violated by F-001" in r.stdout
    assert "https://intern.example.com/#auth-01" in r.stdout


def test_cli_id_lookup_shows_violated_requirement(tmp_path):
    _write_model(tmp_path, REQ_SAMPLE)
    _write_catalog(tmp_path, _CATALOG)
    r = _run(["--output-dir", str(tmp_path), "--id", "F-001"])
    assert r.returncode == 0
    assert "Violates: REQ-AUTH-01" in r.stdout


def test_checked_but_no_custom_catalog_is_stated_not_silent(tmp_path):
    """meta says the requirements check ran, but only against the bundled OWASP
    baseline. Staying silent there reads as "checked, nothing violated" — a
    false compliance claim. The digest must say so explicitly.
    """
    _write_model(tmp_path, REQ_SAMPLE)
    _write_catalog(tmp_path, dict(_CATALOG, source="bundled-bestpractices"))
    r = _run(["--output-dir", str(tmp_path)])
    assert r.returncode == 0
    assert "REQUIREMENTS — this scan verified NO custom requirements" in r.stdout
    assert "bundled OWASP best-practices baseline" in r.stdout
    assert "Do not report compliance" in r.stdout


def test_check_off_stays_completely_silent(tmp_path):
    """The common case: no requirements configured at all. No block, no noise —
    the feature must cost nothing when unused.
    """
    import yaml

    _write_model(tmp_path, REQ_SAMPLE)
    data = yaml.safe_load(textwrap.dedent(REQ_SAMPLE))
    data["meta"]["check_requirements"] = False
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    r = _run(["--output-dir", str(tmp_path)])
    assert r.returncode == 0
    assert "REQUIREMENTS" not in r.stdout
    assert "violates:" not in r.stdout


def test_no_violation_is_not_reported_as_compliance(tmp_path):
    """A custom catalog with nothing broken must not read as "you comply"."""
    import yaml

    _write_model(tmp_path, REQ_SAMPLE)
    data = yaml.safe_load(textwrap.dedent(REQ_SAMPLE))
    for t in data["threats"]:
        t.pop("violated_requirements", None)
        t.pop("requirement_id", None)
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    _write_catalog(tmp_path, _CATALOG)
    r = _run(["--output-dir", str(tmp_path)])
    assert "No finding breaks a declared requirement." in r.stdout
    assert "Not the same as 'compliant'" in r.stdout
