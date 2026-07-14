"""Tests for scripts/architecture_coverage_checks.py (arch.md §Erste Lieferung)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).parent.parent
ENGINE = REPO_ROOT / "scripts" / "architecture_coverage_checks.py"
ROUTE_INV = REPO_ROOT / "scripts" / "route_inventory.py"
SCHEMA = json.loads((REPO_ROOT / "schemas" / "architecture-coverage.schema.json").read_text())

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import architecture_coverage_checks as acc  # noqa: E402

ALL_RULE_IDS = {
    "ARCH-COOKIE-001",
    "ARCH-CORS-001",
    "ARCH-JWT-001",
    "ARCH-TLS-001",
    "ARCH-MGMT-001",
    "ARCH-XSS-001",
    "ARCH-SQLI-001",
    "ARCH-AUTHZ-001",
    "ARCH-AUTHN-001",
    "ARCH-BOLA-001",
    "ARCH-INPUT-001",
    "ARCH-SUPPLY-001",
    "ARCH-SECRET-001",
}


def _run_engine(repo: Path, output_dir: Path | None = None) -> dict:
    args = [sys.executable, str(ENGINE), "--repo-root", str(repo), "--stdout"]
    if output_dir is not None:
        args += ["--output-dir", str(output_dir)]
    proc = subprocess.run(args, capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)


def _build_inventory(repo: Path, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [sys.executable, str(ROUTE_INV), "--repo-root", str(repo), "--output-dir", str(output_dir)],
        check=True,
        capture_output=True,
        text=True,
    )


def _verdict(out: dict, rule_id: str) -> dict:
    matches = [r for r in out["rules_evaluated"] if r["rule_id"] == rule_id]
    assert matches, f"{rule_id} missing from rules_evaluated[]"
    return matches[0]


def _compiled_rule(**overrides) -> acc.CompiledRule:
    base = {
        "rule_id": "TEST-001",
        "title": "Test rule",
        "domain": "AuthN",
        "control": "Test Control",
        "output": "control_only",
        "family": "hard",
        "precondition_patterns": [],
        "positive_patterns": [],
        "cooccurrence_patterns": [],
        "cooccurrence_window": 0,
        "exculpatory_patterns": [],
        "route_inventory_required": False,
        "requires_management_surface": False,
        "route_requires": {},
        "forbidden_route_signals": {},
        "inventory_pattern": {},
        "threat_category_id": "TH-TEST",
        "stride": "Spoofing",
        "cwe": "CWE-287",
        "hypothesis_id_prefix": "ARCH-HYP-TEST",
        "severity_cap": "High",
        "weak_or_missing_controls": ["Test Control"],
        "architectural_theme": "",
        "generic_threat_title": "",
    }
    base.update(overrides)
    return acc.CompiledRule(**base)


# ---------------------------------------------------------------------------
# Contract: every rule must be evaluated
# ---------------------------------------------------------------------------


def test_every_rule_appears_in_rules_evaluated(tmp_path: Path) -> None:
    out = _run_engine(tmp_path)
    seen = {r["rule_id"] for r in out["rules_evaluated"]}
    assert seen == ALL_RULE_IDS


def test_rules_evaluated_carries_weakness_mechanism_metadata(tmp_path: Path) -> None:
    out = _run_engine(tmp_path)
    assert _verdict(out, "ARCH-SQLI-001")["weakness_mechanism"] == "database-query-concatenation"
    assert _verdict(out, "ARCH-XSS-001")["weakness_mechanism"] == "frontend-output-encoding"


def test_output_validates_against_schema(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text(
        "app.use(cors({origin:'*', credentials:true}));\nconst dsn = 'postgres://u:p@h/db?sslmode=disable';\n"
    )
    out = _run_engine(tmp_path)
    jsonschema.validate(out, SCHEMA)


def test_io_helpers_exclude_vendor_override_and_load_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("APPSEC_ARCH_INCLUDE_VENDOR", raising=False)
    assert acc._is_excluded("node_modules/pkg/index.js") is True

    monkeypatch.setenv("APPSEC_ARCH_INCLUDE_VENDOR", "1")
    assert acc._is_excluded("node_modules/pkg/index.js") is False
    monkeypatch.delenv("APPSEC_ARCH_INCLUDE_VENDOR", raising=False)

    def boom(_rel):
        raise RuntimeError("bad scan-excludes")

    monkeypatch.setattr(acc, "_scan_is_excluded", boom)
    assert acc._is_excluded("vendor/lib/app.js") is True

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.ts").write_text("const x = 1;\n", encoding="utf-8")
    (tmp_path / "src" / "notes.txt").write_text("ignored\n", encoding="utf-8")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("ignored\n", encoding="utf-8")
    assert [p.relative_to(tmp_path).as_posix() for p in acc._walk_sources(tmp_path)] == ["src/app.ts"]

    assert acc._read_lines(tmp_path / "missing.ts") == []
    assert acc._load_json_or_none(tmp_path / "missing.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{bad", encoding="utf-8")
    assert acc._load_json_or_none(bad) is None
    good = tmp_path / "good.json"
    good.write_text('{"ok": true}', encoding="utf-8")
    assert acc._load_json_or_none(good) == {"ok": True}


def test_plugin_data_file_and_rule_loading_errors(tmp_path: Path, monkeypatch) -> None:
    override = tmp_path / "override.yaml"
    monkeypatch.setenv("ARCH_COVERAGE_RULES_YAML", str(override))
    assert acc._plugin_data_file("ARCH_COVERAGE_RULES_YAML", tmp_path / "default.yaml", "rules.yaml") == override
    monkeypatch.delenv("ARCH_COVERAGE_RULES_YAML")

    plugin = tmp_path / "plugin"
    (plugin / "data").mkdir(parents=True)
    plugin_rule = plugin / "data" / "architecture-coverage-rules.yaml"
    plugin_rule.write_text("version: 1\nrules: []\n", encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(plugin))
    assert (
        acc._plugin_data_file("ARCH_COVERAGE_RULES_YAML", tmp_path / "default.yaml", "architecture-coverage-rules.yaml")
        == plugin_rule
    )
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT")

    missing = tmp_path / "missing.yaml"
    try:
        acc._load_rules(missing)
    except FileNotFoundError as exc:
        assert "not found" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("missing rules file was accepted")

    bad_version = tmp_path / "bad-version.yaml"
    bad_version.write_text("version: 2\nrules: []\n", encoding="utf-8")
    try:
        acc._load_rules(bad_version)
    except ValueError as exc:
        assert "unsupported version" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("unsupported rules file was accepted")


def test_scan_file_truncates_hits_and_cooccurrence_window() -> None:
    rule = _compiled_rule(
        precondition_patterns=[acc.re.compile("PRE")],
        positive_patterns=[acc.re.compile("POS")],
        cooccurrence_patterns=[acc.re.compile("CO")],
        exculpatory_patterns=[acc.re.compile("SAFE")],
    )
    hits = acc._scan_file_for_rule(
        "app.ts",
        ["PRE\n", "SAFE POS\n", "CO\n", "POS" + ("x" * 450) + "\n"],
        rule,
    )

    assert hits.precondition[0][:2] == ("app.ts", 1)
    assert hits.exculpatory[0][:2] == ("app.ts", 2)
    assert len(hits.positive[-1][2]) == 400
    assert acc._cooccurrence_satisfied(hits, 0) == hits.positive
    assert [h[1] for h in acc._cooccurrence_satisfied(hits, 1)] == [4]


# ---------------------------------------------------------------------------
# CORS — ARCH-CORS-001
# ---------------------------------------------------------------------------


def test_cors_wildcard_with_credentials_anti_pattern(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text("app.use(cors({\n  origin: '*',\n  credentials: true,\n}));\n")
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-CORS-001")
    assert v["status"] == "anti_pattern"
    assert v["confidence"] == "high"
    assert "weakness_id" not in v
    assert v["architectural_theme"] == "SecureDefaults"
    assert "Cross-origin request abuse" in v["generic_threat_title"]
    ids = [c["rule_id"] for c in out["anti_pattern_candidates"]]
    assert "ARCH-CORS-001" in ids
    cors = [c for c in out["anti_pattern_candidates"] if c["rule_id"] == "ARCH-CORS-001"][0]
    assert "weakness_id" not in cors
    assert cors["architectural_theme"] == "SecureDefaults"


def test_cors_specific_origin_no_anti_pattern(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "app.use(cors({\n  origin: 'https://app.example.com',\n  credentials: true,\n}));\n"
    )
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-CORS-001")
    assert v["status"] in {"present", "partial", "not_applicable"}
    ids = [c["rule_id"] for c in out["anti_pattern_candidates"]]
    assert "ARCH-CORS-001" not in ids


def test_cors_anti_pattern_has_severity_cap_not_critical(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text("app.use(cors({ origin: '*', credentials: true }));\n")
    out = _run_engine(tmp_path)
    cors = [c for c in out["anti_pattern_candidates"] if c["rule_id"] == "ARCH-CORS-001"]
    assert cors and cors[0]["severity_cap"] != "Critical"
    assert cors[0]["severity_cap"] == "High"
    assert cors[0]["must_not_carry_cvss"] is True


# ---------------------------------------------------------------------------
# JWT — ARCH-JWT-001
# ---------------------------------------------------------------------------


def test_jwt_verify_without_algorithms_is_weak(tmp_path: Path) -> None:
    (tmp_path / "auth.ts").write_text(
        "import jwt from 'jsonwebtoken';\nexport function check(t){ return jwt.verify(t, 'secret'); }\n"
    )
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-JWT-001")
    assert v["applies"] is True
    assert v["status"] in {"weak", "anti_pattern"}


def test_jwt_with_algorithm_whitelist_present(tmp_path: Path) -> None:
    (tmp_path / "auth.ts").write_text(
        "import jwt from 'jsonwebtoken';\njwt.verify(t, key, { algorithms: ['RS256'] });\n"
    )
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-JWT-001")
    assert v["status"] == "present"


def test_jwt_max_severity_high(tmp_path: Path) -> None:
    """Per critical-criteria.yaml CWE-347 individual cap is High."""
    (tmp_path / "auth.py").write_text("import jwt\ndata = jwt.decode(t, verify=False)\n")
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-JWT-001")
    assert v["applies"]
    assert v["status"] != "anti_pattern" or out["anti_pattern_candidates"][0]["severity_cap"] != "Critical"


# ---------------------------------------------------------------------------
# Cleartext transport — ARCH-TLS-001
# ---------------------------------------------------------------------------


def test_tls_sslmode_disable_anti_pattern(tmp_path: Path) -> None:
    (tmp_path / "db.ts").write_text("export const dsn = 'postgres://u:p@h/db?sslmode=disable';\n")
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-TLS-001")
    assert v["status"] == "anti_pattern"
    ids = [c["rule_id"] for c in out["anti_pattern_candidates"]]
    assert "ARCH-TLS-001" in ids


def test_tls_localhost_http_is_not_finding(tmp_path: Path) -> None:
    (tmp_path / "dev.ts").write_text("const local = 'http://localhost:3000/api';\n")
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-TLS-001")
    assert v["status"] in {"present", "partial"}


# ---------------------------------------------------------------------------
# Cookie hardening — ARCH-COOKIE-001
# ---------------------------------------------------------------------------


def test_cookie_httponly_false_is_weak(tmp_path: Path) -> None:
    (tmp_path / "session.ts").write_text("app.use(session({ secret:'x', cookie:{ httpOnly:false, secure:false } }));\n")
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-COOKIE-001")
    assert v["applies"] is True
    assert v["status"] in {"weak", "anti_pattern"}


def test_cookie_no_signal_is_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "unrelated.ts").write_text("console.log('hi');\n")
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-COOKIE-001")
    assert v["applies"] is False
    assert v["status"] == "not_applicable"


# ---------------------------------------------------------------------------
# Management endpoint — ARCH-MGMT-001 (unknown-is-not-absent gate)
# ---------------------------------------------------------------------------


def test_mgmt_route_with_middleware_present_not_weak(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    (tmp_path / "app.ts").write_text(
        "const router = express.Router();\nrouter.use(requireAuth);\nrouter.get('/admin/users', h);\n"
    )
    _build_inventory(tmp_path, out_dir)
    out = _run_engine(tmp_path, out_dir)
    v = _verdict(out, "ARCH-MGMT-001")
    assert v["status"] in {"present", "partial"}


def test_mgmt_route_unknown_authn_does_not_escalate(tmp_path: Path) -> None:
    """arch.md §Pipeline-Integration Punkt 8: unknown MUST NOT escalate."""
    out_dir = tmp_path / "out"
    (tmp_path / "app.ts").write_text(
        "const app = express();\napp.get('/admin/users', h);\n"  # no nearby middleware → authn=unknown
    )
    _build_inventory(tmp_path, out_dir)
    out = _run_engine(tmp_path, out_dir)
    v = _verdict(out, "ARCH-MGMT-001")
    assert v["status"] != "anti_pattern"
    assert v["status"] != "missing"
    ids = [c["rule_id"] for c in out["anti_pattern_candidates"]]
    assert "ARCH-MGMT-001" not in ids


def test_mgmt_no_inventory_not_applicable(tmp_path: Path) -> None:
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-MGMT-001")
    assert v["applies"] is False
    assert v["skip_reason"]


def test_mgmt_rule_direct_branches() -> None:
    rule = _compiled_rule(
        rule_id="ARCH-MGMT-001",
        route_requires={"authn_signal_in": ["absent"], "authz_signal_in": ["absent"]},
        forbidden_route_signals={"authn_signal": ["middleware_present"]},
    )

    assert acc._evaluate_mgmt_rule(rule, {"routes": []})["skip_reason"] == "no management surface in route inventory"

    protected = {
        "routes": [
            {
                "management_surface": True,
                "method": "GET",
                "path": "/admin",
                "authn_signal": "middleware_present",
                "authz_signal": "absent",
                "handler_file": "app.ts",
                "handler_line": 7,
            }
        ]
    }
    assert acc._evaluate_mgmt_rule(rule, protected)["status"] == "present"

    absent = {
        "routes": [
            {
                "management_surface": True,
                "method": "GET",
                "path": "/admin",
                "authn_signal": "absent",
                "authz_signal": "absent",
                "handler_file": "app.ts",
                "handler_line": 7,
            }
        ]
    }
    verdict = acc._evaluate_mgmt_rule(rule, absent)
    assert verdict["status"] == "weak"
    assert "management surface GET /admin" in verdict["evidence"][0]["signal"]


# ---------------------------------------------------------------------------
# Hypothesis rules — no anti_pattern_candidates from these
# ---------------------------------------------------------------------------


def test_xss_hypothesis_does_not_emit_anti_pattern(tmp_path: Path) -> None:
    (tmp_path / "view.tsx").write_text(
        "export const Div = (p) => (<div dangerouslySetInnerHTML={{__html: p.name}} />);\n"
        "element.innerHTML = req.query.name;\n"
    )
    out = _run_engine(tmp_path)
    assert all(c["rule_id"] != "ARCH-XSS-001" for c in out["anti_pattern_candidates"])
    hyp_ids = {h["rule_id"] for h in out["threat_hypotheses"]}
    assert "ARCH-XSS-001" in hyp_ids


def test_sqli_hypothesis_only_on_concat(tmp_path: Path) -> None:
    (tmp_path / "login.ts").write_text(
        "const q = 'SELECT * FROM users WHERE id = ' + req.params.id;\nawait db.query(q);\n"
    )
    out = _run_engine(tmp_path)
    sqli_hyp = [h for h in out["threat_hypotheses"] if h["rule_id"] == "ARCH-SQLI-001"]
    assert sqli_hyp
    h = sqli_hyp[0]
    assert h["proof_state"] == "control-derived"
    assert h["decision"] == "emit_hypothesis_only"
    assert "weakness_id" not in h
    assert h["architectural_theme"] == "InputValidation"
    assert h["generic_threat_title"] == "Injection through missing centralized input validation"
    assert h["domain"] == "InputVal"
    assert all(c["rule_id"] != "ARCH-SQLI-001" for c in out["anti_pattern_candidates"])


def test_sqli_parameterized_no_hypothesis(tmp_path: Path) -> None:
    (tmp_path / "login.ts").write_text(
        "const r = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);\n"
    )
    out = _run_engine(tmp_path)
    sqli_hyp = [h for h in out["threat_hypotheses"] if h["rule_id"] == "ARCH-SQLI-001"]
    assert not sqli_hyp


def test_authz_hypothesis_not_applicable_without_authenticated_routes(tmp_path: Path) -> None:
    """arch.md: no central AuthZ library does not automatically mean BAC.
    Without ANY authenticated route, the hypothesis precondition is not met."""
    out_dir = tmp_path / "out"
    (tmp_path / "app.ts").write_text("const app = express();\napp.get('/public', h);\napp.delete('/items/:id', h);\n")
    _build_inventory(tmp_path, out_dir)
    out = _run_engine(tmp_path, out_dir)
    v = _verdict(out, "ARCH-AUTHZ-001")
    assert v["applies"] is False


def test_authz_hypothesis_weak_when_sensitive_method_lacks_authz(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    (tmp_path / "app.ts").write_text(
        "const router = express.Router();\n"
        "router.use(requireAuth);\n"  # authn middleware
        "router.delete('/items/:id', h);\n"  # sensitive, no authz signal
    )
    _build_inventory(tmp_path, out_dir)
    out = _run_engine(tmp_path, out_dir)
    v = _verdict(out, "ARCH-AUTHZ-001")
    assert v["applies"] is True
    assert v["status"] == "weak"


def test_authz_hyp_rule_direct_branches() -> None:
    rule = _compiled_rule(rule_id="ARCH-AUTHZ-001", inventory_pattern={})
    assert "sensitive_methods" in acc._evaluate_authz_hyp_rule(rule, {"routes": []})["skip_reason"]

    rule = _compiled_rule(
        rule_id="ARCH-AUTHZ-001",
        inventory_pattern={"sensitive_methods": ["DELETE"], "require_authz_signal_in": ["unknown"], "min_routes": 2},
    )
    unauth = {
        "routes": [{"method": "DELETE", "path": "/items/:id", "authn_signal": "unknown", "authz_signal": "unknown"}]
    }
    assert acc._evaluate_authz_hyp_rule(rule, unauth)["skip_reason"] == "no authenticated routes — precondition not met"

    one_match = {
        "routes": [
            {
                "method": "DELETE",
                "path": "/items/:id",
                "authn_signal": "middleware_present",
                "authz_signal": "unknown",
                "handler_file": "app.ts",
                "handler_line": 3,
            }
        ]
    }
    verdict = acc._evaluate_authz_hyp_rule(rule, one_match)
    assert verdict["status"] == "present"
    assert verdict["evidence"] == []


# ---------------------------------------------------------------------------
# Hypothesis semantics — never confirmed, never CVSS, never Critical
# ---------------------------------------------------------------------------


def test_no_hypothesis_carries_proof_state_confirmed(tmp_path: Path) -> None:
    (tmp_path / "x.ts").write_text(
        "element.innerHTML = req.query.name;\nconst q = 'SELECT * WHERE u = ' + req.body.u;\ndb.query(q);\n"
    )
    out = _run_engine(tmp_path)
    for h in out["threat_hypotheses"]:
        assert h["proof_state"] in {"control-derived", "evidence-backed"}
        assert h["proof_state"] != "confirmed"


def test_anti_pattern_candidates_never_critical(tmp_path: Path) -> None:
    (tmp_path / "x.ts").write_text(
        "app.use(cors({ origin:'*', credentials:true }));\nconst dsn='postgres://u:p@h/db?sslmode=disable';\n"
    )
    out = _run_engine(tmp_path)
    for c in out["anti_pattern_candidates"]:
        assert c["severity_cap"] in {"Low", "Medium", "High"}
        assert c["must_not_carry_cvss"] is True


# ---------------------------------------------------------------------------
# Empty / negative cases
# ---------------------------------------------------------------------------


def test_empty_repo_all_rules_not_applicable(tmp_path: Path) -> None:
    out = _run_engine(tmp_path)
    for r in out["rules_evaluated"]:
        assert r["applies"] is False
    assert out["control_assessments"] == []
    assert out["anti_pattern_candidates"] == []
    assert out["threat_hypotheses"] == []


def test_writes_to_output_dir(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    _run_engine(tmp_path, out_dir)
    target = out_dir / ".architecture-coverage.json"
    assert target.is_file()
    data = json.loads(target.read_text())
    assert data["version"] == 1


def test_cli_missing_repo_and_output_without_stdout(tmp_path: Path, capsys) -> None:
    assert acc._main(["--repo-root", str(tmp_path / "missing"), "--stdout"]) == 1
    assert "repo-root not found" in capsys.readouterr().err

    rules = tmp_path / "rules.yaml"
    rules.write_text("version: 1\nrules: []\n", encoding="utf-8")
    out = tmp_path / "out"
    assert acc._main(["--repo-root", str(tmp_path), "--output-dir", str(out), "--rules-yaml", str(rules)]) == 0
    captured = capsys.readouterr()
    assert ".architecture-coverage.json" in captured.out
    assert (out / ".architecture-coverage.json").is_file()


def test_run_control_and_hypothesis_emits_linked_control(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("POS\n", encoding="utf-8")
    rules = {
        "version": 1,
        "hypothesis_rules": [
            {
                "rule_id": "TEST-HYP-001",
                "id": "TEST-HYP-001",
                "title": "Test hypothesis",
                "domain": "AuthZ",
                "control": "Object authorization",
                "output": "control_and_hypothesis",
                "threat_category_id": "TH-TEST",
                "stride": "Elevation of Privilege",
                "cwe": "CWE-639",
                "hypothesis_id_prefix": "ARCH-HYP-T",
                "weak_or_missing_controls": ["Object authorization"],
                "positive_signals": {"any_pattern": ["POS"]},
            }
        ],
    }

    out = acc.run(tmp_path, None, rules)

    assert out["threat_hypotheses"][0]["hypothesis_id"] == "ARCH-HYP-T-001"
    assert out["control_assessments"][0]["hypothesis_ids"] == ["ARCH-HYP-T-001"]


# ---------------------------------------------------------------------------
# Inventory-flag hypotheses — ARCH-BOLA-001 / ARCH-AUTHN-001
# (consume route_inventory.py missing_authz_suspect / missing_auth_suspect)
# ---------------------------------------------------------------------------


def test_bola_rule_fires_on_missing_authz_suspect(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "app.ts").write_text(
        "const app = express();\n"
        "app.use('/api/orders', security.isAuthorized());\n"
        "app.get('/api/orders/:id', getOrder);\n"
        "app.delete('/api/orders/:id', delOrder);\n"
    )
    _build_inventory(repo, out)
    res = _run_engine(repo, out)
    v = _verdict(res, "ARCH-BOLA-001")
    assert v["applies"] is True
    assert v["status"] == "weak"
    assert v["decision"] == "emit_hypothesis_only"
    hyps = [h for h in res["threat_hypotheses"] if h["rule_id"] == "ARCH-BOLA-001"]
    assert hyps and hyps[0]["proof_state"] != "confirmed"


def test_bola_rule_silent_when_authz_present(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "app.ts").write_text(
        "const app = express();\n"
        "app.use('/api/orders', security.isAuthorized());\n"
        "app.use('/api/orders', requireRole('user'));\n"
        "app.get('/api/orders/:id', getOrder);\n"
    )
    _build_inventory(repo, out)
    v = _verdict(_run_engine(repo, out), "ARCH-BOLA-001")
    assert v["status"] == "present"  # applies, but no suspects → no hypothesis


def test_authn_rule_fires_on_missing_auth_suspect(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "app.ts").write_text("const app = express();\napp.post('/api/admin/users', createUser);\n")
    _build_inventory(repo, out)
    res = _run_engine(repo, out)
    v = _verdict(res, "ARCH-AUTHN-001")
    assert v["applies"] is True
    assert v["status"] == "weak"
    assert v["decision"] == "emit_hypothesis_only"


def test_inventory_flag_rules_not_applicable_without_inventory(tmp_path: Path) -> None:
    """No .route-inventory.json → graceful not_applicable, no crash."""
    res = _run_engine(tmp_path)  # no output_dir → no inventory loaded
    for rid in ("ARCH-BOLA-001", "ARCH-AUTHN-001"):
        v = _verdict(res, rid)
        assert v["applies"] is False
        assert v["status"] == "not_applicable"


def test_inventory_flag_rule_direct_branches() -> None:
    rule = _compiled_rule(inventory_pattern={})
    assert "route_flag" in acc._evaluate_inventory_flag_rule(rule, {"routes": []})["skip_reason"]

    rule = _compiled_rule(inventory_pattern={"route_flag": "missing_auth_suspect", "min_routes": 2})
    inv = {
        "routes": [
            {
                "missing_auth_suspect": True,
                "method": "POST",
                "path": "/admin",
                "authn_signal": "unknown",
                "authz_signal": "unknown",
                "handler_file": "app.ts",
                "handler_line": 5,
            }
        ]
    }
    assert acc._evaluate_inventory_flag_rule(rule, inv)["status"] == "present"


def test_generic_hard_rule_precondition_exculpatory_and_anti_pattern_branches(tmp_path: Path) -> None:
    pre_rule = _compiled_rule(precondition_patterns=[acc.re.compile("PRE")], positive_patterns=[acc.re.compile("POS")])
    assert acc._evaluate_hard_rule(pre_rule, tmp_path, None)["skip_reason"] == "no precondition signal in repo"

    (tmp_path / "app.ts").write_text("PRE\nSAFE\n", encoding="utf-8")
    exculpatory_rule = _compiled_rule(
        precondition_patterns=[acc.re.compile("PRE")],
        positive_patterns=[acc.re.compile("POS")],
        exculpatory_patterns=[acc.re.compile("SAFE")],
    )
    verdict = acc._evaluate_hard_rule(exculpatory_rule, tmp_path, None)
    assert verdict["status"] == "present"
    assert verdict["confidence"] == "medium"

    (tmp_path / "app.ts").write_text("PRE\nSAFE\nPOS\n", encoding="utf-8")
    anti_rule = _compiled_rule(
        output="anti_pattern_candidate",
        precondition_patterns=[acc.re.compile("PRE")],
        positive_patterns=[acc.re.compile("POS")],
        exculpatory_patterns=[acc.re.compile("SAFE")],
    )
    verdict = acc._evaluate_hard_rule(anti_rule, tmp_path, None)
    assert verdict["status"] == "weak"
    assert verdict["confidence"] == "medium"


def test_generic_hypothesis_rule_precondition_exculpatory_and_positive_branches(tmp_path: Path) -> None:
    pre_rule = _compiled_rule(family="hypothesis", precondition_patterns=[acc.re.compile("PRE")])
    assert acc._evaluate_hypothesis_rule(pre_rule, tmp_path, None)["skip_reason"] == "no precondition signal in repo"

    (tmp_path / "app.ts").write_text("PRE\nSAFE\n", encoding="utf-8")
    exculpatory_rule = _compiled_rule(
        family="hypothesis",
        precondition_patterns=[acc.re.compile("PRE")],
        positive_patterns=[acc.re.compile("POS")],
        exculpatory_patterns=[acc.re.compile("SAFE")],
    )
    assert acc._evaluate_hypothesis_rule(exculpatory_rule, tmp_path, None)["status"] == "present"

    (tmp_path / "app.ts").write_text("PRE\nSAFE\nPOS\n", encoding="utf-8")
    verdict = acc._evaluate_hypothesis_rule(exculpatory_rule, tmp_path, None)
    assert verdict["status"] == "partial"
    assert verdict["confidence"] == "low"


def test_decision_helpers_cover_unknown_statuses() -> None:
    rule = _compiled_rule(output="anti_pattern_candidate")
    assert (
        acc._decision_for_hard(rule, {"applies": True, "status": "anti_pattern"}) == "emit_control_and_threat_candidate"
    )
    assert acc._decision_for_hard(rule, {"applies": True, "status": "other"}) == "no_action"
    assert acc._decision_for_hypothesis(rule, {"applies": False, "status": "weak"}) == "no_action"
    assert acc._decision_for_hypothesis(rule, {"applies": True, "status": "present"}) == "emit_control_only"
