"""Tests for scripts/architecture_coverage_checks.py (arch.md §Erste Lieferung)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest


REPO_ROOT = Path(__file__).parent.parent
ENGINE = REPO_ROOT / "scripts" / "architecture_coverage_checks.py"
ROUTE_INV = REPO_ROOT / "scripts" / "route_inventory.py"
SCHEMA = json.loads((REPO_ROOT / "schemas" / "architecture-coverage.schema.json").read_text())

ALL_RULE_IDS = {
    "ARCH-COOKIE-001", "ARCH-CORS-001", "ARCH-JWT-001",
    "ARCH-TLS-001", "ARCH-MGMT-001",
    "ARCH-XSS-001", "ARCH-SQLI-001", "ARCH-AUTHZ-001", "ARCH-INPUT-001",
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
        [sys.executable, str(ROUTE_INV), "--repo-root", str(repo),
         "--output-dir", str(output_dir)],
        check=True, capture_output=True, text=True,
    )


def _verdict(out: dict, rule_id: str) -> dict:
    matches = [r for r in out["rules_evaluated"] if r["rule_id"] == rule_id]
    assert matches, f"{rule_id} missing from rules_evaluated[]"
    return matches[0]


# ---------------------------------------------------------------------------
# Contract: every rule must be evaluated
# ---------------------------------------------------------------------------


def test_every_rule_appears_in_rules_evaluated(tmp_path: Path) -> None:
    out = _run_engine(tmp_path)
    seen = {r["rule_id"] for r in out["rules_evaluated"]}
    assert seen == ALL_RULE_IDS


def test_output_validates_against_schema(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text(
        "app.use(cors({origin:'*', credentials:true}));\n"
        "const dsn = 'postgres://u:p@h/db?sslmode=disable';\n"
    )
    out = _run_engine(tmp_path)
    jsonschema.validate(out, SCHEMA)


# ---------------------------------------------------------------------------
# CORS — ARCH-CORS-001
# ---------------------------------------------------------------------------


def test_cors_wildcard_with_credentials_anti_pattern(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "app.use(cors({\n"
        "  origin: '*',\n"
        "  credentials: true,\n"
        "}));\n"
    )
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
        "app.use(cors({\n"
        "  origin: 'https://app.example.com',\n"
        "  credentials: true,\n"
        "}));\n"
    )
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-CORS-001")
    assert v["status"] in {"present", "partial", "not_applicable"}
    ids = [c["rule_id"] for c in out["anti_pattern_candidates"]]
    assert "ARCH-CORS-001" not in ids


def test_cors_anti_pattern_has_severity_cap_not_critical(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "app.use(cors({ origin: '*', credentials: true }));\n"
    )
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
        "import jwt from 'jsonwebtoken';\n"
        "export function check(t){ return jwt.verify(t, 'secret'); }\n"
    )
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-JWT-001")
    assert v["applies"] is True
    assert v["status"] in {"weak", "anti_pattern"}


def test_jwt_with_algorithm_whitelist_present(tmp_path: Path) -> None:
    (tmp_path / "auth.ts").write_text(
        "import jwt from 'jsonwebtoken';\n"
        "jwt.verify(t, key, { algorithms: ['RS256'] });\n"
    )
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-JWT-001")
    assert v["status"] == "present"


def test_jwt_max_severity_high(tmp_path: Path) -> None:
    """Per critical-criteria.yaml CWE-347 individual cap is High."""
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        "data = jwt.decode(t, verify=False)\n"
    )
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-JWT-001")
    assert v["applies"]
    assert v["status"] != "anti_pattern" or out["anti_pattern_candidates"][0]["severity_cap"] != "Critical"


# ---------------------------------------------------------------------------
# Cleartext transport — ARCH-TLS-001
# ---------------------------------------------------------------------------


def test_tls_sslmode_disable_anti_pattern(tmp_path: Path) -> None:
    (tmp_path / "db.ts").write_text(
        "export const dsn = 'postgres://u:p@h/db?sslmode=disable';\n"
    )
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-TLS-001")
    assert v["status"] == "anti_pattern"
    ids = [c["rule_id"] for c in out["anti_pattern_candidates"]]
    assert "ARCH-TLS-001" in ids


def test_tls_localhost_http_is_not_finding(tmp_path: Path) -> None:
    (tmp_path / "dev.ts").write_text(
        "const local = 'http://localhost:3000/api';\n"
    )
    out = _run_engine(tmp_path)
    v = _verdict(out, "ARCH-TLS-001")
    assert v["status"] in {"present", "partial"}


# ---------------------------------------------------------------------------
# Cookie hardening — ARCH-COOKIE-001
# ---------------------------------------------------------------------------


def test_cookie_httponly_false_is_weak(tmp_path: Path) -> None:
    (tmp_path / "session.ts").write_text(
        "app.use(session({ secret:'x', cookie:{ httpOnly:false, secure:false } }));\n"
    )
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
        "const router = express.Router();\n"
        "router.use(requireAuth);\n"
        "router.get('/admin/users', h);\n"
    )
    _build_inventory(tmp_path, out_dir)
    out = _run_engine(tmp_path, out_dir)
    v = _verdict(out, "ARCH-MGMT-001")
    assert v["status"] in {"present", "partial"}


def test_mgmt_route_unknown_authn_does_not_escalate(tmp_path: Path) -> None:
    """arch.md §Pipeline-Integration Punkt 8: unknown MUST NOT escalate."""
    out_dir = tmp_path / "out"
    (tmp_path / "app.ts").write_text(
        "const app = express();\n"
        "app.get('/admin/users', h);\n"   # no nearby middleware → authn=unknown
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
        "const q = 'SELECT * FROM users WHERE id = ' + req.params.id;\n"
        "await db.query(q);\n"
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
    """arch.md: keine zentrale AuthZ-Bibliothek ist nicht automatisch BAC.
    Without ANY authenticated route, the hypothesis precondition is not met."""
    out_dir = tmp_path / "out"
    (tmp_path / "app.ts").write_text(
        "const app = express();\n"
        "app.get('/public', h);\n"
        "app.delete('/items/:id', h);\n"
    )
    _build_inventory(tmp_path, out_dir)
    out = _run_engine(tmp_path, out_dir)
    v = _verdict(out, "ARCH-AUTHZ-001")
    assert v["applies"] is False


def test_authz_hypothesis_weak_when_sensitive_method_lacks_authz(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    (tmp_path / "app.ts").write_text(
        "const router = express.Router();\n"
        "router.use(requireAuth);\n"     # authn middleware
        "router.delete('/items/:id', h);\n"  # sensitive, no authz signal
    )
    _build_inventory(tmp_path, out_dir)
    out = _run_engine(tmp_path, out_dir)
    v = _verdict(out, "ARCH-AUTHZ-001")
    assert v["applies"] is True
    assert v["status"] == "weak"


# ---------------------------------------------------------------------------
# Hypothesis semantics — never confirmed, never CVSS, never Critical
# ---------------------------------------------------------------------------


def test_no_hypothesis_carries_proof_state_confirmed(tmp_path: Path) -> None:
    (tmp_path / "x.ts").write_text(
        "element.innerHTML = req.query.name;\n"
        "const q = 'SELECT * WHERE u = ' + req.body.u;\n"
        "db.query(q);\n"
    )
    out = _run_engine(tmp_path)
    for h in out["threat_hypotheses"]:
        assert h["proof_state"] in {"control-derived", "evidence-backed"}
        assert h["proof_state"] != "confirmed"


def test_anti_pattern_candidates_never_critical(tmp_path: Path) -> None:
    (tmp_path / "x.ts").write_text(
        "app.use(cors({ origin:'*', credentials:true }));\n"
        "const dsn='postgres://u:p@h/db?sslmode=disable';\n"
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
