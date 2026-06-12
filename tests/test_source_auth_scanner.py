"""Tests for scripts/source_auth_scanner.py (deterministic broken-access-control
scanner, data/source-auth-checks.yaml → AUTHZ-001..008) and its wiring.

The scanner produces `.source-auth-findings.json`, ingested by
`merge_threats.py:_load_source_auth_findings`. The producer is run by the
skill-level pre-pass in SKILL-impl.md; before 2026-06 it was authored,
schema-validated, and ingested end-to-end but never actually invoked, so the
eight high-precision authz checks were dead. The wiring-guard test below exists
to stop that regression recurring.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "source_auth_scanner.py"
CHECKS = REPO_ROOT / "data" / "source-auth-checks.yaml"
SKILL_IMPL = REPO_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"
SCHEMA = REPO_ROOT / "schemas" / "source-auth-findings.schema.yaml"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import source_auth_scanner as S  # noqa: E402


def _scan(tmp_path: Path) -> list:
    checks = S.load_checks(CHECKS)
    return S.scan_repo(tmp_path, checks)


def _ids(findings) -> set[str]:
    return {f.check_id for f in findings}


# ---------------------------------------------------------------------------
# Functional detection
# ---------------------------------------------------------------------------


def test_authz001_bola_attacker_controlled_owner_id(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes/order.ts").write_text(
        "export function getOrder(req, res) {\n  return Order.findAll({ where: { UserId: req.body.userId } });\n}\n"
    )
    assert "AUTHZ-001" in _ids(_scan(tmp_path))


def test_authz001_suppressed_by_session_identity(tmp_path: Path) -> None:
    """req.user.id within the forward counter window proves session-derived identity.

    The counter window scans the match line forward (data/source-auth-checks.yaml:
    "counter_window — lines AFTER match"), so the ownership proof must follow.
    """
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes/order.ts").write_text(
        "export function getOrder(req, res) {\n"
        "  const rows = Order.findAll({ where: { UserId: req.body.userId } });\n"
        "  return requireOwnership(rows, req.user.id);\n"
        "}\n"
    )
    assert "AUTHZ-001" not in _ids(_scan(tmp_path))


def test_authz003_mass_assignment_privileged_field(tmp_path: Path) -> None:
    (tmp_path / "user.js").write_text(
        "function register(req, res) {\n"
        "  const role = req.body.role;\n"
        "  return User.create({ email: req.body.email, role });\n"
        "}\n"
    )
    assert "AUTHZ-003" in _ids(_scan(tmp_path))


def test_authz003_suppressed_by_allowlist(tmp_path: Path) -> None:
    """A privilege-field strip in the forward window suppresses the finding."""
    (tmp_path / "user.js").write_text(
        "function register(req, res) {\n"
        "  const role = req.body.role;\n"
        "  delete req.body.role;\n"
        "  return User.create(_.pick(req.body, ['email', 'password']));\n"
        "}\n"
    )
    assert "AUTHZ-003" not in _ids(_scan(tmp_path))


def test_authz008_sensitive_route_without_auth(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text("const app = express();\napp.post('/api/Users', createUser);\n")
    assert "AUTHZ-008" in _ids(_scan(tmp_path))


def test_authz008_suppressed_by_auth_middleware(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text("const app = express();\napp.post('/api/Users', isAuthorized(), createUser);\n")
    assert "AUTHZ-008" not in _ids(_scan(tmp_path))


def test_test_files_are_excluded(tmp_path: Path) -> None:
    (tmp_path / "order.spec.ts").write_text(
        "it('rejects BOLA', () => {\n  Order.findAll({ where: { UserId: req.body.userId } });\n});\n"
    )
    assert _scan(tmp_path) == []


# ---------------------------------------------------------------------------
# Sidecar schema + ingest wiring
# ---------------------------------------------------------------------------


def test_emitted_sidecar_validates_against_schema(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    (repo / "routes").mkdir(parents=True)
    (repo / "routes/order.ts").write_text(
        "export function getOrder(req, res) {\n  return Order.findAll({ where: { UserId: req.body.userId } });\n}\n"
    )
    out.mkdir()
    rc = subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(repo), "--output-dir", str(out), "--quiet"],
        capture_output=True,
        text=True,
    ).returncode
    assert rc == 0
    sidecar = out / ".source-auth-findings.json"
    assert sidecar.is_file()
    rc2 = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "validate_intermediate.py"), "source_auth_findings", str(sidecar)],
        capture_output=True,
        text=True,
    ).returncode
    assert rc2 == 0


def test_merge_threats_ingests_findings(tmp_path: Path) -> None:
    """The producer↔consumer contract: a sidecar on disk becomes merged threats."""
    import merge_threats as M

    repo = tmp_path / "repo"
    out = tmp_path / "out"
    (repo).mkdir()
    (repo / "user.js").write_text(
        "function register(req, res) {\n  const role = req.body.role;\n  return User.create({ role });\n}\n"
    )
    out.mkdir()
    subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(repo), "--output-dir", str(out), "--quiet"],
        check=True,
    )
    threats = M._load_source_auth_findings(out)
    assert threats, "ingest produced no threats from a non-empty sidecar"
    t = threats[0]
    assert t.get("cwe") and t.get("title") and t.get("evidence")


def test_no_sidecar_is_non_fatal(tmp_path: Path) -> None:
    import merge_threats as M

    assert M._load_source_auth_findings(tmp_path) == []


# ---------------------------------------------------------------------------
# Wiring guard — prevents the scanner from being orphaned again
# ---------------------------------------------------------------------------


def test_skill_impl_invokes_scanner_in_prepass() -> None:
    text = SKILL_IMPL.read_text(encoding="utf-8")
    assert "scripts/source_auth_scanner.py" in text, (
        "SKILL-impl.md must invoke source_auth_scanner.py in the deterministic "
        "pre-pass — otherwise .source-auth-findings.json is never produced and "
        "the AUTHZ-001..008 checks are dead (merge_threats only reads the file)."
    )
    # Must sit under the same DRY_RUN/RERENDER guard as the route-inventory pre-pass.
    assert "SOURCE_AUTH_PREPASS" in text


def test_all_eight_checks_load() -> None:
    checks = S.load_checks(CHECKS)
    assert {c.id for c in checks} >= {f"AUTHZ-00{n}" for n in range(1, 9)}


# ---------------------------------------------------------------------------
# Multi-language checks (P2): Python + Java
# ---------------------------------------------------------------------------


def test_authz101_python_privileged_field_mass_assignment(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def update_profile(request):\n"
        "    is_staff = request.data['is_staff']\n"
        "    user.is_staff = is_staff\n"
        "    user.save()\n"
    )
    findings = _scan(tmp_path)
    assert "AUTHZ-101" in _ids(findings)
    assert findings[0].source_type == "python_source"


def test_authz101_suppressed_by_serializer(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def update_profile(request):\n"
        "    role = request.data.get('role')\n"
        "    serializer.is_valid(raise_exception=True)\n"
        "    serializer.save()\n"
    )
    assert "AUTHZ-101" not in _ids(_scan(tmp_path))


def test_authz102_python_whole_body_spread(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text("def create_user(request):\n    return User.objects.create(**request.data)\n")
    assert "AUTHZ-102" in _ids(_scan(tmp_path))


def test_authz103_pyjwt_missing_algorithms(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text("import jwt\ndef who(token):\n    return jwt.decode(token, SECRET)\n")
    assert "AUTHZ-103" in _ids(_scan(tmp_path))


def test_authz103_pyjwt_with_algorithms_suppressed(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import jwt\ndef who(token):\n    return jwt.decode(token, SECRET, algorithms=['RS256'])\n"
    )
    assert "AUTHZ-103" not in _ids(_scan(tmp_path))


def test_authz201_java_unsigned_jwt(tmp_path: Path) -> None:
    (tmp_path / "Auth.java").write_text(
        "public Claims parse(String t) {\n  return Jwts.parser().parseClaimsJwt(t).getBody();\n}\n"
    )
    findings = _scan(tmp_path)
    assert "AUTHZ-201" in _ids(findings)
    assert findings[0].source_type == "java_source"


def test_java_signed_jws_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "Auth.java").write_text(
        "public Claims parse(String t) {\n  return Jwts.parser().setSigningKey(k).parseClaimsJws(t).getBody();\n}\n"
    )
    assert "AUTHZ-201" not in _ids(_scan(tmp_path))


def test_python_test_files_excluded(tmp_path: Path) -> None:
    (tmp_path / "test_views.py").write_text("def test_x(request):\n    User.objects.create(**request.data)\n")
    assert _scan(tmp_path) == []
