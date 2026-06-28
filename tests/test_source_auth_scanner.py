"""Tests for scripts/source_auth_scanner.py (deterministic broken-access-control
+ injection scanner, data/source-auth-checks.yaml → AUTHZ-001..102 + INJ-001..003)
and its wiring.

The scanner produces `.source-auth-findings.json`, ingested by
`merge_threats.py:_load_source_auth_findings`. The producer is run by the
skill-level pre-pass in SKILL-impl.md; before 2026-06 it was authored,
schema-validated, and ingested end-to-end but never actually invoked, so the
eight high-precision authz checks were dead. The wiring-guard test below exists
to stop that regression recurring.
"""

from __future__ import annotations

import json
import re
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


def _check(
    *,
    cid: str = "TEST-001",
    file_patterns: list[str] | None = None,
    exclude_file_patterns: list[str] | None = None,
    pattern: str = "BAD",
    counter_scope: str = "window",
    counter_patterns: list[str] | None = None,
) -> S.Check:
    return S.Check(
        id=cid,
        name="Test authorization check",
        description="",
        file_patterns=file_patterns or ["**/*.js"],
        exclude_file_patterns=exclude_file_patterns or [],
        pattern=re.compile(pattern),
        counter_scope=counter_scope,
        counter_window=3,
        counter_patterns=[re.compile(p) for p in (counter_patterns or [])],
        severity_if_violated="High",
        cwe="CWE-862",
        finding_type="missing-authz",
        breach_vector="internet-anon",
        rationale="test rationale",
        remediation="fix it",
    )


def _checks_yaml(**overrides) -> str:
    fields = {
        "id": "TEST-001",
        "name": "Test authorization check",
        "file_patterns": ["**/*.js"],
        "pattern": "BAD",
        "counter_scope": "window",
        "counter_patterns": [],
        "severity_if_violated": "High",
        "cwe": "CWE-862",
        "finding_type": "missing-authz",
        "breach_vector": "internet-anon",
        "rationale": "test rationale",
        "remediation": "fix it",
    }
    fields.update(overrides)
    lines = ["checks:", "-"]
    for key, value in fields.items():
        lines.append(f"  {key}: {json.dumps(value)}")
    return "\n".join(lines) + "\n"


def _write_checks(path: Path, **overrides) -> Path:
    path.write_text(_checks_yaml(**overrides), encoding="utf-8")
    return path


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


def test_authz003_does_not_skip_challenge_or_verify_named_source(tmp_path: Path) -> None:
    """Production source must not be hidden just because its filename is generic."""
    (tmp_path / "challengeHandler.ts").write_text(
        "export function updateChallenge(req, res) {\n"
        "  return Challenge.create({ name: req.body.name, role: req.body.role });\n"
        "}\n"
    )
    (tmp_path / "verifyUser.ts").write_text(
        "export function verifyUser(req, res) {\n"
        "  return User.update({ isAdmin: req.body.isAdmin }, { where: { id: req.body.id } });\n"
        "}\n"
    )
    assert "AUTHZ-003" in _ids(_scan(tmp_path))


def test_authz008_sensitive_route_without_auth(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text("const app = express();\napp.post('/api/Users', createUser);\n")
    assert "AUTHZ-008" in _ids(_scan(tmp_path))


def test_authz008_suppressed_by_auth_middleware(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text("const app = express();\napp.post('/api/Users', isAuthorized(), createUser);\n")
    assert "AUTHZ-008" not in _ids(_scan(tmp_path))


# ---------------------------------------------------------------------------
# Injection family (INJ-001 SQLi / INJ-002 cmdi / INJ-003 SSRF)
# ---------------------------------------------------------------------------


def test_inj001_sql_injection_interpolated_query(tmp_path: Path) -> None:
    (tmp_path / "login.js").write_text(
        "app.post('/login', async (req, res) => {\n"
        "  const sql = `SELECT id FROM users WHERE email = '${req.body.email}'`\n"
        "  return db.query(sql)\n"
        "})\n"
    )
    assert "INJ-001" in _ids(_scan(tmp_path))


def test_inj001_not_triggered_by_parameterized_query(tmp_path: Path) -> None:
    """A bound/placeholder query interpolates nothing into the SQL string."""
    (tmp_path / "login.js").write_text(
        "app.post('/login', async (req, res) => {\n"
        "  return db.query('SELECT id FROM users WHERE email = ?', [req.body.email])\n"
        "})\n"
    )
    assert "INJ-001" not in _ids(_scan(tmp_path))


def test_inj002_command_injection_interpolated_exec(tmp_path: Path) -> None:
    (tmp_path / "export.js").write_text(
        "app.post('/admin/export', (req, res) => {\n"
        "  exec(`tar -czf /tmp/out.tgz ${req.body.path}`, cb)\n"
        "})\n"
    )
    assert "INJ-002" in _ids(_scan(tmp_path))


def test_inj002_not_triggered_by_execfile_argv(tmp_path: Path) -> None:
    """execFile with an argv array runs no shell, so it must not match."""
    (tmp_path / "export.js").write_text(
        "app.post('/admin/export', (req, res) => {\n"
        "  execFile('tar', ['-czf', '/tmp/out.tgz', req.body.path], cb)\n"
        "})\n"
    )
    assert "INJ-002" not in _ids(_scan(tmp_path))


def test_inj003_ssrf_request_controlled_url(tmp_path: Path) -> None:
    (tmp_path / "webhook.js").write_text(
        "app.post('/webhooks/preview', async (req, res) => {\n"
        "  const r = await fetch(req.body.url)\n"
        "  res.json(await r.json())\n"
        "})\n"
    )
    assert "INJ-003" in _ids(_scan(tmp_path))


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


def test_main_rejects_invalid_repo_and_missing_output_dir(tmp_path: Path, capsys) -> None:
    assert S.main(["--repo-root", str(tmp_path / "missing"), "--dry-run"]) == 2
    assert "is not a directory" in capsys.readouterr().err

    repo = tmp_path / "repo"
    repo.mkdir()
    assert S.main(["--repo-root", str(repo), "--checks", str(CHECKS)]) == 2
    assert "--output-dir is required" in capsys.readouterr().err


def test_main_rejects_unresolved_or_missing_checks(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    monkeypatch.setattr(S, "_discover_plugin_root", lambda: None)
    assert S.main(["--repo-root", str(repo), "--dry-run"]) == 2
    assert "cannot resolve plugin root" in capsys.readouterr().err

    assert S.main(["--repo-root", str(repo), "--checks", str(tmp_path / "missing.yaml"), "--dry-run"]) == 2
    assert "checks file" in capsys.readouterr().err


def test_main_rejects_bad_checks_file(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    bad_checks = tmp_path / "bad-checks.yaml"
    _write_checks(bad_checks, pattern="[")

    assert S.main(["--repo-root", str(repo), "--checks", str(bad_checks), "--dry-run"]) == 2

    assert "failed to load checks" in capsys.readouterr().err


def test_main_dry_run_prints_findings_and_summary(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("BAD\n", encoding="utf-8")
    checks = _write_checks(tmp_path / "checks.yaml")

    assert S.main(["--repo-root", str(repo), "--checks", str(checks), "--dry-run"]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)[0]["check_id"] == "TEST-001"
    assert "1 finding(s) across 1 check(s)" in captured.err


def test_main_writes_sidecar_and_non_quiet_tally(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "app.js").write_text("BAD\n", encoding="utf-8")
    checks = _write_checks(tmp_path / "checks.yaml")

    assert S.main(["--repo-root", str(repo), "--output-dir", str(out), "--checks", str(checks)]) == 0

    captured = capsys.readouterr()
    assert (out / ".source-auth-findings.json").is_file()
    assert "wrote" in captured.err
    assert "TEST-001" in captured.err


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


def test_load_checks_rejects_invalid_contracts(tmp_path: Path) -> None:
    bad_root = tmp_path / "bad-root.yaml"
    bad_root.write_text("not_checks: []\n", encoding="utf-8")
    try:
        S.load_checks(bad_root)
    except ValueError as exc:
        assert "top-level `checks:`" in str(exc)
    else:  # pragma: no cover - defensive assertion style for clearer failure
        raise AssertionError("invalid root was accepted")

    missing_id = tmp_path / "missing-id.yaml"
    _write_checks(missing_id, id="")
    try:
        S.load_checks(missing_id)
    except ValueError as exc:
        assert "missing id" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("check without id was accepted")

    bad_scope = tmp_path / "bad-scope.yaml"
    _write_checks(bad_scope, counter_scope="project")
    try:
        S.load_checks(bad_scope)
    except ValueError as exc:
        assert "counter_scope" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("invalid scope was accepted")

    bad_regex = tmp_path / "bad-regex.yaml"
    _write_checks(bad_regex, pattern="[")
    try:
        S.load_checks(bad_regex)
    except ValueError as exc:
        assert "invalid regex" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("invalid regex was accepted")

    missing_name = tmp_path / "missing-name.yaml"
    missing_name.write_text(
        _checks_yaml().replace('  name: "Test authorization check"\n', ""),
        encoding="utf-8",
    )
    try:
        S.load_checks(missing_name)
    except ValueError as exc:
        assert "missing required field" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("missing required field was accepted")


def test_glob_matcher_handles_braces_question_and_char_classes() -> None:
    assert S._matches_any_glob("src/foo.js", ["src/{foo,bar}.js"])
    assert S._matches_any_glob("src/Auth.ts", ["src/[A-Z]uth.t?"])
    assert S._matches_any_glob("src/{oops.js", ["src/{oops.js"])
    assert S._matches_any_glob("src/file[.js", ["src/file[.js"])
    assert not S._matches_any_glob("src/baz.js", ["src/{foo,bar}.js"])


def test_call_scope_without_closing_paren_returns_capped_window() -> None:
    assert S._scope_lines_for_call(["guard(", "  req.body.userId", "  more"], 0, 2) == [
        "guard(",
        "  req.body.userId",
        "  more",
    ]


def test_evidence_snippet_truncates_long_lines() -> None:
    snippet = S._evidence_snippet(["x" * 250], 0)
    assert "..." in snippet
    assert len(snippet.split(": ", 1)[1]) == 200


def test_scan_file_skips_large_missing_and_empty_files(tmp_path: Path, monkeypatch) -> None:
    check = _check()
    big = tmp_path / "big.js"
    big.write_text("BAD\n", encoding="utf-8")
    monkeypatch.setattr(S, "_MAX_FILE_BYTES", 1)
    assert S.scan_file(big, "big.js", [check]) == []

    assert S.scan_file(tmp_path / "missing.js", "missing.js", [check]) == []

    empty = tmp_path / "empty.js"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setattr(S, "_MAX_FILE_BYTES", 1_500_000)
    assert S.scan_file(empty, "empty.js", [check]) == []


def test_scan_repo_skips_outside_and_universally_excluded_paths(tmp_path: Path, monkeypatch) -> None:
    excluded = tmp_path / "node_modules" / "pkg" / "bad.js"
    excluded.parent.mkdir(parents=True)
    excluded.write_text("BAD\n", encoding="utf-8")
    outside = tmp_path.parent / "outside.js"
    outside.write_text("BAD\n", encoding="utf-8")
    normal = tmp_path / "src" / "bad.js"
    normal.parent.mkdir()
    normal.write_text("BAD\n", encoding="utf-8")

    monkeypatch.setattr(S, "_walk_repo", lambda _repo_root: iter([outside, excluded, normal]))

    findings = S.scan_repo(tmp_path, [_check()])

    assert [f.file for f in findings] == ["src/bad.js"]


def test_discover_plugin_root_prefers_env_and_returns_none_when_unresolved(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
    assert S._discover_plugin_root() == tmp_path

    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT")
    script = tmp_path / "elsewhere" / "scripts" / "source_auth_scanner.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")
    monkeypatch.setattr(S, "__file__", str(script))
    assert S._discover_plugin_root() is None


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
