"""Tests for the deterministic access-control, injection, and direct LLM-flow
checks in scripts/source_auth_scanner.py and their pipeline wiring.

The scanner produces `.source-auth-findings.json`, ingested by
`merge_threats.py:_load_source_auth_findings`. The producer is run by the
controller pre-pass; before 2026-06 it was authored,
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

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "source_auth_scanner.py"
CHECKS = REPO_ROOT / "data" / "source-auth-checks.yaml"
CONTROLLER = REPO_ROOT / "scripts" / "orchestration_controller.py"
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
        required_context_patterns=[],
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


def test_required_context_pattern_gates_ambiguous_syntax(tmp_path: Path) -> None:
    """A rule can require a local security purpose before it emits a finding."""
    check_path = _write_checks(
        tmp_path / "checks.yaml",
        pattern="HASH\\(md5\\)",
        required_context_patterns=["(?i)password"],
    )
    checks = S.load_checks(check_path)
    (tmp_path / "plain.js").write_text("const value = HASH(md5);\n", encoding="utf-8")
    (tmp_path / "password.js").write_text("const passwordDigest = HASH(md5);\n", encoding="utf-8")

    findings = S.scan_repo(tmp_path, checks)
    assert [(f.file, f.check_id) for f in findings] == [("password.js", "TEST-001")]


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


def test_inj001_not_triggered_by_log_string_with_dml_word(tmp_path: Path) -> None:
    """Log/error strings that merely contain the English word insert/update/
    delete plus a ${...} interpolation are not SQL. The bare-DML-verb form of
    the pattern flagged these (17 Critical FPs on juice-shop's data seeder);
    requiring full clause structure (INSERT INTO / DELETE FROM / ...) fixes it.
    """
    (tmp_path / "datacreator.js").write_text(
        "async function seed() {\n"
        "  try { await Model.bulkCreate(rows) }\n"
        "  catch (err) { logger.error(`Could not bulk insert Challenges: ${err}`) }\n"
        "  logger.error(`Could not perform soft delete for the user ${userId}`)\n"
        "}\n"
    )
    assert "INJ-001" not in _ids(_scan(tmp_path))


def test_served_codefixes_snippets_are_excluded(tmp_path: Path) -> None:
    """Intentionally-vulnerable coding-challenge snippets under codefixes/ are
    stored as data and rendered as text (never executed), so the deterministic
    source scan — which cannot judge reachability — must not mine them for
    Critical injection findings even though they carry real interpolated SQL.
    """
    d = tmp_path / "data" / "static" / "codefixes"
    d.mkdir(parents=True)
    (d / "loginAdminChallenge_1.js").write_text(
        "function login(req) {\n  return db.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)\n}\n"
    )
    assert "INJ-001" not in _ids(_scan(tmp_path))


def test_inj002_command_injection_interpolated_exec(tmp_path: Path) -> None:
    (tmp_path / "export.js").write_text(
        "app.post('/admin/export', (req, res) => {\n  exec(`tar -czf /tmp/out.tgz ${req.body.path}`, cb)\n})\n"
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
# Direct LLM-output handling (LLM05 / LLM06)
# ---------------------------------------------------------------------------


def _llm_js(body: str) -> str:
    return (
        'import OpenAI from "openai";\n'
        "const completion = await client.chat.completions.create({ model: 'gpt-4o', messages });\n"
        "const modelText = completion.choices[0].message.content;\n"
        f"{body}"
    )


def test_llm_structured_output_without_schema_is_detected(tmp_path: Path) -> None:
    (tmp_path / "decision.ts").write_text(
        _llm_js("const decision = JSON.parse(modelText);\nreturn applyDecision(decision.action, decision.score);\n"),
        encoding="utf-8",
    )

    findings = _scan(tmp_path)

    finding = next(f for f in findings if f.check_id == "INJ-LLM-001")
    assert finding.line == 4
    assert finding.cwe == ["CWE-20"]
    assert finding.title == "Improper LLM Output Validation (decision.ts:4)"


def test_direct_nested_llm_structured_output_is_detected(tmp_path: Path) -> None:
    (tmp_path / "direct-decision.ts").write_text(
        "import { llm } from './model';\n"
        "const decision = JSON.parse((await llm.invoke(prompt)).content);\n"
        "return applyDecision(decision.action);\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-001" in _ids(_scan(tmp_path))


def test_llm_structured_output_with_closed_schema_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "decision.ts").write_text(
        "const DecisionSchema = z.object({\n"
        "  action: z.enum(['read', 'summarize']),\n"
        "  score: z.number().min(0).max(100),\n"
        "  objectId: z.string().uuid(),\n"
        "}).strict();\n"
        + _llm_js(
            "const rawDecision = JSON.parse(modelText);\n"
            "const decision = DecisionSchema.parse(rawDecision);\n"
            "return applyDecision(decision.action, decision.score);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-001" not in _ids(_scan(tmp_path))


def test_llm_structured_output_with_permissive_schema_stays_flagged(tmp_path: Path) -> None:
    (tmp_path / "decision.ts").write_text(
        _llm_js(
            "const rawDecision = JSON.parse(modelText);\n"
            "const decision = DecisionSchema.parse(rawDecision);\n"
            "return applyDecision(decision.action, decision.score);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-001" in _ids(_scan(tmp_path))


@pytest.mark.parametrize(
    "schema",
    [
        "const DecisionSchema = z.object({ action: z.enum(['read']), score: z.number().min(0) });",
        "const DecisionSchema = z.object({ action: z.string(), score: z.number().min(0) }).strict();",
    ],
)
def test_llm_structured_schema_requires_closure_and_enum_allowlist(tmp_path: Path, schema: str) -> None:
    (tmp_path / "decision.ts").write_text(
        schema
        + "\n"
        + _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const decision = DecisionSchema.parse(raw);\n"
            "return applyDecision(decision);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-001" in _ids(_scan(tmp_path))


def test_closed_python_schema_suppresses_structured_finding(tmp_path: Path) -> None:
    (tmp_path / "decision.py").write_text(
        "from typing import Literal\n"
        "from pydantic import BaseModel, ConfigDict, Field\n"
        "class Decision(BaseModel):\n"
        "    model_config = ConfigDict(extra='forbid')\n"
        "    action: Literal['read', 'summarize']\n"
        "    score: int = Field(ge=0, le=100)\n"
        "from openai import OpenAI\n"
        "completion = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
        "model_text = completion.choices[0].message.content\n"
        "raw = json.loads(model_text)\n"
        "decision = Decision.model_validate(raw)\n"
        "apply_decision(decision)\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-001" not in _ids(_scan(tmp_path))


def test_jsonschema_validation_suppresses_structured_finding(tmp_path: Path) -> None:
    (tmp_path / "decision.py").write_text(
        "DECISION_SCHEMA = {\n"
        "    'type': 'object',\n"
        "    'properties': {\n"
        "        'action': {'type': 'string', 'enum': ['read', 'summarize']},\n"
        "        'score': {'type': 'integer', 'minimum': 0, 'maximum': 100},\n"
        "    },\n"
        "    'additionalProperties': False,\n"
        "}\n"
        "from openai import OpenAI\n"
        "completion = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
        "model_text = completion.choices[0].message.content\n"
        "raw = json.loads(model_text)\n"
        "jsonschema.validate(raw, DECISION_SCHEMA)\n"
        "apply_decision(raw)\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-001" not in _ids(_scan(tmp_path))


def test_llm_structured_output_requires_all_manual_validation_dimensions(tmp_path: Path) -> None:
    partial = tmp_path / "partial.ts"
    partial.write_text(
        _llm_js(
            "const decision = JSON.parse(modelText);\n"
            "if (typeof decision.score !== 'number') throw new Error('bad');\n"
            "return applyDecision(decision.action, decision.score);\n"
        ),
        encoding="utf-8",
    )
    assert "INJ-LLM-001" in _ids(_scan(tmp_path))

    partial.write_text(
        _llm_js(
            "const decision = JSON.parse(modelText);\n"
            "if (typeof decision.score !== 'number') throw new Error('bad');\n"
            "if (decision.score < 0 || decision.score > 100) throw new Error('range');\n"
            "if (!allowedActions.includes(decision.action)) throw new Error('enum');\n"
            "return applyDecision(decision.action, decision.score);\n"
        ),
        encoding="utf-8",
    )
    assert "INJ-LLM-001" not in _ids(_scan(tmp_path))


def test_llm_structured_validation_after_first_use_is_too_late(tmp_path: Path) -> None:
    (tmp_path / "late-validation.ts").write_text(
        _llm_js(
            "const decision = JSON.parse(modelText);\n"
            "applyDecision(decision.action);\n"
            "DecisionSchema.parse(decision);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-001" in _ids(_scan(tmp_path))


def test_ignored_non_throwing_schema_predicate_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "ignored-safe-parse.ts").write_text(
        "const DecisionSchema = z.object({\n"
        "  action: z.enum(['read']),\n"
        "  score: z.number().min(0).max(100),\n"
        "}).strict();\n"
        + _llm_js(
            "const decision = JSON.parse(modelText);\n"
            "DecisionSchema.safeParse(decision);\n"
            "return applyDecision(decision.action);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-001" in _ids(_scan(tmp_path))


def test_schema_invocation_is_not_mistaken_for_a_schema_definition(tmp_path: Path) -> None:
    (tmp_path / "missing-schema.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const decision = DecisionSchema.parse(raw);\n"
            "const unrelated = { type: 'number', minimum: 0, enum: ['read'] };\n"
            "applyDecision(decision);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-001" in _ids(_scan(tmp_path))


def test_incomplete_schema_does_not_borrow_constraints_from_a_neighbor(tmp_path: Path) -> None:
    (tmp_path / "mixed-schemas.ts").write_text(
        "const DecisionSchema = z.object({ score: z.number() });\n"
        "const OtherSchema = z.object({ action: z.enum(['read']) }).strict().min(1);\n"
        + _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const decision = DecisionSchema.parse(raw);\n"
            "applyDecision(decision);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-001" in _ids(_scan(tmp_path))


def test_llm_output_to_html_and_markdown_raw_html_is_detected(tmp_path: Path) -> None:
    (tmp_path / "chat.ts").write_text(
        _llm_js("const rendered = marked.parse(modelText);\ncontainer.innerHTML = rendered;\n"),
        encoding="utf-8",
    )

    finding = next(f for f in _scan(tmp_path) if f.check_id == "INJ-LLM-002")

    assert finding.line == 5
    assert finding.cwe == ["CWE-79"]


def test_llm_output_sanitized_at_html_sink_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "chat.ts").write_text(
        _llm_js("container.innerHTML = DOMPurify.sanitize(marked.parse(modelText));\n"),
        encoding="utf-8",
    )

    assert "INJ-LLM-002" not in _ids(_scan(tmp_path))


def test_direct_model_output_sanitized_into_alias_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "chat.ts").write_text(
        "import { llm } from './model';\n"
        "const safe = DOMPurify.sanitize(\n"
        "  (await llm.invoke(prompt)).content,\n"
        ");\n"
        "container.innerHTML = safe;\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-002" not in _ids(_scan(tmp_path))


def test_unrelated_html_sanitizer_does_not_suppress_llm_sink(tmp_path: Path) -> None:
    (tmp_path / "chat.ts").write_text(
        _llm_js("const safeHelp = DOMPurify.sanitize(helpText);\ncontainer.innerHTML = modelText;\n"),
        encoding="utf-8",
    )

    assert "INJ-LLM-002" in _ids(_scan(tmp_path))


def test_html_sanitizer_after_sink_is_too_late(tmp_path: Path) -> None:
    (tmp_path / "chat.ts").write_text(
        _llm_js("container.innerHTML = modelText; DOMPurify.sanitize(modelText);\n"),
        encoding="utf-8",
    )

    assert "INJ-LLM-002" in _ids(_scan(tmp_path))


def test_static_html_sink_near_model_output_is_not_tainted(tmp_path: Path) -> None:
    (tmp_path / "chat.ts").write_text(
        _llm_js("container.innerHTML = '<p>Ready</p>';\nconsole.log(modelText);\n"),
        encoding="utf-8",
    )

    assert "INJ-LLM-002" not in _ids(_scan(tmp_path))


def test_static_html_sink_on_same_line_as_other_llm_use_is_not_tainted(tmp_path: Path) -> None:
    (tmp_path / "chat.ts").write_text(
        _llm_js("container.innerHTML = '<p>Ready</p>'; console.log(modelText);\n"),
        encoding="utf-8",
    )

    assert "INJ-LLM-002" not in _ids(_scan(tmp_path))


def test_llm_output_to_sql_shell_and_code_execution_is_detected(tmp_path: Path) -> None:
    (tmp_path / "agent.ts").write_text(
        _llm_js("db.query(modelText);\nexec(modelText);\neval(modelText);\n"),
        encoding="utf-8",
    )

    findings = [f for f in _scan(tmp_path) if f.check_id == "INJ-LLM-003"]

    assert {tuple(f.cwe) for f in findings} == {("CWE-89",), ("CWE-78",), ("CWE-94",)}


def test_direct_nested_llm_outputs_reach_each_sink_class(tmp_path: Path) -> None:
    (tmp_path / "direct-sinks.ts").write_text(
        "import { llm } from './model';\n"
        "panel.innerHTML = (await llm.invoke(prompt)).content;\n"
        "eval((await llm.invoke(prompt)).content);\n"
        "await fetch((await llm.invoke(prompt)).content);\n"
        "await executeTool((await llm.invoke(prompt)).content);\n",
        encoding="utf-8",
    )

    assert {
        "INJ-LLM-002",
        "INJ-LLM-003",
        "INJ-LLM-004",
        "AUTHZ-LLM-001",
    } <= _ids(_scan(tmp_path))


def test_unrelated_inline_sanitizer_does_not_hide_direct_model_output(tmp_path: Path) -> None:
    (tmp_path / "direct-html.ts").write_text(
        "import { llm } from './model';\n"
        "panel.innerHTML = DOMPurify.sanitize(helpText) + (await llm.invoke(prompt)).content;\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-002" in _ids(_scan(tmp_path))


def test_parameterized_sql_and_fixed_shell_free_process_are_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "agent.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const decision = DecisionSchema.parse(raw);\n"
            "await db.query('SELECT id FROM jobs WHERE id = ?', [decision.id]);\n"
            "execFile('/usr/bin/printf', ['%s', modelText]);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-003" not in _ids(_scan(tmp_path))


def test_python_fixed_shell_free_argv_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from openai import OpenAI\n"
        "completion = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
        "model_text = completion.choices[0].message.content\n"
        "subprocess.run(['/usr/bin/printf', '%s', model_text], check=True)\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-003" not in _ids(_scan(tmp_path))


@pytest.mark.parametrize(
    "argv",
    ["[f'{model_text}', '--version']", "['/usr/bin/' + model_text, '--version']"],
)
def test_python_model_selected_executable_in_argv_is_detected(tmp_path: Path, argv: str) -> None:
    (tmp_path / "agent.py").write_text(
        "from openai import OpenAI\n"
        "completion = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
        "model_text = completion.choices[0].message.content\n"
        f"subprocess.run({argv}, check=True)\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-003" in _ids(_scan(tmp_path))


def test_shell_mode_with_model_output_in_later_argument_is_detected(tmp_path: Path) -> None:
    (tmp_path / "agent.ts").write_text(
        _llm_js("spawn('/usr/bin/printf', ['%s', modelText], { shell: true });\n"),
        encoding="utf-8",
    )

    assert "INJ-LLM-003" in _ids(_scan(tmp_path))


@pytest.mark.parametrize(
    "process_call",
    [
        "execFile('/bin/sh', ['-c', modelText]);",
        "subprocess.run(['/usr/bin/python3', '-c', model_text], check=True)",
    ],
)
def test_fixed_interpreter_code_flag_with_model_program_is_detected(tmp_path: Path, process_call: str) -> None:
    suffix = ".py" if process_call.startswith("subprocess") else ".ts"
    source = (
        "from openai import OpenAI\n"
        "completion = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
        "model_text = completion.choices[0].message.content\n"
        if suffix == ".py"
        else _llm_js("")
    )
    (tmp_path / f"interpreter{suffix}").write_text(source + process_call + "\n", encoding="utf-8")

    assert "INJ-LLM-003" in _ids(_scan(tmp_path))


def test_javascript_compile_helper_is_not_treated_as_code_execution(tmp_path: Path) -> None:
    (tmp_path / "template.ts").write_text(_llm_js("compile(modelText);\n"), encoding="utf-8")

    assert "INJ-LLM-003" not in _ids(_scan(tmp_path))


def test_llm_selected_url_and_path_require_sink_specific_guards(tmp_path: Path) -> None:
    (tmp_path / "resources.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const request = RequestSchema.parse(raw);\n"
            "await fetch(request.url);\n"
            "await fs.readFile(request.path);\n"
        ),
        encoding="utf-8",
    )

    findings = [f for f in _scan(tmp_path) if f.check_id == "INJ-LLM-004"]

    assert {tuple(f.cwe) for f in findings} == {("CWE-918",), ("CWE-22",)}


def test_secondary_url_and_path_arguments_are_detected(tmp_path: Path) -> None:
    (tmp_path / "resources.py").write_text(
        "from openai import OpenAI\n"
        "completion = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
        "model_text = completion.choices[0].message.content\n"
        "requests.request('GET', model_text)\n",
        encoding="utf-8",
    )
    (tmp_path / "resources.ts").write_text(
        _llm_js("fs.rename('/srv/staging/file', modelText, callback);\n"),
        encoding="utf-8",
    )

    findings = [f for f in _scan(tmp_path) if f.check_id == "INJ-LLM-004"]

    assert {f.file for f in findings} == {"resources.py", "resources.ts"}


def test_llm_selected_url_and_path_with_guards_are_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "resources.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const request = RequestSchema.parse(raw);\n"
            "assertAllowedUrl(request.url);\n"
            "await fetch(request.url);\n"
            "const safePath = resolveContainedPath(request.path);\n"
            "await fs.readFile(safePath);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-004" not in _ids(_scan(tmp_path))


def test_unrelated_resource_guard_does_not_suppress_llm_url(tmp_path: Path) -> None:
    (tmp_path / "resources.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const request = RequestSchema.parse(raw);\n"
            "assertAllowedUrl(config.healthcheckUrl);\n"
            "await fetch(request.url);\n"
        ),
        encoding="utf-8",
    )

    assert "INJ-LLM-004" in _ids(_scan(tmp_path))


def test_resource_guard_after_sink_is_too_late(tmp_path: Path) -> None:
    (tmp_path / "resources.ts").write_text(
        _llm_js("await fetch(modelText); assertAllowedUrl(modelText);\n"),
        encoding="utf-8",
    )

    assert "INJ-LLM-004" in _ids(_scan(tmp_path))


def test_inline_resource_guard_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "resources.ts").write_text(
        _llm_js("await fetch(assertAllowedUrl(modelText));\n"),
        encoding="utf-8",
    )

    assert "INJ-LLM-004" not in _ids(_scan(tmp_path))


def test_inline_resource_guard_is_accepted_for_direct_model_call(tmp_path: Path) -> None:
    (tmp_path / "resources.ts").write_text(
        "import { llm } from './model';\nawait fetch(assertAllowedUrl((await llm.invoke(prompt)).content));\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-004" not in _ids(_scan(tmp_path))


def test_unrelated_inline_resource_guard_does_not_hide_direct_model_output(tmp_path: Path) -> None:
    (tmp_path / "resources.ts").write_text(
        "import { llm } from './model';\n"
        "await fetch(combine(assertAllowedUrl(config.healthcheckUrl), (await llm.invoke(prompt)).content));\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-004" in _ids(_scan(tmp_path))


def test_ignored_resource_predicate_does_not_suppress_llm_url(tmp_path: Path) -> None:
    (tmp_path / "resources.ts").write_text(
        _llm_js("isAllowedUrl(modelText);\nawait fetch(modelText);\n"),
        encoding="utf-8",
    )

    assert "INJ-LLM-004" in _ids(_scan(tmp_path))


def test_llm_selected_object_and_tool_require_authorization(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const action = ActionSchema.parse(raw);\n"
            "await Account.findByPk(action.objectId);\n"
            "await tools[action.tool](action.arguments);\n"
        ),
        encoding="utf-8",
    )

    findings = [f for f in _scan(tmp_path) if f.check_id == "AUTHZ-LLM-001"]

    assert len(findings) == 2
    assert all(f.cwe == ["CWE-862"] for f in findings)


def test_llm_selected_object_and_tool_with_allowlist_and_authz_are_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const action = ActionSchema.parse(raw);\n"
            "requireOwnership(req.user, action.objectId);\n"
            "await Account.findByPk(action.objectId);\n"
            "if (!allowedTools.includes(action.tool)) throw new Error('tool');\n"
            "authorize(req.user, action.tool);\n"
            "await tools[action.tool](action.arguments);\n"
        ),
        encoding="utf-8",
    )

    assert "AUTHZ-LLM-001" not in _ids(_scan(tmp_path))


def test_direct_tool_selection_with_inline_allowlist_and_authz_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(
        "import { llm } from './model';\n"
        "await executeTool(authorize(req.user, assertAllowedTool((await llm.invoke(prompt)).content)));\n",
        encoding="utf-8",
    )

    assert "AUTHZ-LLM-001" not in _ids(_scan(tmp_path))


def test_tool_authorization_without_action_allowlist_stays_flagged(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const action = ActionSchema.parse(raw);\n"
            "authorize(req.user, action.tool);\n"
            "await tools[action.tool](action.arguments);\n"
        ),
        encoding="utf-8",
    )

    assert "AUTHZ-LLM-001" in _ids(_scan(tmp_path))


def test_static_object_lookup_on_same_line_as_other_llm_use_is_not_tainted(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(
        _llm_js("await Account.findByPk(accountId); console.log(modelText);\n"),
        encoding="utf-8",
    )

    assert "AUTHZ-LLM-001" not in _ids(_scan(tmp_path))


def test_inline_owner_filter_authorizes_llm_selected_object(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const action = ActionSchema.parse(raw);\n"
            "await Account.findOne({ where: { id: action.objectId, ownerId: req.user.id } });\n"
        ),
        encoding="utf-8",
    )

    assert "AUTHZ-LLM-001" not in _ids(_scan(tmp_path))


def test_authorization_after_object_sink_is_too_late(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const action = ActionSchema.parse(raw);\n"
            "await Account.findByPk(action.objectId); authorize(req.user, action.objectId);\n"
        ),
        encoding="utf-8",
    )

    assert "AUTHZ-LLM-001" in _ids(_scan(tmp_path))


def test_unrelated_authorization_marker_does_not_suppress_llm_object(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const action = ActionSchema.parse(raw);\n"
            "const currentUserLabel = req.user.name;\n"
            "await Account.findByPk(action.objectId);\n"
        ),
        encoding="utf-8",
    )

    assert "AUTHZ-LLM-001" in _ids(_scan(tmp_path))


def test_identity_and_object_logging_does_not_count_as_authorization(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(
        _llm_js(
            "const action = JSON.parse(modelText);\n"
            "logger.info({ currentUser: req.user, objectId: action.objectId });\n"
            "await Account.findByPk(action.objectId);\n"
        ),
        encoding="utf-8",
    )

    assert "AUTHZ-LLM-001" in _ids(_scan(tmp_path))


def test_explicit_caller_role_gate_can_authorize_llm_selected_object(tmp_path: Path) -> None:
    (tmp_path / "admin-tools.ts").write_text(
        _llm_js(
            "const raw = JSON.parse(modelText);\n"
            "const action = ActionSchema.parse(raw);\n"
            "requireRole(req.user, 'account-admin');\n"
            "await Account.findByPk(action.objectId);\n"
        ),
        encoding="utf-8",
    )

    assert "AUTHZ-LLM-001" not in _ids(_scan(tmp_path))


def test_generic_response_variable_without_llm_surface_is_not_tainted(tmp_path: Path) -> None:
    (tmp_path / "http.ts").write_text(
        "const response = await fetch('/status');\ncontainer.innerHTML = response.text;\n",
        encoding="utf-8",
    )

    assert not (_ids(_scan(tmp_path)) & S._LLM_OUTPUT_CHECK_IDS)


def test_python_llm_output_to_process_is_detected(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from openai import OpenAI\n"
        "completion = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
        "model_text = completion.choices[0].message.content\n"
        "subprocess.run(model_text, shell=True)\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-003" in _ids(_scan(tmp_path))


def test_multiline_llm_assignment_is_tracked(tmp_path: Path) -> None:
    (tmp_path / "agent.ts").write_text(
        'import OpenAI from "openai";\n'
        "const completion =\n"
        "  await client.chat.completions.create({ model: 'gpt-4o', messages });\n"
        "const modelText = completion.choices[0].message.content;\n"
        "eval(modelText);\n",
        encoding="utf-8",
    )

    assert "INJ-LLM-003" in _ids(_scan(tmp_path))


def test_llm_sinks_in_test_files_are_excluded(tmp_path: Path) -> None:
    (tmp_path / "agent.spec.ts").write_text(_llm_js("eval(modelText);\n"), encoding="utf-8")

    assert not (_ids(_scan(tmp_path)) & S._LLM_OUTPUT_CHECK_IDS)


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
    (repo / "routes/agent.ts").write_text(_llm_js("eval(modelText);\n"), encoding="utf-8")
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
    assert "INJ-LLM-003" in sidecar.read_text(encoding="utf-8")


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


def test_controller_invokes_scanner_in_prepass() -> None:
    text = CONTROLLER.read_text(encoding="utf-8")
    start = text.index("def _prepasses(")
    block = text[start : text.index("\ndef ", start + 1)]
    assert "source_auth_scanner.py" in block, (
        "the controller must invoke source_auth_scanner.py in the deterministic "
        "pre-pass — otherwise .source-auth-findings.json is never produced and "
        "the AUTHZ-001..008 checks are dead (merge_threats only reads the file)."
    )
    assert "route_inventory.py" in block


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


def test_evidence_snippet_keeps_long_lines_under_cap() -> None:
    # Lines up to _EVIDENCE_MAX_LINE are kept whole (the PDF soft-wraps them) —
    # a 250-char code line is no longer truncated mid-token.
    snippet = S._evidence_snippet(["x" * 250], 0)
    assert "…" not in snippet
    assert len(snippet.split(": ", 1)[1]) == 250


def test_evidence_snippet_trims_over_cap_at_word_boundary() -> None:
    # Over-cap lines trim at a WORD boundary (never mid-token) and append " …".
    line = ("a" * 395) + " plain: true"
    snippet = S._evidence_snippet([line], 0)
    body = snippet.split(": ", 1)[1]
    assert body.endswith(" …")
    # The trailing token is dropped whole, not cut mid-identifier.
    assert "plain: tr" not in body


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
