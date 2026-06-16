"""Tests for scripts/package_internal_plugin.py — internal plugin packager.

In-process tests so coverage is collected. Pins current behavior of the
validation helpers, the package-policy parser (every _die error branch),
the copy/overlay/patch steps, namespace rewrite + leak check, archive writing,
and the main() orchestration via a minimal synthetic plugin root.
"""

from __future__ import annotations

import json
import tarfile

import package_internal_plugin as pkg
import pytest

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def test_validate_package_name_ok():
    pkg._validate_package_name("acme-appsec")


@pytest.mark.parametrize("name", ["-bad", "Bad", "a b", "UPPER", "@x"])
def test_validate_package_name_bad(name):
    with pytest.raises(SystemExit):
        pkg._validate_package_name(name)


def test_validate_version_empty():
    with pytest.raises(SystemExit):
        pkg._validate_version("")


def test_validate_version_slash():
    with pytest.raises(SystemExit):
        pkg._validate_version("1/2")


def test_validate_version_ok():
    pkg._validate_version("0.4.0-beta")


def test_require_plugin_root_missing(tmp_path):
    with pytest.raises(SystemExit):
        pkg._require_plugin_root(tmp_path)


# ---------------------------------------------------------------------------
# Synthetic plugin source builder
# ---------------------------------------------------------------------------


def _make_source(root):
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "appsec-advisor", "version": "0.0.0"}), encoding="utf-8"
    )
    (root / "config.json").write_text(json.dumps({}), encoding="utf-8")
    for d in ("agents", "skills", "scripts", "schemas"):
        (root / d).mkdir()
    # a skill with the entry command and an upstream namespace leak
    smk = root / "skills" / "create-threat-model"
    smk.mkdir()
    (smk / "SKILL.md").write_text("Run appsec-advisor:create-threat-model now.\n", encoding="utf-8")
    other = root / "skills" / "publish-threat-model"
    other.mkdir()
    (other / "SKILL.md").write_text("appsec-advisor:publish stuff\n", encoding="utf-8")
    # excluded top-level + nested excludes
    (root / "tests").mkdir()
    (root / "tests" / "x.py").write_text("# excluded\n", encoding="utf-8")
    (root / "scripts" / "__pycache__").mkdir()
    (root / "scripts" / "__pycache__" / "c.pyc").write_text("x", encoding="utf-8")
    (root / "scripts" / "docs").mkdir()
    (root / "scripts" / "docs" / "note.md").write_text("excluded\n", encoding="utf-8")
    # hooks
    hooks = root / "hooks"
    hooks.mkdir()
    (hooks / "hooks.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [{"hooks": [{"command": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/agent_logger.py"}]}],
                    "UserPromptSubmit": [
                        {"hooks": [{"command": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/security_steering.py"}]}
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    (hooks / "steering_keywords.json").write_text("{}", encoding="utf-8")
    return root


def _make_org_profile(root):
    root.mkdir(parents=True)
    (root / "org-profile.yaml").write_text("organization:\n  id: acme\n", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# copy_source / overlay / patch
# ---------------------------------------------------------------------------


def test_copy_source_applies_excludes(tmp_path):
    source = _make_source(tmp_path / "src")
    build = tmp_path / "build" / "acme"
    pkg.copy_source(source, build)
    assert (build / ".claude-plugin" / "plugin.json").is_file()
    assert not (build / "tests").exists()
    assert not (build / "scripts" / "__pycache__").exists()
    assert not (build / "scripts" / "docs").exists()
    # re-copy over an existing build removes it first
    pkg.copy_source(source, build)
    assert (build / "config.json").is_file()


def test_overlay_org_profile_missing_yaml(tmp_path):
    build = tmp_path / "build"
    build.mkdir()
    op = tmp_path / "op"
    op.mkdir()
    with pytest.raises(SystemExit):
        pkg.overlay_org_profile(op, build)


def test_overlay_org_profile_replaces_existing(tmp_path):
    build = tmp_path / "build"
    build.mkdir()
    op = _make_org_profile(tmp_path / "op")
    (build / "org-profile").mkdir()
    (build / "org-profile" / "stale.txt").write_text("old", encoding="utf-8")
    pkg.overlay_org_profile(op, build)
    assert (build / "org-profile" / "org-profile.yaml").is_file()
    assert not (build / "org-profile" / "stale.txt").exists()


def test_patch_plugin_json_default_and_override(tmp_path):
    build = tmp_path / "build"
    (build / ".claude-plugin").mkdir(parents=True)
    (build / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "x"}), encoding="utf-8")
    pkg.patch_plugin_json(build, "acme", "1.0.0", None)
    data = json.loads((build / ".claude-plugin" / "plugin.json").read_text())
    assert data["name"] == "acme" and data["version"] == "1.0.0"
    assert "Internal packaged build" in data["description"]
    pkg.patch_plugin_json(build, "acme", "1.0.0", "custom desc")
    data = json.loads((build / ".claude-plugin" / "plugin.json").read_text())
    assert data["description"] == "custom desc"


def test_patch_config(tmp_path):
    build = tmp_path / "build"
    build.mkdir()
    (build / "config.json").write_text(json.dumps({"keep": 1}), encoding="utf-8")
    pkg.patch_config(build)
    data = json.loads((build / "config.json").read_text())
    assert data["keep"] == 1
    assert data["organization_profile"]["enabled"] is True
    assert data["organization_profile"]["path"] == "org-profile/org-profile.yaml"


# ---------------------------------------------------------------------------
# Package-policy loading
# ---------------------------------------------------------------------------


def test_load_yaml_or_json_read_error(tmp_path):
    # a directory path -> read_text raises OSError
    d = tmp_path / "adir"
    d.mkdir()
    with pytest.raises(SystemExit):
        pkg._load_yaml_or_json(d)


def test_load_yaml_or_json_bad_json(tmp_path):
    p = tmp_path / "p.json"
    p.write_text("{bad", encoding="utf-8")
    with pytest.raises(SystemExit):
        pkg._load_yaml_or_json(p)


def test_load_yaml_or_json_json_ok(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"a": 1}), encoding="utf-8")
    assert pkg._load_yaml_or_json(p) == {"a": 1}


def test_load_yaml_or_json_yaml_ok(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("a: 1\n", encoding="utf-8")
    assert pkg._load_yaml_or_json(p) == {"a": 1}


def test_load_yaml_or_json_bad_yaml(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("a: [1, 2\n  b: 3\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        pkg._load_yaml_or_json(p)


def test_load_yaml_or_json_yaml_without_pyyaml(tmp_path, monkeypatch):
    p = tmp_path / "p.yaml"
    p.write_text("a: 1\n", encoding="utf-8")
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SystemExit):
        pkg._load_yaml_or_json(p)


def test_load_yaml_or_json_empty_returns_dict(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("", encoding="utf-8")
    assert pkg._load_yaml_or_json(p) == {}


def test_load_yaml_or_json_non_mapping(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(SystemExit):
        pkg._load_yaml_or_json(p)


def test_load_package_policy_explicit_missing(tmp_path):
    with pytest.raises(SystemExit):
        pkg.load_package_policy(tmp_path, str(tmp_path / "nope.yaml"))


def test_load_package_policy_explicit_ok(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"plugin_surface": {}}), encoding="utf-8")
    policy, path = pkg.load_package_policy(tmp_path, str(p))
    assert path == p.resolve()


def test_load_package_policy_auto_discovery(tmp_path):
    op = tmp_path / "op"
    op.mkdir()
    (op / "package-policy.yaml").write_text("plugin_surface: {}\n", encoding="utf-8")
    policy, path = pkg.load_package_policy(op, None)
    assert path is not None and path.name == "package-policy.yaml"


def test_load_package_policy_none_found(tmp_path):
    op = tmp_path / "op"
    op.mkdir()
    policy, path = pkg.load_package_policy(op, None)
    assert policy == {} and path is None


# ---------------------------------------------------------------------------
# _policy_surface
# ---------------------------------------------------------------------------


def test_policy_surface_explicit_block():
    assert pkg._policy_surface({"plugin_surface": {"skills": {}}}) == {"skills": {}}


def test_policy_surface_fallback_to_root():
    assert pkg._policy_surface({"skills": {}}) == {"skills": {}}


def test_policy_surface_not_mapping():
    with pytest.raises(SystemExit):
        pkg._policy_surface({"plugin_surface": [1, 2]})


def test_policy_surface_unknown_keys():
    with pytest.raises(SystemExit):
        pkg._policy_surface({"plugin_surface": {"bogus": 1}})


# ---------------------------------------------------------------------------
# _read_name_list
# ---------------------------------------------------------------------------


def test_read_name_list_absent_key():
    assert pkg._read_name_list({}, "include", "skills") is None


def test_read_name_list_none_value():
    assert pkg._read_name_list({"include": None}, "include", "skills") == set()


def test_read_name_list_not_a_list():
    with pytest.raises(SystemExit):
        pkg._read_name_list({"include": "x"}, "include", "skills")


def test_read_name_list_non_string_items():
    with pytest.raises(SystemExit):
        pkg._read_name_list({"include": [1, 2]}, "include", "skills")


def test_read_name_list_empty_name():
    with pytest.raises(SystemExit):
        pkg._read_name_list({"include": ["  "]}, "include", "skills")


def test_read_name_list_duplicates():
    with pytest.raises(SystemExit):
        pkg._read_name_list({"include": ["a", "a"]}, "include", "skills")


def test_read_name_list_ok():
    assert pkg._read_name_list({"include": ["a", "b"]}, "include", "skills") == {"a", "b"}


# ---------------------------------------------------------------------------
# _resolve_keep_set
# ---------------------------------------------------------------------------


AVAIL = {"create-threat-model", "publish-threat-model", "other"}


def test_resolve_keep_block_none_keeps_all():
    assert pkg._resolve_keep_set(None, AVAIL, "skills") == AVAIL


def test_resolve_keep_block_not_mapping():
    with pytest.raises(SystemExit):
        pkg._resolve_keep_set([1], AVAIL, "skills")


def test_resolve_keep_unknown_keys():
    with pytest.raises(SystemExit):
        pkg._resolve_keep_set({"bogus": []}, AVAIL, "skills")


def test_resolve_keep_both_include_exclude():
    with pytest.raises(SystemExit):
        pkg._resolve_keep_set({"include": ["other"], "exclude": ["other"]}, AVAIL, "skills")


def test_resolve_keep_neither_keeps_all():
    assert pkg._resolve_keep_set({}, AVAIL, "skills") == AVAIL


def test_resolve_keep_unknown_name():
    with pytest.raises(SystemExit):
        pkg._resolve_keep_set({"include": ["ghost"]}, AVAIL, "skills")


def test_resolve_keep_include_subset():
    assert pkg._resolve_keep_set({"include": ["other"]}, AVAIL, "skills") == {"other"}


def test_resolve_keep_exclude_subset():
    assert pkg._resolve_keep_set({"exclude": ["other"]}, AVAIL, "skills") == AVAIL - {"other"}


def test_resolve_keep_required_missing():
    with pytest.raises(SystemExit):
        pkg._resolve_keep_set({"include": ["other"]}, AVAIL, "skills", required={"create-threat-model"})


def test_resolve_keep_required_present():
    keep = pkg._resolve_keep_set(
        {"include": ["create-threat-model"]}, AVAIL, "skills", required={"create-threat-model"}
    )
    assert keep == {"create-threat-model"}


# ---------------------------------------------------------------------------
# _available_skills / _hook_id / _load_hooks / _available_hook_ids
# ---------------------------------------------------------------------------


def test_available_skills_no_dir(tmp_path):
    assert pkg._available_skills(tmp_path) == set()


def test_available_skills_found(tmp_path):
    src = _make_source(tmp_path / "src")
    assert pkg._available_skills(src) == {"create-threat-model", "publish-threat-model"}


def test_hook_id_branches():
    assert pkg._hook_id("python tool.py") is None
    assert pkg._hook_id("python /x/scripts/agent_logger.py") == "agent-logger"
    assert pkg._hook_id("py /x/scripts/foo_bar.py") == "foo-bar"


def test_load_hooks_no_file(tmp_path):
    path, data = pkg._load_hooks(tmp_path)
    assert data == {"hooks": {}}


def test_load_hooks_bad_json(tmp_path):
    h = tmp_path / "hooks"
    h.mkdir()
    (h / "hooks.json").write_text("{bad", encoding="utf-8")
    with pytest.raises(SystemExit):
        pkg._load_hooks(tmp_path)


def test_load_hooks_no_top_level_hooks(tmp_path):
    h = tmp_path / "hooks"
    h.mkdir()
    (h / "hooks.json").write_text(json.dumps({"nope": 1}), encoding="utf-8")
    with pytest.raises(SystemExit):
        pkg._load_hooks(tmp_path)


def test_available_hook_ids(tmp_path):
    src = _make_source(tmp_path / "src")
    assert pkg._available_hook_ids(src) == {"agent-logger", "security-coach"}


def test_available_hook_ids_skips_malformed(tmp_path):
    h = tmp_path / "hooks"
    h.mkdir()
    (h / "hooks.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "E1": "not-a-list",
                    "E2": [
                        "not-a-dict",
                        {"hooks": ["x", {"command": 1}, {"command": "python /x/scripts/agent_logger.py"}]},
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    assert pkg._available_hook_ids(tmp_path) == {"agent-logger"}


# ---------------------------------------------------------------------------
# apply_skill_policy / apply_hook_policy
# ---------------------------------------------------------------------------


def test_apply_skill_policy_removes(tmp_path):
    src = _make_source(tmp_path / "src")
    result = pkg.apply_skill_policy(src, {"skills": {"include": ["create-threat-model"]}})
    assert result["included"] == ["create-threat-model"]
    assert result["removed"] == ["publish-threat-model"]
    assert not (src / "skills" / "publish-threat-model").exists()


def test_apply_hook_policy_filters_and_removes_keywords(tmp_path):
    src = _make_source(tmp_path / "src")
    result = pkg.apply_hook_policy(src, {"hooks": {"include": ["agent-logger"]}})
    assert "agent-logger" in result["included"]
    assert "security-coach" in result["removed"]
    # security-coach removed -> steering_keywords.json deleted
    assert not (src / "hooks" / "steering_keywords.json").exists()
    # hooks.json no longer references security_steering
    data = json.loads((src / "hooks" / "hooks.json").read_text())
    cmds = json.dumps(data)
    assert "security_steering" not in cmds
    assert "agent_logger" in cmds


def test_apply_hook_policy_keep_all(tmp_path):
    src = _make_source(tmp_path / "src")
    result = pkg.apply_hook_policy(src, {})
    assert set(result["included"]) == {"agent-logger", "security-coach"}
    assert result["removed"] == []


def test_apply_hook_policy_skips_malformed_entries(tmp_path):
    h = tmp_path / "hooks"
    h.mkdir()
    (h / "hooks.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "E1": "not-a-list",
                    "E2": [
                        "not-a-dict",
                        {
                            "hooks": [
                                "x",
                                {"command": 5},
                                {"command": "python /x/scripts/agent_logger.py"},
                            ]
                        },
                        {"hooks": []},
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    result = pkg.apply_hook_policy(tmp_path, {})
    assert result["included"] == ["agent-logger"]
    # E2 retained (has a kept hook), E1 dropped (not a list)
    assert result["events"] == ["E2"]


# ---------------------------------------------------------------------------
# write_surface_manifest
# ---------------------------------------------------------------------------


def test_write_surface_manifest_policy_none(tmp_path):
    build = tmp_path / "b"
    build.mkdir()
    pkg.write_surface_manifest(build, None, {"included": []}, {"included": []})
    data = json.loads((build / pkg.SURFACE_MANIFEST).read_text())
    assert data["policy"] is None
    assert data["version"] == 1


def test_write_surface_manifest_policy_in_org_profile(tmp_path):
    build = tmp_path / "b"
    (build / "org-profile").mkdir(parents=True)
    (build / "org-profile" / "package-policy.yaml").write_text("x\n", encoding="utf-8")
    policy_path = build / "org-profile" / "package-policy.yaml"
    pkg.write_surface_manifest(build, policy_path, {}, {}, upstream_url="https://x")
    data = json.loads((build / pkg.SURFACE_MANIFEST).read_text())
    assert data["policy"] == "org-profile/package-policy.yaml"
    assert data["upstream_url"] == "https://x"


def test_write_surface_manifest_policy_relative(tmp_path):
    build = tmp_path / "b"
    build.mkdir()
    policy_path = build / "sub" / "policy.json"
    policy_path.parent.mkdir()
    policy_path.write_text("{}", encoding="utf-8")
    pkg.write_surface_manifest(build, policy_path, {}, {})
    data = json.loads((build / pkg.SURFACE_MANIFEST).read_text())
    assert data["policy"] == "sub/policy.json"


def test_write_surface_manifest_policy_outside_build(tmp_path):
    build = tmp_path / "b"
    build.mkdir()
    policy_path = tmp_path / "elsewhere" / "policy.json"
    policy_path.parent.mkdir()
    policy_path.write_text("{}", encoding="utf-8")
    pkg.write_surface_manifest(build, policy_path, {}, {})
    data = json.loads((build / pkg.SURFACE_MANIFEST).read_text())
    assert data["policy"] == "policy.json"


def test_apply_package_surface_policy(tmp_path):
    src = _make_source(tmp_path / "src")
    pkg.apply_package_surface_policy(src, {"plugin_surface": {}}, None)
    assert (src / pkg.SURFACE_MANIFEST).is_file()


# ---------------------------------------------------------------------------
# rewrite_namespace / check_namespace_leaks
# ---------------------------------------------------------------------------


def test_rewrite_namespace(tmp_path):
    src = _make_source(tmp_path / "src")
    pkg.rewrite_namespace(src, "acme")
    txt = (src / "skills" / "create-threat-model" / "SKILL.md").read_text()
    assert "acme:create-threat-model" in txt
    assert "appsec-advisor:" not in txt


def test_check_namespace_leaks_clean(tmp_path):
    src = _make_source(tmp_path / "src")
    pkg.rewrite_namespace(src, "acme")
    pkg.check_namespace_leaks(src)  # no raise


def test_check_namespace_leaks_detects(tmp_path):
    src = _make_source(tmp_path / "src")
    with pytest.raises(SystemExit):
        pkg.check_namespace_leaks(src)


def test_check_namespace_leaks_no_roots(tmp_path):
    build = tmp_path / "b"
    build.mkdir()
    pkg.check_namespace_leaks(build)  # nothing to scan, no raise


def test_rewrite_namespace_skips_non_utf8(tmp_path):
    src = _make_source(tmp_path / "src")
    # a .md text-suffixed file with invalid utf-8 bytes is skipped silently
    bad = src / "skills" / "create-threat-model" / "binary.md"
    bad.write_bytes(b"\xff\xfe appsec-advisor:leak")
    pkg.rewrite_namespace(src, "acme")
    # untouched (still contains raw bytes, not rewritten)
    assert bad.read_bytes().startswith(b"\xff\xfe")


def test_check_namespace_leaks_skips_non_utf8(tmp_path):
    src = _make_source(tmp_path / "src")
    pkg.rewrite_namespace(src, "acme")
    bad = src / "skills" / "create-threat-model" / "binary.md"
    bad.write_bytes(b"\xff\xfe appsec-advisor:leak")
    # the undecodable file is skipped, so no leak is reported
    pkg.check_namespace_leaks(src)


# ---------------------------------------------------------------------------
# write_archive / remove_stale_archive
# ---------------------------------------------------------------------------


def test_write_archive(tmp_path):
    build = tmp_path / "b" / "acme"
    build.mkdir(parents=True)
    (build / "f.txt").write_text("hi", encoding="utf-8")
    dist = tmp_path / "dist"
    tar_path, sha_path = pkg.write_archive(build, "acme", "1.0.0", dist)
    assert tar_path.is_file() and sha_path.is_file()
    with tarfile.open(tar_path) as tf:
        names = tf.getnames()
    assert any(n.startswith("acme") for n in names)
    assert "acme-1.0.0.tgz" in sha_path.read_text()


def test_remove_stale_archive(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    tgz = dist / "acme-1.0.0.tgz"
    sha = dist / "acme-1.0.0.tgz.sha256"
    tgz.write_text("x", encoding="utf-8")
    sha.write_text("x", encoding="utf-8")
    pkg.remove_stale_archive("acme", "1.0.0", dist)
    assert not tgz.exists() and not sha.exists()
    # idempotent when absent
    pkg.remove_stale_archive("acme", "1.0.0", dist)


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------


def test_parse_args_minimal():
    ns = pkg.parse_args(["--org-profile", "op", "--name", "acme", "--version", "1.0.0"])
    assert ns.name == "acme" and ns.version == "1.0.0"
    assert ns.skip_validation is False and ns.skip_archive is False


# ---------------------------------------------------------------------------
# main() — full orchestration with validation/archive skipped & exercised.
# ---------------------------------------------------------------------------


def _run_main(tmp_path, extra=None, monkeypatch=None):
    src = _make_source(tmp_path / "src")
    op = _make_org_profile(tmp_path / "op")
    argv = [
        "--source",
        str(src),
        "--org-profile",
        str(op),
        "--name",
        "acme",
        "--version",
        "1.0.0",
        "--build-dir",
        str(tmp_path / "build"),
        "--dist-dir",
        str(tmp_path / "dist"),
    ]
    if extra:
        argv += extra
    return pkg.main(argv)


def test_main_skip_validation_and_archive(tmp_path, capsys):
    code = _run_main(tmp_path, extra=["--skip-validation", "--skip-archive"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Build tree ready" in out
    build = tmp_path / "build" / "acme"
    # plugin patched, namespace rewritten, manifest written
    data = json.loads((build / ".claude-plugin" / "plugin.json").read_text())
    assert data["name"] == "acme"
    assert (build / pkg.SURFACE_MANIFEST).is_file()
    assert (build / "org-profile" / "org-profile.yaml").is_file()


def test_main_with_archive_skip_validation(tmp_path, capsys):
    code = _run_main(tmp_path, extra=["--skip-validation"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Artifact:" in out and "SHA256:" in out
    assert (tmp_path / "dist" / "acme-1.0.0.tgz").is_file()


def test_main_runs_validation(tmp_path, monkeypatch, capsys):
    calls = []

    def fake_run(cmd, check):
        calls.append(cmd)

        class R:
            returncode = 0

        return R()

    monkeypatch.setattr(pkg.subprocess, "run", fake_run)
    code = _run_main(tmp_path, extra=["--skip-archive"])
    assert code == 0
    # validate_config.py and validate_org_profile.py both invoked
    joined = " ".join(" ".join(map(str, c)) for c in calls)
    assert "validate_config.py" in joined
    assert "validate_org_profile.py" in joined


def test_main_bad_name_exits(tmp_path):
    src = _make_source(tmp_path / "src")
    op = _make_org_profile(tmp_path / "op")
    with pytest.raises(SystemExit):
        pkg.main(
            [
                "--source",
                str(src),
                "--org-profile",
                str(op),
                "--name",
                "BadName",
                "--version",
                "1.0.0",
                "--build-dir",
                str(tmp_path / "build"),
                "--dist-dir",
                str(tmp_path / "dist"),
            ]
        )
