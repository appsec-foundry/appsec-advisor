"""Configuration parsing preserves scope and excludes non-executable evidence."""

from _supply_chain_config import ci_steps, renovate_configs


def test_job_advisory_is_inherited_by_scanner():
    assert ci_steps("jobs:\n  scan:\n    continue-on-error: true\n    steps:\n      - run: npm audit\n") == [
        ("npm audit", True)
    ]


def test_step_name_and_comment_do_not_run_a_scanner():
    assert ci_steps("steps:\n  - name: npm audit\n    run: echo done\n# npm audit\n") == [("echo done", False)]


def test_json5_disabled_renovate(tmp_path):
    (tmp_path / "renovate.json5").write_text('{// config\n enabled: false, enabledManagers: ["npm"],}')
    assert renovate_configs(tmp_path)[0][1]["enabled"] is False


def test_invalid_and_external_configs_are_not_credited(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "renovate.json").write_text("not a mapping")
    other = tmp_path / "external"
    other.write_text("{}")
    (repo / ".renovaterc").symlink_to(other)
    assert renovate_configs(repo) == []
