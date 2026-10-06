"""Build-plane placement shared by Figure 1a, Figure 1b and the §2.2 diagram (RA-28)."""

from model.build_plane import build_component_ids, is_build_component, is_ci_definition


def test_a_ci_component_without_zones_is_build_plane():
    # The juice-shop shape: tier application, no deployment_zones, CI files plus build-neutral files.
    component = {
        "id": "pipeline",
        "tier": "application",
        "paths": [".github/workflows/**", ".gitlab-ci.yml", "Dockerfile", "docker-compose.test.yml", "package.json"],
    }
    assert is_build_component(component)


def test_other_ci_systems_and_names_are_recognised_the_same_way():
    for paths in (["Jenkinsfile", "pom.xml"], [".circleci/config.yml", "requirements.txt"], ["azure-pipelines.yml"]):
        assert is_build_component({"id": "release-automation", "paths": paths}), paths


def test_application_source_keeps_a_component_in_the_runtime():
    component = {"id": "api", "paths": [".github/workflows/deploy.yml", "src/server/**", "package.json"]}
    assert not is_build_component(component)


def test_build_files_without_a_ci_definition_stay_runtime():
    assert not is_build_component({"id": "image", "paths": ["Dockerfile", "package.json"]})
    assert not is_build_component({"id": "empty", "paths": []})


def test_build_zone_tokens_match_whole_tokens_only():
    assert is_build_component({"id": "a", "deployment_zones": ["ci-cd-runtime"]})
    assert is_build_component({"id": "b", "deployment_zones": ["deployment-pipeline"]})
    assert not is_build_component({"id": "c", "deployment_zones": ["social-network", "internet"]})


def test_ci_definition_matches_globs_and_leading_dot_slash():
    assert is_ci_definition("./.github/workflows/ci.yml")
    assert is_ci_definition(".github/workflows/**")
    assert not is_ci_definition("github/workflows/ci.yml")


def test_build_component_ids_selects_only_build_components():
    components = [
        {"id": "web", "paths": ["src/**"]},
        {"id": "ci", "paths": [".github/workflows/*"]},
    ]
    assert build_component_ids(components) == {"ci"}
