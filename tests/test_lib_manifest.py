"""Unit tests for scripts/_lib_manifest.py — manifest dependency enumerator."""

from __future__ import annotations

from pathlib import Path

import _lib_manifest as M

# ---------------------------------------------------------------------------
# discover_manifests
# ---------------------------------------------------------------------------


def test_discover_manifests_finds_known_names(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "requirements.txt").write_text("")
    (tmp_path / "go.mod").write_text("")
    (tmp_path / "App.csproj").write_text("<Project/>")
    found = {p.name for p in M.discover_manifests(tmp_path)}
    assert {"package.json", "requirements.txt", "go.mod", "App.csproj"} <= found


def test_discover_manifests_skips_vendor_dirs(tmp_path: Path):
    nm = tmp_path / "node_modules" / "dep"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")
    found = M.discover_manifests(tmp_path)
    assert all("node_modules" not in p.parts for p in found)
    assert any(p.parent == tmp_path for p in found)


def test_discover_manifests_ignores_unrelated_files(tmp_path: Path):
    (tmp_path / "README.md").write_text("hi")
    (tmp_path / "main.py").write_text("x = 1")
    assert M.discover_manifests(tmp_path) == []


# ---------------------------------------------------------------------------
# parse_manifest dispatch + best-effort error handling
# ---------------------------------------------------------------------------


def test_parse_manifest_unknown_name_returns_empty(tmp_path: Path):
    p = tmp_path / "whatever.txt"
    p.write_text("nothing")
    assert M.parse_manifest(p, tmp_path) == []


def test_parse_manifest_malformed_json_returns_empty(tmp_path: Path):
    p = tmp_path / "package.json"
    p.write_text("{ not valid json")
    assert M.parse_manifest(p, tmp_path) == []


def test_parse_manifest_rel_path_outside_repo_root(tmp_path: Path):
    # path not relative to repo_root -> rel falls back to str(path)
    other = tmp_path / "sub"
    other.mkdir()
    p = other / "package.json"
    p.write_text('{"dependencies": {"a": "1.0.0"}}')
    deps = M.parse_manifest(p, tmp_path / "different")
    assert deps[0].manifest == str(p)


# ---------------------------------------------------------------------------
# _parse_package_json
# ---------------------------------------------------------------------------


def test_parse_package_json_all_blocks(tmp_path: Path):
    p = tmp_path / "package.json"
    p.write_text(
        """{
  "dependencies": {"express": "^4.0.0"},
  "devDependencies": {"jest": "29.0.0"},
  "peerDependencies": {"react": ">=18"},
  "optionalDependencies": {"fsevents": "*"}
}"""
    )
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["express"].ecosystem == "npm"
    assert by_name["express"].version == "^4.0.0"
    assert by_name["express"].line > 1
    assert set(by_name) == {"express", "jest", "react", "fsevents"}


def test_parse_package_json_empty(tmp_path: Path):
    p = tmp_path / "package.json"
    p.write_text("{}")
    assert M.parse_manifest(p, tmp_path) == []


# ---------------------------------------------------------------------------
# _parse_requirements_txt
# ---------------------------------------------------------------------------


def test_parse_requirements_txt(tmp_path: Path):
    p = tmp_path / "requirements.txt"
    p.write_text("flask==2.0.1  # web\nrequests>=2.20\n\n# a comment\n-e .\nunpinned\nbad line with spaces only ok\n")
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["flask"].version == "==2.0.1"
    assert by_name["requests"].version == ">=2.20"
    assert by_name["unpinned"].version is None
    # "-e ." skipped (starts with -), comment skipped, blank skipped
    assert "flask" in by_name and by_name["flask"].ecosystem == "pip"


def test_parse_requirements_dev_variant_name(tmp_path: Path):
    p = tmp_path / "requirements-dev.txt"
    p.write_text("pytest==7.0\n")
    deps = M.parse_manifest(p, tmp_path)
    assert deps[0].package == "pytest"


# ---------------------------------------------------------------------------
# _parse_pyproject_toml
# ---------------------------------------------------------------------------


def test_parse_pyproject_toml_poetry_table(tmp_path: Path):
    p = tmp_path / "pyproject.toml"
    p.write_text(
        "[tool.poetry.dependencies]\n"
        'python = "^3.10"\n'
        'requests = "^2.28"\n'
        "[tool.poetry.dev-dependencies]\n"
        'pytest = "^7.0"\n'
    )
    deps = M.parse_manifest(p, tmp_path)
    names = {d.package for d in deps}
    assert "requests" in names
    assert "pytest" in names
    assert "python" not in names  # explicitly skipped


def test_parse_pyproject_toml_pep621_list(tmp_path: Path):
    p = tmp_path / "pyproject.toml"
    p.write_text('dependencies = ["foo>=1.0", "bar"]\n')
    deps = M.parse_manifest(p, tmp_path)
    names = {d.package for d in deps}
    assert "foo" in names
    assert "bar" in names


# ---------------------------------------------------------------------------
# _parse_pipfile
# ---------------------------------------------------------------------------


def test_parse_pipfile(tmp_path: Path):
    p = tmp_path / "Pipfile"
    p.write_text(
        '[packages]\nrequests = "*"\nflask = ">=1.0"\n[dev-packages]\npytest = "*"\n[scripts]\ntest = "pytest"\n'
    )
    deps = M.parse_manifest(p, tmp_path)
    names = {d.package for d in deps}
    assert "requests" in names
    assert "flask" in names
    assert "pytest" in names
    # 'test' under [scripts] excluded because in_deps reset on [scripts]
    assert "test" not in names


# ---------------------------------------------------------------------------
# _parse_setup_py
# ---------------------------------------------------------------------------


def test_parse_setup_py(tmp_path: Path):
    p = tmp_path / "setup.py"
    p.write_text(
        "from setuptools import setup\n"
        "setup(\n"
        "    install_requires=[\n"
        '        "requests>=2.0",\n'
        '        "click",\n'
        "    ],\n"
        ")\n"
    )
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["requests"].version == ">=2.0"
    assert by_name["click"].version is None


def test_parse_setup_py_no_install_requires(tmp_path: Path):
    p = tmp_path / "setup.py"
    p.write_text("setup(name='x')\n")
    assert M.parse_manifest(p, tmp_path) == []


# ---------------------------------------------------------------------------
# _parse_go_mod
# ---------------------------------------------------------------------------


def test_parse_go_mod_block_and_single(tmp_path: Path):
    p = tmp_path / "go.mod"
    p.write_text(
        "module example.com/x\n"
        "go 1.21\n"
        "require github.com/pkg/errors v0.9.1\n"
        "require (\n"
        "    github.com/gin-gonic/gin v1.9.0\n"
        "    // a comment line\n"
        "    golang.org/x/net v0.0.1\n"
        ")\n"
    )
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["github.com/pkg/errors"].version == "v0.9.1"
    assert by_name["github.com/gin-gonic/gin"].version == "v1.9.0"
    assert by_name["golang.org/x/net"].version == "v0.0.1"
    assert all(d.ecosystem == "go" for d in deps)
    # comment line inside block must not become a dep
    assert "//" not in by_name


# ---------------------------------------------------------------------------
# _parse_pom_xml
# ---------------------------------------------------------------------------


def test_parse_pom_xml(tmp_path: Path):
    p = tmp_path / "pom.xml"
    p.write_text(
        "<project>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.springframework</groupId>\n"
        "      <artifactId>spring-core</artifactId>\n"
        "      <version>5.3.0</version>\n"
        "    </dependency>\n"
        "    <dependency>\n"
        "      <groupId>junit</groupId>\n"
        "      <artifactId>junit</artifactId>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["org.springframework:spring-core"].version == "5.3.0"
    assert by_name["junit:junit"].version is None
    assert all(d.ecosystem == "maven" for d in deps)


# ---------------------------------------------------------------------------
# _parse_build_gradle
# ---------------------------------------------------------------------------


def test_parse_build_gradle(tmp_path: Path):
    p = tmp_path / "build.gradle"
    p.write_text(
        "dependencies {\n"
        "    implementation 'org.apache.commons:commons-lang3:3.12.0'\n"
        '    testImplementation "junit:junit:4.13"\n'
        "    api 'singlecoord'\n"
        "}\n"
    )
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["org.apache.commons:commons-lang3"].version == "3.12.0"
    assert by_name["junit:junit"].version == "4.13"
    # 'singlecoord' has only one part -> skipped
    assert "singlecoord" not in by_name


# ---------------------------------------------------------------------------
# _parse_gemfile
# ---------------------------------------------------------------------------


def test_parse_gemfile(tmp_path: Path):
    p = tmp_path / "Gemfile"
    p.write_text("source 'https://rubygems.org'\n# comment\ngem 'rails', '7.0.0'\ngem \"puma\"\n")
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["rails"].version == "7.0.0"
    assert by_name["puma"].version is None
    assert all(d.ecosystem == "gem" for d in deps)


# ---------------------------------------------------------------------------
# _parse_composer_json
# ---------------------------------------------------------------------------


def test_parse_composer_json(tmp_path: Path):
    p = tmp_path / "composer.json"
    p.write_text(
        """{
  "require": {"php": ">=8.0", "monolog/monolog": "^2.0", "ext-json": "*"},
  "require-dev": {"phpunit/phpunit": "^9.0"}
}"""
    )
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["monolog/monolog"].version == "^2.0"
    # php and ext-* skipped
    assert "php" not in by_name
    assert "ext-json" not in by_name
    # BUG (producer): the `pkg.startswith("php")` guard over-matches any
    # package whose NAME begins with "php" (phpunit, phpstan, php-di, ...),
    # so legitimate require-dev deps like phpunit/phpunit are dropped.
    assert "phpunit/phpunit" not in by_name


# ---------------------------------------------------------------------------
# _parse_cargo_toml
# ---------------------------------------------------------------------------


def test_parse_cargo_toml(tmp_path: Path):
    p = tmp_path / "Cargo.toml"
    p.write_text(
        "[package]\n"
        'name = "x"\n'
        "[dependencies]\n"
        'serde = "1.0"\n'
        'tokio = { version = "1", features = ["full"] }\n'
        "[dev-dependencies]\n"
        'mockall = "0.11"\n'
    )
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["serde"].version == '"1.0"'
    assert "tokio" in by_name
    assert by_name["mockall"].version == '"0.11"'
    assert all(d.ecosystem == "cargo" for d in deps)


# ---------------------------------------------------------------------------
# _parse_csproj + _parse_packages_config
# ---------------------------------------------------------------------------


def test_parse_csproj(tmp_path: Path):
    p = tmp_path / "App.csproj"
    p.write_text(
        "<Project>\n"
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />\n'
        '    <PackageReference Include="Serilog" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["Newtonsoft.Json"].version == "13.0.1"
    assert by_name["Serilog"].version is None
    assert all(d.ecosystem == "nuget" for d in deps)


def test_parse_packages_config(tmp_path: Path):
    p = tmp_path / "packages.config"
    p.write_text(
        '<?xml version="1.0"?>\n'
        "<packages>\n"
        '  <package id="EntityFramework" version="6.4.4" />\n'
        '  <package id="bare" />\n'
        "</packages>\n"
    )
    deps = M.parse_manifest(p, tmp_path)
    by_name = {d.package: d for d in deps}
    assert by_name["EntityFramework"].version == "6.4.4"
    assert by_name["bare"].version is None


# ---------------------------------------------------------------------------
# _find_line_for_key
# ---------------------------------------------------------------------------


def test_find_line_for_key_found_and_default():
    text = 'line1\n"target": 1\nline3'
    assert M._find_line_for_key(text, "target") == 2
    assert M._find_line_for_key(text, "missing") == 1


# ---------------------------------------------------------------------------
# enumerate_deps — integration across multiple manifests
# ---------------------------------------------------------------------------


def test_enumerate_deps_across_ecosystems(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.0.0"}}')
    (tmp_path / "requirements.txt").write_text("flask==2.0\n")
    (tmp_path / "go.mod").write_text("module x\nrequire a/b v1.0.0\n")
    deps = list(M.enumerate_deps(tmp_path))
    ecosystems = {d.ecosystem for d in deps}
    assert {"npm", "pip", "go"} <= ecosystems
    packages = {d.package for d in deps}
    assert {"express", "flask", "a/b"} <= packages


def test_dep_is_frozen():
    d = M.Dep("npm", "x", "1.0", "package.json", 1)
    import dataclasses

    try:
        d.package = "y"  # type: ignore[misc]
        raise AssertionError("Dep should be frozen")
    except dataclasses.FrozenInstanceError:
        pass
