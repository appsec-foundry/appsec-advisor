"""Unit tests for scripts/_manifest_readers.py — polyglot infobox readers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import _manifest_readers as R


def ctx_for(repo_root: Path) -> SimpleNamespace:
    """Build a ctx whose output_dir.parent.parent == repo_root.

    _repo_root_candidates returns [output_dir.parent.parent, output_dir.parent,
    output_dir]; placing files at repo_root makes them resolve via the first
    candidate (the canonical <repo>/docs/security layout).
    """
    out = repo_root / "docs" / "security"
    out.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(output_dir=out)


# ---------------------------------------------------------------------------
# _repo_root_candidates
# ---------------------------------------------------------------------------


def test_repo_root_candidates_levels(tmp_path: Path):
    out = tmp_path / "a" / "b"
    out.mkdir(parents=True)
    cands = R._repo_root_candidates(SimpleNamespace(output_dir=out))
    assert cands == [tmp_path, tmp_path / "a", out]


def test_repo_root_candidates_no_output_dir():
    class Bad:
        @property
        def output_dir(self):
            raise RuntimeError("nope")

    assert R._repo_root_candidates(Bad()) == []


# ---------------------------------------------------------------------------
# read_package_json
# ---------------------------------------------------------------------------


def test_read_package_json(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name": "demo", "version": "1.0"}')
    data = R.read_package_json(ctx_for(tmp_path))
    assert data["name"] == "demo"


def test_read_package_json_missing(tmp_path: Path):
    assert R.read_package_json(ctx_for(tmp_path)) == {}


def test_read_package_json_malformed(tmp_path: Path):
    (tmp_path / "package.json").write_text("{ broken")
    assert R.read_package_json(ctx_for(tmp_path)) == {}


# ---------------------------------------------------------------------------
# read_project_manifest dispatch chain
# ---------------------------------------------------------------------------


def test_read_project_manifest_prefers_package_json(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name": "p"}')
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "py"\n')
    assert R.read_project_manifest(ctx_for(tmp_path))["name"] == "p"


def test_read_project_manifest_pyproject_fallback_with_readme_desc(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "py"\nversion = "2.0"\n')
    (tmp_path / "README.md").write_text("# Title\n\nA short description.\n")
    data = R.read_project_manifest(ctx_for(tmp_path))
    assert data["name"] == "py"
    # NOTE: _read_pyproject_toml always emits a "description" key (value None
    # when absent), so the setdefault("description", read_readme_description)
    # in read_project_manifest is a no-op — the README fallback never fires
    # for pyproject/cargo/etc. The key exists but stays None.
    assert data["description"] is None


def test_read_project_manifest_cargo(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "rustcrate"\nversion = "0.1.0"\n')
    data = R.read_project_manifest(ctx_for(tmp_path))
    assert data["name"] == "rustcrate"
    assert data["runtime"] == "Rust (Cargo)"


def test_read_project_manifest_go(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module github.com/o/r\ngo 1.21\n")
    data = R.read_project_manifest(ctx_for(tmp_path))
    assert data["name"] == "r"
    assert data["repository"] == "github.com/o/r"
    assert data["runtime"] == "Go 1.21"


def test_read_project_manifest_pom(tmp_path: Path):
    (tmp_path / "pom.xml").write_text(
        "<project>\n"
        "  <name>MyApp</name>\n"
        "  <version>1.2.3</version>\n"
        "  <description>Java thing</description>\n"
        "</project>\n"
    )
    data = R.read_project_manifest(ctx_for(tmp_path))
    assert data["name"] == "MyApp"
    assert data["version"] == "1.2.3"


def test_read_project_manifest_gradle(tmp_path: Path):
    (tmp_path / "build.gradle").write_text("version = '3.0'\ngroup = 'com.acme'\n")
    (tmp_path / "settings.gradle").write_text("rootProject.name = 'gr'\n")
    data = R.read_project_manifest(ctx_for(tmp_path))
    assert data["name"] == "gr"
    assert data["version"] == "3.0"
    assert data["author"] == "com.acme"


def test_read_project_manifest_readme_only(tmp_path: Path):
    (tmp_path / "README.md").write_text("# T\n\nOnly a readme here.\n")
    data = R.read_project_manifest(ctx_for(tmp_path))
    assert data == {"description": "Only a readme here."}


def test_read_project_manifest_empty(tmp_path: Path):
    assert R.read_project_manifest(ctx_for(tmp_path)) == {}


# ---------------------------------------------------------------------------
# _read_pyproject_toml details
# ---------------------------------------------------------------------------


def test_read_pyproject_full_pep621(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'name = "fullproj"\n'
        'version = "1.0"\n'
        'description = "desc"\n'
        'requires-python = ">=3.10"\n'
        'dependencies = ["requests>=2.0", "click"]\n'
        'authors = [{name = "Jane", email = "jane@example.com"}]\n'
        'keywords = ["a", "b"]\n'
        'license = {text = "MIT"}\n'
        "[project.urls]\n"
        'Homepage = "https://example.com"\n'
        'Repository = "https://github.com/x/y"\n'
    )
    data = R._read_pyproject_toml(ctx_for(tmp_path))
    assert data["name"] == "fullproj"
    assert data["author"] == "Jane (jane@example.com)"
    assert data["license"] == "MIT"
    assert data["homepage"] == "https://example.com"
    assert data["repository"] == "https://github.com/x/y"
    assert "Python >=3.10" in data["runtime"]
    assert "requests" in data["runtime"]


def test_read_pyproject_string_author_and_license_file(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "p"\nauthors = ["Just A String"]\nlicense = {file = "LICENSE"}\n'
    )
    data = R._read_pyproject_toml(ctx_for(tmp_path))
    assert data["author"] == "Just A String"
    assert data["license"] == "LICENSE"


def test_read_pyproject_poetry_block(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[tool.poetry]\nname = "poet"\nversion = "0.1"\n')
    data = R._read_pyproject_toml(ctx_for(tmp_path))
    assert data["name"] == "poet"


def test_read_pyproject_no_project_table(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[build-system]\nrequires = []\n")
    assert R._read_pyproject_toml(ctx_for(tmp_path)) == {}


def test_read_pyproject_malformed(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project\nbroken")
    assert R._read_pyproject_toml(ctx_for(tmp_path)) == {}


# ---------------------------------------------------------------------------
# _read_cargo_toml details
# ---------------------------------------------------------------------------


def test_read_cargo_full(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        "[package]\n"
        'name = "c"\n'
        'version = "0.2"\n'
        'description = "rust crate"\n'
        'authors = ["Dev <d@e.com>"]\n'
        'license = "Apache-2.0"\n'
        'repository = "https://github.com/a/b"\n'
        'rust-version = "1.70"\n'
    )
    data = R._read_cargo_toml(ctx_for(tmp_path))
    assert data["author"] == "Dev <d@e.com>"
    assert data["runtime"] == "Rust 1.70"
    assert data["license"] == "Apache-2.0"


def test_read_cargo_no_package(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nserde = "1"\n')
    assert R._read_cargo_toml(ctx_for(tmp_path)) == {}


def test_read_cargo_malformed(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[package\nbad")
    assert R._read_cargo_toml(ctx_for(tmp_path)) == {}


# ---------------------------------------------------------------------------
# _read_go_mod details
# ---------------------------------------------------------------------------


def test_read_go_mod_non_github(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module example.org/foo\n")
    data = R._read_go_mod(ctx_for(tmp_path))
    assert data["name"] == "foo"
    assert data["repository"] is None
    assert data["runtime"] == "Go"


def test_read_go_mod_no_module(tmp_path: Path):
    (tmp_path / "go.mod").write_text("go 1.21\n")
    assert R._read_go_mod(ctx_for(tmp_path)) == {}


# ---------------------------------------------------------------------------
# _read_pom_xml details
# ---------------------------------------------------------------------------


def test_read_pom_full_with_namespace(tmp_path: Path):
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <artifactId>art</artifactId>\n"
        "  <version>1.0</version>\n"
        "  <url>https://site</url>\n"
        "  <licenses><license><name>MIT</name></license></licenses>\n"
        "  <developers><developer><name>Dev</name></developer></developers>\n"
        "  <scm><url>https://scm</url></scm>\n"
        "  <properties><java.version>17</java.version></properties>\n"
        "  <dependencies>\n"
        "    <dependency><artifactId>guava</artifactId></dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    data = R._read_pom_xml(ctx_for(tmp_path))
    assert data["name"] == "art"
    assert data["license"] == "MIT"
    assert data["author"] == "Dev"
    assert data["repository"] == "https://scm"
    assert "Java 17" in data["runtime"]
    assert "guava" in data["runtime"]


def test_read_pom_malformed(tmp_path: Path):
    (tmp_path / "pom.xml").write_text("<project><unclosed>")
    assert R._read_pom_xml(ctx_for(tmp_path)) == {}


# ---------------------------------------------------------------------------
# _read_gradle details
# ---------------------------------------------------------------------------


def test_read_gradle_kts_with_java_and_spring(tmp_path: Path):
    (tmp_path / "build.gradle.kts").write_text(
        'version = "1.0"\n'
        'group = "com.x"\n'
        'description = "grtxt"\n'
        "sourceCompatibility = '11'\n"
        'id("org.springframework.boot") version "3.0.0"\n'
        "dependencies {\n"
        "    implementation('org.foo:bar:1.0')\n"
        "}\n"
    )
    (tmp_path / "settings.gradle.kts").write_text('rootProject.name = "ktsproj"\n')
    data = R._read_gradle(ctx_for(tmp_path))
    assert data["name"] == "ktsproj"
    assert data["description"] == "grtxt"
    assert "Java 11" in data["runtime"]
    assert "Spring Boot 3.0.0" in data["runtime"]
    # impl_deps regex captures the FIRST coordinate segment (group/org), and
    # the .split(":")[-1] of that single-segment match yields the group, not
    # the artifact — so "org.foo" lands in runtime, not "bar".
    assert "org.foo" in data["runtime"]


def test_read_gradle_archives_base_name_fallback(tmp_path: Path):
    (tmp_path / "build.gradle").write_text("archivesBaseName = 'abn'\nJavaVersion.VERSION_1_8\n")
    data = R._read_gradle(ctx_for(tmp_path))
    assert data["name"] == "abn"
    assert "Java 1.8" in data["runtime"]


def test_read_gradle_none(tmp_path: Path):
    assert R._read_gradle(ctx_for(tmp_path)) == {}


# ---------------------------------------------------------------------------
# read_readme_description
# ---------------------------------------------------------------------------


def test_readme_description_strips_markdown(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Title\n\nA **bold** project using [link](http://x) and `code` here.\n")
    desc = R.read_readme_description(ctx_for(tmp_path))
    assert desc == "A bold project using link and code here."


def test_readme_description_skips_badges_and_frontmatter(tmp_path: Path):
    (tmp_path / "README.md").write_text(
        "---\ntitle: x\n---\n# Heading\n\n![badge](url)\n> quote\nThe real description line.\n"
    )
    desc = R.read_readme_description(ctx_for(tmp_path))
    assert desc == "The real description line."


def test_readme_description_truncates(tmp_path: Path):
    long = "x" * 300
    (tmp_path / "README.md").write_text(f"# T\n\n{long}\n")
    desc = R.read_readme_description(ctx_for(tmp_path))
    assert desc.endswith("…")
    assert len(desc) <= 248


def test_readme_description_none(tmp_path: Path):
    assert R.read_readme_description(ctx_for(tmp_path)) is None


# ---------------------------------------------------------------------------
# format_author
# ---------------------------------------------------------------------------


def test_format_author_variants():
    assert R.format_author(None) is None
    assert R.format_author("  Name  ") == "Name"
    assert R.format_author("") is None
    assert R.format_author({"name": "N", "email": "e@x"}) == "N (e@x)"
    assert R.format_author({"name": "N"}) == "N"
    assert R.format_author({"email": "e@x"}) is None
    assert R.format_author(["First", "Second"]) == "First"
    assert R.format_author([]) is None
    assert R.format_author(123) is None


# ---------------------------------------------------------------------------
# read_license_file
# ---------------------------------------------------------------------------


def test_license_mit(tmp_path: Path):
    (tmp_path / "LICENSE").write_text("MIT License\n\nPermission is hereby granted...")
    assert R.read_license_file(ctx_for(tmp_path)) == "MIT"


def test_license_apache(tmp_path: Path):
    (tmp_path / "LICENSE.txt").write_text("Apache License, Version 2.0\n")
    assert R.read_license_file(ctx_for(tmp_path)) == "Apache-2.0"


def test_license_gpl3(tmp_path: Path):
    (tmp_path / "COPYING").write_text("GNU GENERAL PUBLIC LICENSE Version 3, 29 June")
    assert R.read_license_file(ctx_for(tmp_path)) == "GPL-3.0"


def test_license_unknown_first_line(tmp_path: Path):
    (tmp_path / "LICENSE").write_text("Custom Proprietary Terms\nmore text")
    assert R.read_license_file(ctx_for(tmp_path)) == "Custom Proprietary Terms"


def test_license_none(tmp_path: Path):
    assert R.read_license_file(ctx_for(tmp_path)) is None


# ---------------------------------------------------------------------------
# derive_homepage
# ---------------------------------------------------------------------------


def test_derive_homepage_explicit():
    assert R.derive_homepage(None, {"homepage": "http://h"}) == "http://h"


def test_derive_homepage_from_remote_ssh():
    out = R.derive_homepage("git@github.com:o/r.git", {})
    assert out == "https://github.com/o/r"


def test_derive_homepage_strips_git_prefix_suffix():
    out = R.derive_homepage("git+https://github.com/o/r.git", {})
    assert out == "https://github.com/o/r"


def test_derive_homepage_none():
    assert R.derive_homepage(None, {}) is None


# ---------------------------------------------------------------------------
# read_readme_tags
# ---------------------------------------------------------------------------


def test_readme_tags_frontmatter_list(tmp_path: Path):
    (tmp_path / "README.md").write_text("---\ntags:\n  - alpha\n  - beta\n---\n# T\n")
    assert R.read_readme_tags(ctx_for(tmp_path)) == ["alpha", "beta"]


def test_readme_tags_frontmatter_string(tmp_path: Path):
    (tmp_path / "README.md").write_text("---\ntopics: one two three\n---\n# T\n")
    assert R.read_readme_tags(ctx_for(tmp_path)) == ["one", "two", "three"]


def test_readme_tags_github_topics_file(tmp_path: Path):
    (tmp_path / "README.md").write_text("# no frontmatter\n")
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "topics").write_text("- security\n- python\n# comment\n")
    assert R.read_readme_tags(ctx_for(tmp_path)) == ["security", "python"]


def test_readme_tags_none(tmp_path: Path):
    assert R.read_readme_tags(ctx_for(tmp_path)) is None


# ---------------------------------------------------------------------------
# extract_repo_url
# ---------------------------------------------------------------------------


def test_extract_repo_url_variants():
    assert R.extract_repo_url(None) is None
    assert R.extract_repo_url("https://github.com/x/y") == "https://github.com/x/y"
    assert R.extract_repo_url({"type": "git", "url": "git+https://github.com/x/y.git"}) == "https://github.com/x/y"
    assert R.extract_repo_url({"type": "git"}) is None


# ---------------------------------------------------------------------------
# derive_runtime
# ---------------------------------------------------------------------------


def test_derive_runtime_node_and_framework():
    pkg = {
        "engines": {"node": ">=18"},
        "dependencies": {"express": "^4.18.0"},
    }
    out = R.derive_runtime(pkg)
    assert "Node.js >=18" in out
    assert "Express 4" in out


def test_derive_runtime_angular_scoped():
    out = R.derive_runtime({"dependencies": {"@angular/core": "~15.1.0"}})
    assert out == "Angular 15"


def test_derive_runtime_empty():
    assert R.derive_runtime({}) is None
    assert R.derive_runtime({"dependencies": {"unknownlib": "1"}}) is None
