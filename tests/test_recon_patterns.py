"""
Tests for scripts/recon_patterns.py — Sprint 3 Item #1.

Covers the Python-migrated recon categories:
  Cat 11  Exposed Routes
  Cat 14  CI/CD Supply Chain (unpinned GitHub Actions)
  Cat 15  Container Base Images
  Cat 17  Postinstall Scripts
  Cat 18  Security Headers & CORS
  Cat 21  Client-Side Secrets
  Cat 22  WebSocket & Real-Time
  Cat 23  postMessage & iframe
  Cat 24  Client-Side Routing & Auth Guards
  Cat 27  GitHub Actions Workflow Privilege Hardening
  Cat 28  AI Coding Assistant & IDE Agent Configurations

Plus repo-walk behaviour, hard-exclude regression guards, and CLI smoke.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import recon_patterns as rp  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "recon_patterns.py"


@pytest.fixture
def repo(tmp_path):
    """Fresh repo fixture; individual tests populate files as needed."""
    return tmp_path


# ---------------------------------------------------------------------------
# Hard-exclude behaviour
# ---------------------------------------------------------------------------


class TestHardExcludes:
    @pytest.mark.parametrize(
        "path",
        [
            "node_modules/foo/package.json",
            "vendor/github.com/x/y.go",
            ".venv/lib/python3.10/site-packages/foo.py",
            "venv/lib/python3.10/site-packages/bar.py",
            ".venv-tests/lib/python3.10/site-packages/baz.py",
            "venv-prod/lib/foo.py",
            "venv_linux/lib/foo.py",
            ".tox/py310/lib/foo.py",
            ".gradle/caches/modules/x.jar",
            "dist/bundle.js",
            "build/output.js",
            "target/Foo.class",
            ".git/config",
            "__pycache__/foo.cpython-310.pyc",
            "Pods/GoogleSignIn/foo.framework",
            "bower_components/jquery/jquery.js",
        ],
    )
    def test_path_is_excluded(self, path):
        assert rp._is_excluded(path), f"{path} must be hard-excluded"

    def test_normal_source_included(self):
        assert not rp._is_excluded("src/auth/login.ts")
        assert not rp._is_excluded("services/api/app.py")

    def test_package_json_in_root_included(self):
        """The application's own package.json MUST be scanned (for Cat 17)."""
        assert not rp._is_excluded("package.json")

    def test_package_json_in_node_modules_excluded(self):
        """A package.json deep in node_modules is a dep, not app source.
        Hard-exclude wins over the 'always include manifests' whitelist."""
        assert rp._is_excluded("node_modules/foo/package.json")
        assert rp._is_excluded("scripts/node_modules/whatwg-url/package.json")

    def test_scan_exclude_errors_fall_back_to_builtin_dirs(self, monkeypatch):
        class BrokenExcludes:
            @staticmethod
            def is_always_included(_path):
                raise RuntimeError("bad exclude config")

            @staticmethod
            def is_excluded(_path):
                raise RuntimeError("bad exclude config")

        monkeypatch.setattr(rp, "_SCAN_EXCLUDES", True)
        monkeypatch.setattr(rp, "scan_excludes", BrokenExcludes)

        assert rp._is_excluded("coverage/report.js")
        assert not rp._is_excluded("src/app.ts")

    def test_walk_repo_skips_binary_unknown_files_and_records_manifest(self, repo):
        (repo / "src").mkdir()
        (repo / "src" / "app.ts").write_text("export const x = 1;\n", encoding="utf-8")
        (repo / "src" / "blob.bin").write_bytes(b"\0\1")
        (repo / "node_modules").mkdir()
        (repo / "node_modules" / "dep.ts").write_text("ignored\n", encoding="utf-8")
        outside = repo.parent / "outside.ts"
        outside.write_text("leak\n", encoding="utf-8")
        try:
            (repo / "src" / "outside-link.ts").symlink_to(outside)
        except OSError:
            pytest.skip("symlinks are not supported in this environment")

        manifest: list[str] = []
        files = [p.relative_to(repo).as_posix() for p in rp._walk_repo(repo, manifest=manifest)]

        assert files == ["src/app.ts"]
        assert manifest == ["src/app.ts"]

    def test_grep_file_truncates_long_lines_and_ignores_missing_file(self, repo):
        path = repo / "app.ts"
        path.write_text('app.get("/admin", h);' + "x" * 450 + "\n", encoding="utf-8")

        matches = rp._grep_file(path, rp._CAT11_PATTERN)

        assert matches[0][1].endswith("…")
        assert rp._grep_file(repo / "missing.ts", rp._CAT11_PATTERN) == []


# ---------------------------------------------------------------------------
# Category 11 — Exposed Routes
# ---------------------------------------------------------------------------


class TestCat11:
    def test_matches_admin_route(self, repo):
        (repo / "app.ts").write_text('app.get("/admin/users", handler);\n', encoding="utf-8")
        out = rp.scan_exposed_routes(repo)
        assert out["count"] == 1
        assert out["findings"][0]["file"] == "app.ts"

    def test_matches_actuator(self, repo):
        (repo / "src" / "Main.java").parent.mkdir(parents=True)
        (repo / "src" / "Main.java").write_text('@RequestMapping("/actuator")\nclass M {}\n', encoding="utf-8")
        out = rp.scan_exposed_routes(repo)
        assert out["count"] == 1

    def test_matches_swagger_and_graphiql(self, repo):
        (repo / "routes.ts").write_text(
            'app.get("/swagger", ui);\napp.get("/graphiql", gql);\n',
            encoding="utf-8",
        )
        out = rp.scan_exposed_routes(repo)
        assert out["count"] >= 2

    def test_shebang_does_not_match_env(self, repo):
        """Regression: `#!/usr/bin/env python3` must NOT match the /env
        exposed-route pattern."""
        (repo / "script.py").write_text("#!/usr/bin/env python3\n\nprint('hi')\n", encoding="utf-8")
        out = rp.scan_exposed_routes(repo)
        assert out["count"] == 0, f"shebang matched /env: {out['findings']}"

    def test_random_test_file_name_does_not_match(self, repo):
        """`src/test.ts` must NOT match the /test route pattern."""
        (repo / "src").mkdir()
        (repo / "src" / "mytest.ts").write_text("export const x = 'hello';\n", encoding="utf-8")
        out = rp.scan_exposed_routes(repo)
        assert out["count"] == 0

    def test_skips_non_source_extensions(self, repo):
        """Cat 11 only scans source-code extensions — markdown prose must
        be ignored even when it mentions /admin."""
        (repo / "README.md").write_text("The /admin endpoint is documented here.\n", encoding="utf-8")
        out = rp.scan_exposed_routes(repo)
        assert out["count"] == 0

    def test_hard_excluded_dir_not_scanned(self, repo):
        (repo / "node_modules").mkdir()
        (repo / "node_modules" / "pkg.ts").write_text('app.get("/admin", h);\n', encoding="utf-8")
        out = rp.scan_exposed_routes(repo)
        assert out["count"] == 0


# ---------------------------------------------------------------------------
# Category 14 — CI/CD Supply Chain
# ---------------------------------------------------------------------------


class TestCat14:
    def test_unpinned_action_tag_flagged(self, repo):
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            textwrap.dedent("""
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: actions/setup-node@v3
        """).strip()
            + "\n",
            encoding="utf-8",
        )
        out = rp.scan_ci_supply_chain(repo)
        assert out["count"] == 2
        kinds = {f["subcategory"] for f in out["findings"]}
        assert "unpinned-github-action" in kinds
        # Each finding carries the action ref and the tag
        for f in out["findings"]:
            assert "@" in f["action"]
            assert "v" in f["tag"]

    def test_sha_pinned_action_accepted(self, repo):
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            textwrap.dedent("""
            jobs:
              build:
                steps:
                  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        """).strip()
            + "\n",
            encoding="utf-8",
        )
        out = rp.scan_ci_supply_chain(repo)
        assert out["count"] == 0

    def test_local_action_not_flagged(self, repo):
        """`./local/action` references must not be flagged."""
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "jobs:\n  x:\n    steps:\n      - uses: ./actions/local@v1\n",
            encoding="utf-8",
        )
        out = rp.scan_ci_supply_chain(repo)
        unpinned = [f for f in out["findings"] if f["subcategory"] == "unpinned-github-action"]
        assert unpinned == []

    def test_non_workflow_files_and_unreadable_workflow_are_ignored(self, repo, monkeypatch):
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "notes.txt").write_text("- uses: actions/checkout@v4\n", encoding="utf-8")
        broken = wf / "broken.yml"
        broken.write_text("- uses: actions/checkout@v4\n", encoding="utf-8")
        original_read_text = Path.read_text

        def boom_for_broken(path, *args, **kwargs):
            if path == broken:
                raise OSError("unreadable")
            return original_read_text(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", boom_for_broken)

        assert rp.scan_ci_supply_chain(repo)["count"] == 0

    def test_gitlab_image_flagged(self, repo):
        (repo / ".gitlab-ci.yml").write_text(
            textwrap.dedent("""
            image: python:3.11
            build:
              script: echo hi
        """).strip()
            + "\n",
            encoding="utf-8",
        )
        out = rp.scan_ci_supply_chain(repo)
        kinds = {f["subcategory"] for f in out["findings"]}
        assert "gitlab-image" in kinds

    def test_unreadable_gitlab_ci_is_ignored(self, repo, monkeypatch):
        path = repo / ".gitlab-ci.yml"
        path.write_text("image: python:3.11\n", encoding="utf-8")
        original_read_text = Path.read_text

        def boom_for_gitlab(path_arg, *args, **kwargs):
            if path_arg == path:
                raise OSError("unreadable")
            return original_read_text(path_arg, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", boom_for_gitlab)

        assert rp.scan_ci_supply_chain(repo)["count"] == 0

    def test_no_workflows_no_findings(self, repo):
        out = rp.scan_ci_supply_chain(repo)
        assert out["count"] == 0


# ---------------------------------------------------------------------------
# Category 15 — Container base images
# ---------------------------------------------------------------------------


class TestCat15:
    def test_latest_dockerfile_image_flagged(self, repo):
        (repo / "Dockerfile").write_text("FROM node:latest\n", encoding="utf-8")
        out = rp.scan_container_images(repo)
        assert out["count"] == 1
        assert out["findings"][0]["subcategory"] == "latest-tag"

    def test_digest_pinned_image_accepted(self, repo):
        (repo / "Dockerfile").write_text("FROM node:20@sha256:" + "a" * 64 + "\n", encoding="utf-8")
        out = rp.scan_container_images(repo)
        assert out["count"] == 0

    def test_image_issue_classification_edges(self):
        assert rp._container_image_issue("scratch") is None
        assert rp._container_image_issue("nginx") == "missing-tag"
        assert rp._container_image_issue("nginx:latest") == "latest-tag"
        assert rp._container_image_issue("nginx:1.25") == "missing-digest"

    def test_compose_image_and_malformed_grep_result(self, repo, monkeypatch):
        compose = repo / "docker-compose.yml"
        compose.write_text("services:\n  app:\n    image: redis\n", encoding="utf-8")
        out = rp.scan_container_images(repo)
        assert out["findings"][0]["subcategory"] == "missing-tag"

        dockerfile = repo / "Dockerfile"
        dockerfile.write_text("FROM node\n", encoding="utf-8")
        monkeypatch.setattr(rp, "_grep_file", lambda *_args, **_kwargs: [(1, "FROM")])
        assert rp.scan_container_images(repo)["count"] == 0


# ---------------------------------------------------------------------------
# Category 17 — Postinstall Scripts
# ---------------------------------------------------------------------------


class TestCat17:
    def test_npm_postinstall_flagged(self, repo):
        (repo / "package.json").write_text(
            json.dumps(
                {
                    "name": "app",
                    "version": "1.0.0",
                    "scripts": {
                        "postinstall": "./scripts/setup.sh",
                        "test": "jest",
                    },
                }
            ),
            encoding="utf-8",
        )
        out = rp.scan_postinstall(repo)
        hooks = [f for f in out["findings"] if f["subcategory"] == "npm-lifecycle"]
        assert len(hooks) == 1
        assert hooks[0]["hook"] == "postinstall"
        assert "setup.sh" in hooks[0]["command"]

    def test_npm_multiple_lifecycle_hooks(self, repo):
        (repo / "package.json").write_text(
            json.dumps(
                {
                    "scripts": {
                        "preinstall": "node prep.js",
                        "postinstall": "node post.js",
                        "prepare": "husky install",
                        "prebuild": "clean.sh",
                        "test": "jest",  # must be ignored — not a lifecycle
                    },
                }
            ),
            encoding="utf-8",
        )
        out = rp.scan_postinstall(repo)
        hooks = {f["hook"] for f in out["findings"] if f["subcategory"] == "npm-lifecycle"}
        assert hooks == {"preinstall", "postinstall", "prepare", "prebuild"}

    def test_python_setup_py_shell_flagged(self, repo):
        (repo / "setup.py").write_text(
            "import os\nos.system('install extras')\nfrom setuptools import setup\nsetup()\n",
            encoding="utf-8",
        )
        out = rp.scan_postinstall(repo)
        kinds = {f["subcategory"] for f in out["findings"]}
        assert "python-setup-shell" in kinds

    def test_npmrc_ignore_scripts_flagged(self, repo):
        (repo / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
        out = rp.scan_postinstall(repo)
        kinds = {f["subcategory"] for f in out["findings"]}
        assert "npmrc-ignore-scripts" in kinds

    def test_clean_package_json_no_findings(self, repo):
        (repo / "package.json").write_text(json.dumps({"scripts": {"test": "jest", "build": "tsc"}}), encoding="utf-8")
        out = rp.scan_postinstall(repo)
        assert out["count"] == 0

    def test_invalid_package_json_and_non_dict_scripts_ignored(self, repo):
        (repo / "package.json").write_text("{not-json", encoding="utf-8")
        assert rp.scan_postinstall(repo)["count"] == 0

        (repo / "package.json").write_text(json.dumps({"scripts": ["postinstall"]}), encoding="utf-8")
        assert rp.scan_postinstall(repo)["count"] == 0

    def test_unreadable_npmrc_and_excluded_setup_py_are_ignored(self, repo, monkeypatch):
        npmrc = repo / ".npmrc"
        npmrc.write_text("ignore-scripts=true\n", encoding="utf-8")
        excluded_setup = repo / "node_modules" / "pkg" / "setup.py"
        excluded_setup.parent.mkdir(parents=True)
        excluded_setup.write_text("import os\nos.system('x')\n", encoding="utf-8")
        original_read_text = Path.read_text

        def boom_for_npmrc(path_arg, *args, **kwargs):
            if path_arg == npmrc:
                raise OSError("unreadable")
            return original_read_text(path_arg, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", boom_for_npmrc)

        assert rp.scan_postinstall(repo)["count"] == 0

    def test_node_modules_package_json_ignored(self, repo):
        """Dep-tree package.json must not be scanned."""
        nm = repo / "node_modules" / "dep"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            json.dumps({"scripts": {"postinstall": "node malicious.js"}}), encoding="utf-8"
        )
        out = rp.scan_postinstall(repo)
        assert out["count"] == 0, "node_modules/**/package.json must not contribute to postinstall findings"


# ---------------------------------------------------------------------------
# Category 18 — Security Headers & CORS
# ---------------------------------------------------------------------------


class TestCat18:
    def test_helmet_matched(self, repo):
        (repo / "server.ts").write_text(
            "import helmet from 'helmet';\napp.use(helmet());\n",
            encoding="utf-8",
        )
        out = rp.scan_security_headers(repo)
        assert out["count"] >= 1

    def test_csp_header_matched(self, repo):
        (repo / "middleware.js").write_text(
            'res.setHeader("Content-Security-Policy", "default-src \'self\'");\n',
            encoding="utf-8",
        )
        out = rp.scan_security_headers(repo)
        assert out["count"] == 1

    def test_cors_middleware_matched(self, repo):
        (repo / "app.py").write_text(
            "from fastapi.middleware.cors import CorsMiddleware\n",
            encoding="utf-8",
        )
        out = rp.scan_security_headers(repo)
        assert out["count"] == 1

    def test_no_header_no_findings(self, repo):
        (repo / "plain.ts").write_text("export const x = 1;\n", encoding="utf-8")
        out = rp.scan_security_headers(repo)
        assert out["count"] == 0


# ---------------------------------------------------------------------------
# Categories 21–24, 27, 28
# ---------------------------------------------------------------------------


class TestAdditionalDeterministicCategories:
    def test_client_secret_pattern_flagged(self, repo):
        (repo / ".env").write_text("VITE_FIREBASE_APIKEY=abc123\n", encoding="utf-8")
        out = rp.scan_client_secrets(repo)
        assert out["count"] == 1
        assert out["findings"][0]["category"] == 21

    def test_websocket_pattern_flagged(self, repo):
        (repo / "socket.ts").write_text("const ws = new WebSocket(url)\n", encoding="utf-8")
        out = rp.scan_websocket(repo)
        assert out["count"] == 1

    def test_postmessage_pattern_flagged(self, repo):
        (repo / "frame.ts").write_text("window.addEventListener('message', onMsg)\n", encoding="utf-8")
        out = rp.scan_postmessage(repo)
        assert out["count"] == 1

    def test_client_routing_guard_flagged(self, repo):
        (repo / "router.ts").write_text("router.beforeEach(requireAuth)\n", encoding="utf-8")
        out = rp.scan_client_routing(repo)
        assert out["count"] == 1

    def test_github_actions_privilege_patterns_flagged(self, repo):
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "pr.yml").write_text(
            textwrap.dedent("""
            on:
              pull_request_target:
            permissions: write-all
            jobs:
              test:
                runs-on: [self-hosted, linux]
                steps:
                  - run: echo hi
        """).strip()
            + "\n",
            encoding="utf-8",
        )
        out = rp.scan_gha_privileges(repo)
        kinds = {f["subcategory"] for f in out["findings"]}
        assert {"pull-request-target", "permissions-write-all", "self-hosted-runner"} <= kinds

    def test_github_actions_scope_write_and_missing_permissions_flagged(self, repo):
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "write.yml").write_text("permissions:\n  contents: write\n", encoding="utf-8")
        (wf / "missing.yaml").write_text("jobs:\n  test:\n    runs-on: ubuntu-latest\n", encoding="utf-8")
        (wf / "notes.txt").write_text("permissions:\n  contents: write\n", encoding="utf-8")
        out = rp.scan_gha_privileges(repo)
        kinds = {f["subcategory"] for f in out["findings"]}
        assert "permissions-write" in kinds
        assert "missing-permissions-block" in kinds

    def test_unreadable_workflow_is_ignored_by_privilege_scan(self, repo, monkeypatch):
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        broken = wf / "broken.yml"
        broken.write_text("permissions: write-all\n", encoding="utf-8")
        original_read_text = Path.read_text

        def boom_for_broken(path_arg, *args, **kwargs):
            if path_arg == broken:
                raise OSError("unreadable")
            return original_read_text(path_arg, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", boom_for_broken)

        assert rp.scan_gha_privileges(repo)["count"] == 0

    def test_ai_assistant_config_and_dangerous_pattern_flagged(self, repo):
        d = repo / ".claude"
        d.mkdir()
        (d / "settings.json").write_text('{"permissions":["Bash(*)"]}\n', encoding="utf-8")
        out = rp.scan_ai_assistant_configs(repo)
        kinds = {f["subcategory"] for f in out["findings"]}
        assert "assistant-config-present" in kinds
        assert "dangerous-assistant-config-pattern" in kinds

    def test_ai_assistant_scan_handles_dirs_duplicates_mcp_and_stat_errors(self, repo, monkeypatch):
        agents = repo / ".claude" / "agents"
        agents.mkdir(parents=True)
        (agents / "sec.md").write_text("rm -rf /tmp/x\n", encoding="utf-8")
        (repo / ".mcp.json").write_text('{"mcpServers":{}}\n', encoding="utf-8")
        nested = repo / "nested"
        nested.mkdir()
        (nested / "mcp.json").write_text("{}", encoding="utf-8")
        excluded = repo / "node_modules" / ".claude" / "settings.json"
        excluded.parent.mkdir(parents=True)
        excluded.write_text('{"permissions":["Bash(*)"]}\n', encoding="utf-8")

        original_is_file = Path.is_file
        original_stat = Path.stat

        def is_file_for_sec(path_arg):
            if path_arg.name == "sec.md":
                return True
            return original_is_file(path_arg)

        def maybe_boom_stat(path_arg, *args, **kwargs):
            if path_arg.name == "sec.md":
                raise OSError("stat failed")
            return original_stat(path_arg, *args, **kwargs)

        monkeypatch.setattr(Path, "is_file", is_file_for_sec)
        monkeypatch.setattr(Path, "stat", maybe_boom_stat)

        out = rp.scan_ai_assistant_configs(repo)
        files = {f["file"] for f in out["findings"] if f["subcategory"] == "assistant-config-present"}
        assert ".claude/agents/sec.md" in files
        assert ".mcp.json" in files
        assert "nested/mcp.json" in files
        assert all(not f.startswith("node_modules/") for f in files)
        sec = [f for f in out["findings"] if f["file"] == ".claude/agents/sec.md" and f["line"] is None][0]
        assert sec["size"] is None


# ---------------------------------------------------------------------------
# run_all + CLI
# ---------------------------------------------------------------------------


class TestRunAll:
    def test_end_to_end(self, repo):
        # Cat 11 signal
        (repo / "app.ts").write_text('app.get("/admin", h);\n', encoding="utf-8")
        # Cat 14 signal
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")
        # Cat 15 signal
        (repo / "Dockerfile").write_text("FROM python\n", encoding="utf-8")
        # Cat 17 signal
        (repo / "package.json").write_text(json.dumps({"scripts": {"postinstall": "./hook.sh"}}), encoding="utf-8")
        # Cat 18 signal
        (repo / "mw.ts").write_text("app.use(helmet());\n", encoding="utf-8")
        # Cat 21–24 signals
        (repo / ".env").write_text("VITE_FIREBASE_APIKEY=abc\n", encoding="utf-8")
        (repo / "client.ts").write_text(
            "new WebSocket(url)\nwindow.postMessage('x','*')\nrouter.beforeEach(requireAuth)\n",
            encoding="utf-8",
        )
        # Cat 28 signal
        (repo / "AGENTS.md").write_text("project instructions\n", encoding="utf-8")

        report = rp.run_all(repo)
        assert report["version"] == 1
        for cat_id in ("11", "14", "15", "17", "18", "21", "22", "23", "24", "27", "28"):
            assert report["categories"][cat_id]["count"] >= 1

    def test_scan_manifest(self, repo):
        (repo / "src").mkdir()
        (repo / "src" / "app.ts").write_text('app.get("/admin", h);\n', encoding="utf-8")
        (repo / "README.md").write_text("docs\n", encoding="utf-8")
        (repo / "node_modules").mkdir()
        (repo / "node_modules" / "dep.ts").write_text("ignored\n", encoding="utf-8")

        report = rp.run_all(repo, include_manifest=True)

        assert report["scan_manifest"] == ["README.md", "src/app.ts"]
        assert report["scan_manifest_count"] == 2


class TestCLI:
    def test_all_subcommand(self, repo):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "all", "--repo-root", str(repo)],
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(r.stdout)
        assert set(out["categories"].keys()) == {
            "11",
            "14",
            "15",
            "17",
            "18",
            "21",
            "22",
            "23",
            "24",
            "27",
            "28",
        }

    @pytest.mark.parametrize(
        "cmd",
        [
            "exposed-routes",
            "ci-supply-chain",
            "container-images",
            "postinstall",
            "security-headers",
            "client-secrets",
            "websocket",
            "postmessage",
            "client-routing",
            "gha-privileges",
            "ai-assistant-configs",
        ],
    )
    def test_category_subcommands(self, cmd, repo):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), cmd, "--repo-root", str(repo)],
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(r.stdout)
        assert "findings" in out
        assert "count" in out

    def test_missing_repo(self, tmp_path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "all", "--repo-root", str(tmp_path / "nope")],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1

    def test_manifest_requires_all_command(self, repo, tmp_path):
        r = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "exposed-routes",
                "--repo-root",
                str(repo),
                "--scan-manifest",
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert "requires command 'all'" in r.stderr

        manifest_file = tmp_path / "out" / "manifest.txt"
        r2 = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "all",
                "--repo-root",
                str(repo),
                "--manifest-file",
                str(manifest_file),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(r2.stdout)
        assert out["scan_manifest"] == []
        assert manifest_file.read_text(encoding="utf-8") == "\n"
