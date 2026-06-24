"""
Tests for scripts/recon_patterns.py — Sprint 3 Item #1.

Covers the Python-migrated recon categories:
  Cat 9   OAuth / OIDC
  Cat 10  SPA / BFF
  Cat 11  Exposed Routes
  Cat 13  AI / LLM Integration (deterministic detection)
  Cat 14  CI/CD Supply Chain (unpinned GitHub Actions)
  Cat 15  Container Base Images
  Cat 17  Postinstall Scripts
  Cat 18  Security Headers & CORS
  Cat 19  Frontend Framework & XSS Patterns
  Cat 20  DOM-Based XSS Sources
  Cat 21  Client-Side Secrets
  Cat 22  WebSocket & Real-Time
  Cat 23  postMessage & iframe
  Cat 24  Client-Side Routing & Auth Guards
  Cat 27  GitHub Actions Workflow Privilege Hardening
  Cat 28  AI Coding Assistant & IDE Agent Configurations
  Cat 29  Mobile App Architecture & Platform Config

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

    def test_composite_action_descriptor_survives_build_named_action_dir(self):
        """A local GitHub composite action can legitimately live under
        .github/actions/build/action.yml. The "build" segment is source context
        here, not a generated build-output directory."""
        assert not rp._is_excluded(".github/actions/build/action.yml")
        assert not rp._is_excluded(".github/actions/build/action.yaml")
        assert rp._is_excluded(".github/actions/build/node_modules/dep/index.js")

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

    def test_walk_repo_skips_oversize_files(self, repo, monkeypatch, capsys):
        monkeypatch.setenv("APPSEC_MAX_FILE_BYTES", "1000")
        (repo / "src").mkdir()
        (repo / "src" / "small.ts").write_text("export const x = 1;\n", encoding="utf-8")
        (repo / "src" / "huge.json").write_text("x" * 2000, encoding="utf-8")

        rp._OVERSIZE_SKIPPED.clear()
        files = [p.relative_to(repo).as_posix() for p in rp._walk_repo(repo)]

        assert files == ["src/small.ts"]
        assert "src/huge.json" in rp._OVERSIZE_SKIPPED
        assert "skipped oversize file" in capsys.readouterr().err

    def test_run_all_reports_oversize_count(self, repo, monkeypatch):
        monkeypatch.setenv("APPSEC_MAX_FILE_BYTES", "1000")
        (repo / "huge.json").write_text("x" * 2000, encoding="utf-8")

        report = rp.run_all(repo)

        assert report["skipped_oversize_count"] == 1
        assert report["skipped_oversize"] == ["huge.json"]

    def test_grep_file_truncates_long_lines_and_ignores_missing_file(self, repo):
        path = repo / "app.ts"
        path.write_text('app.get("/admin", h);' + "x" * 450 + "\n", encoding="utf-8")

        matches = rp._grep_file(path, rp._CAT11_PATTERN)

        assert matches[0][1].endswith("…")
        assert rp._grep_file(repo / "missing.ts", rp._CAT11_PATTERN) == []


# ---------------------------------------------------------------------------
# Category 9 — OAuth / OIDC
# ---------------------------------------------------------------------------


class TestCat9OAuthOidc:
    def test_oauth_frontend_code_flow_without_pkce_and_state_flagged(self, repo):
        (repo / "frontend" / "src" / "app").mkdir(parents=True)
        (repo / "frontend" / "src" / "app" / "login.ts").write_text(
            "const url = `https://idp.example/authorize?response_type=code&client_id=${clientId}`;\n",
            encoding="utf-8",
        )

        out = rp.scan_oauth_oidc(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert "oauth-oidc-surface" in subs
        assert "oauth-code-without-pkce" in subs
        assert "oauth-missing-state" in subs
        assert any(f["subcategory"] == "oauth-code-without-pkce" and f["severity"] == "High" for f in out["findings"])

    def test_oauth_implicit_plain_pkce_ropc_and_refresh_storage_flagged(self, repo):
        (repo / "auth.ts").write_text(
            "const implicit = 'response_type=token';\n"
            "const method = 'code_challenge_method=plain';\n"
            "const grant = 'grant_type=password';\n"
            "localStorage.setItem('refresh_token', refreshToken);\n",
            encoding="utf-8",
        )

        out = rp.scan_oauth_oidc(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert {
            "oauth-implicit-flow",
            "oauth-pkce-plain",
            "oauth-ropc-grant",
            "oauth-refresh-token-browser-storage",
        } <= subs

    def test_oidc_missing_nonce_and_claim_validation_gap_flagged(self, repo):
        (repo / "server.py").write_text(
            "def callback():\n"
            "    id_token = request.args['id_token']\n"
            "    return exchange(id_token)\n",
            encoding="utf-8",
        )

        out = rp.scan_oauth_oidc(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert "oidc-missing-nonce" in subs
        assert "oidc-claim-validation-gap" in subs

    def test_redirect_secret_and_static_state_antipatterns_flagged(self, repo):
        (repo / "frontend").mkdir()
        (repo / "frontend" / "oauth.ts").write_text(
            "const client_secret = 'do-not-ship';\n"
            "const redirect_uri = 'http://evil.example/callback';\n"
            "if (allowedRedirects.some(r => redirect_uri.startsWith(r))) return redirect_uri;\n"
            "const state = 'state';\n",
            encoding="utf-8",
        )

        out = rp.scan_oauth_oidc(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert "oauth-client-secret-in-frontend" in subs
        assert "oauth-insecure-redirect-uri" in subs
        assert "oauth-redirect-uri-weak-match" in subs
        assert "oauth-static-state-or-nonce" in subs

    def test_run_all_includes_oauth_category(self, repo):
        (repo / "auth.ts").write_text("const url = '/authorize?response_type=token';\n", encoding="utf-8")
        out = rp.run_all(repo)
        assert "9" in out["categories"]
        assert any(f["subcategory"] == "oauth-implicit-flow" for f in out["categories"]["9"]["findings"])


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
# Categories 10, 19–24, 27–29
# ---------------------------------------------------------------------------


class TestAdditionalDeterministicCategories:
    def test_spa_without_bff_and_client_role_trust_flagged(self, repo):
        (repo / "app.ts").write_text(
            "localStorage.setItem('access_token', jwt);\n"
            "const isAdmin = jwtDecode(localStorage.getItem('access_token')).role === 'admin';\n",
            encoding="utf-8",
        )

        out = rp.scan_spa_bff(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert "spa-token-browser-storage" in subs
        assert "spa-client-side-role-trust" in subs
        assert "spa-without-bff-candidate" in subs
        assert any(f.get("anti_pattern") == "SPA without BFF" for f in out["findings"])

    def test_bff_marker_suppresses_spa_without_bff_candidate(self, repo):
        (repo / "app.ts").write_text(
            "localStorage.setItem('access_token', jwt);\n"
            "// Backend-for-Frontend uses httpOnly SameSite cookies for the real session.\n",
            encoding="utf-8",
        )

        out = rp.scan_spa_bff(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert "spa-token-browser-storage" in subs
        assert "spa-without-bff-candidate" not in subs

    def test_frontend_framework_and_unsafe_html_patterns_flagged(self, repo):
        (repo / "package.json").write_text(
            json.dumps({"dependencies": {"@angular/core": "19.0.0", "react": "18.2.0"}}),
            encoding="utf-8",
        )
        (repo / "component.tsx").write_text(
            "return <div dangerouslySetInnerHTML={{__html: userHtml}} />;\n",
            encoding="utf-8",
        )
        (repo / "safe-html.service.ts").write_text(
            "return sanitizer.bypassSecurityTrustHtml(userHtml);\n",
            encoding="utf-8",
        )

        out = rp.scan_frontend_xss(repo)
        subs = {f["subcategory"] for f in out["findings"]}
        frameworks = {f.get("framework") for f in out["findings"]}

        assert {"Angular", "React"} <= frameworks
        assert "frontend-unsafe-html-sink" in subs
        assert "frontend-sanitizer-bypass" in subs

    def test_dom_xss_source_sink_candidate_flagged(self, repo):
        (repo / "search.ts").write_text(
            "const q = new URLSearchParams(location.search).get('q');\n"
            "document.getElementById('out')!.innerHTML = q ?? '';\n",
            encoding="utf-8",
        )

        out = rp.scan_dom_xss(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert "dom-xss-source" in subs
        assert "dom-xss-source-sink-candidate" in subs

    def test_client_secret_pattern_flagged(self, repo):
        (repo / ".env").write_text("VITE_FIREBASE_APIKEY=abc123\n", encoding="utf-8")
        out = rp.scan_client_secrets(repo)
        assert out["count"] == 1
        assert out["findings"][0]["category"] == 21

    def test_websocket_pattern_flagged(self, repo):
        (repo / "socket.ts").write_text("const ws = new WebSocket('ws://chat.example/ws')\n", encoding="utf-8")
        out = rp.scan_websocket(repo)
        subs = {f["subcategory"] for f in out["findings"]}
        assert "websocket-surface" in subs
        assert "websocket-cleartext" in subs

    def test_websocket_server_auth_and_origin_candidates_flagged(self, repo):
        (repo / "server.ts").write_text(
            "const wss = new WebSocketServer({ server });\n"
            "wss.on('connection', socket => socket.send('ready'));\n",
            encoding="utf-8",
        )

        out = rp.scan_websocket(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert "websocket-missing-auth-candidate" in subs
        assert "websocket-origin-validation-gap" in subs

    def test_postmessage_pattern_flagged(self, repo):
        (repo / "frame.ts").write_text(
            "window.postMessage(payload, '*');\n"
            "window.addEventListener('message', onMsg);\n"
            "<iframe src=\"https://widgets.example\"></iframe>\n"
            "<a target=\"_blank\" href=\"https://example.test\">open</a>\n",
            encoding="utf-8",
        )
        out = rp.scan_postmessage(repo)
        subs = {f["subcategory"] for f in out["findings"]}
        assert "browser-message-surface" in subs
        assert "postmessage-wildcard-target" in subs
        assert "message-listener-no-origin-check" in subs
        assert "iframe-missing-sandbox" in subs
        assert "window-opener-noopener-missing" in subs

    def test_client_routing_guard_flagged(self, repo):
        (repo / "router.ts").write_text(
            "router.beforeEach(requireAuth)\n"
            "if (localStorage.getItem('role') === 'admin') next();\n",
            encoding="utf-8",
        )
        out = rp.scan_client_routing(repo)
        subs = {f["subcategory"] for f in out["findings"]}
        assert "client-side-auth-guard-surface" in subs
        assert "client-side-role-guard" in subs
        assert "guard-without-server-authority-candidate" in subs

    def test_mobile_android_architecture_antipatterns_flagged(self, repo):
        android = repo / "android" / "app" / "src" / "main"
        android.mkdir(parents=True)
        (android / "AndroidManifest.xml").write_text(
            textwrap.dedent(
                """
                <manifest>
                  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
                    <activity android:name=".DeepLinkActivity" android:exported="true">
                      <intent-filter>
                        <data android:scheme="myapp"/>
                      </intent-filter>
                    </activity>
                  </application>
                </manifest>
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        net = android / "res" / "xml"
        net.mkdir(parents=True)
        (net / "network_security_config.xml").write_text(
            '<network-security-config><base-config cleartextTrafficPermitted="true">'
            '<trust-anchors><certificates src="user"/></trust-anchors></base-config></network-security-config>\n',
            encoding="utf-8",
        )
        (android / "MainActivity.kt").write_text(
            "webView.settings.setJavaScriptEnabled(true)\n"
            "webView.addJavascriptInterface(bridge, \"Native\")\n"
            "WebView.setWebContentsDebuggingEnabled(true)\n"
            "getSharedPreferences(\"auth\", 0).getString(\"refresh_token\", null)\n"
            "val verifier = HostnameVerifier { _, _ -> true }\n",
            encoding="utf-8",
        )

        out = rp.scan_mobile_architecture(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert {
            "mobile-app-surface",
            "android-debuggable-enabled",
            "android-allowbackup-enabled",
            "android-cleartext-traffic-enabled",
            "android-exported-component-without-permission",
            "android-custom-url-scheme",
            "android-network-config-cleartext",
            "android-user-ca-trusted",
            "android-webview-js-bridge",
            "android-webview-javascript-enabled",
            "android-webview-debugging-enabled",
            "android-token-sharedpreferences",
            "android-accept-all-tls",
        } <= subs

    def test_mobile_ios_architecture_antipatterns_flagged(self, repo):
        ios = repo / "ios" / "App"
        ios.mkdir(parents=True)
        (ios / "Info.plist").write_text(
            textwrap.dedent(
                """
                <plist><dict>
                  <key>NSAllowsArbitraryLoads</key>
                  <true/>
                  <key>NSExceptionAllowsInsecureHTTPLoads</key>
                  <true/>
                  <key>CFBundleURLSchemes</key>
                </dict></plist>
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (ios / "WebView.swift").write_text(
            "import WebKit\n"
            "webView.configuration.userContentController.addScriptMessageHandler(self, name: \"bridge\")\n"
            "UserDefaults.standard.set(refreshToken, forKey: \"refresh_token\")\n"
            "let policy = kSecAttrAccessibleAlways\n"
            "let credential = URLCredential(trust: serverTrust)\n",
            encoding="utf-8",
        )

        out = rp.scan_mobile_architecture(repo)
        subs = {f["subcategory"] for f in out["findings"]}

        assert {
            "mobile-app-surface",
            "ios-ats-arbitrary-loads",
            "ios-ats-insecure-exception",
            "ios-custom-url-scheme-surface",
            "ios-webview-js-bridge",
            "ios-token-userdefaults",
            "ios-keychain-accessible-always",
            "ios-accept-all-tls",
        } <= subs

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

    def test_mcp_servers_are_classified_by_transport_origin_and_secret(self, repo):
        (repo / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "remote": {
                            "type": "sse",
                            "url": "https://mcp.example.test/sse",
                            "headers": {"Authorization": "Bearer ${MCP_TOKEN}"},
                        },
                        "registry": {
                            "command": "npx",
                            "args": ["-y", "@example/mcp-server"],
                        },
                        "secret": {
                            "command": "node",
                            "args": ["server.js"],
                            "env": {"API_KEY": "sk-test-hardcoded-secret"},
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        out = rp.scan_ai_assistant_configs(repo)
        mcp = {f["server"]: f for f in out["findings"] if f.get("server")}

        assert mcp["remote"]["subcategory"] == "mcp-remote-server"
        assert mcp["remote"]["transport"] == "sse"
        assert mcp["remote"]["origin"] == "remote URL"
        assert mcp["remote"]["severity"] == "High"

        assert mcp["registry"]["subcategory"] == "mcp-public-registry-server"
        assert mcp["registry"]["origin"] == "public registry (npx)"
        assert mcp["registry"]["severity"] == "High"

        assert mcp["secret"]["subcategory"] == "mcp-hardcoded-secret"
        assert mcp["secret"]["severity"] == "Critical"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Cat 13 — AI / LLM Integration (deterministic detection)
# ---------------------------------------------------------------------------


class TestCat13AiIntegration:
    # --- positive: must detect -------------------------------------------

    def test_plain_openai_chatbot(self, repo):
        """The #1 case the old 5-AND rule missed: a bare SDK import."""
        (repo / "chat.ts").write_text('import OpenAI from "openai";\nconst c = new OpenAI();\n', encoding="utf-8")
        out = rp.scan_ai_integration(repo)
        assert out["count"] >= 1
        subs = {f["subcategory"] for f in out["findings"]}
        assert "llm-sdk" in subs

    def test_langchain_rag(self, repo):
        (repo / "rag.py").write_text(
            "from langchain.prompts import ChatPromptTemplate\nimport chromadb\n",
            encoding="utf-8",
        )
        out = rp.scan_ai_integration(repo)
        assert out["count"] >= 1
        subs = {f["subcategory"] for f in out["findings"]}
        assert {"llm-sdk", "prompt-framework", "vector-db"} & subs

    def test_agent_stack(self, repo):
        (repo / "agent.py").write_text("executor = AgentExecutor(agent=a, tools=t)\n", encoding="utf-8")
        out = rp.scan_ai_integration(repo)
        assert out["count"] >= 1
        assert any(f["subcategory"] == "agent-framework" for f in out["findings"])

    def test_sdkless_rest_integration_weak_path(self, repo):
        """No SDK token — detected via the anchored weak rule:
        prompt-construction + model-config."""
        (repo / "llm.py").write_text(
            'system_prompt = "You are a helpful assistant"\n'
            'r = requests.post(url, json={"temperature": 0.7, "messages": msgs})\n',
            encoding="utf-8",
        )
        out = rp.scan_ai_integration(repo)
        assert out["count"] >= 1
        subs = {f["subcategory"] for f in out["findings"]}
        assert "prompt-construction" in subs and "model-config" in subs

    def test_literal_model_id(self, repo):
        (repo / "config.yaml").write_text("model: gpt-4o\n", encoding="utf-8")
        out = rp.scan_ai_integration(repo)
        assert out["count"] >= 1
        assert any(f["subcategory"] == "model-name" for f in out["findings"])

    # --- negative: must NOT detect (false-positive guards) ----------------

    def test_classic_ml_not_detected(self, repo):
        """embedding + temperature (annealing) but NO prompt anchor → no fire."""
        (repo / "train.py").write_text(
            "from sklearn.manifold import TSNE\nembedding_dim = 128\ntemperature = 0.95  # simulated annealing\n",
            encoding="utf-8",
        )
        out = rp.scan_ai_integration(repo)
        assert out["count"] == 0

    def test_person_named_claude_not_detected(self, repo):
        """Bare 'claude' is a name, not a model id."""
        (repo / "users.py").write_text('claude = User(name="Claude", role="admin")\n', encoding="utf-8")
        out = rp.scan_ai_integration(repo)
        assert out["count"] == 0

    def test_lone_temperature_not_detected(self, repo):
        (repo / "thermostat.py").write_text("self.temperature = 21.5\n", encoding="utf-8")
        out = rp.scan_ai_integration(repo)
        assert out["count"] == 0

    def test_scattered_weak_signals_not_detected(self, repo):
        """Weak signals in SEPARATE files (scattered security vocabulary, e.g. a
        docs/taxonomy repo) must NOT trip the co-located weak rule."""
        (repo / "a.yaml").write_text("note: system prompt injection is a risk\n", encoding="utf-8")
        (repo / "b.yaml").write_text("note: embeddings can leak data\n", encoding="utf-8")
        (repo / "c.yaml").write_text("note: temperature of the reactor\n", encoding="utf-8")
        out = rp.scan_ai_integration(repo)
        assert out["count"] == 0

    def test_claude_tooling_dir_excluded(self, repo):
        """A Claude Code config mentioning api.anthropic.com must not flag the
        target as an LLM app — .claude/ is tooling, not application source."""
        cdir = repo / ".claude"
        cdir.mkdir()
        (cdir / "settings.local.json").write_text(
            '{"permissions":{"allow":["WebFetch(domain:api.anthropic.com)"]}}\n',
            encoding="utf-8",
        )
        out = rp.scan_ai_integration(repo)
        assert out["count"] == 0

    def test_empty_repo(self, repo):
        out = rp.scan_ai_integration(repo)
        assert out["count"] == 0
        assert out["category"] == 13


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
        (repo / "package.json").write_text(
            json.dumps({"scripts": {"postinstall": "./hook.sh"}, "dependencies": {"react": "18.2.0"}}),
            encoding="utf-8",
        )
        # Cat 18 signal
        (repo / "mw.ts").write_text("app.use(helmet());\n", encoding="utf-8")
        # Cat 10, 20–24 signals
        (repo / ".env").write_text("VITE_FIREBASE_APIKEY=abc\n", encoding="utf-8")
        (repo / "client.ts").write_text(
            "localStorage.setItem('access_token', jwt)\n"
            "const q = new URLSearchParams(location.search)\n"
            "document.body.innerHTML = q\n"
            "new WebSocket(url)\nwindow.postMessage('x','*')\nrouter.beforeEach(requireAuth)\n",
            encoding="utf-8",
        )
        # Cat 29 signal
        android = repo / "android" / "app" / "src" / "main"
        android.mkdir(parents=True)
        (android / "AndroidManifest.xml").write_text(
            '<manifest><application android:debuggable="true"/></manifest>\n',
            encoding="utf-8",
        )
        # Cat 28 signal
        (repo / "AGENTS.md").write_text("project instructions\n", encoding="utf-8")

        report = rp.run_all(repo)
        assert report["version"] == 1
        for cat_id in ("10", "11", "14", "15", "17", "18", "19", "20", "21", "22", "23", "24", "27", "28", "29"):
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
            "9",
            "10",
            "11",
            "13",
            "14",
            "15",
            "17",
            "18",
            "19",
            "20",
            "21",
            "22",
            "23",
            "24",
            "27",
            "28",
            "29",
        }

    @pytest.mark.parametrize(
        "cmd",
        [
            "spa-bff",
            "exposed-routes",
            "ai-integration",
            "ci-supply-chain",
            "container-images",
            "postinstall",
            "security-headers",
            "frontend-xss",
            "dom-xss",
            "client-secrets",
            "websocket",
            "postmessage",
            "client-routing",
            "gha-privileges",
            "ai-assistant-configs",
            "mobile-architecture",
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
