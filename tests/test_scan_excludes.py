"""
Tests for scripts/scan_excludes.py — the centralised scan-exclusion loader
(Sprint 1 Item F).

Three responsibilities covered:
  1. YAML loader schema/shape validation
  2. is_excluded() + is_always_included() whitelist-wins semantics
  3. glob_exclusion_string() determinism and opt-in relief
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import scan_excludes  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent
YAML_FILE = PLUGIN_ROOT / "data" / "scan-excludes.yaml"
SCRIPT = PLUGIN_ROOT / "scripts" / "scan_excludes.py"


def _minimal_excludes(**overrides):
    data = {
        "version": 1,
        "directories": [],
        "path_prefixes": [],
        "file_patterns": [],
        "always_include": {
            "file_patterns": [],
            "path_prefixes": [],
        },
        "opt_in": {},
    }
    data.update(overrides)
    return data


def _write_yaml(path: Path, data):
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _reset_cache():
    scan_excludes._reset_cache_for_tests()
    yield
    scan_excludes._reset_cache_for_tests()


# ---------------------------------------------------------------------------
# YAML schema / shape
# ---------------------------------------------------------------------------


class TestYamlShape:
    def test_yaml_exists(self):
        assert YAML_FILE.is_file()

    def test_version_is_1(self):
        data = yaml.safe_load(YAML_FILE.read_text(encoding="utf-8"))
        assert data.get("version") == 1

    def test_required_top_keys(self):
        data = yaml.safe_load(YAML_FILE.read_text(encoding="utf-8"))
        for key in ("directories", "path_prefixes", "file_patterns", "always_include"):
            assert key in data, f"top-level key missing: {key}"

    def test_always_include_has_both_subkeys(self):
        data = yaml.safe_load(YAML_FILE.read_text(encoding="utf-8"))
        ai = data["always_include"]
        assert "file_patterns" in ai
        assert "path_prefixes" in ai

    def test_loader_round_trips(self):
        data = scan_excludes.load_excludes()
        assert isinstance(data["directories"], list)
        assert "node_modules" in data["directories"]
        # Sprint 1 additions
        assert "examples" in data["directories"]
        assert "tests" in data["directories"]
        assert "docs/security/" in data["path_prefixes"]

    def test_always_include_has_asciidoc(self):
        data = scan_excludes.load_excludes()
        patterns = data["always_include"]["file_patterns"]
        assert "*.adoc" in patterns, "AsciiDoc source docs must be whitelisted"
        assert "*.asciidoc" in patterns
        assert "*.proto" in patterns
        assert any(p.startswith("openapi") for p in patterns)

    def test_always_include_has_adr_prefixes(self):
        data = scan_excludes.load_excludes()
        prefixes = data["always_include"]["path_prefixes"]
        assert "docs/adr/" in prefixes
        assert "docs/decisions/" in prefixes
        assert "docs/architecture/" not in prefixes


class TestYamlResolutionAndValidation:
    def test_yaml_path_prefers_env_override(self, tmp_path, monkeypatch):
        override = _write_yaml(tmp_path / "custom-scan-excludes.yaml", _minimal_excludes())
        monkeypatch.setenv("SCAN_EXCLUDES_YAML", str(override))
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)

        assert scan_excludes._yaml_path() == override

    def test_yaml_path_uses_plugin_root_when_present(self, tmp_path, monkeypatch):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        plugin_yaml = _write_yaml(data_dir / "scan-excludes.yaml", _minimal_excludes())
        monkeypatch.delenv("SCAN_EXCLUDES_YAML", raising=False)
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))

        assert scan_excludes._yaml_path() == plugin_yaml

    def test_loader_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="scan-excludes.yaml not found"):
            scan_excludes.load_excludes(str(tmp_path / "missing.yaml"))

    def test_loader_requires_mapping(self, tmp_path):
        fixture = tmp_path / "scan-excludes.yaml"
        fixture.write_text("- not\n- a mapping\n", encoding="utf-8")

        with pytest.raises(ValueError, match="expected top-level mapping"):
            scan_excludes.load_excludes(str(fixture))

    def test_loader_rejects_unsupported_version(self, tmp_path):
        fixture = _write_yaml(tmp_path / "scan-excludes.yaml", {"version": 2})

        with pytest.raises(ValueError, match="unsupported version"):
            scan_excludes.load_excludes(str(fixture))

    def test_loader_rejects_non_list_collections(self, tmp_path):
        fixture = _write_yaml(
            tmp_path / "scan-excludes.yaml",
            _minimal_excludes(directories="node_modules"),
        )

        with pytest.raises(ValueError, match="'directories' must be a list"):
            scan_excludes.load_excludes(str(fixture))

    def test_loader_normalises_missing_optional_collections(self, tmp_path):
        fixture = _write_yaml(tmp_path / "scan-excludes.yaml", {"version": 1})

        data = scan_excludes.load_excludes(str(fixture))

        assert data["directories"] == []
        assert data["path_prefixes"] == []
        assert data["file_patterns"] == []
        assert data["always_include"]["file_patterns"] == []
        assert data["always_include"]["path_prefixes"] == []
        assert data["opt_in"] == {}
        # max_file_bytes defaults when omitted.
        assert data["max_file_bytes"] == scan_excludes.DEFAULT_MAX_FILE_BYTES

    def test_loader_rejects_non_int_max_file_bytes(self, tmp_path):
        fixture = _write_yaml(tmp_path / "scan-excludes.yaml", {"version": 1, "max_file_bytes": "big"})
        with pytest.raises(ValueError, match="max_file_bytes must be an integer"):
            scan_excludes.load_excludes(str(fixture))


# ---------------------------------------------------------------------------
# max_file_bytes() / is_oversize() — per-file byte cap
# ---------------------------------------------------------------------------


class TestMaxFileBytes:
    def test_shipped_yaml_declares_cap(self):
        data = scan_excludes.load_excludes()
        assert isinstance(data["max_file_bytes"], int)
        assert data["max_file_bytes"] > 0

    def test_yaml_value_used(self, tmp_path, monkeypatch):
        monkeypatch.delenv("APPSEC_MAX_FILE_BYTES", raising=False)
        excludes = _minimal_excludes(max_file_bytes=512)
        assert scan_excludes.max_file_bytes(excludes) == 512

    def test_env_overrides_yaml(self, monkeypatch):
        monkeypatch.setenv("APPSEC_MAX_FILE_BYTES", "777")
        excludes = _minimal_excludes(max_file_bytes=512)
        assert scan_excludes.max_file_bytes(excludes) == 777

    def test_bad_env_falls_back_to_yaml(self, monkeypatch):
        monkeypatch.setenv("APPSEC_MAX_FILE_BYTES", "not-a-number")
        excludes = _minimal_excludes(max_file_bytes=512)
        assert scan_excludes.max_file_bytes(excludes) == 512

    def test_is_oversize_respects_limit(self, tmp_path):
        f = tmp_path / "blob.json"
        f.write_text("x" * 2000, encoding="utf-8")
        assert scan_excludes.is_oversize(f, limit=1000)
        assert not scan_excludes.is_oversize(f, limit=5000)

    def test_is_oversize_disabled_when_cap_not_positive(self, tmp_path):
        f = tmp_path / "blob.json"
        f.write_text("x" * 2000, encoding="utf-8")
        assert not scan_excludes.is_oversize(f, limit=0)

    def test_is_oversize_missing_file_returns_false(self, tmp_path):
        assert not scan_excludes.is_oversize(tmp_path / "nope.json", limit=1)


# ---------------------------------------------------------------------------
# is_excluded() — exclusion semantics
# ---------------------------------------------------------------------------


class TestIsExcluded:
    @pytest.mark.parametrize(
        "path",
        [
            "node_modules/react/index.js",
            "dist/bundle.js",
            "examples/demo.ts",
            "tests/test_auth.py",
            "e2e/login.spec.ts",
            "cypress/e2e/login.spec.ts",
            "src/fixtures/mock-tokens.json",
            "src/__fixtures__/user.json",
            "testdata/auth.json",
            "mocks/payment.ts",
            "storybook/Button.stories.tsx",
            ".cache/foo",
            "logs/server.log",
            ".github/pull_request_template.md",
            "docs/security/threat-model.md",
            "docs/images/diagram.png",
            "docs/architecture/diagram.png",
            "docs/site/index.html",
            ".github/ISSUE_TEMPLATE/bug.md",
            "third_party/vendored-lib/main.py",
            "src/foo.min.js",
            "src/types/api.d.ts",
            "src/generated/protocol.pb.go",
            "src/generated/protocol.pb.ts",
            "src/generated/protocol_pb.ts",
            "components/Button.stories.tsx",
            # Colocated tests (non-JS naming conventions)
            "services/user_test.go",
            "app/auth/test_login.py",
            "app/auth/login_test.py",
            "lib/order_spec.rb",
            "src/Auth/LoginTests.cs",
            "src/api/UserControllerTest.java",
            # Lockfiles (body has no signal beyond manifest)
            "package-lock.json",
            "frontend/yarn.lock",
            "services/api/Cargo.lock",
            "gradle.lockfile",
            # Generated code
            "proto/user_pb2.py",
            "lib/models/user.freezed.dart",
            "Forms/MainForm.designer.cs",
            # Generated coverage / report output
            ".nyc_output/out.json",
            "lcov.info",
            "coverage.xml",
            # Documents / packaged binaries
            "docs/manual.pdf",
            "build/app-release.apk",
            "dist/pkg.whl",
            # IaC / build caches
            ".terraform/providers/registry.tf",
            "terraform/.terraform/providers/aws.zip",
            ".aws-sam/build/template.yaml",
            "cdk.out/tree.json",
            "services/.yarn/cache/lodash.zip",
            ".pnpm-store/v3/files/foo",
            ".vite/deps/react.js",
            ".nox/py310/tmp.py",
            ".hypothesis/examples/foo",
            "playwright-report/index.html",
        ],
    )
    def test_excluded_paths(self, path):
        assert scan_excludes.is_excluded(path), f"{path} should be excluded"

    @pytest.mark.parametrize(
        "path",
        [
            "src/auth/login.ts",
            "services/auth/routes.py",
            "internal/handlers/admin.go",
            "app/controllers/session_controller.rb",
            "Dockerfile",
            ".env.production",
            ".github/workflows/ci.yml",
            "migrations/001_create_users.sql",
            "api/schema.graphql",
            "api/schema.gql",
            ".github/dependabot.yml",
            ".npmrc",
            ".yarnrc.yml",
            "CODEOWNERS",
            # Substring-trap guards — these contain test/cache/dist/lock as a
            # SUBSTRING but are real source. Exact-segment matching must NOT
            # exclude them (a substring-based filter would be a quality bug).
            "src/cache/redis_client.ts",  # app caching layer (cache poisoning surface)
            "services/attestation/verify.go",  # SLSA/supply-chain attestation
            "app/distribution/router.py",  # "dist" substring
            "src/contest/leaderboard.ts",  # "test" substring
            "lib/blocklist/loader.go",  # "lock" substring
            "internal/latest/handler.go",  # "test" substring
            # Segment/basename false-positive guards — real source, not
            # vendored output or test data.
            "src/external/payment_gateway.ts",
            "external/auth_service/src/main.go",
            "src/deps/auth.ts",
            "deps/payment/client.py",
            "bin/server.ts",
            "src/logs/audit_logger.py",
            "logs/audit_logger.py",
            "site/app.py",
            "site/server.ts",
            "src/reactive-widget.js",
            "src/chartSigner.js",
            "src/bootstrapAuth.js",
            "src/main.js",
            "src/runtime.js",
        ],
    )
    def test_included_paths(self, path):
        assert not scan_excludes.is_excluded(path), f"{path} should be included"


# ---------------------------------------------------------------------------
# Whitelist wins — always_include overrides directory excludes
# ---------------------------------------------------------------------------


class TestWhitelistWins:
    @pytest.mark.parametrize(
        "path",
        [
            "docs/adr/0001-jwt-rotation.adoc",
            "docs/decisions/0042-token-format.md",  # under path_prefix
            "docs/architecture/c4.adoc",
            "arc42/08_concepts.adoc",
            "any/path/to/openapi.yaml",
            "api/service.proto",
            "examples/openapi.yaml",  # whitelist wins over dir exclude
            "tests/api-contract.proto",  # whitelist wins over tests/
            "docs/README.adoc",
        ],
    )
    def test_always_included_survives_exclusion(self, path):
        assert scan_excludes.is_always_included(path), f"{path} must be whitelisted (matches always_include)"
        assert not scan_excludes.is_excluded(path), f"{path} is whitelisted — is_excluded must return False"

    def test_whitelist_does_not_catch_everything(self):
        """Negative sanity check — plain .md files in docs/ are NOT whitelisted."""
        assert not scan_excludes.is_always_included("docs/foo.md")

    # ---- Manifests and container descriptors in excluded dirs ----

    @pytest.mark.parametrize(
        "path",
        [
            "tests/.env.production",  # .env in tests/
            "examples/Dockerfile",  # Dockerfile in examples/
            "examples/docker-compose.yml",
            "e2e/docker-compose.yaml",
            "third_party/package.json",
            "storybook/Cargo.toml",
            "node_modules/my-pkg/Dockerfile",  # Dockerfile in node_modules (edge!)
        ],
    )
    def test_manifests_and_containers_win_over_exclude(self, path):
        """Category-2 whitelist: manifests and Dockerfiles inside otherwise-
        excluded directories must still be read — they are fine-grained
        security signals (committed .env, unpinned base image) that the
        coarse directory-level exclude would otherwise swallow."""
        assert scan_excludes.is_always_included(path), (
            f"{path} must be whitelisted — manifests/Dockerfiles/env files "
            f"are always security-relevant regardless of location"
        )
        assert not scan_excludes.is_excluded(path)

    # ---- Secret / crypto material in any location ----

    @pytest.mark.parametrize(
        "path",
        [
            "tests/fixtures/leaked.pem",
            "examples/keys/server.key",
            "third_party/ca-bundle.crt",
            ".env",
            "config/.env.staging",
        ],
    )
    def test_secret_material_is_never_excluded(self, path):
        """Category-3 whitelist: .env, .pem, .key, .crt, .p12, .jks files
        must never be overlooked by the scanner."""
        assert scan_excludes.is_always_included(path), (
            f"{path} must be whitelisted — secret/crypto material must be "
            f"readable by the scanner regardless of directory"
        )
        assert not scan_excludes.is_excluded(path)

    # ---- CI workflows ----

    def test_github_workflows_are_included(self):
        """CI workflow files are the primary signal for Cat 14 (unpinned
        Actions) and Cat 27 (privilege hardening) — always readable."""
        assert not scan_excludes.is_excluded(".github/workflows/ci.yml")
        assert not scan_excludes.is_excluded(".github/workflows/release.yaml")
        assert scan_excludes.is_excluded(".github/workflows/screenshot.png")

    def test_leading_dot_slash_is_normalised_for_prefix_matches(self):
        excludes = _minimal_excludes(
            always_include={
                "file_patterns": [],
                "path_prefixes": [".github/workflows/"],
            }
        )

        assert scan_excludes.is_always_included("./.github/workflows/ci.yml", excludes)


# ---------------------------------------------------------------------------
# CI / CD pipeline descriptors — must be included across every provider
# ---------------------------------------------------------------------------


class TestCICoverage:
    """Every major CI/CD pipeline descriptor format must be readable by the
    scanner. These files carry Cat 14 (unpinned Actions / pinned base images),
    Cat 17 (postinstall hooks), Cat 26 (ecosystem install integrity), and
    Cat 27 (privilege hardening) signals. Missing even one provider means
    that repo's supply-chain surface goes unanalyzed."""

    @pytest.mark.parametrize(
        "path",
        [
            # GitHub Actions
            ".github/workflows/ci.yml",
            ".github/workflows/release.yaml",
            ".github/actions/reusable/action.yml",
            # Other providers
            ".gitlab-ci.yml",
            ".gitlab-ci.yaml",
            "Jenkinsfile",
            "Jenkinsfile.release",
            "jenkins/Jenkinsfile.deploy",
            "azure-pipelines.yml",
            "azure-pipelines.yaml",
            ".circleci/config.yml",
            ".travis.yml",
            "bitbucket-pipelines.yml",
            ".buildkite/pipeline.yml",
            ".drone.yml",
            ".woodpecker.yml",
            "cloudbuild.yaml",
            # Self-hosted Git forges
            ".gitea/workflows/ci.yml",
            ".forgejo/workflows/ci.yml",
            # Dependency / update tooling
            "renovate.json",
            ".renovaterc.json",
            ".renovaterc",
            # Pre-commit hooks
            ".pre-commit-config.yaml",
            ".pre-commit-config.yml",
            # IaC directories
            "k8s/deployment.yaml",
            "kubernetes/ingress.yaml",
            "helm/values.yaml",
            "terraform/main.tf",
            "ansible/playbook.yml",
        ],
    )
    def test_ci_file_is_included(self, path):
        assert not scan_excludes.is_excluded(path)

    @pytest.mark.parametrize(
        "path",
        [
            "examples/.gitlab-ci.yml",  # demo dir — file-pattern whitelist wins
            "third_party/Jenkinsfile",  # vendored — file-pattern whitelist wins
            "examples/azure-pipelines.yml",
        ],
    )
    def test_ci_file_survives_excluded_parent(self, path):
        """CI files inside otherwise-excluded directories must still be
        readable when the filename itself is whitelisted."""
        assert not scan_excludes.is_excluded(path), f"{path} must survive exclusion — CI file whitelist wins"


# ---------------------------------------------------------------------------
# Binary / build artifacts — must never slip through
# ---------------------------------------------------------------------------


class TestBinaryAndBuildArtifactExclusion:
    """Every common binary, build-output, and toolchain-cache pattern must
    be excluded. Slipping one in dumps irrelevant bytes into the LLM context
    and produces false-positive Cat 12 (hardcoded secrets) matches on
    compiled/obfuscated content."""

    @pytest.mark.parametrize(
        "path",
        [
            # Package manager / build dirs (baseline)
            "node_modules/react/index.js",
            "vendor/github.com/foo/bar/main.go",
            "dist/bundle.js",
            "build/output.js",
            "target/classes/Main.class",
            "out/index.html",
            "coverage/lcov.info",
            ".next/static/chunk.js",
            ".nuxt/dist/app.js",
        ],
    )
    def test_classic_build_dirs_excluded(self, path):
        assert scan_excludes.is_excluded(path)

    @pytest.mark.parametrize(
        "path",
        [
            ".venv/lib/python3.10/site-packages/foo.py",
            "venv/lib/python3.11/site-packages/bar.py",
            ".tox/py310/lib/foo.py",
            ".pytest_cache/v/cache/nodeids",
            ".mypy_cache/3.10/foo.json",
            ".ruff_cache/0.1.0/foo",
            ".pyre/types.json",
        ],
    )
    def test_python_envs_and_caches_excluded(self, path):
        assert scan_excludes.is_excluded(path), (
            f"{path} must be excluded — Python virtualenvs and tool caches contain thousands of irrelevant files"
        )

    @pytest.mark.parametrize(
        "path",
        [
            ".gradle/caches/modules-2/foo.jar",
            "bin/Debug/Foo.dll",
            "obj/Debug/Foo.obj",
            "Pods/GoogleSignIn/foo.framework",
        ],
    )
    def test_jvm_dotnet_ios_build_dirs_excluded(self, path):
        assert scan_excludes.is_excluded(path)

    @pytest.mark.parametrize(
        "path",
        [
            ".idea/workspace.xml",
            ".vscode/settings.json",
            ".vs/config/applicationhost.config",
        ],
    )
    def test_ide_configs_excluded(self, path):
        assert scan_excludes.is_excluded(path), (
            f"{path} must be excluded — IDE config files are developer-local, "
            f"never security-relevant (unlike .claude/ which IS scanned for Cat 28)"
        )

    @pytest.mark.parametrize(
        "path",
        [
            # Native binary objects anywhere in the tree
            "src/native/foo.o",
            "src/native/foo.a",
            "src/native/foo.obj",
            "lib/native.lib",
            "lib/GoogleSignIn.framework",
            # JVM archives anywhere
            "lib/helper.jar",
            "webapps/app.war",
            "dist/backend.ear",
            # Generic archives anywhere
            "release/app.tar.gz",
            "release/app.tgz",
            "release/app.zip",
            "backup/snapshot.tar",
            "dumps/foo.bz2",
            "dumps/foo.xz",
            "dumps/foo.7z",
            # Compiled native shared objects (pre-existing)
            "src/native.wasm",
            "src/native.dll",
            "src/native.so",
            "src/native.dylib",
            "src/native.exe",
        ],
    )
    def test_binary_files_excluded_anywhere(self, path):
        """Binary artifacts can appear anywhere in the tree (accidentally
        committed, Git LFS pointers, release artifacts checked in). The
        file-pattern exclusion must cover them independent of directory."""
        assert scan_excludes.is_excluded(path), f"{path} must be excluded by file_patterns regardless of directory"


# ---------------------------------------------------------------------------
# Source-code pass-through — the practical invariant
# ---------------------------------------------------------------------------


class TestSourceCodePassthrough:
    """Sanity check: typical production source-code paths must NEVER be
    excluded. This isn't a whitelist (source extensions like *.ts, *.py are
    not in always_include), but the directory-level exclude list is
    conservative enough that normal `src/`, `lib/`, `api/`, `services/`,
    `packages/`, etc. hierarchies pass through untouched."""

    @pytest.mark.parametrize(
        "path",
        [
            "src/auth/login.ts",
            "src/components/Button.tsx",
            "lib/crypto/rsa.py",
            "app/controllers/session_controller.rb",
            "cmd/api/main.go",
            "pkg/middleware/auth.go",
            "internal/handlers/admin.go",
            "api/v1/users.py",
            "services/auth-service/src/index.ts",
            "packages/core/src/router.ts",
            "routes/login.ts",
            "handlers/webhook.go",
            "controllers/PaymentController.java",
            "middleware/rate_limit.py",
            "services/test-service/src/main.ts",  # 'test-service' != 'test' segment
            "packages/test-utils/auth.ts",  # 'test-utils' != 'test' segment
            "src/examples.ts",  # file named 'examples.ts'
            "lib/example.py",  # file named 'example.py'
            "codefixes/update-user-role.ts",
            "data/static/codefixes/patch-auth.ts",
        ],
    )
    def test_source_paths_pass_through(self, path):
        assert not scan_excludes.is_excluded(path), (
            f"production source path {path} must not be excluded — check the scan-excludes.yaml directories list"
        )


# ---------------------------------------------------------------------------
# Opt-in relief (SCAN_TEST_FILES)
# ---------------------------------------------------------------------------


class TestOptInRelief:
    def test_tests_dir_excluded_by_default(self):
        assert scan_excludes.is_excluded("tests/test_auth.py")

    def test_tests_dir_included_with_opt_in(self):
        assert not scan_excludes.is_excluded("tests/test_auth.py", opt_ins=["SCAN_TEST_FILES"])

    def test_fixtures_dir_included_with_opt_in(self):
        assert not scan_excludes.is_excluded("src/fixtures/mock-tokens.json", opt_ins=["SCAN_TEST_FILES"])

    @pytest.mark.parametrize(
        "path",
        [
            "services/user_test.go",
            "app/auth/test_login.py",
            "lib/order_spec.rb",
            "src/Auth/LoginTests.cs",
            "components/Button.test.tsx",
            "components/Button.spec.tsx",
            "e2e/login.spec.tsx",
            "src/fixtures/mock-tokens.json",
            "testdata/auth.json",
            "mocks/payment.ts",
        ],
    )
    def test_colocated_test_excluded_by_default(self, path):
        assert scan_excludes.is_excluded(path), f"{path} should be excluded by default"

    @pytest.mark.parametrize(
        "path",
        [
            "services/user_test.go",
            "app/auth/test_login.py",
            "lib/order_spec.rb",
            "src/Auth/LoginTests.cs",
            "components/Button.test.tsx",
            "components/Button.spec.tsx",
            "e2e/login.spec.tsx",
            "src/fixtures/mock-tokens.json",
            "testdata/auth.json",
            "mocks/payment.ts",
        ],
    )
    def test_colocated_test_re_included_with_opt_in(self, path):
        assert not scan_excludes.is_excluded(path, opt_ins=["SCAN_TEST_FILES"]), (
            f"{path} must be re-included when SCAN_TEST_FILES is enabled"
        )

    def test_unknown_opt_in_noop(self):
        assert scan_excludes.is_excluded("tests/test_auth.py", opt_ins=["NONEXISTENT_FLAG"])

    def test_opt_in_file_pattern_relief(self):
        excludes = _minimal_excludes(
            file_patterns=["*.fixture"],
            opt_in={
                "SCAN_FIXTURES": {
                    "file_patterns": ["*.fixture"],
                }
            },
        )

        assert not scan_excludes.is_excluded("fixtures/auth.fixture", opt_ins=["SCAN_FIXTURES"], excludes=excludes)


# ---------------------------------------------------------------------------
# glob_exclusion_string() — determinism and opt-in relief
# ---------------------------------------------------------------------------


class TestGlobString:
    def test_deterministic_sorted(self):
        s1 = scan_excludes.glob_exclusion_string()
        s2 = scan_excludes.glob_exclusion_string()
        assert s1 == s2, "glob string must be deterministic across calls"
        assert s1.startswith("!{")
        assert s1.endswith("}/**")

    def test_contains_all_default_dirs(self):
        s = scan_excludes.glob_exclusion_string()
        for d in ("node_modules", "vendor", "dist", "examples", "tests", ".cache"):
            assert d in s, f"glob missing directory: {d}"

    def test_opt_in_removes_dirs_from_glob(self):
        without = scan_excludes.glob_exclusion_string()
        with_opt = scan_excludes.glob_exclusion_string(opt_ins=["SCAN_TEST_FILES"])
        assert "tests" in without
        assert "tests" not in with_opt
        assert "__tests__" not in with_opt

    def test_opt_in_leaves_non_test_dirs(self):
        s = scan_excludes.glob_exclusion_string(opt_ins=["SCAN_TEST_FILES"])
        for d in ("node_modules", "vendor", "examples"):
            assert d in s, f"opt-in should not remove {d}"

    def test_empty_directory_list_returns_empty_glob(self):
        assert scan_excludes.glob_exclusion_string(excludes=_minimal_excludes()) == ""


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------


class TestCLI:
    def test_cli_glob(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "glob"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert r.stdout.strip().startswith("!{")
        assert "node_modules" in r.stdout

    def test_cli_check_excluded_exits_0(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "check", "node_modules/react/index.js"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0  # excluded
        assert "excluded" in r.stdout

    def test_cli_check_included_exits_1(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "check", "src/auth.ts"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1  # included
        assert "included" in r.stdout

    def test_cli_dump_is_valid_json(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "dump"],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(r.stdout)
        assert data["version"] == 1

    def test_cli_returns_2_for_invalid_config(self, tmp_path, monkeypatch, capsys):
        fixture = _write_yaml(tmp_path / "scan-excludes.yaml", {"version": 2})
        monkeypatch.setenv("SCAN_EXCLUDES_YAML", str(fixture))

        rc = scan_excludes._cli(["dump"])

        captured = capsys.readouterr()
        assert rc == 2
        assert "unsupported version" in captured.err
