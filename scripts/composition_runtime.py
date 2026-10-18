#!/usr/bin/env python3
"""Explicit offline setup, read-only preflight, and pinned staging-engine launcher.

Bootstrap uses only the standard library. Installation is never triggered by
preflight or invocation. The plugin archive and its lock are trusted release
inputs; assessed repositories and model output cannot select runtime inputs.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_LOCK = 2 * 1024 * 1024
MAX_MANIFEST = 8 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024


class RuntimeError(ValueError):
    """Setup or invocation cannot safely use the selected composition."""


def encode(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular(root: Path, relative: str) -> Path:
    parts = relative.split("/")
    if not relative.isascii() or any(not p or p in {".", ".."} for p in parts) or "\\" in relative or ":" in relative:
        raise RuntimeError("invalid composition path")
    target = root.joinpath(*parts)
    if target.resolve() != target.absolute() or not target.is_file():
        raise RuntimeError("composition files must be regular files without symlinks")
    return target


def read_json(path: Path, maximum: int) -> dict:
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError("composition metadata contains duplicate fields")
            result[key] = value
        return result

    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise RuntimeError("composition metadata exceeds its size limit")
    try:
        value = json.loads(data, object_pairs_hook=unique_fields)
    except RuntimeError:
        raise
    except (ValueError, RecursionError):
        raise RuntimeError("invalid composition metadata") from None
    if not isinstance(value, dict):
        raise RuntimeError("invalid composition metadata")
    return value


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if total > MAX_FILE:
                raise RuntimeError("composition file exceeds its size limit")
            digest.update(block)
    return digest.hexdigest()


def target_platform() -> str:
    machine = platform.machine().lower()
    if sys.platform == "win32" and machine == "x86_64":
        machine = "amd64"
    return f"{sys.platform}-{machine}"


def verified_inputs(plugin: Path) -> tuple[dict, dict, str]:
    lock = read_json(regular(plugin, "components.lock.json"), MAX_LOCK)
    manifest = read_json(regular(plugin, "component-manifest.json"), MAX_MANIFEST)
    if lock.get("schema_version") != 1 or lock.get("interface_version") != 1 or manifest.get("schema_version") != 1:
        raise RuntimeError("incompatible composition interface")
    if manifest.get("qualification") != "unqualified-staging" or manifest.get("lock_sha256") != sha(encode(lock)):
        raise RuntimeError("composition manifest does not match its lock")
    if manifest.get("components") != lock.get("components"):
        raise RuntimeError("component selection mismatch")
    selected = lock.get("runtime", {})
    if f"{sys.version_info.major}.{sys.version_info.minor}" not in selected.get("python", []):
        raise RuntimeError("Python version is not selected; use an interpreter listed in components.lock.json")
    if target_platform() not in selected.get("platforms", []):
        raise RuntimeError("platform is not selected in components.lock.json")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 20000:
        raise RuntimeError("invalid delivered file inventory")
    seen = set()
    total = 0
    for entry in entries:
        path = entry["path"]
        if path.casefold() in seen:
            raise RuntimeError("duplicate delivered file")
        seen.add(path.casefold())
        size = entry["size"]
        if type(size) is not int or not 0 <= size <= MAX_FILE:
            raise RuntimeError("invalid delivered file size")
        total += size
        target = regular(plugin, path)
        if total > 512 * 1024 * 1024 or target.stat().st_size != size or file_sha(target) != entry["sha256"]:
            raise RuntimeError("delivered file integrity mismatch")
    components = lock["components"]
    engines = [c for c in components if c["role"] == "engine"]
    if len(engines) != 1:
        raise RuntimeError("composition needs one pinned engine")
    wheels = [c for c in components if c["role"] in {"engine", "dependency"}]
    for c in wheels:
        name = "runtime/wheels/" + c["artifact"]
        if name.casefold() not in seen or file_sha(regular(plugin, name)) != c["sha256"]:
            raise RuntimeError("locked wheel integrity mismatch")
    identity = {
        "lock": sha(encode(lock)),
        "python": sys.version,
        "interpreter": str(Path(sys.executable).resolve()),
        "platform": target_platform(),
    }
    return lock, manifest, sha(encode(identity))


def default_home() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "AppSecAdvisor/runtimes"
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/AppSecAdvisor/runtimes"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "appsec-advisor/runtimes"


def interpreter(environment: Path) -> Path:
    return environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def runtime_storage(plugin: Path, home: Path) -> Path:
    home = home.absolute()
    plugin = plugin.resolve()
    if home.resolve() != home or home == plugin or plugin in home.parents:
        raise RuntimeError("runtime storage must be outside the plugin and contain no symlinks")
    if any((parent / ".git").exists() for parent in (home, *home.parents)):
        raise RuntimeError("runtime storage must be outside Git checkouts")
    if sys.platform == "win32":
        if Path.home().resolve() not in home.parents:
            raise RuntimeError("Windows runtime storage must stay in the current user's application directories")
    elif home.exists():
        metadata = home.stat()
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
            raise RuntimeError("runtime storage must be user-owned and not writable by other users")
    return home


def clean_environment() -> dict[str, str]:
    # pip must not inherit target-controlled Python paths, index settings or configs.
    env = {
        key: value for key, value in os.environ.items() if not key.upper().startswith(("PYTHON", "PIP_", "VIRTUAL_ENV"))
    }
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_NO_INPUT"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def checked(command: list[str], timeout: int = 180) -> None:
    try:
        result = subprocess.run(
            command, env=clean_environment(), stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("bounded runtime setup command failed; verify Python venv/ensurepip support") from None
    if result.returncode:
        raise RuntimeError(
            "offline runtime setup failed; verify locked wheels, dependency closure and Python compatibility"
        )


# Portable skills that call one deterministic engine command without model use.
DETERMINISTIC_SKILLS = {
    "security-score": {
        "command": "score",
        "capability": "score",
        "expected": {"available": True, "model_calls": False, "scoring_version": 2},
        "description": "Run the bundled Analyzer's deterministic security score without model calls.",
        "example": "score /absolute/repository --json",
    },
    "repo-profile": {
        "command": "repo-profile",
        "capability": "repo_profile",
        "expected": {"available": True, "model_calls": False},
        "description": "Run the bundled Analyzer's deterministic repository profile without model calls.",
        "example": "repo-profile /absolute/directory --json",
    },
    "abuse-cases": {
        "command": "abuse-cases",
        "capability": "abuse_cases",
        "expected": {"available": True, "model_calls": False},
        "description": "Run the bundled Analyzer's read-only abuse-case listing without model calls.",
        "example": "abuse-cases --repo /absolute/repository",
        "resources": ("SKILL.md", "dependencies.json"),
    },
}


def portable_requirements(skill: str, declaration: dict) -> dict:
    """Admit the portable contract of a deterministic skill supported by this host adapter."""
    spec = DETERMINISTIC_SKILLS[skill]
    expected = spec["expected"]
    capabilities = declaration.get("required_capabilities")
    required = capabilities.get(spec["capability"]) if isinstance(capabilities, dict) else None
    commands = declaration.get("required_commands")
    if (
        declaration.get("schema_version") != 1
        or declaration.get("engine") != "appsec-analyzer"
        or declaration.get("interface_versions") != [1]
        or not isinstance(commands, list)
        or len(commands) != 3
        or any(not isinstance(command, str) for command in commands)
        or set(commands) != {"version", "capabilities", spec["command"]}
        or not isinstance(capabilities, dict)
        or capabilities.keys() != {spec["capability"]}
        or declaration.get("model_prerequisites") != []
        or not isinstance(required, dict)
        or required.keys() != expected.keys()
        or any(type(required[key]) is not type(value) or required[key] != value for key, value in expected.items())
    ):
        raise RuntimeError(f"unsupported portable {skill} requirements")
    return required


ASSESSMENT_CAPABILITIES = ["scan", "assessment_entry", "status", "progress", "stop", "results", "query", "export"]
ASSESSMENT_COMMANDS = {
    "version",
    "capabilities",
    "scan",
    "assess",
    "assessment-entry",
    "status",
    "progress",
    "stop",
    "results",
    "query",
    "export",
    "organization-config",
}


def engine_capabilities(python: Path, names: list[str], requirements: dict[str, dict] | None = None) -> None:
    result = subprocess.run(
        [str(python), "-I", "-m", "appsec_analyzer.cli", "capabilities"],
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
    )
    capabilities = json.loads(result.stdout) if result.returncode == 0 and len(result.stdout) < MAX_LOCK else {}
    if (
        not isinstance(capabilities, dict)
        or capabilities.get("interface_version") != 1
        or any(
            not isinstance(capabilities.get(name), dict) or capabilities[name].get("available") is not True
            for name in names
        )
    ):
        raise RuntimeError("installed engine lacks required capabilities")
    if "assessment_entry" in names:
        entry = capabilities["assessment_entry"]
        if (
            type(entry.get("schema_version")) is not int
            or entry["schema_version"] != 1
            or entry.get("model_calls") is not False
        ):
            raise RuntimeError("installed engine lacks the public assessment entry contract")
    for name, required in (requirements or {}).items():
        actual = capabilities.get(name, {})
        if not isinstance(actual, dict) or any(
            type(actual.get(key)) is not type(value) or actual.get(key) != value for key, value in required.items()
        ):
            skill = next((k for k, spec in DETERMINISTIC_SKILLS.items() if spec["capability"] == name), name)
            raise RuntimeError(f"installed engine violates deterministic {skill} requirements")


def preflight(plugin: Path, home: Path) -> tuple[Path, dict]:
    home = runtime_storage(plugin, home)
    lock, _, identity = verified_inputs(plugin)
    environment = home / identity
    receipt = read_json(regular(environment, "composition-receipt.json"), MAX_LOCK)
    if receipt != {"schema_version": 1, "identity": identity, "lock_sha256": sha(encode(lock))}:
        raise RuntimeError("runtime receipt mismatch; run explicit setup")
    python = interpreter(environment)
    regular(environment, "pyvenv.cfg")
    # Unix venv interpreters normally link to the selected system interpreter.
    if not python.is_file() or (environment / "pyvenv.cfg").is_symlink():
        raise RuntimeError("runtime is incomplete; run explicit setup")
    return python, lock


def setup(plugin: Path, home: Path) -> Path:
    lock, _, identity = verified_inputs(plugin)
    plugin, home = plugin.resolve(), runtime_storage(plugin, home)
    # Explicit setup is an operator action. Default storage is outside analyzed repositories.
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    runtime_storage(plugin, home)
    target = home / identity
    if target.exists():
        return preflight(plugin, home)[0]
    guard = home / (identity + ".setup-lock")
    try:
        guard.mkdir(mode=0o700)
    except FileExistsError:
        raise RuntimeError("setup is already active or a stale setup lock needs operator inspection") from None
    try:
        # Create at its final path: virtual environments must never be relocated.
        target.mkdir(mode=0o700)
        try:
            checked([sys.executable, "-I", "-m", "venv", str(target)])
            python = interpreter(target)
            with tempfile.TemporaryDirectory(prefix="advisor-wheel-input-", dir=home) as staging:
                wheelhouse = Path(staging)
                requirements = []
                for component in lock["components"]:
                    if component["role"] not in {"engine", "dependency"}:
                        continue
                    original = regular(plugin, "runtime/wheels/" + component["artifact"])
                    copied = wheelhouse / original.name
                    shutil.copyfile(original, copied)
                    if file_sha(copied) != component["sha256"]:
                        raise RuntimeError("wheel changed during setup")
                    # Exact local wheel paths avoid index discovery or dependency resolution.
                    requirements.append(f"{copied.as_uri()} --hash=sha256:{component['sha256']}")
                selected = wheelhouse / "requirements.txt"
                selected.write_text("\n".join(requirements) + "\n", encoding="utf-8")
                checked(
                    [
                        str(python),
                        "-I",
                        "-m",
                        "pip",
                        "install",
                        "--no-index",
                        "--no-deps",
                        "--no-cache-dir",
                        "--only-binary=:all:",
                        "--require-hashes",
                        "--requirement",
                        str(selected),
                    ]
                )
                checked([str(python), "-I", "-m", "pip", "check"])
            # Verify the actual installed interface before activating its receipt.
            engine = next(c for c in lock["components"] if c["role"] == "engine")
            result = subprocess.run(
                [str(python), "-I", "-m", "appsec_analyzer.cli", "version"],
                env=clean_environment(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=30,
            )
            version = json.loads(result.stdout) if result.returncode == 0 and len(result.stdout) < MAX_LOCK else {}
            if (
                version.get("engine_version") != engine["version"]
                or version.get("interface_version") != lock["interface_version"]
            ):
                raise RuntimeError("installed engine version or interface mismatch")
            requirements = {
                spec["capability"]: portable_requirements(
                    skill, read_json(regular(plugin, f"skills/{skill}/dependencies.json"), MAX_LOCK)
                )
                for skill, spec in DETERMINISTIC_SKILLS.items()
                if skill in lock.get("skill_bindings", [])
            }
            engine_capabilities(python, engine["capabilities"], requirements or None)
            receipt = {"schema_version": 1, "identity": identity, "lock_sha256": sha(encode(lock))}
            pending = target / ".receipt.pending"
            pending.write_bytes(encode(receipt))
            pending.replace(target / "composition-receipt.json")
        except BaseException:
            shutil.rmtree(target)
            raise
    finally:
        guard.rmdir()
    return interpreter(target)


# Ownership follows the configuration dispatch ledger. Shared identity is not
# an engine compatibility declaration; compatibility.core still names Advisor.
_ADVISOR_FIELDS = {"banner", "skills", "hooks", "mcp", "skill_toggles", "baseline", "security_coach"}
_ANALYZER_FIELDS = {
    "policy",
    "branding",
    "requirements",
    "llm_context",
    "llm_policy",
    "analyst",
    "actors",
    "abuse_cases",
    "default_preset",
    "presets",
}
_SHARED_FIELDS = {"api_version", "organization", "compatibility"}
ORG_DISPATCH = "org-profile/composition-dispatch.json"


def split_profile(profile: dict) -> dict:
    """Split ownership and admit only settings with a verified public mapping."""
    unknown = set(profile) - _ADVISOR_FIELDS - _ANALYZER_FIELDS - _SHARED_FIELDS
    advisor = {key: value for key, value in profile.items() if key in _ADVISOR_FIELDS}
    analyzer = {key: value for key, value in profile.items() if key in _ANALYZER_FIELDS}
    # These host consumers have not migrated; retaining their data is not enforcement.
    unsupported = unknown | (set(advisor) & {"baseline", "security_coach"})
    unsupported |= set(analyzer) - {"default_preset", "presets", "policy"}
    for preset in analyzer.get("presets", {}).values():
        unsupported.update(f"presets.*.{key}" for key in set(preset) - {"base_mode"})
    if unsupported:
        raise RuntimeError(
            "staging settings require an explicit public consumer: "
            + ", ".join(sorted(unsupported))
            + "; the pinned Analyzer cannot preserve these settings; use the existing --source packaging path"
        )
    return {
        "schema_version": 1,
        "identity": {key: profile[key] for key in sorted(_SHARED_FIELDS)},
        "advisor": advisor,
        "analyzer": analyzer,
    }


def profile_data(data: bytes, *, maximum: int = 2 * 1024 * 1024) -> dict:
    import yaml

    if len(data) > maximum:
        raise RuntimeError("staging organization profile exceeds its byte limit")

    class UniqueLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
            if any(not isinstance(key, str) for key in keys) or len(keys) != len(set(keys)):
                raise RuntimeError("staging organization profile contains ambiguous keys")
            return super().construct_mapping(node, deep=deep)

    try:
        for count, token in enumerate(yaml.scan(data)):
            if count > 10000 or isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)):
                raise RuntimeError("organization profile cannot contain YAML anchors, aliases or excessive tokens")
        value = yaml.load(data, Loader=UniqueLoader)
        json.dumps(value, allow_nan=False)
        if not isinstance(value, dict):
            raise RuntimeError("organization profile must contain a mapping")
        return value
    except yaml.YAMLError:
        raise RuntimeError("staging organization profile is not valid data-only YAML")


def project_profile(plugin: str, selection: str, core: str, engine: str) -> bytes:
    """Host-side data adapter executed with the pinned runtime's dependencies."""
    import yaml
    from jsonschema import Draft202012Validator

    root = Path(plugin)
    schema = yaml.safe_load(regular(root, "schemas/org-profile.schema.yaml").read_bytes())
    path = Path(selection)
    # Open parent directories without following links, including during replacement.
    parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("external profile must be a singly linked regular file")
        profile = profile_data(stream.read(65537), maximum=65536)
    if not Draft202012Validator(schema).is_valid(profile):
        raise RuntimeError("external organization profile does not match its complete schema")
    if profile["default_preset"] not in profile["presets"]:
        raise RuntimeError("external organization default preset is unavailable")
    dispatch = split_profile(profile)
    if dispatch["advisor"]:
        raise RuntimeError("external runtime host settings require packaging; use --source for unmigrated consumers")
    projection = encode(
        {
            "schema_version": 1,
            "engine_version": engine,
            "advisor_core_version": core,
            "profile": {**dispatch["identity"], **dispatch["analyzer"]},
        }
    )
    if len(projection) > 65536:
        raise RuntimeError("external engine projection exceeds its byte limit")
    return projection


def selected_profile(plugin: Path, selection: str) -> Path:
    """Canonical operator selection shared with the public provenance argument."""
    path = Path(selection).expanduser()
    if not path.is_absolute():
        path = plugin / path
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise RuntimeError("external profile must not traverse symlinks")
    path = Path(os.path.abspath(path))
    if path.resolve() != path or not path.is_file() or path.stat().st_nlink != 1:
        raise RuntimeError("external profile must be a singly linked regular file without symlinks")
    return path


def external_projection(
    plugin: Path, python: Path, selection: str, arguments: list[str], inventory: set[str], lock: dict, home: Path, stack
) -> str:
    """Select only operator data, snapshot it privately, and preserve cleanup."""
    schema_path = "schemas/org-profile.schema.yaml"
    if schema_path not in inventory or stack is None:
        raise RuntimeError("external profile validation resources are missing; reassemble the reviewed host")
    path = selected_profile(plugin, selection)
    if arguments[0] == "score":
        sources = [arg for arg in arguments[1:] if arg not in {"--json", "--yaml", "--"}]
        if len(sources) != 1:
            raise RuntimeError("external score selection requires one explicit source")
        source = sources[0]
        if "://" not in source and not source.startswith("git@"):
            if path.is_relative_to(Path(source).expanduser().resolve()):
                raise RuntimeError("external profile must be outside the selected source")
    engine = next(component for component in lock["components"] if component["role"] == "engine")
    # runpy loads only the verified host adapter; no source-controlled imports.
    adapter = (
        "import runpy,sys; m=runpy.run_path(sys.argv[1]); sys.stdout.buffer.write(m['project_profile'](*sys.argv[2:]))"
    )
    result = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            adapter,
            str(regular(plugin, "scripts/composition_runtime.py")),
            str(plugin),
            str(path),
            lock["plugin"]["version"],
            engine["version"],
        ],
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise RuntimeError("external organization profile is invalid or contains unsupported settings")
    # Private per-invocation storage is outside sources and the read-only plugin.
    temporary = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix=".profile-", dir=home)))
    config = temporary / "analyzer-config.yaml"
    config.write_bytes(result.stdout)
    config.chmod(0o600)
    return str(config)


def organization_arguments(
    plugin: Path, python: Path, arguments: list[str], manifest: dict, *, lock=None, home=None, stack=None
) -> list[str]:
    """Dispatch the engine-only projection through its declared public API."""
    inventory = {entry["path"] for entry in manifest["files"]}
    packaged = ORG_DISPATCH in inventory
    if arguments[0] in {
        "version",
        "capabilities",
        "repo-profile",
        "abuse-cases",
        "assessment-entry",
        "status",
        "progress",
        "stop",
        "results",
        "query",
        "export",
    }:
        # Output-scoped consumers and the repository profile make no assessment or model call. In particular,
        # cancellation must remain usable with a missing external profile.
        return arguments
    disabled = os.environ.get("APPSEC_ADVISOR_NO_ORG_PROFILE", "").strip().lower() in {"1", "true", "yes", "on"}
    preset = os.environ.get("APPSEC_ADVISOR_PRESET")
    external = os.environ.get("APPSEC_ADVISOR_ORG_PROFILE")
    forwarded = [arguments[0]]
    index = 1
    while index < len(arguments):
        arg = arguments[index]
        if arg == "--":
            forwarded.extend(arguments[index:])
            break
        if arg == "--no-org-profile":
            disabled = True
        elif arg in {"--preset", "--org-profile"} or arg.startswith(("--preset=", "--org-profile=")):
            name, separator, value = arg.partition("=")
            if not separator:
                index += 1
                if index == len(arguments) or arguments[index].startswith("--"):
                    raise RuntimeError("organization selection requires a value")
                value = arguments[index]
            if not value:
                raise RuntimeError("organization selection requires a nonempty value")
            if name == "--preset":
                preset = value
            else:
                external = value
        else:
            forwarded.append(arg)
        index += 1
    if disabled:
        return [*forwarded, "--no-org-profile"] if forwarded[0] in {"scan", "assess"} else forwarded
    if external is not None and not external:
        raise RuntimeError("organization selection requires a nonempty value")
    if preset is not None and not preset:
        raise RuntimeError("organization selection requires a nonempty value")
    if not packaged and external is None:
        if preset is not None:
            raise RuntimeError("preset selection requires an active organization profile")
        return forwarded
    # Capability names alone are insufficient: require the versioned mapping.
    result = subprocess.run(
        [str(python), "-I", "-m", "appsec_analyzer.cli", "capabilities"],
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
    )
    capabilities = json.loads(result.stdout) if result.returncode == 0 and len(result.stdout) < MAX_LOCK else {}
    expected = {
        "available": True,
        "schema_version": 1,
        "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"],
    }
    actual = capabilities.get("organization_config") if isinstance(capabilities, dict) else None
    if not isinstance(actual, dict) or any(
        type(actual.get(key)) is not type(value) or actual.get(key) != value for key, value in expected.items()
    ):
        raise RuntimeError("pinned engine lacks the required public organization configuration interface")
    commands = actual.get("commands")
    workflow = forwarded[0]
    if workflow == "organization-config":
        workflow = forwarded[forwarded.index("--") + 1] if "--" in forwarded and forwarded[-1] != "--" else "score"
    if (
        not isinstance(commands, list)
        or any(not isinstance(command, str) for command in commands)
        or "score" not in commands
        or workflow not in {"score", "scan", "assess"}
        or workflow not in commands
        or (workflow in {"scan", "assess"} and actual.get("profile_source_validation") is not True)
    ):
        raise RuntimeError("pinned engine lacks the required organization workflow or source validation")
    provenance = []
    if external is not None:
        if actual.get("profile_source_validation") is True:
            provenance = ["--profile-source", str(selected_profile(plugin, external))]
        config = external_projection(plugin, python, external, forwarded, inventory, lock, home, stack)
    else:
        if "org-profile/analyzer-config.yaml" not in inventory:
            raise RuntimeError("organization engine projection is missing from the verified inventory")
        config = str(regular(plugin, "org-profile/analyzer-config.yaml"))
    if forwarded[0] == "organization-config":
        if (
            len(forwarded) < 2
            or forwarded[1] not in {"show", "validate"}
            or any(
                arg in {"--config", "--profile-source"} or arg.startswith(("--config=", "--profile-source="))
                for arg in forwarded[2:]
            )
        ):
            raise RuntimeError("select organization-config show or validate")
        return [
            "organization-config",
            forwarded[1],
            "--config",
            config,
            *provenance,
            *(["--preset", preset] if preset else []),
            *forwarded[2:],
        ]
    return [
        "organization-config",
        "run",
        "--config",
        config,
        *provenance,
        *(["--preset", preset] if preset else []),
        "--",
        *forwarded,
    ]


def launch(plugin: Path, home: Path, arguments: list[str], timeout: int, skill: str | None = None) -> int:
    python, lock = preflight(plugin, home)
    if not arguments:
        raise RuntimeError("select a supported public engine command")
    manifest = read_json(regular(plugin, "component-manifest.json"), MAX_MANIFEST)
    if skill is not None:
        if skill not in lock.get("skill_bindings", []):
            raise RuntimeError("skill invocation binding is not selected in this composition")
        if skill in DETERMINISTIC_SKILLS:
            spec = DETERMINISTIC_SKILLS[skill]
            if arguments[0] not in {"version", "capabilities", spec["command"]}:
                raise RuntimeError(f"{skill} binding permits only version, capabilities and {spec['command']}")
            requirements = portable_requirements(
                skill, read_json(regular(plugin, f"skills/{skill}/dependencies.json"), MAX_LOCK)
            )
            engine_capabilities(python, [spec["capability"]], {spec["capability"]: requirements})
        elif skill == "appsec-analyzer":
            if arguments[0] not in ASSESSMENT_COMMANDS:
                raise RuntimeError("assessment binding permits only its public workflow and consumers")
            if arguments[0] == "organization-config" and (
                len(arguments) < 2 or arguments[1] not in {"show", "validate"}
            ):
                raise RuntimeError("assessment configuration binding permits only inspection")
            engine_capabilities(python, ASSESSMENT_CAPABILITIES)
            inner = arguments.index("--") + 1 if arguments[0] == "organization-config" and "--" in arguments else 0
            if inner < len(arguments) and arguments[inner] in {"scan", "assess"}:
                # Execution settings, host selection and display stay independent.
                display = (
                    []
                    if any(arg == "--width" or arg.startswith("--width=") for arg in arguments[inner:])
                    else ["--width=72"]
                )
                arguments = [
                    *arguments,
                    "--launch-defaults=advisor",
                    "--host=claude-cli",
                    "--non-interactive",
                    *display,
                ]
        else:
            raise RuntimeError("skill invocation binding is not supported")
    if not arguments or arguments[0] not in {
        "version",
        "capabilities",
        "organization-config",
        "profiles",
        "preflight",
        "scan",
        "scan-sources",
        "score",
        "repo-profile",
        "abuse-cases",
        "assess",
        "status",
        "progress",
        "stop",
        "results",
        "analyst",
        "analyze-threats",
        "audit-requirements",
        "authnz-review",
        "assessment-entry",
        "query",
        "export",
    }:
        raise RuntimeError("select a supported public engine command")
    cancellable = arguments[0] in {"scan", "assess"}
    output = None
    for index, argument in enumerate(arguments):
        if argument.startswith("--output="):
            output = argument.partition("=")[2]
        elif argument == "--output" and index + 1 < len(arguments):
            output = arguments[index + 1]
    with contextlib.ExitStack() as stack:
        arguments = organization_arguments(plugin, python, arguments, manifest, lock=lock, home=home, stack=stack)
        options = (
            {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            if sys.platform == "win32"
            else {"start_new_session": True}
        )
        process = subprocess.Popen(
            [str(python), "-I", "-m", "appsec_analyzer.cli", *arguments], env=clean_environment(), **options
        )
        try:
            return process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as interruption:
            # Give the engine a bounded opportunity to settle its own run accounting.
            if cancellable and output:
                try:
                    subprocess.run(
                        [str(python), "-I", "-m", "appsec_analyzer.cli", "stop", "--output", output],
                        env=clean_environment(),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if sys.platform == "win32":
                # No shell or PATH executable selection. Native qualification remains required.
                killer = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/taskkill.exe"
                try:
                    subprocess.run([str(killer), "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=10)
                finally:
                    if process.poll() is None:
                        process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=10)
            if isinstance(interruption, KeyboardInterrupt):
                return 130
            raise RuntimeError(
                "engine invocation interrupted or timed out; inspect public status before resuming"
            ) from None


def follow(
    plugin: Path, home: Path, output: str, timeout: int, from_end: bool = False, *, wait_for_stop: bool = False
) -> int:
    """Display public progress; ending this monitor never cancels its owner."""
    python, lock = preflight(plugin, home)
    if "appsec-analyzer" not in lock.get("skill_bindings", []):
        raise RuntimeError("assessment binding is not selected")
    engine_capabilities(python, ASSESSMENT_CAPABILITIES)
    render = (
        None
        if wait_for_stop
        else runpy.run_path(str(regular(plugin, "scripts/runtime/assessment_console.py")))["render"]
    )

    def query(*arguments):
        result = subprocess.run(
            [str(python), "-I", "-m", "appsec_analyzer.cli", *arguments],
            env=clean_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
        )
        if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
            raise RuntimeError("public assessment progress unavailable; inspect the owner task")
        document = json.loads(result.stdout)
        if not isinstance(document, dict) or document.get("interface_version") != 1:
            raise RuntimeError("invalid public assessment progress")
        return document

    deadline = time.monotonic() + timeout
    startup = time.monotonic() + min(60, timeout)
    run_id, offset = None, 0
    while time.monotonic() < deadline:
        holder = query("assessment-entry", "holder", "--output", output)
        if type(holder.get("live")) is not bool:
            raise RuntimeError("invalid public assessment holder")
        if wait_for_stop:
            if not holder["live"]:
                return 0
            time.sleep(1)
            continue
        if holder.get("live") is True:
            if run_id is not None and holder.get("run_id") != run_id:
                print("Assessment owner changed; inspect public status.", flush=True)
                return 0
            run_id = holder.get("run_id")
        if run_id is None:
            if time.monotonic() >= startup:
                print("No live assessment observed; inspect the owner task notification.", flush=True)
                return 0
        else:
            progress = query("progress", "--output", output, "--after", str(offset))
            if progress.get("run_id") == run_id:
                events = progress.get("events")
                cursor = progress.get("next_offset")
                if not isinstance(events, list) or len(events) > 100 or type(cursor) is not int or cursor < 0:
                    raise RuntimeError("invalid public progress events or cursor")
                if not from_end:
                    if progress.get("events_omitted"):
                        print("Earlier progress events omitted; inspect the owner output.", flush=True)
                    for event in events:
                        if not isinstance(event, dict):
                            raise RuntimeError("invalid public progress event")
                        for line in render(event):
                            print(line, flush=True)
                from_end, offset = False, cursor
                if progress.get("assessment_status") != "running" or holder.get("live") is False:
                    return 0
        time.sleep(1)
    if wait_for_stop:
        print("Assessment still has a live holder; inspect public status before starting another run.", flush=True)
        return 3
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "preflight", "run", "follow", "wait"))
    parser.add_argument("--plugin", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", help="Explicit assessment directory for the public progress follower")
    parser.add_argument("--from-end", action="store_true")
    parser.add_argument("--runtime-home", type=Path, default=default_home())
    parser.add_argument("--timeout", type=int, default=43200)
    parser.add_argument(
        "--skill",
        choices=("security-score", "repo-profile", "abuse-cases", "appsec-analyzer"),
        help="Use a selected staging skill invocation binding",
    )
    raw = list(sys.argv[1:] if argv is None else argv)
    split = raw.index("--") if "--" in raw else len(raw)
    ns = parser.parse_args(raw[:split])
    arguments = raw[split + 1 :]
    if ns.action != "run" and arguments:
        parser.error("engine arguments are only valid for run")
    if ns.action != "run" and ns.skill:
        parser.error("skill bindings are only valid for run")
    if not 1 <= ns.timeout <= 43200:
        parser.error("timeout must be between 1 and 43200 seconds")
    if ns.action in {"follow", "wait"} and not ns.output:
        parser.error("follow and wait require --output")
    if ns.action not in {"follow", "wait"} and ns.output or ns.action != "follow" and ns.from_end:
        parser.error("--output belongs to follow/wait and --from-end to follow; engine arguments follow --")
    try:
        if ns.action == "wait":
            return follow(ns.plugin, ns.runtime_home, ns.output, min(ns.timeout, 300), wait_for_stop=True)
        if ns.action == "follow":
            return follow(ns.plugin, ns.runtime_home, ns.output, min(ns.timeout, 1800), ns.from_end)
        if ns.action == "setup":
            setup(ns.plugin, ns.runtime_home)
            print("Staging runtime ready. Model-host prerequisites and live qualification remain separate.")
        elif ns.action == "preflight":
            preflight(ns.plugin, ns.runtime_home)
            print("Pinned staging runtime ready; no installation or model call performed.")
        else:
            return launch(ns.plugin, ns.runtime_home, arguments, ns.timeout, ns.skill)
    except RuntimeError as exc:
        print(f"Runtime unavailable: {exc}. Check the reviewed lock and explicit setup.", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.TimeoutExpired):
        print(
            "Runtime unavailable: verify the selected Python/platform, package integrity, and explicit setup.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
