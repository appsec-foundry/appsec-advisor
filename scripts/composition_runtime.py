#!/usr/bin/env python3
"""Explicit offline setup, read-only preflight, and pinned staging-engine launcher.

Bootstrap uses only the standard library. Installation is never triggered by
preflight or invocation. The plugin archive and its lock are trusted release
inputs; assessed repositories and model output cannot select runtime inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
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


def score_requirements(declaration: dict) -> dict:
    """Admit the portable score contract supported by this host adapter."""
    expected = {"available": True, "model_calls": False, "scoring_version": 2}
    capabilities = declaration.get("required_capabilities")
    required = capabilities.get("score") if isinstance(capabilities, dict) else None
    commands = declaration.get("required_commands")
    if (
        declaration.get("schema_version") != 1
        or declaration.get("engine") != "appsec-analyzer"
        or declaration.get("interface_versions") != [1]
        or not isinstance(commands, list)
        or len(commands) != 3
        or any(not isinstance(command, str) for command in commands)
        or set(commands) != {"version", "capabilities", "score"}
        or not isinstance(capabilities, dict)
        or capabilities.keys() != {"score"}
        or declaration.get("model_prerequisites") != []
        or not isinstance(required, dict)
        or required.keys() != expected.keys()
        or any(type(required[key]) is not type(value) or required[key] != value for key, value in expected.items())
    ):
        raise RuntimeError("unsupported portable security-score requirements")
    return required


def engine_capabilities(python: Path, names: list[str], score: dict | None = None) -> None:
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
    if score is not None:
        actual = capabilities.get("score", {})
        if not isinstance(actual, dict) or any(
            type(actual.get(key)) is not type(value) or actual.get(key) != value for key, value in score.items()
        ):
            raise RuntimeError("installed engine violates deterministic security-score requirements")


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
            score = None
            if "security-score" in lock.get("skill_bindings", []):
                score = score_requirements(
                    read_json(regular(plugin, "skills/security-score/dependencies.json"), MAX_LOCK)
                )
            engine_capabilities(python, engine["capabilities"], score)
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


ORG_DISPATCH = "org-profile/composition-dispatch.json"


def organization_arguments(plugin: Path, python: Path, arguments: list[str], manifest: dict) -> list[str]:
    """Dispatch the engine-only projection through its declared public API."""
    inventory = {entry["path"] for entry in manifest["files"]}
    if ORG_DISPATCH not in inventory:
        return arguments
    if "org-profile/analyzer-config.yaml" not in inventory:
        raise RuntimeError("organization engine projection is missing from the verified inventory")
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
        "commands": ["score"],
        "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"],
    }
    actual = capabilities.get("organization_config") if isinstance(capabilities, dict) else None
    if not isinstance(actual, dict) or any(
        type(actual.get(key)) is not type(value) or actual.get(key) != value for key, value in expected.items()
    ):
        raise RuntimeError("pinned engine lacks the required public organization configuration interface")
    if arguments[0] in {"version", "capabilities"}:
        return arguments
    disabled = os.environ.get("APPSEC_ADVISOR_NO_ORG_PROFILE", "").strip().lower() in {"1", "true", "yes", "on"}
    preset = os.environ.get("APPSEC_ADVISOR_PRESET") or None
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
    if external and not disabled:
        # External Advisor profiles require host validation/splitting before
        # engine dispatch; an engine-only envelope cannot stand in for them.
        raise RuntimeError(
            "external organization profile selection is not yet supported by composed staging; use --source"
        )
    if disabled:
        return forwarded
    config = str(regular(plugin, "org-profile/analyzer-config.yaml"))
    if forwarded[0] == "organization-config":
        if (
            len(forwarded) < 2
            or forwarded[1] not in {"show", "validate"}
            or any(arg == "--config" or arg.startswith("--config=") for arg in forwarded[2:])
        ):
            raise RuntimeError("select organization-config show or validate")
        return [
            "organization-config",
            forwarded[1],
            "--config",
            config,
            *(["--preset", preset] if preset else []),
            *forwarded[2:],
        ]
    return [
        "organization-config",
        "run",
        "--config",
        config,
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
        if skill != "security-score" or skill not in lock.get("skill_bindings", []):
            raise RuntimeError("skill invocation binding is not selected in this composition")
        if not arguments or arguments[0] not in {"version", "capabilities", "score"}:
            raise RuntimeError("security-score binding permits only version, capabilities and score")
        requirements = score_requirements(
            read_json(regular(plugin, "skills/security-score/dependencies.json"), MAX_LOCK)
        )
        engine_capabilities(python, ["score"], requirements)
    if not arguments or arguments[0] not in {
        "version",
        "capabilities",
        "organization-config",
        "profiles",
        "preflight",
        "scan",
        "scan-sources",
        "score",
        "assess",
        "status",
        "progress",
        "stop",
        "results",
        "analyst",
        "analyze-threats",
        "audit-requirements",
        "authnz-review",
    }:
        raise RuntimeError("select a supported public engine command")
    arguments = organization_arguments(plugin, python, arguments, manifest)
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
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        # Give the engine a bounded opportunity to settle its own run accounting.
        if "--output" in arguments:
            index = arguments.index("--output") + 1
            if index < len(arguments):
                try:
                    subprocess.run(
                        [str(python), "-I", "-m", "appsec_analyzer.cli", "stop", "--output", arguments[index]],
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
        raise RuntimeError("engine invocation interrupted; inspect public status before resuming") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "preflight", "run"))
    parser.add_argument("--plugin", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--runtime-home", type=Path, default=default_home())
    parser.add_argument("--timeout", type=int, default=43200)
    parser.add_argument("--skill", choices=("security-score",), help="Use a selected staging skill invocation binding")
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
    try:
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
