"""Verified modular baseline packages and portable plugin adapters.

Release installers are parsed as data, never executed. Verification reads all
pinned artifacts without importing the repository's loader. The only activation
file is the existing baseline Markdown carrier; immutable snapshots survive
updates and removal for sessions that still reference them.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shlex
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_TOTAL = 8 * MAX_BYTES
DIGEST = re.compile(r"[0-9a-f]{64}")
MODULE_ID = re.compile(r"[a-z][a-z0-9-]*:[a-z][a-z0-9-]*")
MARKER = "<!-- appsec-advisor modular baseline: "
UPSTREAM_START = "<!-- aiscb managed policy -->"
UPSTREAM_END = "<!-- /aiscb managed policy -->"


class ModularError(ValueError):
    """The package or its activation cannot be verified."""


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ModularError("duplicate policy key")
        result[key] = value
    return result


def document(raw: bytes | str):
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ModularError("invalid policy JSON") from exc


def safe(path: Path) -> Path:
    """Reject links in both existing write destinations and read paths."""
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ModularError("symlink in baseline path")
    return path


def relative(root: Path, name: str) -> Path:
    if (
        not isinstance(name, str)
        or not name
        or "\\" in name
        or Path(name).is_absolute()
        or any(part in ("", ".", "..") for part in name.split("/"))
    ):
        raise ModularError("unsafe baseline artifact path")
    return safe(root / name)


def read(path: Path, limit: int = MAX_BYTES) -> bytes:
    try:
        safe(path)
        if not path.is_file():
            raise ModularError(f"not a regular baseline artifact: {path.name}")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as exc:
        raise ModularError(f"missing or unreadable baseline artifact: {path.name}") from exc
    if len(raw) > limit:
        raise ModularError("baseline artifact exceeds size limit")
    return raw


def validate(package: dict, contents: dict[str, bytes]) -> list[str]:
    if (
        not isinstance(package, dict)
        or set(package) != {"schema", "release", "core", "overlay", "modules", "files"}
        or type(package["schema"]) is not int
        or package["schema"] != 1
        or not isinstance(package["release"], str)
        or not isinstance(package["files"], dict)
        or not 1 <= len(package["files"]) <= 256
        or not isinstance(package["modules"], list)
        or not 1 <= len(package["modules"]) <= 128
    ):
        raise ModularError("invalid policy package schema")
    if sum(len(value) for value in contents.values()) > MAX_TOTAL:
        raise ModularError("policy package exceeds total size limit")
    for name, entry in package["files"].items():
        relative(Path("."), name)
        if (
            not isinstance(entry, dict)
            or set(entry) != {"size", "sha256"}
            or type(entry["size"]) is not int
            or not 0 < entry["size"] <= MAX_BYTES
            or not isinstance(entry["sha256"], str)
            or not DIGEST.fullmatch(entry["sha256"])
        ):
            raise ModularError("invalid policy artifact metadata")
        raw = contents.get(name)
        if raw is None or len(raw) != entry["size"] or digest(raw) != entry["sha256"]:
            raise ModularError(f"policy artifact mismatch: {name}")
        try:
            raw.decode("utf-8")
        except UnicodeError as exc:
            raise ModularError("policy artifact is not UTF-8") from exc
    core, overlay = package["core"], package["overlay"]
    if (
        not isinstance(core, str)
        or core not in contents
        or (overlay is not None and (not isinstance(overlay, str) or overlay not in contents))
        or "policy_loader.py" not in contents
    ):
        raise ModularError("missing core, overlay or loader")
    modules = {}
    artifacts = {core, overlay, "policy_loader.py"}
    for entry in package["modules"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"id", "artifact", "trigger", "paths", "requires", "blueprints"}
            or not isinstance(entry["id"], str)
            or not MODULE_ID.fullmatch(entry["id"])
            or entry["id"] in modules
            or not isinstance(entry["artifact"], str)
            or entry["artifact"] not in contents
            or entry["artifact"] in artifacts
            or not isinstance(entry["trigger"], str)
            or not entry["trigger"].strip()
        ):
            raise ModularError("invalid policy module")
        for key in ("paths", "requires", "blueprints"):
            if not isinstance(entry[key], list) or any(not isinstance(item, str) for item in entry[key]):
                raise ModularError("invalid module dependencies or blueprints")
        if any(name not in contents for name in entry["blueprints"]):
            raise ModularError("missing blueprint")
        if f"`module-id: {entry['id']}`" not in contents[entry["artifact"]].decode():
            raise ModularError("module identity mismatch")
        artifacts.add(entry["artifact"])
        modules[entry["id"]] = entry
    visiting, visited = set(), set()

    def visit(name):
        if name not in modules or name in visiting:
            raise ModularError("missing or cyclic module dependency")
        if name in visited:
            return
        visiting.add(name)
        for dependency in modules[name]["requires"]:
            visit(dependency)
        visiting.remove(name)
        visited.add(name)

    for name in modules:
        visit(name)
    return list(modules)


def load_package(root: Path, expected: str) -> tuple[dict, dict[str, bytes]]:
    if not isinstance(expected, str) or not DIGEST.fullmatch(expected):
        raise ModularError("missing trusted policy digest")
    raw = read(root / "policy.json")
    if digest(raw) != expected:
        raise ModularError("policy manifest digest mismatch")
    package = document(raw)
    files = package.get("files") if isinstance(package, dict) else None
    if not isinstance(files, dict) or len(files) > 256:
        raise ModularError("invalid policy file inventory")
    contents, total = {}, 0
    for name in files:
        value = read(relative(root, name))
        total += len(value)
        if total > MAX_TOTAL:
            raise ModularError("policy package exceeds total size limit")
        contents[name] = value
    validate(package, contents)
    return package, contents


def from_bundle(bundle: dict[str, bytes]) -> tuple[dict, dict[str, bytes], bytes]:
    """Extract data from an already authenticated self-contained installer."""
    try:
        tree = ast.parse(bundle["install.py"])
        values = [
            node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "EMBEDDED_POLICY" for target in node.targets)
        ]
        if len(values) != 1 or not isinstance(values[0], ast.Constant) or not isinstance(values[0].value, str):
            raise ModularError("release has no embedded modular policy")
        resources = document(values[0].value)
        if (
            not isinstance(resources, dict)
            or len(resources) > 64
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in resources.items())
        ):
            raise ModularError("invalid embedded policy inventory")
        catalog = document(resources["baseline/catalog.json"])
        if catalog["baseline_id"] != document(bundle["bundle.json"])["baseline_id"]:
            raise ModularError("modular catalog release mismatch")
        entries = [catalog["core"], *catalog["modules"]]
        if len(entries) > 128:
            raise ModularError("too many embedded modules")
        contents = {entry["file"]: resources["baseline/" + entry["file"]].encode() for entry in entries}
        for entry in entries:
            raw = contents[entry["file"]]
            if entry["size"] != len(raw) or entry["sha256"] != digest(raw):
                raise ModularError("embedded policy differs from its catalog")
        contents["policy_loader.py"] = resources["scripts/policy_loader.py"].encode()
        package = {
            "schema": 1,
            "release": catalog["baseline_id"],
            "core": catalog["core"]["file"],
            "overlay": None,
            "modules": [
                {
                    "id": entry["id"],
                    "artifact": entry["file"],
                    "trigger": entry["trigger"],
                    "paths": entry["paths"],
                    "requires": entry["requires"],
                    "blueprints": [],
                }
                for entry in catalog["modules"]
            ],
            "files": {name: {"size": len(raw), "sha256": digest(raw)} for name, raw in sorted(contents.items())},
        }
        validate(package, contents)
        manifest = (json.dumps(package, indent=2) + "\n").encode()
        return package, contents, manifest
    except (KeyError, TypeError, SyntaxError, RecursionError) as exc:
        raise ModularError("invalid embedded modular policy") from exc


def bundled(config: dict) -> dict[str, bytes]:
    """Authenticate the offline distribution with the configured release key."""
    import baseline_check as bc
    import baseline_release as br

    directory = config.get("bundle_dir")
    if not directory:
        raise ModularError("this build ships no modular baseline bundle")
    root = bc._plugin_root() / directory
    bundle = {name: read(root / name) for name in ("bundle.json", "bundle.json.sig", "install.py", br.BASELINE_FILE)}
    try:
        br.verify_signature(bundle["bundle.json"], bundle["bundle.json.sig"], config["release"]["allowed_signers"])
        baseline_id, _, _ = br._pinned_baseline(bundle["bundle.json"])
        if not bc.is_match(baseline_id, config["id"]):
            raise ModularError("bundled modular baseline does not match the configured id")
        manifest = document(bundle["bundle.json"])
        for name, source in (("install.py", "scripts/install.py"), (br.BASELINE_FILE, br.BASELINE_FILE)):
            entry = manifest["files"][source]
            if (
                set(entry) != {"size", "sha256"}
                or entry["size"] != len(bundle[name])
                or entry["sha256"] != digest(bundle[name])
            ):
                raise ModularError("bundled artifact differs from its signed manifest")
    except (br.ReleaseError, KeyError, TypeError) as exc:
        raise ModularError("bundled modular release verification failed") from exc
    from_bundle(bundle)
    return bundle


def resolve(config: dict, offline: bool, *, fallback: bool = True) -> tuple[dict[str, bytes], str, str]:
    import baseline_release as br

    if config.get("url") or config.get("git") or not config.get("release"):
        raise ModularError(
            "modular installation requires a signed bundle source; use --complete for a standalone baseline"
        )
    reason = "--offline" if offline else ""
    if not offline:
        try:
            release = br.fetch_latest(config["release"], config["id"], include_bundle=True)
            if release.bundle is None:
                raise ModularError("release has no modular bundle")
            from_bundle(release.bundle)
            return release.bundle, release.origin, ""
        except (br.ReleaseError, ModularError) as exc:
            if not fallback:
                raise ModularError(str(exc)) from exc
            reason = str(exc)
    return bundled(config), "verified bundled modular release", reason


def metadata(text: str) -> dict | None:
    if MARKER not in text:
        return None
    lines = [line for line in text.splitlines() if line.startswith(MARKER) and line.endswith(" -->")]
    if len(lines) != 1:
        raise ModularError("invalid modular adapter marker")
    info = document(lines[0][len(MARKER) : -4])
    if (
        not isinstance(info, dict)
        or set(info) != {"schema", "scope", "digest"}
        or type(info["schema"]) is not int
        or info["schema"] != 1
        or info["scope"] not in ("user", "project", "project-rules")
        or not isinstance(info["digest"], str)
        or not DIGEST.fullmatch(info["digest"])
    ):
        raise ModularError("invalid modular adapter metadata")
    return info


def storage(target: Path, scope: str) -> Path:
    if scope == "project-rules":
        if target.parent.name != "rules" or target.parent.parent.name != ".claude":
            raise ModularError("invalid project-rules adapter location")
        base = target.parents[2]
    else:
        base = target.parent
    return base / ".appsec-baseline" / "releases"


def render(target: Path, scope: str, fingerprint: str, package: dict, contents: dict[str, bytes]) -> str:
    if any(char in str(target) for char in "`\n\r"):
        raise ModularError("baseline path cannot contain Markdown delimiters or line breaks")
    root = storage(target, scope) / fingerprint
    loader = root / "policy_loader.py"
    if scope != "user":
        base = target.parents[2] if scope == "project-rules" else target.parent
        loader = loader.relative_to(base)
    command = shlex.join(["python3", str(loader), "--digest", fingerprint])
    info = {"schema": 1, "scope": scope, "digest": fingerprint}
    text = MARKER + json.dumps(info, separators=(",", ":")) + " -->\n"
    text += contents[package["core"]].decode().rstrip() + "\n\n## Installed module adapter\n\n"
    text += "Installation mode: modular. Managed by appsec-advisor.\n"
    text += "The catalog lists available modules, not loaded bodies. "
    if scope != "user":
        text += "Run the loader from the repository root. "
    text += f"Load selected IDs with `{command} MODULE_ID [MODULE_ID ...]`.\n"
    text += "The loader verifies full bodies and dependencies. Load before affected work and after context loss; stop affected work if unavailable.\n\n"
    for entry in package["modules"]:
        text += f"- `{entry['id']}`: {entry['trigger']}"
        if entry["paths"]:
            text += "; additional paths: " + ", ".join(entry["paths"])
        text += "\n"
    return text


def inspect(target: Path, text: str) -> dict | None:
    """Validate a plugin adapter or an upstream managed modular integration."""
    info = metadata(text)
    if info:
        root = storage(target, info["scope"]) / info["digest"]
        package, contents = load_package(root, info["digest"])
        if text != render(target, info["scope"], info["digest"], package, contents):
            raise ModularError("modular adapter differs from its pinned policy")
        return {
            "mode": "modular",
            "managed_by": "appsec-advisor",
            "available_modules": validate(package, contents),
            "loaded_modules": None,
            "scope": info["scope"],
        }
    if "Installation mode: modular." not in text:
        if "aiscb-MODULES-001" in text and "`module-id:" not in text:
            raise ModularError("modular core has no module adapter")
        return None
    source = re.search(r"Installation mode: modular\. Source: (.+)\. Release: ([^\n]+)\.", text)
    if source is None:
        raise ModularError("modular installation has no supported adapter")
    root = Path(source[1])
    if (
        not root.is_absolute()
        or root.parent.name != "releases"
        or root.parent.parent.name != ".aiscb"
        or not DIGEST.fullmatch(root.name)
    ):
        raise ModularError("invalid upstream snapshot path")
    package, contents = load_package(root, root.name)
    record = document(read(root.parent.parent / "installation.json"))
    if not isinstance(record, dict) or set(record) != {"digest", "modular", "entries"}:
        raise ModularError("invalid upstream installation record")
    start, end = text.find(UPSTREAM_START), text.find(UPSTREAM_END)
    if start < 0 or end < start or text.count(UPSTREAM_START) != 1 or text.count(UPSTREAM_END) != 1:
        raise ModularError("missing or ambiguous upstream managed block")
    block = text[start : end + len(UPSTREAM_END)]
    base = root.parents[2]
    try:
        rel = target.relative_to(base).as_posix()
    except ValueError:
        rel = str(target)
    entries = record.get("entries", {}) if isinstance(record, dict) else {}
    if (
        not isinstance(entries, dict)
        or record.get("digest") != root.name
        or record.get("modular") is not True
        or entries.get(rel, entries.get(str(target))) != digest(block.encode())
        or contents[package["core"]].decode().strip() not in block
    ):
        raise ModularError("upstream managed block or installation record mismatch")
    command = re.search(r"Load selected IDs with `([^`]+)`", block)
    expected = ["python3", str(root / "policy_loader.py"), "--digest", root.name, "MODULE_ID", "[MODULE_ID", "...]"]
    if command is None or shlex.split(command[1]) != expected:
        raise ModularError("upstream loader command differs from the pinned snapshot")
    return {
        "mode": "modular",
        "managed_by": "aiscb",
        "available_modules": validate(package, contents),
        "loaded_modules": None,
    }


def write_snapshot(target: Path, scope: str, bundle: dict[str, bytes], *, dry_run: bool) -> str:
    package, contents, manifest = from_bundle(bundle)
    fingerprint = digest(manifest)
    adapter = render(target, scope, fingerprint, package, contents)
    root = storage(target, scope) / fingerprint
    safe(root)
    if root.exists():
        load_package(root, fingerprint)
    elif not dry_run:
        import os
        import shutil
        import tempfile

        root.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".staging-", dir=root.parent))
        try:
            for name, raw in {**contents, "policy.json": manifest}.items():
                path = relative(stage, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            load_package(stage, fingerprint)
            os.rename(stage, root)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    return adapter
