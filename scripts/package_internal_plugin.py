#!/usr/bin/env python3
"""Build a company-branded appsec-advisor plugin artifact.

This script keeps internal packaging logic in the upstream plugin instead of
copying fragile rsync/sed/json snippets into every company's CI repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

UPSTREAM_NAMESPACE = "appsec-advisor"
# Namespace rewriting + leak detection must reach the script surfaces too:
# scripts/run-headless.sh and many .py helpers hardcode `<namespace>:<skill>`
# command references (e.g. the `claude -p` prompt, `/…:fix-run-issues` hints).
# Excluding .sh/.py left a repackaged plugin dispatching the upstream namespace
# — a broken headless wrapper that check_namespace_leaks never saw.
TEXT_SUFFIXES = {".json", ".md", ".txt", ".yaml", ".yml", ".sh", ".py"}
TOP_LEVEL_EXCLUDES = {
    ".agents",
    ".cache",
    ".claude",
    ".codex",
    ".env",
    ".git",
    ".github",
    ".gitlab-ci.yml",
    ".gitignore",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".venv",
    ".venv-tests",
    "AGENTS.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "SECURITY.md",
    "build",
    "dist",
    "examples",
    "htmlcov",
    "node_modules",
    "pyproject.toml",
    "tests",
}
ANY_LEVEL_EXCLUDES = {
    ".appsec-cache",
    ".cache",
    ".coverage-data",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".venv-tests",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
}
ANY_LEVEL_FILE_EXCLUDES = {
    ".agent-run.log",
    ".appsec-checkpoint",
    ".appsec-lock",
    ".appsec-progress.json",
    ".hook-events.log",
    ".render-integrity.json",
    ".run-issues.json",
    ".scan-start-epoch",
    ".scan-wall-seconds",
    ".section-integrity.json",
    ".skill-config.json",
}
PATH_EXCLUDES = {
    ("data", "appsec-requirements-fallback.yaml"),
    ("docs", "analysis"),
    ("docs", "internal"),
    ("docs", "proposals"),
    ("docs", "security"),
    ("scripts", "docs"),
    ("skills", "create-threat-model", "docs"),
    ("tests", "fixtures", "e2e", "_last-run"),
}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SURFACE_MANIFEST = ".claude-plugin/package-surface.json"
MCP_CONFIG = ".mcp.json"
HOOK_SCRIPT_IDS = {
    "agent_logger.py": "agent-logger",
    "security_steering.py": "security-coach",
}


def _die(message: str, code: int = 2) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)


def _validate_package_name(name: str) -> None:
    if not NAME_RE.match(name):
        _die(
            "plugin name must start with a lowercase letter or digit and contain "
            "only lowercase letters, digits, '.', '_' and '-'"
        )


def _validate_version(version: str) -> None:
    if not version:
        _die("version must not be empty")
    if "/" in version:
        _die("VERSION must not contain '/' because it is used in artifact paths")


def _require_plugin_root(source: Path) -> None:
    required = [
        ".claude-plugin/plugin.json",
        "config.json",
        "agents",
        "skills",
        "scripts",
        "schemas",
    ]
    missing = [rel for rel in required if not (source / rel).exists()]
    if missing:
        _die(f"{source} is not an appsec-advisor plugin root; missing {missing}")


def _copy_ignore(source_root: Path):
    source_root = source_root.resolve()

    def ignore(current: str, names: list[str]) -> set[str]:
        current_path = Path(current).resolve()
        try:
            rel = current_path.relative_to(source_root)
        except ValueError:
            rel = Path(".")

        ignored: set[str] = set()
        for name in names:
            child = current_path / name
            rel_child = tuple((rel / name).parts)
            if rel == Path(".") and name in TOP_LEVEL_EXCLUDES:
                ignored.add(name)
            elif rel_child in PATH_EXCLUDES:
                ignored.add(name)
            elif child.is_dir() and name in ANY_LEVEL_EXCLUDES:
                ignored.add(name)
            elif child.is_file() and name in ANY_LEVEL_FILE_EXCLUDES:
                ignored.add(name)
        return ignored

    return ignore


def copy_source(source: Path, build: Path) -> None:
    if build.exists():
        shutil.rmtree(build)
    build.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, build, ignore=_copy_ignore(source))


def overlay_org_profile(org_profile: Path, build: Path) -> None:
    if not (org_profile / "org-profile.yaml").is_file():
        _die(f"{org_profile} must contain org-profile.yaml")
    target = build / "org-profile"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(org_profile, target)


def patch_plugin_json(build: Path, name: str, version: str, description: str | None) -> None:
    plugin_path = build / ".claude-plugin" / "plugin.json"
    data = json.loads(plugin_path.read_text(encoding="utf-8"))
    data["name"] = name
    data["version"] = version
    data["description"] = (
        description if description is not None else f"Internal packaged build of appsec-advisor for {name}."
    )
    plugin_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _org_profile_banner(build: Path) -> dict:
    """Session-banner overrides declared in the packaged org profile.

    The banner runs as a SessionStart hook and must stay free of a YAML
    dependency, so the profile is resolved into config.json here at build time.
    """
    profile_path = build / "org-profile" / "org-profile.yaml"
    if not profile_path.is_file():
        return {}
    banner = _load_yaml_or_json(profile_path).get("banner")
    if not isinstance(banner, dict):
        return {}
    return {key: value for key, value in banner.items() if key in ("enabled", "headline", "url")}


def _org_profile_baseline(build: Path) -> dict:
    """The organization's own secure-coding baseline, resolved into config.json.

    Like the banner, this is read at build time so the SessionStart hook stays
    free of a YAML dependency. Declaring any source *replaces* the plugin's
    default baseline rather than merging with it: the upstream URL and the
    upstream bundled copy both carry the upstream id, which the organization's
    own id check would refuse anyway, so keeping them would only produce a
    confusing failure. ``file`` is rewritten to the packaged profile path,
    because the profile directory is where it lands in the build.
    """
    profile_path = build / "org-profile" / "org-profile.yaml"
    if not profile_path.is_file():
        return {}
    baseline = _load_yaml_or_json(profile_path).get("baseline")
    if not isinstance(baseline, dict):
        return {}

    resolved = {
        key: value for key, value in baseline.items() if key in ("enabled", "enforce", "id", "name", "install_filename")
    }
    if baseline.get("url"):
        resolved["url"] = baseline["url"]
    if isinstance(baseline.get("git"), dict):
        resolved["git"] = baseline["git"]
    if baseline.get("file"):
        resolved["fallback_file"] = f"org-profile/{str(baseline['file']).lstrip('/')}"

    if any(key in resolved for key in ("id", "url", "git", "fallback_file")):
        # An organization that names its own baseline owns the whole chain; a
        # leftover upstream source would be fetched, fail the id check, and
        # report a puzzling error. The display name goes the same way: inherited,
        # it would head the banner and both skills with the upstream product
        # name over the organization's own rules. Cleared, the generic default
        # applies until the profile sets one.
        for key in ("url", "git", "fallback_file", "name"):
            resolved.setdefault(key, None)
    return resolved


def _org_profile_skill_toggles(build: Path) -> dict:
    """The profile's skill policy, resolved into config.json at build time.

    Without this the policy only exists in ``.org-profile-effective.json``,
    which a run writes into its output directory — so a skill invoked before
    any scan has ever happened found no policy and ran. Resolving it here gives
    every session the same answer from the first command onwards, the way the
    banner and baseline blocks already work.

    Normalised to the ``{enabled, reason}`` shape so consumers see one form,
    matching ``resolve_org_profile.normalize_skill_toggles``.
    """
    profile_path = build / "org-profile" / "org-profile.yaml"
    if not profile_path.is_file():
        return {}
    toggles = _load_yaml_or_json(profile_path).get("skill_toggles")
    if not isinstance(toggles, dict):
        return {}
    out: dict[str, dict] = {}
    for name, value in toggles.items():
        if isinstance(value, bool):
            out[str(name)] = {"enabled": value, "reason": None}
        elif isinstance(value, dict):
            out[str(name)] = {"enabled": bool(value.get("enabled", True)), "reason": value.get("reason")}
    return out


def _prune_unused_baselines(build: Path, baseline: dict) -> None:
    """Drop the upstream bundled baseline when the build does not use it.

    An organization that ships its own baseline never reads the copy in
    ``data/baselines/`` — its id would not match, so an install would refuse it.
    Leaving it in place ships a third-party document, under its own licence,
    that the build's configuration never touches: dead weight in an internal
    package and a puzzle for whoever audits it.
    """
    bundled_dir = build / "data" / "baselines"
    if not bundled_dir.is_dir():
        return
    fallback = baseline.get("fallback_file")
    if isinstance(fallback, str) and fallback.startswith("data/baselines/"):
        return
    shutil.rmtree(bundled_dir, ignore_errors=True)


def patch_config(build: Path, info_url: str | None = None) -> None:
    config_path = build / "config.json"
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data["organization_profile"] = {
        "enabled": True,
        "path": "org-profile/org-profile.yaml",
    }
    baseline = dict(data.get("baseline") or {})
    baseline.update(_org_profile_baseline(build))
    if baseline:
        data["baseline"] = baseline
        _prune_unused_baselines(build, baseline)
    toggles = _org_profile_skill_toggles(build)
    if toggles:
        data["skill_toggles"] = toggles
    banner = dict(data.get("banner") or {})
    banner.update(_org_profile_banner(build))
    if info_url is not None:
        # The flag wins over the profile. An empty value drops the "more
        # information" line; the upstream URL is wrong for an internal build
        # either way.
        banner["url"] = info_url or None
    if banner:
        data["banner"] = banner
    config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _load_yaml_or_json(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        _die(f"cannot read package policy {path}: {exc}")
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            _die(f"invalid JSON package policy {path}: {exc}")
    else:
        try:
            import yaml
        except ImportError:
            _die("package policy YAML requires PyYAML; install pyyaml or use a .json policy file")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            _die(f"invalid YAML package policy {path}: {exc}")
    if data is None:
        return {}
    if not isinstance(data, dict):
        _die(f"package policy {path} must contain a mapping/object at the root")
    return data


def load_package_policy(org_profile: Path, explicit_path: str | None) -> tuple[dict, Path | None]:
    if explicit_path:
        path = Path(explicit_path).resolve()
        if not path.is_file():
            _die(f"package policy not found at {path}")
        return _load_yaml_or_json(path), path

    for name in ("package-policy.yaml", "package-policy.yml", "package-policy.json"):
        candidate = org_profile / name
        if candidate.is_file():
            return _load_yaml_or_json(candidate), candidate.resolve()
    return {}, None


def _policy_surface(policy: dict) -> dict:
    surface = policy.get("plugin_surface", policy)
    if not isinstance(surface, dict):
        _die("package policy 'plugin_surface' must be a mapping/object")
    unknown = set(surface) - {"skills", "hooks", "mcp_servers"}
    if unknown:
        _die(f"package policy has unknown plugin_surface keys: {sorted(unknown)}")
    return surface


def _read_name_list(block: dict, key: str, surface: str) -> set[str] | None:
    if key not in block:
        return None
    value = block[key]
    if value is None:
        return set()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        _die(f"package policy plugin_surface.{surface}.{key} must be a list of strings")
    seen: set[str] = set()
    duplicates: set[str] = set()
    for item in value:
        name = item.strip()
        if not name:
            _die(f"package policy plugin_surface.{surface}.{key} contains an empty name")
        if name in seen:
            duplicates.add(name)
        seen.add(name)
    if duplicates:
        _die(f"package policy plugin_surface.{surface}.{key} contains duplicates: {sorted(duplicates)}")
    return seen


def _resolve_keep_set(
    block: object,
    available: set[str],
    surface: str,
    *,
    required: set[str] | None = None,
) -> set[str]:
    required = required or set()
    if block is None:
        return set(available)
    if not isinstance(block, dict):
        _die(f"package policy plugin_surface.{surface} must be a mapping/object")
    unknown_keys = set(block) - {"include", "exclude"}
    if unknown_keys:
        _die(f"package policy plugin_surface.{surface} has unknown keys: {sorted(unknown_keys)}")
    include = _read_name_list(block, "include", surface)
    exclude = _read_name_list(block, "exclude", surface)
    if include is not None and exclude is not None:
        _die(f"package policy plugin_surface.{surface} cannot set both include and exclude")

    selected = include if include is not None else exclude
    if selected is None:
        return set(available)
    unknown = selected - available
    if unknown:
        _die(
            f"package policy plugin_surface.{surface} references unknown names: "
            f"{sorted(unknown)} (available: {sorted(available)})"
        )
    keep = set(selected) if include is not None else (available - selected)
    missing_required = required - keep
    if missing_required:
        _die(f"package policy plugin_surface.{surface} must keep required names: {sorted(missing_required)}")
    return keep


def _available_skills(build: Path) -> set[str]:
    skills_dir = build / "skills"
    if not skills_dir.is_dir():
        return set()
    return {path.parent.name for path in skills_dir.glob("*/SKILL.md") if path.is_file()}


def _hook_id(command: str) -> str | None:
    if "/scripts/" not in command and "\\scripts\\" not in command:
        return None
    script_name = command.replace("\\", "/").split("/scripts/", 1)[1].split()[0]
    script_name = Path(script_name).name
    return HOOK_SCRIPT_IDS.get(script_name, Path(script_name).stem.replace("_", "-"))


def _load_hooks(build: Path) -> tuple[Path, dict]:
    hooks_path = build / "hooks" / "hooks.json"
    if not hooks_path.is_file():
        return hooks_path, {"hooks": {}}
    try:
        data = json.loads(hooks_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _die(f"invalid hooks.json in packaged copy: {exc}")
    if not isinstance(data, dict) or not isinstance(data.get("hooks"), dict):
        _die("hooks/hooks.json must contain a top-level 'hooks' object")
    return hooks_path, data


def _available_hook_ids(build: Path) -> set[str]:
    _, data = _load_hooks(build)
    ids: set[str] = set()
    for entries in data.get("hooks", {}).values():
        if not isinstance(entries, list):
            continue
        for outer in entries:
            if not isinstance(outer, dict):
                continue
            for hook in outer.get("hooks") or []:
                if not isinstance(hook, dict):
                    continue
                command = hook.get("command")
                if isinstance(command, str):
                    hook_id = _hook_id(command)
                    if hook_id:
                        ids.add(hook_id)
    return ids


def apply_skill_policy(build: Path, surface: dict) -> dict:
    available = _available_skills(build)
    keep = _resolve_keep_set(
        surface.get("skills"),
        available,
        "skills",
        required={"create-threat-model"},
    )
    removed = sorted(available - keep)
    for skill in removed:
        shutil.rmtree(build / "skills" / skill)
    return {"included": sorted(keep), "removed": removed}


# Where an org profile keeps the skills it adds, unless it says otherwise.
ORG_SKILLS_GLOB = "skills/*/SKILL.md"


def overlay_org_skills(build: Path) -> list[str]:
    """Copy the skills the org profile adds into the plugin's skills directory.

    Claude Code discovers skills by convention — every ``skills/<name>/SKILL.md``
    under the plugin root — so adding one is a directory copy. It has to happen
    before the package policy runs, or ``plugin_surface.skills`` could not name
    an added skill and would reject it as unknown.

    Two refusals rather than a silent result:

    * A name that collides with an upstream skill aborts the build. Overwriting
      ``create-threat-model`` with an organization's own file would replace the
      pipeline's entry point without anyone deciding to.
    * Frontmatter that would not pass for an upstream skill aborts too. The
      description is the only text the model sees when choosing a skill, so a
      malformed one degrades routing quietly instead of failing.
    """
    profile_dir = build / "org-profile"
    profile_path = profile_dir / "org-profile.yaml"
    if not profile_path.is_file():
        return []
    block = _load_yaml_or_json(profile_path).get("skills")
    if not isinstance(block, dict):
        return []
    pattern = str(block.get("add") or ORG_SKILLS_GLOB)

    upstream = _available_skills(build)
    added: list[str] = []
    for skill_md in sorted(profile_dir.glob(pattern)):
        source = skill_md.parent
        name = source.name
        _require_inside(profile_dir, skill_md, "skills.add")
        _validate_org_skill(skill_md, name)
        if name in upstream:
            _die(
                f"org profile adds skill '{name}', which the plugin already ships. "
                f"Rename it — replacing an upstream skill would change what its command does."
            )
        if name in added:
            _die(f"org profile adds skill '{name}' more than once")
        shutil.copytree(source, build / "skills" / name)
        added.append(name)
    return added


def _require_inside(root: Path, path: Path, label: str) -> None:
    """Abort when ``path`` escapes ``root`` — a glob must not reach outside."""
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        _die(f"package policy {label}: '{path}' resolves outside the profile directory")


def _validate_org_skill(skill_md: Path, directory: str) -> None:
    """Hold an added skill to the same frontmatter rules as an upstream one."""
    lines = skill_md.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        _die(f"org skill '{directory}': SKILL.md does not start with a '---' frontmatter delimiter")
    try:
        end = lines.index("---", 1)
    except ValueError:
        _die(f"org skill '{directory}': frontmatter is not terminated by a closing '---'")
    try:
        import yaml

        front = yaml.safe_load("\n".join(lines[1:end]))
    except Exception as exc:  # noqa: BLE001
        _die(f"org skill '{directory}': frontmatter is not valid YAML: {exc}")
    if not isinstance(front, dict):
        _die(f"org skill '{directory}': frontmatter must be a mapping")
    unknown = set(front) - {"name", "description"}
    if unknown:
        _die(f"org skill '{directory}': unsupported frontmatter keys {sorted(unknown)}")
    name, description = front.get("name"), front.get("description")
    if name != directory:
        _die(f"org skill '{directory}': frontmatter name '{name}' must match the directory name")
    if not isinstance(description, str) or not description.strip():
        _die(f"org skill '{directory}': a non-empty description is required")
    if len(description) > 1024:
        _die(f"org skill '{directory}': description is {len(description)} characters; the limit is 1024")


def _org_profile_hooks(build: Path) -> dict:
    """Hook definitions declared in the packaged org profile (top-level `hooks`).

    Returns a {id: {event, command, matcher?}} mapping, or {} when the profile
    has none. The org profile is already overlaid into build/org-profile here."""
    profile_path = build / "org-profile" / "org-profile.yaml"
    if not profile_path.is_file():
        return {}
    data = _load_yaml_or_json(profile_path)
    hooks = data.get("hooks")
    return hooks if isinstance(hooks, dict) else {}


def apply_hook_policy(build: Path, surface: dict) -> dict:
    org_hooks = _org_profile_hooks(build)
    # Org hook ids join the upstream ids in the keep-set resolution, so
    # plugin_surface.hooks (include/exclude) gates org hooks too. Declared org
    # hooks are included by default.
    upstream_available = _available_hook_ids(build)
    available = upstream_available | set(org_hooks)
    keep = _resolve_keep_set(surface.get("hooks"), available, "hooks")
    removed = sorted(available - keep)

    hooks_path, data = _load_hooks(build)
    filtered_events: dict[str, list[dict]] = {}
    for event, entries in data.get("hooks", {}).items():
        if not isinstance(entries, list):
            continue
        kept_entries: list[dict] = []
        for outer in entries:
            if not isinstance(outer, dict):
                continue
            hooks = outer.get("hooks") or []
            kept_hooks = []
            for hook in hooks:
                if not isinstance(hook, dict):
                    continue
                command = hook.get("command")
                hook_id = _hook_id(command) if isinstance(command, str) else None
                if hook_id is None or hook_id in keep:
                    kept_hooks.append(hook)
            if kept_hooks:
                new_outer = dict(outer)
                new_outer["hooks"] = kept_hooks
                kept_entries.append(new_outer)
        if kept_entries:
            filtered_events[event] = kept_entries

    # Merge kept org hooks into the built hooks.json under their declared event.
    org_kept: list[dict] = []
    for hook_id in sorted(keep):
        cfg = org_hooks.get(hook_id)
        if not isinstance(cfg, dict):
            continue
        event = cfg.get("event")
        command = cfg.get("command")
        if not event or not command:
            continue
        outer: dict = {"hooks": [{"type": "command", "command": command}]}
        if cfg.get("matcher"):
            outer["matcher"] = cfg["matcher"]
        filtered_events.setdefault(event, []).append(outer)
        org_kept.append({"id": hook_id, "event": event, "command": command})

    if hooks_path.parent.exists():
        hooks_path.write_text(
            json.dumps({"hooks": filtered_events}, indent=2) + "\n",
            encoding="utf-8",
        )

    if "security-coach" in removed:
        keywords_path = build / "hooks" / "steering_keywords.json"
        if keywords_path.exists():
            keywords_path.unlink()

    return {
        # Upstream hooks only — org hooks are tracked separately under "org"
        # (they are not discoverable via the /scripts/ id derivation).
        "included": sorted(upstream_available & keep),
        "removed": removed,
        "events": sorted(filtered_events),
        "org": org_kept,
    }


def _org_profile_mcp_servers(build: Path) -> dict:
    """MCP server definitions declared in the packaged org profile (mcp.servers).

    Returns a {name: server_config} mapping, or {} when the profile has no mcp
    block. The org profile has already been overlaid into build/org-profile at
    this point.
    """
    profile_path = build / "org-profile" / "org-profile.yaml"
    if not profile_path.is_file():
        return {}
    data = _load_yaml_or_json(profile_path)
    servers = (data.get("mcp") or {}).get("servers")
    return servers if isinstance(servers, dict) else {}


def apply_mcp_policy(build: Path, surface: dict) -> dict:
    """Emit build/.mcp.json from the org profile's mcp.servers, gated by the
    package-policy allowlist (plugin_surface.mcp_servers). Declared servers are
    included by default; an include/exclude list narrows them. Writes no file
    when nothing is kept."""
    servers = _org_profile_mcp_servers(build)
    available = set(servers)
    keep = _resolve_keep_set(surface.get("mcp_servers"), available, "mcp_servers")
    removed = sorted(available - keep)

    mcp_path = build / MCP_CONFIG
    if keep:
        payload = {"mcpServers": {name: servers[name] for name in sorted(keep)}}
        mcp_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    elif mcp_path.exists():
        mcp_path.unlink()
    return {"included": sorted(keep), "removed": removed}


def write_surface_manifest(
    build: Path,
    policy_path: Path | None,
    skills: dict,
    hooks: dict,
    upstream_url: str | None = None,
    mcp_servers: dict | None = None,
) -> None:
    if policy_path is None:
        policy_ref = None
    elif (build / "org-profile" / policy_path.name).is_file():
        policy_ref = f"org-profile/{policy_path.name}"
    else:
        try:
            policy_ref = str(policy_path.relative_to(build))
        except ValueError:
            policy_ref = policy_path.name
    manifest = {
        "version": 1,
        "policy": policy_ref,
        "skills": skills,
        "hooks": hooks,
    }
    if mcp_servers is not None:
        manifest["mcp_servers"] = mcp_servers
    if upstream_url:
        manifest["upstream_url"] = upstream_url
        manifest["based_on"] = upstream_url.removesuffix(".git")
    manifest_path = build / SURFACE_MANIFEST
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def apply_package_surface_policy(
    build: Path, policy: dict, policy_path: Path | None, upstream_url: str | None = None
) -> None:
    surface = _policy_surface(policy)
    # Added first, so the package policy can name an org skill like any other
    # and so the manifest counts it among what this build ships.
    org_added = overlay_org_skills(build)
    skills = apply_skill_policy(build, surface)
    if org_added:
        # Recorded separately, the way org hooks are: the artifact surface has
        # to say which parts are the organization's own.
        skills["org_added"] = sorted(org_added)
    hooks = apply_hook_policy(build, surface)
    mcp_servers = apply_mcp_policy(build, surface)
    write_surface_manifest(build, policy_path, skills, hooks, upstream_url, mcp_servers)


def _has_shebang(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def _text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            yield path
        elif not path.suffix and _has_shebang(path):
            # Extensionless executables (CLI shims like scripts/appsec-reviewer-cli)
            # hardcode `<namespace>:<skill>` command references too, but match no
            # suffix. Detect them by shebang so the namespace rewrite and the leak
            # check reach them — without hardcoding shim names.
            yield path


def rewrite_namespace(build: Path, name: str) -> None:
    old = f"{UPSTREAM_NAMESPACE}:"
    new = f"{name}:"
    for path in _text_files(build):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if old in text:
            path.write_text(text.replace(old, new), encoding="utf-8")


def check_namespace_leaks(build: Path) -> None:
    needle = f"{UPSTREAM_NAMESPACE}:"
    leaks: list[str] = []
    for root_name in ("skills", "agents", "scripts"):
        root = build / root_name
        if not root.exists():
            continue
        for path in _text_files(root):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if needle in text:
                leaks.append(str(path.relative_to(build)))
    if leaks:
        shown = "\n  - ".join(leaks[:20])
        _die(f"upstream namespace {needle!r} still present in packaged copy:\n  - {shown}", 1)


def run_validation(build: Path) -> None:
    subprocess.run(
        [sys.executable, str(build / "scripts" / "validate_config.py"), str(build)],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(build / "scripts" / "validate_org_profile.py"),
            str(build / "org-profile" / "org-profile.yaml"),
        ],
        check=True,
    )


def write_archive(build: Path, name: str, version: str, dist_dir: Path) -> tuple[Path, Path]:
    dist_dir.mkdir(parents=True, exist_ok=True)
    tar_path = dist_dir / f"{name}-{version}.tgz"
    sha_path = dist_dir / f"{name}-{version}.tgz.sha256"

    with tarfile.open(tar_path, "w:gz") as archive:
        archive.add(build, arcname=name)

    digest = hashlib.sha256(tar_path.read_bytes()).hexdigest()
    sha_path.write_text(f"{digest}  {tar_path.name}\n", encoding="utf-8")
    return tar_path, sha_path


def remove_stale_archive(name: str, version: str, dist_dir: Path) -> None:
    for path in (
        dist_dir / f"{name}-{version}.tgz",
        dist_dir / f"{name}-{version}.tgz.sha256",
    ):
        if path.exists():
            path.unlink()


HOOK_DESCRIPTIONS = {
    "agent-logger": "Logs all tool calls and agent actions for audit and debugging.",
    "security-coach": "Intercepts tool calls and provides real-time security guidance.",
    "session-banner": "Opens each session with the repository's threat-model and baseline status.",
    "skill-policy-gate": "Blocks skills this organization disabled, on both the typed and the model-invoked path.",
}

# Skills with their own detailed section in the README
MAIN_SKILLS = ["create-threat-model", "audit-security-requirements", "verify-requirements"]
# Skills grouped into a single utility section
UTILITY_SKILLS = [
    "help",
    "threat-model-health",
    "check-permissions",
    "status",
    "fix-run-issues",
    "diagnose-run",
    "clean-run-state",
]


def _skill_description(build: Path, skill: str) -> str:
    """First sentence of a skill's description, for the packaged README table.

    The frontmatter is parsed as YAML rather than scanned line by line. Several
    skills write the description as a block scalar::

        description: >-
          Install the secure-coding baseline into ...

    where the value is on the following lines — a line scan returned the literal
    ``>-`` and the README table shipped that as the skill's description.
    """
    skill_md = build / "skills" / skill / "SKILL.md"
    if not skill_md.exists():
        return ""
    lines = skill_md.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    try:
        end = lines.index("---", 1)
    except ValueError:
        return ""
    try:
        import yaml

        front = yaml.safe_load("\n".join(lines[1:end]))
    except Exception:  # noqa: BLE001 — a malformed skill must not fail the build
        return ""
    desc = (front or {}).get("description") if isinstance(front, dict) else None
    if not isinstance(desc, str):
        return ""
    # A block scalar folds into one line but keeps its newlines when literal;
    # collapse whitespace so the value fits a Markdown table cell.
    desc = " ".join(desc.split())
    # Truncate at the first sentence boundary for readability.
    idx = desc.find(". ")
    if idx != -1:
        desc = desc[: idx + 1]
    return desc


def _skill_section(name: str, org_name: str, skill: str, build: Path) -> str:
    if skill == "create-threat-model":
        return f"""
## `/{name}:create-threat-model`

STRIDE-based architectural threat assessment. Produces `docs/security/threat-model.md`
in your repo, checked against {org_name} security requirements.

**Depth:**

| Flag | Description |
|---|---|
| _(none)_ | Standard — full STRIDE analysis with QA review |
| `--quick` | Faster, lighter analysis; skips QA and attack walkthroughs |
| `--thorough` | Deepest analysis; adds architect review and extended walkthroughs |

**Common options:**

| Flag | Description |
|---|---|
| `--requirements` | Check findings against {org_name} security requirements |
| `--no-requirements` | Skip requirements check for this run |
| `--incremental` | Re-analyze only components changed since last run |
| `--resume` | Continue from the last saved checkpoint after an interruption |
| `--repo <path>` | Analyze a different repository instead of the current one |
| `--output <path>` | Write results to a custom output directory |
| `--sarif` | Also write `threat-model.sarif.json` for CI/tooling integration |
| `--pr-mode` | Focused delta report for a pull/merge request (implies `--incremental`) |
| `--rebuild` | Wipe all prior output and start completely fresh |
| `--dry-run` | Run the full pipeline but write nothing to the repo |

**Examples:**

```text
/{name}:create-threat-model
/{name}:create-threat-model --quick
/{name}:create-threat-model --thorough --requirements
/{name}:create-threat-model --incremental --sarif
/{name}:create-threat-model --repo ../other-service
/{name}:create-threat-model --help
```
"""
    if skill == "audit-security-requirements":
        return f"""
## `/{name}:audit-security-requirements`

Audits the entire codebase against {org_name} security requirements and verifies
whether each tagged requirement (e.g. `[SEC-AUTH-001]`) is implemented.
Prints color-coded status with evidence. Optionally saves results as JSON or Markdown.

```text
/{name}:audit-security-requirements
/{name}:audit-security-requirements --output json
```
"""
    if skill == "verify-requirements":
        return f"""
## `/{name}:verify-requirements`

Checks your recent code changes (current diff) against {org_name} security requirements.
Lighter than a full audit — scoped to what you just changed.
Use `--gate` to turn it into a CI/merge gate that fails on violations.

```text
/{name}:verify-requirements
/{name}:verify-requirements --gate
```
"""
    return ""


def _build_readme(build: Path, name: str, surface_manifest: dict, upstream_url: str | None) -> str:
    org_profile_path = build / "org-profile" / "org-profile.yaml"
    org_name = name  # fallback
    if org_profile_path.exists():
        for line in org_profile_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("name:"):
                org_name = line[len("name:") :].strip()
                break

    skills = surface_manifest.get("skills", {}).get("included", [])
    hooks = surface_manifest.get("hooks", {}).get("included", [])

    # Main skill sections
    main_sections = ""
    for skill in MAIN_SKILLS:
        if skill in skills:
            main_sections += _skill_section(name, org_name, skill, build)

    # Utility skills table
    utility_rows = ""
    for skill in UTILITY_SKILLS:
        if skill in skills:
            desc = _skill_description(build, skill)
            utility_rows += f"| `/{name}:{skill}` | {desc} |\n"
    # Any skills not in either category
    known = set(MAIN_SKILLS + UTILITY_SKILLS)
    for skill in sorted(skills):
        if skill not in known:
            desc = _skill_description(build, skill)
            utility_rows += f"| `/{name}:{skill}` | {desc} |\n"

    utility_section = ""
    if utility_rows:
        utility_section = f"""
## Utility Commands

| Command | Description |
|---|---|
{utility_rows}"""

    hooks_section = ""
    if hooks:
        hook_rows = ""
        for hook in sorted(hooks):
            desc = HOOK_DESCRIPTIONS.get(hook, "")
            hook_rows += f"| `{hook}` | {desc} |\n"
        hooks_section = f"""
## Active Hooks

| Hook | Description |
|---|---|
{hook_rows}"""

    upstream_line = ""
    if upstream_url:
        display_url = upstream_url.removesuffix(".git")
        upstream_line = f"\n- [appsec-advisor]({display_url})"

    based_on_line = ""
    if upstream_url:
        display_url = upstream_url.removesuffix(".git")
        based_on_line = f"\nBased on [appsec-advisor]({display_url})."

    readme = f"""# {name} — {org_name} AppSec Plugin for Claude Code

Internal Claude Code security plugin for {org_name}.
Runs automated threat models and security audits directly in your IDE,
with {org_name} security standards and requirements already baked in.{based_on_line}

## Getting Started

Load the plugin in any repo:

```bash
claude --plugin-dir /path/to/build/{name}
```
{main_sections}{utility_section}{hooks_section}
## Reference
{upstream_line}
"""
    return readme


def write_readme(
    build: Path, name: str, surface_manifest: dict, upstream_url: str | None, readme_path: Path | None = None
) -> None:
    content = _build_readme(build, name, surface_manifest, upstream_url)
    target = readme_path if readme_path else (build / "README.md")
    target.write_text(content, encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and validate an internal appsec-advisor plugin package.")
    parser.add_argument("--source", default=".", help="upstream appsec-advisor checkout")
    parser.add_argument("--org-profile", required=True, help="org-profile directory to bundle")
    parser.add_argument("--name", required=True, help="internal plugin name / command namespace")
    parser.add_argument("--version", required=True, help="internal package version")
    parser.add_argument("--build-dir", default="build", help="build output directory")
    parser.add_argument("--dist-dir", default="dist", help="tarball output directory")
    parser.add_argument("--description", default=None, help="plugin.json description override")
    parser.add_argument(
        "--upstream-url", default=None, help="upstream plugin repository URL recorded in package-surface.json"
    )
    parser.add_argument(
        "--info-url",
        default=None,
        help="internal documentation URL shown in the session banner; pass an empty value to drop the line",
    )
    parser.add_argument(
        "--readme", default=None, help="write generated README.md to this path (default: inside build tree)"
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="skip packaged config and org-profile validation",
    )
    parser.add_argument(
        "--skip-archive",
        action="store_true",
        help="build the packaged tree but do not create a tarball",
    )
    parser.add_argument(
        "--package-policy",
        default=None,
        help=("optional package surface policy; defaults to org-profile/package-policy.yaml when present"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source = Path(args.source).resolve()
    org_profile = Path(args.org_profile).resolve()
    build = (Path(args.build_dir) / args.name).resolve()
    dist_dir = Path(args.dist_dir).resolve()
    package_policy, package_policy_path = load_package_policy(org_profile, args.package_policy)

    _validate_package_name(args.name)
    _validate_version(args.version)
    _require_plugin_root(source)
    remove_stale_archive(args.name, args.version, dist_dir)

    print(f"==> Packaging {args.name} {args.version}", flush=True)
    copy_source(source, build)
    overlay_org_profile(org_profile, build)
    patch_plugin_json(build, args.name, args.version, args.description)
    patch_config(build, args.info_url)
    apply_package_surface_policy(build, package_policy, package_policy_path, args.upstream_url)
    surface_manifest = json.loads((build / SURFACE_MANIFEST).read_text(encoding="utf-8"))
    readme_path = Path(args.readme) if args.readme else None
    write_readme(build, args.name, surface_manifest, args.upstream_url, readme_path)
    rewrite_namespace(build, args.name)
    check_namespace_leaks(build)

    if not args.skip_validation:
        run_validation(build)

    if args.skip_archive:
        print(f"==> Build tree ready at {build}")
    else:
        tar_path, sha_path = write_archive(build, args.name, args.version, dist_dir)
        print(f"==> Build tree ready at {build}")
        print(f"==> Artifact: {tar_path}")
        print(f"==> SHA256:   {sha_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
