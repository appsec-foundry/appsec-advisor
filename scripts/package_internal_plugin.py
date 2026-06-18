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
TEXT_SUFFIXES = {".json", ".md", ".txt", ".yaml", ".yml"}
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
ANY_LEVEL_EXCLUDES = {"__pycache__"}
PATH_EXCLUDES = {
    ("docs", "security"),
    ("scripts", "docs"),
    ("tests", "fixtures", "e2e", "_last-run"),
}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SURFACE_MANIFEST = ".claude-plugin/package-surface.json"
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


def patch_config(build: Path) -> None:
    config_path = build / "config.json"
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data["organization_profile"] = {
        "enabled": True,
        "path": "org-profile/org-profile.yaml",
    }
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
    unknown = set(surface) - {"skills", "hooks"}
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


def apply_hook_policy(build: Path, surface: dict) -> dict:
    available = _available_hook_ids(build)
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
        "included": sorted(keep),
        "removed": removed,
        "events": sorted(filtered_events),
    }


def write_surface_manifest(
    build: Path,
    policy_path: Path | None,
    skills: dict,
    hooks: dict,
    upstream_url: str | None = None,
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
    skills = apply_skill_policy(build, surface)
    hooks = apply_hook_policy(build, surface)
    write_surface_manifest(build, policy_path, skills, hooks, upstream_url)


def _text_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
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
    for root_name in ("skills", "agents"):
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
}

# Skills with their own detailed section in the README
MAIN_SKILLS = ["create-threat-model", "audit-security-requirements", "verify-requirements"]
# Skills grouped into a single utility section
UTILITY_SKILLS = ["threat-model-health", "check-permissions", "status", "fix-run-issues", "clean-run-state"]


def _skill_description(build: Path, skill: str) -> str:
    skill_md = build / "skills" / skill / "SKILL.md"
    if not skill_md.exists():
        return ""
    for line in skill_md.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("description:"):
            desc = line[len("description:") :].strip()
            # Truncate at first sentence boundary for readability
            for sep in (". ", ".\n"):
                idx = desc.find(sep)
                if idx != -1:
                    desc = desc[: idx + 1]
                    break
            return desc
    return ""


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
    patch_config(build)
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
