#!/usr/bin/env python3
"""model/resolve_abuse_cases.py — assemble the active abuse-case set for a run.

Merges three sources into one validated list of abuse-case definitions:

  1. the plugin standard library (``data/abuse-cases/default-library.yaml``)
     unless the org profile sets ``abuse_cases.inherit_defaults: false``;
  2. org-specific case files matched by ``abuse_cases.add`` (a glob relative to
     the org-profile directory), validated against
     ``schemas/abuse-cases.schema.yaml``;
  3. repo-local files under ``<repo>/docs/security/abuse-cases/`` or the
     legacy ``<repo>/.appsec/abuse-cases/``, and explicit
     per-scan files, both bounded by ``data/abuse-case-limits.yaml``;
  4. minus any ids listed in ``abuse_cases.disable``.

Consumed by ``scripts/model/match_abuse_cases.py`` (deterministic matcher) and by
``scripts/validators/validate_org_profile.py`` (semantic validation of the org glob).

The resolver is pure data assembly — no agent dispatch, no recon, no matching.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LIBRARY = PLUGIN_ROOT / "data" / "abuse-cases" / "default-library.yaml"
ABUSE_CASE_SCHEMA = PLUGIN_ROOT / "schemas" / "abuse-cases.schema.yaml"
LIMITS_FILE = PLUGIN_ROOT / "data" / "abuse-case-limits.yaml"
LIMITS_SCHEMA = PLUGIN_ROOT / "schemas" / "abuse-case-limits.schema.json"
SUPPORTED_SCHEMA_VERSIONS = (1, 2)
CASE_FILE_SUFFIXES = (".yaml", ".yml")
# A rejection reason quotes validator messages, which can echo file content.
_MAX_REASON_CHARS = 300


def _load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects a key repeated in one mapping.

    Plain YAML keeps the last value, so a repeated key would silently replace
    what the author wrote first.
    """


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict:
    seen: set = set()
    for key_node, _value in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=True)
        try:
            repeated = key in seen
        except TypeError:
            continue
        if repeated:
            raise yaml.constructor.ConstructorError(None, None, f"duplicate key {str(key)[:60]!r}", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep=True)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def _load_case_yaml(text: str | bytes) -> Any:
    return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 — SafeLoader subclass


def _load_schema() -> dict:
    return _load_yaml(ABUSE_CASE_SCHEMA)


def load_limits(path: Path = LIMITS_FILE) -> dict[str, int]:
    """Return the enforced abuse-case limits as ``{name: value}``."""
    import jsonschema

    data = _load_yaml(path)
    jsonschema.Draft202012Validator(json.loads(LIMITS_SCHEMA.read_text(encoding="utf-8"))).validate(data)
    return {name: entry["value"] for name, entry in data["limits"].items()}


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    """Read a regular, non-symlink file of at most ``max_bytes``."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("not a regular file")
        body = handle.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(f"exceeds the case file size limit of {max_bytes // 1024} KiB")
    return body


def _schema_errors(doc: Any, schema: dict, label: str) -> list[str]:
    try:
        import jsonschema
    except ImportError:
        return [f"{label}: jsonschema not installed; cannot validate abuse cases"]
    validator = jsonschema.Draft202012Validator(schema)
    cases = doc.get("abuse_cases") if isinstance(doc, dict) else None
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
        parts = [str(p) for p in err.path]
        # Name the case an author recognizes, not only its list position.
        if len(parts) >= 2 and parts[0] == "abuse_cases" and isinstance(cases, list):
            index = int(parts[1])
            case_id = cases[index].get("id") if index < len(cases) and isinstance(cases[index], dict) else None
            if isinstance(case_id, str):
                parts[1] = f"{parts[1]} ({case_id})"
        loc = "/".join(parts) or "<root>"
        out.append(f"{label}: {loc}: {err.message}")
    return out


def _version_errors(doc: dict, label: str) -> list[str]:
    """Reject unknown file versions and descriptive cases in version-1 files."""
    version = doc.get("schema_version", 1)
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(str(v) for v in SUPPORTED_SCHEMA_VERSIONS)
        return [f"{label}: schema_version {version!r} is not supported; supported versions: {supported}"]
    if version == 1:
        for case in doc.get("abuse_cases") or []:
            if isinstance(case, dict) and case.get("kind") == "descriptive":
                return [f"{label}: {case.get('id')}: descriptive cases require schema_version: 2"]
    return []


def _check_grants_requires(case: dict, label: str) -> list[str]:
    """Each step's ``requires`` must be granted by an earlier step (or be an
    external precondition declared on step 1). A dangling ``requires`` means the
    chain cannot be verified end-to-end."""
    errors: list[str] = []
    granted: set[str] = set()
    chain = case.get("chain") or []
    for i, step in enumerate(chain):
        req = (step.get("requires") or "").strip()
        if req and req not in granted and i > 0:
            errors.append(f"{label}: step {step.get('step')} requires '{req}' which no earlier step grants")
        grants = (step.get("grants") or "").strip()
        if grants:
            granted.add(grants)
    return errors


def _load_case_file(path: Path, schema: dict, max_bytes: int | None = None) -> tuple[list[dict], list[str]]:
    """Load one case file (`{abuse_cases: [...]}`), validate, return
    (cases, errors). ``max_bytes`` bounds untrusted repository input; such a
    file must be a regular file, not a symlink."""
    label = path.name
    try:
        if max_bytes is None:
            doc = _load_case_yaml(path.read_text(encoding="utf-8"))
        else:
            doc = _load_case_yaml(_read_bounded(path, max_bytes))
    except ValueError as exc:
        return [], [f"{label}: {exc}"]
    except OSError:
        return [], [f"{label}: unreadable or a symbolic link"]
    except yaml.YAMLError as exc:
        return [], [f"{label}: cannot parse: {exc}"]
    if not isinstance(doc, dict):
        return [], [f"{label}: top-level must be a mapping with 'abuse_cases'"]
    errors = _version_errors(doc, label) or _schema_errors(doc, schema, label)
    cases = doc.get("abuse_cases") or []
    if not errors:
        for case in cases:
            errors += _check_grants_requires(case, f"{label}:{case.get('id')}")
    return (cases if not errors else []), errors


def descriptive_steps(case: dict) -> list[str]:
    """A descriptive case's steps; an open case has one step, its check."""
    return list(case.get("steps") or ([case["check"]] if case.get("check") else []))


def case_chain(case: dict) -> list[dict]:
    """Return a case's chain steps; descriptive steps become prose-only steps.

    Downstream consumers (verifier context, report, canonical YAML) iterate
    one step shape. A descriptive step carries no probe, grant, or finding
    classification, and every step is required.
    """
    if case.get("kind") != "descriptive":
        return list(case.get("chain") or [])
    return [
        {"step": index, "label": text, "description": text, "required": True}
        for index, text in enumerate(descriptive_steps(case), start=1)
    ]


# Repository case directories in precedence order: the documented location
# beside the other team-maintained security inputs, then the legacy one.
REPO_LOCAL_SUBDIRS = (Path("docs") / "security" / "abuse-cases", Path(".appsec") / "abuse-cases")


def _reason(errors: list[str]) -> str:
    text = "; ".join(errors)
    return text if len(text) <= _MAX_REASON_CHARS else text[: _MAX_REASON_CHARS - 1] + "…"


def _repo_local_files(root: Path, subdir: Path, max_files: int, admitted: int = 0) -> tuple[list[Path], list[dict]]:
    """Return (admissible files, rejections) for ``<root>/<subdir>``.

    The directory and every file must stay inside the repository. Symbolic
    links are not followed; files beyond the count limit, which ``admitted``
    files from earlier locations already use, are rejected by name.
    """
    repo_dir = root / subdir
    rel_dir = subdir.as_posix()
    if not repo_dir.exists() and not repo_dir.is_symlink():
        return [], []
    try:
        repo_dir.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        return [], [{"path": rel_dir, "reason": "directory resolves outside the repository"}]
    if repo_dir.is_symlink() or not repo_dir.is_dir():
        return [], [{"path": rel_dir, "reason": "not a directory inside the repository"}]
    files: list[Path] = []
    rejected: list[dict] = []
    for path in sorted(p for p in repo_dir.iterdir() if p.suffix in CASE_FILE_SUFFIXES):
        rel = f"{rel_dir}/{path.name}"
        if path.is_symlink():
            rejected.append({"path": rel, "reason": "symbolic links are not admitted"})
        elif admitted + len(files) >= max_files:
            rejected.append({"path": rel, "reason": f"exceeds the limit of {max_files} repository case files"})
        else:
            files.append(path)
    return files, rejected


def resolve_abuse_case_sources(
    org_profile: dict | None,
    profile_dir: Path | None,
    plugin_root: Path = PLUGIN_ROOT,
    repo_root: Path | None = None,
    extra_case_files: list[Path] | None = None,
    limits: dict[str, int] | None = None,
    origins: dict[str, str] | None = None,
) -> tuple[list[dict], list[str], list[dict]]:
    """Return (active_cases, errors, rejected_repo_files).

    When ``origins`` is a dict, it receives ``{case id: origin}`` with origin
    ``library``, ``org``, ``repo``, or ``explicit``. Only ``explicit`` cases
    came from this invocation's own arguments.

    Sources, in load order:
      1. plugin standard library (unless ``inherit_defaults: false``);
      2. org-profile cases matched by ``abuse_cases.add`` (glob relative to
         ``profile_dir``);
      3. **repo-local** cases under ``<repo_root>/docs/security/abuse-cases/``,
         then the legacy ``<repo_root>/.appsec/abuse-cases/`` —
         a zero-config layer that needs no org profile, mirroring the
         known-threats convention so a single repository can ship its own
         scenarios checked into version control;
      4. explicit per-scan files below ``repo_root``;
      minus any ids in ``abuse_cases.disable``.

    Library, org, and explicit-file problems are ``errors``: the operator
    chose those inputs, so the caller fails closed. A repo-local file that is
    invalid, oversized, a symlink, or reuses a loaded id is rejected on its
    own and listed in ``rejected_repo_files`` as ``{path, reason}``; every
    other case stays active, so one broken repository file cannot remove the
    library from a run.
    """
    schema = _load_schema()
    limits = limits or load_limits()
    max_bytes = limits["case_file_kib"] * 1024
    cfg = (org_profile or {}).get("abuse_cases") or {}
    inherit = cfg.get("inherit_defaults", True)
    disabled = set(cfg.get("disable") or [])
    add_glob = cfg.get("add", "abuse-cases/*.yaml")

    cases: list[dict] = []
    errors: list[str] = []
    rejected: list[dict] = []
    loaded_paths: set[Path] = set()
    origin_of: dict[str, str] = {}

    def _admit(file_cases: list[dict], origin: str) -> None:
        cases.extend(file_cases)
        for case in file_cases:
            origin_of.setdefault(case.get("id"), origin)

    library = plugin_root / "data" / "abuse-cases" / "default-library.yaml"
    if inherit and library.exists():
        lib_cases, lib_errors = _load_case_file(library, schema)
        _admit(lib_cases, "library")
        errors += lib_errors

    if profile_dir is not None and add_glob:
        for path in sorted(profile_dir.glob(add_glob)):
            file_cases, file_errors = _load_case_file(path, schema)
            _admit(file_cases, "org")
            errors += file_errors

    # Every id loaded so far, disabled or not: a repository file reusing one
    # would otherwise shadow or be shadowed by a trusted definition.
    known_ids = {case.get("id") for case in cases}

    if repo_root is not None:
        root = Path(repo_root).resolve()
        files: list[tuple[Path, str]] = []
        for subdir in REPO_LOCAL_SUBDIRS:
            found, dir_rejected = _repo_local_files(root, subdir, limits["repo_case_files"], len(files))
            files += [(path, f"{subdir.as_posix()}/{path.name}") for path in found]
            rejected += dir_rejected
        for path, rel in files:
            file_cases, file_errors = _load_case_file(path, schema, max_bytes)
            ids = [case.get("id") for case in file_cases]
            clash = sorted({cid for cid in ids if cid in known_ids or ids.count(cid) > 1})
            if not file_errors and clash:
                file_errors = [f"{path.name}: duplicate abuse-case id {cid!r}" for cid in clash]
            if file_errors:
                rejected.append({"path": rel, "reason": _reason(file_errors)})
                continue
            _admit(file_cases, "repo")
            known_ids.update(ids)
            loaded_paths.add(path.resolve())

    # Explicit per-scan files are constrained to the target repository. They
    # are untrusted data, not arbitrary host-file reads. Unlike the automatic
    # repo-local layer they may live anywhere below the repository root.
    if extra_case_files:
        if repo_root is None:
            errors.append("explicit abuse-case files require a repository root")
        else:
            root = Path(repo_root).resolve()
            for raw_path in extra_case_files:
                path = Path(raw_path)
                candidate = (root / path).resolve() if not path.is_absolute() else path.resolve()
                try:
                    candidate.relative_to(root)
                except ValueError:
                    errors.append(f"explicit abuse-case file {path!s} resolves outside the repository")
                    continue
                if candidate.suffix not in CASE_FILE_SUFFIXES or not candidate.is_file():
                    errors.append(f"explicit abuse-case file {path!s} is not a readable YAML file")
                    continue
                # Naming a file the repo-local layer already picked up is a
                # redundant argument, not a duplicate definition — load it once.
                if candidate in loaded_paths:
                    continue
                loaded_paths.add(candidate)
                file_cases, file_errors = _load_case_file(candidate, schema, max_bytes)
                _admit(file_cases, "explicit")
                errors += file_errors

    # Apply disable + detect duplicate ids (org override wins is NOT supported —
    # a duplicate id is an authoring error, surfaced rather than silently merged).
    seen: dict[str, str] = {}
    active: list[dict] = []
    for case in cases:
        cid = case.get("id")
        if cid in disabled:
            continue
        if cid in seen:
            errors.append(f"duplicate abuse-case id {cid!r} (already defined)")
            continue
        seen[cid] = case.get("title", "")
        active.append(case)

    if origins is not None:
        origins.update({cid: origin_of[cid] for cid in seen})
    return active, errors, rejected


def resolve_abuse_cases(
    org_profile: dict | None,
    profile_dir: Path | None,
    plugin_root: Path = PLUGIN_ROOT,
    repo_root: Path | None = None,
    extra_case_files: list[Path] | None = None,
) -> tuple[list[dict], list[str]]:
    """Return (active_cases, errors) — see ``resolve_abuse_case_sources``.

    Rejected repo-local files are left out of the active set; callers that
    must report them use ``resolve_abuse_case_sources``.
    """
    active, errors, _rejected = resolve_abuse_case_sources(
        org_profile, profile_dir, plugin_root, repo_root, extra_case_files
    )
    return active, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve the active abuse-case set.")
    parser.add_argument("--org-profile", default=None, help="path to org-profile.yaml")
    parser.add_argument("--plugin-root", default=None)
    parser.add_argument(
        "--repo-root",
        default=None,
        help="target repo root; loads <repo>/docs/security/abuse-cases/ and <repo>/.appsec/abuse-cases/",
    )
    parser.add_argument("--list-ids", action="store_true", help="print active ids only")
    args = parser.parse_args(argv)

    plugin_root = Path(args.plugin_root) if args.plugin_root else PLUGIN_ROOT
    repo_root = Path(args.repo_root) if args.repo_root else None
    profile: dict | None = None
    profile_dir: Path | None = None
    if args.org_profile:
        p = Path(args.org_profile)
        profile = _load_yaml(p)
        profile_dir = p.parent

    cases, errors, rejected = resolve_abuse_case_sources(profile, profile_dir, plugin_root, repo_root)
    # As a validation command every problem fails, including a repository
    # file that a scan would only reject on its own.
    for item in rejected:
        sys.stderr.write(f"REJECTED: {item['path']}: {item['reason']}\n")
    if errors or rejected:
        for e in errors:
            sys.stderr.write(f"ERROR: {e}\n")
        return 1
    if args.list_ids:
        for c in cases:
            print(c["id"])
    else:
        json.dump({"abuse_cases": cases}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
