#!/usr/bin/env python3
"""
baseline_state.py — runtime cache for incremental threat modeling.

Owns `$OUTPUT_DIR/.appsec-cache/baseline.json`: the volatile runtime state
that makes Phase 2 recon skipping and Phase 9 STRIDE carry-forward possible
across runs. This file has no user-facing value — its only job is cache
invalidation and counter bookkeeping.

Separation of concerns:

  threat-model.yaml       → fachliches Modell (components, threats, meta,
                             changelog). Committed. Stable schema.
  .stride-<id>.json       → per-component raw STRIDE findings. gitignored.
  .appsec-cache/baseline  → this file. recon fingerprint, id counters,
                             stride file integrity hashes. gitignored.

On `update`, we:
  1. recompute the recon fingerprint (hashes of manifests, Dockerfiles, IaC
     files) against the current repo root
  2. parse `threat-model.yaml` to bump `id_counters.next_threat_id` past
     the highest T-ID actually in the yaml
  3. sha256 every `.stride-<id>.json` currently in OUTPUT_DIR

Schema version is 1. If you change the schema, bump it and add a migration
path — existing runs must continue to work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA_VERSION = 1

# Files that make up the recon fingerprint. Conservative list — if you add a
# new kind of security-relevant input file, add it here AND invalidate caches
# of prior runs by bumping SCHEMA_VERSION.
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock",
    "mix.exs", "mix.lock",
    "project.clj", "deps.edn",
    "pubspec.yaml", "pubspec.lock",
}

DOCKERFILE_PATTERNS = ("Dockerfile", "Dockerfile.*", "*.Dockerfile", "Containerfile")

IAC_SUFFIXES = {".tf", ".tfvars"}
IAC_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
IAC_DIR_HINTS = ("k8s/", "kubernetes/", "helm/", "terraform/", "ansible/", ".github/workflows/")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _iter_repo_files(repo_root: Path) -> list[Path]:
    """Yield every tracked-ish file under repo_root, skipping the junk dirs
    that would otherwise blow up the fingerprint. We use a simple blacklist
    rather than calling `git ls-files` because the plugin also runs against
    non-git repos.
    """
    skip_dirs = {
        ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
        ".pytest_cache", "dist", "build", "target", ".next", ".cache",
    }
    out: list[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        out.append(p)
    return out


def _compute_recon_fingerprint(repo_root: Path) -> dict:
    """Scan the repo and hash every security-relevant manifest/Dockerfile/IaC
    file. Returns a dict ready to go into baseline.json.recon_fingerprint.
    """
    manifests: dict[str, str] = {}
    dockerfiles: dict[str, str] = {}
    iac: dict[str, str] = {}

    for file in _iter_repo_files(repo_root):
        rel = file.relative_to(repo_root).as_posix()
        name = file.name

        if name in MANIFEST_NAMES:
            manifests[rel] = _sha256(file)
            continue

        is_dockerfile = (
            name == "Dockerfile"
            or name == "Containerfile"
            or name.startswith("Dockerfile.")
            or name.endswith(".Dockerfile")
        )
        if is_dockerfile:
            dockerfiles[rel] = _sha256(file)
            continue

        if (
            file.suffix in IAC_SUFFIXES
            or name in IAC_NAMES
            or any(hint in rel for hint in IAC_DIR_HINTS)
        ):
            iac[rel] = _sha256(file)

    return {
        "manifests": manifests,
        "dockerfiles": dockerfiles,
        "iac": iac,
    }


_T_ID_RE = re.compile(r"T-(\d+)")
_M_ID_RE = re.compile(r"M-(\d+)")


def _scan_max_id(yaml_text: str, pattern: re.Pattern[str]) -> int:
    return max((int(m.group(1)) for m in pattern.finditer(yaml_text)), default=0)


def _hash_stride_files(output_dir: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in sorted(output_dir.glob(".stride-*.json")):
        # .stride-<component-id>.json
        stem = p.name[len(".stride-"):-len(".json")]
        out[stem] = {
            "path": p.name,
            "sha256": _sha256(p),
        }
    return out


def _read_existing(cache_path: Path) -> dict:
    if not cache_path.is_file():
        return {}
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def cmd_update(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).resolve()
    repo_root = Path(args.repo_root).resolve()
    cache_dir = output_dir / ".appsec-cache"
    cache_path = cache_dir / "baseline.json"

    if not output_dir.is_dir():
        print(f"baseline_state: output dir not found: {output_dir}", file=sys.stderr)
        return 1
    if not repo_root.is_dir():
        print(f"baseline_state: repo root not found: {repo_root}", file=sys.stderr)
        return 1

    existing = _read_existing(cache_path)
    prev_counters = existing.get("id_counters", {}) if existing else {}

    yaml_path = output_dir / "threat-model.yaml"
    yaml_text = yaml_path.read_text(encoding="utf-8") if yaml_path.is_file() else ""
    max_t = _scan_max_id(yaml_text, _T_ID_RE)
    max_m = _scan_max_id(yaml_text, _M_ID_RE)

    next_threat_id = max(max_t + 1, int(prev_counters.get("next_threat_id", 1)))
    next_mitigation_id = max(max_m + 1, int(prev_counters.get("next_mitigation_id", 1)))

    fingerprint = _compute_recon_fingerprint(repo_root)
    stride_files = _hash_stride_files(output_dir)

    state = {
        "schema_version": SCHEMA_VERSION,
        "mode": args.mode,
        "recon_fingerprint": fingerprint,
        "id_counters": {
            "next_threat_id": next_threat_id,
            "next_mitigation_id": next_mitigation_id,
        },
        "stride_files": stride_files,
    }

    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"baseline_state: wrote {cache_path} "
        f"(manifests={len(fingerprint['manifests'])}, "
        f"dockerfiles={len(fingerprint['dockerfiles'])}, "
        f"iac={len(fingerprint['iac'])}, "
        f"stride={len(stride_files)}, "
        f"next_T={next_threat_id}, next_M={next_mitigation_id})"
    )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    cache_path = Path(args.output_dir).resolve() / ".appsec-cache" / "baseline.json"
    if not cache_path.is_file():
        print(f"baseline_state: no cache at {cache_path}", file=sys.stderr)
        return 1
    print(cache_path.read_text(encoding="utf-8"))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    cache_path = Path(args.output_dir).resolve() / ".appsec-cache" / "baseline.json"
    if not cache_path.is_file():
        print(f"baseline_state: no cache at {cache_path}", file=sys.stderr)
        return 1
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"baseline_state: invalid JSON: {e}", file=sys.stderr)
        return 2

    errors: list[str] = []
    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version != {SCHEMA_VERSION}: got {data.get('schema_version')}")
    for key in ("recon_fingerprint", "id_counters", "stride_files"):
        if key not in data:
            errors.append(f"missing required key: {key}")

    fp = data.get("recon_fingerprint", {})
    for sub in ("manifests", "dockerfiles", "iac"):
        if sub not in fp:
            errors.append(f"recon_fingerprint.{sub} missing")

    counters = data.get("id_counters", {})
    for sub in ("next_threat_id", "next_mitigation_id"):
        if sub not in counters:
            errors.append(f"id_counters.{sub} missing")

    if errors:
        for e in errors:
            print(f"INVALID: {e}", file=sys.stderr)
        return 2
    print(f"VALID: schema_version={SCHEMA_VERSION}")
    return 0


def cmd_check_fingerprint(args: argparse.Namespace) -> int:
    """Exit 0 if the recon fingerprint matches the current repo state; exit 1
    if it differs (caller should re-run Phase 2 recon); exit 2 on error.

    Used by phase-group-recon.md to decide whether Phase 2 can be skipped.
    """
    output_dir = Path(args.output_dir).resolve()
    repo_root = Path(args.repo_root).resolve()
    cache_path = output_dir / ".appsec-cache" / "baseline.json"

    if not cache_path.is_file():
        print("RECON_CHECK: no baseline cache — run Phase 2 normally", file=sys.stderr)
        return 1

    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"RECON_CHECK: cannot read baseline cache: {e}", file=sys.stderr)
        return 2

    cached_fp = data.get("recon_fingerprint", {})
    current_fp = _compute_recon_fingerprint(repo_root)

    if cached_fp == current_fp:
        print("RECON_CHECK: fingerprint unchanged — Phase 2 may be skipped")
        return 0

    # Report first few diffs for the log
    diffs: list[str] = []
    for kind in ("manifests", "dockerfiles", "iac"):
        cached_keys = set(cached_fp.get(kind, {}).keys())
        current_keys = set(current_fp.get(kind, {}).keys())
        for added in sorted(current_keys - cached_keys)[:3]:
            diffs.append(f"+{kind}:{added}")
        for removed in sorted(cached_keys - current_keys)[:3]:
            diffs.append(f"-{kind}:{removed}")
        for k in sorted(cached_keys & current_keys):
            if cached_fp[kind].get(k) != current_fp[kind].get(k):
                diffs.append(f"~{kind}:{k}")
                if len(diffs) >= 10:
                    break
    print(f"RECON_CHECK: fingerprint changed — {', '.join(diffs[:10]) or 'content differs'}")
    return 1


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="baseline_state.py",
        description="Runtime cache bookkeeping for incremental threat modeling.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("update", help="Refresh baseline.json after a successful run.")
    up.add_argument("--output-dir", required=True)
    up.add_argument("--repo-root", required=True)
    up.add_argument("--mode", choices=("full", "incremental"), default="full")
    up.set_defaults(func=cmd_update)

    sh = sub.add_parser("show", help="Print the current baseline.json.")
    sh.add_argument("--output-dir", required=True)
    sh.set_defaults(func=cmd_show)

    vl = sub.add_parser("validate", help="Validate baseline.json schema.")
    vl.add_argument("--output-dir", required=True)
    vl.set_defaults(func=cmd_validate)

    ck = sub.add_parser(
        "check-fingerprint",
        help="Exit 0 if recon fingerprint matches, 1 if it differs.",
    )
    ck.add_argument("--output-dir", required=True)
    ck.add_argument("--repo-root", required=True)
    ck.set_defaults(func=cmd_check_fingerprint)

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
