#!/usr/bin/env python3
"""
baseline_state.py — runtime cache for incremental threat modeling.

Owns `$OUTPUT_DIR/.appsec-cache/baseline.json`: the volatile runtime state
that makes Phase 2 recon skipping and Phase 9 STRIDE carry-forward possible
across runs. This file has no user-facing value — its only job is cache
invalidation and counter bookkeeping.

Separation of concerns:

  threat-model.yaml       → semantic threat model (components, threats, meta,
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

# Local import — plugin_meta lives next to this file.
try:
    from plugin_meta import load_meta as _load_plugin_meta, classify_compat as _classify_compat
except ImportError:  # pragma: no cover — only fails when baseline_state is run outside plugin/scripts
    _load_plugin_meta = None  # type: ignore[assignment]
    _classify_compat = None  # type: ignore[assignment]

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


def _parse_manifest_hashes(raw: str | None) -> dict | None:
    """Parse a pre-computed manifest-hashes JSON string.

    Returns the parsed dict if valid, or None to fall back to computing from repo.
    Expected format: ``{"manifests": {...}, "dockerfiles": {...}, "iac": {...}}``
    """
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "manifests" in data:
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    return None


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

    def _parse_counter(raw, fallback: int = 1) -> int:
        """Parse a counter value that may be int, 'T-025' / 'M-025' string, or missing."""
        if raw is None:
            return fallback
        if isinstance(raw, int):
            return raw
        s = str(raw).strip()
        # Accept legacy 'T-025' / 'M-025' strings written by pre-M2.7 bootstraps
        # or by manually edited baseline.json files.
        if s and s[0:2] in ("T-", "M-"):
            s = s[2:]
        try:
            return int(s)
        except (TypeError, ValueError):
            return fallback

    next_threat_id = max(max_t + 1, _parse_counter(prev_counters.get("next_threat_id"), 1))
    next_mitigation_id = max(max_m + 1, _parse_counter(prev_counters.get("next_mitigation_id"), 1))

    # Use pre-computed hashes if passed via --manifest-hashes to skip rglob
    precomputed = _parse_manifest_hashes(getattr(args, "manifest_hashes", None))
    fingerprint = precomputed if precomputed else _compute_recon_fingerprint(repo_root)
    stride_files = _hash_stride_files(output_dir)

    plugin_meta = _load_plugin_meta() if _load_plugin_meta else {}
    plugin_version = plugin_meta.get("plugin_version", "unknown")
    analysis_version = int(plugin_meta.get("analysis_version", 0))

    state = {
        "schema_version": SCHEMA_VERSION,
        "plugin_version": plugin_version,
        "analysis_version": analysis_version,
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
        f"(plugin_version={plugin_version}, analysis_version={analysis_version}, "
        f"manifests={len(fingerprint['manifests'])}, "
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
    warnings: list[str] = []
    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version != {SCHEMA_VERSION}: got {data.get('schema_version')}")
    for key in ("recon_fingerprint", "id_counters", "stride_files"):
        if key not in data:
            errors.append(f"missing required key: {key}")

    # Version fields are soft-required: a baseline written by an older plugin
    # version may not have them. Missing -> warn (triggers recommend-full on
    # next run via check-compat); present but malformed -> hard error.
    if "analysis_version" not in data:
        warnings.append("analysis_version missing (pre-versioning baseline)")
    else:
        try:
            int(data["analysis_version"])
        except (TypeError, ValueError):
            errors.append(f"analysis_version must be int: got {data['analysis_version']!r}")
    if "plugin_version" not in data:
        warnings.append("plugin_version missing (pre-versioning baseline)")

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
    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    pv = data.get("plugin_version", "unknown")
    av = data.get("analysis_version", "missing")
    print(f"VALID: schema_version={SCHEMA_VERSION} plugin_version={pv} analysis_version={av}")
    return 0


def _extract_baseline_analysis_version(output_dir: Path) -> tuple[int | None, str]:
    """Return (analysis_version, source) for the prior baseline.

    Priority:
      1. threat-model.yaml  -> meta.analysis_version (the authoritative, committed baseline)
      2. .appsec-cache/baseline.json -> analysis_version (runtime cache)

    Returns (None, "missing") if neither source contains a version — this is
    how a pre-versioning baseline looks and how the skill distinguishes
    "legacy but present" from "hard-fail incompatible".
    """
    yaml_path = output_dir / "threat-model.yaml"
    if yaml_path.is_file():
        try:
            text = yaml_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        # Simple line-oriented parse — we don't pull in pyyaml just for one
        # int field. meta.analysis_version lives inside the top-level `meta:`
        # block; match only a root-aligned line to avoid accidentally picking
        # up a nested key with the same name.
        m = re.search(r"(?m)^\s{2}analysis_version:\s*(\d+)\s*$", text)
        if m:
            return (int(m.group(1)), "threat-model.yaml")

    cache_path = output_dir / ".appsec-cache" / "baseline.json"
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        if "analysis_version" in data:
            try:
                return (int(data["analysis_version"]), "baseline.json")
            except (TypeError, ValueError):
                pass

    return (None, "missing")


def cmd_check_compat(args: argparse.Namespace) -> int:
    """Classify the prior baseline's analysis_version against the current plugin.

    Reuses plugin_meta.classify_compat so the skill, the orchestrator, and
    this script all return the same exit codes for the same inputs.

    Exit codes (from plugin_meta):
      0   COMPAT_EQUAL          — baseline matches current analysis_version
      10  COMPAT_RECOMMEND_FULL — baseline older but still in compatible list
      20  INCOMPAT              — baseline outside compatible list; must --full
      30  BASELINE_MISSING      — no version found (legacy)
      2   ERROR                 — plugin_meta not importable / I/O error
    """
    if _classify_compat is None or _load_plugin_meta is None:
        print("baseline_state: plugin_meta helper unavailable", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir).resolve()
    if not output_dir.is_dir():
        print(f"baseline_state: output dir not found: {output_dir}", file=sys.stderr)
        return 2

    baseline_version, source = _extract_baseline_analysis_version(output_dir)
    meta = _load_plugin_meta()
    exit_code, msg = _classify_compat(baseline_version, meta)

    # Stream choice mirrors plugin_meta.cmd_check_compat: equal goes to stdout,
    # everything else to stderr — makes shell-side `2>/dev/null` work cleanly.
    stream = sys.stdout if exit_code == 0 else sys.stderr
    print(f"BASELINE_COMPAT: source={source} baseline_version={baseline_version} {msg}", file=stream)
    return exit_code


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
    up.add_argument("--manifest-hashes", default=None,
                    help="Pre-computed recon fingerprint JSON (skips rglob scan)")
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

    cc = sub.add_parser(
        "check-compat",
        help="Classify the prior baseline's analysis_version against the current plugin.",
    )
    cc.add_argument("--output-dir", required=True)
    cc.set_defaults(func=cmd_check_compat)

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
