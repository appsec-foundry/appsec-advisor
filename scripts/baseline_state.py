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
import os
import re
import subprocess
import sys
from pathlib import Path

# Local import — plugin_meta lives next to this file.
try:
    from plugin_meta import (
        classify_compat as _classify_compat,
    )
    from plugin_meta import (
        classify_plugin_version as _classify_plugin_version,
    )
    from plugin_meta import (
        load_meta as _load_plugin_meta,
    )
except ImportError:  # pragma: no cover — only fails when baseline_state is run outside scripts
    _load_plugin_meta = None  # type: ignore[assignment]
    _classify_compat = None  # type: ignore[assignment]
    _classify_plugin_version = None  # type: ignore[assignment]

from _atomic_io import atomic_write_json

SCHEMA_VERSION = 1

# Files that make up the recon fingerprint. Conservative list — if you add a
# new kind of security-relevant input file, add it here AND invalidate caches
# of prior runs by bumping SCHEMA_VERSION.
MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "poetry.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "mix.exs",
    "mix.lock",
    "project.clj",
    "deps.edn",
    "pubspec.yaml",
    "pubspec.lock",
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


def _iter_repo_files(repo_root: Path, exclude_rel_prefix: str | None = None) -> list[Path]:
    """Yield every tracked-ish file under repo_root, skipping the junk dirs
    that would otherwise blow up the fingerprint. We use a simple blacklist
    rather than calling `git ls-files` because the plugin also runs against
    non-git repos.

    ``exclude_rel_prefix`` (posix path relative to repo_root) skips the
    plugin's own OUTPUT_DIR — plugin-output is never security-relevant
    and including it would make every uncommitted output file flip the
    fingerprint.
    """
    skip_dirs = {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        "target",
        ".next",
        ".cache",
    }
    skip_prefix = (exclude_rel_prefix.rstrip("/") + "/") if exclude_rel_prefix else None
    out: list[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        if skip_prefix:
            try:
                rel = p.relative_to(repo_root).as_posix()
            except ValueError:
                rel = ""
            if rel.startswith(skip_prefix):
                continue
        out.append(p)
    return out


def _compute_recon_fingerprint(repo_root: Path, exclude_rel_prefix: str | None = None) -> dict:
    """Scan the repo and hash every security-relevant manifest/Dockerfile/IaC
    file. Returns a dict ready to go into baseline.json.recon_fingerprint.

    ``exclude_rel_prefix`` skips the plugin's own OUTPUT_DIR (e.g.
    ``docs/security/``) so its uncommitted intermediate files never
    flip the fingerprint.
    """
    manifests: dict[str, str] = {}
    dockerfiles: dict[str, str] = {}
    iac: dict[str, str] = {}

    for file in _iter_repo_files(repo_root, exclude_rel_prefix=exclude_rel_prefix):
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

        if file.suffix in IAC_SUFFIXES or name in IAC_NAMES or any(hint in rel for hint in IAC_DIR_HINTS):
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
        stem = p.name[len(".stride-") : -len(".json")]
        out[stem] = {
            "path": p.name,
            "sha256": _sha256(p),
        }
    return out


def _hash_slice_files(output_dir: Path) -> dict[str, dict]:
    """Hash per-component actor slices for incremental STRIDE re-dispatch (actors.md §13)."""
    out: dict[str, dict] = {}
    for p in sorted(output_dir.glob(".actors-for-*.json")):
        # .actors-for-<component-id>.json
        stem = p.name[len(".actors-for-") : -len(".json")]
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

    # Use pre-computed hashes if passed via --manifest-hashes to skip rglob.
    # When computing fresh, exclude OUTPUT_DIR so the plugin's own writes
    # never flip the fingerprint between runs.
    precomputed = _parse_manifest_hashes(getattr(args, "manifest_hashes", None))
    if precomputed:
        fingerprint = precomputed
    else:
        out_rel = _output_dir_relative_to_repo(output_dir, repo_root)
        fingerprint = _compute_recon_fingerprint(repo_root, exclude_rel_prefix=out_rel)
    stride_files = _hash_stride_files(output_dir)
    slice_files = _hash_slice_files(output_dir)

    # Working-tree snapshot: content hashes of every file that is dirty-vs-HEAD
    # right now (the moment this baseline is written). cmd_check_changes uses it
    # so a file left uncommitted-but-unmodified across runs is recognised as
    # unchanged-since-the-threat-model rather than re-scanned every time it
    # shows up in `git diff`. Manifests are already covered by the recon
    # fingerprint; this generalises the same content comparison to any file.
    out_rel_snap = _output_dir_relative_to_repo(output_dir, repo_root)
    _, working_dirty = _git_diff_names(repo_root, None)
    working_dirty = _filter_diff_paths_via_scan_excludes(working_dirty, out_rel_snap)
    working_tree_snapshot: dict[str, str] = {}
    for rel in working_dirty:
        try:
            working_tree_snapshot[rel] = _sha256(repo_root / rel)
        except OSError:
            continue

    plugin_meta = _load_plugin_meta() if _load_plugin_meta else {}
    plugin_version = plugin_meta.get("plugin_version", "unknown")
    analysis_version = int(plugin_meta.get("analysis_version", 0))

    from datetime import datetime, timezone

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
        "slice_files": slice_files,
        "working_tree_snapshot": working_tree_snapshot,
        "last_run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    # Carry forward the next-run estimator's fields. `cmd_update` rewrites
    # baseline.json from a fresh dict, so without this any baseline write
    # that runs after a prior run's finalization (recon-skip baseline,
    # --incremental/--rebuild re-runs) would silently wipe `last_run_seconds`
    # and the per-component STRIDE durations — exactly the gap that left
    # `last_run_seconds=None` in the 2026-06 juice-shop anchor caches while
    # `component_durations`/`last_run_at` survived. These are pure carry-
    # through (the run-end finalization in SKILL-impl.md owns the writes);
    # we only refuse to destroy them. id_counters is already preserved above.
    for _carry in (
        "last_run_seconds",
        "last_run_mode",
        "last_run_depth",
        "last_run_iso",
        "component_durations",
        "component_durations_recorded_at",
        "component_durations_phase_9_start",
    ):
        if _carry in existing and _carry not in state:
            state[_carry] = existing[_carry]

    # Mirror the committed changelog from threat-model.yaml into the cache.
    # The yaml is the canonical, schema-stable store, but it is fragile: it is
    # frequently untracked in git (the completion summary even nudges users to
    # gitignore docs/security/), and a crash mid-write, a stray rm, or a
    # --rebuild removes it outright. baseline.json lives under .appsec-cache/
    # and survives the --full intermediate wipe, so mirroring the changelog
    # here lets build_threat_model_yaml.py rehydrate an accumulating history
    # instead of silently resetting a lost yaml to "first full scan". The yaml
    # stays authoritative — this is a recovery copy, never the primary source.
    # Best-effort: a parse failure or a changelog-less yaml must never drop an
    # existing mirror (that would defeat the durability it provides).
    changelog_mirror = None
    if yaml_text:
        try:
            import yaml as _yaml  # noqa: PLC0415

            changelog_mirror = (_yaml.safe_load(yaml_text) or {}).get("changelog")
        except Exception:
            changelog_mirror = None
    if changelog_mirror:
        state["changelog_mirror"] = changelog_mirror
    elif existing.get("changelog_mirror"):
        state["changelog_mirror"] = existing["changelog_mirror"]

    cache_dir.mkdir(parents=True, exist_ok=True)
    # Atomic tempfile+rename — a crash mid-write must leave the prior cache
    # intact or the file absent, never a truncated JSON. See _atomic_io.py.
    atomic_write_json(cache_path, state, indent=2, sort_keys=True)

    print(
        f"baseline_state: wrote {cache_path} "
        f"(plugin_version={plugin_version}, analysis_version={analysis_version}, "
        f"manifests={len(fingerprint['manifests'])}, "
        f"dockerfiles={len(fingerprint['dockerfiles'])}, "
        f"iac={len(fingerprint['iac'])}, "
        f"stride={len(stride_files)}, "
        f"slice={len(slice_files)}, "
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
    out_rel = _output_dir_relative_to_repo(output_dir, repo_root)
    current_fp = _compute_recon_fingerprint(repo_root, exclude_rel_prefix=out_rel)

    if cached_fp == current_fp:
        # The bare fingerprint is manifest/Dockerfile/IaC-only — blind to
        # application source. On the incremental path that is fine: the
        # orchestrator's git-diff STRIDE pass back-stops a source change. On the
        # auto-upgraded-full recon-reuse path there is NO such back-stop, so the
        # caller passes --require-clean-tree to demand a PROVABLY unchanged repo
        # (git-aware: committed-since-baseline + working tree + untracked).
        if getattr(args, "require_clean_tree", False):
            baseline_sha = _extract_baseline_commit_sha(output_dir)
            # A non-git repo makes every git probe fail silently (→ looks
            # "clean"), and without a baseline SHA we cannot prove the committed
            # history is unchanged. Either case: we cannot prove cleanliness, so
            # be conservative and run recon.
            if baseline_sha is None or _git_head(repo_root) is None:
                print(
                    "RECON_CHECK: --require-clean-tree but repo is not git-provable "
                    "(no baseline commit_sha or not a git repo) — running Phase 2 recon",
                    file=sys.stderr,
                )
                return 1
            committed, working = _git_diff_names(repo_root, baseline_sha)
            committed = _filter_diff_paths_via_scan_excludes(committed, out_rel)
            working = _filter_diff_paths_via_scan_excludes(working, out_rel)
            if committed or working:
                sample = (committed + working)[:5]
                print(
                    "RECON_CHECK: fingerprint matches but working tree not clean "
                    f"({len(committed) + len(working)} changed: {', '.join(sample)}) — "
                    "running Phase 2 recon"
                )
                return 1
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


def _extract_baseline_plugin_version(output_dir: Path) -> str | None:
    """Return the plugin_version recorded in the prior baseline (yaml wins,
    then .appsec-cache/baseline.json)."""
    yaml_path = output_dir / "threat-model.yaml"
    if yaml_path.is_file():
        try:
            text = yaml_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        m = re.search(r"(?m)^\s{2}plugin_version:\s*['\"]?([^'\"\s]+)['\"]?\s*$", text)
        if m:
            return m.group(1)

    cache_path = output_dir / ".appsec-cache" / "baseline.json"
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        v = data.get("plugin_version")
        if isinstance(v, str) and v:
            return v
    return None


def _extract_baseline_commit_sha(output_dir: Path) -> str | None:
    """Return the commit_sha recorded in the prior baseline yaml's meta.git block."""
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        return None
    try:
        text = yaml_path.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r"(?m)^\s{4}commit_sha:\s*['\"]?([0-9a-f]{7,40})['\"]?\s*$", text)
    return m.group(1) if m else None


def _git_diff_names(repo_root: Path, base_ref: str | None) -> tuple[list[str], list[str]]:
    """Return (committed_changes, working_tree_changes) file lists.

    committed_changes uses either `<base>..HEAD` (if base_ref is given) or `<base>..HEAD`
    with base_ref falling back to None -> empty list. Working-tree changes come from
    `git diff --name-only` (staged + unstaged).
    """
    committed: list[str] = []
    working: list[str] = []
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        if base_ref:
            r = subprocess.run(
                ["git", "-C", str(repo_root), "diff", "--name-only", f"{base_ref}..HEAD"],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
            )
            if r.returncode == 0:
                committed = [ln for ln in r.stdout.splitlines() if ln]

        r = subprocess.run(
            ["git", "-C", str(repo_root), "diff", "--name-only"],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )
        if r.returncode == 0:
            working = [ln for ln in r.stdout.splitlines() if ln]
        # Include staged changes too (diff --cached)
        r = subprocess.run(
            ["git", "-C", str(repo_root), "diff", "--name-only", "--cached"],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )
        if r.returncode == 0:
            for ln in r.stdout.splitlines():
                if ln and ln not in working:
                    working.append(ln)
        # Untracked (new, never git-added) files. `git diff` is blind to these,
        # but a brand-new source file (e.g. a new route handler) IS a source
        # change that must invalidate a no-source-changes / recon-reuse verdict.
        r = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "--others", "--exclude-standard"],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )
        if r.returncode == 0:
            for ln in r.stdout.splitlines():
                if ln and ln not in working:
                    working.append(ln)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return committed, working


def _git_head(repo_root: Path) -> str | None:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0:
            sha = r.stdout.strip()
            return sha or None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def _classify_changed_files_relevance(
    repo_root: Path,
    baseline_sha: str | None,
    all_files: list[str],
) -> tuple[list[str], list[str], dict[str, list[str]]]:
    """Split all_files into (security_relevant, noise_only, reasons_by_file).

    The third return is a per-file ``{path: [reason, …]}`` mapping that
    feeds the human-readable pre-check banner so users can see *why* a
    file flipped the verdict (e.g. ``["name:package.json"]`` for a
    manifest hit, or ``["pattern:auth", "structural:env_security"]`` for
    a Tier-2 hit).

    Conservative fallback: if the filter import fails, everything stays
    relevant and reasons are empty.
    """
    if not all_files:
        return [], [], {}

    try:
        scripts_dir = Path(__file__).resolve().parent
        sys.path.insert(0, str(scripts_dir))
        from security_relevance_filter import classify_files  # noqa: PLC0415

        result = classify_files(str(repo_root), baseline_sha, all_files)
        relevant = result.get("relevant_files", all_files)
        noise = [f for f in all_files if f not in relevant]
        reasons_by_file: dict[str, list[str]] = {}
        for f, info in result.get("files", {}).items():
            reasons_by_file[f] = list(info.get("reasons") or [])
        return relevant, noise, reasons_by_file
    except Exception:
        # Conservative fallback — treat everything as relevant, no reasons.
        return all_files, [], {}


# High-blast-radius change: a change here typically affects far more of the
# threat surface than the single component whose path-glob it matches, yet the
# incremental dirty-set maps it to ONE component and carries every other
# component forward. These substrings flag a changed file as "security-critical
# or attack-surface-changing" so the skill can RECOMMEND a full scan (it never
# silently forces one — the narrow incremental scope is what under-analyzes
# these). The list is deliberately broad: an over-match only surfaces an
# advisory, while a miss is a real coverage gap. Matched case-insensitively as a
# substring of the path.
#
# Three tiers (one flat list — all feed the same recommend-full trigger):
#   A. Security primitives — auth / crypto / session / input-validation / …
#   B. Trust-boundary & I/O surface — routes, endpoints, interfaces in/out, the
#      request/response contract. A NEW route or a changed interface expands the
#      attack surface, which a delta scope scoped to one component never re-models.
#   C. Architecture & data model — middleware, gateways, adapters, ORM/entities,
#      model files, migrations: changing a layer ripples across components.
# Deliberately EXCLUDED (would match nearly every backend file → alert fatigue,
# signal lost): "service", "module", "domain", "core", "lib", "util", "app".
_SECURITY_CRITICAL_SUBSTRINGS = (
    # A — security primitives
    "auth",
    "login",
    "logout",
    "session",
    "token",
    "jwt",
    "oauth",
    "saml",
    "sso",
    "crypto",
    "cipher",
    "encrypt",
    "decrypt",
    "secret",
    "vault",
    "credential",
    "password",
    "passwd",
    "kms",
    "keystore",
    "csrf",
    "cors",
    "csp",
    "rbac",
    "acl",
    "permission",
    "authoriz",
    "guard",
    "ratelimit",
    "rate-limit",
    "rate_limit",
    "valid",
    "sanitiz",
    "escape",
    # B — trust-boundary & I/O surface (routes, interfaces, request/response)
    "route",
    "router",
    "endpoint",
    "controller",
    "handler",
    "resolver",
    "webhook",
    "graphql",
    "grpc",
    "proto",
    "openapi",
    "swagger",
    "api",
    "rest",
    "rpc",
    "serializ",
    "deserializ",
    "marshal",
    "schema",
    "dto",
    "payload",
    "upload",
    "download",
    "ingest",
    "webhooks",
    # C — architecture, layers & data model
    "middleware",
    "interceptor",
    "gateway",
    "adapter",
    "provider",
    "migration",
    "entity",
    "entities",
    "model",
    "repository",
    "dao",
    "orm",
    "layer",
)


def _classify_security_critical(paths: list[str]) -> list[str]:
    """Return the subset of ``paths`` that look security-critical or
    attack-surface-changing (routes / interfaces / architecture / data model).

    Pure path heuristic (no file read): a substring hit on any segment of the
    normalised, lower-cased path. Caller passes the already security-relevant
    set so noise is pre-excluded.
    """
    hits: list[str] = []
    for p in paths:
        norm = p.replace("\\", "/").lower()
        if any(sub in norm for sub in _SECURITY_CRITICAL_SUBSTRINGS):
            hits.append(p)
    return hits


def _filter_diff_paths_via_scan_excludes(paths: list[str], output_dir_rel: str | None) -> list[str]:
    """Drop paths the scanner would never look at anyway.

    Used by ``cmd_check_changes`` BEFORE classifying files via the
    relevance filter. Without this pre-filter, uncommitted plugin-output
    files (``docs/security/``…) and the like flow into the relevance
    filter and force the standard incremental path even when nothing
    real changed.

    Filtering rules (whitelist-wins, same as the runtime scanner):
      1. always_include match  → keep
      2. OUTPUT_DIR prefix     → drop (plugin's own writes, never scanned)
      3. scan_excludes match   → drop
      4. otherwise             → keep

    On any loader failure the input list is returned unchanged so a
    misconfigured plugin install never silently hides changes.
    """
    if not paths:
        return paths
    try:
        scripts_dir = Path(__file__).resolve().parent
        sys.path.insert(0, str(scripts_dir))
        from scan_excludes import is_always_included, is_excluded  # noqa: PLC0415
    except Exception:
        return paths

    out_prefix = output_dir_rel.rstrip("/") + "/" if output_dir_rel else None

    kept: list[str] = []
    for p in paths:
        norm = p.replace("\\", "/")
        if norm.startswith("./"):
            norm = norm[2:]
        try:
            if is_always_included(norm):
                kept.append(p)
                continue
            if out_prefix and norm.startswith(out_prefix):
                continue  # plugin's own output dir
            if is_excluded(norm):
                continue
        except Exception:
            kept.append(p)
            continue
        kept.append(p)
    return kept


def _output_dir_relative_to_repo(output_dir: Path, repo_root: Path) -> str | None:
    """Return OUTPUT_DIR as a posix path relative to REPO_ROOT, or None
    if it sits outside the repo (in which case scanner-side filtering does
    not apply)."""
    try:
        rel = output_dir.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return None
    return rel.as_posix()


def _build_baseline_content_hashes(cache_path: Path) -> dict[str, str]:
    """Map ``{repo-relative-path: bare-hex-sha256}`` for every file whose
    content was hashed into the baseline at the last threat-model generation.

    Sources, merged in this order (later wins on key collision):
      1. ``recon_fingerprint`` manifests / dockerfiles / iac — always present.
      2. ``working_tree_snapshot`` — content hashes of the files that were
         dirty-vs-HEAD when the baseline was written (added by ``cmd_update``).

    This lets ``cmd_check_changes`` ask the only question that matters for an
    incremental re-run — *did this file's content actually change since the
    last threat model?* — instead of *is this file dirty vs the last commit?*.
    A repo whose working tree carries a persistent uncommitted edit (a vendored
    manifest tweak, a local lockfile change) is dirty-vs-HEAD forever; without
    this content comparison every re-run would re-scan it even though nothing
    moved since the report was built.
    """
    data = _read_existing(cache_path)
    out: dict[str, str] = {}
    fp = data.get("recon_fingerprint", {}) or {}
    for bucket in ("manifests", "dockerfiles", "iac"):
        for rel, h in (fp.get(bucket) or {}).items():
            if isinstance(h, str):
                out[rel] = h.split(":", 1)[-1]  # strip "sha256:" prefix
    for rel, h in (data.get("working_tree_snapshot") or {}).items():
        if isinstance(h, str):
            out[rel] = h.split(":", 1)[-1]
    return out


def _split_unchanged_vs_baseline(
    repo_root: Path,
    paths: list[str],
    baseline_hashes: dict[str, str],
) -> tuple[list[str], list[str]]:
    """Split ``paths`` into ``(changed, unchanged)`` by current content.

    A path is *unchanged* when the baseline recorded a content hash for it and
    the file's current on-disk bytes still hash to that value — i.e. it is
    byte-identical to the last-analyzed state, so it is not a real change since
    the last threat model even though ``git diff`` lists it (working tree dirty
    vs HEAD). Paths with no recorded hash, or whose content now differs, stay in
    ``changed``. Unreadable files conservatively stay in ``changed``.
    """
    if not baseline_hashes:
        return list(paths), []
    changed: list[str] = []
    unchanged: list[str] = []
    for rel in paths:
        recorded = baseline_hashes.get(rel)
        if not recorded:
            changed.append(rel)
            continue
        try:
            current = _sha256(repo_root / rel).split(":", 1)[-1]
        except OSError:
            changed.append(rel)
            continue
        if current == recorded:
            unchanged.append(rel)
        else:
            changed.append(rel)
    return changed, unchanged


def cmd_check_changes(args: argparse.Namespace) -> int:
    """Unified fast-path pre-check for incremental runs.

    Combines four signals:
      - git diff committed    (baseline_sha..HEAD, or --base override)
      - git diff working tree (staged + unstaged)
      - recon fingerprint vs cached baseline
      - plugin_version drift (baseline vs current)

    Each changed file is classified by security_relevance_filter so that
    noise-only changes (docs, IDE config, CSS, etc.) do not trigger a run.

    Emits a single JSON decision block to stdout and an exit code the skill
    uses to branch:
        0  = no changes, plugin unchanged, recon fingerprint intact
             -> fast-abort: skip the whole pipeline, reuse prior report
        2  = noise-only changes (all changed files are non-security-relevant)
             -> fast-abort: nothing for the threat model to do
        10 = no source changes, but plugin minor/major bump detected
             -> fast-abort with RECOMMEND_FULL advisory
        1  = security-relevant changes detected
             -> continue normal incremental flow
        3  = error (missing baseline, git unavailable, etc.) — caller falls
             back to the full flow

    The JSON payload carries every signal the skill needs for its Configuration
    Summary so no duplicate git calls are needed downstream.
    """
    output_dir = Path(args.output_dir).resolve()
    repo_root = Path(args.repo_root).resolve()
    if not output_dir.is_dir():
        print(json.dumps({"status": "error", "reason": "output_dir missing"}))
        return 3
    if not (output_dir / "threat-model.yaml").is_file():
        print(json.dumps({"status": "no_baseline", "reason": "threat-model.yaml not found"}))
        return 3

    baseline_sha = _extract_baseline_commit_sha(output_dir)
    base_ref = args.base_ref or baseline_sha
    committed_raw, working_raw = _git_diff_names(repo_root, base_ref)
    head_sha = _git_head(repo_root)

    # Apply scan-excludes + OUTPUT_DIR filter BEFORE any classification
    # downstream. Without this filter, uncommitted plugin-output files
    # (docs/security/…) and other excluded paths flow into the relevance
    # filter and force the standard incremental path even when nothing
    # real changed.
    output_dir_rel = _output_dir_relative_to_repo(output_dir, repo_root)
    committed = _filter_diff_paths_via_scan_excludes(committed_raw, output_dir_rel)
    working = _filter_diff_paths_via_scan_excludes(working_raw, output_dir_rel)
    committed_excluded = [p for p in committed_raw if p not in committed]
    working_excluded = [p for p in working_raw if p not in working]

    cache_path = output_dir / ".appsec-cache" / "baseline.json"

    # Content-equality pre-filter: drop files that git lists as changed but
    # whose current bytes are identical to what the baseline last analyzed.
    # This is what makes "incremental" mean "changed since the last threat
    # model" rather than "dirty vs the last commit" — a persistently
    # uncommitted-but-unmodified manifest no longer forces a re-scan on every
    # invocation. Uses content hashes recorded at the last generation (recon
    # fingerprint + working-tree snapshot); see _build_baseline_content_hashes.
    baseline_content_hashes = _build_baseline_content_hashes(cache_path)
    committed, committed_unchanged = _split_unchanged_vs_baseline(repo_root, committed, baseline_content_hashes)
    working, working_unchanged = _split_unchanged_vs_baseline(repo_root, working, baseline_content_hashes)
    content_unchanged = list(dict.fromkeys(committed_unchanged + working_unchanged))

    # Recon fingerprint

    fingerprint_match = False
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_fp = data.get("recon_fingerprint", {})
            current_fp = _compute_recon_fingerprint(repo_root, exclude_rel_prefix=output_dir_rel)
            fingerprint_match = cached_fp == current_fp
        except (OSError, json.JSONDecodeError):
            fingerprint_match = False

    # Plugin-version drift
    version_tier = "unknown"
    version_message = ""
    baseline_plugin_version = _extract_baseline_plugin_version(output_dir)
    current_plugin_version = None
    if _load_plugin_meta is not None and _classify_plugin_version is not None:
        current_plugin_version = _load_plugin_meta().get("plugin_version")
        version_tier, version_message = _classify_plugin_version(baseline_plugin_version, current_plugin_version)

    has_committed_changes = bool(committed)
    has_working_changes = bool(working)
    no_source_changes = (not has_committed_changes) and (not has_working_changes) and fingerprint_match

    # Security-relevance filter — only runs when there are raw file changes.
    all_changed = list(dict.fromkeys(committed + working))  # dedup, preserve order
    security_relevant: list[str] = []
    noise_only: list[str] = []
    relevance_reasons: dict[str, list[str]] = {}
    if all_changed:
        security_relevant, noise_only, relevance_reasons = _classify_changed_files_relevance(
            repo_root, baseline_sha, all_changed
        )

    # Among the security-relevant changes, flag the high-blast-radius ones:
    # security primitives (auth/crypto/session/validation), trust-boundary & I/O
    # surface (routes/endpoints/interfaces/schemas), and architecture/data-model
    # changes (middleware/gateway/adapter/ORM/model/migration). The incremental
    # dirty-set maps each to a single component and carries the rest forward —
    # exactly the case where the narrow scope under-analyzes. The skill uses this
    # count to RECOMMEND a full scan (never to silently force one).
    security_critical = _classify_security_critical(security_relevant)

    # Decision
    if no_source_changes and version_tier in ("equal", "patch"):
        status = "unchanged"
        exit_code = 0
    elif no_source_changes and version_tier in ("minor", "major"):
        status = "unchanged_plugin_drift"
        exit_code = 10
    elif all_changed and not security_relevant:
        # Files changed, but none are security-relevant — treat as no-op.
        status = "noise_only"
        exit_code = 2
    else:
        status = "changed"
        exit_code = 1

    payload = {
        "status": status,
        "baseline_sha": baseline_sha,
        "head_sha": head_sha,
        "base_ref_used": base_ref,
        "committed_changes": committed[:50],
        "committed_change_count": len(committed),
        "working_tree_changes": working[:50],
        "working_tree_change_count": len(working),
        "security_relevant_changes": security_relevant[:50],
        "security_relevant_change_count": len(security_relevant),
        # High-blast-radius subset: security primitives + attack-surface changes
        # (routes / interfaces / schemas / middleware / models / migrations).
        # Drives the skill's "critical change → recommend full" trigger.
        "security_critical_changes": security_critical[:50],
        "security_critical_change_count": len(security_critical),
        "noise_only_changes": noise_only[:50],
        "fingerprint_match": fingerprint_match,
        "plugin_version": {
            "baseline": baseline_plugin_version,
            "current": current_plugin_version,
            "tier": version_tier,
            "message": version_message,
        },
        # Transparency: count of paths dropped by the scan-excludes pre-filter
        # (plugin output dir + path_prefixes/directories from scan-excludes.yaml).
        "excluded_pre_filter_count": len(committed_excluded) + len(working_excluded),
        "excluded_pre_filter_sample": (committed_excluded + working_excluded)[:10],
        # Files git lists as changed but whose content is byte-identical to the
        # last-analyzed state (dirty-vs-HEAD but unchanged-since-threat-model).
        # Dropped before relevance classification so they never trigger a run.
        "content_unchanged_dropped_count": len(content_unchanged),
        "content_unchanged_dropped_sample": content_unchanged[:10],
        # Per-file relevance reasons feed the human-readable pre-check
        # banner so users can see WHY a run was triggered (e.g. which
        # manifest dependency was added, which auth path matched).
        "relevance_reasons": {f: relevance_reasons.get(f, []) for f in security_relevant[:20]},
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path-glob pattern (with ``**``) to a compiled regex.

    Rules (matching the existing threat-analyst component-mapping prose):
      ``*``       — any chars except ``/``  → ``[^/]*``
      ``**``      — any number of path segments → ``.*`` (and consumes a
                    following ``/`` so ``a/**/b`` matches both ``a/b`` and
                    ``a/x/y/b``).
      ``?``       — a single non-slash char  → ``[^/]``
      everything else literal.
    """
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                out.append(".*")
                i += 2
                if i < n and pattern[i] == "/":
                    i += 1
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c in r".+()[]{}^$|\\":
            out.append("\\" + c)
            i += 1
        else:
            out.append(c)
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _parse_components_from_yaml(yaml_path: Path) -> list[dict]:
    """Minimal-dependency component reader.

    Returns a list of ``{"id": str, "paths": [str, ...]}`` dicts. We use
    PyYAML when it is importable (always true under the plugin's runtime
    deps) and fall back to a regex sweep so the script keeps running on
    a stripped Python install used by tests.
    """
    if not yaml_path.is_file():
        return []
    text = yaml_path.read_text(encoding="utf-8")
    try:
        import yaml as _yaml  # noqa: PLC0415

        data = _yaml.safe_load(text) or {}
        comps = data.get("components") or []
        out: list[dict] = []
        for c in comps:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            paths = c.get("paths") or []
            if not cid or not isinstance(paths, list):
                continue
            out.append({"id": cid, "paths": [str(p) for p in paths if isinstance(p, str)]})
        return out
    except Exception:
        # Regex fallback — coarse but enough to surface component IDs and
        # path globs on a stripped install.
        comps: list[dict] = []
        block_re = re.compile(
            r"^- id:\s*([\w-]+)\s*\n(?:.*\n)*?  paths:\s*\n((?:    -\s.*\n)+)",
            re.M,
        )
        for m in block_re.finditer(text):
            cid = m.group(1)
            paths = re.findall(r"^    -\s+(.+?)\s*$", m.group(2), re.M)
            comps.append({"id": cid, "paths": paths})
        return comps


# Top-level "global" manifest patterns whose change cannot be mapped to a
# single component. When a relevant change touches ONLY these (and no
# component path glob matches), the threat-analyst would take its
# No-Op Delta fast-path anyway — we beat it to it at the skill level
# and skip Stage 1+2+3 entirely.
_GLOBAL_TOPLEVEL_FILES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "Pipfile",
        "Pipfile.lock",
        "pyproject.toml",
        "poetry.lock",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile",
        "composer.json",
        "composer.lock",
        "Gemfile",
        "Gemfile.lock",
        "mix.exs",
        "mix.lock",
        "Dockerfile",
        "Containerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }
)


def cmd_dirty_set(args: argparse.Namespace) -> int:
    """Compute which components are affected by a list of relevant files.

    Maps each ``--files`` entry against ``components[].paths`` globs from
    ``threat-model.yaml`` and emits a structured decision the skill uses
    to decide whether Stage 1 (threat-analyst) needs to spawn at all.

    Exit codes:
      0  proceed — at least one component is dirty (run Stage 1)
      2  no-op — relevant files are only top-level global manifests that
         do NOT map to any component; fast-abort the skill
      3  ambiguous — relevant files do not map to any component but are
         not pure top-level globals (potential new-component signal);
         caller should run the standard incremental flow to be safe
    """
    output_dir = Path(args.output_dir).resolve()
    yaml_path = output_dir / "threat-model.yaml"
    components = _parse_components_from_yaml(yaml_path)

    # Pre-compile path globs once per component.
    compiled: list[tuple[str, list[re.Pattern[str]]]] = [
        (c["id"], [_glob_to_regex(p) for p in c.get("paths", [])]) for c in components
    ]

    files: list[str] = []
    if args.files:
        files.extend(args.files)
    if not args.no_stdin and not sys.stdin.isatty():
        try:
            files.extend(line.strip() for line in sys.stdin if line.strip())
        except OSError:
            pass
    files = list(dict.fromkeys(files))  # dedup, preserve order

    dirty: dict[str, list[str]] = {}
    unmapped: list[str] = []
    for f in files:
        norm = f.replace("\\", "/")
        if norm.startswith("./"):
            norm = norm[2:]
        matched = False
        for cid, patterns in compiled:
            if any(p.match(norm) for p in patterns):
                dirty.setdefault(cid, []).append(f)
                matched = True
        if not matched:
            unmapped.append(f)

    # Decision
    if dirty:
        decision = "dirty"
        exit_code = 0
    else:
        # All relevant files are unmapped — split into pure-global vs
        # potentially-new-component.
        is_all_global = bool(unmapped) and all("/" not in u and u in _GLOBAL_TOPLEVEL_FILES for u in unmapped)
        if is_all_global:
            decision = "noop_global_only"
            exit_code = 2
        elif unmapped:
            decision = "ambiguous_potential_new_component"
            exit_code = 3
        else:
            # No files at all — nothing to decide; treat as no-op.
            decision = "noop_empty_input"
            exit_code = 2

    payload = {
        "decision": decision,
        "dirty_components": [{"id": cid, "files": sorted(set(fs))} for cid, fs in sorted(dirty.items())],
        "dirty_component_ids": sorted(dirty.keys()),
        "unmapped_files": unmapped,
        "all_components_known": [c["id"] for c in components],
        "input_file_count": len(files),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


def cmd_filter_diff_paths(args: argparse.Namespace) -> int:
    """Filter a caller-provided changed-file list using scan excludes.

    This is the small CLI wrapper around ``_filter_diff_paths_via_scan_excludes``
    used by agent prompts after they compute ``git diff --name-only``. Keeping it
    here makes the pre-flight fast path and the in-agent dirty-set logic share
    the same OUTPUT_DIR / scan-excludes behavior.
    """
    output_dir = Path(args.output_dir).resolve()
    repo_root = Path(args.repo_root).resolve()

    paths: list[str] = []
    if args.paths:
        paths.extend(args.paths)
    if not args.no_stdin and not sys.stdin.isatty():
        try:
            paths.extend(line.strip() for line in sys.stdin if line.strip())
        except OSError:
            pass

    # Deduplicate while preserving order so user-facing diagnostics stay stable.
    paths = list(dict.fromkeys(paths))
    output_dir_rel = _output_dir_relative_to_repo(output_dir, repo_root)
    kept = _filter_diff_paths_via_scan_excludes(paths, output_dir_rel)
    excluded = [p for p in paths if p not in kept]

    if args.format == "json":
        print(
            json.dumps(
                {
                    "paths": kept,
                    "count": len(kept),
                    "excluded_count": len(excluded),
                    "excluded_sample": excluded[:10],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for p in kept:
            print(p)
    return 0


# Known-file inventory. Every file the plugin ever writes into $OUTPUT_DIR
# falls into exactly one of these buckets — the `clean` subcommand uses the
# categorisation to decide what to remove and what to keep. If a new
# intermediate artifact is added to the pipeline, append its filename pattern
# to the matching tuple here (and to the drift test in tests/test_cleanup.py).
_PRODUCT_FILES: tuple[str, ...] = (
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.sarif.json",
    "pentest-tasks.yaml",
    "appsec-requirements-report.md",
    "appsec-requirements-report.json",
    ".architect-review.md",
)
_AUDIT_FILES: tuple[str, ...] = (
    ".agent-run.log",
    ".agent-run.log.1",
    ".agent-run.log.2",
    ".hook-events.log",
    ".hook-events.log.1",
    ".hook-events.log.2",
)
_CACHE_FILES: tuple[str, ...] = (
    ".recon-summary.md",
    ".threat-modeling-context.md",
    ".requirements.yaml",
    ".config-scan.json",
    ".sca-practice-findings.json",
    ".known-bad-libs-findings.json",
    ".dep-update-activity.json",
    ".threats-merged.json",
    ".triage-flags.json",
)
_CACHE_DIRS: tuple[str, ...] = (".appsec-cache",)
_TRANSIENT_FILES: tuple[str, ...] = (
    ".appsec-lock",
    ".appsec-checkpoint",
    ".phase-epoch",
    ".session-agent-map",
    ".management-summary-draft.md",
    ".merge-candidates.json",
    ".merge-decisions.json",
    ".merge-findings.json",
)
_TRANSIENT_DIRS: tuple[str, ...] = (".progress",)
# Patterns — matched against basename via fnmatch.
_CACHE_GLOBS: tuple[str, ...] = (".stride-*.json",)


def _collect_removal_targets(output_dir: Path, mode: str) -> dict[str, list[Path]]:
    """Return {category: [paths]} for paths that actually exist on disk.

    `mode='cache'` -> CACHE + TRANSIENT (preserves products and audit logs)
    `mode='all'`   -> CACHE + TRANSIENT + PRODUCT + AUDIT
    """
    import fnmatch

    cache: list[Path] = []
    transient: list[Path] = []
    product: list[Path] = []
    audit: list[Path] = []
    unknown: list[Path] = []

    names_cache_exact = set(_CACHE_FILES)
    names_transient_exact = set(_TRANSIENT_FILES)
    names_product_exact = set(_PRODUCT_FILES)
    names_audit_exact = set(_AUDIT_FILES)
    names_cache_dirs = set(_CACHE_DIRS)
    names_transient_dirs = set(_TRANSIENT_DIRS)

    if not output_dir.is_dir():
        return {"cache": [], "transient": [], "product": [], "audit": [], "unknown": []}

    for entry in sorted(output_dir.iterdir()):
        name = entry.name
        if entry.is_dir():
            if name in names_cache_dirs:
                cache.append(entry)
            elif name in names_transient_dirs:
                transient.append(entry)
            else:
                unknown.append(entry)
            continue
        # Regular file
        if name in names_cache_exact:
            cache.append(entry)
        elif name in names_transient_exact:
            transient.append(entry)
        elif name in names_product_exact:
            product.append(entry)
        elif name in names_audit_exact:
            audit.append(entry)
        elif any(fnmatch.fnmatch(name, g) for g in _CACHE_GLOBS):
            cache.append(entry)
        else:
            unknown.append(entry)

    if mode == "all":
        removals = {"cache": cache, "transient": transient, "product": product, "audit": audit}
    else:  # "cache"
        removals = {"cache": cache, "transient": transient, "product": [], "audit": []}
    removals["unknown"] = unknown
    return removals


def cmd_clean(args: argparse.Namespace) -> int:
    """Delete cache/transient (and optionally product+audit) files in $OUTPUT_DIR.

    Does not run any analysis. Safety rules:
      * Only plugin-owned files are touched (allowlist via _CACHE_FILES etc.);
        unknown files are reported but never deleted.
      * --dry-run prints what would be removed without touching anything.
      * --force skips the interactive confirmation for `--mode all` (implied in CI).
      * A non-existent output dir is a silent success (exit 0, nothing to clean).

    Exit codes:
      0  success (removed or nothing-to-remove)
      1  user declined confirmation
      2  invalid args / cannot access output dir
    """
    import shutil

    output_dir = Path(args.output_dir).resolve()
    mode = args.mode
    if mode not in ("cache", "all"):
        print(f"baseline_state clean: unknown --mode: {mode}", file=sys.stderr)
        return 2
    if not output_dir.exists():
        print(f"baseline_state clean: output dir does not exist: {output_dir}")
        return 0
    if not output_dir.is_dir():
        print(f"baseline_state clean: not a directory: {output_dir}", file=sys.stderr)
        return 2

    targets = _collect_removal_targets(output_dir, mode)
    to_remove: list[Path] = []
    for key in ("cache", "transient", "product", "audit"):
        to_remove.extend(targets.get(key, []))

    if not to_remove:
        print(f"baseline_state clean: nothing to clean in {output_dir} (mode={mode})")
        return 0

    # Summary
    print(f"Clean target : {output_dir}")
    print(f"Mode         : {mode}")
    print(f"Would remove : {len(to_remove)} item(s)")
    for category in ("cache", "transient", "product", "audit"):
        bucket = targets.get(category, [])
        if bucket:
            print(f"  [{category}] ({len(bucket)})")
            for p in bucket:
                print(f"    - {p.relative_to(output_dir)}")
    unknown = targets.get("unknown", [])
    if unknown:
        print(f"  [unknown/preserved] ({len(unknown)}) — not touched")
        for p in unknown[:5]:
            print(f"    - {p.relative_to(output_dir)}")
        if len(unknown) > 5:
            print(f"    ... and {len(unknown) - 5} more")

    if args.dry_run:
        print("\n(dry run — nothing removed)")
        return 0

    # Confirmation only for --mode all in interactive mode without --force.
    if mode == "all" and not args.force:
        ci_mode = os.environ.get("APPSEC_CI_MODE", "").strip() == "1"
        is_tty = sys.stdin.isatty() if hasattr(sys.stdin, "isatty") else False
        if is_tty and not ci_mode:
            try:
                answer = input("\nProceed with removal? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if answer not in ("y", "yes"):
                print("Aborted — no files removed.")
                return 1

    # Execute removals
    removed = 0
    for p in to_remove:
        try:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            removed += 1
        except OSError as e:
            print(f"  [WARN] failed to remove {p}: {e}", file=sys.stderr)

    # When the output dir ends up empty, remove it too in --mode all.
    if mode == "all":
        try:
            if not any(output_dir.iterdir()):
                output_dir.rmdir()
                print(f"\nRemoved empty directory: {output_dir}")
        except OSError:
            pass

    print(f"\nRemoved {removed} item(s).")
    return 0


def cmd_last_run_info(args: argparse.Namespace) -> int:
    """Print a compact summary of the prior run's identity (timestamp, commit
    sha, plugin version). Used by the skill to show a startup banner.
    """
    output_dir = Path(args.output_dir).resolve()
    cache_path = output_dir / ".appsec-cache" / "baseline.json"
    yaml_path = output_dir / "threat-model.yaml"

    info = {
        "has_baseline": False,
        "plugin_version": None,
        "analysis_version": None,
        "commit_sha": None,
        "last_run_at": None,
    }
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            info["has_baseline"] = True
            info["plugin_version"] = data.get("plugin_version")
            info["analysis_version"] = data.get("analysis_version")
            info["last_run_at"] = data.get("last_run_at")
        except (OSError, json.JSONDecodeError):
            pass
    if yaml_path.is_file():
        info["commit_sha"] = _extract_baseline_commit_sha(output_dir)
        if info["plugin_version"] is None:
            info["plugin_version"] = _extract_baseline_plugin_version(output_dir)
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


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
    up.add_argument("--manifest-hashes", default=None, help="Pre-computed recon fingerprint JSON (skips rglob scan)")
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
    ck.add_argument(
        "--require-clean-tree",
        action="store_true",
        help="In addition to the fingerprint match, require a git-provably "
        "unchanged repo (committed-since-baseline + working tree + untracked). "
        "Used by the auto-upgraded-full recon-reuse path, which has no "
        "incremental git-diff STRIDE pass to back-stop a stale recon.",
    )
    ck.set_defaults(func=cmd_check_fingerprint)

    cc = sub.add_parser(
        "check-compat",
        help="Classify the prior baseline's analysis_version against the current plugin.",
    )
    cc.add_argument("--output-dir", required=True)
    cc.set_defaults(func=cmd_check_compat)

    ch = sub.add_parser(
        "check-changes",
        help="Unified fast-path pre-check combining git-diff, recon fingerprint and plugin-version drift.",
    )
    ch.add_argument("--output-dir", required=True)
    ch.add_argument("--repo-root", required=True)
    ch.add_argument(
        "--base-ref",
        default=None,
        help="Git ref to diff HEAD against (default: meta.git.commit_sha from the prior yaml).",
    )
    ch.set_defaults(func=cmd_check_changes)

    fp = sub.add_parser(
        "filter-diff-paths",
        help="Filter changed-file paths through OUTPUT_DIR and scan-excludes rules.",
    )
    fp.add_argument("--output-dir", required=True)
    fp.add_argument("--repo-root", required=True)
    fp.add_argument("--format", choices=("lines", "json"), default="lines")
    fp.add_argument("--no-stdin", action="store_true", help="Only use paths provided as positional arguments.")
    fp.add_argument("paths", nargs="*")
    fp.set_defaults(func=cmd_filter_diff_paths)

    ds = sub.add_parser(
        "dirty-set",
        help=(
            "Map relevant files against components[].paths globs; emit dirty "
            "components and a decision (proceed / noop / ambiguous)."
        ),
    )
    ds.add_argument("--output-dir", required=True)
    ds.add_argument("--files", nargs="*", default=None, help="Relevant files (paths relative to repo root).")
    ds.add_argument("--no-stdin", action="store_true", help="Ignore paths from stdin even when piped in.")
    ds.set_defaults(func=cmd_dirty_set)

    li = sub.add_parser(
        "last-run-info",
        help="Print prior-run identity (plugin_version, analysis_version, commit_sha, last_run_at) as JSON.",
    )
    li.add_argument("--output-dir", required=True)
    li.set_defaults(func=cmd_last_run_info)

    cl = sub.add_parser(
        "clean",
        help="Delete cache/transient (--mode cache) or everything (--mode all) in $OUTPUT_DIR.",
    )
    cl.add_argument("--output-dir", required=True)
    cl.add_argument(
        "--mode",
        choices=("cache", "all"),
        required=True,
        help="'cache' keeps products+audit logs; 'all' wipes everything.",
    )
    cl.add_argument("--dry-run", action="store_true", help="List targets without deleting.")
    cl.add_argument("--force", action="store_true", help="Skip interactive confirmation for --mode all.")
    cl.set_defaults(func=cmd_clean)

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
