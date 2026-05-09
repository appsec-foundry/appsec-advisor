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
        load_meta as _load_plugin_meta,
        classify_compat as _classify_compat,
        classify_plugin_version as _classify_plugin_version,
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


def _iter_repo_files(
    repo_root: Path, exclude_rel_prefix: str | None = None
) -> list[Path]:
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
        ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
        ".pytest_cache", "dist", "build", "target", ".next", ".cache",
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


def _compute_recon_fingerprint(
    repo_root: Path, exclude_rel_prefix: str | None = None
) -> dict:
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

    # Use pre-computed hashes if passed via --manifest-hashes to skip rglob.
    # When computing fresh, exclude OUTPUT_DIR so the plugin's own writes
    # never flip the fingerprint between runs.
    precomputed = _parse_manifest_hashes(getattr(args, "manifest_hashes", None))
    if precomputed:
        fingerprint = precomputed
    else:
        out_rel = _output_dir_relative_to_repo(output_dir, repo_root)
        fingerprint = _compute_recon_fingerprint(
            repo_root, exclude_rel_prefix=out_rel
        )
    stride_files = _hash_stride_files(output_dir)

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
        "last_run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

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
                capture_output=True, text=True, env=env, timeout=15,
            )
            if r.returncode == 0:
                committed = [ln for ln in r.stdout.splitlines() if ln]

        r = subprocess.run(
            ["git", "-C", str(repo_root), "diff", "--name-only"],
            capture_output=True, text=True, env=env, timeout=15,
        )
        if r.returncode == 0:
            working = [ln for ln in r.stdout.splitlines() if ln]
        # Include staged changes too (diff --cached)
        r = subprocess.run(
            ["git", "-C", str(repo_root), "diff", "--name-only", "--cached"],
            capture_output=True, text=True, env=env, timeout=15,
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
            capture_output=True, text=True, timeout=5,
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


def _filter_diff_paths_via_scan_excludes(
    paths: list[str], output_dir_rel: str | None
) -> list[str]:
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
        from scan_excludes import is_excluded, is_always_included  # noqa: PLC0415
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

    # Recon fingerprint
    cache_path = output_dir / ".appsec-cache" / "baseline.json"
    fingerprint_match = False
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_fp = data.get("recon_fingerprint", {})
            current_fp = _compute_recon_fingerprint(
                repo_root, exclude_rel_prefix=output_dir_rel
            )
            fingerprint_match = (cached_fp == current_fp)
        except (OSError, json.JSONDecodeError):
            fingerprint_match = False

    # Plugin-version drift
    version_tier = "unknown"
    version_message = ""
    baseline_plugin_version = _extract_baseline_plugin_version(output_dir)
    current_plugin_version = None
    if _load_plugin_meta is not None and _classify_plugin_version is not None:
        current_plugin_version = _load_plugin_meta().get("plugin_version")
        version_tier, version_message = _classify_plugin_version(
            baseline_plugin_version, current_plugin_version
        )

    has_committed_changes = bool(committed)
    has_working_changes = bool(working)
    no_source_changes = (not has_committed_changes) and (not has_working_changes) and fingerprint_match

    # Security-relevance filter — only runs when there are raw file changes.
    all_changed = list(dict.fromkeys(committed + working))  # dedup, preserve order
    security_relevant: list[str] = []
    noise_only: list[str] = []
    relevance_reasons: dict[str, list[str]] = {}
    if all_changed:
        security_relevant, noise_only, relevance_reasons = (
            _classify_changed_files_relevance(repo_root, baseline_sha, all_changed)
        )

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
        # Per-file relevance reasons feed the human-readable pre-check
        # banner so users can see WHY a run was triggered (e.g. which
        # manifest dependency was added, which auth path matched).
        "relevance_reasons": {
            f: relevance_reasons.get(f, []) for f in security_relevant[:20]
        },
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


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
    ".dep-scan.json",
    ".config-scan.json",
    ".threats-merged.json",
    ".triage-flags.json",
)
_CACHE_DIRS: tuple[str, ...] = (
    ".appsec-cache",
)
_TRANSIENT_FILES: tuple[str, ...] = (
    ".appsec-lock",
    ".appsec-checkpoint",
    ".phase-epoch",
    ".session-agent-map",
    ".management-summary-draft.md",
    ".dep-scan.pid",
    ".dep-scan.stdout",
    ".merge-candidates.json",
    ".merge-decisions.json",
    ".merge-findings.json",
)
_TRANSIENT_DIRS: tuple[str, ...] = (
    ".progress",
)
# Patterns — matched against basename via fnmatch.
_CACHE_GLOBS: tuple[str, ...] = (
    ".stride-*.json",
)


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

    ch = sub.add_parser(
        "check-changes",
        help="Unified fast-path pre-check combining git-diff, recon fingerprint and plugin-version drift.",
    )
    ch.add_argument("--output-dir", required=True)
    ch.add_argument("--repo-root", required=True)
    ch.add_argument("--base-ref", default=None,
                    help="Git ref to diff HEAD against (default: meta.git.commit_sha from the prior yaml).")
    ch.set_defaults(func=cmd_check_changes)

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
    cl.add_argument("--mode", choices=("cache", "all"), required=True,
                    help="'cache' keeps products+audit logs; 'all' wipes everything.")
    cl.add_argument("--dry-run", action="store_true",
                    help="List targets without deleting.")
    cl.add_argument("--force", action="store_true",
                    help="Skip interactive confirmation for --mode all.")
    cl.set_defaults(func=cmd_clean)

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
