#!/usr/bin/env python3
"""validate_evidence_lines.py — deterministic backstop for the
appsec-evidence-verifier agent.

When the LLM verifier is skipped or under-samples (observed: 0 dispatches
on standard-depth sonnet-economy runs despite the spec requiring all
Critical+High findings to be sampled), every threat in threat-model.yaml
ships with `evidence_check: unchecked`. This script provides a deterministic
floor:

  - File existence — `evidence.file` must resolve to a real file under
    REPO_ROOT. Misses are marked `refuted` with flag `file_missing`.
  - Line legitimacy — `evidence.line` must point to a non-empty, non-
    comment-only line. Comment-only or whitespace-only cites are marked
    `ambiguous` with flag `comment_only_line`.
  - All other findings whose existing check is `unchecked` are upgraded
    to `verified` (deterministic — the evidence pointer resolves cleanly).

Idempotent — a finding that already carries `verified-prior`, `refuted`,
or `ambiguous` from the LLM verifier is left untouched during validation.
Before writing the final artifact, however, refuted candidates are removed:
the active threat model is a current-risk snapshot, while the merged
intermediate retains the audit verdict.

Verdicts are persisted back into `.threats-merged.json` as well as
`threat-model.yaml`. This is load-bearing, not bookkeeping: Stage 1c
regenerates `threat-model.yaml` from the merged intermediate
(`SKILL-impl.md`, abuse-case branch), so a floor that wrote only to the YAML
was silently discarded on every standard/thorough run — the depth tiers where
abuse-case verification is enabled. Writing both keeps the floor idempotent
under rebuild and lets `build_threat_model_yaml.build_threats` apply its own
refuted-drop on the regenerated artifact.

Usage:
    python3 validate_evidence_lines.py <output_dir> --repo-root <REPO_ROOT>
"""

from __future__ import annotations

import argparse
import functools
import json
import re
import sys
from pathlib import Path

import yaml

# Local shared modules — single source of truth for inference/coverage-gap
# source-string enums.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _shared_sources import ARCH_ALL_SOURCES  # noqa: E402

# A "comment-only" line is one whose stripped form starts with a recognised
# comment marker AND nothing else of substance follows. We deliberately do
# NOT flag lines that *contain* a trailing `// …` after real code — the
# real code is the evidence; the trailing comment is annotation.
_COMMENT_PREFIXES = ("//", "#", "/*", "*", "<!--", "--")


@functools.lru_cache(maxsize=1)
def _file_exists_config_check_ids() -> frozenset[str]:
    """Return catalog checks whose violation is an absent target file.

    A normal finding pointing at a missing file has a broken evidence anchor.
    For a config-scan ``expect: file_exists`` check, however, the missing file
    is the violation itself and is therefore positive evidence. Keep this
    distinction data-driven so new catalog checks inherit the correct
    evidence semantics without a validator code change.
    """
    catalog = Path(__file__).resolve().parent.parent / "data" / "config-iac-checks.yaml"
    try:
        document = yaml.safe_load(catalog.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return frozenset()
    checks = document.get("checks") or []
    return frozenset(
        str(check.get("id")).strip()
        for check in checks
        if isinstance(check, dict) and check.get("expect") == "file_exists" and check.get("id")
    )


def _is_expected_absence_finding(threat: dict) -> bool:
    """Whether a missing evidence file positively proves this config finding."""
    return (threat.get("source") or "").strip() == "config-scan" and (
        threat.get("config_check_id") or ""
    ).strip() in _file_exists_config_check_ids()


# RC.D — patterns that match a line containing only an import / package
# declaration. STRIDE-analyzer agents sometimes anchor evidence to the first
# line where the vulnerable symbol's NAME appears, which can be an `import`
# statement rather than the sink. The 2026-05 juice-shop run produced
# evidence pointers at line 6 of `frontend/.../helpers.ts` (an
# `import jwtDecode from 'jwt-decode'`) while the actual localStorage access
# was on line 173. Flagging these as `ambiguous` forces a downstream LLM
# verifier (or a human reviewer) to refine the pointer.
_IMPORT_LINE_PATTERNS = (
    # JS / TS / mjs
    re.compile(r"^\s*import\b"),
    re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*require\s*\("),
    # Python
    re.compile(r"^\s*(?:from\s+\S+\s+)?import\b"),
    # Java / Kotlin / Scala / Groovy
    re.compile(r"^\s*import\s+[\w.]+\s*;?\s*$"),
    re.compile(r"^\s*package\s+[\w.]+\s*;?\s*$"),
    # C#
    re.compile(r"^\s*using\s+[\w.]+\s*;\s*$"),
    # Go
    re.compile(r"^\s*import\s+(?:\(|\"[^\"]+\")\s*$"),
)


def _is_import_line(line: str) -> bool:
    """True if the line is an import / package-declaration only line.

    Heuristic: matches whole-line patterns for ES, Python, JVM, .NET, Go.
    A line containing `import` *inside* a larger expression (e.g. a
    dynamic `import('x')` inside a function body) is NOT flagged here.
    """
    for pat in _IMPORT_LINE_PATTERNS:
        if pat.match(line):
            return True
    return False


def _is_comment_only(line: str) -> bool:
    """True if the line is whitespace or starts with a known comment marker."""
    stripped = line.strip()
    if not stripped:
        return True
    for prefix in _COMMENT_PREFIXES:
        if stripped.startswith(prefix):
            return True
    return False


def _resolve_evidence_file(repo_root: Path, file_token: str) -> Path | None:
    """Map an evidence.file token to an actual path. Returns None on miss."""
    if not file_token:
        return None
    root = repo_root.resolve()
    candidate = (root / file_token).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if candidate.is_file():
        return candidate
    # Some Stage-1 emitters strip a leading directory. Try a basename
    # fallback — but only return a hit when exactly one match exists, to
    # avoid silently mis-routing.
    base = Path(file_token).name
    matches = list(repo_root.rglob(base))
    matches = [m for m in matches if m.is_file() and "/node_modules/" not in str(m) and "/.git/" not in str(m)]
    if len(matches) == 1:
        return matches[0]
    return None


def _read_line(path: Path, line_no: int) -> str | None:
    """Return the 1-indexed line content. None if unreadable / out of range."""
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh, start=1):
                if idx == line_no:
                    return line.rstrip("\n")
                if idx > line_no:
                    break
    except OSError:
        return None
    return None


def _evidence_entries(threat: dict) -> list[dict]:
    """Normalise threat.evidence to a list-of-dicts shape."""
    ev = threat.get("evidence")
    if isinstance(ev, dict):
        return [ev]
    if isinstance(ev, list):
        return [e for e in ev if isinstance(e, dict)]
    return []


# Provenance markers meaning "the evidence anchor was attached by inference,
# not derived from a code-level finding." Such a threat must never auto-verify
# off a structurally-valid-but-irrelevant line (the T-065 cleartext-transport
# case: anchor pointed at a real challenges.yml data line → counted as code).
_INFERRED_EVIDENCE_FLAGS = {"tier_reclassified_from_data"}


def _is_inferred(threat: dict) -> bool:
    """True when the threat's evidence anchor is inferred / coverage-gap
    provenance rather than code-derived."""
    if (threat.get("source") or "").strip() in ARCH_ALL_SOURCES:
        return True
    flags = threat.get("evidence_flags") or []
    return any(f in _INFERRED_EVIDENCE_FLAGS or f.startswith("tier_reclassified_from_") for f in flags)


def _validate_one(threat: dict, repo_root: Path) -> tuple[str, list[str]]:
    """Return (final_check, flags) for a single threat."""
    flags: list[str] = []
    entries = _evidence_entries(threat)
    if not entries:
        return "ambiguous", ["no_evidence"]

    file_misses = 0
    comment_only = 0
    import_only = 0
    code_hits = 0
    for ev in entries:
        file_token = (ev.get("file") or "").strip()
        line_token = ev.get("line")
        try:
            line_no = int(line_token) if line_token is not None else None
        except (TypeError, ValueError):
            line_no = None

        path = _resolve_evidence_file(repo_root, file_token)
        if path is None:
            file_misses += 1
            continue
        if line_no is None or line_no < 1:
            # File exists but no line — accept as code_hit; the file
            # presence is itself evidence.
            code_hits += 1
            continue
        content = _read_line(path, line_no)
        if content is None:
            # File exists but line is out of range — treat as ambiguous,
            # not refuted, since the file is real.
            flags.append("line_out_of_range")
            continue
        if _is_comment_only(content):
            comment_only += 1
        elif _is_import_line(content):
            # RC.D — import/package declaration is structurally not where
            # a vulnerability lives. Pointer needs refinement before any
            # downstream consumer treats it as proof.
            import_only += 1
        else:
            code_hits += 1

    if file_misses == len(entries):
        if _is_expected_absence_finding(threat):
            flags.append("expected_file_absent")
            return "verified", flags
        flags.append("file_missing")
        return "refuted", flags
    if file_misses > 0:
        flags.append("partial_file_missing")
    # Import-only beats comment-only when both are present at different
    # evidence rows: a refined evidence pointer is needed regardless.
    if import_only > 0 and code_hits == 0:
        flags.append("import_line_only")
        return "ambiguous", flags
    if import_only > 0:
        flags.append("some_import_lines")
    if comment_only > 0 and code_hits == 0:
        flags.append("comment_only_line")
        return "ambiguous", flags
    if comment_only > 0:
        flags.append("some_comment_lines")
    if code_hits > 0:
        if _is_inferred(threat):
            # Inferred / coverage-gap provenance: the evidence anchor was
            # attached, not code-derived, so a structurally-valid line is not
            # proof. Cap at ambiguous and flag for reviewer refinement rather
            # than auto-"verified". (A genuine LLM verifier verdict already
            # short-circuited in validate_yaml via _RESPECTED_PRIOR_STATES, so
            # this never overrides a real verification.)
            flags.append("evidence_anchor_unverified")
            return "ambiguous", flags
        return "verified", flags
    return "ambiguous", flags or ["evidence_unverifiable"]


# States that the LLM verifier (or a prior deterministic run) may have set.
# We never *lower* one of these; we only fill in `unchecked` or unset.
_RESPECTED_PRIOR_STATES = {"verified", "refuted", "ambiguous", "verified-prior"}


def validate_yaml(data: dict, repo_root: Path) -> tuple[dict, dict]:
    """Mutate `data['threats']` in place. Return (data, stats)."""
    threats = data.get("threats") or []
    if not isinstance(threats, list):
        return data, {"sampled": 0, "verified": 0, "refuted": 0, "ambiguous": 0, "skipped": 0}

    stats = {"sampled": 0, "verified": 0, "refuted": 0, "ambiguous": 0, "skipped": 0}
    for t in threats:
        if not isinstance(t, dict):
            continue
        prior = (t.get("evidence_check") or "").strip()
        if prior in _RESPECTED_PRIOR_STATES:
            stats["skipped"] += 1
            continue
        final, flags = _validate_one(t, repo_root)
        t["evidence_check"] = final
        if flags:
            existing = list(t.get("evidence_flags") or [])
            # Merge without duplication, preserve insertion order.
            for f in flags:
                if f not in existing:
                    existing.append(f)
            t["evidence_flags"] = existing
        stats["sampled"] += 1
        stats[final] = stats.get(final, 0) + 1

    return data, stats


def drop_refuted_findings(data: dict) -> int:
    """Remove evidence-refuted candidates from the final active model.

    ``refuted`` is valid intermediate evidence-verification state but must not
    appear in ``threat-model.yaml``. Fixed findings from an incremental scan
    are already represented through ``resolved_prior_findings`` and the
    changelog; a new scan has no active finding to render once its evidence is
    refuted.
    """
    threats = data.get("threats")
    if not isinstance(threats, list):
        return 0
    kept: list[object] = []
    dropped = 0
    for threat in threats:
        if isinstance(threat, dict) and (threat.get("evidence_check") or "").strip().lower() == "refuted":
            dropped += 1
            continue
        kept.append(threat)
    data["threats"] = kept
    return dropped


def persist_to_merged(output_dir: Path, data: dict) -> int:
    """Mirror floor verdicts into `.threats-merged.json`. Return count written.

    Join key is `t_id` in the merged intermediate, which
    ``build_threat_model_yaml.build_threats`` renames to `id` in the YAML.
    Call this *before* :func:`drop_refuted_findings`, which removes refuted
    entries from ``data`` — the merged intermediate must keep them so the
    rebuild can re-apply the drop and the audit trail survives.

    The never-lower rule from :func:`validate_yaml` applies here too: a real
    LLM verdict already in the merged file is never overwritten by the floor.
    Missing file is not an error — some paths run the floor without a merged
    intermediate present.
    """
    merged_path = output_dir / ".threats-merged.json"
    if not merged_path.is_file():
        return 0
    try:
        merged = json.loads(merged_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"validate_evidence_lines: could not parse {merged_path}: {exc}", file=sys.stderr)
        return 0
    if not isinstance(merged, dict) or not isinstance(merged.get("threats"), list):
        return 0

    verdicts = {
        t["id"]: t
        for t in (data.get("threats") or [])
        if isinstance(t, dict) and t.get("id") and t.get("evidence_check")
    }
    written = 0
    for threat in merged["threats"]:
        if not isinstance(threat, dict):
            continue
        source = verdicts.get(threat.get("t_id") or threat.get("id"))
        if source is None:
            continue
        if (threat.get("evidence_check") or "").strip() in _RESPECTED_PRIOR_STATES:
            continue
        threat["evidence_check"] = source["evidence_check"]
        if source.get("evidence_flags"):
            existing = list(threat.get("evidence_flags") or [])
            for flag in source["evidence_flags"]:
                if flag not in existing:
                    existing.append(flag)
            threat["evidence_flags"] = existing
        written += 1

    if written:
        merged_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    return written


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="validate_evidence_lines", description="Deterministic evidence-line validation backstop."
    )
    p.add_argument("output_dir", help="Directory containing threat-model.yaml.")
    p.add_argument("--repo-root", required=True, help="Root of the analyzed repository.")
    args = p.parse_args(argv)

    output_dir = Path(args.output_dir)
    repo_root = Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"validate_evidence_lines: repo-root {repo_root} is not a directory", file=sys.stderr)
        return 1
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"validate_evidence_lines: no yaml at {yaml_path}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"validate_evidence_lines: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print(f"validate_evidence_lines: {yaml_path} did not parse to a mapping", file=sys.stderr)
        return 1

    data, stats = validate_yaml(data, repo_root)
    # Mirror verdicts into the merged intermediate *before* dropping refuted
    # entries from the active model — the rebuild reads the merged file and
    # re-applies the drop itself.
    mirrored = persist_to_merged(output_dir, data)
    dropped_refuted = drop_refuted_findings(data)
    yaml_path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False),
        encoding="utf-8",
    )
    print(
        f"validate_evidence_lines: sampled={stats['sampled']} "
        f"verified={stats.get('verified', 0)} refuted={stats.get('refuted', 0)} "
        f"ambiguous={stats.get('ambiguous', 0)} skipped(prior)={stats['skipped']} "
        f"dropped_refuted={dropped_refuted} mirrored_to_merged={mirrored}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
