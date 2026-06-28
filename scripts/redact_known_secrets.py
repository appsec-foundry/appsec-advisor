#!/usr/bin/env python3
"""Deterministic exact-value secret redaction over rendered artifacts.

The pattern-based masker (``secret_scan.mask_text``) neutralises a secret only
in the *form* it can match (e.g. ``secret = '...'``). When an LLM author copies
a raw secret VALUE into prose ("the JWT signing secret is the literal
e2e-fixture-jwt-secret-7f4c91") no pattern matches and the value ships in the
report — and it propagates through the STRIDE -> merged -> yaml/sarif/md/html
pipeline (2026-06-28 e2e leak).

This pass closes that gap. It scans the repository SOURCE for secret values —
where they appear in a matchable assignment / token form, so ``secret_scan``
yields the clean value — then replaces each exact value string everywhere it
occurs in the output artifacts, prose included. Because it is an exact-string
replacement of a value the source scanner already flagged AS a secret, it adds
no false positives beyond the scanner's existing prose / code-identifier guards.

Conservative by design: only values >= 8 chars that are not already masked are
redacted, and the source walk honours ``data/scan-excludes.yaml``.

Usage:
    redact_known_secrets.py --repo-root <repo> --output-dir <out> [--write-scan-json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scan_excludes  # noqa: E402
from secret_scan import _value_is_masked, scan_file, scan_text  # noqa: E402

# Output artifacts a copied secret can reach. Globs are resolved under the
# output dir; the data-pipeline sidecars are included because the secret enters
# there first (analyst evidence) before propagating to the published files.
_ARTIFACT_GLOBS = (
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.sarif.json",
    "threat-model.html",
    "pentest-tasks.yaml",
    ".threats-merged.json",
    ".merge-candidates.json",
    ".source-auth-findings.json",
    ".config-scan-findings.json",
    ".stride-*.json",
    ".fragments/*.md",
    ".fragments/*.json",
)

_MIN_VALUE_LEN = 8


def _masked(value: str) -> str:
    """First 4 chars + ``****`` — carries a masking marker (so the result can
    never be re-flagged) while breaking the reusable secret."""
    head = value[:4] if len(value) > 4 else ""
    return f"{head}**** ({len(value)} chars)"


def collect_source_secrets(repo_root: Path) -> dict[str, str]:
    """Walk the repository source and return ``{raw_value: masked_value}`` for
    every high-confidence secret value found."""
    excludes = scan_excludes.load_excludes()
    cap = scan_excludes.max_file_bytes(excludes)
    secrets: dict[str, str] = {}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root).as_posix()
        if scan_excludes.is_excluded(rel, excludes):
            continue
        try:
            if path.stat().st_size > cap:
                continue
        except OSError:
            continue
        for hit in scan_file(path):
            value = (hit.value or "").strip()
            if len(value) < _MIN_VALUE_LEN or _value_is_masked(value):
                continue
            secrets.setdefault(value, _masked(value))
    return secrets


def redact_artifacts(output_dir: Path, secrets: dict[str, str]) -> dict:
    """Replace each known secret value in every artifact. Returns a report."""
    redacted: dict[str, int] = {}
    touched_files: list[str] = []
    seen: set[Path] = set()
    targets: list[Path] = []
    for glob in _ARTIFACT_GLOBS:
        for p in sorted(output_dir.glob(glob)):
            if p.is_file() and p not in seen:
                seen.add(p)
                targets.append(p)

    for path in targets:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        new_text = text
        file_hits = 0
        for value, mask in secrets.items():
            count = new_text.count(value)
            if count:
                new_text = new_text.replace(value, mask)
                redacted[value] = redacted.get(value, 0) + count
                file_hits += count
        if file_hits and new_text != text:
            path.write_text(new_text, encoding="utf-8")
            touched_files.append(path.name)

    return {
        "check": "redact_known_secrets",
        "source_secret_values": len(secrets),
        "total_redactions": sum(redacted.values()),
        "files_modified": sorted(set(touched_files)),
        "redacted": [{"value_preview": v[:4] + "…", "length": len(v), "count": n} for v, n in sorted(redacted.items())],
    }


def _residual_scan(output_dir: Path) -> list[str]:
    """Final pattern scan over the published artifacts — confirms the redaction
    left nothing the unmasked-secrets gate would still catch."""
    issues: list[str] = []
    for rel in ("threat-model.md", "threat-model.yaml", "threat-model.sarif.json", "threat-model.html"):
        p = output_dir / rel
        if not p.is_file():
            continue
        try:
            for hit in scan_text(p.read_text(encoding="utf-8", errors="replace")):
                issues.append(f"{p.name}: {hit.render()}")
        except OSError:
            continue
    return issues


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Exact-value secret redaction over rendered artifacts.")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument(
        "--write-scan-json",
        action="store_true",
        help="Also write .qa-secret-scan.json with the post-redaction residual scan.",
    )
    a = ap.parse_args(argv)
    repo_root = Path(a.repo_root)
    output_dir = Path(a.output_dir)
    if not output_dir.is_dir():
        sys.stderr.write(f"redact_known_secrets: no output dir {output_dir} — skipping\n")
        return 0

    secrets = collect_source_secrets(repo_root) if repo_root.is_dir() else {}
    report = redact_artifacts(output_dir, secrets)
    (output_dir / ".secret-redaction.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    residual = _residual_scan(output_dir)
    if a.write_scan_json:
        (output_dir / ".qa-secret-scan.json").write_text(
            json.dumps(
                {
                    "check": "unmasked_secrets",
                    "ok": 1 if not residual else 0,
                    "issue_count": len(residual),
                    "issues": residual,
                    "redaction": report,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    if report["total_redactions"]:
        sys.stderr.write(
            f"redact_known_secrets: redacted {report['total_redactions']} occurrence(s) of "
            f"{len(report['redacted'])} secret value(s) across {len(report['files_modified'])} file(s)\n"
        )
    # Fail closed only if a residual raw secret survived (should never happen
    # after exact-value redaction, but the gate must not pass a leak silently).
    return 2 if residual else 0


if __name__ == "__main__":
    sys.exit(main())
