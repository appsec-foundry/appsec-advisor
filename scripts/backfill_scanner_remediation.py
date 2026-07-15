#!/usr/bin/env python3
"""Backfill a structured ``remediation`` block on scanner-derived threats.

Static scanners (``source_auth_scanner``, the crypto scan, the config/IaC scan)
express a finding's fix as ONE canonical instruction, surfaced as the threat's
``mitigation_title`` — never a structured ``remediation.steps`` / ``verification``
block (see ``source_auth_scanner.py`` mapping ``check.remediation`` →
``recommended_mitigation_title``). ``build_mitigations`` then synthesises a
``kind: fix`` P1/P2 card from that title.

The 2026-07-13 developer-actionability gate (``validate_mitigation_quality.py``)
requires every P1/P2 fix card to carry at least two concrete steps AND one
executable verification. Those details are copied onto the card from the
addressed threat's ``remediation`` by ``hydrate_mitigation_details.py`` — but a
scanner finding has NO such block, so when the Stage-1 LLM does not happen to
hand-author one (non-deterministic), the card ships stepless and the gate
hard-fails the whole run after Stage 1. In the pre-gate pipeline these findings
became gate-exempt ``kind: review`` cards; the current pipeline (intentionally)
makes them real fix cards, which newly subjects them to the gate.

This emitter closes the gap deterministically. For every threat that lacks
``remediation.steps`` it writes a remediation block whose:

  * step 1 is the concrete fix instruction, resolved in priority order from the
    check library by id (``source_check_id`` → source-auth/crypto checks;
    ``config_check_id`` → config-iac checks) then the threat's
    ``mitigation_title``;
  * step 2 is a regression-test/CI instruction so the pattern cannot reappear;
  * ``verification`` is a concrete re-scan assertion naming the check id and the
    finding's ``file:line``.

Runs in the auto-emitter pass BEFORE ``hydrate_mitigation_details.py`` (which
promotes the block onto the card) and on the thin-runtime recovery path for the
same reason. Idempotent and best-effort: authored ``remediation.steps`` always
win, and any failure falls back to the pre-script YAML rather than aborting.

Usage:
    python3 backfill_scanner_remediation.py <output_dir>

Exit codes: 0 always (best-effort emitter; failures are warnings on stderr).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

# Check libraries keyed by check id. source-auth-checks.yaml holds AUTHZ-* and
# INJ-* entries; crypto-checks.yaml holds CRYPTO-*; config-iac-checks.yaml holds
# IAC-*. All share `{id, remediation, name}` shape under a top-level `checks`.
_LIBRARY_FILES = ("source-auth-checks.yaml", "crypto-checks.yaml", "config-iac-checks.yaml")

_REGRESSION_STEP = (
    "Add a regression test (or CI check) that fails on the vulnerable pattern and passes once the fix is in place."
)


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _load_check_index(plugin_root: Path) -> dict[str, dict]:
    """Index every check by its id across the source/crypto/config libraries."""
    index: dict[str, dict] = {}
    for name in _LIBRARY_FILES:
        path = plugin_root / "data" / name
        if not path.is_file():
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        checks = data.get("checks") if isinstance(data, dict) else data
        if isinstance(checks, dict):
            checks = list(checks.values())
        if not isinstance(checks, list):
            continue
        for check in checks:
            if isinstance(check, dict) and _text(check.get("id")):
                index.setdefault(check["id"], check)
    return index


def _evidence_location(threat: dict) -> str:
    """`file:line` (or `file`) for the finding, for a concrete verification."""
    evidence = threat.get("evidence") or []
    if isinstance(evidence, dict):
        evidence = [evidence]
    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, dict) and _text(item.get("file")):
                line = item.get("line")
                return f"{_text(item['file'])}:{line}" if line is not None else _text(item["file"])
    affected = threat.get("affected_files") or []
    if isinstance(affected, list) and affected and _text(affected[0]):
        return _text(affected[0])
    return ""


def _check_id(threat: dict) -> str:
    return _text(threat.get("source_check_id") or threat.get("config_check_id"))


def _instruction(threat: dict, checks: dict[str, dict]) -> str:
    """The concrete fix instruction — library remediation, then mitigation_title."""
    entry = checks.get(_check_id(threat))
    if isinstance(entry, dict) and _text(entry.get("remediation")):
        return _text(entry["remediation"])
    return _text(threat.get("mitigation_title"))


def _verification(threat: dict, checks: dict[str, dict]) -> str:
    """A concrete re-scan assertion naming the check id and file:line."""
    check_id = _check_id(threat)
    location = _evidence_location(threat)
    where = f" at {location}" if location else ""
    if check_id:
        return f"Re-run the {check_id} scanner check; it reports no match{where}, and the regression test passes."
    cwe = _text(threat.get("cwe"))
    subject = f"the {cwe} finding" if cwe else "this finding"
    return f"Re-run the security scan; {subject}{where} is cleared, and the regression test passes."


def _has_steps(threat: dict) -> bool:
    remediation = threat.get("remediation")
    return (
        isinstance(remediation, dict)
        and isinstance(remediation.get("steps"), list)
        and any(_text(step) for step in remediation["steps"])
    )


def backfill(data: dict, checks: dict[str, dict]) -> int:
    """Write a remediation block on scanner threats lacking one; return count."""
    changed = 0
    for threat in data.get("threats") or []:
        if not isinstance(threat, dict) or _has_steps(threat):
            continue
        instruction = _instruction(threat, checks)
        if not instruction:
            # No concrete instruction to anchor a fix — leave for the gate to
            # surface rather than emit a vague, invented step.
            continue
        remediation = threat.get("remediation")
        if not isinstance(remediation, dict):
            remediation = {}
        remediation["steps"] = [instruction, _REGRESSION_STEP]
        if not _text(remediation.get("verification")):
            remediation["verification"] = _verification(threat, checks)
        remediation.setdefault("effort", "Medium")
        threat["remediation"] = remediation
        changed += 1
    return changed


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: backfill_scanner_remediation.py <output_dir>", file=sys.stderr)
        return 0
    yaml_path = Path(args[0]) / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"backfill_scanner_remediation: no {yaml_path} — skipping", file=sys.stderr)
        return 0
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"backfill_scanner_remediation: failed to load yaml: {exc}", file=sys.stderr)
        return 0
    if not isinstance(data, dict):
        print("backfill_scanner_remediation: yaml root is not a mapping — skipping", file=sys.stderr)
        return 0
    plugin_root = Path(__file__).resolve().parent.parent
    checks = _load_check_index(plugin_root)
    count = backfill(data, checks)
    if count:
        yaml_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096), encoding="utf-8")
    print(f"backfill_scanner_remediation: backfilled remediation on {count} scanner threat(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
