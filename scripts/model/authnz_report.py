#!/usr/bin/env python3
"""model/authnz_report.py — deterministic counts and validation for authnz-review.

The authnz-review skill prints category counts after each scanner phase, and the
authnz-analyzer agent writes `.authnz-report.json`. Neither count is hand-tallied:

  counts    categorise the scanner sidecars in `--output-dir` by CWE and print
            the per-category counts as JSON. Keys appear only for sidecars that
            exist, so the skill can call it after Phase 2 and again after Phase 3.
  finalize  validate the report and scanner inputs, retain omitted signals,
            validate id references, recompute `summary`, and write atomically.
  gate      fail on incomplete analysis or Critical/High findings, using the
            validated findings rather than supplied summary counts.

The category of a finding is its CWE, through `CATEGORY_BY_CWE`. Keying on the
CWE instead of the check id keeps every language variant of a check (AUTHZ-GO-001,
AUTHZ-PHP-002, ...) in its class without a list to maintain. The analyzer agent
documents the same table; `tests/test_authnz_report.py` keeps the two equal.

Exit codes:
    0  success; JSON printed on stdout
    1  the gate failed
    2  a sidecar or the report is unreadable, or the report is invalid
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
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "authnz-report.schema.json"

# The AuthN/AuthZ weakness classes the analyzer reasons about. A scanner finding
# whose CWE is not listed (injection, crypto, mobile storage) is out of scope.
CATEGORY_BY_CWE = {
    "CWE-639": "idor",
    "CWE-862": "route_auth",
    "CWE-306": "route_auth",
    "CWE-915": "mass_assign",
    "CWE-347": "jwt",
    "CWE-345": "jwt",
    "CWE-640": "credential",
    "CWE-521": "credential",
}
CATEGORIES = ("idor", "route_auth", "mass_assign", "jwt", "credential")
CWE_TITLES = {
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-862": "Missing Authorization",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-640": "Weak Password Recovery Mechanism for Forgotten Password",
    "CWE-521": "Weak Password Requirements",
}


class InputError(Exception):
    """A sidecar or report that cannot be read."""


def category_of(cwe: Any) -> str | None:
    """The category of a CWE string or of the first mapped CWE in a list; None when out of scope."""
    for c in cwe if isinstance(cwe, list) else [cwe]:
        if isinstance(c, str) and c in CATEGORY_BY_CWE:
            return CATEGORY_BY_CWE[c]
    return None


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError(f"{path.name}: top level is not an object")
    return data


def _findings(doc: dict) -> list[dict]:
    return [f for f in doc.get("findings") or [] if isinstance(f, dict)]


def scan_counts(output_dir: Path) -> dict:
    """Per-category counts of the scanner and confirmer sidecars present in `output_dir`."""
    out: dict[str, dict] = {}
    scanner = output_dir / ".source-auth-findings.json"
    if scanner.exists():
        counts = dict.fromkeys(CATEGORIES, 0)
        out_of_scope = 0
        for f in _findings(_load_json(scanner)):
            cat = category_of(f.get("cwe"))
            if cat:
                counts[cat] += 1
            else:
                out_of_scope += 1
        out["scanner"] = {**counts, "in_scope": sum(counts.values()), "out_of_scope": out_of_scope}
    confirm = output_dir / ".authz-confirm-findings.json"
    if confirm.exists():
        doc = _load_json(confirm)
        found = _findings(doc)
        out["confirmed"] = {
            "idor": sum(1 for f in found if category_of(f.get("cwe")) == "idor"),
            "route_auth": sum(1 for f in found if category_of(f.get("cwe")) == "route_auth"),
            "total": len(found),
            "unresolved_suspects": len(doc.get("unresolved_suspects") or []),
        }
    return out


def report_errors(report: Any) -> list[str]:
    """Schema violations plus duplicate finding ids and chain ids that name no finding."""
    validator = Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
    errors = [
        f"{'.'.join(str(p) for p in e.absolute_path) or 'root'}: {e.message}"
        for e in sorted(validator.iter_errors(report), key=lambda e: list(e.absolute_path))
    ]
    if errors:
        return errors
    ids = [f["id"] for f in report["findings"]]
    errors += [f"findings: id {i} is duplicated" for i in sorted({i for i in ids if ids.count(i) > 1})]
    known = set(ids)
    for n, chain in enumerate(report["chain_findings"]):
        for ref in [chain["root_id"], *chain["chain_ids"]]:
            if ref not in known:
                errors.append(f"chain_findings.{n}: {ref} names no finding")
    for n, disposition in enumerate(report.get("signal_dispositions", [])):
        if disposition["finding_id"] not in known:
            errors.append(f"signal_dispositions.{n}: unknown finding")
    return errors


def recompute_summary(report: dict) -> dict:
    """The summary block, counted from `findings[]`, `chain_findings[]` and `stride_covered[]`."""
    findings = report["findings"]

    def count(pred) -> int:
        return sum(1 for f in findings if pred(f))

    return {
        "total_findings": len(findings),
        **{sev.lower(): count(lambda f, s=sev: f["severity"] == s) for sev in ("Critical", "High", "Medium", "Low")},
        "idor_confirmed": count(lambda f: f["category"] == "idor" and f["source"] == "confirmed-instance"),
        "idor_hypotheses": count(lambda f: f["category"] == "idor" and f["source"] == "hypothesis"),
        "missing_auth": count(lambda f: f["category"] == "route_auth"),
        "jwt_findings": count(lambda f: f["category"] == "jwt"),
        "credential_findings": count(lambda f: f["category"] == "credential"),
        "privilege_escalation": count(lambda f: f.get("privilege_escalation") is True),
        "requirements_annotated": count(lambda f: bool(f["requirement_id"])),
        "stride_deduplicated": len(report["stride_covered"]),
        "chains": len(report["chain_findings"]),
    }


def _validated_input(path: Path, schema_name: str) -> dict:
    doc = _load_json(path)
    schema = yaml.safe_load((SCHEMA_PATH.parent / schema_name).read_text(encoding="utf-8"))
    if not Draft202012Validator(schema).is_valid(doc):
        raise InputError(f"{path.name}: invalid analysis input")
    return doc


def _retain_signals(report: dict, directory: Path, require_inputs: bool) -> None:
    """Retain every mapped scanner signal, independently of model omissions or scope guesses."""
    dispositions = []
    next_id = max((int(f["id"][3:]) for f in report["findings"]), default=0)

    def retain(signal: dict, source: str) -> str:
        nonlocal next_id
        for finding in report["findings"]:
            if finding["cwe"] == signal["cwe"] and any(
                e["file"] == signal["file"] and e.get("line") == signal["line"] for e in finding["evidence"]
            ):
                # A hypothesis cannot account for an actual scanner instance.
                if source == "hypothesis" or finding["source"] != "hypothesis":
                    return finding["id"]
        next_id += 1
        fid = f"AZ-{next_id:03d}"
        report["findings"].append(
            {
                "id": fid,
                "title": signal["title"],
                "severity": signal["severity"],
                "category": signal["category"],
                "cwe": signal["cwe"],
                "stride": "Spoofing" if signal["category"] in {"jwt", "credential"} else "Elevation of Privilege",
                "source": source,
                "component_id": None,
                "evidence": [
                    {"file": signal["file"], "line": signal["line"], "snippet": signal.get("evidence_snippet", "")}
                ],
                "attack_path": signal["scenario"],
                "remediation": {
                    "summary": signal.get("recommended_mitigation_title")
                    or "Verify the cited access-control path and enforce the required server-side check.",
                    "reference": f"{signal['cwe']} — {CWE_TITLES[signal['cwe']]}",
                },
                "requirement_id": None,
                "requirement_url": None,
            }
        )
        return fid

    for name, source in (
        (".source-auth-findings.json", "scanner"),
        (".authz-confirm-findings.json", "confirmed-instance"),
    ):
        path = directory / name
        if not require_inputs and not path.exists():
            continue
        doc = _validated_input(path, "source-auth-findings.schema.yaml")
        for finding in doc["findings"]:
            category = category_of(finding.get("cwe"))
            if category is None:
                continue
            if not isinstance(finding.get("line"), int) or finding["line"] < 1 or not finding.get("scenario"):
                raise InputError(f"{name}: in-scope signal lacks a usable source location or scenario")
            cwe = next(c for c in finding["cwe"] if CATEGORY_BY_CWE.get(c) == category)
            fid = retain({**finding, "cwe": cwe, "category": category}, source)
            dispositions.append(
                {
                    "sidecar": name,
                    "check_id": finding["check_id"],
                    "file": finding["file"],
                    "line": finding["line"],
                    "finding_id": fid,
                }
            )
    route_path = directory / ".route-inventory.json"
    if require_inputs or route_path.exists():
        inventory = _validated_input(route_path, "route-inventory.schema.json")
        for route in inventory["routes"]:
            if "authorization-review-required" not in route.get("notes", []):
                continue
            retain(
                {
                    "file": route["handler_file"],
                    "line": route["handler_line"],
                    "category": "route_auth",
                    "cwe": "CWE-862",
                    "severity": "Medium",
                    "title": f"Authorization unresolved for {route['method']} {route['path']}",
                    "scenario": "The route authenticates its caller, but the extracted evidence does not establish permission for this operation. Check the effective scopes, roles or policies and any upstream enforcement before concluding that unauthorized access is possible.",
                    "recommended_mitigation_title": "Trace the required operation permission through the token validator and every applicable middleware or policy; do not infer required scopes from the HTTP verb.",
                },
                "hypothesis",
            )
    report["signal_dispositions"] = dispositions


def finalize(path: Path, *, require_inputs: bool = False) -> dict:
    """Validate the report at `path`, write its recomputed summary back, and return it."""
    report = _load_json(path)
    errors = report_errors(report)
    if errors:
        raise InputError("report is invalid:\n" + "\n".join(f"  - {e}" for e in errors[:12]))
    _retain_signals(report, path.parent, require_inputs)
    errors = report_errors(report)
    if errors:
        raise InputError("reconciled report is invalid: " + errors[0])
    report["summary"] = recompute_summary(report)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".authnz-report-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    return report


def gate(path: Path) -> dict:
    """Evaluate the actual findings and completion state, never a supplied summary."""
    report = _load_json(path)
    if report_errors(report):
        raise InputError("report is invalid")
    count = sum(f["severity"] in {"Critical", "High"} for f in report["findings"])
    return {"failed": report["partial"] or count > 0, "partial": report["partial"], "critical_high": count}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    c = sub.add_parser("counts", help="print per-category counts of the scanner sidecars")
    c.add_argument("--output-dir", required=True, type=Path)
    f = sub.add_parser("finalize", help="validate the report and recompute its summary")
    f.add_argument("--report", required=True, type=Path)
    f.add_argument("--require-inputs", action="store_true", help="Require and reconcile all three scanner sidecars")
    g = sub.add_parser("gate", help="Fail on an incomplete review or Critical/High findings")
    g.add_argument("--report", required=True, type=Path)
    args = ap.parse_args(argv)

    try:
        if args.command == "counts":
            print(json.dumps(scan_counts(args.output_dir)))
        elif args.command == "gate":
            result = gate(args.report)
            print(json.dumps(result))
            return 1 if result["failed"] else 0
        else:
            report = finalize(args.report, require_inputs=args.require_inputs)
            print(json.dumps({"partial": report["partial"], **report["summary"]}))
    except InputError as exc:
        print(f"authnz_report: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
