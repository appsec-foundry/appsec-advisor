#!/usr/bin/env python3
"""Run repository-only deterministic scanners without a threat-model run.

The default output includes console details and a parseable summary. ``--yaml``
and ``--json`` emit the selected results to stdout; a PATH argument writes the
selected format to that path. Scanner sidecars and remote checkouts remain in
temporary directories.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import yaml
from jsonschema import ValidationError, validate

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _path_guard import iter_escaping_symlinks  # noqa: E402
from scan_excludes import is_assessment_artifact  # noqa: E402
from security_score import _clone, _remote_url  # noqa: E402

SCANS = ("config", "source", "authz", "mass-assignment", "architecture", "endpoints", "stack")
FINDING_SCANS = ("config", "source", "mass-assignment")
TIMEOUT_S = 600
SCHEMA = HERE.parent / "schemas" / "repo-scan.schema.yaml"
SEVERITY_LEVEL = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _run(command: list[str]) -> str:
    try:
        done = subprocess.run(
            [sys.executable, str(HERE / command[0]), *command[1:]],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{command[0]} timed out") from exc
    except OSError as exc:
        raise RuntimeError(f"{command[0]} could not start: {exc}") from exc
    if done.returncode:
        detail = (done.stderr or done.stdout or "").strip().splitlines()
        raise RuntimeError(f"{command[0]} failed: {detail[-1] if detail else f'exit {done.returncode}'}")
    return done.stdout


def _read(path: Path, expected: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"{expected}: invalid scanner output: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{expected}: scanner output must be an object")
    return data


def _findings(data: dict[str, Any], label: str, repo_root: Path, minimum_severity: str = "all") -> dict[str, Any]:
    rows = data.get("findings")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise RuntimeError(f"{label}: scanner output has no valid findings list")
    kept = [row for row in rows if not is_assessment_artifact(str(row.get("file") or ""), repo_root)]
    visible = (
        kept
        if minimum_severity == "all"
        else [
            row
            for row in kept
            if SEVERITY_LEVEL.get(str(row.get("severity") or "").strip().lower(), -1)
            >= SEVERITY_LEVEL[minimum_severity]
        ]
    )
    return {
        "name": label,
        "checks_run": data.get("checks_run", 0),
        "findings": visible,
        "findings_total": len(visible),
        "ignored_assessment_findings": len(rows) - len(kept),
    }


def collect(
    repo_root: Path,
    work_dir: Path,
    selected: list[str],
    progress: Callable[[str], None] | None = None,
    minimum_severity: str = "all",
) -> dict[str, Any]:
    """Run selected repo scanners and retain their validated JSON payloads."""
    repo, out = str(repo_root), str(work_dir)
    results: list[dict[str, Any]] = []

    def announce(message: str) -> None:
        if progress is not None:
            progress(message)

    if "config" in selected:
        announce("config: scanning configuration and IaC...")
        path = work_dir / ".config-scan.json"
        _run(["config_iac_scanner.py", "--repo-root", repo, "--output", str(path)])
        result = _findings(_read(path, "config"), "config", repo_root, minimum_severity)
        results.append(result)
        announce(f"config: {result['findings_total']} findings from {result['checks_run']} checks")

    for label in ("source", "authz"):
        if label not in selected:
            continue
        announce(f"{label}: scanning source code...")
        source_command = ["source_auth_scanner.py", "--repo-root", repo, "--output-dir", out, "--quiet"]
        if label == "authz":
            source_command += ["--check-prefix", "AUTHZ-"]
        _run(source_command)
        data = _read(work_dir / ".source-auth-findings.json", label)
        result = _findings(data, label, repo_root, minimum_severity)
        results.append(result)
        announce(f"{label}: {result['findings_total']} findings from {result['checks_run']} checks")

    if "mass-assignment" in selected:
        announce("mass-assignment: scanning entity writes...")
        _run(["mass_assignment_scanner.py", "--repo-root", repo, "--output-dir", out, "--quiet"])
        result = _findings(
            _read(work_dir / ".mass-assignment-findings.json", "mass-assignment"),
            "mass-assignment",
            repo_root,
            minimum_severity,
        )
        results.append(result)
        announce(f"mass-assignment: {result['findings_total']} findings")

    inventory: dict[str, Any] | None = None
    if any(name in selected for name in ("architecture", "endpoints", "stack")):
        announce("endpoints: enumerating route registrations...")
        _run(["route_inventory.py", "--repo-root", repo, "--output-dir", out])
        inventory = _read(work_dir / ".route-inventory.json", "route-inventory")
        routes = inventory.get("routes")
        coverage = inventory.get("coverage")
        if not isinstance(routes, list) or not all(isinstance(route, dict) for route in routes):
            raise RuntimeError("endpoints: scanner output has no valid routes list")
        if not isinstance(coverage, dict):
            raise RuntimeError("endpoints: scanner output has no valid coverage object")
        announce(f"endpoints: {len(routes)} routes found")

    if "endpoints" in selected:
        assert inventory is not None
        results.append(
            {
                "name": "endpoints",
                "routes": inventory["routes"],
                "route_count": len(inventory["routes"]),
                "coverage": inventory["coverage"],
            }
        )

    if "stack" in selected:
        assert inventory is not None
        announce("stack: profiling languages and build manifests...")
        try:
            profile = json.loads(_run(["repo_profile.py", "--repo", repo, "--json"]))
        except ValueError as exc:
            raise RuntimeError(f"stack: invalid profile output: {exc}") from exc
        if (
            not isinstance(profile, dict)
            or not isinstance(profile.get("languages"), list)
            or not isinstance(profile.get("manifests"), list)
        ):
            raise RuntimeError("stack: profile output has no valid languages or manifests")
        results.append(
            {
                "name": "stack",
                "languages": profile["languages"],
                "manifests": profile["manifests"],
                "frameworks": inventory["coverage"].get("frameworks_detected", []),
            }
        )
        announce(f"stack: {len(profile['languages'])} languages, {len(profile['manifests'])} ecosystems")

    if "architecture" in selected:
        announce("architecture: evaluating applicable controls...")
        _run(["architecture_coverage_checks.py", "--repo-root", repo, "--output-dir", out])
        data = _read(work_dir / ".architecture-coverage.json", "architecture")
        rules = data.get("rules_evaluated")
        if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
            raise RuntimeError("architecture: scanner output has no valid rules list")
        results.append(
            {
                "name": "architecture",
                "checks_run": len(rules),
                "rules": rules,
                "rules_applicable": sum(rule.get("status") != "not_applicable" for rule in rules),
            }
        )
        announce(f"architecture: {results[-1]['rules_applicable']} of {len(rules)} rules applicable")

    return {
        "version": 1,
        "repo": str(repo_root),
        "scans": results,
        "summary": summarize(results, minimum_severity),
    }


def summarize(scans: list[dict[str, Any]], minimum_severity: str = "all") -> dict[str, Any]:
    """Summarize selected results without counting AUTHZ twice with source."""
    names = {scan["name"] for scan in scans}
    source_keys = {
        (finding.get("file"), finding.get("line"), finding.get("check_id"))
        for scan in scans
        if scan["name"] == "source"
        for finding in scan["findings"]
    }
    severities: Counter[str] = Counter()
    findings_total = 0
    for scan in scans:
        if "findings" not in scan:
            continue
        rows = scan["findings"]
        if scan["name"] == "authz" and "source" in names:
            rows = [
                finding
                for finding in rows
                if (finding.get("file"), finding.get("line"), finding.get("check_id")) not in source_keys
            ]
        findings_total += len(rows)
        for finding in rows:
            severity = str(finding.get("severity") or "").strip().lower()
            severities[severity if severity in {"critical", "high", "medium", "low"} else "other"] += 1

    endpoints = next((scan for scan in scans if scan["name"] == "endpoints"), None)
    stack = next((scan for scan in scans if scan["name"] == "stack"), None)
    architecture = next((scan for scan in scans if scan["name"] == "architecture"), None)
    frameworks = (
        stack["frameworks"]
        if stack is not None
        else endpoints["coverage"].get("frameworks_detected", [])
        if endpoints is not None
        else []
    )
    return {
        "scans_run": len(scans),
        "minimum_severity": minimum_severity,
        "findings_total": findings_total,
        "severity_counts": {key: severities[key] for key in ("critical", "high", "medium", "low", "other")},
        "endpoints_total": endpoints["route_count"] if endpoints is not None else None,
        "architecture_applicable": architecture["rules_applicable"] if architecture is not None else None,
        "frameworks": frameworks,
        "languages": [row["language"] for row in stack["languages"] if row.get("category") == "code"]
        if stack is not None
        else [],
    }


def render_text(report: dict[str, Any]) -> str:
    def visible(value: Any) -> str:
        return json.dumps(str(value), ensure_ascii=False)[1:-1]

    lines = [f"Deterministic repository scans: {visible(report['repo'])}"]
    for scan in report["scans"]:
        if scan["name"] == "endpoints":
            lines.append(f"  endpoints: {scan['route_count']} routes")
            coverage = scan["coverage"]
            lines.append(
                "    auth review candidates: "
                f"{coverage.get('missing_auth_suspect_count', 0)} authn, "
                f"{coverage.get('missing_authz_suspect_count', 0)} authz"
            )
            for route in scan["routes"]:
                lines.append(
                    f"    {visible(route.get('method') or '?')} {visible(route.get('path') or '?')} "
                    f"[{visible(route.get('framework') or '?')}] "
                    f"{visible(route.get('handler_file') or '?')}:{visible(route.get('handler_line') or '?')}"
                )
            unsupported = scan["coverage"].get("unsupported_route_files") or []
            if unsupported:
                lines.append(f"    {len(unsupported)} route files could not be enumerated")
            continue
        if scan["name"] == "stack":
            languages = (
                ", ".join(visible(row["language"]) for row in scan["languages"] if row.get("category") == "code")
                or "none detected"
            )
            manifests = ", ".join(visible(row["ecosystem"]) for row in scan["manifests"]) or "none detected"
            frameworks = ", ".join(visible(row) for row in scan["frameworks"]) or "none detected"
            lines.append(f"  stack: languages: {languages}; manifests: {manifests}; route frameworks: {frameworks}")
            for row in scan["languages"]:
                if row.get("category") == "code":
                    noun = "file" if row["files"] == 1 else "files"
                    lines.append(
                        f"    {visible(row['language'])}: {row['files']} {noun}, {row['share']}% of source bytes"
                    )
            continue
        if scan["name"] == "architecture":
            lines.append(f"  architecture: {scan['rules_applicable']}/{scan['checks_run']} rules applicable")
            statuses = Counter(rule.get("status") for rule in scan["rules"])
            lines.append(
                "    "
                + ", ".join(
                    f"{key}={statuses[key]}" for key in ("present", "partial", "weak", "missing", "anti_pattern")
                )
            )
            continue
        lines.append(f"  {scan['name']}: {scan['findings_total']} findings, {scan['checks_run']} checks")
        counts = Counter(str(finding.get("severity") or "?").strip().lower() for finding in scan["findings"])
        if counts:
            lines.append(
                "    severities: "
                + ", ".join(f"{key}={counts[key]}" for key in ("critical", "high", "medium", "low") if counts[key])
            )
        for finding in scan["findings"]:
            location = visible(finding.get("file") or "?")
            if finding.get("line") is not None:
                location += f":{finding['line']}"
            lines.append(
                f"    {visible(finding.get('severity') or '?')} {visible(finding.get('check_id') or '?')} "
                f"{location} — {visible(finding.get('title') or '?')}"
            )
        if scan["ignored_assessment_findings"]:
            lines.append(f"    ignored {scan['ignored_assessment_findings']} prior-assessment findings")
    summary = report["summary"]
    counts = summary["severity_counts"]
    endpoints = summary["endpoints_total"]
    architecture = summary["architecture_applicable"]
    lines += [
        "",
        "SUMMARY "
        f"scans={summary['scans_run']} findings={summary['findings_total']} "
        f"minimum_severity={summary['minimum_severity']} "
        f"critical={counts['critical']} high={counts['high']} medium={counts['medium']} "
        f"low={counts['low']} other={counts['other']} "
        f"endpoints={endpoints if endpoints is not None else 'na'} "
        f"architecture_applicable={architecture if architecture is not None else 'na'}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Local directory or HTTPS Git URL")
    parser.add_argument(
        "--scan",
        action="append",
        choices=(*SCANS, "all"),
        help="Select a scan (repeatable; default: all, or finding scans with a severity filter).",
    )
    formats = parser.add_mutually_exclusive_group()
    formats.add_argument(
        "--yaml",
        nargs="?",
        const="-",
        metavar="PATH",
        help="Emit selected results as YAML to stdout, or write them to PATH",
    )
    formats.add_argument(
        "--json",
        nargs="?",
        const="-",
        metavar="PATH",
        help="Emit selected results as JSON to stdout, or write them to PATH",
    )
    thresholds = parser.add_mutually_exclusive_group()
    thresholds.add_argument("--medium", action="store_true", help="Show Medium, High, and Critical findings")
    thresholds.add_argument("--high", action="store_true", help="Show High and Critical findings")
    thresholds.add_argument("--critical", action="store_true", help="Show Critical findings only")
    args = parser.parse_args(argv)
    minimum_severity = next((key for key in ("medium", "high", "critical") if getattr(args, key)), "all")
    if not args.scan:
        selected = list(FINDING_SCANS) if minimum_severity != "all" else [name for name in SCANS if name != "authz"]
    elif "all" in args.scan:
        selected = [name for name in SCANS if name != "authz"]
    else:
        selected = list(dict.fromkeys(args.scan))

    def progress(message: str) -> None:
        if args.json is None:
            print(f"PROGRESS {message}", file=sys.stderr, flush=True)

    started = time.monotonic()
    try:
        with contextlib.ExitStack() as cleanup:
            if "://" in args.repo:
                remote = _remote_url(args.repo)
                progress("cloning remote repository...")
                parent = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="appsec-scan-repo-")))
                root = parent / "checkout"
                _clone(remote, root)
                progress("remote checkout ready")
                display = remote
                escaping = next(iter_escaping_symlinks(root), None)
                if escaping is not None:
                    raise ValueError(f"checkout contains an escaping symlink: {escaping.path.relative_to(root)}")
            else:
                root = Path(args.repo).expanduser().resolve()
                if not root.is_dir():
                    raise ValueError(f"not a directory: {root}")
                display = str(root)
            progress(f"running {len(selected)} selected scans (minimum severity: {minimum_severity})")
            work_dir = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="appsec-scan-")))
            report = collect(root, work_dir, selected, progress=progress, minimum_severity=minimum_severity)
            report["repo"] = display
            validate(report, yaml.safe_load(SCHEMA.read_text(encoding="utf-8")))
            progress(f"completed {len(report['scans'])} scans in {time.monotonic() - started:.1f}s")

            if args.yaml is None and args.json is None:
                print(render_text(report))
            else:
                format_name = "YAML" if args.yaml is not None else "JSON"
                destination = args.yaml if args.yaml is not None else args.json
                payload = (
                    yaml.safe_dump(report, sort_keys=False, allow_unicode=True)
                    if format_name == "YAML"
                    else json.dumps(report, indent=2, ensure_ascii=False) + "\n"
                )
                if destination == "-":
                    print(payload, end="")
                else:
                    target = Path(destination).expanduser().resolve()
                    if not target.parent.is_dir():
                        raise ValueError(f"{format_name} output directory does not exist: {target.parent}")
                    with tempfile.NamedTemporaryFile(
                        mode="w",
                        encoding="utf-8",
                        dir=target.parent,
                        prefix=".appsec-scan-",
                        suffix=".tmp",
                        delete=False,
                    ) as stream:
                        staged = Path(stream.name)
                        stream.write(payload)
                    try:
                        os.replace(staged, target)
                    finally:
                        staged.unlink(missing_ok=True)
                    if args.json is None:
                        print(f"Wrote {target}")
    except (ValueError, RuntimeError, OSError, ValidationError, yaml.YAMLError) as exc:
        print(f"repo_scan: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
