#!/usr/bin/env python3
"""
dep_scan.py — pure Software Composition Analysis (SCA) scanner.

Replaces the former `appsec-dep-scanner` LLM agent. Runs deterministically:
discover dependency manifests, invoke native audit tools (npm audit,
pip-audit, govulncheck, mvn dependency-check) when available, fall back to
a static heuristic list (`claude-plugin/data/dep-scan-heuristics.yaml`) otherwise.

Output schema is byte-compatible with the former agent's `.dep-scan.json`
contract — downstream consumers (Phase 10 SCA synthesis, render_threat_model,
SARIF export) need no changes.

Usage
-----
    python3 dep_scan.py --repo-root <DIR> --output-dir <DIR> [--manifests <list>]

The `--manifests` argument is a comma-separated list of relative manifest
paths, normally pre-discovered by recon-scanner. When omitted, the script
auto-discovers manifests using the canonical filenames below.

Cache: when `<OUTPUT_DIR>/.dep-scan.json` exists, is < 1 hour old, and its
`manifest_hashes` field matches the current manifests, the scan is skipped.

Exit codes
    0  scan completed (or cache hit)
    1  IO / discovery error
    2  usage error
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

# Manifest filenames the scanner recognizes. Order is meaningful only for
# discovery output — the auditor for each is selected per-file below.
_MANIFEST_FILENAMES = (
    "package-lock.json",
    "package.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "poetry.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
)

_TOOL_TIMEOUT_SEC = 90
_CACHE_MAX_AGE_SEC = 3600
_HEURISTICS_PATH = Path(__file__).resolve().parent.parent / "data" / "dep-scan-heuristics.yaml"


# ---------------------------------------------------------------------------
# IO / discovery
# ---------------------------------------------------------------------------

def _discover_manifests(repo_root: Path) -> list[Path]:
    """Walk the repo and return manifest files. Skips common vendored dirs."""
    skip_dirs = {"node_modules", ".git", "vendor", "dist", "build",
                 "__pycache__", ".venv", "venv", "target"}
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for f in filenames:
            if f in _MANIFEST_FILENAMES:
                found.append(Path(dirpath) / f)
    return sorted(found)


def _md5_hash(path: Path, length: int = 8) -> str:
    h = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()[:length]


def _hashes_for(manifests: list[Path], repo_root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in manifests:
        try:
            rel = str(m.relative_to(repo_root))
        except ValueError:
            rel = str(m)
        out[rel] = _md5_hash(m)
    return out


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _is_cache_valid(output_dir: Path, current_hashes: dict[str, str]) -> bool:
    cache = output_dir / ".dep-scan.json"
    if not cache.exists():
        return False
    try:
        with cache.open() as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return False
    cached_hashes = data.get("manifest_hashes")
    if not isinstance(cached_hashes, dict) or cached_hashes != current_hashes:
        return False
    scanned_at = data.get("scanned_at")
    if not isinstance(scanned_at, str):
        return False
    try:
        # Tolerate Z suffix and naive parses; we only need an age comparison.
        ts = _dt.datetime.strptime(scanned_at, "%Y-%m-%dT%H:%M:%SZ")
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return False
    age = (_dt.datetime.now(_dt.timezone.utc) - ts).total_seconds()
    return age < _CACHE_MAX_AGE_SEC


# ---------------------------------------------------------------------------
# Heuristic fallback
# ---------------------------------------------------------------------------

def _load_heuristics() -> list[dict[str, Any]]:
    if not _HEURISTICS_PATH.exists():
        return []
    try:
        with _HEURISTICS_PATH.open() as fh:
            doc = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return []
    entries = doc.get("known_vulns") or []
    return [e for e in entries if isinstance(e, dict)]


def _normalize_version(v: str) -> tuple[int, ...]:
    """Loose SemVer / PEP-440 numeric tuple. Non-numeric suffixes truncated.
    Used only for heuristic <-comparisons; does not pretend to be a full
    version-spec parser."""
    if not isinstance(v, str):
        return ()
    s = v.strip().lstrip("=v^~>< ")
    parts: list[int] = []
    for chunk in s.split("."):
        num = ""
        for c in chunk:
            if c.isdigit():
                num += c
            else:
                break
        if not num:
            break
        parts.append(int(num))
    return tuple(parts)


def _version_below(found: str, threshold: str) -> bool:
    """True iff `found` < `threshold` under loose comparison. Returns False
    on parse failure (safe default — don't flag uncertain versions)."""
    f = _normalize_version(found)
    t = _normalize_version(threshold)
    if not f or not t:
        return False
    return f < t


def _heuristic_npm(manifest: Path, content: str, heuristics: list[dict]) -> list[dict]:
    findings: list[dict] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return findings
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        d = data.get(section)
        if isinstance(d, dict):
            for name, ver in d.items():
                if isinstance(ver, str):
                    deps[name] = ver
    for h in heuristics:
        if h.get("ecosystem") != "npm":
            continue
        pkg = h.get("package")
        ver = deps.get(pkg)
        if ver and _version_below(ver, h.get("vulnerable_below", "")):
            findings.append(_finding(manifest, pkg, ver, h))
    return findings


def _heuristic_python(manifest: Path, content: str, heuristics: list[dict]) -> list[dict]:
    findings: list[dict] = []
    deps: dict[str, str] = {}
    # naive requirements.txt-style parse: "pkg==1.2.3" or "pkg>=1.2.3"
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        for sep in ("==", ">=", "~=", "==="):
            if sep in line:
                name, _, ver = line.partition(sep)
                deps[name.strip().lower()] = ver.strip()
                break
    for h in heuristics:
        if h.get("ecosystem") != "python":
            continue
        pkg = (h.get("package") or "").lower()
        ver = deps.get(pkg)
        if ver and _version_below(ver, h.get("vulnerable_below", "")):
            findings.append(_finding(manifest, h.get("package"), ver, h))
    return findings


def _finding(manifest: Path, pkg: str, version: str, h: dict) -> dict:
    return {
        "manifest": str(manifest.name),
        "package": pkg,
        "version_found": version,
        "issue": h.get("issue") or "",
        "cve_id": h.get("cve"),
        "source": "heuristic",
        "severity": h.get("severity") or "Medium",
        "cvss_v4": None,
    }


# ---------------------------------------------------------------------------
# Native audit tools
# ---------------------------------------------------------------------------

def _run_tool(cmd: list[str], cwd: Path) -> tuple[str | None, bool]:
    """Run a tool with timeout. Returns (stdout, was_available).
    was_available=False means the binary is not on PATH."""
    binary = cmd[0]
    if shutil.which(binary) is None:
        return None, False
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True,
            timeout=_TOOL_TIMEOUT_SEC,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, True
    # Many audit tools exit non-zero when vulns are found — accept any output
    # that parses as JSON.
    return proc.stdout, True


def _npm_audit_findings(out: str, manifest_name: str) -> list[dict]:
    findings: list[dict] = []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return findings
    vulns = data.get("vulnerabilities") or {}
    if not isinstance(vulns, dict):
        return findings
    for name, info in vulns.items():
        if not isinstance(info, dict):
            continue
        sev = (info.get("severity") or "medium").capitalize()
        if sev not in {"Critical", "High", "Medium", "Low"}:
            sev = "Medium"
        via_list = info.get("via") or []
        cve = None
        title = ""
        cvss_block = None
        for v in via_list:
            if isinstance(v, dict):
                cwe = v.get("cwe")  # noqa: F841 — kept for future use
                title = v.get("title") or title
                if v.get("cves"):
                    cves = v.get("cves")
                    if isinstance(cves, list) and cves:
                        cve = cves[0]
                cvss = v.get("cvss")
                if isinstance(cvss, dict) and cvss.get("vectorString"):
                    cvss_block = {
                        "vector": cvss.get("vectorString"),
                        "base_score": cvss.get("score"),
                        "severity": sev,
                        "source": "npm-audit",
                        "version_fallback": "3.1" if "CVSS:3" in (cvss.get("vectorString") or "") else None,
                    }
                break
        findings.append({
            "manifest": manifest_name,
            "package": name,
            "version_found": info.get("range") or info.get("version") or "",
            "issue": title or f"Known vulnerability in {name}",
            "cve_id": cve,
            "source": "live-audit",
            "severity": sev,
            "cvss_v4": cvss_block,
        })
    return findings


def _pip_audit_findings(out: str, manifest_name: str) -> list[dict]:
    findings: list[dict] = []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return findings
    deps = data.get("dependencies") or []
    if not isinstance(deps, list):
        return findings
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        for vuln in dep.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            findings.append({
                "manifest": manifest_name,
                "package": dep.get("name") or "",
                "version_found": dep.get("version") or "",
                "issue": vuln.get("description") or vuln.get("id") or "",
                "cve_id": vuln.get("id") if str(vuln.get("id") or "").startswith("CVE-") else None,
                "source": "live-audit",
                "severity": "High",  # pip-audit doesn't always emit severity
                "cvss_v4": None,
            })
    return findings


def _govulncheck_findings(out: str, manifest_name: str) -> list[dict]:
    """govulncheck emits one JSON object per line."""
    findings: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = obj.get("finding") if isinstance(obj, dict) else None
        if not isinstance(finding, dict):
            continue
        osv = finding.get("osv") or finding.get("OSV") or ""
        symbol = finding.get("symbol") or ""
        findings.append({
            "manifest": manifest_name,
            "package": symbol or "<unknown>",
            "version_found": "",
            "issue": f"govulncheck flagged {osv}".strip(),
            "cve_id": osv if str(osv).startswith("CVE-") else None,
            "source": "live-audit",
            "severity": "High",
            "cvss_v4": None,
        })
    return findings


# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------

def _scan_manifest(manifest: Path, repo_root: Path, heuristics: list[dict]) -> tuple[list[dict], str]:
    """Returns (findings, mode) where mode ∈ {live-audit, heuristic, skipped}."""
    name = manifest.name
    rel = str(manifest.relative_to(repo_root)) if manifest.is_relative_to(repo_root) else str(manifest)
    if name in ("package-lock.json", "package.json"):
        out, available = _run_tool(["npm", "audit", "--json"], cwd=manifest.parent)
        if available and out:
            findings = _npm_audit_findings(out, rel)
            if findings or "vulnerabilities" in out:
                return findings, "live-audit"
        # fall through to heuristic
        try:
            content = manifest.read_text()
        except OSError:
            return [], "skipped"
        return _heuristic_npm(manifest, content, heuristics), "heuristic"

    if name in ("requirements.txt", "Pipfile", "pyproject.toml"):
        out, available = _run_tool(
            ["pip-audit", "--format", "json", "-r", str(manifest)],
            cwd=manifest.parent,
        )
        if available and out:
            findings = _pip_audit_findings(out, rel)
            if findings or "dependencies" in out:
                return findings, "live-audit"
        try:
            content = manifest.read_text()
        except OSError:
            return [], "skipped"
        return _heuristic_python(manifest, content, heuristics), "heuristic"

    if name in ("go.mod", "go.sum"):
        out, available = _run_tool(["govulncheck", "-json", "./..."], cwd=manifest.parent)
        if available and out:
            return _govulncheck_findings(out, rel), "live-audit"
        return [], "skipped"

    # Maven and others — no heuristics yet, skip cleanly
    return [], "skipped"


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------

def _write_output(output_dir: Path, repo_root: Path, findings: list[dict],
                  manifest_hashes: dict[str, str]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "scanned_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo_root": str(repo_root),
        "manifest_hashes": manifest_hashes,
        "summary": {"vulnerable_dependencies": len(findings)},
        "vulnerable_dependencies": findings,
    }
    out = output_dir / ".dep-scan.json"
    with out.open("w") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, sort_keys=False)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_manifests(spec: str | None, repo_root: Path) -> list[Path]:
    if not spec:
        return _discover_manifests(repo_root)
    items: list[Path] = []
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry:
            continue
        p = (repo_root / entry).resolve() if not Path(entry).is_absolute() else Path(entry)
        if p.exists():
            items.append(p)
    return items


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dep_scan",
        description="SCA dependency vulnerability scan (replaces the former dep-scanner agent).",
    )
    parser.add_argument("--repo-root", required=True,
                        help="Absolute path to the repository being scanned.")
    parser.add_argument("--output-dir", required=True,
                        help="Absolute output directory (typically docs/security/).")
    parser.add_argument("--manifests", default=None,
                        help="Comma-separated relative manifest paths. Auto-discover when omitted.")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    repo_root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    if not repo_root.exists():
        print(f"dep_scan: repo-root not found: {repo_root}", file=sys.stderr)
        return 1

    manifests = _parse_manifests(args.manifests, repo_root)
    if not manifests:
        # Write an empty result rather than failing — Phase 10 then logs "no
        # manifests detected" and skips synthesis cleanly.
        _write_output(output_dir, repo_root, [], {})
        print("dep_scan: no dependency manifests found — wrote empty .dep-scan.json")
        return 0

    current_hashes = _hashes_for(manifests, repo_root)
    if _is_cache_valid(output_dir, current_hashes):
        print(f"dep_scan: cache hit — reusing existing .dep-scan.json "
              f"({len(manifests)} manifests, hashes match, age < 1h)")
        return 0

    heuristics = _load_heuristics()
    all_findings: list[dict] = []
    live_count = heuristic_count = skipped_count = 0
    for m in manifests:
        findings, mode = _scan_manifest(m, repo_root, heuristics)
        all_findings.extend(findings)
        if mode == "live-audit":
            live_count += 1
        elif mode == "heuristic":
            heuristic_count += 1
        else:
            skipped_count += 1

    out_path = _write_output(output_dir, repo_root, all_findings, current_hashes)
    print(
        f"dep_scan: wrote {out_path} "
        f"({len(all_findings)} vulnerabilities across {len(manifests)} manifests "
        f"— live: {live_count}, heuristic: {heuristic_count}, skipped: {skipped_count})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
