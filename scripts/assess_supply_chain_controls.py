#!/usr/bin/env python3
"""
assess_supply_chain_controls.py — deterministic supply chain control assessment.

Replaces the LLM reasoning loop for Phase 8's "Operations, Runtime and Supply Chain"
domain by evaluating the 9 rule-based sub-controls directly from recon artifacts.
Saves ~4 orchestrator turns per run (the LLM no longer needs to read recon sections
7.14–7.17, 7.26–7.28, reason through 9 sub-controls, and write the assessment prose).

Sub-controls evaluated (per phase-group-architecture.md §"Operations, Runtime and Supply
Chain — sub-controls"):
  1. CVE scanning
  2. Lockfile pinning
  3. CI install integrity
  4. CI/CD action pinning
  5. Container image hygiene
  6. Dependency confusion
  7. Postinstall scripts
  8. Dependency management (Renovate / Dependabot)
  9. SCA tooling

Output: $OUTPUT_DIR/.supply-chain-assessment.json

Usage:
  python3 assess_supply_chain_controls.py <output_dir> [--repo-root <path>]
  python3 assess_supply_chain_controls.py <output_dir> --report-only   (print JSON, no file write)

Exit codes:
  0   Assessment written (or printed in --report-only mode).
  1   Required input not found (.recon-summary.md missing and no repo-root given).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Effectiveness enum
# ---------------------------------------------------------------------------
ADEQUATE = "Adequate"
PARTIAL = "Partial"
WEAK = "Weak"
MISSING = "Missing"


# ---------------------------------------------------------------------------
# Recon-summary text helpers
# ---------------------------------------------------------------------------

def _load_recon(output_dir: str, repo_root: str | None) -> str:
    """Return recon-summary text, or empty string if unavailable."""
    recon_path = Path(output_dir) / ".recon-summary.md"
    if recon_path.exists():
        return recon_path.read_text(encoding="utf-8", errors="replace")
    # Fallback: scan repo root directly (first-run before recon writes the file).
    return ""


def _section(text: str, heading: str) -> str:
    """Extract the text block under a recon-summary section heading."""
    pattern = rf"(?m)^#{1,4}\s+{re.escape(heading)}.*?$(.*?)(?=^#{1,4}\s|\Z)"
    m = re.search(pattern, text, re.DOTALL | re.MULTILINE)
    return m.group(1) if m else ""


def _has(text: str, *patterns: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


# ---------------------------------------------------------------------------
# Sub-control evaluators
# ---------------------------------------------------------------------------

def _eval_lockfile(recon: str, repo_root: str | None) -> dict[str, str]:
    """Lockfile pinning: is a lockfile present and committed?"""
    present = _has(recon, r"package-lock\.json", r"yarn\.lock", r"pnpm-lock\.yaml",
                   r"Pipfile\.lock", r"poetry\.lock", r"Gemfile\.lock",
                   r"Cargo\.lock", r"go\.sum", r"composer\.lock")
    # Check repo root directly when available
    if not present and repo_root:
        lockfiles = [
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "Pipfile.lock", "poetry.lock", "Gemfile.lock",
            "Cargo.lock", "go.sum", "composer.lock",
        ]
        present = any(Path(repo_root, lf).exists() for lf in lockfiles)

    if present:
        return {"effectiveness": ADEQUATE, "reason": "Lockfile present and committed for detected ecosystem(s)."}
    return {"effectiveness": MISSING, "reason": "No lockfile found for any detected package ecosystem."}


def _eval_ci_install(recon: str) -> dict[str, str]:
    """CI install integrity: does CI use deterministic install flags?"""
    deterministic = _has(recon,
        r"npm\s+ci\b", r"--frozen-lockfile", r"--immutable",
        r"--require-hashes", r"cargo\s+build\s+--locked",
        r"dotnet\s+restore\s+--locked", r"bundle\s+install\s+--frozen",
        r"go\s+mod\s+verify",
    )
    mutable = _has(recon, r"npm\s+install\b", r"pip\s+install\b(?!\s+--require-hashes)")
    if deterministic:
        return {"effectiveness": ADEQUATE, "reason": "CI uses deterministic install commands (npm ci / --frozen-lockfile / equivalent)."}
    if mutable:
        return {"effectiveness": MISSING, "reason": "CI uses mutable install commands (npm install / pip install without hashes)."}
    return {"effectiveness": MISSING, "reason": "No CI install step detected."}


def _eval_action_pinning(recon: str, repo_root: str | None) -> dict[str, str]:
    """GitHub Actions pinning: SHA-pinned vs. mutable tags."""
    # Read workflow files directly when repo root is available
    workflow_text = recon
    if repo_root:
        wf_dir = Path(repo_root) / ".github" / "workflows"
        if wf_dir.is_dir():
            parts = []
            for wf in wf_dir.glob("*.yml"):
                try:
                    parts.append(wf.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
            for wf in wf_dir.glob("*.yaml"):
                try:
                    parts.append(wf.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
            if parts:
                workflow_text = "\n".join(parts)

    # SHA-pinned: uses@<40-char hex> or @sha256:
    sha_pinned = bool(re.search(r"uses:\s*\S+@[0-9a-f]{40}", workflow_text) or
                      re.search(r"uses:\s*\S+@sha256:", workflow_text))
    # Mutable: uses@v<digit> or @latest
    mutable_ref = bool(re.search(r"uses:\s*\S+@v\d", workflow_text) or
                       re.search(r"uses:\s*\S+@latest", workflow_text))
    has_workflows = bool(re.search(r"uses:\s*\S+@", workflow_text))

    if not has_workflows:
        return {"effectiveness": MISSING, "reason": "No GitHub Actions workflows detected."}
    if sha_pinned and not mutable_ref:
        return {"effectiveness": ADEQUATE, "reason": "All detected GitHub Actions steps pinned to commit SHA."}
    if sha_pinned and mutable_ref:
        return {"effectiveness": PARTIAL, "reason": "Mix of SHA-pinned and mutable-tag Actions references."}
    return {"effectiveness": MISSING, "reason": "GitHub Actions steps pinned to mutable tags (@v<N> / @latest)."}


def _eval_container_hygiene(recon: str, repo_root: str | None) -> dict[str, str]:
    """Container image hygiene: digest-pinned base images."""
    dockerfile_text = recon
    if repo_root:
        df = Path(repo_root) / "Dockerfile"
        if df.exists():
            try:
                dockerfile_text = df.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

    has_dockerfile = _has(dockerfile_text, r"^FROM\s", r"FROM\s+\S")
    if not has_dockerfile:
        return {"effectiveness": MISSING, "reason": "No Dockerfile detected."}

    digest_pinned = bool(re.search(r"FROM\s+\S+@sha256:[0-9a-f]{64}", dockerfile_text))
    uses_latest = bool(re.search(r"FROM\s+\S+:latest", dockerfile_text, re.IGNORECASE) or
                       re.search(r"FROM\s+\S+\s", dockerfile_text) and
                       not re.search(r"FROM\s+\S+:\S+", dockerfile_text))
    version_tagged = bool(re.search(r"FROM\s+\S+:\d", dockerfile_text))

    if digest_pinned:
        return {"effectiveness": ADEQUATE, "reason": "Base image pinned to SHA-256 digest."}
    if version_tagged:
        return {"effectiveness": PARTIAL, "reason": "Base image pinned to version tag but not digest."}
    return {"effectiveness": MISSING, "reason": "Base image uses :latest tag or no tag."}


def _eval_dependency_confusion(recon: str, repo_root: str | None) -> dict[str, str]:
    """Dependency confusion: scoped packages / private registry."""
    has_private_registry = _has(recon,
        r"registry\.npmrc", r"\.npmrc", r"@\w+/",
        r"private.*registry", r"verdaccio", r"artifactory", r"nexus",
    )
    npmrc_path = Path(repo_root or "", ".npmrc") if repo_root else None
    if npmrc_path and npmrc_path.exists():
        try:
            npmrc = npmrc_path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"registry\s*=", npmrc) or re.search(r"@\w+:registry", npmrc):
                return {"effectiveness": ADEQUATE, "reason": ".npmrc configures private/scoped registry."}
        except OSError:
            pass

    if has_private_registry:
        return {"effectiveness": PARTIAL, "reason": "Scoped packages or private registry references detected — partial protection."}
    return {"effectiveness": MISSING, "reason": "No private registry or scoped package configuration detected."}


def _eval_postinstall(recon: str, repo_root: str | None) -> dict[str, str]:
    """Postinstall scripts: are install hooks audited or disabled?"""
    pkg_json: dict[str, Any] = {}
    if repo_root:
        pkg_path = Path(repo_root) / "package.json"
        if pkg_path.exists():
            try:
                pkg_json = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                pass

    scripts = pkg_json.get("scripts", {})
    has_postinstall = "postinstall" in scripts or "preinstall" in scripts or "install" in scripts

    ignore_scripts = _has(recon, r"ignore-scripts", r"--no-scripts", r"npm_config_ignore_scripts")

    if not has_postinstall:
        return {"effectiveness": ADEQUATE, "reason": "No postinstall/preinstall hooks detected in package.json."}
    if ignore_scripts:
        return {"effectiveness": ADEQUATE, "reason": "Install hooks present but --ignore-scripts / npm_config_ignore_scripts configured."}
    # Hooks exist — classify by content
    hook_cmd = scripts.get("postinstall", scripts.get("preinstall", scripts.get("install", "")))
    if re.search(r"(curl|wget|fetch|http|node\s+-e|eval)", hook_cmd, re.IGNORECASE):
        return {"effectiveness": MISSING, "reason": f"Postinstall hook executes network/eval operation: {hook_cmd!r:.80}"}
    return {"effectiveness": PARTIAL, "reason": "Install hooks present (build tasks only); no explicit audit or --ignore-scripts."}


def _eval_dep_management(recon: str, repo_root: str | None) -> dict[str, str]:
    """Dependency management: Renovate or Dependabot configured."""
    renovate = False
    dependabot = False

    if repo_root:
        renovate_paths = [
            Path(repo_root) / "renovate.json",
            Path(repo_root) / "renovate.json5",
            Path(repo_root) / ".github" / "renovate.json",
            Path(repo_root) / ".renovaterc",
            Path(repo_root) / ".renovaterc.json",
        ]
        renovate = any(p.exists() for p in renovate_paths)

        dependabot_path = Path(repo_root) / ".github" / "dependabot.yml"
        dependabot_path2 = Path(repo_root) / ".github" / "dependabot.yaml"
        dependabot = dependabot_path.exists() or dependabot_path2.exists()

    if not renovate and not dependabot:
        renovate = _has(recon, r"renovate", r"renovatebot")
        dependabot = _has(recon, r"dependabot")

    if renovate or dependabot:
        tool = "Renovate" if renovate else "Dependabot"
        return {"effectiveness": PARTIAL, "reason": f"{tool} detected — verify security-updates are explicitly enabled and all ecosystems covered."}
    return {"effectiveness": MISSING, "reason": "No Renovate or Dependabot configuration detected."}


def _eval_cve_scanning(recon: str) -> dict[str, str]:
    """CVE scanning: SCA tool in CI with blocking policy."""
    blocking = _has(recon,
        r"npm\s+audit\s+--audit-level=(high|critical)",
        r"snyk\s+test.*--severity-threshold",
        r"trivy.*--exit-code\s+1",
        r"grype.*--fail-on",
        r"osv-scanner.*--fail",
        r"pip-audit.*--fail-on",
    )
    advisory = _has(recon,
        r"npm\s+audit\b", r"snyk\s+test\b", r"trivy\b", r"grype\b",
        r"osv-scanner\b", r"pip-audit\b", r"OWASP.*dependency",
    )
    if blocking:
        return {"effectiveness": ADEQUATE, "reason": "SCA tool configured with blocking policy on Critical/High findings."}
    if advisory:
        return {"effectiveness": PARTIAL, "reason": "SCA tool present but advisory-only (no blocking exit code configured)."}
    return {"effectiveness": MISSING, "reason": "No SCA/CVE scanning tool detected in CI or manifests."}


def _eval_sca_tooling(recon: str) -> dict[str, str]:
    """SCA tooling: dedicated SCA tool vs. native audit only."""
    dedicated = _has(recon, r"snyk\b", r"trivy\b", r"grype\b", r"osv-scanner\b",
                     r"OWASP.*dependency.check", r"dependency.check\b", r"syft\b")
    native_only = _has(recon, r"npm\s+audit\b", r"pip-audit\b", r"cargo\s+audit\b")
    if dedicated:
        return {"effectiveness": ADEQUATE, "reason": "Dedicated SCA tool (Snyk/Trivy/Grype/OSV-Scanner or equivalent) detected."}
    if native_only:
        return {"effectiveness": PARTIAL, "reason": "Only native audit commands (npm audit / pip-audit) detected — no dedicated SCA tool."}
    return {"effectiveness": MISSING, "reason": "No SCA tooling detected in CI or manifests."}


# ---------------------------------------------------------------------------
# Overall domain rating derivation
# ---------------------------------------------------------------------------

_EFFECTIVENESS_RANK = {ADEQUATE: 3, PARTIAL: 2, WEAK: 1, MISSING: 0}


def _derive_overall(sub_controls: list[dict[str, Any]]) -> tuple[str, str]:
    ratings = [sc["effectiveness"] for sc in sub_controls]
    if any(r == MISSING for r in ratings):
        worst = WEAK  # per spec: any Missing → at most Weak domain
    elif all(r == ADEQUATE for r in ratings):
        worst = ADEQUATE
    else:
        worst = PARTIAL

    missing_names = [sc["name"] for sc in sub_controls if sc["effectiveness"] == MISSING]
    partial_names = [sc["name"] for sc in sub_controls if sc["effectiveness"] == PARTIAL]
    if missing_names:
        reason = f"Missing controls: {', '.join(missing_names)}."
        if partial_names:
            reason += f" Partial: {', '.join(partial_names)}."
    elif partial_names:
        reason = f"Partial controls: {', '.join(partial_names)}."
    else:
        reason = "All supply chain sub-controls rated Adequate."
    return worst, reason


# ---------------------------------------------------------------------------
# Main assessment
# ---------------------------------------------------------------------------

def assess(output_dir: str, repo_root: str | None) -> dict[str, Any]:
    recon = _load_recon(output_dir, repo_root)

    sub_controls = [
        {"name": "CVE scanning",          **_eval_cve_scanning(recon)},
        {"name": "Lockfile pinning",       **_eval_lockfile(recon, repo_root)},
        {"name": "CI install integrity",   **_eval_ci_install(recon)},
        {"name": "CI/CD action pinning",   **_eval_action_pinning(recon, repo_root)},
        {"name": "Container image hygiene", **_eval_container_hygiene(recon, repo_root)},
        {"name": "Dependency confusion",   **_eval_dependency_confusion(recon, repo_root)},
        {"name": "Postinstall scripts",    **_eval_postinstall(recon, repo_root)},
        {"name": "Dependency management",  **_eval_dep_management(recon, repo_root)},
        {"name": "SCA tooling",            **_eval_sca_tooling(recon)},
    ]

    overall_effectiveness, overall_reason = _derive_overall(sub_controls)

    return {
        "schema_version": 1,
        "domain": "Operations, Runtime and Supply Chain Controls",
        "sub_controls": sub_controls,
        "overall_effectiveness": overall_effectiveness,
        "overall_reason": overall_reason,
        "source": "deterministic:assess_supply_chain_controls.py",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deterministic supply chain control assessment for Phase 8"
    )
    parser.add_argument("output_dir", help="Assessment output directory (docs/security)")
    parser.add_argument("--repo-root", default=None, help="Repository root (optional, improves detection)")
    parser.add_argument("--report-only", action="store_true",
                        help="Print JSON to stdout instead of writing file")
    args = parser.parse_args()

    result = assess(args.output_dir, args.repo_root)
    payload = json.dumps(result, indent=2)

    if args.report_only:
        print(payload)
        return

    out_path = Path(args.output_dir) / ".supply-chain-assessment.json"
    try:
        out_path.write_text(payload + "\n", encoding="utf-8")
        print(
            f"assess_supply_chain_controls: wrote {out_path} "
            f"(overall={result['overall_effectiveness']}, "
            f"{sum(1 for sc in result['sub_controls'] if sc['effectiveness'] == 'Missing')} missing / "
            f"{sum(1 for sc in result['sub_controls'] if sc['effectiveness'] == 'Adequate')} adequate)"
        )
    except OSError as exc:
        print(f"assess_supply_chain_controls: write failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
