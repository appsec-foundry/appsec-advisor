#!/usr/bin/env python3
"""Proposal 1 — emit SCA-practice control rows + MF-NNN findings.

Replaces the CVE-shaped dep_scan.py with three architectural-posture
indicators that converge on a single underlying property: patch
management maturity (sca.md §1.5).

What this emits, per repo:

  1. Three rows appended to `$OUTPUT_DIR/.security-controls.json` —
     under domain "Operations Runtime and Supply Chain Controls":
       • "Automated SCA scanning"        (Adequate | Partial | Missing)
       • "Automated dependency updates"  (Adequate | Partial | Missing)
       • "Lockfile hygiene"              (Adequate | Partial | Missing)

  2. For each row classified as `Missing` or `Partial`, a meta-finding
     row appended to `$OUTPUT_DIR/.sca-practice-findings.json`. The
     finalisation aggregator (build_threat_model_yaml.py) merges that
     sidecar into the rendered `meta_findings[]` block. MF-NNN ids are
     allocated dense by the aggregator across all sidecars — this script
     does NOT pre-allocate ids (avoids collisions with emit_meta_findings).

Inputs (all optional — degrades gracefully):
  --repo-root <path>       (required) repo under analysis
  --output-dir <path>      (required) where to write sidecars
  --asset-tier <Tier>      e.g. "Tier 1 — Restricted" / "T1" / "T2" / …
                            Default: T2 (conservative middle, per sca-practice-severity.yaml)

Detection is **passive** — walks CI workflow YAML, lockfiles, and
repo-config files. This script (and the plugin overall) **never runs
`npm audit` / `pip-audit` / `govulncheck` / `snyk` / any package-manager
or vulnerability-database tool**. Per-CVE reporting is intentionally
out of scope — users should run a dedicated SCA tool (Snyk / Trivy /
Dependabot / OSV-Scanner / language-native audit) in their CI; the
plugin only surfaces the **architectural-posture** signal.

A peer emitter (`emit_dep_update_activity.py`) consults `git log` over a
90-day window for dep-update commits. When that sidecar reports `active`
cadence we lift the "Automated dependency updates" rating even without
Dependabot / Renovate config files in the repo — that covers Renovate
hosted-app mode, Dependabot security-updates (repo-settings only), and
teams that patch manually but on a disciplined cadence.

This script is idempotent — re-running rewrites the SCA rows and the
sidecar list. Hand-authored rows (any non-SCA-practice control) are
preserved verbatim in .security-controls.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DOMAIN = "Operations Runtime and Supply Chain Controls"

CONTROL_SCANNING = "Automated SCA scanning"
CONTROL_UPDATES = "Automated dependency updates"
CONTROL_LOCKFILE = "Lockfile hygiene"

SCA_CONTROLS = (CONTROL_SCANNING, CONTROL_UPDATES, CONTROL_LOCKFILE)

# Detection signatures.

# Tools that count as "blocking" SCA when found in CI workflow YAML.
# Conservative — only well-known dedicated tools and language-native
# audit commands. A repo using a homegrown shell script is not credited.
_SCA_TOOL_TOKENS = (
    r"\bsnyk\s+test\b",
    r"\bsnyk\s+monitor\b",
    r"\btrivy\s+fs\b",
    r"\btrivy\s+repo\b",
    r"\bgrype\b",
    r"\bosv-scanner\b",
    r"\bdependency-check\b",
    r"\bnpm\s+audit\b",
    r"\bpip-audit\b",
    r"\bcargo\s+audit\b",
    r"\bbundle\s+audit\b",
    r"\bcomposer\s+audit\b",
    r"\bdotnet\s+list\s+package\s+--vulnerable\b",
    r"\bgovulncheck\b",
    r"\bmend\b|\bwhitesource\b",
    r"\bgithub/codeql-action\b",  # CodeQL covers SCA via dep-graph too
)
_SCA_TOOL_RE = re.compile("|".join(_SCA_TOOL_TOKENS), re.IGNORECASE)

_CI_FILE_GLOBS = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "bitbucket-pipelines.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
)

# Dependabot v2 (the only supported variant — v1 EOL in 2021).
_DEPENDABOT_PATH = ".github/dependabot.yml"

# Renovate config locations — file-mode only. Self-hosted-app mode is
# not detectable from the repo and produces a false-negative.
_RENOVATE_PATHS = (
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.json5",
    ".github/renovate.json",
    ".github/renovate.json5",
)

# Lockfiles per ecosystem. A repo can have multiple.
_LOCKFILE_PATTERNS = {
    "npm": ("package-lock.json", "npm-shrinkwrap.json"),
    "yarn": ("yarn.lock",),
    "pnpm": ("pnpm-lock.yaml",),
    "pip": ("Pipfile.lock", "poetry.lock", "uv.lock", "requirements.lock"),
    "go": ("go.sum",),
    "gem": ("Gemfile.lock",),
    "composer": ("composer.lock",),
    "cargo": ("Cargo.lock",),
}

# Manifest files that imply a lockfile should exist for the ecosystem.
_MANIFEST_TO_ECOSYSTEM = {
    "package.json": "npm",  # or yarn/pnpm — any of the three is fine
    "requirements.txt": "pip",
    "Pipfile": "pip",
    "pyproject.toml": "pip",
    "go.mod": "go",
    "Gemfile": "gem",
    "composer.json": "composer",
    "Cargo.toml": "cargo",
}

# Asset-tier normalization.
_TIER_RE = re.compile(r"\bT(?:ier\s*)?([1-4])\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Asset-tier resolution
# ---------------------------------------------------------------------------


def _normalize_tier(raw: str | None) -> str:
    """Normalize 'Tier 1 — Restricted' / 'T1' / 'tier-1' → 'T1'.

    Default to T2 (conservative middle) when unparseable.
    """
    if not raw:
        return "T2"
    m = _TIER_RE.search(raw)
    if not m:
        return "T2"
    return f"T{m.group(1)}"


# ---------------------------------------------------------------------------
# Detection — fully deterministic, file-system driven
# ---------------------------------------------------------------------------


def _read_ci_files(repo_root: Path) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    for glob in _CI_FILE_GLOBS:
        for path in repo_root.glob(glob):
            if not path.is_file():
                continue
            try:
                out.append((path, path.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
    return out


def classify_sca_scanning(repo_root: Path) -> tuple[str, list[str]]:
    """Return (Adequate|Partial|Missing, evidence_file_lines)."""
    ci_files = _read_ci_files(repo_root)
    if not ci_files:
        return "Missing", []
    hits: list[str] = []
    for path, text in ci_files:
        for i, line in enumerate(text.splitlines(), start=1):
            if _SCA_TOOL_RE.search(line):
                rel = str(path.relative_to(repo_root)) if path.is_relative_to(repo_root) else str(path)
                hits.append(f"{rel}:{i}")
                break
    if not hits:
        return "Missing", []
    # Partial vs Adequate: heuristic — if the repo has manifests for N
    # ecosystems and SCA appears in fewer CI files than ecosystems, mark
    # partial. Otherwise adequate.
    ecosystems = _detect_ecosystems(repo_root)
    if len(hits) >= max(1, len(ecosystems)):
        return "Adequate", hits
    return "Partial", hits


def _load_activity_sidecar(output_dir: Path) -> dict:
    """Load .dep-update-activity.json when present. Graceful degradation
    — emit_dep_update_activity.py is a peer emitter and may not have been
    run yet (e.g. in a degraded run); we treat its absence as 'unknown
    cadence' rather than failing."""
    path = output_dir / ".dep-update-activity.json"
    if not path.is_file():
        return {"cadence": "unknown"}
    try:
        return json.loads(path.read_text(encoding="utf-8")) or {"cadence": "unknown"}
    except (json.JSONDecodeError, OSError):
        return {"cadence": "unknown"}


def classify_auto_updates(repo_root: Path, output_dir: Path) -> tuple[str, list[str]]:
    evidence: list[str] = []
    has_dependabot = (repo_root / _DEPENDABOT_PATH).is_file()
    if has_dependabot:
        evidence.append(_DEPENDABOT_PATH + ":1")
    has_renovate = any((repo_root / p).is_file() for p in _RENOVATE_PATHS)
    if has_renovate:
        for p in _RENOVATE_PATHS:
            if (repo_root / p).is_file():
                evidence.append(p + ":1")
                break

    # Activity sidecar — when emit_dep_update_activity.py ran first, lift
    # the rating out of Missing for repos that patch on a regular cadence
    # even without Dependabot / Renovate config files. Covers (a) Renovate
    # hosted-app mode (no config file in repo), (b) Dependabot
    # security-updates (configured at repo settings, no file), (c) teams
    # with manual but disciplined update PRs.
    activity = _load_activity_sidecar(output_dir)
    cadence = activity.get("cadence", "unknown")
    if activity.get("dep_update_commits"):
        evidence.append(
            f"git-log: {activity['dep_update_commits']} dep-update commit(s) in "
            f"last {activity.get('window_days', 90)} days "
            f"(cadence={cadence})"
        )

    if not has_dependabot and not has_renovate:
        # No config file — fall back to the activity signal.
        if cadence == "active":
            return "Partial", evidence  # patching happens but not automated by config
        return "Missing", []

    # Config file present. Partial: only one of {Dependabot, Renovate}
    # present AND multiple ecosystems detected. The single-tool case is
    # fine for single-eco repos.
    ecosystems = _detect_ecosystems(repo_root)
    if len(ecosystems) > 1 and not (has_dependabot and has_renovate):
        if has_dependabot:
            try:
                cfg = yaml.safe_load((repo_root / _DEPENDABOT_PATH).read_text(encoding="utf-8", errors="replace"))
                covered = {u.get("package-ecosystem") for u in (cfg or {}).get("updates", []) if isinstance(u, dict)}
                eco_alias = {
                    "npm": {"npm", "yarn", "pnpm"},
                    "pip": {"pip"},
                    "gomod": {"go"},
                    "bundler": {"gem"},
                    "composer": {"composer"},
                    "cargo": {"cargo"},
                    "maven": {"maven"},
                    "gradle": {"maven"},
                    "nuget": {"nuget"},
                }
                covered_norm: set[str] = set()
                for c in covered:
                    if c in eco_alias:
                        covered_norm |= eco_alias[c]
                    elif c:
                        covered_norm.add(c)
                if not ecosystems.issubset(covered_norm):
                    return "Partial", evidence
            except (yaml.YAMLError, OSError):
                pass
    return "Adequate", evidence


def classify_lockfile_hygiene(repo_root: Path) -> tuple[str, list[str]]:
    ecosystems = _detect_ecosystems(repo_root)
    if not ecosystems:
        # No package manifests detected → not applicable, treat as Adequate
        # (no lockfile expected, no gap to report).
        return "Adequate", []
    evidence: list[str] = []
    missing: list[str] = []
    for eco in ecosystems:
        # Find any acceptable lockfile for this ecosystem.
        candidates = []
        if eco == "npm":
            candidates = (
                list(_LOCKFILE_PATTERNS["npm"]) + list(_LOCKFILE_PATTERNS["yarn"]) + list(_LOCKFILE_PATTERNS["pnpm"])
            )
        elif eco in _LOCKFILE_PATTERNS:
            candidates = list(_LOCKFILE_PATTERNS[eco])
        found = False
        for name in candidates:
            for p in repo_root.rglob(name):
                if not p.is_file():
                    continue
                if any(part in {"node_modules", ".venv", "venv", "vendor", ".git"} for part in p.parts):
                    continue
                rel = str(p.relative_to(repo_root)) if p.is_relative_to(repo_root) else str(p)
                evidence.append(f"{rel}:1")
                found = True
                break
            if found:
                break
        if not found:
            missing.append(eco)
    if not missing:
        return "Adequate", evidence
    if len(missing) == len(ecosystems):
        return "Missing", []
    return "Partial", evidence


def _detect_ecosystems(repo_root: Path) -> set[str]:
    out: set[str] = set()
    for manifest_name, eco in _MANIFEST_TO_ECOSYSTEM.items():
        for p in repo_root.rglob(manifest_name):
            if not p.is_file():
                continue
            if any(
                part in {"node_modules", ".venv", "venv", "vendor", ".git", "target", "build", "dist"}
                for part in p.parts
            ):
                continue
            out.add(eco)
            break
    return out


# ---------------------------------------------------------------------------
# Sidecar writers
# ---------------------------------------------------------------------------


def _load_existing_security_controls(path: Path) -> dict:
    if not path.is_file():
        return {"schema_version": 1, "security_controls": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"schema_version": 1, "security_controls": []}
        data.setdefault("schema_version", 1)
        data.setdefault("security_controls", [])
        return data
    except (json.JSONDecodeError, OSError):
        return {"schema_version": 1, "security_controls": []}


def _upsert_sca_rows(controls: list[dict], rows: list[dict]) -> list[dict]:
    """Replace any existing rows in the SCA-practice triple, append new ones."""
    kept = [
        c
        for c in controls
        if not (isinstance(c, dict) and c.get("domain") == DOMAIN and c.get("control") in SCA_CONTROLS)
    ]
    return kept + rows


def _load_severity_policy(plugin_root: Path) -> dict:
    path = plugin_root / "data" / "sca-practice-severity.yaml"
    if not path.is_file():
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return {}


def _severity_for(policy: dict, control: str, tier: str, effectiveness: str) -> str:
    if effectiveness == "Missing":
        block = (policy or {}).get("missing_severity", {})
    elif effectiveness == "Partial":
        block = (policy or {}).get("partial_severity", {})
    else:
        return "Informational"
    by_tier = block.get(control, {}) if isinstance(block, dict) else {}
    return by_tier.get(tier) or by_tier.get(policy.get("default_tier", "T2"), "Medium")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run(repo_root: Path, output_dir: Path, asset_tier_raw: str | None, plugin_root: Path) -> int:
    tier = _normalize_tier(asset_tier_raw)
    policy = _load_severity_policy(plugin_root)

    scanning_eff, scanning_ev = classify_sca_scanning(repo_root)
    updates_eff, updates_ev = classify_auto_updates(repo_root, output_dir)
    lockfile_eff, lockfile_ev = classify_lockfile_hygiene(repo_root)

    rows = [
        {
            "domain": DOMAIN,
            "control": CONTROL_SCANNING,
            "effectiveness": scanning_eff,
            "kind": "lifecycle",
            "assessment": _assessment_text(CONTROL_SCANNING, scanning_eff, scanning_ev),
            "linked_threats": [],
        },
        {
            "domain": DOMAIN,
            "control": CONTROL_UPDATES,
            "effectiveness": updates_eff,
            "kind": "lifecycle",
            "assessment": _assessment_text(CONTROL_UPDATES, updates_eff, updates_ev),
            "linked_threats": [],
        },
        {
            "domain": DOMAIN,
            "control": CONTROL_LOCKFILE,
            "effectiveness": lockfile_eff,
            "kind": "lifecycle",
            "assessment": _assessment_text(CONTROL_LOCKFILE, lockfile_eff, lockfile_ev),
            "linked_threats": [],
        },
    ]

    # Persist to .security-controls.json sidecar.
    sc_path = output_dir / ".security-controls.json"
    sc_data = _load_existing_security_controls(sc_path)
    sc_data["security_controls"] = _upsert_sca_rows(sc_data.get("security_controls", []), rows)
    sc_path.write_text(json.dumps(sc_data, indent=2, sort_keys=False), encoding="utf-8")

    # Persist meta-finding rows to .sca-practice-findings.json. The
    # build_threat_model_yaml.py aggregator picks these up and merges
    # them into meta_findings[] with deterministic MF-NNN allocation.
    findings: list[dict] = []
    for row, evidence_files in (
        (rows[0], scanning_ev),
        (rows[1], updates_ev),
        (rows[2], lockfile_ev),
    ):
        if row["effectiveness"] in {"Missing", "Partial"}:
            severity = _severity_for(policy, row["control"], tier, row["effectiveness"])
            findings.append(
                {
                    "title": f"{row['control']}: {row['effectiveness'].lower()}",
                    "category": "Insufficient Patch Management",
                    "summary": _missing_finding_summary(row["control"], row["effectiveness"], tier),
                    "evidence": [
                        {"file": e.split(":", 1)[0], "line": int(e.split(":", 1)[1]) if ":" in e else 1}
                        for e in (evidence_files or [])
                    ],
                    "severity": severity,
                    "control": row["control"],
                    "effectiveness": row["effectiveness"],
                    "source": "sca-practice",  # so the aggregator can MF-id it
                    "derived_from": [],  # no T-NNN linkage; this is process-level
                    "asset_tier": tier,
                }
            )

    findings_path = output_dir / ".sca-practice-findings.json"
    findings_path.write_text(
        json.dumps({"schema_version": 1, "findings": findings}, indent=2, sort_keys=False),
        encoding="utf-8",
    )

    print(
        f"emit_sca_practice: tier={tier} "
        f"scanning={scanning_eff} updates={updates_eff} lockfile={lockfile_eff} "
        f"→ {len(findings)} sca-practice finding(s)"
    )
    return 0


def _assessment_text(control: str, effectiveness: str, evidence: list[str]) -> str:
    if effectiveness == "Adequate":
        if evidence:
            return f"{control} present: " + ", ".join(evidence[:3])
        return f"{control} present (no specific evidence captured)"
    if effectiveness == "Partial":
        return (
            f"{control} present but coverage is partial. "
            f"Evidence: {', '.join(evidence[:3]) if evidence else 'none on disk'}. "
            "Expand to all detected ecosystems before treating this control as adequate."
        )
    return (
        f"{control} not detected in the repository. "
        "Patch-management posture depends on this control being in place — the "
        "team is reactive rather than proactive without it."
    )


def _missing_finding_summary(control: str, effectiveness: str, tier: str) -> str:
    state = "missing" if effectiveness == "Missing" else "partial"
    return (
        f"Asset tier {tier}: {control} is {state}. The architectural concern is "
        "patch-management maturity — without this signal the team relies on "
        "ad-hoc upgrades after the fact. Address by introducing the control "
        "at the platform level (CI workflow, repo config, or org policy), "
        "not by reacting to individual CVE advisories."
    )


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Emit SCA-practice control rows + MF findings")
    p.add_argument("--repo-root", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument(
        "--asset-tier", default=None, help='Raw asset-tier string (e.g. "Tier 1 — Restricted" / "T2"). Default: T2.'
    )
    p.add_argument("--plugin-root", default=None, type=Path, help="Override plugin root for severity-policy lookup")
    args = p.parse_args(argv)

    plugin_root = args.plugin_root or Path(__file__).resolve().parent.parent
    if not args.repo_root.is_dir():
        print(f"emit_sca_practice: repo-root not a directory: {args.repo_root}", file=sys.stderr)
        return 2
    if not args.output_dir.is_dir():
        print(f"emit_sca_practice: output-dir not a directory: {args.output_dir}", file=sys.stderr)
        return 2

    return run(args.repo_root, args.output_dir, args.asset_tier, plugin_root)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
