#!/usr/bin/env python3
"""publish_threat_model.py — pre-flight checks and .gitignore patching for
/appsec-advisor:publish-threat-model.

Exit codes:
  0  — all checks passed (or --check-only with no blockers)
  1  — blocker found (secrets detected, no threat-model.yaml, etc.)
  2  — bad arguments / missing required files
  3  — git operation failed
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Publishable files — tiers
# ---------------------------------------------------------------------------

# Always published when present
TIER1 = ["threat-model.md", "threat-model.yaml"]

# Published automatically when present (no flag needed)
TIER2 = ["threat-model.sarif.json", "threat-model.pdf", ".architect-review.md"]

# Never published — get explicit "never publish" exceptions in .gitignore
NEVER_PUBLISH = [
    "pentest-tasks.yaml",
    ".dep-scan.json",
    ".threat-modeling-context.md",
    ".recon-summary.md",
    ".triage-flags.json",
    ".threats-merged.json",
    ".stride-*.json",
]

# Patterns that suggest accidental secret exposure in the threat model
_SECRET_PATTERNS = [
    re.compile(r'(?i)(password|passwd|secret|api[_-]?key|token|bearer|private[_-]?key)\s*[=:]\s*\S{8,}'),
    re.compile(r'(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'(?i)(AWS|AZURE|GCP)_[A-Z_]{3,}\s*=\s*[A-Za-z0-9+/]{16,}'),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(cwd), check=check)


def _git_root(path: Path) -> Path | None:
    try:
        r = _run(["git", "rev-parse", "--show-toplevel"], cwd=path, check=False)
        if r.returncode == 0:
            return Path(r.stdout.strip())
    except FileNotFoundError:
        pass
    return None


def check_repo_visibility(repo_root: Path) -> tuple[bool, str]:
    """Returns (is_public, message). Non-fatal — warn only."""
    try:
        r = _run(["gh", "repo", "view", "--json", "isPrivate", "--jq", ".isPrivate"],
                 cwd=repo_root, check=False)
        if r.returncode == 0:
            is_private = r.stdout.strip().lower() == "true"
            if not is_private:
                return True, (
                    "⚠  This repository appears to be PUBLIC. Publishing a threat model\n"
                    "   to a public repo exposes vulnerability details to attackers.\n"
                    "   Proceed only if you have reviewed the report for sensitive content."
                )
            return False, ""
    except FileNotFoundError:
        pass
    return False, ""  # gh not available — skip silently


def scan_for_secrets(md_path: Path) -> list[str]:
    """Return list of warning lines if suspicious patterns found."""
    try:
        text = md_path.read_text(errors="replace")
    except OSError:
        return []
    hits = []
    for pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            snippet = m.group(0)[:60].replace("\n", " ")
            hits.append(f"   Possible secret near: {snippet!r}")
    return hits


def patch_gitignore(gitignore_path: Path, output_dir: Path, files_to_publish: list[Path]) -> bool:
    """Insert negation exceptions into .gitignore for published files.

    Idempotent — re-running adds no duplicates. Returns True when the file
    was modified, False when it was already up-to-date.
    """
    text = gitignore_path.read_text() if gitignore_path.exists() else ""

    # Collect names already negated (strip trailing comments like "# published …")
    existing_negations = set()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("!docs/security/") or stripped.startswith("! docs/security/"):
            # normalize: drop leading "!" and any trailing "  # …" comment
            base = stripped.lstrip("!").split("#")[0].strip()
            existing_negations.add(base)
            existing_negations.add(f"!{base}")

    new_lines: list[str] = []
    from datetime import date
    today = date.today().isoformat()

    for f in files_to_publish:
        rel = f"docs/security/{f.name}"
        if rel not in existing_negations:
            new_lines.append(f"!{rel}  # published {today}")

    # Never-publish explicit guards (add once, idempotent)
    never_marker = "# appsec-advisor: never-publish guards (do not remove)"
    if never_marker not in text:
        new_lines.append("")
        new_lines.append(never_marker)
        for name in NEVER_PUBLISH:
            rel = f"docs/security/{name}"
            new_lines.append(f"docs/security/{name}  # never publish")

    if not new_lines:
        return False

    # Insert after the "docs/security/" ignore line
    lines = text.splitlines()
    insert_idx = None
    for i, line in enumerate(lines):
        if line.strip() in ("docs/security/", "docs/security/**"):
            insert_idx = i + 1
            break

    if insert_idx is not None:
        lines[insert_idx:insert_idx] = new_lines
    else:
        lines += [""] + new_lines

    gitignore_path.write_text("\n".join(lines) + "\n")
    return True


def extract_commit_metadata(yaml_path: Path) -> dict:
    """Pull version + threat counts + top-2 finding titles from threat-model.yaml."""
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(yaml_path.read_text())
    except Exception:
        return {}

    meta = data.get("meta", {})
    version = meta.get("version", "")

    threats = data.get("threats", []) or []
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    top: list[str] = []
    for t in threats:
        sev = t.get("risk", t.get("severity", ""))
        if sev in counts:
            counts[sev] += 1
        if len(top) < 2 and sev in ("Critical", "High"):
            tid = t.get("t_id", "")
            title = t.get("title", "")
            if tid and title:
                top.append(f"{tid} {title[:60]}")

    return {"version": version, "counts": counts, "top": top, "total": len(threats)}


def build_commit_message(output_dir: Path, yaml_path: Path, published: list[Path]) -> str:
    meta = extract_commit_metadata(yaml_path)
    counts = meta.get("counts", {})
    total = meta.get("total", 0)
    version = meta.get("version", "")
    top = meta.get("top", [])

    ver_str = f" v{version}" if version else ""
    c = counts.get("Critical", 0)
    h = counts.get("High", 0)
    m = counts.get("Medium", 0)
    lo = counts.get("Low", 0)

    subject = f"security: publish threat model{ver_str} ({total} threats: {c} Critical, {h} High)"

    body_lines = [
        "",
        f"Components analyzed: see threat-model.yaml",
        f"Severity breakdown : Critical={c}, High={h}, Medium={m}, Low={lo}",
    ]
    if top:
        body_lines.append("Top findings       :")
        for t in top:
            body_lines.append(f"  - {t}")

    published_names = ", ".join(f.name for f in published)
    body_lines.append(f"Published files    : {published_names}")
    body_lines.append("")
    body_lines.append(
        "threat-model.yaml enables other repos to declare this service as a"
    )
    body_lines.append(
        "dependency via docs/related-repos.yaml for cross-repo STRIDE analysis."
    )

    return subject + "\n" + "\n".join(body_lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pre-flight checks and .gitignore patching for publishing a threat model."
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--check-only", action="store_true",
                        help="Run checks but do not modify .gitignore or commit")
    parser.add_argument("--commit", action="store_true",
                        help="Create a git commit after patching .gitignore")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Emit results as JSON (for skill consumption)")
    args = parser.parse_args()

    output_dir: Path = args.output_dir.resolve()
    repo_root: Path = args.repo_root.resolve()

    results: dict = {
        "blockers": [],
        "warnings": [],
        "files_to_publish": [],
        "gitignore_patched": False,
        "committed": False,
        "commit_message": "",
    }

    # --- Check threat-model.yaml exists (required for cross-repo consumption) ---
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.exists():
        results["blockers"].append(
            "threat-model.yaml not found — run /appsec-advisor:create-threat-model --yaml first"
        )

    md_path = output_dir / "threat-model.md"
    if not md_path.exists():
        results["blockers"].append("threat-model.md not found in output directory")

    if results["blockers"]:
        _print_results(results, args.json_out)
        return 1

    # --- Repo visibility check ---
    is_public, vis_msg = check_repo_visibility(repo_root)
    if vis_msg:
        results["warnings"].append(vis_msg)

    # --- Secret scan ---
    secret_hits = scan_for_secrets(md_path)
    if secret_hits:
        results["blockers"].append(
            "Possible secrets detected in threat-model.md:\n" + "\n".join(secret_hits) + "\n"
            "   Review and redact before publishing."
        )

    if results["blockers"]:
        _print_results(results, args.json_out)
        return 1

    # --- Determine files to publish ---
    files_to_publish: list[Path] = []
    for name in TIER1:
        p = output_dir / name
        if p.exists():
            files_to_publish.append(p)

    for name in TIER2:
        p = output_dir / name
        if p.exists():
            files_to_publish.append(p)

    results["files_to_publish"] = [str(f) for f in files_to_publish]

    if args.check_only:
        _print_results(results, args.json_out)
        return 0

    # --- Find .gitignore ---
    git_root = _git_root(output_dir) or repo_root
    gitignore_path = git_root / ".gitignore"

    # --- Patch .gitignore ---
    patched = patch_gitignore(gitignore_path, output_dir, files_to_publish)
    results["gitignore_patched"] = patched

    # --- Commit ---
    if args.commit:
        commit_msg = build_commit_message(output_dir, yaml_path, files_to_publish)
        results["commit_message"] = commit_msg
        try:
            stage_files = [str(gitignore_path)] + [str(f) for f in files_to_publish]
            _run(["git", "add"] + stage_files, cwd=git_root)
            _run(["git", "commit", "-m", commit_msg], cwd=git_root)
            results["committed"] = True
        except subprocess.CalledProcessError as e:
            results["blockers"].append(f"git commit failed: {e.stderr.strip()}")
            _print_results(results, args.json_out)
            return 3

    _print_results(results, args.json_out)
    return 0


def _print_results(results: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(results, indent=2))
        return

    if results["blockers"]:
        print("\n✗ Publish blocked:\n")
        for b in results["blockers"]:
            print(f"  {b}")
        print()
        return

    if results["warnings"]:
        for w in results["warnings"]:
            print(f"\n{w}")

    files = results["files_to_publish"]
    if files:
        print("\nFiles to publish:")
        for f in files:
            print(f"  {f}")

    if results["gitignore_patched"]:
        print("\n✓ .gitignore updated with negation exceptions")
    else:
        print("\n✓ .gitignore already up-to-date")

    if results["committed"]:
        print("✓ Committed to git")
        if results["commit_message"]:
            subject = results["commit_message"].splitlines()[0]
            print(f"  {subject}")
    print()


if __name__ == "__main__":
    sys.exit(main())
