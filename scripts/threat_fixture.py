#!/usr/bin/env python3
"""threat_fixture.py — freeze a completed threat-model run into a reusable,
git-diffable golden-master fixture, and replay it to detect the effect of
deterministic-pipeline code changes across repos — without re-scanning.

Two subcommands:

  freeze   Take a completed assessment OUTPUT_DIR (a real run) and produce a
           curated fixture package: the pre-tail input sidecars, canonical
           golden outputs (threat-model.yaml/.md/.sarif.json) rebuilt with the
           CURRENT code, optional scanner goldens, a pinned source-repo SHA,
           and a sha256 MANIFEST. The golden is "what today's code emits", so a
           later replay diff IS the effect of a code change.

  replay   Re-run the deterministic tail (and optionally the source scanners)
           from a frozen fixture, normalise volatile fields, and diff the
           result against the stored golden. Zero diff == no behavioural drift.

Why a *whole curated bundle* and not just the report: regression-testing a code
change needs the producer's INPUTS (sidecars + .fragments/) to re-run, plus the
golden OUTPUTS to diff against. A report-only snapshot cannot be replayed.

Volatile fields scrubbed before every comparison (verified against
build_threat_model_yaml.py): meta.generated (datetime.now), meta.git.* (read
from the scanned repo's git), and changelog[].date / current_sha / previous_date
(date.today / repo HEAD). Everything downstream (compose, export_sarif) inherits
its determinism from the scrubbed yaml, so it needs no separate scrubbing.

Storage: the canonical form is the UNPACKED directory (git diffs it, reviews it,
delta-compresses it). `--archive` additionally emits a reproducible .tgz for
hand-off; it is never the source of truth.

This is a manual developer/test tool. It is NOT part of the scanned-repo
pipeline and grants the skill no new permissions.
"""

from __future__ import annotations

import argparse
import difflib
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

import yaml

# --- constants -------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = _SCRIPT_DIR.parent

SENTINEL_TS = "2000-01-01T00:00:00Z"
SENTINEL_DATE = "2000-01-01"
SENTINEL_SHA = "0" * 40

# Fixed work-dir parent name. compose's last-resort project-name fallback is
# `output_dir.parent.name` (compose_threat_model.py); building under a stable
# parent makes that fallback deterministic across freeze and replay instead of
# leaking the random TemporaryDirectory name. Real project names (yaml /
# package.json) still win over the fallback, so this only neutralises the leak.
_WORK_PARENT = "threat-fixture-work"

# Placeholder repo-root name used when no source repo is given. build_yaml's
# project fallback is `repo_root.name` (meta.project), so freeze and replay must
# use the SAME name or that field drifts. (A real --repo basename is naturally
# stable across both, so it needs no placeholder.)
_NO_REPO_NAME = "no-repo"

# Volatile keys emitted by scanners (e.g. route_inventory.py): a wall-clock
# stamp and the absolute repo path. Scrubbed before comparison.
_SCANNER_VOLATILE_TS = ("generated_at", "scanned_at", "timestamp")
_SCANNER_VOLATILE_PATH = ("repo_root",)

# The final report artifacts. They are rebuilt as golden, never copied into
# inputs/ — keeping a prior threat-model.yaml in inputs/ would make
# build_threat_model_yaml carry its changelog forward (non-deterministic).
OUTPUT_FILES = (
    "threat-model.yaml",
    "threat-model.md",
    "threat-model.sarif.json",
    "threat-model.pdf",
    "pentest-tasks.yaml",
    "analysis-model.md",
)

# Runtime telemetry / logs / volatile caches — excluded from inputs/. The
# freeze step rebuilds the tail from what remains and fails loudly if it
# dropped something a producer actually reads, so this list is allowed to be
# aggressive without risking a silently-broken fixture.
NOISE_EXACT = {
    ".appsec-progress.json",
    ".appsec-checkpoint",
    ".skill-watchdog.tick",
    ".phase-epoch",
    ".scan-start-epoch",
    ".scan-wall-seconds",
    ".stage-stats.jsonl",
    ".compose-stats.json",
    ".session-agent-map",
    ".assessment-summary-emitted",
    ".assessment-owner-sid",
    ".stage1-resume-count",
}
NOISE_DIRS = {".appsec-cache", "docs", ".dispatch-context"}
NOISE_SUFFIXES = (".log", ".tick", ".tmp")


def _is_noise_top(name: str) -> bool:
    """Classify a top-level entry name in the run dir as droppable noise."""
    if name in OUTPUT_FILES:
        return True
    if name in NOISE_EXACT or name in NOISE_DIRS:
        return True
    if name.endswith(NOISE_SUFFIXES):
        return True
    # rotated logs: .agent-run.log.1 etc.
    if ".log." in name:
        return True
    if name.endswith("-start") and name.startswith(".stage"):
        return True
    return False


# Maps a scanner's output sidecar to the script that produces it. Both follow
# the `--repo-root <repo> --output-dir <dir>` convention.
SCANNER_REGISTRY = {
    ".route-inventory.json": "route_inventory.py",
    ".source-auth-findings.json": "source_auth_scanner.py",
}


# --- normalisation ---------------------------------------------------------


def scrub_yaml_obj(obj: dict[str, Any]) -> dict[str, Any]:
    """Replace time/git-derived fields with stable sentinels, in place."""
    meta = obj.get("meta")
    if isinstance(meta, dict):
        if "generated" in meta:
            meta["generated"] = SENTINEL_TS
        git = meta.get("git")
        if isinstance(git, dict):
            if "commit_sha" in git:
                git["commit_sha"] = SENTINEL_SHA
            if "branch" in git:
                git["branch"] = "main"
            if "remote_url" in git:
                git["remote_url"] = ""
    changelog = obj.get("changelog")
    if isinstance(changelog, list):
        for entry in changelog:
            if not isinstance(entry, dict):
                continue
            if "date" in entry:
                entry["date"] = SENTINEL_DATE
            if entry.get("previous_date"):
                entry["previous_date"] = SENTINEL_DATE
            if "current_sha" in entry:
                entry["current_sha"] = SENTINEL_SHA
    return obj


def canonical_yaml(obj: Any) -> str:
    """Deterministic YAML serialisation used for both golden and replay."""
    return yaml.safe_dump(
        obj,
        sort_keys=True,
        allow_unicode=True,
        default_flow_style=False,
        width=1000,
    )


def normalize_yaml_text(text: str) -> str:
    """Load → scrub volatile fields → canonical re-dump."""
    return canonical_yaml(scrub_yaml_obj(yaml.safe_load(text)))


def canonical_json(text_or_obj: Any) -> str:
    obj = json.loads(text_or_obj) if isinstance(text_or_obj, str) else text_or_obj
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def canonical_scanner_json(text_or_obj: Any) -> str:
    """Canonical JSON with scanner wall-clock / path fields scrubbed."""
    obj = json.loads(text_or_obj) if isinstance(text_or_obj, str) else text_or_obj
    if isinstance(obj, dict):
        for k in _SCANNER_VOLATILE_TS:
            if k in obj:
                obj[k] = SENTINEL_TS
        for k in _SCANNER_VOLATILE_PATH:
            if k in obj:
                obj[k] = ""
    return canonical_json(obj)


def _work_path(td: str) -> Path:
    """A work dir under a stable parent name (see _WORK_PARENT)."""
    parent = Path(td) / _WORK_PARENT
    parent.mkdir(exist_ok=True)
    return parent / "assessment"


def _no_repo_root(td: str) -> Path:
    """Stable placeholder repo-root for the no-source-repo case."""
    d = Path(td) / _NO_REPO_NAME
    d.mkdir(exist_ok=True)
    return d


# --- integrity -------------------------------------------------------------


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _iter_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file())


def write_manifest(fixture_dir: Path) -> dict[str, str]:
    """sha256 every file under fixture_dir (except the manifest itself)."""
    manifest_path = fixture_dir / "MANIFEST.json"
    entries: dict[str, str] = {}
    for p in _iter_files(fixture_dir):
        if p == manifest_path:
            continue
        entries[p.relative_to(fixture_dir).as_posix()] = _sha256(p)
    manifest_path.write_text(
        json.dumps({"files": entries}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return entries


def verify_manifest(fixture_dir: Path) -> list[str]:
    """Return a list of human-readable integrity problems (empty == clean)."""
    manifest_path = fixture_dir / "MANIFEST.json"
    if not manifest_path.is_file():
        return ["MANIFEST.json missing"]
    recorded: dict[str, str] = json.loads(manifest_path.read_text())["files"]
    problems: list[str] = []
    present = {p.relative_to(fixture_dir).as_posix() for p in _iter_files(fixture_dir) if p != manifest_path}
    for rel, digest in recorded.items():
        fp = fixture_dir / rel
        if not fp.is_file():
            problems.append(f"missing: {rel}")
        elif _sha256(fp) != digest:
            problems.append(f"changed: {rel}")
    for rel in sorted(present - set(recorded)):
        problems.append(f"untracked: {rel}")
    return problems


# --- subprocess tail -------------------------------------------------------


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=PLUGIN_ROOT, capture_output=True, text=True)


def _build_yaml(work: Path, repo_root: Path) -> None:
    cp = _run(
        [
            "python3",
            str(_SCRIPT_DIR / "build_threat_model_yaml.py"),
            str(work),
            "--repo-root",
            str(repo_root),
            "--plugin-root",
            str(PLUGIN_ROOT),
        ]
    )
    if cp.returncode != 0:
        raise RuntimeError(f"build_threat_model_yaml failed:\n{cp.stderr}")


def _compose(work: Path) -> None:
    cp = _run(
        [
            "python3",
            str(_SCRIPT_DIR / "compose_threat_model.py"),
            "--output-dir",
            str(work),
            "--strict",
        ]
    )
    if cp.returncode != 0:
        raise RuntimeError(f"compose_threat_model failed:\n{cp.stdout}\n{cp.stderr}")


def _export_sarif(yaml_path: Path, out_path: Path) -> None:
    cp = _run(
        [
            "python3",
            str(_SCRIPT_DIR / "export_sarif.py"),
            "--threat-model",
            str(yaml_path),
            "--output",
            str(out_path),
        ]
    )
    if cp.returncode != 0:
        raise RuntimeError(f"export_sarif failed:\n{cp.stderr}")


def _run_scanner(script: str, repo_root: Path, work: Path) -> None:
    cp = _run(
        [
            "python3",
            str(_SCRIPT_DIR / script),
            "--repo-root",
            str(repo_root),
            "--output-dir",
            str(work),
        ]
    )
    if cp.returncode != 0:
        raise RuntimeError(f"{script} failed:\n{cp.stderr}")


# --- git pin ---------------------------------------------------------------


def _git(args: list[str], repo: Path) -> str | None:
    cp = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    return cp.stdout.strip() if cp.returncode == 0 else None


def _pin_repo(repo: Path) -> dict[str, Any]:
    return {
        "repo_path": str(repo),
        "commit_sha": _git(["rev-parse", "HEAD"], repo) or "unknown",
        "branch": _git(["rev-parse", "--abbrev-ref", "HEAD"], repo) or "unknown",
        "dirty": bool(_git(["status", "--porcelain"], repo)),
    }


# --- freeze ----------------------------------------------------------------


def freeze(run_dir: Path, into: Path, repo: Path | None, archive: bool) -> Path:
    run_dir = run_dir.resolve()
    into = into.resolve()
    if not (run_dir / "threat-model.yaml").is_file():
        raise SystemExit(f"Error: {run_dir} has no threat-model.yaml — not a completed run.")
    if into.exists():
        raise SystemExit(f"Error: fixture dir already exists: {into}")

    inputs = into / "inputs"
    golden = into / "golden"
    inputs.mkdir(parents=True)
    golden.mkdir(parents=True)

    # 1. copy non-noise, non-output inputs
    for entry in sorted(run_dir.iterdir()):
        if _is_noise_top(entry.name):
            continue
        dest = inputs / entry.name
        if entry.is_dir():
            shutil.copytree(entry, dest)
        else:
            shutil.copy2(entry, dest)

    # 2. rebuild canonical golden tail in a throwaway work dir
    with tempfile.TemporaryDirectory() as td:
        work = _work_path(td)
        shutil.copytree(inputs, work)
        repo_root = repo.resolve() if repo else _no_repo_root(td)
        _build_yaml(work, repo_root)
        # scrub the yaml *before* compose so the md inherits the sentinels
        norm = normalize_yaml_text((work / "threat-model.yaml").read_text())
        (work / "threat-model.yaml").write_text(norm, encoding="utf-8")
        _compose(work)
        _export_sarif(work / "threat-model.yaml", work / "threat-model.sarif.json")

        (golden / "threat-model.yaml").write_text(norm, encoding="utf-8")
        (golden / "threat-model.md").write_text((work / "threat-model.md").read_text(), encoding="utf-8")
        (golden / "threat-model.sarif.json").write_text(
            canonical_json((work / "threat-model.sarif.json").read_text()),
            encoding="utf-8",
        )

    # 3. scanner goldens (re-run the producer against the pinned repo)
    scanners: dict[str, str] = {}
    if repo:
        scanner_golden = into / "scanner-golden"
        for sidecar, script in SCANNER_REGISTRY.items():
            if not (run_dir / sidecar).is_file():
                continue
            with tempfile.TemporaryDirectory() as td:
                work = Path(td)
                _run_scanner(script, repo.resolve(), work)
                produced = work / sidecar
                if not produced.is_file():
                    continue
                scanner_golden.mkdir(exist_ok=True)
                (scanner_golden / sidecar).write_text(canonical_scanner_json(produced.read_text()), encoding="utf-8")
                scanners[sidecar] = script

    # 4. metadata + integrity
    depth = "unknown"
    try:
        cfg = json.loads((inputs / ".skill-config.json").read_text())
        depth = cfg.get("assessment_depth", "unknown")
    except (OSError, ValueError):
        pass
    meta = {
        "fixture_version": 1,
        "assessment_depth": depth,
        "plugin_version": json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text()).get("version"),
        "repo": _pin_repo(repo) if repo else None,
        "scanners": scanners,
        "sentinels": {
            "generated": SENTINEL_TS,
            "date": SENTINEL_DATE,
            "sha": SENTINEL_SHA,
        },
    }
    (into / "expected-meta.json").write_text(json.dumps(meta, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    write_manifest(into)

    if archive:
        make_archive(into)
    return into


def make_archive(fixture_dir: Path) -> Path:
    """Reproducible .tgz (sorted entries, mtime=0, root-owned) for hand-off
    only — the unpacked directory stays the source of truth."""
    tgz = fixture_dir.with_suffix(".tgz")

    def _reset(ti: tarfile.TarInfo) -> tarfile.TarInfo:
        ti.mtime = 0
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        return ti

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        base = fixture_dir.name
        for p in _iter_files(fixture_dir):
            tar.add(p, arcname=f"{base}/{p.relative_to(fixture_dir).as_posix()}", filter=_reset)
    with open(tgz, "wb") as out, gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(buf.getvalue())
    return tgz


# --- replay ----------------------------------------------------------------


def _diff(name: str, golden: str, actual: str) -> list[str]:
    if golden == actual:
        return []
    return list(
        difflib.unified_diff(
            golden.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=f"golden/{name}",
            tofile=f"replay/{name}",
        )
    )


def replay(fixture: Path, stages: list[str], repo: Path | None) -> dict[str, Any]:
    fixture = fixture.resolve()
    inputs = fixture / "inputs"
    golden = fixture / "golden"
    if not golden.is_dir():
        raise SystemExit(f"Error: not a fixture (no golden/): {fixture}")

    meta = json.loads((fixture / "expected-meta.json").read_text())
    results: dict[str, Any] = {"integrity": verify_manifest(fixture), "stages": {}}

    if "yaml" in stages:
        with tempfile.TemporaryDirectory() as td:
            work = _work_path(td)
            shutil.copytree(inputs, work)
            for out in OUTPUT_FILES:  # ensure no prior output leaks in
                (work / out).unlink(missing_ok=True)
            repo_root = repo.resolve() if repo else _no_repo_root(td)
            _build_yaml(work, repo_root)
            produced = normalize_yaml_text((work / "threat-model.yaml").read_text())
            results["stages"]["yaml"] = _diff(
                "threat-model.yaml",
                (golden / "threat-model.yaml").read_text(),
                produced,
            )

    if "md" in stages:
        with tempfile.TemporaryDirectory() as td:
            work = _work_path(td)
            work.mkdir(parents=True)
            if (inputs / ".fragments").is_dir():
                shutil.copytree(inputs / ".fragments", work / ".fragments")
            # carry any other sidecars compose may reference
            for entry in inputs.iterdir():
                if entry.name == ".fragments":
                    continue
                target = work / entry.name
                if entry.is_dir():
                    shutil.copytree(entry, target)
                else:
                    shutil.copy2(entry, target)
            shutil.copy2(golden / "threat-model.yaml", work / "threat-model.yaml")
            _compose(work)
            results["stages"]["md"] = _diff(
                "threat-model.md",
                (golden / "threat-model.md").read_text(),
                (work / "threat-model.md").read_text(),
            )

    if "sarif" in stages:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "s.json"
            _export_sarif(golden / "threat-model.yaml", out)
            results["stages"]["sarif"] = _diff(
                "threat-model.sarif.json",
                (golden / "threat-model.sarif.json").read_text(),
                canonical_json(out.read_text()),
            )

    if "scanner" in stages and meta.get("scanners"):
        scanner_golden = fixture / "scanner-golden"
        repo_path = repo or (Path(meta["repo"]["repo_path"]) if meta.get("repo") else None)
        if not repo_path or not Path(repo_path).is_dir():
            results["stages"]["scanner"] = ["SKIPPED: source repo unavailable"]
        else:
            diffs: list[str] = []
            for sidecar, script in meta["scanners"].items():
                with tempfile.TemporaryDirectory() as td:
                    work = Path(td)
                    _run_scanner(script, Path(repo_path).resolve(), work)
                    produced = canonical_scanner_json((work / sidecar).read_text())
                    diffs += _diff(sidecar, (scanner_golden / sidecar).read_text(), produced)
            results["stages"]["scanner"] = diffs

    return results


def _resolve_stages(arg: str, fixture: Path) -> list[str]:
    if arg == "all":
        stages = ["yaml", "md", "sarif"]
        meta = json.loads((fixture / "expected-meta.json").read_text())
        if meta.get("scanners"):
            stages.append("scanner")
        return stages
    return [s.strip() for s in arg.split(",") if s.strip()]


# --- CLI -------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="threat_fixture.py", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("freeze", help="Snapshot a completed run into a fixture.")
    f.add_argument("--run", type=Path, required=True, help="Completed OUTPUT_DIR.")
    f.add_argument("--into", type=Path, required=True, help="New fixture dir.")
    f.add_argument("--repo", type=Path, default=None, help="Scanned source repo (enables scanner goldens + SHA pin).")
    f.add_argument("--archive", action="store_true", help="Also emit a reproducible .tgz next to the fixture.")

    r = sub.add_parser("replay", help="Re-run the tail and diff against golden.")
    r.add_argument("--fixture", type=Path, required=True)
    r.add_argument("--stage", default="all", help="Comma list of yaml,md,sarif,scanner or 'all'.")
    r.add_argument("--repo", type=Path, default=None, help="Override source repo for the scanner stage.")

    ns = ap.parse_args(argv)

    if ns.cmd == "freeze":
        out = freeze(ns.run, ns.into, ns.repo, ns.archive)
        print(f"✓ froze fixture → {out}")
        return 0

    res = replay(ns.fixture, _resolve_stages(ns.stage, ns.fixture), ns.repo)
    failed = False
    for problem in res["integrity"]:
        print(f"INTEGRITY: {problem}")
        failed = True
    for stage, diffs in res["stages"].items():
        skipped = len(diffs) == 1 and diffs[0].startswith("SKIPPED")
        if not diffs or skipped:
            print(f"✓ {stage}: {'skipped' if skipped else 'no drift'}")
            continue
        failed = True
        print(f"✗ {stage}: DRIFT")
        sys.stdout.writelines(diffs)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
