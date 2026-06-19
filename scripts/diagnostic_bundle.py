#!/usr/bin/env python3
"""diagnostic_bundle.py — build an ANONYMISED diagnostic bundle from a threat-
model run so a user who hits a pipeline error can hand it to the maintainer for
triage, WITHOUT disclosing any of their results or source.

Two subcommands:

  collect   Read a run's OUTPUT_DIR and emit a small `.tgz` containing only
            anonymised analysis telemetry: tool/plugin versions, the run shape
            (phases reached, stage timings, aggregate counts), a metadata-only
            file inventory (name/size/sha256 — never contents), and the run
            logs with paths / quoted strings / secrets scrubbed.

  inspect   Read a bundle (`.tgz` or unpacked dir) and print a triage summary:
            environment, where the run stopped, the last error, count
            histograms, and the file inventory.

WHAT NEVER ENTERS A BUNDLE (by construction, not by redaction toggle):
  • threat-model.yaml / .md / .sarif.json contents (the findings)
  • .stride-*.json / .threats-merged.json / .triage-flags.json contents
  • evidence snippets, component names/paths/descriptions, CWE→location maps
  • the scanned-repo root path, repo name, or any absolute filesystem path

Only AGGREGATE, anonymised shape leaves the machine: counts and histograms
(e.g. "14 threats: 3 High / 8 Medium / 3 Low", "9 components by type"), never
the items themselves. This is the deliberate contrast with threat_fixture.py,
which captures a FULL replayable fixture for your own / consented repos. Use
this tool for untrusted third-party error reports; use threat_fixture for
regression-testing the deterministic tail.

This is a manual developer/support tool. It is NOT part of the scanned-repo
pipeline and grants the skill no new permissions.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import platform
import re
import tarfile
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = _SCRIPT_DIR.parent

# Final report artifacts + intermediate finding sidecars. Their NAMES + sizes +
# sha go into the inventory, but their CONTENTS are never copied.
SENSITIVE_CONTENT = (
    "threat-model.yaml",
    "threat-model.md",
    "threat-model.sarif.json",
    "threat-model.pdf",
    "analysis-model.md",
    "pentest-tasks.yaml",
)

# Logs are the only file content copied — always through _scrub_line().
LOG_NAMES = (".agent-run.log", ".hook-events.log")

# ── anonymisation ──────────────────────────────────────────────────────────

_ABS_PATH = re.compile(r"(?:/[\w.\-+@]+){2,}/?")  # /a/b... (≥2 segments)
_QUOTED = re.compile(r"""(['"])(?:\\.|(?!\1).)*\1""")  # '...' or "..."
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_TOKEN = re.compile(r"\b[A-Za-z0-9+/_-]{32,}\b")  # long opaque blobs (secrets)


def _scrub_line(text: str, repo_root: str | None, repo_name: str | None) -> str:
    """Best-effort defence-in-depth scrub of a free-text log line. The safe
    diagnostic signal is the structured prefix (timestamp/level/component/
    event); detail is scrubbed because it can embed paths or finding titles."""
    if repo_root:
        text = text.replace(repo_root, "<repo>")
    if repo_name:
        text = re.sub(rf"\b{re.escape(repo_name)}\b", "<repo>", text)
    text = _EMAIL.sub("<email>", text)
    text = _QUOTED.sub("<str>", text)
    text = _TOKEN.sub("<token>", text)
    text = _ABS_PATH.sub("<path>", text)
    return text


def _scrub_text(text: str, repo_root: str | None, repo_name: str | None) -> str:
    return "".join(_scrub_line(ln, repo_root, repo_name) for ln in text.splitlines(keepends=True))


# ── aggregation (counts only — never the items) ────────────────────────────


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _as_items(obj: Any, *keys: str) -> list[dict]:
    """Coerce a sidecar into a flat list of dict items, tolerant of shape."""
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        for k in keys:
            v = obj.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def _histogram(items: list[dict], field: str) -> dict[str, int]:
    c = Counter(str(it.get(field)) for it in items if it.get(field) is not None)
    return dict(sorted(c.items()))


def _aggregate(out: Path) -> dict[str, Any]:
    """Anonymised count histograms from the finding sidecars — never titles,
    locations, names, or descriptions."""
    summary: dict[str, Any] = {}

    comps = _as_items(_load_json(out / ".components.json"), "components")
    if comps:
        summary["components"] = {
            "count": len(comps),
            "by_type": _histogram(comps, "type"),
            "by_tier": _histogram(comps, "tier"),
        }

    # prefer triage-flags (post-triage severities), fall back to merged threats
    threats = _as_items(_load_json(out / ".triage-flags.json"), "threats", "items")
    if not threats:
        threats = _as_items(_load_json(out / ".threats-merged.json"), "threats", "items")
    if threats:
        summary["threats"] = {
            "count": len(threats),
            "by_severity": _histogram(threats, "severity"),
            "by_stride": _histogram(threats, "stride"),
        }
    return summary


# ── run shape ──────────────────────────────────────────────────────────────


def _run_shape(out: Path, repo_root: str | None, repo_name: str | None) -> dict[str, Any]:
    shape: dict[str, Any] = {}

    prog = _load_json(out / ".appsec-progress.json")
    if isinstance(prog, dict):
        shape["last_progress"] = {
            k: prog.get(k) for k in ("phase", "step", "event", "kind", "status") if prog.get(k) is not None
        }

    stats_path = out / ".stage-stats.jsonl"
    if stats_path.is_file():
        stages = []
        for ln in stats_path.read_text(encoding="utf-8").splitlines():
            row = None
            try:
                row = json.loads(ln)
            except ValueError:
                continue
            if isinstance(row, dict):
                stages.append({k: row.get(k) for k in ("stage", "seconds", "status") if k in row})
        if stages:
            shape["stages"] = stages

    # last error line from the agent log (scrubbed)
    log = out / ".agent-run.log"
    if log.is_file():
        errors = [
            _scrub_line(ln.rstrip("\n"), repo_root, repo_name)
            for ln in log.read_text(encoding="utf-8", errors="replace").splitlines()
            if " ERROR " in ln or "AGENT_ERROR" in ln
        ]
        if errors:
            shape["error_count"] = len(errors)
            shape["last_error"] = errors[-1]
    return shape


# ── inventory (metadata only) ──────────────────────────────────────────────


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _inventory(out: Path) -> dict[str, Any]:
    """Per top-level entry: name → size + sha256 (files) or file_count + bytes
    (dirs). Names are fixed plugin sidecar names, never scanned-repo paths."""
    inv: dict[str, Any] = {}
    for entry in sorted(out.iterdir()):
        if entry.name == ".git":
            continue
        if entry.is_dir():
            files = [p for p in entry.rglob("*") if p.is_file()]
            inv[entry.name + "/"] = {
                "file_count": len(files),
                "bytes": sum(p.stat().st_size for p in files),
            }
        else:
            inv[entry.name] = {
                "bytes": entry.stat().st_size,
                "sha256": _sha256(entry),
                "sensitive_content_excluded": entry.name in SENSITIVE_CONTENT,
            }
    return inv


# ── skill config (sanitised subset) ────────────────────────────────────────


def _safe_config(out: Path) -> dict[str, Any]:
    cfg = _load_json(out / ".skill-config.json")
    if not isinstance(cfg, dict):
        return {}
    # keep only non-path scalar settings (depth, toggles); drop any string that
    # could be a path or identifier.
    safe: dict[str, Any] = {}
    for k, v in cfg.items():
        if isinstance(v, bool) or isinstance(v, (int, float)):
            safe[k] = v
        elif isinstance(v, str) and "/" not in v and len(v) <= 40:
            safe[k] = v
    return safe


# ── archive ────────────────────────────────────────────────────────────────


def _write_archive(src_dir: Path, tgz: Path) -> None:
    """Reproducible .tgz: sorted entries, mtime=0, root-owned."""

    def _reset(ti: tarfile.TarInfo) -> tarfile.TarInfo:
        ti.mtime = 0
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        return ti

    base = tgz.stem  # appsec-diag-xxxxxxxx
    files = sorted(p for p in src_dir.rglob("*") if p.is_file())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for p in files:
            tar.add(p, arcname=f"{base}/{p.relative_to(src_dir).as_posix()}", filter=_reset)
    with open(tgz, "wb") as out, gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(buf.getvalue())


def _plugin_version() -> str | None:
    try:
        return json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text()).get("version")
    except (OSError, ValueError):
        return None


# ── collect ────────────────────────────────────────────────────────────────


def collect(run: Path, into: Path, repo_root: str | None) -> Path:
    run = run.resolve()
    if not run.is_dir():
        raise SystemExit(f"Error: not a directory: {run}")
    repo_name = Path(repo_root).name if repo_root else None

    env = {
        "schema_version": 1,
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "plugin_version": _plugin_version(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "config": _safe_config(run),
    }
    shape = _run_shape(run, repo_root, repo_name)
    counts = _aggregate(run)
    inventory = _inventory(run)

    with tempfile.TemporaryDirectory() as td:
        stage = Path(td) / "bundle"
        stage.mkdir()
        (stage / "env-manifest.json").write_text(json.dumps(env, indent=2, sort_keys=True) + "\n")
        (stage / "run-summary.json").write_text(
            json.dumps({"shape": shape, "counts": counts}, indent=2, sort_keys=True) + "\n"
        )
        (stage / "inventory.json").write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")

        logs = stage / "logs"
        logs.mkdir()
        for name in LOG_NAMES:
            for src in sorted(run.glob(name + "*")):  # incl. rotations .1/.2
                if not src.is_file():
                    continue
                scrubbed = _scrub_text(src.read_text(encoding="utf-8", errors="replace"), repo_root, repo_name)
                (logs / src.name.lstrip(".")).write_text(scrubbed, encoding="utf-8")

        digest = hashlib.sha256()
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                digest.update(p.read_bytes())
        bundle_id = digest.hexdigest()[:8]

        if into.is_dir() or into.suffix != ".tgz":
            into = into / f"appsec-diag-{bundle_id}.tgz"
        into.parent.mkdir(parents=True, exist_ok=True)
        renamed = stage.with_name(into.stem)
        stage.rename(renamed)
        _write_archive(renamed, into)
    return into


# ── inspect ────────────────────────────────────────────────────────────────


def _read_bundle(bundle: Path) -> dict[str, Any]:
    """Return {env, summary, inventory} from a .tgz or unpacked dir."""
    if bundle.is_dir():
        root = bundle
        read = lambda n: (root / n).read_text() if (root / n).is_file() else None  # noqa: E731
        return {
            "env": json.loads(read("env-manifest.json") or "{}"),
            "summary": json.loads(read("run-summary.json") or "{}"),
            "inventory": json.loads(read("inventory.json") or "{}"),
        }
    with tarfile.open(bundle, "r:gz") as tar:

        def _member(suffix: str) -> Any:
            for m in tar.getmembers():
                if m.name.endswith(suffix) and m.isfile():
                    f = tar.extractfile(m)
                    return json.loads(f.read().decode()) if f else {}
            return {}

        return {
            "env": _member("env-manifest.json"),
            "summary": _member("run-summary.json"),
            "inventory": _member("inventory.json"),
        }


def _bundle_text(bundle: Path, suffix: str) -> str | None:
    """Read one already-scrubbed text member from a .tgz / dir IN MEMORY — no
    disk extraction, so a hand-crafted bundle cannot path-traverse on read."""
    if bundle.is_dir():
        for p in sorted(bundle.rglob("*")):
            if p.is_file() and p.as_posix().endswith(suffix):
                return p.read_text(errors="replace")
        return None
    with tarfile.open(bundle, "r:gz") as tar:
        for m in tar.getmembers():
            if m.isfile() and m.name.endswith(suffix):
                f = tar.extractfile(m)
                return f.read().decode(errors="replace") if f else None
    return None


def inspect(bundle: Path, log_tail: int = 0) -> int:
    bundle = bundle.resolve()
    if not bundle.exists():
        raise SystemExit(f"Error: no such bundle: {bundle}")
    data = _read_bundle(bundle)
    env, summary = data["env"], data["summary"]
    shape, counts = summary.get("shape", {}), summary.get("counts", {})

    print("── environment ───────────────────────────")
    for k in ("plugin_version", "platform", "python_version", "collected_at"):
        print(f"  {k:16} {env.get(k)}")
    if env.get("config"):
        print(f"  {'config':16} {json.dumps(env['config'])}")

    print("\n── where it stopped ──────────────────────")
    if shape.get("last_progress"):
        print(f"  last progress    {json.dumps(shape['last_progress'])}")
    if shape.get("error_count"):
        print(f"  errors           {shape['error_count']}")
        print(f"  last error       {shape.get('last_error')}")
    if shape.get("stages"):
        print(f"  stages recorded  {len(shape['stages'])}")

    print("\n── anonymised counts ─────────────────────")
    print(f"  {json.dumps(counts) if counts else '(none)'}")

    print("\n── file inventory ────────────────────────")
    for name, meta in data["inventory"].items():
        if "bytes" in meta and "sha256" in meta:
            flag = " [content excluded]" if meta.get("sensitive_content_excluded") else ""
            print(f"  {name:34} {meta['bytes']:>9} B{flag}")
        else:
            print(f"  {name:34} {meta.get('file_count', '?')} files / {meta.get('bytes', '?')} B")

    if log_tail:
        log = _bundle_text(bundle, "logs/agent-run.log")
        if log:
            lines = log.splitlines()
            print(f"\n── scrubbed log tail (last {log_tail}) ────────")
            for ln in lines[-log_tail:]:
                print(f"  {ln}")
    return 0


# ── CLI ────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="diagnostic_bundle.py", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="Build an anonymised diagnostic bundle from a run's OUTPUT_DIR.")
    c.add_argument("--run", type=Path, required=True, help="The run OUTPUT_DIR (e.g. <repo>/docs/security).")
    c.add_argument("--into", type=Path, default=Path("."), help="Output .tgz path or a directory to write it into.")
    c.add_argument("--repo-root", default=None, help="Scanned repo path, used only to scrub it out of the logs.")

    i = sub.add_parser("inspect", help="Print a triage summary of a bundle (.tgz or unpacked dir).")
    i.add_argument("--bundle", type=Path, required=True)
    i.add_argument(
        "--logs", type=int, default=0, metavar="N", help="Also print the last N scrubbed agent-run.log lines."
    )

    ns = ap.parse_args(argv)
    if ns.cmd == "collect":
        out = collect(ns.run, ns.into, ns.repo_root)
        print(f"✓ wrote anonymised diagnostic bundle → {out}")
        return 0
    return inspect(ns.bundle, ns.logs)


if __name__ == "__main__":
    raise SystemExit(main())
