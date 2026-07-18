#!/usr/bin/env python3
"""detect_impl_strategy.py — P2 implementation-strategy axis.

Deterministically classifies, per weakness class, whether a solved problem is
solved with a recognized *standard* or *home-grown* — the axis that decides
whether "no central control" is exculpated (a vetted library IS the control) or
aggravated (bespoke crypto/authz is a risk multiplier). Reads the catalog
`data/security-libraries.yaml` and the target repo (package.json dependencies +
a source grep for bespoke patterns), and writes `$OUTPUT_DIR/.impl-strategy.json`:

    {"version": 1, "strategies": {"<weakness_class>": {
        "strategy": "standard-vetted|standard-misused|home-grown|none",
        "vetted_libs_found": [...], "bespoke_hit": bool}}}

Classification (proposal §2 / §P2.3):
    vetted present AND no bespoke  → standard-vetted   (exculpatory)
    vetted present AND bespoke     → standard-misused  (a finding)
    no vetted     AND bespoke      → home-grown        (risk multiplier)
    neither                        → none

RULE: standard-vetted requires a detected lib AND no bespoke/misuse signal —
never library-presence alone (else `alg:none` gets a free pass).

Consumed by merge_threats.build_weakness_register, which stamps
`implementation_strategy` onto the matching weakness and applies the exculpatory
(vetted → suppress a pure design gap) / aggravating (home-grown) severity effect.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from _atomic_io import atomic_write_json

_HERE = Path(__file__).resolve().parent
_CATALOG = _HERE.parent / "data" / "security-libraries.yaml"

# Source extensions worth grepping for bespoke patterns (JS/TS ecosystems where
# the catalogs are written; extend as the catalog grows).
_SRC_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
_EXCLUDE_DIRS = {
    "node_modules",
    ".git",
    "dist",
    "build",
    "out",
    "coverage",
    ".next",
    ".nuxt",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    "codefixes",
}
_MAX_FILE_BYTES = 2_000_000


def _load_catalog() -> dict[str, Any]:
    try:
        import yaml

        doc = yaml.safe_load(_CATALOG.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — missing/broken catalog → no-op
        return {}
    return doc if isinstance(doc, dict) else {}


def _iter_source_files(repo_root: Path):
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _EXCLUDE_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in _SRC_EXTS:
            yield p


def collect_dependencies(repo_root: Path) -> set[str]:
    """Union of dependency names across every package.json in the repo
    (dependencies + devDependencies + peer/optional)."""
    deps: set[str] = set()
    for pkg in repo_root.rglob("package.json"):
        if any(part in _EXCLUDE_DIRS for part in pkg.parts):
            continue
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            block = data.get(key)
            if isinstance(block, dict):
                deps.update(str(k) for k in block)
    return deps


_BESPOKE_EVIDENCE_CAP = 5


def _scan_bespoke(repo_root: Path, patterns: list[str]) -> tuple[bool, list[dict[str, Any]]]:
    """Scan the source tree once for a domain's bespoke/misuse patterns.

    Returns ``(hit, evidence)`` where ``hit`` is the whole-text boolean used for
    strategy classification (parity with the former ``_bespoke_hit`` — catches
    multi-line matches too), and ``evidence`` is up to ``_BESPOKE_EVIDENCE_CAP``
    repo-root-relative ``{file, line}`` sites (line-based) used as the observable
    backing of the Gap-A design signal (I2). Evidence may be empty even when
    ``hit`` is True (a match only visible across line boundaries) — the signal
    emitter then simply does not fire, which is the conservative choice."""
    if not patterns:
        return False, []
    compiled: list[re.Pattern] = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat))
        except re.error:
            continue
    if not compiled:
        return False, []
    hit = False
    evidence: list[dict[str, Any]] = []
    for f in _iter_source_files(repo_root):
        try:
            if f.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not hit and any(rx.search(text) for rx in compiled):
            hit = True
        if len(evidence) < _BESPOKE_EVIDENCE_CAP:
            for lineno, line in enumerate(text.splitlines(), 1):
                if any(rx.search(line) for rx in compiled):
                    try:
                        rel = str(f.relative_to(repo_root))
                    except ValueError:
                        rel = f.name
                    evidence.append({"file": rel, "line": lineno})
                    if len(evidence) >= _BESPOKE_EVIDENCE_CAP:
                        break
        if hit and len(evidence) >= _BESPOKE_EVIDENCE_CAP:
            break
    return hit, evidence


def _bespoke_hit(repo_root: Path, patterns: list[str]) -> bool:
    return _scan_bespoke(repo_root, patterns)[0]


def _classify(vetted_found: list[str], bespoke_hit: bool) -> str:
    if vetted_found and not bespoke_hit:
        return "standard-vetted"
    if vetted_found and bespoke_hit:
        return "standard-misused"
    if bespoke_hit:
        return "home-grown"
    return "none"


def build_strategy_map(repo_root: Path) -> dict[str, dict[str, Any]]:
    """Return {weakness_class: {strategy, vetted_libs_found, bespoke_hit}}."""
    catalog = _load_catalog()
    domains = catalog.get("domains") or {}
    if not domains:
        return {}
    deps = collect_dependencies(repo_root)
    out: dict[str, dict[str, Any]] = {}
    for wclass, spec in domains.items():
        if not isinstance(spec, dict):
            continue
        vetted = [lib for lib in (spec.get("vetted_libs") or []) if lib in deps]
        bespoke, evidence = _scan_bespoke(repo_root, spec.get("bespoke_patterns") or [])
        strategy = _classify(vetted, bespoke)
        # `none` carries no signal for the reconciler; omit to keep the sidecar tight.
        if strategy == "none":
            continue
        entry: dict[str, Any] = {
            "strategy": strategy,
            "vetted_libs_found": sorted(vetted),
            "bespoke_hit": bespoke,
        }
        # Gap-A: carry the sink sites so build_impl_design_signals can back a
        # design-risk weakness with observable file:line evidence.
        if evidence:
            entry["bespoke_evidence"] = evidence
        out[wclass] = entry
    return out


def build_impl_design_signals(
    strategy_map: dict[str, dict[str, Any]], catalog: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Gap-A: for each `central_control` domain whose control is home-grown or
    misused (bespoke sink present, not a vetted standard), emit a design signal
    so the reconciler surfaces a design-risk weakness EVEN WHEN no concrete
    SQLi/XSS/IDOR instance was confirmed — the observable backing (I2) is the
    bespoke sink's own file:line. Consumed by merge_threats._load_design_signals.

    Only fires for domains marked `central_control` in security-libraries.yaml
    (input validation, output encoding, access control, authentication) and only
    for `home-grown` / `standard-misused` strategies with concrete evidence — a
    `standard-vetted` domain emits nothing (the vetted control IS the control),
    and a domain with no bespoke evidence emits nothing (no speculation)."""
    catalog = catalog if catalog is not None else _load_catalog()
    domains = catalog.get("domains") or {}
    signals: list[dict[str, Any]] = []
    for wclass, entry in (strategy_map or {}).items():
        strategy = entry.get("strategy")
        if strategy not in ("home-grown", "standard-misused"):
            continue
        evidence = entry.get("bespoke_evidence") or []
        if not evidence:
            continue
        cc = ((domains.get(wclass) or {}) if isinstance(domains.get(wclass), dict) else {}).get("central_control")
        if not isinstance(cc, dict):
            continue  # domain is not a centralizable control → do not surface
        # Component spread proxy: distinct parent directories of the sink sites.
        # ≥ SYSTEMIC_SPREAD_MIN dirs → the reconciler treats it as systemic
        # (severity bump, principle VIOLATED); a single dir stays WEAK.
        comps = sorted({(str(e.get("file") or "").rsplit("/", 1)[0] or ".") for e in evidence})
        backing = [
            {
                "pattern": cc.get("principle") or wclass.replace("_", " "),
                "hit_count": len(evidence),
                "example": f"{evidence[0].get('file')}:{evidence[0].get('line')}",
            }
        ]
        signals.append(
            {
                "rule_id": "IMPL-STRATEGY",
                "weakness_class": wclass,
                "mechanism_id": cc.get("mechanism_id"),
                "cwe": cc.get("cwe"),
                "title": cc.get("weakness_title"),
                "statement": cc.get("statement") or f"Home-grown {wclass.replace('_', ' ')} handling.",
                "absent_control_signal": backing,
                "implementation_strategy": strategy,
                "severity": "Medium",
                "affected_components": comps,
            }
        )
    return signals


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="detect_impl_strategy.py", description=__doc__)
    p.add_argument("--repo-root", required=True, help="Path to the target repository root.")
    p.add_argument("--output-dir", required=True, help="Directory to write .impl-strategy.json into.")
    args = p.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"detect_impl_strategy: repo-root not found: {repo_root}", file=sys.stderr)
        return 1
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    strategies = build_strategy_map(repo_root)
    target = out_dir / ".impl-strategy.json"
    atomic_write_json(target, {"version": 1, "strategies": strategies}, indent=2)
    print(f"detect_impl_strategy: wrote {target} ({len(strategies)} classes with a strategy signal)")

    # Gap-A: emit design signals for home-grown/misused central controls so the
    # reconciler surfaces a design-risk weakness even absent a confirmed
    # instance. Separate sidecar (merge_threats._load_design_signals merges it
    # with the arch-coverage stream); absent/empty → non-fatal, no weakness.
    design_signals = build_impl_design_signals(strategies)
    ds_target = out_dir / ".impl-design-signals.json"
    atomic_write_json(ds_target, {"version": 1, "design_signals": design_signals}, indent=2)
    print(f"detect_impl_strategy: wrote {ds_target} ({len(design_signals)} central-control design signal(s))")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
