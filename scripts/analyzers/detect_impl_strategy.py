#!/usr/bin/env python3
"""Classify observed implementation choices and emit source-backed practices.

The catalog describes supported JS/TS signals. Dependency presence records a
library inventory; it does not establish control enforcement or suppress a
weakness. Source observations are bounded, deterministic implementation
practices, never proof of an absent application-wide control.

The merger invokes emit_artifacts before reconciliation and again after triage.
Both emitted sidecars are validated against their schemas before atomic writes.
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
import re
import sys
from pathlib import Path
from typing import Any

from shared._atomic_io import atomic_write_json
from shared._finding_state import is_refuted
from shared._path_guard import is_safe_to_read, run_path_arg

from analyzers.source_auth_scanner import _JS_LEXEME, _without_js_comments
from analyzers.weakness_signals import production_path, validate_document

_HERE = Path(__file__).resolve().parents[1]
# Per weakness class: vetted libraries, bespoke source patterns and the central control they bypass.
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
# Source sites kept per weakness class; a few sites show the practice, more add no signal.
_BESPOKE_EVIDENCE_CAP = 5


def _load_catalog() -> dict[str, Any]:
    try:
        import yaml

        doc = yaml.safe_load(_CATALOG.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — missing/broken catalog → no-op
        return {}
    return doc if isinstance(doc, dict) else {}


# ================================================================ repository inputs
# Production JS/TS sources and package.json files only: test, example and excluded directories are skipped, and
# every file passes the path guard, so a symlink cannot pull in content from outside the repository.


def _iter_source_files(repo_root: Path):
    for directory, dirs, names in os.walk(repo_root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs if d not in _EXCLUDE_DIRS and production_path(Path(directory, d).relative_to(repo_root))
        )
        for name in sorted(names):
            p = Path(directory, name)
            if (
                p.suffix.lower() in _SRC_EXTS
                and production_path(p.relative_to(repo_root))
                and is_safe_to_read(p, repo_root)
            ):
                yield p


def collect_dependencies(repo_root: Path) -> set[str]:
    """Union of dependency names across every package.json in the repo
    (runtime dependencies + peer/optional)."""
    deps: set[str] = set()
    for pkg in repo_root.rglob("package.json"):
        relative = pkg.relative_to(repo_root)
        if (
            any(part in _EXCLUDE_DIRS for part in relative.parts)
            or not production_path(relative)
            or not is_safe_to_read(pkg, repo_root)
        ):
            continue
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        for key in ("dependencies", "peerDependencies", "optionalDependencies"):
            block = data.get(key)
            if isinstance(block, dict):
                deps.update(str(k) for k in block)
    return deps


# ================================================================ bespoke-pattern scan
# Matches each catalog bespoke pattern against comment-free source. A match inside a string literal is data, not
# code, and is skipped. Each class keeps its first sites in file walk order, up to _BESPOKE_EVIDENCE_CAP.


def _sanitized_html_alias(text: str, match: re.Match) -> bool:
    """Exclude a local sanitizer result passed directly to a raw HTML sink."""
    sink = re.search(r"(?:innerHTML\s*=|__html\s*:)\s*([A-Za-z_$][\w$]*)\b", match.group())
    if not sink:
        return False
    name = re.escape(sink[1])
    assignments = list(re.finditer(rf"\b{name}\s*=(?!=)\s*([^;\n]+)", text[: match.start()]))
    if not assignments:
        return False
    last = assignments[-1]
    # Only a directly preceding assignment can prove this local data flow;
    # another block or an intervening write invalidates the exclusion.
    between = text[last.end() : match.start()]
    if re.search(r"[{}=]", between):
        return False
    return bool(re.fullmatch(r"(?:DOMPurify\.sanitize|sanitizeHtml)\([^;\n]+\)", last[1].strip()))


def _read_source(path: Path) -> str | None:
    """The file without JS comments; ``None`` when it is too large or unreadable."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return _without_js_comments(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


def _scan_domains(repo_root: Path, domains: dict) -> dict[str, list[dict]]:
    """Read each production source once and retain bounded, deterministic sites."""
    compiled = {
        name: [re.compile(pattern) for pattern in spec.get("bespoke_patterns", [])] for name, spec in domains.items()
    }
    evidence: dict[str, list[dict]] = {name: [] for name in domains}
    for path in _iter_source_files(repo_root):
        text = _read_source(path)
        if text is None:
            continue
        literals = [(m.start(), m.end()) for m in _JS_LEXEME.finditer(text)]
        rel = path.relative_to(repo_root).as_posix()
        for name, patterns in compiled.items():
            sites = evidence[name]
            if len(sites) >= _BESPOKE_EVIDENCE_CAP:
                continue
            matches = sorted((m for rx in patterns for m in rx.finditer(text)), key=lambda m: m.start())
            for match in matches:
                if any(start < match.start() < end for start, end in literals):
                    continue
                if name == "output_xss_csp" and _sanitized_html_alias(text, match):
                    continue
                site = {"file": rel, "line": text.count("\n", 0, match.start()) + 1}
                if site not in sites:
                    sites.append(site)
                if len(sites) >= _BESPOKE_EVIDENCE_CAP:
                    break
    return evidence


# ================================================================ strategy per weakness class
# The strategy names how a class is implemented: vetted library only, library plus bespoke code, bespoke code
# only, or neither. The weakness reconciler reads it from .impl-strategy.json.


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
    evidence_by_class = _scan_domains(repo_root, domains)
    out: dict[str, dict[str, Any]] = {}
    for wclass, spec in domains.items():
        if not isinstance(spec, dict):
            continue
        vetted = [lib for lib in (spec.get("vetted_libs") or []) if lib in deps]
        evidence = evidence_by_class[wclass]
        bespoke = bool(evidence)
        strategy = _classify(vetted, bespoke)
        # `none` carries no signal for the reconciler; omit to keep the sidecar tight.
        if strategy == "none":
            continue
        entry: dict[str, Any] = {
            "strategy": strategy,
            "vetted_libs_found": sorted(vetted),
            "bespoke_hit": bespoke,
        }
        # Preserve source sites as implementation evidence, not control absence.
        if evidence:
            entry["bespoke_evidence"] = evidence
        out[wclass] = entry
    return out


# ================================================================ implementation design signals
# One IMPL-STRATEGY signal per class with bespoke code and a catalogued central control. It describes a practice
# at concrete sites (REQ-MOD-002), never the absence of a control across the application.


def build_impl_design_signals(
    strategy_map: dict[str, dict[str, Any]], catalog: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Emit observed implementation practices for catalogued control mechanisms.

    Only home-grown/misused paths with concrete production file-and-line
    evidence qualify. The historical central_control catalog key selects the
    mechanism; it does not prove control absence or component spread.
    """
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
        signals.append(
            {
                "rule_id": "IMPL-STRATEGY",
                "weakness_class": wclass,
                "mechanism_id": cc.get("mechanism_id"),
                "cwe": cc.get("cwe"),
                "title": cc.get("weakness_title"),
                "statement": cc.get("statement") or f"Home-grown {wclass.replace('_', ' ')} handling.",
                "practice_evidence": evidence,
                "implementation_strategy": strategy,
                "severity": "Medium",
                "affected_components": [],
            }
        )
    return signals


# ================================================================ reconciliation with findings and output
# After triage the merger passes the findings. A site whose finding verification refuted (same CWE, file and
# line) is dropped and the class is classified again; findings of the signal's CWE at its sites supply the
# affected components and instance ids.


def _evidence_items(threat: dict) -> list:
    """A finding's evidence as a list; a single evidence mapping is accepted too."""
    evidence = threat.get("evidence") or []
    return [evidence] if isinstance(evidence, dict) else evidence


def _refuted_sites(threats: list[dict] | None) -> set[tuple]:
    """(cwe, file, line) of every evidence site of a refuted finding."""
    refuted = set()
    for threat in threats or []:
        if is_refuted(threat):
            refuted.update(
                (threat.get("cwe"), e.get("file"), e.get("line"))
                for e in _evidence_items(threat)
                if isinstance(e, dict)
            )
    return refuted


def _drop_refuted_evidence(strategies: dict[str, dict[str, Any]], refuted: set[tuple]) -> None:
    domains = _load_catalog().get("domains") or {}
    for name, entry in strategies.items():
        if entry.get("bespoke_evidence"):
            cwe = ((domains.get(name) or {}).get("central_control") or {}).get("cwe")
            entry["bespoke_evidence"] = [
                e for e in entry["bespoke_evidence"] if (cwe, e["file"], e["line"]) not in refuted
            ]
            entry["bespoke_hit"] = bool(entry["bespoke_evidence"])
            entry["strategy"] = _classify(entry["vetted_libs_found"], entry["bespoke_hit"])


def _attach_findings(signal: dict[str, Any], threats: list[dict] | None) -> None:
    """Set the components and ids of unrefuted findings with the signal's CWE at one of its sites."""
    sites = {(e["file"], e["line"]) for e in signal["practice_evidence"]}
    owners = set()
    ids = []
    for threat in threats or []:
        if threat.get("cwe") != signal["cwe"] or is_refuted(threat):
            continue
        if not any((e.get("file"), e.get("line")) in sites for e in _evidence_items(threat) if isinstance(e, dict)):
            continue
        if component := threat.get("component_id") or threat.get("component"):
            owners.add(component)
        if tid := threat.get("t_id") or threat.get("id"):
            ids.append(tid)
    signal["affected_components"] = sorted(owners)
    signal["instance_ids"] = sorted(set(ids))


def emit_artifacts(repo_root: Path, out_dir: Path, threats: list[dict] | None = None) -> tuple[dict, list[dict]]:
    """Write validated observations; each invocation replaces stale run state."""
    strategies = build_strategy_map(repo_root)
    _drop_refuted_evidence(strategies, _refuted_sites(threats))
    signals = build_impl_design_signals(strategies)
    for signal in signals:
        _attach_findings(signal, threats)
    strategy_doc = {"version": 1, "strategies": strategies}
    signal_doc = {"version": 1, "design_signals": signals}
    validate_document(strategy_doc, "impl-strategy")
    validate_document(signal_doc)
    atomic_write_json(out_dir / ".impl-strategy.json", strategy_doc, indent=2)
    atomic_write_json(out_dir / ".impl-design-signals.json", signal_doc, indent=2)
    return strategies, signals


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="detect_impl_strategy.py", description=__doc__)
    p.add_argument("--repo-root", required=True, help="Path to the target repository root.")
    p.add_argument(
        "--output-dir", required=True, type=run_path_arg, help="Directory to write .impl-strategy.json into."
    )
    args = p.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"detect_impl_strategy: repo-root not found: {repo_root}", file=sys.stderr)
        return 1
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    strategies, design_signals = emit_artifacts(repo_root, out_dir)
    target = out_dir / ".impl-strategy.json"
    print(f"detect_impl_strategy: wrote {target} ({len(strategies)} classes with a strategy signal)")

    ds_target = out_dir / ".impl-design-signals.json"
    print(f"detect_impl_strategy: wrote {ds_target} ({len(design_signals)} implementation observation(s))")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
