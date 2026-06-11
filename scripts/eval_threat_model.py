#!/usr/bin/env python3
"""eval_threat_model.py: developer-facing quality eval for a threat-model run.

This is a TEST tool, not part of the create-threat-model pipeline. The pytest
suite + qa_checks.py already cover STRUCTURAL correctness (schema, render,
cross-refs, determinism). They do NOT judge the SEMANTIC quality of the
LLM-authored output. This harness fills that gap with a find -> adversarial-verify
loop over five rubric dimensions.

Split of labour (AGENTS.md: prefer deterministic Python, make the LLM do less):
  * `prepare`   — deterministic: load a run's artifacts, compute hard signals
                  (STRIDE histogram per component, zero-threat components,
                  component->path existence), and write a compact `brief.json`
                  the LLM judges consume. Emits only HARD facts as deterministic
                  findings (missing component paths == recon hallucination);
                  everything softer is a *signal* for a judge, never a standalone
                  finding, to keep the deterministic findings false-positive-free.
  * `aggregate` — deterministic: merge the judges' candidate findings with the
                  verifiers' refute-by-default verdicts, keep only `real` ones,
                  score, and render EVAL-REVIEW.md.

The five dimensions and the JUDGE/VERIFY agent logic live in
`agents/appsec-eval-judge.md`; the orchestration in
`skills/eval-threat-model/SKILL.md`.

Exit codes:
    0  prepare succeeded, or aggregate found no confirmed High+/Critical defect
    1  aggregate confirmed at least one High or Critical threat-model defect
    2  usage / load / parse error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

# Canonical STRIDE category names. Mirrors scripts/merge_threats.py
# `_STRIDE_ORDER` / `_STRIDE_LETTER` (STRIDE is a fixed, stable acronym).
_STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]
_STRIDE_LETTER_TO_NAME = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

# The rubric. Keys are stable (used for sidecar filenames judge-<dim>.json).
DIMENSIONS = [
    "stride_coverage",
    "severity_proportionality",
    "threat_plausibility",
    "recommendation_actionability",
    "missed_surface",
]

# Eval-finding severity order (worst first). Distinct from THREAT severity:
# this rates how serious the threat-model *defect* is, not the threat.
_EVAL_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_GATING_SEVERITIES = {"critical", "high"}

_RECON_SUMMARY_MAX = 6000  # chars of recon prose passed to judges
_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "eval-threat-model.schema.json"
_SCHEMA_DOC: dict[str, Any] | None = None


def _err(msg: str) -> int:
    print(f"eval_threat_model: {msg}", file=sys.stderr)
    return 2


def _load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a YAML mapping")
    return data


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _schema_doc() -> dict[str, Any]:
    global _SCHEMA_DOC  # noqa: PLW0603 - tiny process-local cache for repeated sidecars
    if _SCHEMA_DOC is None:
        _SCHEMA_DOC = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return _SCHEMA_DOC


def _schema_errors(payload: Any, definition: str) -> list[str]:
    schema = dict(_schema_doc())
    schema["$ref"] = f"#/$defs/{definition}"
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    out: list[str] = []
    for err in errors:
        loc = ".".join(str(p) for p in err.absolute_path) or "root"
        out.append(f"{loc}: {err.message}")
    return out


def _load_validated_json(path: Path, definition: str, problems: list[str]) -> dict | None:
    if not path.is_file():
        problems.append(f"missing {path.name}")
        return None
    try:
        payload = _load_json(path)
    except Exception as exc:  # noqa: BLE001 - aggregate reports all sidecar problems together
        problems.append(f"{path.name}: cannot parse JSON: {exc}")
        return None
    errors = _schema_errors(payload, definition)
    if errors:
        problems.extend(f"{path.name}: {e}" for e in errors)
        return None
    return payload


def _normalize_stride(value: str | None) -> str | None:
    """Map a STRIDE field to its canonical full name, or None if unknown."""
    if not value:
        return None
    v = value.strip()
    if v in _STRIDE_CATEGORIES:
        return v
    if v in _STRIDE_LETTER_TO_NAME:
        return _STRIDE_LETTER_TO_NAME[v]
    return None


def _repo_relative_path_exists(repo_root: Path, raw_path: object) -> bool:
    """Return whether raw_path exists under repo_root without following escapes.

    Component paths come from the generated threat model, which is untrusted
    input for this developer eval. Treat absolute paths, parent traversal, and
    symlink escapes as missing instead of probing outside the target repo.
    """
    if not isinstance(raw_path, str) or not raw_path.strip():
        return False
    rel = Path(raw_path)
    if rel.is_absolute() or ".." in rel.parts:
        return False
    try:
        root = repo_root.resolve(strict=True)
        candidate = (root / rel).resolve(strict=False)
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False
    return candidate.exists()


# --------------------------------------------------------------------------- #
# prepare
# --------------------------------------------------------------------------- #
def prepare(run_dir: Path, out: Path, repo: Path | None) -> int:
    yml = run_dir / "threat-model.yaml"
    if not yml.is_file():
        return _err(f"no threat-model.yaml under {run_dir}")
    try:
        model = _load_yaml(yml)
    except Exception as exc:  # noqa: BLE001 — surface any parse failure as usage error
        return _err(f"cannot parse {yml}: {exc}")

    # Optional enrichment from the merged-threats sidecar (cwe / source / evidence).
    merged_by_id: dict[str, dict] = {}
    merged_path = run_dir / ".threats-merged.json"
    if merged_path.is_file():
        try:
            for t in _load_json(merged_path).get("threats", []):
                merged_by_id[t.get("t_id", "")] = t
        except Exception:  # noqa: BLE001 — enrichment is best-effort
            pass

    recon = ""
    recon_path = run_dir / ".recon-summary.md"
    if recon_path.is_file():
        recon = recon_path.read_text(encoding="utf-8")[:_RECON_SUMMARY_MAX]

    threats_raw = model.get("threats") or []
    components_raw = model.get("components") or []
    mitigations_raw = model.get("mitigations") or []

    # STRIDE present-set per component id.
    present: dict[str, set[str]] = {}
    threat_count: dict[str, int] = {}
    for t in threats_raw:
        cid = t.get("component_id") or ""
        cat = _normalize_stride(t.get("stride_category") or t.get("stride"))
        threat_count[cid] = threat_count.get(cid, 0) + 1
        if cat:
            present.setdefault(cid, set()).add(cat)

    det_findings: list[dict] = []
    components: list[dict] = []
    missing_paths: list[dict] = []
    repo_root = repo.resolve(strict=True) if repo is not None else None

    for c in components_raw:
        cid = c.get("id") or ""
        pres = sorted(present.get(cid, set()), key=_STRIDE_CATEGORIES.index)
        absent = [s for s in _STRIDE_CATEGORIES if s not in present.get(cid, set())]
        paths = [str(p) for p in (c.get("paths") or [])]
        paths_exist = None
        if repo_root is not None:
            paths_exist = []
            for p in paths:
                exists = _repo_relative_path_exists(repo_root, p)
                paths_exist.append({"path": p, "exists": exists})
                if not exists:
                    missing_paths.append({"component": cid, "path": p})
        components.append(
            {
                "id": cid,
                "name": c.get("name"),
                "kind": c.get("kind"),
                "paths": paths,
                "threat_count": threat_count.get(cid, 0),
                "stride_present": pres,
                "stride_absent": absent,
                "paths_exist": paths_exist,
            }
        )

    # Hard deterministic finding: a component points at a path that does not
    # exist in the target repo == recon invented a component. FP-free, so emitted
    # directly (verified=true), no judge needed.
    for i, mp in enumerate(missing_paths, start=1):
        det_findings.append(
            {
                "id": f"DET-{i:03d}",
                "dimension": "recon_fidelity",
                "severity": "medium",
                "target_id": mp["component"],
                "title": f"Component {mp['component']} references missing path '{mp['path']}'",
                "detail": (
                    f"threat-model.yaml lists path '{mp['path']}' for component "
                    f"{mp['component']}, but it does not exist in the target repo — "
                    "the component may be hallucinated or the path is stale."
                ),
                "source": "deterministic",
            }
        )

    threats = []
    for t in threats_raw:
        tid = t.get("t_id") or ""
        m = merged_by_id.get(tid, {})
        threats.append(
            {
                "id": tid,
                "component": t.get("component"),
                "component_id": t.get("component_id"),
                "stride": _normalize_stride(t.get("stride_category") or t.get("stride")),
                "severity": t.get("severity") or t.get("risk"),
                "likelihood": t.get("likelihood"),
                "impact": t.get("impact"),
                "title": t.get("title"),
                "scenario": t.get("scenario"),
                "controls_in_place": t.get("controls_in_place"),
                "cwe": m.get("cwe"),
                "source": m.get("source"),
                "evidence": m.get("evidence"),
                "mitigation_ids": t.get("mitigations") or [],
            }
        )

    mitigations = [
        {
            "id": m.get("m_id"),
            "title": m.get("title"),
            "priority": m.get("priority"),
            "why": m.get("why"),
            "how": m.get("how"),
            "verification": m.get("verification"),
            "addresses": m.get("addresses") or [],
        }
        for m in mitigations_raw
    ]

    zero = [c["id"] for c in components if c["threat_count"] == 0]
    low = [c["id"] for c in components if 0 < c["threat_count"] <= 1]

    brief = {
        "version": 1,
        "run_dir": str(run_dir),
        "repo": str(repo) if repo else None,
        "project": model.get("project") or {},
        "recon_summary": recon,
        "components": components,
        "threats": threats,
        "mitigations": mitigations,
        "dimensions": DIMENSIONS,
        # Deterministic signals — pre-digested so each judge gets compact context.
        "signals": {
            "stride_coverage": {
                c["id"]: {"present": c["stride_present"], "absent": c["stride_absent"]} for c in components
            },
            "missed_surface": {
                "zero_threat_components": zero,
                "low_threat_components": low,
            },
            "recon_fidelity": {"missing_paths": missing_paths},
        },
    }

    schema_errors = [
        *(f"brief.json: {e}" for e in _schema_errors(brief, "brief")),
        *(f"det-findings.json: {e}" for e in _schema_errors({"version": 1, "findings": det_findings}, "det_findings")),
    ]
    if schema_errors:
        return _err("internal eval artifact failed schema validation:\n  - " + "\n  - ".join(schema_errors))

    out.mkdir(parents=True, exist_ok=True)
    (out / "brief.json").write_text(json.dumps(brief, indent=2), encoding="utf-8")
    (out / "det-findings.json").write_text(
        json.dumps({"version": 1, "findings": det_findings}, indent=2), encoding="utf-8"
    )

    print(
        f"eval_threat_model: prepared — {len(components)} components, "
        f"{len(threats)} threats, {len(mitigations)} mitigations; "
        f"{len(det_findings)} deterministic finding(s); "
        f"zero-threat components: {zero or 'none'}"
    )
    print(f"  brief:        {out / 'brief.json'}")
    print(f"  det-findings: {out / 'det-findings.json'}")
    return 0


# --------------------------------------------------------------------------- #
# aggregate
# --------------------------------------------------------------------------- #
def _sev_rank(sev: str) -> int:
    try:
        return _EVAL_SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return len(_EVAL_SEVERITY_ORDER)


def aggregate(out: Path) -> int:
    if not out.is_dir():
        return _err(f"output dir {out} does not exist — run `prepare` first")

    problems: list[str] = []
    det_doc = _load_validated_json(out / "det-findings.json", "det_findings", problems)

    confirmed: list[dict] = []
    dropped: list[dict] = []
    per_dim: dict[str, dict] = {}
    loaded: dict[str, tuple[list[dict], dict[str, dict]]] = {}

    for dim in DIMENSIONS:
        jpath = out / f"judge-{dim}.json"
        jdoc = _load_validated_json(jpath, "judge", problems)
        if jdoc and jdoc.get("dimension") != dim:
            problems.append(f"{jpath.name}: dimension {jdoc.get('dimension')!r} does not match filename {dim!r}")
        cand = jdoc.get("candidates", []) if jdoc else []
        cand_ids: list[str] = []
        for c in cand:
            cid = c.get("cand_id", "")
            if cid in cand_ids:
                problems.append(f"{jpath.name}: duplicate candidate id {cid!r}")
            cand_ids.append(cid)

        vpath = out / f"verify-{dim}.json"
        vdoc = _load_validated_json(vpath, "verify", problems)
        if vdoc and vdoc.get("dimension") != dim:
            problems.append(f"{vpath.name}: dimension {vdoc.get('dimension')!r} does not match filename {dim!r}")
        verdicts: dict[str, dict] = {}
        verdict_ids: list[str] = []
        for v in vdoc.get("verdicts", []) if vdoc else []:
            vid = v.get("cand_id", "")
            if vid in verdict_ids:
                problems.append(f"{vpath.name}: duplicate verdict for candidate id {vid!r}")
            verdict_ids.append(vid)
            verdicts[vid] = v

        missing_verdicts = sorted(set(cand_ids) - set(verdict_ids))
        extra_verdicts = sorted(set(verdict_ids) - set(cand_ids))
        if missing_verdicts:
            problems.append(f"{vpath.name}: missing verdict(s) for {', '.join(missing_verdicts)}")
        if extra_verdicts:
            problems.append(f"{vpath.name}: verdict(s) for unknown candidate(s) {', '.join(extra_verdicts)}")

        loaded[dim] = (cand, verdicts)

    if problems:
        return _err("aggregate input invalid:\n  - " + "\n  - ".join(problems))

    for dim, (cand, verdicts) in loaded.items():
        kept = 0
        for c in cand:
            v = verdicts.get(c.get("cand_id", ""))
            # Refute-by-default: a candidate survives ONLY on an explicit `real`.
            if v and v.get("verdict") == "real":
                confirmed.append({**c, "dimension": dim, "verify_reason": v.get("reason", "")})
                kept += 1
            else:
                dropped.append(
                    {
                        **c,
                        "dimension": dim,
                        "verify_reason": (v or {}).get("reason", "no verdict / refuted"),
                    }
                )
        per_dim[dim] = {"candidates": len(cand), "confirmed": kept, "dropped": len(cand) - kept}

    # Deterministic findings are confirmed by construction.
    for d in (det_doc or {}).get("findings", []):
        confirmed.append({**d, "verify_reason": "deterministic fact"})

    confirmed.sort(key=lambda f: _sev_rank(f.get("severity", "info")))

    counts = {s: 0 for s in _EVAL_SEVERITY_ORDER}
    for f in confirmed:
        counts[(f.get("severity") or "info").lower()] = counts.get((f.get("severity") or "info").lower(), 0) + 1

    results = {
        "version": 1,
        "summary": {
            "confirmed_total": len(confirmed),
            "by_severity": counts,
            "dropped_total": len(dropped),
            "per_dimension": per_dim,
        },
        "confirmed": confirmed,
        "dropped": dropped,
    }
    errors = _schema_errors(results, "results")
    if errors:
        return _err("eval-results.json failed schema validation:\n  - " + "\n  - ".join(errors))
    (out / "eval-results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    _render_review(out / "EVAL-REVIEW.md", results)

    gating = counts.get("critical", 0) + counts.get("high", 0)
    headline = (
        f"eval_threat_model: {len(confirmed)} confirmed defect(s) "
        f"({counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low, "
        f"{counts.get('info', 0)} info); {len(dropped)} candidate(s) dropped by verify."
    )
    print(headline)
    print(f"  review: {out / 'EVAL-REVIEW.md'}")
    return 1 if gating > 0 else 0


def _render_review(path: Path, results: dict) -> None:
    s = results["summary"]
    lines: list[str] = []
    lines.append("# Threat-Model Evaluation")
    lines.append("")
    lines.append(
        f"Confirmed defects: **{s['confirmed_total']}** "
        f"({s['by_severity'].get('critical', 0)} critical, "
        f"{s['by_severity'].get('high', 0)} high, "
        f"{s['by_severity'].get('medium', 0)} medium, "
        f"{s['by_severity'].get('low', 0)} low, "
        f"{s['by_severity'].get('info', 0)} info) · "
        f"{s['dropped_total']} candidate(s) dropped by adversarial verify."
    )
    lines.append("")
    lines.append("## Per-dimension")
    lines.append("")
    lines.append("| Dimension | Candidates | Confirmed | Dropped |")
    lines.append("|---|---|---|---|")
    for dim, d in s["per_dimension"].items():
        lines.append(f"| {dim} | {d['candidates']} | {d['confirmed']} | {d['dropped']} |")
    lines.append("")

    lines.append("## Confirmed findings")
    lines.append("")
    if not results["confirmed"]:
        lines.append("_None — no deterministic defect and every semantic candidate was refuted._")
    else:
        for f in results["confirmed"]:
            tid = f.get("target_id") or ""
            tag = f" ({tid})" if tid else ""
            lines.append(f"### [{(f.get('severity') or 'info').upper()}] {f.get('title', '(untitled)')}{tag}")
            lines.append(f"- Dimension: `{f.get('dimension', '')}`")
            if f.get("detail"):
                lines.append(f"- {f['detail']}")
            if f.get("suggested_fix"):
                lines.append(f"- Fix: {f['suggested_fix']}")
            if f.get("evidence"):
                lines.append(f"- Evidence: {f['evidence']}")
            lines.append(f"- Verify: {f.get('verify_reason', '')}")
            lines.append("")

    if results["dropped"]:
        lines.append("## Dropped candidates (refuted by verify)")
        lines.append("")
        for f in results["dropped"]:
            lines.append(
                f"- ~~{f.get('title', '(untitled)')}~~ (`{f.get('dimension', '')}`) — {f.get('verify_reason', '')}"
            )
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Semantic quality eval for a threat-model run.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prepare", help="compute deterministic signals + judge brief")
    p.add_argument("--run-dir", required=True, help="dir holding threat-model.yaml (+ sidecars)")
    p.add_argument("--out", required=True, help="eval working/output dir")
    p.add_argument("--repo", default=None, help="optional target repo root for path-existence checks")

    a = sub.add_parser("aggregate", help="merge judge + verify sidecars into EVAL-REVIEW.md")
    a.add_argument("--out", required=True, help="eval working/output dir (same as prepare)")

    args = parser.parse_args(argv)

    if args.cmd == "prepare":
        run_dir = Path(args.run_dir)
        if not run_dir.is_dir():
            return _err(f"run-dir {run_dir} is not a directory")
        repo = Path(args.repo) if args.repo else None
        if repo is not None and not repo.is_dir():
            return _err(f"repo {repo} is not a directory")
        return prepare(run_dir, Path(args.out), repo)

    if args.cmd == "aggregate":
        return aggregate(Path(args.out))

    return _err("unknown command")  # pragma: no cover — argparse enforces


if __name__ == "__main__":
    sys.exit(main())
