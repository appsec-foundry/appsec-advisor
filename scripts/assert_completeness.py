#!/usr/bin/env python3
"""Assert the generated threat model is SUBSTANTIVELY complete.

The single authority for "every required register is present AND non-empty given
the upstream data", replacing the scattered presence-only gates that let a
heading-only §10 Mitigation Register ship at "17/17 sections".

Reads data/completeness-contract.yaml (which checks are active, their phase and
severity) and runs the matching NAMED check. No embedded expression language —
each invariant id maps to a Python function here; the contract only toggles and
prioritizes them.

Two phases:
  --phase build   asserts cross-yaml invariants on threat-model.yaml AFTER the
                  deterministic build + emitters. Catches a skipped emitter
                  deterministically with a non-zero exit, regardless of which
                  LLM/skill-body step died.
  --phase render  asserts substance on the rendered threat-model.md AFTER compose.

Exit code: 2 if any `fail`-severity invariant is violated, else 0. `warn`
invariants are logged but never block.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


# ── individual checks ───────────────────────────────────────────────────────
# Each returns (ok: bool, detail: str). detail is shown only when not ok.


def _crit_high(threat: dict) -> bool:
    sev = (threat.get("effective_severity") or threat.get("risk") or threat.get("severity") or "").strip().lower()
    return sev in ("critical", "high")


def chk_every_threat_has_id(y: dict, md: str) -> tuple[bool, str]:
    missing = [i for i, t in enumerate(y.get("threats") or []) if not (isinstance(t, dict) and t.get("id"))]
    return (not missing, f"{len(missing)} threat(s) without an id")


def chk_mitigations_nonempty_when_remediations(y: dict, md: str) -> tuple[bool, str]:
    threats = y.get("threats") or []
    has_remediation = any(
        (isinstance(t, dict)) and ((t.get("remediation") or {}).get("steps") or t.get("mitigation_title"))
        for t in threats
    )
    if not has_remediation:
        return True, ""  # self-gate: nothing to mitigate from
    n = len(y.get("mitigations") or [])
    return (n > 0, "threats carry remediation content but mitigations[] is empty")


def chk_mitigation_links_resolve(y: dict, md: str) -> tuple[bool, str]:
    threats = y.get("threats") or []
    mits = y.get("mitigations") or []
    mit_ids = {m.get("id") for m in mits if isinstance(m, dict)}
    threat_ids = {t.get("id") for t in threats if isinstance(t, dict)}
    dangling_t = []
    for t in threats:
        for mid in t.get("mitigation_ids") or []:
            if mid not in mit_ids:
                dangling_t.append(f"{t.get('id')}→{mid}")
    dangling_m = []
    for m in mits:
        for tid in m.get("threat_ids") or []:
            if tid not in threat_ids:
                dangling_m.append(f"{m.get('id')}→{tid}")
    problems = dangling_t + dangling_m
    return (not problems, "dangling links: " + ", ".join(problems[:8]) + (" …" if len(problems) > 8 else ""))


def chk_crit_high_have_mitigation_link(y: dict, md: str) -> tuple[bool, str]:
    unlinked = []
    for t in y.get("threats") or []:
        if not isinstance(t, dict):
            continue
        if (t.get("source") or "") == "config-scan":
            continue
        if _crit_high(t) and not (t.get("mitigation_ids") or []):
            unlinked.append(t.get("id"))
    return (
        not unlinked,
        f"{len(unlinked)} Critical/High finding(s) without a mitigation link: "
        + ", ".join(str(x) for x in unlinked[:10]),
    )


def chk_conditional_fragment_present(y: dict, md: str) -> tuple[bool, str]:
    # Currently advisory: we can only check the signals we can see in the yaml.
    # If the model meta declares an LLM/AI surface but no ai_risks were carried,
    # that's worth a warning. Extend as more conditional signals become yaml-visible.
    meta = y.get("meta") or {}
    if meta.get("has_llm_surface") and not (y.get("ai_risks") or meta.get("ai_exposure")):
        return False, "meta.has_llm_surface set but no AI exposure content present"
    return True, ""


def chk_render_required_sections_present(y: dict, md: str, required: list[str]) -> tuple[bool, str]:
    missing = []
    for title in required:
        # match a markdown heading line ending in the required title
        if not re.search(r"(?m)^#{1,3}\s+.*" + re.escape(title) + r"\s*$", md):
            missing.append(title)
    return (not missing, "missing required section(s): " + ", ".join(missing))


def chk_render_mitigation_register_substance(y: dict, md: str) -> tuple[bool, str]:
    if not (y.get("mitigations") or []):
        return True, ""  # self-gate
    has_card = bool(re.search(r"(?m)^#{2,4}\s.*\bM-\d{2,}", md)) or '<a id="m-' in md.lower()
    return (has_card, "§10 present but contains no M-NNN mitigation card (boilerplate only)")


def chk_render_findings_register_substance(y: dict, md: str) -> tuple[bool, str]:
    if not (y.get("threats") or []):
        return True, ""  # self-gate
    has_row = bool(re.search(r"F-\d{2,}", md)) or '<a id="f-' in md.lower()
    return (has_row, "§8 present but contains no F-NNN finding row (boilerplate only)")


_CHECKS = {
    "every_threat_has_id": chk_every_threat_has_id,
    "mitigations_nonempty_when_remediations": chk_mitigations_nonempty_when_remediations,
    "mitigation_links_resolve": chk_mitigation_links_resolve,
    "crit_high_have_mitigation_link": chk_crit_high_have_mitigation_link,
    "conditional_fragment_present": chk_conditional_fragment_present,
    "render_required_sections_present": chk_render_required_sections_present,
    "render_mitigation_register_substance": chk_render_mitigation_register_substance,
    "render_findings_register_substance": chk_render_findings_register_substance,
}


def _load_contract(plugin_root: Path) -> dict:
    path = plugin_root / "data" / "completeness-contract.yaml"
    if not path.is_file() or yaml is None:
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def run(output_dir: Path, plugin_root: Path, phase: str) -> int:
    contract = _load_contract(plugin_root)
    if not contract:
        sys.stderr.write("assert-completeness: no contract found — skipping (non-fatal)\n")
        return 0

    yaml_path = output_dir / "threat-model.yaml"
    y = {}
    if yaml_path.is_file() and yaml is not None:
        try:
            y = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError):
            y = {}
    md = ""
    md_path = output_dir / "threat-model.md"
    if phase == "render" and md_path.is_file():
        md = md_path.read_text(encoding="utf-8")

    required = contract.get("required_sections") or []
    failures: list[str] = []
    warnings: list[str] = []
    ran = 0

    for inv in contract.get("invariants") or []:
        if not isinstance(inv, dict) or inv.get("enabled") is False:
            continue
        if inv.get("phase") != phase:
            continue
        cid = inv.get("id")
        fn = _CHECKS.get(cid)
        if fn is None:
            continue
        ran += 1
        if cid == "render_required_sections_present":
            ok, detail = fn(y, md, required)
        else:
            ok, detail = fn(y, md)
        if ok:
            continue
        line = f"[{cid}] {detail}"
        hint = inv.get("fix_hint")
        if hint:
            line += f"  (fix: {hint})"
        if (inv.get("severity") or "fail") == "warn":
            warnings.append(line)
        else:
            failures.append(line)

    for w in warnings:
        sys.stderr.write(f"assert-completeness WARN  {w}\n")
    for f in failures:
        sys.stderr.write(f"assert-completeness FAIL  {f}\n")

    if failures:
        sys.stderr.write(
            f"assert-completeness[{phase}]: {len(failures)} failure(s), {len(warnings)} warning(s) "
            f"across {ran} check(s) — BLOCKING\n"
        )
        return 2
    sys.stdout.write(f"assert-completeness[{phase}]: OK ({ran} check(s), {len(warnings)} warning(s))\n")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--phase", choices=("build", "render"), required=True)
    p.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = p.parse_args()
    if not args.output_dir.is_dir():
        sys.stderr.write(f"assert-completeness: output dir not found: {args.output_dir}\n")
        return 0  # non-fatal: nothing to assert
    return run(args.output_dir, args.plugin_root, args.phase)


if __name__ == "__main__":
    raise SystemExit(main())
