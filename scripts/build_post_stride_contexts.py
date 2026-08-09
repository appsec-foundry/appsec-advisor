#!/usr/bin/env python3
"""Build bounded, receiptable semantic inputs after STRIDE merge."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from _atomic_io import atomic_write_json

MAX_EVIDENCE_ITEMS = 256
MAX_EVIDENCE_BYTES = 524_288
EVIDENCE_WINDOW_RADIUS = 5
MAX_SYNTHESIS_ITEMS = 512
MAX_SYNTHESIS_BYTES = 524_288

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


class PostStrideContextError(ValueError):
    """Raised when bounded post-STRIDE context cannot be built safely."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PostStrideContextError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PostStrideContextError(f"{label} must be a JSON object")
    return value


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=False, default=str) + "\n").encode("utf-8")


def _write_bounded(path: Path, value: dict[str, Any], max_bytes: int) -> Path:
    size = len(_canonical_bytes(value))
    value["limits"]["serialized_bytes"] = size
    payload = _canonical_bytes(value)
    if len(payload) > max_bytes:
        raise PostStrideContextError(f"{path.name} exceeds the {max_bytes}-byte cap")
    # serialized_bytes can change its own digit count once. Recompute to a fixed point.
    for _ in range(3):
        size = len(payload)
        value["limits"]["serialized_bytes"] = size
        payload = _canonical_bytes(value)
        if len(payload) == size:
            break
    if len(payload) > max_bytes:
        raise PostStrideContextError(f"{path.name} exceeds the {max_bytes}-byte cap")
    atomic_write_json(path, value, sort_keys=False)
    return path


def _stable_bucket(t_id: str, divisor: int) -> bool:
    return int(hashlib.sha256(t_id.encode("utf-8")).hexdigest()[:2], 16) % divisor == 0


def _eligible(threat: dict[str, Any], repo_root: Path) -> bool:
    if threat.get("evidence_check") == "verified-prior" or threat.get("source") == "known-vuln":
        return False
    evidence = threat.get("evidence")
    if not isinstance(evidence, dict) or not isinstance(evidence.get("file"), str):
        return False
    relative = Path(evidence["file"])
    if relative.is_absolute() or ".." in relative.parts:
        return False
    try:
        resolved = (repo_root / relative).resolve(strict=True)
    except OSError:
        return False
    return resolved.is_file() and resolved.is_relative_to(repo_root.resolve())


def select_evidence_threats(
    threats: list[dict[str, Any]], repo_root: Path, *, depth: str, noncritical_cap: int
) -> list[dict[str, Any]]:
    """Apply the established depth policy before any model sees the findings."""
    eligible = [row for row in threats if isinstance(row, dict) and _eligible(row, repo_root)]
    critical = sorted(
        (row for row in eligible if row.get("risk") == "Critical"), key=lambda row: str(row.get("t_id") or "")
    )
    noncritical: list[dict[str, Any]]
    if depth == "quick":
        noncritical = sorted(
            (row for row in eligible if row.get("risk") == "High" and _stable_bucket(str(row.get("t_id") or ""), 2)),
            key=lambda row: str(row.get("t_id") or ""),
        )
    elif depth == "standard":
        high = sorted(
            (row for row in eligible if row.get("risk") == "High"), key=lambda row: str(row.get("t_id") or "")
        )
        medium = sorted(
            (row for row in eligible if row.get("risk") == "Medium" and _stable_bucket(str(row.get("t_id") or ""), 4)),
            key=lambda row: str(row.get("t_id") or ""),
        )
        noncritical = [*high, *medium]
    elif depth == "thorough":
        noncritical = sorted(
            (row for row in eligible if row.get("risk") not in {"Critical", "Low", "Informational"}),
            key=lambda row: (_SEVERITY_ORDER.get(str(row.get("risk") or ""), 9), str(row.get("t_id") or "")),
        )
    else:
        raise PostStrideContextError(f"unsupported assessment depth {depth!r}")
    selected = [*critical, *noncritical[:noncritical_cap]]
    if len(selected) > MAX_EVIDENCE_ITEMS:
        raise PostStrideContextError(f"evidence sample has {len(selected)} items; maximum is {MAX_EVIDENCE_ITEMS}")
    return selected


def _source_window(repo_root: Path, evidence: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    relative = Path(str(evidence["file"]))
    resolved = (repo_root / relative).resolve(strict=True)
    payload = resolved.read_bytes()
    text = payload.decode("utf-8", errors="replace").splitlines()
    cited = evidence.get("line")
    line = cited if isinstance(cited, int) and not isinstance(cited, bool) else 1
    start = max(1, line - EVIDENCE_WINDOW_RADIUS)
    end = min(len(text), line + EVIDENCE_WINDOW_RADIUS)
    return _sha256(payload), [{"line": number, "text": text[number - 1][:1000]} for number in range(start, end + 1)]


def build_evidence_context(
    merged_payload: bytes,
    repo_root: Path,
    *,
    depth: str,
    noncritical_cap: int,
) -> dict[str, Any]:
    merged = _load_object(merged_payload, "threats-merged-v1")
    threats = merged.get("threats")
    if not isinstance(threats, list) or any(not isinstance(row, dict) for row in threats):
        raise PostStrideContextError("threats-merged-v1 has no object threats array")
    selected = select_evidence_threats(threats, repo_root, depth=depth, noncritical_cap=noncritical_cap)
    samples: list[dict[str, Any]] = []
    for threat in selected:
        evidence = threat["evidence"]
        file_sha256, window = _source_window(repo_root, evidence)
        samples.append(
            {
                "t_id": threat.get("t_id"),
                "title": threat.get("title"),
                "scenario": threat.get("scenario"),
                "risk": threat.get("risk"),
                "source": threat.get("source"),
                "evidence_summary": threat.get("evidence_summary"),
                "evidence": {"file": evidence["file"], "line": evidence.get("line")},
                "source_sha256": file_sha256,
                "source_window": window,
            }
        )
    return {
        "schema_version": 1,
        "source": {
            "artifact_path": ".threats-merged.json",
            "sha256": _sha256(merged_payload),
            "threat_count": len(threats),
        },
        "policy": {
            "depth": depth,
            "noncritical_cap": noncritical_cap,
            "critical_uncapped": True,
            "window_radius": EVIDENCE_WINDOW_RADIUS,
        },
        "limits": {
            "max_samples": MAX_EVIDENCE_ITEMS,
            "max_bytes": MAX_EVIDENCE_BYTES,
            "selected_samples": len(samples),
            "serialized_bytes": 0,
            "ordering_key": "severity,t_id with stable depth sampling",
        },
        "samples": samples,
    }


def validate_evidence_context_sources(value: dict[str, Any], merged_payload: bytes, repo_root: Path) -> None:
    """Reject stale source artifacts or source windows immediately before dispatch."""
    source = value.get("source")
    if not isinstance(source, dict) or source.get("sha256") != _sha256(merged_payload):
        raise PostStrideContextError("evidence context is stale for .threats-merged.json")
    for sample in value.get("samples", []):
        evidence = sample.get("evidence") if isinstance(sample, dict) else None
        if not isinstance(evidence, dict) or not isinstance(evidence.get("file"), str):
            raise PostStrideContextError("evidence context has an invalid source path")
        actual_sha256, actual_window = _source_window(repo_root, evidence)
        if sample.get("source_sha256") != actual_sha256 or sample.get("source_window") != actual_window:
            raise PostStrideContextError(f"evidence context source window is stale for {evidence['file']}")


def apply_evidence_verification(
    merged: dict[str, Any], context: dict[str, Any], verification: dict[str, Any]
) -> dict[str, Any]:
    """Apply only verdict fields after binding the side channel to its selected sample."""
    threats = merged.get("threats")
    samples = context.get("samples")
    summary = verification.get("summary")
    flags = verification.get("flags")
    if not isinstance(threats, list) or not isinstance(samples, list):
        raise PostStrideContextError("evidence application inputs have no record arrays")
    if not isinstance(summary, dict) or not isinstance(flags, list):
        raise PostStrideContextError("evidence verification has no summary or flags")
    sample_ids = [row.get("t_id") for row in samples if isinstance(row, dict)]
    if len(sample_ids) != len(samples) or len(set(sample_ids)) != len(sample_ids):
        raise PostStrideContextError("evidence context has duplicate or invalid sample IDs")
    if summary.get("total_threats") != len(threats):
        raise PostStrideContextError("evidence verification total does not match canonical threats")
    if summary.get("sampled") != len(samples):
        raise PostStrideContextError("evidence verification sample count does not match selected context")
    if verification.get("depth") != context.get("policy", {}).get("depth"):
        raise PostStrideContextError("evidence verification depth does not match selected context")
    resolved = sum(int(summary.get(key) or 0) for key in ("verified", "refuted", "ambiguous"))
    if len(flags) != resolved:
        raise PostStrideContextError("evidence verification flags do not match resolved outcomes")
    flag_ids: set[str] = set()
    verdict_by_threat: dict[str, dict[str, Any]] = {}
    for flag in flags:
        if not isinstance(flag, dict) or flag.get("t_id") not in sample_ids:
            raise PostStrideContextError("evidence verification references an unselected threat")
        if flag.get("t_id") in verdict_by_threat or flag.get("flag_id") in flag_ids:
            raise PostStrideContextError("evidence verification contains duplicate threat or flag IDs")
        verdict_by_threat[str(flag["t_id"])] = flag
        flag_ids.add(str(flag.get("flag_id")))
    for threat in threats:
        if not isinstance(threat, dict) or threat.get("t_id") not in verdict_by_threat:
            continue
        flag = verdict_by_threat[str(threat["t_id"])]
        threat["evidence_check"] = flag["verdict"]
        annotation = {
            "flag_id": flag["flag_id"],
            "verdict": flag["verdict"],
            "reason": flag["reason"],
            "line_excerpt": flag["line_excerpt"],
            "verified_at": verification.get("generated_at"),
        }
        existing = threat.get("evidence_flags")
        threat["evidence_flags"] = (
            [
                row
                for row in existing
                if isinstance(existing, list) and isinstance(row, dict) and row.get("flag_id") != flag["flag_id"]
            ]
            if isinstance(existing, list)
            else []
        )
        threat["evidence_flags"].append(annotation)
    return merged


def _component_tiers(components_payload: bytes) -> dict[str, str]:
    components = _load_object(components_payload, "components-v1").get("components")
    if not isinstance(components, list):
        raise PostStrideContextError("components-v1 has no components array")
    tiers: dict[str, str] = {}
    for component in components:
        if isinstance(component, dict) and isinstance(component.get("id"), str):
            tier = component.get("tier")
            if tier not in {"client", "application", "data"}:
                raise PostStrideContextError(f"component {component['id']!r} has no supported tier")
            tiers[component["id"]] = tier
    return tiers


def build_synthesis_contexts(merged_payload: bytes, components_payload: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    merged = _load_object(merged_payload, "threats-merged-v1")
    threats = merged.get("threats")
    if not isinstance(threats, list) or any(not isinstance(row, dict) for row in threats):
        raise PostStrideContextError("threats-merged-v1 has no object threats array")
    if len(threats) > MAX_SYNTHESIS_ITEMS:
        raise PostStrideContextError(
            f"post-STRIDE synthesis has {len(threats)} threats; maximum is {MAX_SYNTHESIS_ITEMS}"
        )
    tiers = _component_tiers(components_payload)
    source = {
        "artifact_path": ".threats-merged.json",
        "sha256": _sha256(merged_payload),
        "threat_count": len(threats),
        "components_artifact_path": ".components.json",
        "components_sha256": _sha256(components_payload),
    }
    generated: list[dict[str, Any]] = []
    mitigations: list[dict[str, Any]] = []
    for threat in threats:
        component_id = threat.get("component_id")
        if component_id not in tiers:
            raise PostStrideContextError(f"threat {threat.get('t_id')!r} references unknown component")
        generated.append(
            {
                "t_id": threat.get("t_id"),
                "title": threat.get("title"),
                "scenario": threat.get("scenario"),
                "component_id": component_id,
                "component_tier": tiers[component_id],
                "stride": threat.get("stride"),
                "cwe": threat.get("cwe"),
                "risk": threat.get("risk"),
                "evidence_tier": threat.get("evidence_tier"),
            }
        )
        remediation = threat.get("remediation") if isinstance(threat.get("remediation"), dict) else {}
        mitigations.append(
            {
                "t_id": threat.get("t_id"),
                "mitigation_title": threat.get("mitigation_title"),
                "effort": remediation.get("effort"),
                "steps": remediation.get("steps") if isinstance(remediation.get("steps"), list) else [],
                "verification": remediation.get("verification"),
                "reference": remediation.get("reference"),
            }
        )
    common_limits = {
        "max_records": MAX_SYNTHESIS_ITEMS,
        "max_bytes": MAX_SYNTHESIS_BYTES,
        "serialized_bytes": 0,
        "ordering_key": "canonical merged threat order",
    }
    return (
        {"schema_version": 1, "source": source, "limits": dict(common_limits), "threats": generated},
        {"schema_version": 1, "source": source, "limits": dict(common_limits), "mitigations": mitigations},
    )


def write_evidence_context(output_dir: Path, repo_root: Path, depth: str, cap: int) -> Path:
    payload = (output_dir / ".threats-merged.json").read_bytes()
    value = build_evidence_context(payload, repo_root, depth=depth, noncritical_cap=cap)
    target = output_dir / ".dispatch-context" / "post-stride" / "evidence-sample.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    return _write_bounded(target, value, MAX_EVIDENCE_BYTES)


def write_synthesis_contexts(output_dir: Path) -> tuple[Path, Path]:
    merged_payload = (output_dir / ".threats-merged.json").read_bytes()
    components_payload = (output_dir / ".components.json").read_bytes()
    generated, mitigations = build_synthesis_contexts(merged_payload, components_payload)
    target_dir = output_dir / ".dispatch-context" / "post-stride"
    target_dir.mkdir(parents=True, exist_ok=True)
    generated_path = _write_bounded(target_dir / "generated-threats.json", generated, MAX_SYNTHESIS_BYTES)
    mitigations_path = _write_bounded(target_dir / "proposed-mitigations.json", mitigations, MAX_SYNTHESIS_BYTES)
    return generated_path, mitigations_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    evidence = sub.add_parser("evidence")
    evidence.add_argument("--output-dir", required=True, type=Path)
    evidence.add_argument("--repo-root", required=True, type=Path)
    evidence.add_argument("--depth", required=True, choices=("quick", "standard", "thorough"))
    evidence.add_argument("--noncritical-cap", required=True, type=int)
    synthesis = sub.add_parser("synthesis")
    synthesis.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "evidence":
            paths = [
                write_evidence_context(
                    args.output_dir.resolve(), args.repo_root.resolve(), args.depth, args.noncritical_cap
                )
            ]
        else:
            paths = list(write_synthesis_contexts(args.output_dir.resolve()))
    except (OSError, PostStrideContextError) as exc:
        print(f"build_post_stride_contexts: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"artifacts": [str(path) for path in paths]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
