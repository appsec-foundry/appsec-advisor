"""Build bounded architect packets from canonical findings and admitted context.

This pure API does not read target repositories, dispatch models, or publish run
artifacts. The controller must supply the admitted analyst context and retain
the returned manifest. Limits are explicit caller inputs pending calibration.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import copy
import json
from functools import lru_cache
from pathlib import Path

import yaml
from analyzers.architect_review import ReviewError, _canonical_valid, fingerprint
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from shared._severity_policy import (
    RANK,
    companion_cwes,
    cwe_ceiling,
    finding_cwe,
    individual_critical_ceiling,
    load_policy,
)
from validators.secret_scan import mask_structure

SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schemas"
SCHEMA_NAME = "architect-review-context.schema.json"
_SOURCES = (SCHEMA_NAME, "threats-merged.schema.yaml", "stride-analyst-context.schema.json", "stride.schema.yaml")
_PROSE_FIELDS = (
    "scenario",
    "evidence_summary",
    "mitigation_title",
    "remediation",
    "risk_reason",
    "likelihood_reason",
    "impact_reason",
    "rationale",
    "threat_category_id",
    "mitigation_ids",
    "controls_in_place",
    "attack_steps",
    "violated_requirements",
)


def packet_bytes(packet: dict) -> bytes:
    """The exact UTF-8 representation whose bytes admission accounts for."""
    return json.dumps(packet, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@lru_cache(maxsize=1)
def _contracts() -> tuple[dict, dict, dict, Registry]:
    documents = [yaml.safe_load((SCHEMA_ROOT / name).read_text(encoding="utf-8")) for name in _SOURCES]
    registry = Registry().with_resources((doc["$id"], Resource.from_contents(doc)) for doc in documents)
    return *documents[:3], registry


def validate_manifest(value: dict) -> None:
    """Reject forged scope, omitted findings, duplicate assignments, and overflow.

    Source freshness is checked separately with verify_manifest_sources before
    dispatch and again before consuming proposals. Unknown schema URIs are not
    retrieved: the registry contains only the fixed local contracts.
    """
    schema, _, _, registry = _contracts()
    if not Draft202012Validator(schema, registry=registry).is_valid(value):
        raise ReviewError("invalid architect context contract")
    seen: set[str] = set()
    if len(value["packets"]) > value["limits"]["max_packets"]:
        raise ReviewError("architect packet count exceeds admission")
    for index, packet in enumerate(value["packets"], 1):
        if packet["packet_id"] != f"packet-{index:04d}":
            raise ReviewError("architect packet identity is not canonical")
        for key in ("run_id", "input_sha256", "context_sha256", "policy_sha256"):
            if packet[key] != value[key]:
                raise ReviewError("architect packet is not bound to its manifest")
        if (
            len(packet["findings"]) > value["limits"]["max_findings"]
            or len(packet_bytes(packet)) > value["limits"]["max_packet_bytes"]
        ):
            raise ReviewError("architect packet exceeds admission")
        for row in packet["findings"]:
            finding = row["finding"]
            if finding["t_id"] in seen or finding["component_id"] != packet["component_id"]:
                raise ReviewError("architect finding has duplicate or foreign ownership")
            seen.add(finding["t_id"])
    for row in value["excluded"]:
        if row["t_id"] in seen:
            raise ReviewError("architect finding has multiple dispositions")
        seen.add(row["t_id"])


def build_context(
    merged: dict,
    analyst_context: dict,
    *,
    run_id: str,
    max_findings: int,
    max_packet_bytes: int,
    max_packets: int,
    output_dir: Path | None = None,
) -> dict:
    """Group eligible findings without truncating a finding or hiding coverage.

    Read business declarations from the admitted analyst source, not its STRIDE
    projection: that projection deliberately omits explicit no-harm context.
    Missing context remains null. Declared business harm never changes ratings.
    Policy caps account for companions in the complete canonical register.
    """
    _canonical_valid(merged, output_dir)
    _, merged_schema, analyst_schema, registry = _contracts()
    if not Draft202012Validator(analyst_schema, registry=registry).is_valid(analyst_context):
        raise ReviewError("invalid admitted analyst context")
    limits = {"max_findings": max_findings, "max_packet_bytes": max_packet_bytes, "max_packets": max_packets}
    if (
        not isinstance(run_id, str)
        or not 1 <= len(run_id) <= 128
        or not run_id.strip()
        or any(type(value) is not int for value in limits.values())
        or not 1 <= max_findings <= 32
        or not 1 <= max_packet_bytes <= 131_072
        or not 1 <= max_packets <= 10_000
    ):
        raise ReviewError("invalid controller architect limits")
    caps, criteria = load_policy()
    result = {
        "schema_version": 1,
        "run_id": run_id,
        "input_sha256": fingerprint(merged),
        "context_sha256": fingerprint(analyst_context),
        "policy_sha256": fingerprint([caps, criteria]),
        "limits": limits,
        "packets": [],
        "excluded": [],
    }
    fields = set(merged_schema["properties"]["threats"]["items"]["properties"]) | set(_PROSE_FIELDS)
    # Merged provenance and repeated instances are not needed for a first
    # assessment. Their canonical hash remains bound, and no mapping is editable.
    fields -= {"merged_from", "instances", "affected_files", "instance_count", "triage_flags"}
    threats = merged["threats"]
    if len({row["t_id"] for row in threats}) != len(threats):
        raise ReviewError("duplicate canonical finding identity")
    priorities = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}
    groups: dict[str, list[dict]] = {}
    for row in threats:
        if row.get("evidence_check") == "refuted":
            result["excluded"].append({"t_id": row["t_id"], "reason": "refuted"})
        else:
            groups.setdefault(row["component_id"], []).append(row)

    def order(row: dict) -> tuple:
        return (row.get("evidence_check") not in (None, "ambiguous"), -RANK[row["risk"]], row["t_id"])

    for component in sorted(groups, key=lambda key: (min(order(row) for row in groups[key]), key)):
        source = analyst_context.get(component, {})
        context = {
            target: copy.deepcopy(source.get(field))
            for target, field in (
                ("business", "business_context"),
                ("architecture", "architecture_context"),
                ("controls", "controls"),
            )
        }
        context, _ = mask_structure(context)
        packet = None
        for threat in sorted(groups[component], key=order):
            cwe = finding_cwe(threat)
            ceiling = min(
                (cwe_ceiling(cwe, caps, companion_cwes(threat, threats)), individual_critical_ceiling(cwe, criteria)),
                key=RANK.__getitem__,
            )
            projected = {
                "finding": {key: copy.deepcopy(value) for key, value in threat.items() if key in fields},
                "risk_ceiling": ceiling,
                "ordinary_priority": priorities[threat["risk"]],
            }
            projected, _ = mask_structure(projected)
            if packet is not None:
                candidate = {**packet, "findings": [*packet["findings"], projected]}
                if len(candidate["findings"]) <= max_findings and len(packet_bytes(candidate)) <= max_packet_bytes:
                    packet["findings"].append(projected)
                    continue
            candidate = {
                key: result[key]
                for key in ("schema_version", "run_id", "input_sha256", "context_sha256", "policy_sha256")
            }
            candidate.update(
                packet_id=f"packet-{len(result['packets']) + 1:04d}",
                component_id=component,
                context=context,
                findings=[projected],
            )
            if len(packet_bytes(candidate)) > max_packet_bytes:
                result["excluded"].append({"t_id": threat["t_id"], "reason": "oversized"})
            elif len(result["packets"]) >= max_packets:
                result["excluded"].append({"t_id": threat["t_id"], "reason": "packet_limit"})
            else:
                packet = candidate
                result["packets"].append(packet)
    result["excluded"].sort(key=lambda row: row["t_id"])
    validate_manifest(result)
    return result


def verify_manifest_sources(
    manifest: dict,
    merged: dict,
    analyst_context: dict,
    *,
    run_id: str,
    max_findings: int,
    max_packet_bytes: int,
    max_packets: int,
    output_dir: Path | None = None,
) -> None:
    """Reconstruct controller-owned selection; a valid hash alone is not authority."""
    validate_manifest(manifest)
    expected = build_context(
        merged,
        analyst_context,
        run_id=run_id,
        max_findings=max_findings,
        max_packet_bytes=max_packet_bytes,
        max_packets=max_packets,
        output_dir=output_dir,
    )
    if manifest != expected:
        raise ReviewError("architect context is stale or altered")
