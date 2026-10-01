"""Deterministic assessment/remediation correction core; no runtime dispatch.

This module neither calls a model nor writes run files. The controller adapter,
analyzers/architect_review_runtime.py, authorizes packets, binds snapshots,
bounds calls and publishes accepted data.

The first contract deliberately rejects evidence, CVSS, ownership and deletion
edits. Those require their own semantic verification or a deterministic scorer.
Schema conformance does not prove that an authored fix or assessment is sound.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import copy
import hashlib
import json
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from shared._severity_policy import RANK, normalize_risks

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas/architect-corrections.schema.json"
MAX_PROPOSAL_BYTES = 131_072
# Legitimate proposals nest a few levels; the bound must not depend on the interpreter's recursion limit.
MAX_PROPOSAL_DEPTH = 32
_RATING_KEYS = ("risk", "likelihood", "impact")


class ReviewError(ValueError):
    """Required canonical input or caller-owned review scope is invalid."""


def _within_depth(value: Any, limit: int) -> bool:
    """Check container nesting iteratively, so no input depth can exhaust the stack."""
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (dict, list)):
            if depth > limit:
                return False
            stack.extend((child, depth + 1) for child in (item.values() if isinstance(item, dict) else item))
    return True


def fingerprint(value: Any) -> str:
    """Hash a canonical JSON value without copying its contents into diagnostics."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _valid(value: Any, definition: str | None = None) -> bool:
    schema = _schema()
    if definition:
        schema = {"$defs": schema["$defs"], "$ref": f"#/$defs/{definition}"}
    try:
        return Draft202012Validator(schema).is_valid(value)
    except RecursionError:
        return False


def _canonical_valid(merged: dict, output_dir: Path | None = None) -> None:
    from validators.validate_intermediate import validate_threats_merged

    valid, _errors = validate_threats_merged(merged, output_dir=output_dir)
    if not valid:
        # Validator messages can include arbitrary source strings. Keep them
        # out of the application report; the canonical gate owns diagnostics.
        raise ReviewError("canonical merged threats failed validation")


def _rating(threat: dict) -> dict:
    return {key: threat[key] for key in _RATING_KEYS}


def _fix(threat: dict) -> dict | None:
    remediation = threat.get("remediation")
    if not isinstance(remediation, dict):
        return None
    return {
        "title": threat.get("mitigation_title"),
        **{key: remediation.get(key) for key in ("steps", "verification", "effort")},
    }


def _outcome(tid: str, status: str, reason: str, decision: dict | None = None) -> dict:
    return {
        "t_id": tid,
        "status": status,
        "reason": reason,
        "assessment": decision["assessment"] if decision and status != "rejected" else "unreviewed",
        "remediation": decision["remediation"] if decision and status != "rejected" else "unreviewed",
    }


def apply_corrections(
    merged: dict,
    proposal: Any,
    *,
    run_id: str,
    packet_id: str,
    finding_ids: list[str],
    output_dir: Path | None = None,
) -> tuple[dict, dict]:
    """Return a validated copy and audit; rejected finding transactions are atomic.

    Scope arguments come from the controller, never from the proposal. The
    input hash binds this exact canonical snapshot. Context/source freshness
    and whether a job is still authorized remain controller responsibilities.
    """
    _canonical_valid(merged, output_dir)
    originals = {row["t_id"]: row for row in merged["threats"]}
    if (
        not run_id
        or not re.fullmatch(r"packet-[0-9]{4,}", packet_id)
        or not 1 <= len(finding_ids) <= 32
        or len(set(finding_ids)) != len(finding_ids)
        or not set(finding_ids).issubset(originals)
    ):
        raise ReviewError("invalid controller review scope")
    current_hash = fingerprint(merged)
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "packet_id": packet_id,
        "input_sha256": current_hash,
        "output_sha256": current_hash,
        "outcomes": [],
        "accepted": [],
    }
    result = copy.deepcopy(merged)

    def reject_packet(reason: str) -> tuple[dict, dict]:
        report["outcomes"] = [_outcome(tid, "rejected", reason) for tid in finding_ids]
        return result, report

    if not _within_depth(proposal, MAX_PROPOSAL_DEPTH):
        return reject_packet("invalid_json_value")
    try:
        size = len(json.dumps(proposal, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        return reject_packet("invalid_json_value")
    if size > MAX_PROPOSAL_BYTES:
        return reject_packet("proposal_too_large")
    # Validate the envelope independently: one malformed record must not make
    # another, independent valid finding lose its correction.
    envelope = dict(proposal) if isinstance(proposal, dict) else None
    if not isinstance(envelope, dict) or not isinstance(envelope.get("decisions"), list):
        return reject_packet("invalid_envelope")
    decisions = envelope["decisions"]
    envelope["decisions"] = []
    if not _valid(envelope) or len(decisions) > 32:
        return reject_packet("invalid_envelope")
    if any(envelope[key] != report[key] for key in ("run_id", "packet_id", "input_sha256")):
        return reject_packet("stale_or_foreign_packet")
    if any(not isinstance(row, dict) or row.get("t_id") not in finding_ids for row in decisions):
        return reject_packet("foreign_or_unidentified_finding")
    counts = Counter(row["t_id"] for row in decisions)
    by_id = {row["t_id"]: row for row in decisions}
    positions = {row["t_id"]: index for index, row in enumerate(result["threats"])}
    for tid in sorted(finding_ids):
        decision = by_id.get(tid)
        if decision is None:
            report["outcomes"].append(_outcome(tid, "unreviewed", "missing_result"))
            continue
        if counts[tid] != 1 or not _valid(decision, "decision"):
            report["outcomes"].append(_outcome(tid, "rejected", "duplicate_or_invalid_decision"))
            continue
        original = originals[tid]
        if original.get("evidence_check") == "refuted":
            report["outcomes"].append(_outcome(tid, "rejected", "refuted_finding"))
            continue
        candidate = copy.deepcopy(original)
        rating = decision.get("rating")
        fix = decision.get("fix")
        if rating:
            candidate.update(rating)
            candidate.pop("risk_before_policy", None)
            for key in ("effective_severity", "rank", "rank_score", "severity_rationale", "severity_rationale_manual"):
                candidate.pop(key, None)
        if fix:
            existing = original.get("remediation")
            has_fix = isinstance(existing, dict) and bool(existing.get("steps"))
            if (fix["operation"] == "add") == has_fix:
                report["outcomes"].append(_outcome(tid, "rejected", "remediation_operation_mismatch"))
                continue
            value = fix["value"]
            candidate["mitigation_title"] = value["title"]
            # Replacement removes old examples and generic `how` guidance.
            # Requirements mappings live on the finding and stay untouched.
            candidate["remediation"] = {key: copy.deepcopy(value[key]) for key in ("steps", "verification", "effort")}
            if isinstance(existing, dict):
                for key in ("reference", "blueprint"):
                    if key in existing:
                        candidate["remediation"][key] = copy.deepcopy(existing[key])
        trial = copy.deepcopy(result)
        trial["threats"][positions[tid]] = candidate
        if rating:
            normalize_risks(trial["threats"])
            candidate = trial["threats"][positions[tid]]
        try:
            _canonical_valid(trial, output_dir)
        except ReviewError:
            report["outcomes"].append(_outcome(tid, "rejected", "invalid_final_finding"))
            continue
        # Never normalize unrelated legacy findings as a side effect of review.
        if any(
            row != result["threats"][index] for index, row in enumerate(trial["threats"]) if index != positions[tid]
        ):
            report["outcomes"].append(_outcome(tid, "rejected", "unrelated_policy_change"))
            continue
        result = trial
        report["outcomes"].append(_outcome(tid, "accepted", "validated", decision))
        if rating or fix:
            report["accepted"].append(
                {
                    "t_id": tid,
                    "rationale": decision["reason"],
                    "rating": {"before": _rating(original), "requested": rating, "after": _rating(candidate)}
                    if rating
                    else None,
                    "remediation": {
                        "operation": fix["operation"],
                        "before_sha256": fingerprint(_fix(original)),
                        "after": _fix(candidate),
                    }
                    if fix
                    else None,
                }
            )
    _canonical_valid(result, output_dir)
    report["output_sha256"] = fingerprint(result)
    if not _valid(report, "report"):
        raise ReviewError("application report failed validation")
    return result, report


def _check_report(report: dict, merged_snapshot: dict, output_dir: Path | None = None) -> None:
    if not isinstance(report, dict):
        raise ReviewError("application report must be an object")
    definition = "batch_report" if "packet_reports" in report else "report"
    if not _valid(report, definition):
        raise ReviewError("application report failed validation")
    _canonical_valid(merged_snapshot, output_dir)
    if report["output_sha256"] != fingerprint(merged_snapshot):
        raise ReviewError("application report does not match the accepted snapshot")
    findings = {row["t_id"]: row for row in merged_snapshot["threats"]}
    outcomes = {row["t_id"]: row for row in report["outcomes"]}
    if len(outcomes) != len(report["outcomes"]):
        raise ReviewError("application report has duplicate outcomes")
    if "packet_reports" in report:
        parts = report["packet_reports"]
        if len({part["packet_id"] for part in parts}) != len(parts):
            raise ReviewError("application report has duplicate packets")
        if any(part[key] != report[key] for part in parts for key in ("run_id", "input_sha256")):
            raise ReviewError("application report mixes runs or input snapshots")
        accepted = sorted((row for part in parts for row in part["accepted"]), key=lambda row: row["t_id"])
        if accepted != report["accepted"]:
            raise ReviewError("application report lost or altered a packet correction")
        part_outcomes = [row for part in parts for row in part["outcomes"]]
        if len({row["t_id"] for row in part_outcomes}) != len(part_outcomes) or any(
            outcomes.get(row["t_id"]) != row for row in part_outcomes
        ):
            raise ReviewError("application report lost or altered packet coverage")
        assigned = {row["t_id"] for row in part_outcomes}
        if any(
            row["status"] != "unreviewed" or row["reason"] not in {"refuted", "oversized", "packet_limit"}
            for tid, row in outcomes.items()
            if tid not in assigned
        ):
            raise ReviewError("application report has an unauthored disposition")
    ids = [row["t_id"] for row in report["accepted"]]
    if len(ids) != len(set(ids)) or not set(ids).issubset(findings):
        raise ReviewError("application report has duplicate or foreign findings")
    for correction in report["accepted"]:
        outcome = outcomes.get(correction["t_id"], {})
        if outcome.get("status") != "accepted" or any(
            correction[field] is not None and outcome.get(disposition) != "corrected"
            for field, disposition in (("rating", "assessment"), ("remediation", "remediation"))
        ):
            raise ReviewError("accepted correction has no matching coverage outcome")
        source = findings[correction["t_id"]]
        if correction["rating"] and correction["rating"]["after"] != _rating(source):
            raise ReviewError("accepted rating does not match its source")
        if correction["remediation"] and correction["remediation"]["after"] != _fix(source):
            raise ReviewError("accepted remediation does not match its source")


def apply_review(
    merged: dict,
    analyst_context: dict,
    manifest: dict,
    proposals: dict,
    *,
    run_id: str,
    max_findings: int,
    max_packet_bytes: int,
    max_packets: int,
    output_dir: Path | None = None,
) -> tuple[dict, dict]:
    """Apply independent packets against their common frozen input snapshot.

    A sequential application against the previously modified register would
    incorrectly reject every later packet as stale. Validate each packet on the
    frozen input, combine its authorized finding transactions, then validate the
    complete candidate once more before handing it to the sole runtime writer.
    """
    from contexts.build_architect_context import verify_manifest_sources

    verify_manifest_sources(
        manifest,
        merged,
        analyst_context,
        run_id=run_id,
        max_findings=max_findings,
        max_packet_bytes=max_packet_bytes,
        max_packets=max_packets,
        output_dir=output_dir,
    )
    packet_ids = {packet["packet_id"] for packet in manifest["packets"]}
    if not isinstance(proposals, dict) or not set(proposals).issubset(packet_ids):
        raise ReviewError("foreign architect proposal packet")
    result = copy.deepcopy(merged)
    positions = {row["t_id"]: index for index, row in enumerate(result["threats"])}
    report = {
        key: manifest[key] for key in ("schema_version", "run_id", "input_sha256", "context_sha256", "policy_sha256")
    }
    report.update(output_sha256=manifest["input_sha256"], outcomes=[], accepted=[], packet_reports=[])
    for packet in manifest["packets"]:
        pid = packet["packet_id"]
        ids = [row["finding"]["t_id"] for row in packet["findings"]]
        proposal = proposals.get(
            pid,
            {
                "schema_version": 1,
                "run_id": run_id,
                "packet_id": pid,
                "input_sha256": manifest["input_sha256"],
                "decisions": [],
            },
        )
        stale_context = pid in proposals and (
            not isinstance(proposal, dict)
            or any(proposal.get(key) != manifest[key] for key in ("context_sha256", "policy_sha256"))
        )
        candidate, part = apply_corrections(
            merged,
            {} if stale_context else proposal,
            run_id=run_id,
            packet_id=pid,
            finding_ids=ids,
            output_dir=output_dir,
        )
        if stale_context:
            for outcome in part["outcomes"]:
                outcome["reason"] = "stale_or_foreign_context"
        for accepted in part["accepted"]:
            index = positions[accepted["t_id"]]
            result["threats"][index] = candidate["threats"][index]
        report["packet_reports"].append(part)
        report["outcomes"].extend(part["outcomes"])
        report["accepted"].extend(part["accepted"])
    for excluded in manifest["excluded"]:
        report["outcomes"].append(_outcome(excluded["t_id"], "unreviewed", excluded["reason"]))
    report["outcomes"].sort(key=lambda row: row["t_id"])
    report["accepted"].sort(key=lambda row: row["t_id"])
    report["output_sha256"] = fingerprint(result)
    # This includes companion-cap and cross-finding validation. On failure the
    # caller retains the complete original register, not a partly applied one.
    _check_report(report, result, output_dir)
    return result, report


def _card_priority(card: dict, risk: str, threats: dict) -> str:
    """Keep deterministic finding-fix exceptions under their existing owner."""
    if card.get("auto_source") == "finding-fix":
        from model.emit_finding_fix_mitigations import _UNAUTH_VEKTORS, _resolve_priority

        members = [threats[tid] for tid in card.get("threat_ids", [])]
        vector = next((row.get("vektor") for row in members if row.get("vektor") in _UNAUTH_VEKTORS), "")
        return _resolve_priority(risk, card.get("effort", "Medium"), vector)
    return {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}[risk]


def project_reviewed_mitigations(
    model: dict, report: dict, *, merged_snapshot: dict, output_dir: Path | None = None
) -> dict:
    """Project accepted source fixes after grouping, before final enrichment.

    Pure integration helper, not an automatic writer. The caller supplies the
    accepted merged snapshot from its own state. Distinct reviewed
    fixes get their own cards, preserving unrelated members of shared cards.
    """
    _check_report(report, merged_snapshot, output_dir)
    result = copy.deepcopy(model)
    threats = {row["id"]: row for row in result.get("threats", [])}
    next_id = (
        max(
            (
                int(match.group(1))
                for row in result.get("mitigations", [])
                if (match := re.fullmatch(r"M-(\d+)[a-z]?", row["id"]))
            ),
            default=0,
        )
        + 1
    )
    priorities = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}
    for correction in report["accepted"]:
        tid = correction["t_id"]
        threat = threats.get(tid)
        if threat is None:  # Below the report floor: retain the audit only.
            continue
        if correction["rating"] and _rating(threat) != correction["rating"]["after"]:
            raise ReviewError("accepted source rating changed before projection")
        fix = correction["remediation"]
        if not fix:
            continue
        expected = fix["after"]
        if _fix(threat) != expected:
            raise ReviewError("accepted source remediation changed before projection")
        existing = [
            row for row in result["mitigations"] if tid in row.get("threat_ids", []) and row.get("kind", "fix") == "fix"
        ]
        if (
            len(existing) == 1
            and existing[0].get("threat_ids") == [tid]
            and all(existing[0].get(key) == expected[key] for key in ("title", "steps", "verification", "effort"))
            and existing[0]["id"] in threat.get("mitigation_ids", [])
        ):
            continue
        retained = []
        for mitigation in result["mitigations"]:
            if tid in mitigation.get("threat_ids", []) and mitigation.get("kind", "fix") == "fix":
                mitigation["threat_ids"] = [item for item in mitigation["threat_ids"] if item != tid]
                if not mitigation["threat_ids"]:
                    continue
            retained.append(mitigation)
        result["mitigations"] = retained
        linked = [row["id"] for row in retained if tid in row.get("threat_ids", [])]
        mid = f"M-{next_id:03d}"
        next_id += 1
        result["mitigations"].append(
            {
                "id": mid,
                "title": expected["title"],
                "threat_ids": [tid],
                "kind": "fix",
                "priority": priorities[threat["risk"]],
                "severity": threat["risk"],
                "effort": expected["effort"],
                "steps": copy.deepcopy(expected["steps"]),
                "verification": expected["verification"],
            }
        )
        threat["mitigation_ids"] = linked + [mid]
    changed_ratings = {row["t_id"] for row in report["accepted"] if row["rating"]}
    for mitigation in result.get("mitigations", []):
        ids = mitigation.get("threat_ids", [])
        if mitigation.get("kind", "fix") != "fix" or not changed_ratings.intersection(ids):
            continue
        risk = max((threats[tid]["risk"] for tid in ids), key=RANK.__getitem__)
        mitigation["severity"] = risk
        mitigation["priority"] = _card_priority(mitigation, risk, threats)
    return result


def reviewed_mitigation_errors(
    model: dict, report: dict, *, merged_snapshot: dict, output_dir: Path | None = None
) -> list[str]:
    """Detect later writers losing or diluting an accepted fix; never repair it."""
    try:
        _check_report(report, merged_snapshot, output_dir)
    except ReviewError as exc:
        return [str(exc)]
    threats = {row["id"]: row for row in model.get("threats", [])}
    errors: list[str] = []
    changed_ratings = {row["t_id"] for row in report["accepted"] if row["rating"]}
    for card in model.get("mitigations", []):
        ids = card.get("threat_ids", [])
        if card.get("kind", "fix") == "fix" and changed_ratings.intersection(ids):
            if any(tid not in threats for tid in ids):
                errors.append("reviewed mitigation has an unknown finding")
                continue
            risk = max((threats[tid]["risk"] for tid in ids), key=RANK.__getitem__)
            if card.get("severity") != risk or card.get("priority") != _card_priority(card, risk, threats):
                errors.append("accepted assessment no longer determines mitigation priority")
    for correction in report["accepted"]:
        tid = correction["t_id"]
        if tid in threats and correction["rating"] and _rating(threats[tid]) != correction["rating"]["after"]:
            errors.append(f"{tid}: accepted assessment was changed")
        fix = correction["remediation"]
        if not fix or tid not in threats:
            continue
        cards = [
            row
            for row in model.get("mitigations", [])
            if tid in row.get("threat_ids", []) and row.get("kind", "fix") == "fix"
        ]
        expected = fix["after"]
        matching = [
            row
            for row in cards
            if all(row.get(key) == expected[key] for key in ("title", "steps", "verification", "effort"))
        ]
        if len(cards) != 1 or len(matching) != 1 or matching[0]["id"] not in threats[tid].get("mitigation_ids", []):
            errors.append(f"{tid}: accepted remediation was changed or diluted")
    return errors
