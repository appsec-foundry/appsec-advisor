"""shared/_finding_state.py — the one authority for a finding's evidence state.

Every surface that asks "is this finding confirmed?", "was it refuted?",
"is it in the report?" or "may it count as evidence?" calls these predicates
instead of reading ``evidence_tier`` / ``evidence_check`` itself. Before this
module those rules were copied into a dozen readers and disagreed: Figure 2
and the team questions treated only verified evidence as confirmed, while the
summary count, the posture verdict and the severity companions also counted
unchecked findings.

Decision (operator, see ``docs/internal/decisions.md``): a finding is
*confirmed* only when its evidence was established — ``llm-verified``,
``absence-verified`` or ``verified-prior``. ``pointer-resolved``,
``unchecked``, ``ambiguous`` and ``refuted`` are not confirmed. Unconfirmed
findings stay in the register; they are only not called confirmed.

Field sources, newest first:

* ``evidence_basis``, written with ``evidence_check`` by every producer that
  sets a verdict (``record_evidence``): the evidence verifier, the
  deterministic line and absence checks, abuse-case promotion and the
  shallower-depth carry-forward; ``confirmed`` and ``in_report_scope`` when a
  producer states them;
* legacy fields (``evidence_tier``, ``evidence_check``) for runs, resumes,
  rerenders and baselines written before ``evidence_basis`` existed.

Legacy limitation: a legacy ``evidence_check: verified`` also covers pointers
the deterministic line check merely resolved, so the legacy fallback cannot
tell ``pointer-resolved`` from ``llm-verified`` and treats both as verified.
``evidence_basis`` separates them.

Deliberately not routed here:

* abuse-case step verdicts and boundary-leg verdicts (``render_abuse_cases``,
  ``triage_compute_ranking``, the abuse and boundary sections of
  ``compose_threat_model``) — they judge chain steps, not a finding's own
  evidence;
* checks that require a fresh verifier receipt for this run
  (``evidence_check == "verified"`` without ``verified-prior``:
  ``flow_route_auth``, ``qa_checks._is_verified_disabled_code_comment``) —
  they need ``llm-verified`` once the finalize pass writes it;
* checks on one specific state (``carried-unverified-shallower-depth``,
  ``ambiguous`` review mitigations, the verifier guard, sampling, ordering).
"""

from __future__ import annotations

CONFIRMED_BASES = frozenset({"llm-verified", "absence-verified", "verified-prior"})
DISCREDITED_BASES = frozenset({"refuted", "ambiguous"})
_LEGACY_CONFIRMED_CHECKS = frozenset({"verified", "verified-prior"})
_PRACTICE_TIER = "insecure-practice"


def _text(value: object) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def evidence_basis(threat: dict | None) -> str:
    """The finding's evidence basis: the finalized field, else the legacy check."""
    if not isinstance(threat, dict):
        return ""
    return _text(threat.get("evidence_basis")) or _text(threat.get("evidence_check"))


def record_evidence(threat: dict, check: str, basis: str | None = None) -> None:
    """Set a verdict and its basis together; the basis defaults to the check.

    ``verified`` is the only check with more than one basis, so every producer
    that sets it names how it was established.
    """
    threat["evidence_check"] = check
    threat["evidence_basis"] = basis or check


def basis_unstated(threat: dict | None) -> bool:
    """A verified verdict that does not say whether a verifier or a pointer made it."""
    if not isinstance(threat, dict):
        return False
    return not _text(threat.get("evidence_basis")) and _text(threat.get("evidence_check")) == "verified"


def is_refuted(threat: dict | None) -> bool:
    """Evidence verification refuted the finding; it leaves the delivered model."""
    return evidence_basis(threat) == "refuted"


def is_discredited(threat: dict | None) -> bool:
    """The finding's evidence was refuted or could not be established.

    Weaker than ``not is_confirmed``: an unchecked or practice-tier finding is
    not discredited. Used where a finding only has to be usable evidence, for
    example as a companion CWE that lifts a severity cap.
    """
    return evidence_basis(threat) in DISCREDITED_BASES


def evidence_established(threat: dict | None) -> bool:
    """The finding's evidence was established, whatever its exploitability tier."""
    if not isinstance(threat, dict):
        return False
    basis = _text(threat.get("evidence_basis"))
    if basis:
        return basis in CONFIRMED_BASES
    return _text(threat.get("evidence_check")) in _LEGACY_CONFIRMED_CHECKS


def is_confirmed(threat: dict | None) -> bool:
    """The finding is confirmed exploitable on established evidence."""
    if not isinstance(threat, dict):
        return False
    finalized = threat.get("confirmed")
    if isinstance(finalized, bool):
        return finalized
    if _text(threat.get("evidence_tier")) == _PRACTICE_TIER:
        return False
    return evidence_established(threat)


def in_report_scope(threat: dict | None) -> bool:
    """The finding belongs to the delivered model (the finalized field, else not refuted)."""
    if not isinstance(threat, dict):
        return False
    finalized = threat.get("in_report_scope")
    if isinstance(finalized, bool):
        return finalized
    return not is_refuted(threat)
