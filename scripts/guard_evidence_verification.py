#!/usr/bin/env python3
"""G1 — degenerate-evidence-verification guard.

The Phase-10a evidence-verifier (see `agents/appsec-evidence-verifier.md`)
samples findings, re-reads each cited `evidence.file:line`, and stamps one of
{`verified`, `refuted`, `ambiguous`} onto `evidence_check`. A model that is too
weak for the task can silently punt on *every* finding — the 2026-07-05
juice-shop run observed a Haiku dispatch return 51/51 identical canned
`ambiguous` verdicts (0 verified, 0 refuted) in a 57 ms batch, i.e. it never
actually read the evidence. That degenerate output is not signal; treating it
as signal is catastrophic downstream:

  * `emit_review_mitigations.py` turns EVERY ambiguous finding into a
    `kind:review` "Manual review …" P3 card and links it via
    `threats[].mitigation_ids[]`;
  * `emit_finding_fix_mitigations.py` then skips every finding that already
    carries a `mitigation_ids[]` entry, so NO real `kind:fix` (P1) mitigation is
    ever synthesised — the Mitigation Register collapses to all-P3 and
    "Top Mitigations" ships a single junk row;
  * §8 renders a `◌ (evidence ambiguous)` marker on every finding.

This guard runs BEFORE `emit_review_mitigations.py` in `auto_emitter_pass.sh`.
When the distribution is degenerate it strips `evidence_check` / `evidence_flags`
from every threat so the run is treated as *unverified-neutral*: no review cards
are synthesised, real fix mitigations are produced normally, and the downstream
deterministic floor (`validate_evidence_lines.py`, which only fills threats that
carry NO prior verdict) re-derives sensible per-line verdicts for §8.

Degenerate ≡ (sampled >= MIN_SAMPLE) AND (verified == 0) AND (refuted == 0)
             AND (ambiguous / sampled >= AMBIGUOUS_RATIO).

The guard also records a ``fallback_required`` gate when the verifier claims a
non-trivial sample but returns no verdicts at all. That result is neither a
healthy sample nor an ambiguity distribution; the deterministic
``validate_evidence_lines.py`` pass immediately following this guard becomes
the required evidence backstop for the run.

Requiring 0 verified AND 0 refuted is deliberate: a real verifier run on a
vulnerable target surfaces plenty of `verified`, so an all-ambiguous-with-zero-
signal result is a model failure, not a genuinely uncertain codebase.

Best-effort and idempotent: on a healthy (non-degenerate) run it is a no-op and
exits 0. Any error is non-fatal (exit 0) so it can never abort a run that has
already spent 25+ minutes in Stage 1.

Usage:
    python3 guard_evidence_verification.py <output_dir>
"""

from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

import yaml
from event_log import format_line

# Degeneracy thresholds. MIN_SAMPLE guards against tripping on tiny samples
# (quick mode may verify only a handful of Criticals); AMBIGUOUS_RATIO mirrors
# the ">70% ambiguous" operator intent.
MIN_SAMPLE = 5
AMBIGUOUS_RATIO = 0.70

_VERDICTS = ("verified", "refuted", "ambiguous")


def _distribution(threats: list) -> dict:
    counts = {v: 0 for v in _VERDICTS}
    for t in threats:
        if not isinstance(t, dict):
            continue
        ec = (t.get("evidence_check") or "").strip().lower()
        # "verified-prior" is a deterministic-floor state, count it as verified
        # signal so a floor-heavy run is never mistaken for degenerate.
        if ec == "verified-prior":
            ec = "verified"
        if ec in counts:
            counts[ec] += 1
    counts["sampled"] = counts["verified"] + counts["refuted"] + counts["ambiguous"]
    return counts


def is_degenerate(counts: dict) -> bool:
    sampled = counts.get("sampled", 0)
    if sampled < MIN_SAMPLE:
        return False
    if counts.get("verified", 0) != 0 or counts.get("refuted", 0) != 0:
        return False
    return counts.get("ambiguous", 0) / sampled >= AMBIGUOUS_RATIO


def summary_degenerate(output_dir: Path) -> bool | None:
    """Degeneracy read from the LLM verifier's OWN ``.evidence-verification.json``
    summary — the authoritative, uncontaminated signal.

    The yaml distribution mixes the LLM's verdicts with the deterministic floor
    (``validate_evidence_lines.py``), which fills the *unchecked* findings and can
    add a handful of ``verified`` verdicts. Those floor verdicts must NOT mask an
    all-ambiguous LLM run: the 2026-07-05 juice-shop yaml showed
    ``{ambiguous: 51, verified: 7}`` (the 7 were floor-derived) while the LLM
    summary was ``verified=0, refuted=0, ambiguous=51`` — unmistakably degenerate.
    Reading the summary catches that; the yaml distribution alone did not.

    Returns True/False, or None when the summary is missing/unusable (caller then
    falls back to the yaml distribution via ``is_degenerate``).
    """
    path = output_dir / ".evidence-verification.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    summary = (data.get("summary") or {}) if isinstance(data, dict) else {}
    v, r, a = summary.get("verified"), summary.get("refuted"), summary.get("ambiguous")
    if v is None or r is None or a is None:
        return None
    return v == 0 and r == 0 and a >= MIN_SAMPLE


def summary_has_no_verdicts(output_dir: Path) -> bool | None:
    """Return whether a non-trivial verifier sample produced no verdicts.

    ``sampled`` is the verifier's intended/attempted sample count; ``unchecked``
    may therefore equal it after a turn cut-off.  This is distinct from an
    all-ambiguous model failure and must not be silently treated as a healthy
    verification pass.
    """
    path = output_dir / ".evidence-verification.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    summary = (data.get("summary") or {}) if isinstance(data, dict) else {}
    sampled, verified, refuted, ambiguous = (
        summary.get("sampled"),
        summary.get("verified"),
        summary.get("refuted"),
        summary.get("ambiguous"),
    )
    if not all(
        isinstance(value, int) and not isinstance(value, bool) for value in (sampled, verified, refuted, ambiguous)
    ):
        return None
    return sampled >= MIN_SAMPLE and verified == 0 and refuted == 0 and ambiguous == 0


def _neutralize(threats: list) -> int:
    """Strip ONLY the untrustworthy ``ambiguous`` verdicts (and their flags).

    A degenerate run has zero ``verified``/``refuted`` from the LLM, so every
    ``ambiguous`` in the yaml is the LLM's punt. Any ``verified``/``refuted`` /
    ``verified-prior`` present is deterministic-floor signal and is KEPT — the
    floor then re-derives the stripped findings on the next
    ``validate_evidence_lines.py`` pass."""
    stripped = 0
    for t in threats:
        if not isinstance(t, dict):
            continue
        if (t.get("evidence_check") or "").strip().lower() == "ambiguous":
            t.pop("evidence_check", None)
            t.pop("evidence_flags", None)
            stripped += 1
    return stripped


def _log(output_dir: Path, event: str, msg: str) -> None:
    try:
        with (output_dir / ".agent-run.log").open("a", encoding="utf-8") as fh:
            fh.write(format_line(event, msg, level="WARN", component="skill"))
    except OSError:
        pass


def _annotate_summary(output_dir: Path, counts: dict) -> None:
    """Record the neutralisation in the side-channel summary for observability."""
    path = output_dir / ".evidence-verification.json"
    if not path.is_file():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    data["degenerate_neutralized"] = True
    data["degenerate_reason"] = (
        f"all-ambiguous verifier output "
        f"(verified={counts.get('verified', 0)}, refuted={counts.get('refuted', 0)}, "
        f"ambiguous={counts.get('ambiguous', 0)}/{counts.get('sampled', 0)}) — "
        f"treated as model failure and neutralized by guard_evidence_verification.py"
    )
    data["degenerate_neutralized_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def _mark_fallback_required(output_dir: Path) -> None:
    """Persist the no-verdict gate for QA and run diagnostics."""
    path = output_dir / ".evidence-verification.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    data["verification_gate"] = "fallback_required"
    data["verification_gate_reason"] = (
        "verifier sampled findings but returned no verified, refuted, or ambiguous verdicts; "
        "validate_evidence_lines.py must provide the deterministic fallback"
    )
    data["verification_gate_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def guard(output_dir: Path) -> int:
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"guard_evidence_verification: no yaml at {yaml_path} — skipping", file=sys.stderr)
        return 0
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"guard_evidence_verification: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 0
    if not isinstance(data, dict):
        return 0
    threats = data.get("threats") or []
    if not isinstance(threats, list):
        return 0

    no_verdicts = summary_has_no_verdicts(output_dir)
    if no_verdicts:
        _mark_fallback_required(output_dir)
        _log(
            output_dir,
            "EVIDENCE_VERIFIER_NO_VERDICTS",
            "sampled findings but produced no verdicts; deterministic evidence fallback required",
        )
        print(
            "guard_evidence_verification: FALLBACK_REQUIRED — verifier sampled findings but "
            "produced no verdicts; validate_evidence_lines.py will provide the deterministic backstop",
            file=sys.stderr,
        )

    counts = _distribution(threats)
    # Prefer the LLM verifier's own summary (uncontaminated by the deterministic
    # floor); fall back to the yaml distribution when it is unavailable.
    summary_signal = summary_degenerate(output_dir)
    degenerate = summary_signal if summary_signal is not None else is_degenerate(counts)
    if not degenerate:
        print(
            "guard_evidence_verification: evidence distribution healthy "
            f"(verified={counts['verified']} refuted={counts['refuted']} "
            f"ambiguous={counts['ambiguous']} sampled={counts['sampled']}"
            f"{'; summary present' if summary_signal is not None else ''}) — no-op",
            file=sys.stderr,
        )
        return 0

    stripped = _neutralize(threats)
    if stripped == 0:
        print(
            "guard_evidence_verification: degenerate signal but no ambiguous verdicts to strip — no-op",
            file=sys.stderr,
        )
        return 0
    try:
        yaml_path.write_text(
            yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False),
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"guard_evidence_verification: write-back failed: {exc}", file=sys.stderr)
        return 0

    msg = (
        f"degenerate LLM verifier output (all-ambiguous, no verified/refuted from the "
        f"model{'; via .evidence-verification.json summary' if summary_signal else ''}). "
        f"Stripped {stripped} ambiguous verdict(s); floor-derived verified/refuted kept. "
        f"validate_evidence_lines.py re-derives the stripped findings."
    )
    _log(output_dir, "EVIDENCE_VERIFIER_DEGENERATE", msg)
    _annotate_summary(output_dir, counts)
    print(f"guard_evidence_verification: DEGENERATE — {msg}", file=sys.stderr)
    return 0


def main(argv: list) -> int:
    if len(argv) != 1:
        print("Usage: guard_evidence_verification.py <output_dir>", file=sys.stderr)
        return 2
    return guard(Path(argv[0]))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
