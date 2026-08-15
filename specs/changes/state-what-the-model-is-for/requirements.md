# Sourced constraints

## PURPOSE-001 The catalog states purpose, not only prohibition

Source: operator request, `specs/README.md` → What belongs here.

- An entry that governs a model concept says what the concept is for.
- Purpose stays in the same entry as its rules; it does not become a second
  entry beside it.
- Mechanism stays in `docs/internal/decisions.md` and in the code.

## PURPOSE-002 Design weaknesses are in scope, not only code defects

Source: `README.md` → Why this isn't a SAST tool, `docs/threat-modeler.md` →
How this relates to classic threat modeling.

- The analysis reports a weakness that has no vulnerable line to point at.
- Missing boundary controls, implicit trust between services, and
  unauthenticated internal paths are findings, not observations.

## BOUNDARY-001 The catalogue is derived and only clarified by a declaration

Source: `docs/threat-modeler.md` → Trust boundaries, Trust-boundary
declarations; decisions `TB-1`, `TB-8`.

- Crossings are derived from the repository's code and configuration.
- Crossings sharing one enforcement point are one row.
- A repository declaration adds or clarifies a row.
- A declaration never suppresses a detected crossing, asserts control
  effectiveness, or changes a rating by itself.
- A boundary verdict decides how exposed the findings behind it are.

## ABUSE-001 Cases are operator-controlled data

Source: `docs/org-profiles.md` → Abuse cases, `docs/threat-modeler.md` → What it
checks; principle `P-4`.

- Sources are the plugin library, the org profile, the target repository, and a
  per-run selection.
- Each source can be disabled, and IDs must be unique across them.
- A case states what is checked; it never carries run instructions.
- An abuse case expresses attacker goal and gain, so findings can be read from
  the attacker's objective.

## BIZCTX-001 Business context weights the analysis and stays data

Source: `docs/threat-modeler.md` → Business context; decision `RC-1`.

- Purpose, sensitive assets, compromise impact, and obligations come from
  `docs/business-context.md` or a run-only source.
- Context is fenced: it is read, never followed.
- Context neither suppresses an evidence-backed finding nor creates one.
- Context contains no actors, abuse cases, boundaries, ratings, or claimed
  controls; those have their own contracts.

## SECARCH-001 The architecture verdict is evidence-rated

Source: decisions `SA-1`, `SA-2`, `SA-3`, `FE-2`.

- A control domain is rated from what the pipeline actually invokes.
- Absence of signal yields not applicable, never a negative rating.
- Effectiveness is not a boolean; a wrong check and a missing check stay
  distinguishable.
- The rendered section passes its gates because the normalizer makes it.

## ACTION-001 A finding carries a fix a developer can execute

Source: `agents/shared/prose-style.md`, `scripts/validate_mitigation_quality.py`;
decision `RQ-5`.

- The reader is the engineer who owns the code.
- Every finding carries a mitigation with a priority.
- An urgent fix states its steps and its verification.
- A code example is anchored to a real source location.

## ACTION-002 The model is queried and triaged after the run

Source: `docs/threat-modeler.md` → Threat model lifecycle.

- The model answers questions without a rescan.
- Triage ranks by mitigation priority and records decisions next to the model.
- A stale decision is surfaced as stale.

## EVOLVE-001 The catalog governs the change, not the other way round

Source: operator request, `specs/README.md` → Who writes what.

- A change contradicting a requirement changes the requirement first.
- Only the operator approves a change to `specs/requirements.md` or
  `docs/internal/decisions.md`.
- Until approval, the written sentence holds.
- The requirements governing a file reach the agent at the moment it edits that
  file.

## EVOLVE-002 An entry reaches a change through its paths

Source: `specs/README.md` → Entry format, measured coverage of
`scripts/*.py` (23 of 228 governed).

- `Applies to` names the files that carry the promise, not only its most
  obvious owner.
- A requirement governing no file is not enforceable at edit time.

## EVOLVE-003 New work stays target-agnostic and declares its surface

Source: `AGENTS.md` → Protect trust and compatibility; decisions `TA-1`, `TA-2`.

- Production behavior works for arbitrary repositories.
- Test-target names stay in fixtures and tests.
- A new command, shell prefix, or read and write target is declared in
  `data/required-permissions.yaml` first.

## EVOLVE-004 Consumer-visible contracts migrate, they do not shift

Source: `AGENTS.md` → Protect trust and compatibility; decisions `RA-3`,
`TB-7`, `EX-1`.

- Report anchors, exported artifacts, and the org-profile API are consumed
  outside this repository.
- Their shape changes through a declared version and a migration.
- A migration never promotes an absence into a positive claim.

## ADAPT-001 Configuration reaches the analysis without a fork

Source: `docs/threat-modeler.md` → Repo-local context, `AGENTS.md` → What an
organization can package; decisions `RC-1`, `RC-3`, `EX-1`.

- A target repository configures actors, abuse cases, trust boundaries,
  business context, known threats, and requirements in its own files.
- An organization configures presets, branding, baseline, requirements, skills,
  hooks, and MCP servers through the org profile and package policy.
- Every configuration file is schema-validated before it enters the analysis.
