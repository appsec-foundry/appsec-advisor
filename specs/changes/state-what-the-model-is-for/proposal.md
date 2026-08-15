# State what the model is for

## Problem

The catalog says what the pipeline must not get wrong, and skips what the
plugin is for. A reader learns that a trust boundary is an assumption that can
fail, but not why the model carries boundaries at all, where the catalogue comes
from, or that a team can declare one. The same holds for abuse cases. Business
context has no entry, so nothing states that the model is weighted by what the
system is worth. Whole promise areas have no requirement: the security
architecture verdict, actionable mitigations, the triage and query skills, and
the repository-level configuration surface. Six decision areas — `SA`, `EXP`,
`RR`, `TA`, `ST`, `RP` — are cited by no requirement at all.

Two consequences. Somebody changing `prepare_trust_boundary_context.py` or
`normalize_security_architecture.py` gets `check_specs.py --for` output that
tells them nothing about the promise they are touching. And a requirement that
never states the purpose cannot catch a change that keeps every rule and loses
the point.

The second problem is reach. `requirements_hook.py` puts the governing
requirements in front of an agent at the moment it edits a file — the one moment
they can still change the edit — and holds `specs/requirements.md` behind an
operator prompt. That machinery works. It governs 23 of 228 top-level scripts.
`_url_guard.py`, `_path_guard.py`, `export_sarif.py`, `redact_known_secrets.py`,
`validate_mitigation_quality.py`, `normalize_security_architecture.py`,
`resolve_abuse_cases.py`, and `runtime_cleanup.py` are all edited without a
requirement in sight. Filling the gaps above is therefore not documentation
work: it is what makes the existing guard fire where the pipeline is actually
changed.

## Goal

Say what each part of the model is for and where it comes from, in the entry
that already governs it. Add entries for the four promise areas that have none:
security architecture, actionable mitigation, the post-run workflow, and
repository-level configuration. State that the catalog binds a change before the
code does, and widen `Applies to` so that rule reaches the files a change
actually touches.

## Non-goals

- Changing behavior. Every entry describes what the pipeline already does.
- Moving mechanism into the catalog. How a verdict is derived stays in the
  decision register; how a file is parsed stays in the code.
- Writing missing guards. An entry with no test carries the documented
  advisory marker.
- Covering `ST`, `RP`, and the uncited `OR` rows. Those are build decisions and
  belong in the register.

## User-visible effect

None at runtime. `check_specs.py --for <path>` surfaces the purpose of a
component alongside its rules, and the catalog states the promises a user would
recognise: findings that have no vulnerable line, a boundary catalogue a team
can extend, abuse cases an organization controls, and a fix that names steps and
a location.

## Proposed entries

Reworded entries keep their ID. Sentences below are the text to approve.

### Reworded

**REQ-PUR-002 — The subject is the design, not only the code**

> The analysis asks what an attacker could do to this system, not only where a
> line of code is wrong: missing boundary controls, implicit trust between
> services, unauthenticated internal paths, and design weaknesses with no
> vulnerable line to point at. It sits next to code scanners rather than
> replacing them, and the report is review input, never a release verdict.

**REQ-MOD-003 — A trust boundary is an assumption that can fail**

> A boundary is the one place a crossing is controlled, and whether its
> assumption still holds decides how exposed everything behind it is. A finding
> refutes the assumption; if findings sit in the protected components but none
> examines the crossing, the boundary is unconfirmed, and it is never shown as
> intact merely because evidence is absent.

**REQ-MOD-004 — An abuse case is a hypothesis until a probe confirms it**

> An abuse case says how someone would misuse the system and what they gain, so
> the report can be read from the attacker's goal rather than only from the
> code. One becomes a finding only when a probe confirms it in the code, and
> then it is an ordinary finding, not a category of its own.

### New

**REQ-MOD-006 — The boundary catalogue is derived, and a declaration only clarifies it**

> Crossings come from the repository's code and configuration, one row per
> enforcement point. A team may declare a crossing the code does not show, but a
> declaration never suppresses a detected one and never asserts that its control
> works.

**Applies to:** `scripts/prepare_trust_boundary_context.py`, `schemas/trust-boundaries-repo.schema.yaml`
**Source:** `docs/threat-modeler.md` → Trust-boundary declarations, decisions `TB-1`, `TB-8`
**Guard:** `test_repository_declaration_is_additive_and_cannot_self_confirm`,
`test_partial_leg_declaration_adds_a_condition_but_never_removes_a_leg`

**REQ-MOD-007 — Abuse cases come from a library the operator controls**

> Cases come from the plugin's standard library, an organization's additions,
> the repository's own cases, and a per-run selection, and each source can be
> turned off. A case decides what is checked; it never decides how the run
> behaves.

**Applies to:** `scripts/resolve_abuse_cases.py`, `data/abuse-cases/**`, `schemas/abuse-cases.schema.yaml`
**Source:** `docs/org-profiles.md` → Abuse cases, principle `P-4`
**Guard:** `test_library_loads_mandatory_cases`, `test_repo_local_honours_disable`,
`test_explicit_case_file_cannot_escape_repo`

**REQ-BIZ-003 — Business context says what is worth protecting**

> A repository may state purpose, sensitive assets, compromise impact, and
> obligations in `docs/business-context.md`, and the analysis weights findings
> with it instead of rating every component alike. It is read as data, never
> followed, and it neither suppresses a finding the repository supports nor
> creates one on its own.

**Applies to:** `scripts/load_business_context.py`, `scripts/build_threat_modeling_context.py`
**Source:** `docs/threat-modeler.md` → Business context, principle `P-4`, decision `RC-1`
**Guard:** `test_external_context_is_policy_validated_and_fenced`,
`test_run_only_business_context_replaces_the_repository_file`

**REQ-ARC-001 — The architecture verdict rates what exists and says so when there is nothing**

> Each control domain is rated from what the pipeline actually invokes, not from
> a tool name in a config file. A system with no such surface is marked not
> applicable rather than rated badly, and a wrong check stays distinguishable
> from a missing one.

**Applies to:** `data/architecture-coverage-rules.yaml`, `data/architectural-controls.yaml`,
`scripts/normalize_security_architecture.py`
**Source:** decisions `SA-1`, `SA-2`, `SA-3`, `FE-2`
**Guard:** `test_cookie_no_signal_is_not_applicable`, `test_empty_repo_all_rules_not_applicable`,
`test_normalizer_makes_all_three_gates_pass`

**REQ-RPT-004 — The report is addressed to the developer who has to fix it**

> The reader is the engineer who owns the code, so a finding names where it is,
> why the attack works, and what to change, in the repository's own vocabulary
> rather than a framework's. A sentence a developer cannot act on is not a
> finding.

**Applies to:** `agents/shared/prose-style.md`, `agents/shared/prose-samples.md`
**Source:** `agents/shared/prose-style.md` → reader, `AGENTS.md` → Keep the repository maintainable
**Guard:** `test_prose_style_file_exists`, `test_prose_authoring_files_reference_anchor`

**REQ-RPT-005 — A fix is prioritized, concrete, and checkable**

> Every finding carries a mitigation with a priority, and an urgent fix states
> its steps and how to verify it. A code example is anchored to a real source
> location, never invented to look concrete.

**Applies to:** `scripts/validate_mitigation_quality.py`, `scripts/emit_finding_fix_mitigations.py`,
`scripts/hydrate_mitigation_details.py`
**Source:** `docs/threat-modeler.md` → What you get, decision `RQ-5`
**Guard:** `test_urgent_fix_requires_steps_and_verification`,
`test_urgent_code_example_needs_a_source_location`,
`test_remediation_string_fallback_and_priority_rules`

**REQ-USE-001 — The model is worked, not filed**

> After a run the model can be asked questions and triaged finding by finding,
> with decisions kept next to the model instead of in a chat. Ranking follows
> mitigation priority, and a stale decision is shown as stale rather than
> silently applied.

**Applies to:** `skills/ask-threat-model/**`, `skills/review-threat-model/**`,
`scripts/query_threat_model.py`
**Source:** `docs/threat-modeler.md` → Threat model lifecycle
**Guard:** `test_display_id_maps_t_to_f`, `test_reconcile_ranks_and_marks_untriaged`,
`test_reconcile_merges_sidecar_decisions`, `test_reconcile_flags_stale_entries`

**REQ-CFG-002 — A repository configures its own analysis in declared files**

> Actors, abuse cases, trust boundaries, business context, known threats, and a
> requirements catalog are configured in the target repository's own files, each
> against its schema. None of them suppresses a finding the repository's
> evidence supports.

**Applies to:** `scripts/resolve_actors.py`, `scripts/resolve_abuse_cases.py`,
`scripts/build_threat_modeling_context.py`, `schemas/known-threats.schema.yaml`
**Source:** `docs/threat-modeler.md` → Repo-local context, decisions `RC-1`, `RC-3`
**Guard:** `test_resolver_never_writes_actor_choices_back_to_repo`,
`test_rejects_invalid_known_threats_before_context_publication`

### New — how the catalog governs the next change

**REQ-EVO-001 — The catalog binds a change before the code does**

> Work that would contradict a requirement changes the requirement first, and
> only the operator approves that change; until then the sentence that is
> written holds. The requirements governing a file are put in front of whoever
> edits it, at the moment of the edit.

**Applies to:** `specs/requirements.md`, `scripts/check_specs.py`, `scripts/requirements_hook.py`
**Source:** `specs/README.md` → Who writes what, What is enforced
**Guard:** `test_held_files_require_user_approval`, `test_governed_file_carries_its_requirements`,
`test_project_settings_wire_every_write_surface_to_the_hook`

**REQ-EVO-002 — New behavior works for any repository and declares what it touches**

> Behavior added to the pipeline works for arbitrary repositories; a name that
> exists only in a test target stays in fixtures and tests. A new command, shell
> prefix, or read and write target is declared in the permission catalog before
> it runs.

**Applies to:** `data/test-target-vocabulary.yaml`, `data/required-permissions.yaml`
**Source:** `AGENTS.md` → Protect trust and compatibility, decisions `TA-1`, `TA-2`
**Guard:** `test_name_in_python_string_literal_is_reported`, `test_name_in_help_text_is_reported`

**REQ-EVO-003 — A contract someone else consumes changes only with a migration**

> Report anchors, exported artifacts, and the org-profile API are read outside
> this repository, so their shape changes through a declared version and a
> migration rather than in place. A migration never turns an absence into a
> positive claim.

**Applies to:** `schemas/threat-model.output.schema.yaml`, `schemas/org-profile.schema.yaml`
**Source:** `AGENTS.md` → Protect trust and compatibility, decisions `RA-3`, `TB-7`, `EX-1`
**Guard:** `test_normalize_migrates_legacy_without_promoting_absence`,
`test_analysis_v5_declares_prior_read_compatibility`,
`test_main_invalid_analysis_compatibility_fails`

### Coverage, not only wording

An entry only reaches a change through its `Applies to`. Alongside the new
entries, widen the existing ones to the files that carry their promise and are
governed by nothing today:

| Entry | Add to `Applies to` |
|---|---|
| `REQ-TRU-001` | `scripts/_path_guard.py`, `scripts/_url_guard.py` |
| `REQ-TRU-002` | `scripts/redact_known_secrets.py` |
| `REQ-RPT-001` | `scripts/emit_severity_rationale.py`, `scripts/_severity_rollup.py` |
| `REQ-MOD-003` | `scripts/build_trust_boundary_assessment_input.py`, `scripts/_boundary_adjacency.py` |
| `REQ-MOD-004` | `scripts/match_abuse_cases.py`, `scripts/verify_abuse_cases.py`, `scripts/abuse_case_gate.py` |
| `REQ-INC-002` | `scripts/runtime_cleanup.py` |

This is the part that makes the difference for future work: a requirement that
governs no file is a sentence nobody meets while changing the pipeline.

### Approved late, and not yet true everywhere

`REQ-MOD-008` says that reference documentation the operator hands to the run —
a design specification or roadmap — is analyzed and cited as the source of what
it reveals. Two halves, and only one of them is implemented.

- **A document inside the target repository** is already covered. It is a
  target-owned declaration, evidence carries `file` and optional `line`, and a
  finding can cite it today.
- **A document supplied from outside** (`--context <url|path>`, a captured
  business-context source) cannot be cited. Evidence entries require a
  repository-relative `file`, so there is no shape for a URL or an out-of-tree
  path, and decision `FE-4` currently says external context may seed only an
  unverified hypothesis.

So the entry ships with `— (no guard written)` and two follow-ups: amend `FE-4`
to separate operator-supplied reference documentation from repository-pointed
context, and give evidence a shape that can carry a supplied document. Until
then a finding from such a document has nowhere to put its citation.

### Deferred, listed so the gap is on record

- **Exports.** `EXP-1`–`EXP-4` are cited by nothing: `threat-model.md` stays
  authoritative, SARIF stays the scanner export, Threat Dragon stays alpha and
  opt-in.
- **Remote fetches and passive supply chain.** `FE-5`, `FE-6`, `TR-4`: every
  fetch through the allow-list and SSRF guard, and no package manager or network
  CVE scanner is ever run.
- **Related repositories.** `RR-1`–`RR-3` are only partly carried by
  `REQ-MOD-005`.

Each would add an entry, and the catalog has to stay readable in one sitting.
They are a separate decision, not part of this change.
