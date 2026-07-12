# Implplan — Weakness-Class Evidence Model + Systemic Posture Verdict

**Status:** OPEN / not started. Implements
`proposal-weakness-class-evidence-model.md` (model + locked decisions §9).
Scope per author decision: **the full model incl. Layer-2**, delivered as one
plan, built in the P1→P4 order below (each phase leaves the suite green and the
pipeline runnable).

All `file:line` targets are from the proposal's verified fact base; confirm exact
insertion points at implementation time (line numbers drift). Contract rule
(AGENTS.md §4): every schema/producer/consumer/test moves together.

## Invariants (must hold after every phase)

- **I1** No user-facing artifact contains the word/category "hypothesis"
  (fragment, schema label, section, heading). Grep-guarded in QA.
- **I2** Nothing is emitted without observable backing (`absent_control_signal[]`
  OR `practice_evidence[]` OR a confirmed sink). Speculation is dropped.
- **I3** CVSS only on `confirmed-exploitable` instances (existing gate,
  `threats-merged.schema.yaml:240`); never on a weakness.
- **I4** Headline count is **post-consolidation** — a weakness + its instances,
  never per raw practice site (§4d-bis). Count can only *drop or hold* for the
  redundant/pervasive cases vs today.
- **I5** Determinism preserved — reconciler/folding/count are Python, not LLM
  (AGENTS.md: prefer deterministic Python).

---

## P1 — Two-type register + merger reconciler (load-bearing)

Everything else hangs on this. Fixes the juice-shop contradiction and prevents
count explosion.

### P1.1 Schema

- `schemas/threats-merged.schema.yaml` + `schemas/threat-model.output.schema.yaml`:
  - Add `evidence_tier` enum `[confirmed-exploitable, insecure-practice]` on
    instance-level threats (distinct from the existing `evidence_check`
    verification enum — do NOT overload it).
  - Add `kind` enum `[design, implementation]` for weakness rows.
  - Add `severity_basis` enum `[confirmed, design-risk]`.
  - New `weakness` object: `{id, weakness_class, kind, statement, severity,
    severity_basis, implementation_strategy?, observable_backing:
    {absent_control_signal[]?, practice_evidence[]?}, instances[]}` where
    `instances[]` = confirmed-exploitable threats (own F-NNN, file, line, cvss,
    poc_hint).
  - Retire top-level `threat_hypotheses[]` (keep the field readable for one
    release for back-compat; stop *producing* it — see P1.3).
- `schemas/stride.schema.yaml`: add `evidence_tier` so analyzer output can carry
  it (default `confirmed-exploitable` when a sink is proven, else
  `insecure-practice`).
- **Verify:** `python -m jsonschema` self-check on each schema; existing schema
  tests updated and green.

### P1.2 Merger reconciler (`scripts/merge_threats.py`) — the pivot (§4d-bis)

- Change grouping key from `(CWE, STRIDE, cwe-family)` (`:748`) to
  **`(weakness_class, scope)`**; weakness becomes the parent, raw threats/scanner
  hits become `instances[]` (confirmed) or `practice_evidence[]` (observed,
  non-exploitable).
- Fold the arch-coverage **design signal** into the same weakness heading here
  (the reconciler): a `(weakness_class, component)` that already has ≥1
  confirmed instance **absorbs** the matching design signal as the weakness's
  `statement` + `absent_control_signal[]`; it is never emitted as a peer.
- Reuse `_match_consolidation_group` + `consolidation-groups.yaml` (`:853`) as
  the class↔CWE map (every group already keys a weakness class); extend groups
  so each of the 9 `weakness-classes.yaml` clusters has one.
- Map `weakness-classes.yaml` CWEs → `weakness_class` for grouping
  (`_classify_threat_cluster` `compose_threat_model.py:5087` already does this;
  lift the mapping into a shared helper both merger and composer import).
- **Scope-granularity decision (resolves proposal §4d-bis open item):**
  - `kind: design` weaknesses are **app-wide** (a missing *central* control is
    global by nature) → one weakness per class, `affected_components[]` lists the
    spread.
  - `kind: implementation` groups **per component**, BUT rolls up into a single
    app-wide `kind: design` weakness when the same class appears in **≥2
    components AND no central control is present** (that co-occurrence *is* the
    systemic signal). Threshold `SYSTEMIC_SPREAD_MIN = 2`, in
    `data/weakness-classes.yaml` per-class override allowed.
- **Verify:** unit test — feed 2 confirmed CWE-89 (login/search) + 1 arch SQLi
  signal → assert exactly **1** weakness `injection/SQLi`, `kind: design`, 2
  `instances[]`, 0 top-level hypotheses, `severity_basis` on the weakness.

### P1.3 Bridge routing (`scripts/arch_coverage_to_threats.py`)

- Stop routing unpromoted design signals to `threat_hypotheses[]` (`:432-453`).
  Instead emit a normalized **design-signal record** (class, component,
  statement, `absent_control_signal[]`, strategy) that `merge_threats.py`
  consumes in P1.2.
- Keep the `proof_state`/`confidence` gate (`:188,197`) only as the
  emit-or-drop guard for I2 (no observable absent-control signal → drop).
- **Verify:** grep — `threat_hypotheses` no longer written by the producer;
  design signals reach the merger.

### P1.4 Count + composer (`scripts/compose_threat_model.py`)

- Render a **weakness as a heading** with its `instances[]` and
  `practice_evidence[]` beneath — never three peers (extend the §8 card/register
  path; the class-heading pattern mirrors existing `_build_threat_card`).
- Headline count (management_summary, `_render_management_summary:9217`): one
  total **+ breakdown** "N findings — X confirmed-exploitable · Y implementation
  · Z design", computed post-consolidation. Confirmed-exploitable = the only
  CVSS/headline-eligible subset for CVSS purposes, but all three count.
- Ranking (`triage_compute_ranking.py`): allow `severity_basis: design-risk`
  weaknesses into `findings_ranked[]` and permit a design-risk Critical to sort
  #1 (locked decision §9.3); tag visually distinct from confirmed Criticals.
- **Verify:** re-render juice-shop fixture → §8 shows "Insecure SQL handling"
  with 2 instances, no separate SQLi hypothesis anywhere; count line shows the
  breakdown; I1 grep clean.

### P1.5 QA + tests

- QA (`scripts/qa_checks.py`): add I1 grep guard (no "hypothesis" user-facing),
  I2 guard (no weakness without observable_backing), I4 guard (count == distinct
  weaknesses + confirmed instances).
- Golden regen for the fixture + juice-shop example.
- **Verify:** `make test` + targeted `qa_checks` subset green; baseline failures
  separated per CONTRIBUTING.

---

## P2 — Implementation-strategy axis (vetted / misused / home-grown / none)

### P2.1 Recon inventory
- Extend `scripts/recon_patterns.py`: a library/protocol inventory per domain
  (authn: passport/next-auth/openid-client/jsonwebtoken; input-val:
  zod/joi/express-validator; crypto: argon2/bcrypt/libsodium; ORM presence).
  Cat-9 OAuth (`scan_oauth_oidc:489`) already separates surface vs 15 misuse
  subcategories — the template for the misuse layer.
### P2.2 Misuse detectors (Cat-N functions, not new scripts)
- New `scan_*` functions in `recon_patterns.py` for co-occurrence misuse the
  rule catalogs can't express: crypto (bcrypt present but low rounds), input-val
  (schema imported but sink bypasses it), authn (verify present but decode path
  bypasses it). LLM sink misuse stays STRIDE-only.
### P2.3 Classification
- `implementation_strategy` field populated by: lib detected + no misuse →
  `standard-vetted` (exculpatory, lowers weakness severity, can suppress a
  design weakness → Fall B); lib + misuse → `standard-misused`; bespoke pattern
  + no lib → `home-grown` (raises severity); nothing → `none`.
- **Rule (I2-adjacent):** `standard-vetted` requires *detected lib* **AND** *no
  misuse signal* — never library-presence alone.
- **Verify:** fixture with parameterized ORM → SQLi design weakness suppressed
  (Fall B); fixture with hand-rolled JWT → `home-grown`, severity bumped.

---

## P3 — Close deterministic scanner gaps

### P3.1 Crypto rule pack (biggest gap — zero rules today)
- New `data/crypto-checks.yaml` run through the **existing catalog-driven
  `source_auth_scanner.py` engine** (no new Python): md5/sha1 as password hash
  (CWE-328/916), `Math.random()` for tokens (CWE-330), `alg:'none'` (cross-ref
  authn), ECB mode, low bcrypt rounds. Include `counter_patterns` (non-security
  hashing) to avoid FPs.
- Overlap rule: hardcoded key CWE-798 stays in Authn/Secrets, cross-ref only.
### P3.2 Input-val gaps
- Add path-traversal (CWE-22) + XXE (CWE-611) rules to
  `data/source-auth-checks.yaml` (INJ-004/005), same engine.
### P3.3 Optional
- Weak-JWT-secret rule (no detector today; AUTHZ-007 is an algo-allowlist check).
### P3.4 Contract
- `data/required-permissions.yaml` + `tests/test_check_permissions.py` for any
  new scanner invocation (AGENTS.md:98,318).
- **Verify:** crypto fixture (md5 password hash) → 1 confirmed/insecure-practice
  instance under a `weak_crypto` weakness; permissions test green.

---

## P4 — Layer-2 systemic posture verdict

### P4.1 Fusion script (new, deterministic)
- New `scripts/build_posture_verdict.py`: per `architectural_theme` (principle,
  enum `architecture-coverage.schema.json:940`), fuse **control-effectiveness**
  (`architectural-controls.yaml` adequate/partial/weak/missing) ×
  **recurrence** (instance count + component spread) × **worst evidence_tier** ×
  **implementation_strategy** → a principle row.
- **Scoring rubric (resolves proposal §7.4 open item):**
  - `VIOLATED` — control missing/weak **AND** (≥1 confirmed instance OR pervasive
    home-grown/none design weakness across ≥2 components).
  - `WEAK` — control partial, or isolated instances with a present-but-bypassed
    control.
  - `ADEQUATE` — control adequate, no confirmed instances, standard-vetted.
  - Rubric lives in a versioned `data/posture-rubric.yaml`, calibrated against
    juice-shop + synthetic fixture (not a magic number).
### P4.2 meta_findings generalization + missing renderer
- Generalize `build_meta_findings` category enum
  (`threat-model.output.schema.yaml:853`, 3 supply-chain buckets) to any
  principle theme.
- **Wire the missing renderer** — no composer consumes `meta_findings` today
  (latent bug); add `_render_*` in `compose_threat_model.py` +
  `sections-contract.yaml` entry.
### P4.3 Surfaces
- **Security Principles** verdict table (scored) + **Top Systemic Risks** ranked
  by recurrence/principle, in `management_summary`. The existing LLM `verdict`
  blockquote + `architectural_anti_patterns` callout now *narrate the computed
  verdict* instead of inventing one.
- **Verify:** juice-shop → InputValidation = VIOLATED (systemic) surfaces above
  isolated findings; a pervasive design weakness ranks #1 (§9.3).

---

## Cross-cutting

- **Migration / back-compat:** P1 can ship alone and already fixes the reported
  bug; `threat_hypotheses[]` readable-but-unproduced for one release, then
  removed. Incremental-rescan reconciliation (prior-finding carry) must map old
  hypothesis entries → new design signals.
- **Golden/e2e:** regen fixtures each phase; gate release on `e2e-full-standard`.
- **Event log:** route any new script logging through `scripts/event_log.py`.
- **Definition of done per phase:** suite green, pipeline runs end-to-end on the
  fixture, invariants I1–I5 hold, golden updated.

## Risk register

- R1 Count regression the *other* way (over-merging hides real distinct bugs) —
  guard: instances keep individual F-NNN + file:line; a weakness never hides an
  instance's severity.
- R2 `standard-vetted` false-negatives (lib present, subtly misused) — mitigated
  by the misuse layer (P2.2); when unsure, do NOT grant vetted.
- R3 Crypto FPs (md5 for non-security hashing) — counter_patterns (P3.1).
- R4 Posture rubric miscalibration — versioned rubric + fixture calibration,
  never inline constants.
- R5 Reconciler scope-granularity mis-collapse — `SYSTEMIC_SPREAD_MIN` per-class
  override + unit tests on multi-component fixtures.
