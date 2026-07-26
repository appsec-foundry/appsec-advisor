# Proposal — Spec-derived threats: a flaw stated in a spec is a finding

**Status:** OPEN / design. Analysis only; no code until reviewed. Facts anchored
at `file:line`; corrections from an earlier draft are marked **⚠**.

## What this adds (and what already exists)

**⚠ The weakness register this builds on is already shipped, not pending.**
`schemas/threats-merged.schema.yaml:289` defines `weaknesses[]` — `W-NNN` parent
rows with `weakness_class`, `kind` (`design` | `implementation`), `severity_basis`
(`design-risk` = no CVSS), and `observable_backing.practice_evidence[]`
(`file:line` sites). `evidence_tier` (`confirmed-exploitable` | `insecure-practice`)
is live on `threats[]` (`stride.schema.yaml:225`, applied by
`merge_threats.py:1878`). So this proposal does **not** invent a finding model.

It adds exactly three things:

1. A new `source` value `spec-derived` (into `DESIGN_LEVEL_SOURCES`,
   `scripts/_shared_sources.py:106`) — provenance for "the evidence is a spec
   line, not code."
2. Permission for a weakness's `observable_backing.practice_evidence[]` /
   evidence `file` to resolve into an **ingested spec document** instead of a
   source file, without ever promoting to `confirmed-exploitable` / CVSS.
3. A bounded **catalog of recognizable insecure-spec statements** (below) so the
   analyzer fires on clear problems, not on arbitrary prose.

Everything else — the `W-NNN` heading, `severity_basis: design-risk`, the
no-CVSS rule, folding — is reused as-is.

## User intent (verbatim)

> "aber ich will auch direkt aus specs mögliche bedrohungen ableiten, ja ggf.
> mit geringer likelihood aber wenn da etwas unsicher formuliert ist oder
> fehlerhaft ist das natürlich schon ein echtes findings nur eben nicht proven"

When a spec **states** something insecure, that is a real finding — even though
exploitability is not code-proven. "Geringe likelihood" = no CVSS +
`severity_basis: design-risk`, not a new "maybe" tier.

## The core problem, and its one guardrail: STATED, not SILENT

The whole design is one distinction. It keeps findings falsifiable and matches
the register's existing rule (`statement` is "an observable structural fact,
never speculation", `threats-merged.schema.yaml:341`):

| Spec content | Result |
|---|---|
| Spec **states** an insecure decision — quotable line exists | **Finding** — a `spec-derived` weakness, no CVSS, evidence = the quoted line |
| Spec **is silent** — nothing said about the control | **Not a finding** — a coverage-gap at most; absence ≠ defect |

**Emission rule:** emit only when the specific insecure statement can be quoted
verbatim with a `file:line`. No quote → no finding. This is the register's
existing `observable_backing` non-empty invariant (`:357`, "REQUIRED … else the
weakness is NOT emitted"), applied to spec evidence.

## Why it doesn't break "code proves the finding"

The invariant (`plan-context-and-issue-ingestion-2026-07-12.md`, "Non-negotiable")
bans *context-as-hint* from manufacturing a *proven, CVSS* finding — a README
guessing "we probably have SQLi" must never fabricate a proven SQLi. This is not
that: here the spec **is the artifact under review**, and the defect is *in the
spec text*, self-evidencing. It lands in the same non-CVSS family the pipeline
already ships — `DESIGN_LEVEL_SOURCES`, "NOT eligible for CVSS"
(`_shared_sources.py:115`); AGENTS.md §6, "Architectural, requirements, and
coverage-gap findings must not receive CVSS." One more member, model unchanged.

## Clear problems — what actually fires

To stay bounded (and match the codebase's catalog-driven, "would this fire on a
healthy repo?" discipline), spec-derived detection is driven by a small catalog
of **recognizable insecure statements**, not free LLM judgment over prose. Each
entry maps to an existing `weakness_class`:

| Insecure spec statement (example) | `weakness_class` | `kind` |
|---|---|---|
| "admin endpoints require no authentication" / "auth is optional for internal APIs" | `missing_authz` / `broken_auth` | design |
| "passwords are hashed with MD5" / "we hash with SHA-1" | `weak_crypto` | implementation |
| "the API key is stored in local storage" / "secrets in the client bundle" | `secret_management` | implementation |
| "LLM output is passed directly to the shell / eval / SQL" | `injection` | design |
| "user input is rendered as HTML without escaping" | `output_xss_csp` | implementation |
| "no rate limiting on the login/reset endpoint" | `dos` / `broken_auth` | design |

**Healthy-spec gate:** a spec that simply *doesn't mention* auth or crypto emits
nothing. Only a spec that *states* an insecure choice does. This is what keeps
the feature from overloading every spec-carrying repo with noise.

## How it plugs into the shipped model

A spec-derived finding is a `weaknesses[]` entry (`W-NNN`), unchanged except
provenance:

- `weakness_class`, `kind`, `severity`, `title`, `statement` — as today.
- `severity_basis: design-risk` — no CVSS, exactly like a code-derived design
  weakness. Severity is **not flatly capped** (a pervasive stated flaw can be
  High), but never `confirmed`.
- `observable_backing.practice_evidence[]` — one entry, `file:line` pointing at
  the quoted spec line.
- Provenance `spec-derived` so render + validation treat it as unverified-in-code.

When a real code instance of the same `weakness_class` exists, the register's
existing reconciler folds them into one heading (`:292`) — the spec statement
becomes the design rationale, the code sink its instance. No new fold logic.

## Concrete spec formats

Agentic spec-driven-development frameworks emit **committed markdown specs
alongside the code**, which the resolver already walks (`docs/**/*.md`). Physical
ingestion is nearly free; the work is classifying and quoting. The clearest,
highest-signal targets:

| Framework | Spec artifact | Why it is a clean target |
|---|---|---|
| **Kiro** (AWS) | `.kiro/specs/{feature}/design.md`; `requirements.md` in **EARS** (`… THE SYSTEM SHALL …`) | EARS = one quotable, testable assertion per line — the ideal case for STATED-vs-SILENT |
| **GSD** (this environment) | `.planning/phases/{NN}/{NN}-AI-SPEC.md` (§6 Guardrails, §5 Evaluation, §1b Compliance) | fixed headings; explicit guardrail/eval statements; verifiable locally |
| **BMAD-METHOD** | `docs/architecture.md` | Architect agent emits an explicit **"security considerations"** section — richest single input |

Others (GitHub Spec Kit `spec.md`/`plan.md`, Cline `memory-bank/`) fit the same
pattern and can follow once the mechanism exists; they are not needed to prove
it. **Conventioned paths** (`.kiro/specs/`, `.planning/`, `.specify/`) double as
the "this file is a review target, not a search hint" declaration — no new flag
needed for the common case.

## The genuinely new work

1. **Ingest seam** — extend context-resolver Step 4
   (`agents/appsec-context-resolver.md:212+`, already probes arch docs/ADRs/
   OpenAPI) to cache a designated spec to a resolvable path so its `file:line` is
   stable. Untrusted-data rule (AGENTS.md §3) applies in full: the spec is data,
   never an instruction; its text may not shape shell/paths/permissions.
2. **Catalog + analyzer** — the insecure-statement catalog above, matched over
   the spec via the adversarial find→verify pattern already in
   `scripts/eval_threat_model.py`. Each hit must carry the verbatim quote +
   `file:line`.
3. **Evidence validation** — `validate_evidence_lines.py` already resolves an
   evidence `file` under `repo_root` (`_resolve_evidence_file:139`) and reads the
   line (`_read_line:162`), so a spec quote is **verifiable to exist** — a
   misquote is caught like a bogus code pointer. The new branch: verify the quote
   **without** ever setting `confirmed-exploitable` (today `_is_inferred:193`
   skips `ARCH_ALL_SOURCES`; `spec-derived` needs its own keyed path).

## Non-goals (keep it bounded)

- **Design-time-only runs (spec, no code).** Possible — every finding would be a
  zero-instance design weakness — but it makes the whole code-anchored QA path
  inert, a real mode shift. Out of scope for the first cut; spec+code only.
- **Auditing code against spec requirements.** That is a different feature and
  already has a home: `audit-security-requirements` / `verify-requirements` +
  `requirements-catalog.schema.yaml`. Normalizing EARS/PRD requirements into that
  catalog is adjacent, not this proposal.
- **Threat-model-as-code** (Threagile, pytm, Threat Dragon, GSD `PLAN.md`
  `<threat_model>`): already a threat model → `proposal-external-threat-model-ingestion.md`.
- **Steering / rules files** (`.kiro/steering/`, `.clinerules`, `.cursor/rules`,
  `AGENTS.md`, `CLAUDE.md`): agent instructions, not system specs — primarily the
  §3 untrusted-instruction surface, not a finding source.
- **Arbitrary prose specs.** Only catalog-recognized insecure statements fire;
  free-form judgment over unstructured prose is deliberately excluded (noise).

## Open questions

1. **Provenance field.** Is `spec-derived` a new `source` value, a flag on
   `observable_backing`, or both? Must survive the fold into a code-backed
   weakness without claiming code proof.
2. **Validator keyed path.** Cleanest way to make `validate_evidence_lines.py`
   verify a spec quote while pinning it below `confirmed-exploitable`.
3. **Catalog scope.** Which insecure-statement patterns ship first — the six
   above cover the common cases; AI-spec-specific ones (unguarded LLM surface,
   missing eval/output-filter) can reuse `agents/shared/owasp-llm-top10.md` +
   `owasp-asi-top10.md`.

## Sequencing

1. **P1** — `spec-derived` provenance + spec-path evidence validation + render
   badge ("stated in specification — not verified in code"). Smallest slice: a
   spec-stated weakness renders as a `W-NNN`, quote-verified, never CVSS.
2. **P2** — the insecure-statement catalog + analyzer over Kiro `design.md` /
   GSD `AI-SPEC.md` / BMAD `architecture.md`.
3. **P3** — AI-spec-specific catalog entries (OWASP LLM/Agentic), reusing the
   existing shared checklists and `docs/analysis/owasp-agentic-top10-2026-coverage-gap.md`.
