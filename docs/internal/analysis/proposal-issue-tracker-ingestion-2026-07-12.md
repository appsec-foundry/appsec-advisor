# Proposal: Issue-Tracker Ingestion (GitHub / GitLab Issues → Threat Model)

**Status:** Analysis only — no implementation. 2026-07-12.
**Question that started this:** *Can we feed issue-tracker findings (GitHub/GitLab issues) into the threat analysis, and how would they affect threat-model findings?*

---

## TL;DR

- **No context input affects `threats[]` deterministically today.** Every route from context → finding is soft STRIDE-LLM influence. Issues would be no exception. (verified — see §1)
- A deterministic issue loader is feasible and mirrors existing patterns (`load_related_repos.py`, `emit_dep_update_activity.py`, `load_org_context.py`).
- The clean route (`docs/known-threats.yaml`) **cannot be fed deterministically**: its schema hard-requires `stride`, `component`, `severity`, `status` — exactly the 4 fields an issue does not carry — and validates fail-loud at Phase 1. (verified — §2)
- **Option 1 (separate context section)** = deterministic, small, soft effect. Recommended MVP.
- **Option 2 (known-threats integration)** = full finding integration, but requires a new LLM classifier sub-agent (post-recon) *and* a STRIDE-analyzer prompt change for evidence-less entries. (verified couplings — §4)
- GitLab is feasible via a provider abstraction; three differences (no `glab` installed, no `author_association` equivalent, self-hosted base-URL → SSRF). (§5)

---

## 1. How context affects findings today (verified)

No context input deterministically seeds a `threats[]` row or adjusts severity/status. The only deterministic finding-adjacent effect is `status: accepted` known-threats → §11 "Accepted Risks" **doc table** (explicitly *not* a finding).

| Input | Deterministic effect | Finding creation |
|-------|---------------------|------------------|
| `docs/known-threats.yaml` | `accepted` → `meta.accepted_risks[]` → §11 table (`pregenerate_fragments.py:gen_out_of_scope`, `threat-analyst.md:1224`) | soft STRIDE-LLM only |
| `CROSS_REPO_CONTEXT` | `_compute_expectation_mismatch` detection (`load_related_repos.py:425`), self-labelled "hypothesis seed" | soft (`stride-analyzer.md:108`) |
| `.threat-modeling-context.md` prose | none | soft — all consumers are LLM agents |

Provenance fields that *do* exist (set by the STRIDE **LLM**, preserved through merge): `threats[].prior_finding_ref` (`threat-model.output.schema.yaml:651`), `threats[].source` enum incl. `known-threats` (`_shared_sources.py:104`). No `known_threat_id` field.

## 2. Why issues cannot feed known-threats deterministically (verified)

`schemas/known-threats.schema.yaml:21`:
```
required: [id, title, stride, component, severity, status, description]
```
(`evidence` optional/nullable, `:51`.)

Issue coverage of the 7 required fields:

| Field | From issue? |
|-------|-------------|
| id, title, description | ✅ trivial |
| **stride** | ❌ no STRIDE category on an issue → must be inferred |
| **component** | ❌ no architecture component → must be inferred (+ canonicalized) |
| **severity** | ❌ label ≠ Critical/High/Medium/Low taxonomy |
| **status** | ❌ GitHub state is open/closed, not open/mitigated/accepted/false-positive |

Schema validation is fail-loud at Phase 1 (`known-threats.schema.yaml:9-10`, `validate_intermediate.validate_known_threats:1083`) → an under-populated deterministic entry **aborts the run**. Therefore a raw deterministic issue→known-threats loader is impossible without a classification step.

**Unmapped component is *not* silently dropped** (`threat-analyst.md:1200`): canonicalize "miss" → key under raw ID + `KNOWN_THREATS_UNMAPPED` WARN + QA Check 5 surfaces "unaddressed". BUT such an entry is dispatched to no STRIDE analyzer → appears only in the QA "Prior Findings Not Addressed" doc table, never as a verified finding. STRIDE re-verification (`prior_finding_ref`) fires only when `component` maps to a real component.

---

## 3. Shared foundation (both options)

**`scripts/load_issues.py`** — deterministic, provider-abstracted fetch. Normalized record the loader can produce *without* inference:

```
IssueRecord:
  id: "GH-1234"           provider: github|gitlab
  title / body(~40 lines truncated) / labels[] / url
  state: open             # open-only in MVP
  author / author_association: MEMBER   # github via `gh api`; gitlab via members call
  provenance: member | external
  secret_scan: clean | redacted         # reuse scripts/secret_scan.scan_text (canonical, NOT load_org_context dup)
```

- GitHub fetch: `gh api repos/:o/:r/issues` — NOT `gh issue list --json` (verified: `authorAssociation` is not a supported json field on gh 2.4.0). Mirror `emit_dep_update_activity.py` (`shutil.which("gh")` guard, subprocess timeout, `None` when unavailable).
- Config gate in `config.json`: `issue_context: {enabled:false, provider, labels, states:[open], max_issues:20, author_associations:[OWNER,MEMBER,COLLABORATOR]}` (default off, like `external_context`).
- Security: issue bodies are attacker-controllable on public repos → prime prompt-injection vector. Default-on member/author-association filter; secret-scan; `<untrusted-data>` wrap (mandatory).

---

## 4. Option 1 vs Option 2

### Option 1 — Separate context section (deterministic)

```
load_issues.py → .issues.json
  → context-resolver Step 4k renders `## Known Issues (Tracker)`
     into .threat-modeling-context.md, <untrusted-data source="github-issues">
  → STRIDE-analyzer + threat-analyst read it like any context — SOFT
```
No schema coupling, no inference, no `prior_finding_ref`. Effect ends where existing context ends.

**Files:** `scripts/load_issues.py` (NEW) · `schemas/issues.schema.json` (NEW — validates loader output, not known-threats) · `agents/appsec-context-resolver.md` (EDIT: Step 4k + header row `:618` + Step-5 render + .gitignore block `:588`) · `config.json` (EDIT) · `tests/test_load_issues.py` (NEW) · `AGENTS.md`/`README` (EDIT). `required-permissions.yaml`: **no change** (Bash(*) + `Write(OUTPUT_DIR/.*)` cover it).

### Option 2 — known-threats integration with LLM classification

Where the classifier sits is **forced**: `component` canonicalization needs the recon component inventory (Phase 2), but the known-threats index is built in Phase 1 → classification cannot live in context-resolver. Requires a **new sub-agent after recon, before Phase-9 dispatch**:

```
Phase 1  context-resolver → .issues.json (fetch only, deterministic)
Phase 2  recon → component inventory
Phase 2½ NEW appsec-issue-classifier (LLM):
           in:  .issues.json + recon components + STRIDE enum
           infer: stride, component(→canonical), severity(label-map+LLM)
           map:   state=open → status=open ; closed → not ingested
           out:  schema-valid known-threats entries → merge into .known-threats-index.json
Phase 9  existing slicing + STRIDE re-verification fires unchanged
```

**Two confirmed extra couplings (not optional):**
1. **status ambiguity** → mitigate with **open-only** ingest (closed can't map cleanly to mitigated/accepted/false-positive).
2. **STRIDE requires an evidence pointer** (verified `stride-analyzer.md:144` "read cited evidence at the exact line", `:149` "Do not re-search the repo"). Issues have no `evidence.file` → needs a **STRIDE-analyzer prompt change**: an evidence-less branch. ⚠ **Anti-cheat constraint (non-negotiable):** the branch must be `evidence:null` → *search the component for the described weakness and anchor a real `evidence.file:line`*; **if no code sink is found, DROP the item — never raise a finding from issue prose.** The issue is a search hint, not evidence. This keeps Option 2 aligned with the code-evidence spine (`evidence_integrity` `qa_checks.py:3059`; the `challenges.yml` loophole is already closed by `validate_evidence_lines.py:144-153`). Without this constraint, Option 2 becomes an answer-key importer for test apps like Juice Shop. Real contract change on a core agent.

**Files (= Option 1 +):** `agents/appsec-issue-classifier.md` (NEW LLM sub-agent) · `agents/appsec-threat-analyst.md` (EDIT: dispatch classifier post-recon, merge into `.known-threats-index.json` `:1193`) · `agents/appsec-stride-analyzer.md` (EDIT: evidence-less branch `:144-149`) · `schemas/known-threats.schema.yaml` (maybe: `origin: github-issue` provenance). Drift-guard is harder (LLM → fixture-based). Sub-agent dispatch: per AGENTS.md §7 a checkpoint, but the plugin records no Task/Agent entries (dispatch runs under Bash(*)/orchestrator, verified) → doc, not permission, work.

### Decision matrix

| | Option 1 | Option 2 |
|---|----------|----------|
| Effect on findings | soft, no traceability | full re-verify + `prior_finding_ref` + accepted-risks |
| Determinism | full | loader yes, classification LLM |
| New LLM cost | none | +1 sub-agent pass/run |
| Core-agent edits | none | STRIDE prompt + threat-analyst orchestration |
| New files | 2 (+3 edits) | 3 (+5 edits) |
| Ordering constraint | no | yes (post-recon) |
| Fits "make LLM do less" | ✅ | ⚠ |

**Recommendation:** Option 1 as MVP. Option 2 only if provable finding integration is a real product goal. The `.issues.json` loader is identical for both → Option 1 is not a dead-end investment.

---

## 5. GitLab feasibility

Feasible via a provider-pluggable loader (`--provider github|gitlab`); normalized record, schema, secret-scan, wrapping, rendering are provider-agnostic — only the fetch adapter differs. Three differences:

1. **No `glab` installed** (verified: not on PATH) → prefer GitLab REST API + `GITLAB_TOKEN` over the CLI.
2. **No `author_association` equivalent** — member restriction needs a separate `/projects/:id/members/all` call → weaker/costlier hardening.
3. **Self-hosted base-URL** (`gitlab.example.com`) → real SSRF surface → `_url_guard.validate_target_url` (`load_related_repos.py:191`) is mandatory, unlike the fixed github.com host.

---

## Verified evidence index

- Context→finding effect: `appsec-context-resolver.md:319-330,690-693,733` · `appsec-stride-analyzer.md:108,143-166` · `load_related_repos.py:425-470` · `pregenerate_fragments.py:2934-3010` · `threat-model.output.schema.yaml:77-99,651-654` · `_shared_sources.py:104-114`
- known-threats schema/validation: `schemas/known-threats.schema.yaml:21,51,9-10` · `validate_intermediate.py:455,1083` · `threat-analyst.md:1193-1224` · `canonicalize_component_id.py:143-161`
- STRIDE evidence requirement: `appsec-stride-analyzer.md:144,149`
- permissions: `data/required-permissions.yaml:81,133` (Bash(*), Write(OUTPUT_DIR/.*), no Task/Agent entries)
- gh/glab: `gh 2.4.0` — `authorAssociation` not a `gh issue list --json` field; `glab` absent · blueprint `emit_dep_update_activity.py:172`
