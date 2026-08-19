# Repository Legacy and Pipeline Ballast Analysis

**Date:** 2026-08-19

**Status:** Point-in-time analysis; no implementation is included

**Scope:** Tracked legacy code, prompt context, runtime dispatch, obsolete fixtures,
and local generated artifacts

## Executive decision

The main cost is not untracked files. The inspected local build and run artifacts
are ignored by Git and do not enter a commit or plugin release. They consume local
disk space only because `.gitignore` prevents tracking but does not delete them.

The highest-value tracked cleanup is concentrated in five changes:

1. Remove the legacy producer generation and every silent fallback to it.
2. Dispatch the small Management Summary renderer for default Quick runs instead
   of loading the complete threat renderer.
3. Replace the legacy Stage-3 safety and completion slices with bounded thin
   runtimes while preserving every deterministic and security gate.
4. Remove the unconsumed `_chain-skeleton.md` artifact path and its unreachable
   implementation.
5. Remove the documented but non-functional `--qa-scan-repo` option, or implement
   it under a separate product decision. Removal is the recommended outcome.

**Maintainer direction recorded on 2026-08-19:** WP7 parity work was intentionally
skipped. The legacy producer is not a supported rollback strategy and must be
retired. Modes that have no compact implementation must fail explicitly or be
ported; they must not silently select the legacy runtime.

## Method

This analysis used repository references, live dispatch conditions, file sizes,
ignored-file status, and existing contracts. Static token estimates use the rough
planning conversion of four bytes per token. They indicate context scale, not
provider billing or measured cache behavior.

The governing contracts are:

- `REQ-CTX-002`: shorten a prompt that exceeds its budget; do not raise the budget.
- `REQ-CTX-003`: lazy-load phase groups and preserve stable-to-volatile prompt order.
- `REQ-FLW-003`: validate required artifacts at every stage boundary.
- `REQ-FLW-004`: keep producer retries bounded by their contract.
- Decisions `CE-1` through `CE-5`: bound, list, and cache prompt surfaces.
- Principles `P-1`, `P-2`, `P-3`, and `P-6`: keep one deterministic control plane
  and derive rather than ask a model to author deterministic state.

The existing context-reduction plan explicitly defers Stage-2 through Stage-4
admission work to WP6. Its repository status still describes WP7 context-v2
incremental/resume parity and legacy-switch removal as deferred and not
implemented. That text does not reflect the maintainer decision above: WP7 is not
to be completed as a parity project. The replacement migration is a single-runtime
cutover that removes the fallback and deliberately revisits the generation-scoped
decisions.

## Measured context surfaces

| Surface | Size | Observation |
|---|---:|---|
| `skills/create-threat-model/SKILL-impl.md` | 381,902 bytes | Legacy implementation body still used in bounded slices |
| `agents/appsec-threat-renderer.md` | 93,510 bytes | Loaded by default Quick Stage 2 because parallel specialist dispatch is disabled |
| `agents/appsec-ms-renderer.md` | 2,540 bytes | Small specialist that imports only the Management Summary contract slice |
| Management Summary contract slice, renderer lines 128-389 | 28,804 bytes | Specialist plus slice totals about 31.3 KB |
| Security architecture contract slice, renderer lines 390-715 | 48,515 bytes | Used only when architecture enrichment is required |
| Legacy Stage-3 safety slice, `SKILL-impl.md` lines 3462-3764 | 23,524 bytes | Loaded on every non-dry full/rebuild path |
| Legacy Stage-3 QA/repair continuation, lines 3765-4169 | 31,184 bytes | Loaded only when QA or repair needs it |
| Legacy completion slice, lines 4208-4795 | 37,404 bytes | Loaded when the run completes |
| `agents/appsec-threat-analyst.md` | 152,206 bytes | Legacy Stage-1 producer and compatibility branches |
| `agents/appsec-stride-analyzer.md` | 69,302 bytes | Legacy per-component STRIDE analyzer |
| `agents/appsec-stride-analyzer-v2.md` | 11,992 bytes | Bounded context-v2 counterpart |

The default non-dry compact runtime therefore still loads about 60.9 KB of
legacy Stage-3 and completion text, approximately 15,200 static input tokens.
A QA/repair path adds about 31.2 KB, approximately 7,800 tokens.

## Priority 1: implement next

### P1.1 — Remove the legacy producer generation and fallback

**Why it still exists.** The legacy generation is historical rollback and parity
machinery. It is not needed by the default full/rebuild path. At present it is
selected by `APPSEC_CONTEXT_V2=0`, by `APPSEC_THIN_ORCHESTRATOR=0`, and by modes
that `compact_runtime_eligible` excludes. The exclusion currently covers dry-run,
resume, max-wall-time, max-cost, and live-phase execution. Incremental mode also
selects the legacy generation because `resolve_runtime_generation` supports
context-v2 only for full/rebuild. Rerender already has a compact top-level runtime,
although its persisted generation label remains legacy because it does not run a
new Stage-1 producer.

The headless wrapper already refuses to resume a persisted context-v2 run rather
than mixing generations. This demonstrates that the safe behavior is explicit
failure, not a transparent legacy fallback.

**Maintainer decision.** Do not implement WP7 merely to preserve generation
parity. Remove the legacy generation and make the compact/controller runtime the
only runtime. Preserve a feature only by porting it to that runtime. Otherwise
reject the unsupported invocation with a precise migration message.

**Recommended cutover.** Treat this as an explicit compatibility migration:

1. Remove the `APPSEC_THIN_ORCHESTRATOR=0` and `APPSEC_CONTEXT_V2=0` opt-outs.
2. Make runtime and generation resolution incapable of returning `legacy` for a
   new invocation.
3. Enumerate incremental, resume, dry-run, max-wall-time, max-cost, live-phase,
   and rerender behavior. Port each supported mode or fail before dispatch; never
   restart it through the legacy producer.
4. Replace generation-coexistence decisions `ST-3` and `OR-1` with the resulting
   single-owner invariant, and update the orchestration contract and guards in the
   same migration.
5. Remove legacy agent recursion, compatibility prompt branches, legacy runtime
   selection tests, and producer files only after the route has no reference to
   them.

**Exit criteria.** No configuration or mode can dispatch the legacy analyst or
legacy STRIDE analyzer. Unsupported modes fail closed before model dispatch and
state mutation. Full/rebuild and rerender remain on the compact controller path.
Tests prove that the removed environment opt-outs cannot re-enable the old
generation.

### P1.2 — Use the Management Summary specialist for default Quick Stage 2

**Evidence.** `orchestration_controller.py` selects parallel specialists only
when `enrich_arch_fragments` is true, parallel rendering is enabled, and no retry
is pending. Quick depth sets `enrich_arch_fragments` to false by default. The
fallback consequently dispatches the complete 93.5 KB threat renderer even though
Quick needs the Management Summary work and retains the deterministic security
architecture scaffold.

The Management Summary specialist and its imported contract total about 31.3 KB.
Replacing the complete renderer on this path removes about 62.2 KB, or roughly
15,500 static input tokens, from each default Quick Stage-2 dispatch.

**Recommended change.** Add a Quick Stage-2 dispatch that invokes only
`appsec-ms-renderer`. Keep the existing deterministic architecture fragment and
the controller-owned compose, prose-fix, QA-autofix, and validation tail.

**Exit criteria.** Golden Quick output retains every required section, Management
Summary fragment, validation result, secret gate, and completion invariant. A
cut-off or invalid fragment must still enter the bounded repair behavior instead
of silently degrading.

### P1.3 — Add thin Stage-3 safety and completion runtimes

**Evidence.** `SKILL-full-runtime.md` already uses thin Stage 1 and Stage 2, but
loads Stage 3 and completion from `SKILL-impl.md`. The controller already owns
mitigation completion, fragment validation, deterministic pregeneration, strict
composition, verdict emission, prose fixes, QA autofix, and checkpointing in its
compose tail. The resident legacy slices still describe orchestration around many
of these operations.

**Recommended change.** Create bounded `SKILL-thin-stage3.md` and
`SKILL-thin-completion.md` surfaces. Leave semantic review decisions with the
review agents and move no security decision into permissive prose. The thin Stage
3 must retain the hard secret-leak gate even when Quick, `--no-qa`, or PR mode
skips the remaining QA work. Preserve the documented mutation order:

1. strict compose;
2. prose fixes;
3. QA autofix;
4. completion placeholder patching;
5. read-only final structure and integrity gates.

**Exit criteria.** Prompt-budget tests list the new live surfaces. Quick, Standard,
Thorough, QA-disabled, repair, architect-review, cut-off, and completion paths have
equivalent gate outcomes. No required validator or cleanup action becomes optional.

### P1.4 — Remove `_chain-skeleton.md`

**Evidence.** `pregenerate_fragments.py` states that no agent consumes this file.
`gen_attack_walkthroughs_skeleton` returns the normal deterministic walkthrough
output before its historical body, leaving the old body unreachable. The registry
still exposes `_chain-skeleton.md`, and the legacy Stage-3 and recovery slices still
request it. Approximately 17.7 KB of helper code sits in the obsolete helper
section, with tests maintaining otherwise dead behavior.

**Recommended change.** Remove the registry entry, Stage-3 requests, obsolete
helper implementation, QA exceptions that exist only for this artifact, and tests
that solely preserve it.

**Compatibility boundary.** Do not remove the report anchor
`#critical-attack-chain`. That anchor is a separate public deep-link compatibility
contract for the live Critical Attack Tree.

### P1.5 — Retire the `--qa-scan-repo` no-op

**Location.** The parser and summary handling live in `scripts/resolve_config.py`;
the user-facing claim is in `skills/create-threat-model/HELP.txt`; the compatibility
description is in `SKILL-impl.md`; and `tests/test_qa_depth_profile.py` confirms the
old Pass 2c producer is retired.

**Impact.** A caller can request a deep repository QA scan and receive a successful
configuration summary even though no QA consumer performs that scan. This can
create false confidence about unlinked file-reference coverage.

**Status.** Open product-contract defect. No implementation consumes the resolved
flag.

**Recommended change.** Remove the CLI flag, help text, configuration-summary
entry, obsolete scan-exclude binding, and compatibility tests. Record the visible
CLI removal in the changelog. Implementing a new repository-wide QA pass would be
a separate bounded-work and evidence-design change, not cleanup.

## Priority 2: follow-up cleanup

| Candidate | Recommendation | Main guard |
|---|---|---|
| `ENRICH_TOP_MITIGATIONS` | Retire its authoring contract; no live resolver or dispatch sets it | Decide whether the composer keeps one-release read compatibility for old fragments |
| `_render_threat_hypotheses_table` | Remove the uncalled production helper and tests that call only the helper | Confirm no proposal is being activated in the same release |
| Architect reviewer Check 9 and `architectural_findings[]` references | Rewrite for F-only `architectural_theme` findings and renumber checks | Preserve Stage-4 read-only and blocking-repair-plan boundaries |
| `APPSEC_TRIAGE_DETERMINISTIC` in dispatch prompts | Remove the ineffective dispatch signal only | Keep the script's standalone debug flag and controller-owned `--force` execution |
| `top-threats-architecture.md` authoring instructions | Remove producer instructions; consider temporarily retaining composer read compatibility | Verify old-fragment rerender compatibility before deleting the fallback |
| `critical-attack-chain.json` fixture files | Remove obsolete fixture artifacts superseded by `ms-critical-attack-tree.json` | Keep the live legacy Markdown anchor |
| Ruff ignore for `scripts/harvest-requirements.py` | Delete the stale per-file ignore for the nonexistent dashed path | Run lint configuration checks |

These changes are smaller than WP6 but should follow the P1 runtime work so that
test updates describe the final producer ownership rather than an intermediate
state.

## Priority 3: planned compatibility work

### WP7 status clarification

WP7 was the proposed work package for context-v2 incremental and resume support,
legacy-switch removal, and release-default rollout. The repository implemented
generation selection, persistence, schema-version binding, and incompatible
generation rejection. It did not implement context-v2 incremental/resume parity;
the plan marks that remainder as deferred.

Per maintainer direction, that remainder was skipped rather than left as required
future work. The cleanup must therefore retire the legacy generation directly and
preserve fail-closed behavior. It must not describe WP7 parity as a prerequisite.
If incremental or resume is still a supported product feature, it needs a compact
implementation under a separate scoped change. If it is not supported, resolution
must reject it clearly instead of invoking legacy code.

### Other compatibility candidates

- Remove `RENDER_ONLY=true` only after proving that no supported recovery or
  external invocation uses the legacy Stage-2 signal. The single-runtime cutover
  should remove it if no such caller exists.
- Remove documentation-only taxonomy fields `signal_required` and
  `signal_patterns`, or implement them under an explicit Phase-9 gating decision.
- Remove the reserved `additional_components` schema field only through the
  structured-artifact compatibility process.
- Decide whether `scripts/migrate_v3_to_v4.py` is a supported manual tool. If it
  is supported, document and test it; otherwise remove it.
- Update or remove `tests/HAIKU_COVERAGE_TEST.md`, which uses the deprecated
  `haiku-economy` alias and has no live test role.
- Verify whether the two old tracked patch files under `docs/internal/analysis/`
  still preserve unique rationale before archiving or removing them. Do not use
  patch applicability alone as proof that their changes landed.

## Priority 4: do not treat as repository cleanup

### Ignored local artifacts

The following point-in-time local artifacts were confirmed by
`git status --ignored` to be ignored:

| Local path | Approximate size |
|---|---:|
| `scripts/node_modules/` | 504 MB |
| `tests/__pycache__/` | 12 MB |
| `scripts/__pycache__/` | 5.5 MB |
| `.ruff_cache/` | 2.4 MB |
| `.pytest_cache/` | 1.3 MB |
| `tests/fixtures/e2e/_repair-run/` | 15 MB |
| `.cache/` | 6.4 MB |
| `docs/security/` | 3.1 MB |
| accidental `--level/` directory | 12 KB |

They are local disk-cleanup candidates, not tracked code or release ballast.
Deleting them is optional and should not be mixed into a repository-cleanup
commit. `.coverage-data/`, seen in the earlier inventory, was absent when this
document was written.

`git lfs prune --dry-run` reported 9 files and 26 MB as locally pruneable. That
is also optional workstation maintenance and requires normal remote-retention
checks before a real prune.

### Tracked material to retain by default

- Do not delete `agents/appsec-authnz-analyzer.md`; it is used by the separate
  `authnz-review` skill even though the create-threat-model pipeline does not
  dispatch it.
- Do not deduplicate fixtures by hash alone. Identical fixtures frequently
  isolate different test contracts.
- Do not bulk-delete `docs/internal/analysis`, `docs/analysis`, `docs/proposals`,
  or `specs/changes`. The four trees currently contain 104 files, and decision
  entries link to analysis documents as rationale.
- Do not remove security, schema, QA, or secret gates for prompt or wall-time
  savings.

## Recommended implementation sequence

Use separate, reviewable changes:

1. Perform the single-runtime cutover: remove opt-outs and fallbacks, define each
   special mode as compact-supported or explicitly unsupported, and migrate the
   generation-scoped contracts and guards.
2. Remove the now-unreachable legacy analyst, analyzer, recursion, compatibility
   prompt branches, and route tests.
3. Remove `_chain-skeleton.md`, the stale Ruff ignore, and clearly obsolete
   fixtures or uncalled helpers whose references are fully traced.
4. Remove `--qa-scan-repo` as a user-visible CLI correction.
5. Change the default Quick renderer dispatch and replay the Quick golden fixture.
6. Introduce thin Stage-3 and completion runtimes with explicit prompt budgets.
7. Perform the architect-reviewer and remaining prompt-contract cleanup.

For each changed production file, run `scripts/check_specs.py --for <path>` first,
trace producer, artifact contract, consumer, validator, tests, permissions, and
cleanup, and preserve unrelated working-tree changes. Run targeted tests after
each slice, followed by `make lint`, `make test`, and `make check` for the
cross-module runtime changes.
