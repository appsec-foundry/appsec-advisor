# Can Stage 2 run more than two parallel renderers?

Date: 2026-07-27
Scope: `PARALLEL_RENDER=true` path (Agent S `appsec-secarch-renderer` + Agent M `appsec-ms-renderer`).
Evidence: one measured production run (juice-shop, standard depth, sonnet-4-6) — `.agent-run.log`
and `.hook-events.log` in the latest juice-shop output directory. Single sample; treat the absolute
numbers as indicative. The measured critical path is solid for this run, but its shape is not yet
proven across repositories or renderer configurations.

Verification status: the code and contract claims were re-checked on 2026-07-30 against the
resolver, controller, composer, pregenerator, rerender runtime, secarch agent definition, §6
authoring contract, and SCA-practice producer. All of them hold.

**The measurements below are not reproducible.** Their source run no longer exists: no log in any
juice-shop output directory carries the cited timestamps. The surviving run in that directory is a
different one (8 STRIDE components in the text below, 6 on disk) and disagrees on figures the
recommendation leans on:

| Measured below | Surviving run on disk |
|---|---|
| Stage 2 = 14m49s | 13m24s |
| Agent M idle 8m53s | ~2m50s between the last MS write and Agent S returning |
| Agent M writes four fragments | five |
| §6 fragment 53,292 characters, 34 F-IDs | 71,555 characters, 31 F-IDs |
| §6.11 12,769 · §6.2 8,603 · section total 51,868 | 14,639 · 13,684 · 70,130 |
| 3× `RUN_ABORTED` on `validate_intermediate`, 3m58s lost | no `RUN_ABORTED`, no `INVALID` in either log |
| Phase 10a 13m03s · 10b 4m40s · Phase 8 1m48s · Phase 10 38s | 9m17s · 5m54s · 4m35s · 4m11s |

Only the deterministic parts match: §6.12 (437 characters) and the chapter preamble (1,424 vs
1,425). Treat every absolute number below as a lost single sample, not as a baseline. Re-measure
before using any of them; do not re-derive them speculatively.

The structural findings do not depend on those numbers and stand: the two implementation blockers,
the §6.2/§6.3 coupling, the incomplete rerender mode containment, and the SCA producer defect.
Step 0 (the SCA producer fix) has since been implemented.

**Depth scope — measured at standard; normally applicable to standard and thorough.**
`resolve_enrich_arch_fragments` turns `enrich_arch_fragments` off by default at quick depth, and
`prepare_stage2` gates the parallel path on that flag. The quick scaffold still contains H3
sections and some `NARRATIVE_PLACEHOLDER` comments; they do not reach a new quick report because
the composer suppresses §6 entirely when no rich standard/thorough section can be carried forward.
When rich prior §6 content exists, quick preserves that content instead. `--enrich-arch` can still
enable the parallel dispatch at quick depth, while the composer's independent depth gate can
suppress the newly enriched section when no rich prior exists. That forced-quick path is
internally inconsistent and must be tested or fixed separately; it is not evidence for the
performance conclusions below.

## Short answer

For the measured run, extra parallelism can shorten the critical path only by splitting
**§6 Security Architecture**. Adding an MS-side agent would not help this sample because Agent M
finishes almost nine minutes before Agent S. That is not a repository-independent result:
requirements compliance and the other conditional MS fragments can change Agent M's workload.

A §6 split appears feasible, but quality parity is unproven. It is *not* a dispatch-only change:
it needs contracted part artifacts, validation, an exact manifest, and a deterministic assembler
because two agents cannot write `security-architecture.md` concurrently. The recommendation is to
remove avoidable evidence lookup first, measure again, and build the split only if the measured
SecArch path remains materially above Agent M.

## Full-run context — where the 1h43m actually goes

Same run, derived from `PHASE_START` / `PHASE_END` pairs in `.agent-run.log`. Run window
03:20:24 – 05:03:47 = 103m23s; the segments below account for 101m14s (the remainder is
inter-phase gaps of a few seconds each).

| Segment | Wall | Share |
|---|---:|---:|
| Phase 9 — STRIDE fan-out, 8 components (incl. ~2m50 dispatch latency + ~1m36 resume) | 18m55s | 18.3 % |
| **Stage 2 — parallel render** (secarch 13m12s ‖ MS 4m14s) + compose | 14m49s | 14.3 % |
| Phase 10a — evidence verification (sampled) | 13m03s | 12.6 % |
| Abuse-case verification fan-out (4 agents) | 7m15s | 7.0 % |
| Stage 3 — QA review | 6m39s | 6.4 % |
| Phase 9 — STRIDE merge | 5m51s | 5.7 % |
| Phase 1+2+2.5 — context resolution, recon, config/IaC scan (parallel) | 4m47s | 4.6 % |
| Phase 10b — triage validation + ranking | 4m40s | 4.5 % |
| Completion summary + final structure/integrity gates | 4m30s | 4.4 % |
| Stage-1 gate retries (3× `validate_intermediate` fail) + auto-emitters | 3m58s | 3.8 % |
| Skill startup, config resolve, permission gates | 3m18s | 3.2 % |
| Phase 2.7+3+4 — actor layer, architecture modeling, walkthrough prep | 3m13s | 3.1 % |
| Phase 5+6+7 — assets, attack surface, trust boundaries (parallel) | 3m05s | 3.0 % |
| Phase 9 — STRIDE dispatch prep | 3m04s | 3.0 % |
| Phase 8 — security controls catalog | 1m48s | 1.7 % |
| Phase 11 — Stage-1 finalization substeps 1-3 | 1m17s | 1.2 % |
| Phase 10 — scan synthesis | 38s | 0.6 % |
| Phase 2.6 — architecture coverage pre-pass | 24s | 0.4 % |

§6 enrichment alone is 13m12s = **12.8 % of the whole run** — second-largest single work item
after the STRIDE fan-out, and the largest one that is a single agent rather than a fan-out.

Worth noting separately: the 3m58s block at 04:25:55 is pure loss. `validate_intermediate.py`
failed three times with `INVALID: threats[66]: 'scenario' is a required property` (logged as
`RUN_ABORTED`) before the run recovered. That is a producer-side schema defect, not a
performance-tuning question, and it is cheaper to fix than anything discussed above.

**Unverified.** No `RUN_ABORTED` and no `INVALID` line survives in either log on disk, so this item
cannot be confirmed or costed. If the defect is real it will reappear; do not chase it from here.

## Measured Stage-2 timeline

| Event | Time (UTC) |
|---|---|
| Phase 11 start | 04:37:49 |
| Agent S spawned | 04:38:29 |
| Agent M spawned | 04:38:34 |
| Agent M writes its four fragments | 04:41:21 – 04:42:04 |
| Agent M done (compactness gate PASS) | 04:42:48 |
| **Agent M idle from here** | **04:42:48 – 04:51:41 (8m53s)** |
| Agent S single `Write` of `security-architecture.md` (53,292 chars) | 04:51:31 |
| Agent S done | 04:51:41 |
| Compose + phase end | 04:52:38 |

Stage 2 wall: **14m49s**. Critical path: Agent S, **13m12s**.

Agent S decomposes roughly as:

- ~31s spawn + initial contract, prose-reference, YAML, and scaffold reads
- ~8m15s evidence queries and planning, including long windows without a tool call
- ~4m16s generating one 53,292-character `Write`

## Where the time actually goes

Two facts constrain any speed-up:

**1. The critical path is Agent S alone.** A third agent that takes work off Agent M (e.g. splitting
`security-posture-attack-paths.json` or `requirements-compliance.md` out of the MS role) changes
nothing — that work already fits inside Agent S's shadow.

**2. Roughly a third of Agent S's output is echoed scaffold.** The deterministic scaffold from
`gen_security_architecture_v2` is 39,059 characters / 39,824 UTF-8 bytes, of which 22,243
characters are the 75 `NARRATIVE_PLACEHOLDER` instruction comments that get replaced. The frozen
structure the agent must reproduce verbatim is therefore **16,816 characters** (headings, anchors,
`Controls covered`, `Implemented controls`, finding lists, the §6.1 table, and the chapter
preamble). Final fragment: 53,292 characters / 53,784 UTF-8 bytes = 16.8k echoed characters +
36.5k characters of new prose. The echo exists because the agent has only `Write` (no `Edit`) and
owns the whole file.

Section sizes in the produced fragment (basis for any split):

| Section | Characters incl. H3 | H4 | Mermaid |
|---|---:|---:|---:|
| 6.1 Security Control Overview (MECHANICAL-FROZEN) | 2,445 | 0 | 0 |
| 6.2 Identity and Authentication | 8,603 | 2 | 2 |
| 6.3 Session and Token | 4,903 | 2 | 1 |
| 6.4 Authorization | 3,473 | 1 | 0 |
| 6.5 Query Construction / Data Access | 2,445 | 1 | 0 |
| 6.6 Input Boundary Validation | 2,171 | 1 | 0 |
| 6.7 Output Encoding and Rendering | 3,257 | 2 | 0 |
| 6.8 Browser and Cross-Origin | 3,756 | 3 | 0 |
| 6.9 Cryptography, Secrets, Data Protection | 2,792 | 1 | 0 |
| 6.10 File, Parser, Outbound Request | 3,033 | 1 | 0 |
| 6.11 Operations, Runtime, Supply Chain | 12,769 | 7 | 0 |
| 6.12 Real-time / Not Applicable | 437 | 0 | 0 |
| 6.13 Defense-in-Depth Summary | 1,784 | 0 | 0 |

## Quality and contract risks of an N-way §6 split

Ranked by severity. The first two are implementation blockers.

**BLOCKER — concurrent writes to one file.** Every current §6 agent would `Write`
`.fragments/security-architecture.md` in full; last writer wins and silently discards the other
sections. Fix structurally: each agent writes `.fragments/security-architecture.part-<N>.md`
containing only its assigned `### 6.X` blocks, and a deterministic assembler produces
`security-architecture.md` before compose. Existing downstream consumers can continue to point at
the assembled file, but the producer path is wider than a new dispatch: the agent ownership
contract, thin and rerender runtimes, telemetry, budgets, permissions, validation, and tests all
need to change.

**BLOCKER — part artifacts need an exact, validated handoff.** Part files are structured artifacts
exchanged between agents and the assembler. They need a defined shape and validation path. The
assembler must consume an exact run-local manifest, never a `part-*` glob: stale parts can survive
a cutoff, `--keep-runtime-files`, or an interrupted retry and silently contaminate the next
assembly. Before an atomic write it must reject missing, duplicate, overlapping, out-of-order, or
unexpected sections and any surviving narrative placeholder. A run-id-scoped temporary directory
or exact manifest is safer than shared, reusable filenames.

**MEDIUM — genuinely cross-section content.** Two places in the §6 contract span sections:

- §6.2 ↔ §6.3 carry a mandated *bridging sentence* locating the boundary between authentication
  flows and the session-token lifecycle. §6.2 and §6.3 must therefore stay in the **same** agent.
- §6.13 Defense-in-Depth Summary synthesises across all sections. Its evidence comes from
  structured findings and control data in `threat-model.yaml`, not from sibling prose alone, so it
  *can* be authored in parallel — but wording may drift against per-section verdicts. Safest: give
  it to whichever agent owns the largest control set, or author it in a short serial tail after
  the parts return (+1–2 min, which would consume a material share of the gain).

**LOW TO MEDIUM — dangling cross-references, contradictions, and tone drift.** §6 prose cross-links between sections
(`§6.2 Password Storage` → `§6.9.2`). All anchors are pregenerated and therefore known *before*
dispatch, so passing each agent the full anchor list removes the guesswork. `prose-style.md` +
`prose-samples.md` are already shared, and `normalize_security_architecture.py` plus the existing
QA link checks catch structural link drift. They do not prove semantic agreement between two
independently authored verdict narratives. Quality parity therefore needs a golden replay plus a
semantic review, not only contract-pass results.

**LOW — deterministic structure reduces, but does not remove, risk.** §6.1's overview table is
`MECHANICAL-FROZEN`; H4 headings, anchors, and the `**Controls covered:**` line are scaffolded and
LOCKED. The assembler should preserve these bytes from the scaffold rather than ask a part agent to
reproduce them. Finding routing is not a reason to label the risk `NONE`: the pregenerator carries
a static `_V2_CWE_ROUTING` copy that mirrors the contract with additional exceptions, while
upstream `linked_threats` also influences the emitted lists. Existing routing correctness remains
an upstream invariant that the split must preserve and validate.

**Mode containment is incomplete today.** `prepare_stage2` disables parallel dispatch when
`.inline-shortcut-retry-count` exists, so thin-runtime inline retries use the single renderer.
However, compact `--rerender` explicitly loads the legacy Stage-2 dispatch slice, whose parallel
condition checks enrichment and dry-run only; it does not check `RERENDER` or `retry_pending`.
The split would therefore affect rerender unless a mode guard is added. Repair and retry modes need
explicit tests rather than an assumption that they are serial.

## Expected gain (sublinear)

Per-agent fixed cost (contract read, prose references, YAML reads) does not divide, so wall-clock
gain should flatten while token cost grows with agent count. The values below are illustrative
hypotheses derived from one run, not benchmark results:

| Configuration | Est. Stage-2 wall | Note |
|---|---|---|
| measured S + M | 14m49s | S = 13m12s critical path in this run |
| M + 2 §6 agents | target to validate: ~10 min | 6.2–6.6 ‖ 6.7–6.13 before deterministic improvements |
| M + 3 §6 agents | target to validate: ~8–9 min | 6.2–6.3 ‖ 6.4–6.9 ‖ 6.10–6.13 |
| M + 4 §6 agents | target to validate: ~7–8 min | likely diminishing; four duplicated preambles |

The working hypothesis is **3 renderers total (M + 2 §6 agents)**. It is not yet a recommended
configuration. After deterministic grounding, Agent M may become the critical path with only two
§6 agents, making further SecArch fan-out useless.

## Deep dive — anatomy of the secarch agent and every lever

### Where the 13m12s goes

| Window | Duration | What happens |
|---|---:|---|
| 04:38:29 – 04:39:00 | ~31s | Spawn, read contract lines 390–715, `prose-style.md`, `prose-samples.md`, and the 39,059-character scaffold |
| 04:39:00 – 04:47:15 | ~8m15s | Evidence lookup and planning — ad-hoc `python3 -c` queries against the 435 KB `threat-model.yaml`, plus long turns with no tool call at all |
| 04:47:15 – 04:51:31 | ~4m16s | One `Write` of 53,292 characters (≈13.3k tokens only under a rough four-characters-per-token assumption; ≈208 chars/s) |
| 04:51:31 – 04:51:41 | ~10s | `grep -c NARRATIVE_PLACEHOLDER` self-check, `STEP_END` |

The middle block is the largest and is the one nobody has attacked yet. It exists partly because
the scaffold hands the agent **bare F-IDs** and nothing else:

```
**Relevant findings**

- [F-007](#f-007)
- [F-008](#f-008)
- [F-058](#f-058)
```

34 distinct F-IDs are referenced across the scaffold. To write one `**Security assessment**` the
agent must resolve each ID — title, CWE, severity, `evidence.file:line`, excerpt — out of a 435 KB
YAML it can only reach through `Bash`/`Read`. That lookup contributes to the ad-hoc query traffic
visible in `.hook-events.log` between 04:39 and 04:43; the remaining no-tool time cannot be
attributed precisely from the trace.

### Work distribution per section (measured)

`scaffold` and `final` below are character counts including each `###` heading but excluding the
1,424-character chapter preamble before §6.1. `new prose` is the final count minus the
non-placeholder scaffold characters: equivalently `final - scaffold + placeholder-comment
characters`. This is the quantity that approximates generation work; it is not a byte or token
count.

| Section | scaffold | final | new prose | placeholders |
|---|---:|---:|---:|---:|
| 6.1 Overview (MECHANICAL-FROZEN) | 2,445 | 2,445 | 0 | 0 |
| 6.2 Identity and Authentication | 5,828 | 8,603 | 4,993 | 8 |
| 6.3 Session and Token | 3,113 | 4,903 | 3,980 | 8 |
| 6.4 Authorization | 2,310 | 3,473 | 2,932 | 6 |
| 6.5 Query Construction | 1,590 | 2,445 | 1,886 | 4 |
| 6.6 Input Boundary Validation | 2,397 | 2,171 | 1,729 | 6 |
| 6.7 Output Encoding | 2,621 | 3,257 | 2,307 | 6 |
| 6.8 Browser and Cross-Origin | 3,525 | 3,756 | 2,565 | 8 |
| 6.9 Crypto, Secrets, Data | 1,578 | 2,792 | 2,218 | 4 |
| 6.10 File, Parser, Outbound | 1,653 | 3,033 | 2,417 | 4 |
| **6.11 Operations, Runtime, Supply Chain** | 9,234 | 12,769 | **10,303** | 19 |
| 6.12 Real-time / Not Applicable | 437 | 437 | 0 | 0 |
| 6.13 Defense-in-Depth Summary | 904 | 1,784 | 1,146 | 2 |
| **Section total** | **37,635** | **51,868** | **36,476** | **75** |

Adding the unchanged chapter preamble yields the whole-file values of 39,059 scaffold characters
and 53,292 final characters.

§6.11 alone is 28 % of all generated prose, spread over 7 H4 blocks.

### The 75 placeholders — how many actually need an LLM?

| Placeholder class | Count | Deterministic source available today |
|---|---:|---|
| H4 `**Security assessment**` | 21 | **Seed available, not trusted prose** — `security_controls[].assessment` is present on 23/23 controls, but only 2/23 strings contain explicit file:line evidence and at least one deterministic SCA assessment is incorrect |
| H4 `**Status:**` | 21 | Partly — 19 placeholders already have the effectiveness token and need a clause; 2 require the whole token + clause. A clause is not safely deterministic until its source field is validated |
| Section `**Verdict:**` | 11 | Partly — the §6.1 computation is a candidate for §6.2–§6.11 (10/10 matched this run). §6.13 is cross-cutting synthesis and must not inherit its `—` overview value |
| Section `**Assessment:**` | 11 | No — genuine section-level synthesis |
| H4 positive intro | 5 | No direct source — `implementation` is already passed through when present; these placeholders remain precisely where the rendered control lacks it |
| Mermaid `sequenceDiagram` | 2 | No |
| Optional code excerpt | 2 | No |
| `**Implemented controls:**` | 2 | No direct source for the affected sections — the generator would already fill this line if matched controls supplied `implementation` |

The original claim that **53 of 75** placeholders have a deterministic source is not supported.
The useful deterministic opportunity is narrower: pre-resolve evidence for all 21 H4 assessments,
retain the Stage-1 assessment as an explicitly untrusted seed, and consider pre-filling only the
10 category verdicts in §6.2–§6.11. Status clauses, positive introductions, section assessments,
diagrams, excerpts, and §6.13 still require authored or newly contracted source fields.

### Defect found while measuring

`_emit_v2_subcontrol_legacy` (`scripts/pregenerate_fragments.py:4540`) never reads
`c["assessment"]` — it always emits the "2-4 sentences" placeholder. Its sibling
`_emit_v2_subcontrol_block` (`:4445`) *does* pass `sub["assessment"]` through verbatim. The legacy
path is taken whenever an emitted control has no `subcontrols[]`, which was true for all 23 control
rows in this run. The generated scaffold contained 21 H4 assessment placeholders, so every emitted
H4 security assessment was re-authored even though Stage 1 held a seed string.

This is not evidence that the Stage-1 strings are safe to render. §6.11.5 "Automated SCA scanning"
carries this deterministic Stage-1 assessment:

```text
Automated SCA scanning present: .github/workflows/codeql-analysis.yml:23, .github/workflows/pr-compliance.yml:168
```

The second reference is a false positive: that line
contains a regular expression naming tools such as Snyk and Trivy for PR-spam scoring; it does not
run a scanner. The first reference is `github/codeql-action/init`, which is code-scanning setup,
not evidence that the repository runs the dedicated dependency-review action documented by
[GitHub's dependency-review guidance](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review).
The LLM rewrite is also wrong: it claims `npm audit` runs in `.github/workflows/ci.yml`, but that
workflow contains no `npm audit` invocation.

The root defect is therefore upstream in `emit_sca_practice.py`: raw line-token matching credits
tool names inside non-executable data, and its CodeQL token is treated as sufficient SCA evidence.
The legacy emitter creates a second defect by discarding source provenance, but substituting or
seeding the current SCA assessment without fixing its producer would preserve incorrect evidence.

### Levers, ordered by prerequisite and expected value

Savings below are hypotheses to benchmark, not measured effects.

| # | Lever | Attacks | Saving hypothesis | Quality / contract risk |
|---|---|---|---:|---|
| L0 | Correct `emit_sca_practice.py`: parse executable workflow steps, exclude comments/regex/script data, and require a real SCA or dependency-review invocation | false Stage-1 evidence | performance-neutral | reduces report risk; prerequisite for reusing SCA assessments |
| L1 | Build a pre-resolved evidence pack for each emitted H4: routed finding ID, title, CWE, severity, canonical file:line, bounded excerpt, and the Stage-1 assessment as an untrusted seed | repeated lookup in the 8m15s middle | −3 to −5 min target | low only with schema/validation, canonical escaping, size caps, secret masking, and data-only labeling |
| L2 | Pre-fill category verdicts for §6.2–§6.11 from the same helper that owns §6.1; keep §6.13 authored. Put the validated seed and evidence next to each H4 placeholder, but do not render the seed verbatim | 10 verdict placeholders + H4 lookup | −1 min target | low after L0/L1; source assessments remain seeds, not authoritative prose |
| L3 | Replace full-file reproduction with contracted prose patches or validated per-section slices plus a deterministic assembler | 16.8k echoed characters | −1 to −1.5 min target | low to medium; new artifacts, validation, stale-part isolation, and atomic assembly required |
| L4 | Two-way §6 parallel split using L3's artifact | remaining SecArch authoring | target: roughly half the remaining authoring tail | medium until quality parity is measured |
| L5 | Deterministic prose for the three SCA-practice controls | 3 H4 blocks | −20 to −30s target | only after L0; templated prose must still reflect real executable evidence |

L0 is a correctness prerequisite. L1 and the narrow part of L2 are the cheapest performance
experiment because they can preserve the existing single-fragment handoff. L3 is not a
"no-contract-change" optimization: even without parallelism it introduces a producer/assembler
boundary and must satisfy the same artifact rules as L4.

### Projection

The original projection put L1+L2+L3 at approximately **7 minutes** for Agent S and a subsequent
two-way split at approximately **4 minutes**. Keep those figures as benchmark targets, not expected
outcomes. The 8m15s middle window mixes lookup with model planning, and the 4m16s `Write` window is
not guaranteed to shrink in direct proportion to removed characters.

The stopping condition remains useful: once SecArch is at or below Agent M's workload, further
SecArch agents cannot reduce Stage-2 wall time. In this sample that boundary is 4m14s, but it must be
remeasured because Agent M's conditional fragments vary by repository.

### Rejected

- **More MS-side agents for this sample** — Agent M already idles 8m53s. Reconsider only if a
  benchmark with requirements or other conditional fragments moves M onto the critical path.
- **Assuming Opus is slower** — model output speed and reasoning behavior were not compared in this
  run. Do not select or reject a model from the Sonnet-only trace; benchmark it if model choice is
  in scope.
- **Raising `maxTurns`** — 60 is a ceiling, not a driver; the agent used a fraction of it.
- **`Edit` per placeholder** — 75 tool round-trips replace one streamed `Write`. Token cost drops,
  wall-clock likely a wash, and `old_string` uniqueness across 75 near-identical placeholder
  comments is a new failure mode. A single contracted prose-patch artifact avoids that uniqueness
  problem without assuming that 13 slice writes will be faster.
- **Turning enrichment off at standard** — that is quick-depth behaviour. It removes the narrative,
  which is a coverage cut, not a performance fix.

## Cheaper first move

Do not start with slices or extra agents. First remove repeated evidence discovery while preserving
the current single-file authoring contract. A validated evidence pack beside the existing
placeholders attacks the largest observed window without introducing concurrent writers.

Stopping full-file reproduction remains a promising second optimization: 16.8k of the
53.3k-character `Write` is deterministic structure. However, per-section slices are new pipeline
artifacts, not a zero-risk output trick. Prefer one schema-validated prose-patch artifact or an
exact section manifest over 13 unconstrained Markdown writes. The deterministic assembler should
copy all frozen structure from the scaffold and insert only validated prose payloads.

## Recommendation

**Do not build the parallel split.** Not "not yet" — the Step-2 gate below is already unmet on the
only evidence that still exists. The gate asks for a repeated Agent S ↔ Agent M gap of at least two
minutes or 30%, whichever is larger; 30% of Agent S is roughly 3.6 minutes, and the surviving run's
gap is about 2m50s. Agent S is still the critical path, but not by enough to justify a new
multi-artifact contract.

Reopen this only from a fresh, repeated measurement — not from the numbers above.

### Step 0 — fix the evidence producer (done)

Implemented: `classify_sca_scanning` now matches only executable step values (`_executable_lines`),
CodeQL is no longer credited as dependency scanning, and bare tool-name tokens were replaced by
invocation and action-reference forms. On the juice-shop reference the control moved from
`Adequate` — citing a PR-spam regex — to `Missing`. What the fix had to do:

- inspect parsed executable workflow steps rather than raw line-token matches,
- exclude comments, regex literals, PR body scanners, examples, and other non-executable mentions,
- distinguish CodeQL code scanning from dependency review / SCA enforcement,
- state the inspected signal, trigger, false-positive exclusions, rating mapping, and required
  evidence,
- add neutral fixtures covering true scanner invocations and tool-name-only false positives,
- replay the juice-shop fixture and verify that `pr-compliance.yml:168` is no longer credited.

This is a producer fix, not a renderer workaround.

One tradeoff was accepted deliberately: a scanner shelled out from inside a `github-script` body is
no longer credited. Inspecting those bodies is what produced the false evidence.

### Step 1 — add a validated grounding pack without changing the handoff

At each emitted H4 placeholder, make the already-routed evidence cheap to consume:

- finding ID, title, CWE, severity, canonical `evidence.file:line`, and a bounded excerpt,
- the control's Stage-1 assessment as an explicitly untrusted seed, not rendered truth,
- a deterministic category verdict only for §6.2–§6.11,
- a stable H4/section identifier so the renderer does not need to infer ownership.

Prefer a schema-validated sidecar or a safely encoded structured block over raw imported text in an
HTML comment. If comments are used, escape comment terminators, cap every field, mask secrets, and
label repository-derived strings as data, never instructions. Do not substitute the Stage-1
assessment verbatim: most strings are terse, only two carry explicit file:line evidence in this
sample, and the SCA example proves producer quality cannot be assumed.

Touchpoints include the producer that builds the pack, its schema and validator, the pregenerator
or focused agent prompt that references it, required permissions/tests for any new command or
target, and the golden fixture replay. The section contract, composer, and QA can stay unchanged
only if the existing `security-architecture.md` handoff remains intact.

### Step 2 — benchmark before changing the artifact shape

Run repeated comparable standard assessments against the same repository revision and
configuration. Record separately:

- SecArch spawn-to-return wall time,
- evidence-query tool calls and time,
- output characters and Stage-2 tokens,
- Agent M wall time,
- compose/QA result and semantic defects,
- total Stage-2 wall time.

Compare medians rather than one run. Treat ~7 minutes for Agent S as a target to test, not an
acceptance expectation. Proceed to slices or parallelism only if SecArch remains materially above
Agent M after grounding. A practical gate is a repeated gap of at least two minutes or 30%,
whichever is larger; a smaller gap does not justify a new multi-artifact contract.

### Step 3 — remove scaffold echo only if it still matters

If writing remains material after Step 2, introduce one contracted prose-patch artifact or exact
per-section slices and a deterministic assembler. The assembler must:

- read an exact run-local manifest,
- require each assigned section exactly once and reject unexpected sections,
- preserve frozen scaffold bytes and insert prose only at named targets,
- reject unresolved placeholders, duplicate anchors, and missing §6.2/§6.3 bridge content,
- write `security-architecture.md` atomically,
- leave the existing compose, QA, repair, and finding-reference consumers pointed at the assembled
  file,
- cover full, retry, rerender, repair, cutoff, and `--keep-runtime-files` behavior in tests.

### Step 4 — split only if the post-assembly benchmark still justifies it

Add two §6 agents only when the single-agent, evidence-grounded, no-echo path still exceeds the
Step-2 gate. Keep §6.2 and §6.3 together. Either give §6.13 to the same agent and validate verdict
agreement or author it in a serial synthesis tail. Split by *new-prose characters*, not rendered
size: the partition measured here was 6.2–6.8 (20,392) ‖ 6.9–6.13 (16,084) — recompute it from the
run you benchmark, because per-section sizes vary enough between runs to move the boundary.

Before enabling it by default, demonstrate:

- contract and golden-fixture parity,
- no increase in QA/repair iterations,
- no semantic contradictions across sections,
- a repeatable Stage-2 wall-time improvement after assembly overhead,
- correct behavior in full and rerender modes,
- Agent M has not already become the critical path.

### Outside §6 — cheaper wins if the goal is total runtime

§6 is not the lever for whole-run wall-clock. Two larger items in the same run:

- **3m58s of pure loss** from three `RUN_ABORTED` retries on `validate_intermediate.py`
  (`threats[66]: 'scenario' is a required property`). A producer-side schema defect, cheaper to fix
  than anything above — but unverified, see the note in the full-run context section.
- **STRIDE totals 27m50s (27 %)** — prep 3m04s, fan-out 18m55s, merge 5m51s — of which roughly
  4.5 min is dispatch and resume latency with no analyzer running.
