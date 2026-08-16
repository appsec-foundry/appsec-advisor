# Context-v2 audit: the stale evidence bundle abort, 2026-08-16

A full standard scan of a juice-shop checkout aborted after 49 minutes, at the
dispatch gate between STRIDE wave 1 and wave 2:

```
validate_dispatch_manifest.py failed with exit 1: ERROR context-v2 evidence
validation failed: evidence bundle is stale for repository: primary
```

All five wave-1 components had finished (`web-frontend` 14 threats, `api-server`
16, `auth-service` 13, `sqlite-db` 8, `ci-cd-pipeline` 7). Wave 2
(`realtime-channel`, `web3-nft`) never dispatched. No `threat-model.md` was
produced and the runtime forbids resume.

This note records the cause, the fix, and five further defects found while
auditing the context-v2 surface around it.

## F1 — The run invalidated its own evidence bundles (fixed)

`repository_fingerprint` in `scripts/build_stride_evidence_bundles.py` binds an
evidence bundle to HEAD plus a `dirty_worktree_sha256` over every dirty and
untracked file in the analyzed repository. Its `excluded_root` covers only
`$OUTPUT_DIR` (`docs/security/`).

Of 592 fingerprint inputs, exactly one changed between the bundle build
(06:59:08Z) and the gate (07:19:38Z):

```
07:17:06Z  .appsec-progress.json     <-- written by the run, at the repo root
03:20:32Z  .gitignore                <-- the scan session's own hypothesis, 3h too early
```

`scripts/log_event.py` took `output_dir = Path(argv[1])` unvalidated. An unset
`$OUTPUT_DIR` reaches it as an empty string, and `Path("")` is `Path(".")` —
the agent's working directory, which is the analyzed repository root. The STRIDE
analyst for `sqlite-db` logged its `AGENT_END` there at 07:17:06Z, changing the
fingerprint 2.5 minutes before the gate read it.

Two artifacts land there, not one. Only the second aborts the run:

```
.gitignore:28:*.log   .agent-run.log            -> ignored by the target repo's own rule
                      .appsec-progress.json     -> not ignored, enters the fingerprint
```

`scripts/.gitignore-template` anchors every entry on `docs/security/`, so it
covers neither. That the run survived until wave 2 at all is an accident of the
target repository's `*.log` pattern.

Older strays from the same class sit in that checkout: a `--event/` directory
containing `.agent-run.log` and `.appsec-progress.json`, and a `--help` file —
both from invocations where the argument shifted into the `output_dir` slot.

**Fix.** `log_event.py` now rejects an empty `output_dir` argument and one that
starts with `-`, instead of logging to an arbitrary directory. Covered by
`tests/test_log_event.py::TestMainArgErrors::test_empty_output_dir_is_rejected`
and `::test_option_in_output_dir_slot_is_rejected`, which also assert that no
file is created in the working directory.

The fingerprint's exclusion scope was deliberately left alone. Widening it would
weaken an integrity control to accommodate a writer that should not be writing
there.

## F2 — The fingerprint bound the whole worktree, not the evidence (fixed)

`build_stride_dispatch_manifest.py:1686` calls `build_all` once, for every
selected component, when the manifest is written. Wave 2's bundles were built at
06:59:08Z and first validated at 07:19:38Z — after wave 1's agents had run for
15 minutes. With a whole-worktree fingerprint, that required the analyzed
repository to stay byte-identical for the entire STRIDE phase.

Rebuilding each wave's bundles at its own dispatch was considered and rejected:
it shortens the window from ~45 to ~15 minutes without closing it — an editor
save, a `--watch` build, or a commit in a live checkout still aborts the run —
and `build_all` consumes its inputs (`component.pop("business_context")`,
`pop("architecture_context")`), so it is not safely repeatable on a persisted
manifest.

**Fix.** `repository_fingerprint` now takes `cited_paths` and hashes exactly the
files the bundle makes claims about: the paths retained in `source_slices` plus
the primary-repository paths referenced by the bounded `evidence` records. HEAD
is still recorded and compared.

Builder and validator both derive that set through one shared helper,
`bundle_citation_paths`, from the bundle's **own** admitted content. That
symmetry matters: the builder previously computed protected paths from the
pre-truncation `raw` records while the bundle stores the post-truncation
`evidence`, so deriving the two sides independently would have produced
different sets whenever a cap dropped a record.

This is a narrowing of scope, not a relaxation of strength. A change to a cited
file still invalidates the bundle — `test_bundle_becomes_stale_when_source_bytes_change`
and `test_bundle_becomes_stale_when_source_change_is_staged` both still pass,
the latter now against a file the bundle actually cites. What no longer aborts a
run is a change to a file the bundle never mentioned.

Guarded by:

- `test_unrelated_repository_churn_does_not_invalidate_a_bundle` — replays this
  incident, including a `.appsec-progress.json` written at the repository root.
- `test_fingerprint_covers_only_the_cited_files`
- `test_fingerprint_ignores_citations_inside_the_output_directory`

**Residual risk.** `commit_sha` is still compared, so a commit made in the
analyzed repository during the STRIDE phase aborts the run even when no cited
file changed. That was left in place deliberately — dropping it is a second
semantic change, and cited-content equality already covers the guarantee the
bundle makes. Revisit if it shows up in practice.

## F3 — Prior plugin output counted as analyzed-repository state (fixed with F2)

The old fingerprint hashed **590 files, 7.8 MB** on every call. The largest
entries were the plugin's own earlier output directories:

```
405 KB  docs/security.v1-backup/threat-model.md
368 KB  docs/security-ab-thin/threat-model.md
366 KB  docs/security-ab-legacy/threat-model.md
```

Only the active `docs/security/` was excluded, so prior runs, backups, and A/B
directories counted as source state. Narrowing to cited paths removes them.
Measured against this run's bundles: 1–18 files and 6–72 KB per component.

The `excluded_root` guard is kept as defense in depth — a citation into the
output directory hashes as `<excluded>` rather than as live bytes — even though
component path routing makes such a citation unreachable today.

## F8 — The serial-dispatch detector was dead on every real run (fixed)

Found while verifying F5. `check_stride_dispatch._COMPONENT_ID_RE` matched
`COMPONENT_ID=`, upper case. The hook writes `component_id=web-frontend`. On
this run:

```
_context_v2_dispatch_starts() -> {}
_dispatch_intervals()         -> {}
detect_serial_dispatch()      -> []      # "parallel", unconditionally
```

`[]` means "no finding", so the guard reported a healthy fan-out no matter what
the orchestrator did. REQ-FLW-001 requires a serial wave to be reported as a
defect; nothing could have reported one.

The suite stayed green because every fixture invented the upper-case spelling —
including `test_context_v2_serial_wave_is_detected_from_production_event_shapes`,
whose name asserts the opposite of what it did.

Second failure in the same function: completion came only from the
agent-written `AGENT_END`, and four of five analyzers never wrote one (F5). Even
with the regex corrected, a non-compliant analyzer would silently disable the
guard.

**Fix.** The component pattern is case-insensitive and still accepts the
bracketed form. Completion now also accepts `AGENT_USAGE`, the controller's own
row. Three tests pin the production shapes and all three fail against the old
regex:

- `test_production_parallel_wave_is_read_and_not_flagged` — asserts the detector
  *sees* all five components, not merely that it stays silent.
- `test_production_serial_wave_is_detected`
- `test_production_serial_wave_is_detected_without_agent_written_events`

Against the real log the detector now reads all five dispatch times and returns
`[]` — the same verdict as before the fix, for the first time on evidence.

## F4 — The STRIDE depth check is bypassed by omission (fixed)

`log_event.py` validates a logged `depth` against the authoritative dispatch
call only under `if agent == "stride-analyzer-v2"`, which requires the caller to
pass `--agent stride-analyzer-v2 --component-id`. A caller that omits the flags
writes whatever depth text it likes.

That happened in this run. `ci-cd-pipeline` is a `light` component in
`.stride-selection.json` and `.dispatch-waves.json`:

```
07:04:59Z  threat-analyst  AGENT_START component=ci-cd-pipeline depth=full
07:10:35Z  threat-analyst  AGENT_END   component=ci-cd-pipeline depth=light threats=7
```

The component column reads `threat-analyst`, the default — so the flags were
absent and the start event carries a depth the plan contradicts. A guard that
only runs when the caller opts in is not a guard.

**Fix.** Validation now triggers on the claim rather than on the caller: a
detail naming a component that a dispatched Agent call currently owns, together
with a `depth=` token, is rewritten from the authoritative call whoever logs it.
A line that names no dispatched component is left alone, so
`ORCHESTRATION_READY … depth=standard` still passes through untouched. Pinned by
`test_depth_claim_is_validated_even_without_the_stride_agent_flag` and
`test_a_depth_line_naming_no_dispatched_component_is_left_alone`; the first
fails against the previous behavior.

## F5 — Four of five STRIDE agents logged nothing (impact removed, cause open)

`docs/security/.agent-run.log` contains `AGENT_START`/`AGENT_END` for
`ci-cd-pipeline` only. `web-frontend`, `api-server`, `auth-service` and
`sqlite-db` produced neither — `sqlite-db`'s pair went to the repository root
(F1), the other three were never emitted at all.

The agent definition requires both events and nothing verifies that they
arrived. `agents/shared/logging-standard.md` assigns them to each sub-agent, so
who owns them is a documented contract — not something to change here.

What was fixed is the damage. Three consumers depended on agent compliance and
no longer do:

- per-component durations (F6) now come from the controller's spans;
- serial-dispatch detection (F8) now accepts the controller's completion row;
- the depth check (F4) no longer needs the agent to identify itself.

Still open: `compose_threat_model._agent_dispatch_rows` scrapes
`AGENT_INVOKE|AGENT_START` for the model-attribution table. This run logged zero
`AGENT_INVOKE` and one `AGENT_START` against ten `AGENT_SPAWN`. It is a fallback
behind `stats.agents[]` from the YAML, so the effect is confined to renders
where that list is empty — a resume or re-render.

The remaining question is whether analyzers should emit these events at all now
that nothing deterministic reads them, or whether the controller should own
them. That is a change to the logging contract and belongs in a decision, not in
this note.

## F6 — STRIDE attempt timestamps are invented by the model

`agents/appsec-stride-analyzer-v2.md:95` asks the agent to fill `started_at` and
`analyzed_at` with `"<ISO 8601 UTC>"`. The agents returned:

```
api-server      started 00:00:00Z   analyzed 00:15:00Z
auth-service    started 00:00:00Z   analyzed 01:15:00Z
ci-cd-pipeline  started 00:00:00Z   analyzed 00:00:00Z
sqlite-db       started 00:00:00Z   analyzed 00:00:00Z
web-frontend    started 00:00:00Z   analyzed 00:01:00Z
```

The wave ran from 07:02:59Z to 07:19:19Z. Every value is fabricated.

These are not cosmetic. `record_component_durations._stride_durations` ranked
them **first**, above every measurement, and merges the result into
`.appsec-cache/baseline.json` — the baseline `estimate_duration.py` reads to
predict the next run:

| component | self-reported | actual |
|---|---|---|
| auth-service | 4500 s | 927 s |
| api-server | 900 s | 623 s |
| web-frontend | 60 s | 801 s |
| sqlite-db | 0 s | 773 s |
| ci-cd-pipeline | 0 s | 359 s |

The documented rationale — "the agent's own clock" is per-component-accurate
under parallel dispatch — is sound about the problem and wrong about the
instrument. An LLM has no clock.

The declared fallback was already broken too: it pairs `AGENT_INVOKE` with
`AGENT_DONE`, and both fire at dispatch. Web-frontend's `AGENT_DONE` lands one
second after its spawn; the analysis took 801.

**Fix.** A new `_controller_dispatch_durations` pairs `AGENT_SPAWN` with
`AGENT_USAGE` by `component_id=`. Both are stamped by the controller, so they
stay correct under parallel fan-out and cannot be misreported by the agent being
measured. It takes priority; the self-reported values drop to rank 2 for logs
that predate the controller events. Replayed against this run's log it returns
801 / 623 / 927 / 773 / 359 — the wall-clock spans in the log.

`scripts/record_component_durations.py` had no test module, against the repo
rule. `tests/test_record_component_durations.py` now covers the source priority,
the dispatch-is-not-completion trap, a still-running component, bounds, and the
baseline merge.

## F7 — Duplicate completion records in the trace log

`.appsec-trace.log` carries six `AGENT_COMPLETE` lines for the single
recon-scanner dispatch. Five have `in=0 out=0 turns=? stop=unknown`; only the
first and last carry real usage. `.agent-run.log` records one clean
`AGENT_SPAWN`/`AGENT_USAGE` pair for the same agent. Unexplained — the trace
emitter appears to fire on something other than completion.

## What worked

Worth stating, because the abort came out of this machinery: context-v2 itself
behaved correctly throughout.

- Six routing revisions, receipt `valid` at every one, `runtime_generation`
  `context-v2`, manifest `context_version: 2`.
- Role-dependent admission is real, not a global switch: `business.project_context`
  is `forbidden-by-core` for the trust-boundary analyst and `plan-enforced` for
  the control analyst.
- In the STRIDE fan-out, 95 deliveries across five components, of which only
  five are `legacy_unreceipted`. Each analyst got component-scoped projections
  with recorded sha256 instead of the full architecture model, recon summary,
  project context, or prior findings.
- Parallelism is correct: `concurrency=5`, all five spawns inside one turn
  (07:02:59–07:04:40, no `SESSION_STOP` between them), verified overlap.

## Status

| ID | Finding | Status |
|---|---|---|
| F1 | `log_event.py` writes into the analyzed repository root | fixed |
| F2 | Fingerprint bound the whole worktree instead of the evidence | fixed |
| F3 | Prior output directories counted as repository state | fixed with F2 |
| F4 | Depth validation was opt-in and was bypassed | fixed |
| F5 | Four of five STRIDE agents emitted no lifecycle events | impact removed, cause open |
| F6 | Durations were taken from model-authored timestamps | fixed |
| F7 | Duplicate `AGENT_COMPLETE` in the trace log | open, deferred |
| F8 | Serial-dispatch detector was dead on every real run | fixed |
| F9 | Producers and consumers disagree on the event vocabulary | guards fixed, vocabulary open |
| F10 | `format_line` emits event names `parse_line` cannot read | fixed |
| F11 | An agent writes raw JSON into `.agent-run.log` | open |

F1 removed the plugin as a cause of the abort; F2 removed everything else that
is not evidence. Together they make the binding generic: a run is no longer
hostage to unrelated activity in the repository it analyzes, whoever causes it.

F4, F6 and F8 share one shape with F5 — a fact the controller already holds was
taken from the agent instead, and the check that should have caught the
mismatch was keyed on the agent volunteering for it. Each is now read from the
controller's own events.

F7 is deferred deliberately. `AGENT_COMPLETE` is emitted from the `Stop` hook,
and current Claude Code releases fire `Stop` inside sub-agent sessions under the
parent's session id, so one dispatch yields several rows. Distinguishing them
needs per-dispatch identity in the hook; every heuristic short of that also
masks a genuine mid-run abort, which is the same reason the
`SESSION_ABORTED_MIDRUN` false positive was left in place.

Before context-v2 ships, `stale for repository` deserves a user-facing line —
what the binding covers and what to do — since a scan can still abort on it and
no document currently names the message.

## F9 — Producers and consumers disagree on the event vocabulary

F8 was not a typo. It is one instance of a structural gap: `event_log` owns
`format_line` **and** `parse_line`, but no consumer uses the reader. 49
log-parsing regexes across five modules each re-derive the grammar.

Measured by replaying every such literal against the 1301 real log lines of
this run: **32 matched nothing.** Excluding the events an aborted run never
reaches (QA, architect, finalization), the confirmed drifts are:

| expected by consumers | actually emitted |
|---|---|
| `PHASE_START [Phase 9/11] …` | `PHASE_START trust-boundary-analyst` — no bracket |
| `AGENT_INVOKE … model=` | never; context-v2 dispatches via `AGENT_SPAWN` |
| `SCAN_START … agent=` | `SCAN_START reconnaissance-scan` |
| `ASSESSMENT_START` | absent from the entire run |

Nine parsers in `agent_logger`, `compose_threat_model`,
`render_completion_summary`, `record_stage_stats` and
`record_component_durations` read nothing. None of them fails loudly; each
returns an empty result, which is indistinguishable from a healthy run.

The consequence for F6 was total: `_read_phase_9_start` required the bracket, so
`main()` returned before computing anything. Durations were never recorded at
all, and the improved source would have changed nothing on its own.

**Fixed here** are the consumers where the empty read disables a guard or loses
data outright: phase-9 anchoring (falls back to the first STRIDE `AGENT_SPAWN`),
serial-dispatch detection (F8), and the STRIDE model-drift advisory, which keyed
on `AGENT_INVOKE` and was therefore silent on exactly the runs it exists to
check — a `--reasoning-model opus` setting quietly served by sonnet.

**Not fixed here** is the phase-boundary vocabulary itself. Restoring
`[Phase N/M]`, or migrating the remaining consumers onto `parse_line` plus the
controller's lifecycle events, changes what several producers emit and what the
report renders. That is a decision, not a patch, and it degrades reporting
rather than breaking runs.

## F10 — The writer emits lines the reader cannot read

`format_line` pads an event name to `EVENT_WIDTH` (18) but never truncates, so a
longer name overflows the column both of `parse_line`'s fixed-width offsets key
on. `AGENT_RETURN_FIELDS` (19) and `AGENT_USAGE_UNAVAILABLE` (23) made **69 of
798** `.hook-events.log` lines unreadable.

`test_long_event_name_is_not_truncated` existed and passed — it asserted only
that the name appears in the written line, never that the line parses back.

**Fix.** `parse_line` now also reads the leading field as the event when it
looks like one, covering both shapes and a detail containing double spaces.
Hook-log coverage went from 91% to 100%. Pinned by a roundtrip test
parameterised over the over-long names and both line shapes.

## F11 — An agent writes a third log format

Nine lines in `.agent-run.log` are raw JSON:

```
{"ts":"2026-08-16T06:39:37Z","agent":"actor-discoverer","event":"STEP_START",…}
```

AGENTS.md is explicit that `log_event.py` and the documented shell fallback are
the only legal writers and that no other format may be invented. These lines are
invisible to every consumer, including `parse_line`, which correctly rejects
them. The fix belongs in the actor-discoverer prompt; left open.

## Method note

Three fixtures in this area asserted things production never satisfied, and
every suite was green throughout: the upper-case `COMPONENT_ID=` (F8), a
staleness test using a file its bundle did not cite (F2), and a long-event-name
test that checked the name was written but never that it could be read (F10).

Two habits followed from that, and both should outlive this note.

**A fix is not verified until its test fails without it.** Every fix here was
reverted in place and the new test re-run; the counter-check is recorded per
finding above.

**Fixtures do not establish that a consumer works.** They establish that it
works against what the fixture's author believed production emits. So the fixes
were replayed against the aborted run's own logs, bundles and repository
wherever a real artifact existed — which is how F9 turned up, and how the F6
fix was caught being inert.

`tests/test_log_shape_contract.py` makes that permanent: a trimmed corpus of
real lines in `tests/fixtures/logs/context-v2-run.log`, asserted to be readable
by the shared parser and by the consumers that must not fail open. Reverting F8,
F9 or F10 fails it. When a producer changes shape, add the line to the corpus
before changing a consumer's regex.
