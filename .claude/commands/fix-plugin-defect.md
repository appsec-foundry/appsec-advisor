---
name: fix-plugin-defect
description: >-
  Turn a finished appsec-advisor run into a verified, generic, guarded plugin
  fix. Finds what actually broke (log symptoms plus the artifact divergences no
  log records), proves the root cause by executing it, derives a fix that holds
  for arbitrary target repositories rather than the one that exposed it, and
  lands it with a guard test. Use after a create-threat-model run that produced
  wrong numbers, a broken or inconsistent report, a crash, or Run Issues you
  want explained — and whenever you are about to fix plugin code at all.
---

# Fix a plugin defect

This is a maintainer dev tool — project-local, never shipped with the plugin.

Input: a finished run's `OUTPUT_DIR` (usually `<target>/docs/security`) and the
plugin checkout. Output: a committed fix whose correctness you executed, that
holds for repositories other than the one that exposed it, and that a test
pins.

Set `APPSEC_PLUGIN_DEV=1` — several diagnostic paths gate on it.

Work the stages in order. Do not start writing a fix from stage 1
evidence; a symptom that looks obvious is the usual way a wrong fix gets
written. Stages 2 and 3 each end with an independent challenge (2b, 3b): your
own analysis is a hypothesis until someone without your context failed to
refute it.

### Delegation pattern

Several defects from one run are normal. Fan the work out, but keep the two
roles apart:

- **Analysis** (stages 2a, 3a): parallel `fork` agents, one per defect
  cluster, all launched in one message. Forks inherit your context, which is
  what analysis needs. Research only: no edits; scratch work in `$TMPDIR`.
- **Challenge** (stages 2b, 3b): fresh `general-purpose` agents, never forks.
  A fork inherits your framing and confirms it. Give each challenger the
  claims with `file:line` and the run paths, not your reasoning, and tell it
  to refute by default and to reproduce where it can.

Every agent reports per item: verdict, `file:line`, decisive evidence in one to
three lines, corrections. Cap the length. You stay the one who decides; an
agent's summary is a claim until you have checked the code locations it cites.

---

## 1. Find what actually broke

Three sources, in ascending order of value. Use all three — the last one finds
what the others structurally cannot.

**a) Recorded symptoms.** `$OUTPUT_DIR/.run-issues.json`, plus
`/appsec-advisor:diagnose-run` for a per-issue `file:line` assessment.

These are heuristics and mostly false positives. `BASH_WARN` fires whenever a
command's *output* matches an error keyword — a `grep` for `getErrorMessage`
in target source trips it every time. Never quote a count from this file as a
defect count. Read each `raw_event` and decide for yourself.

**b) Run anomalies.** Non-zero gate exits, waiter repeats, `PARTIAL` or
`incomplete` markers in the completion summary, stage stats that cover fewer
agents than were dispatched, budget banners.

**c) Artifact consistency — the sweep no log replaces.** The defects that
matter most leave no log line: two artifacts from one run that disagree. Check
at minimum:

- Every number the console summary prints against the same number in
  `threat-model.md`.
- Sub-counts against their totals in each block that shows a breakdown.
- `threat-model.yaml` against what the report says about it.
- Stamped `threat-model-<slug>.*` against the canonical files.
- Counts in the Management Summary against §8 and against the YAML.
- Every trust boundary in the catalog against the diagrams. Is each one shown
  somewhere?
- Reported findings against each other. Do any share a file and line, or
  describe the same defect from two sources?
- Evidence paths against the repository. Is the file tracked, and does it
  exist?
- Each finding's stored tier or status against the verdict that should
  determine it.

A divergence here is a real defect even when every gate passed green: gates
check each artifact against its own contract, not artifacts against each other.

**Then triage every candidate into exactly one bucket.** This is the step
people skip, and it is what keeps you from filing your own mistake as a plugin
bug:

| Bucket | Test |
|---|---|
| Plugin defect | The plugin produced the wrong thing from correct inputs |
| Orchestrator error | You deviated from the runtime instructions — re-read them before blaming code |
| Environment | Sandbox, missing binary, permissions, network |
| Expected | The depth, mode, or flag says this does not run |

Worked example of the second bucket: stage stats covering 9 of 13 agents looks
like a stats bug. The Stage-1 runtime says to *group* parallel jobs by role and
record the **sum**; recording each agent separately under one accumulation id
makes the script dedupe the rest, correctly. That is an orchestrator error. Fix
your own behavior and say so; do not patch the script.

Carry forward only the plugin-defect bucket. State the others plainly in your
report.

---

## 2. Verify the root cause

### 2a. Find it

**No fix before you can execute the divergence.** Reproduce it outside the
report: import the producing function, feed it the artifact from the run, and
print both the value it produces and the value the other surface shows. If you
cannot make the two numbers appear side by side, you have a hypothesis, not a
root cause.

Then name the producer — `file:line` — and trace it: producer → contract →
consumer → validation → tests. Trace all of it; a fix that lands in the
consumer when the producer is wrong is the symptom patch this whole workflow
exists to avoid.

Before proposing anything, ask what governs that file:

```bash
python3 scripts/check_specs.py --for <path>
grep -n "<file, constant, or test you are about to touch>" docs/internal/decisions.md
```

If a decision governs the behavior, you are not looking at a bug — you are
looking at a decision you may disagree with. That is an operator question.
Stop and ask.

### 2b. Have it challenged

Hand every root-cause claim to fresh challengers (see Delegation pattern),
grouped by subsystem. Each claim carries its symptom, its `file:line`, and its
impact claim ("this count is wrong", "this alone forces outcome X"). Ask for
CONFIRMED, PARTIAL, or REFUTED per claim, and for a reproduction against a copy
of the run where possible: rerun the scanner, recompute the counter with and
without the suspect row, render a minimal synthetic model.

Expect refutations, especially of impact claims. A mechanism can be real while
its claimed effect is not: a counter that miscounts one row, while eight other
rows produce the same outcome anyway; a summary number that looks inflated but
whose reader already filters the bad rows. Carry forward only what survived,
with the corrected impact. Report refuted claims to the operator as refuted,
including your own.

---

## 3. Derive a fix that holds generally

### 3a. Derive it

The requirement that makes this different from ordinary debugging: production
behavior must work for arbitrary target repositories. The repository that
exposed the defect is a witness, never the specification.

**Fix the source.** The producer, prompt, heuristic, renderer, or deterministic
enforcer that creates the wrong output. Never the rendered report, never the
schema, never the QA gate, never a fixture or golden expectation.

**Prefer delegation over reimplementation.** If a shared rule already exists
for what you are computing, call it. A second implementation of the same rule
is the defect class most likely to reappear — a module that exists precisely to
reconcile surfaces is evidence that the rule is subtle and that another surface
already drifted once.

**Enumerate the shapes the fix must hold for**, and include shapes the tested
repository does not have. For a model-level rule that means: absent optional
sections, empty collections, every enum value including the rare ones, and
inputs where the buggy path and the correct path coincide by accident. If your
fix is only demonstrably right on the repository that exposed it, it is not
done.

**Search for sibling surfaces** carrying the same pattern, and decide each one
explicitly — same defect, or a deliberately different basis? Do not blanket
convert: a triage surface counting the list it operates on may be answering a
different question than a summary surface, and unifying them silently breaks
it. Record the ones you deliberately left alone, in a comment or a contract
line, so the next reader does not "finish the job".

Delegating this search to a subagent is reasonable when the surface count is
large; the decision per hit stays yours.

**Look for the shared cause before fixing defects one by one.** When several
verified defects exist, ask whether they share a mechanism. Recurring shapes in
this plugin:

- Several producers build the same record ad hoc, so fields drift per producer.
- A derived field is stored early, and readers compensate for it at read time.
- A gate that would catch the defect only warns.
- A model abstraction answers the wrong question, for example a per-file check
  for a repository-level property.

A fix per symptom adds yet another compensating surface. If the shared cause
is the real defect, the measure is to remove it, even when that is larger.

### 3b. Challenge the measures

Before implementing, hand the measures to fresh challengers. Run two kinds of
challenge in parallel.

**Per-measure feasibility**, grouped by subsystem. Ask each challenger:

- What already exists that the measure should extend instead of duplicating?
- Which consumers break: schemas, enums, exporters, renderers, other agents?
- What does a changed field do semantically downstream? A demotion that also
  drops records from a register is not a relabel.
- Does the measure behave differently at other depths, sampling caps or modes?
- Does a design decision or commit explain the current behavior?
  Use `git log -S` and `docs/internal/decisions.md`.

Where a measure changes matching, grouping, or counting, require a
**prototype on the run's data** that reports numbers, for example true
duplicates caught against false merges per candidate key. A key that looks
right on paper is often the one that over-merges.

**One root-cause-versus-symptom review across all measures.** Give it the
verified defects, the measures, and concrete hypotheses about shared causes
(the shapes above). Ask, per measure: root-cause fix, partial, or symptom?
Ask also which existing validator should have caught each defect.

**Consolidate yourself.** Challengers will contradict each other, for example
"tracked files only" against "tracked plus untracked-not-ignored". Resolve
every conflict explicitly, with the reason. Write down what you drop from the
original proposal. When the consolidated plan contains a cross-cutting
refactor, present it to the operator with order and risk before stage 4: that
is a scope decision, not a fix.

Order the plan as follows:

1. Invariant tests that are red on today's defects.
2. Small, independent fixes.
3. The structural change.
4. A rerun on the witness repository and at least one other repository.

---

## 4. Verify the fix before you commit to it

Run the intended computation against (a) the exact artifact from the failing
run and (b) each shape from stage 3. Show that the two previously divergent
surfaces now produce identical values.

Do this before wiring the change through the codebase. A fix that has not
produced the right number on the real failing input is a guess, however clean
the diff looks.

---

## 5. Implement and verify the implementation

**Baseline on failure only.** Do not run the suite before you change anything.
When a selected test fails after your change, rerun only the failing tests at
the merge base (`CONTRIBUTING.md` → Targeted tests shows the worktree
commands). A failure that also occurs there is pre-existing; any other failure
is yours.

Implement, and add a guard:

- A test that fails when the defect returns. Parametrize it over the shapes
  from stage 3.
- Assert against the **rule** — compare the surface to the authority it must
  agree with — not against numbers copied from today's run. A test pinning
  `34` breaks the day the rule legitimately changes and teaches nobody why.
- A golden-master diff alone is not a guard. Its expectation is whatever
  today's code emits, so it locks defects in. Add semantic invariants over a
  frozen run fixture, such as "no reported finding without verified evidence
  is marked confirmed" or "every boundary is represented".
- Register the decision in `docs/internal/decisions.md` when breaking the
  invariant again would be costly and non-obvious, naming its guard. Follow the
  table's existing shape.
- Update the module docstring that owns the rule so the next reader sees every
  surface bound by it.

Verify, in this order:

```bash
pytest tests/test_<the modules you touched>.py
make test-plan BASE=origin/dev              # review the selection and its reasons
make validate test-changed BASE=origin/dev  # falls back to the full suite when unrouted
make lint
```

Name every failing test and whether it also fails at the merge base. For renderer
or report-structure changes, inspect the golden diff rather than regenerating it
reflexively.

`CHANGELOG.md` gets an entry only when a user would notice it in a run or its
output: one short sentence, what it now does, no cause clause.

**Report what you executed.** Name the tests you ran and their result, the
pre-existing failures you did not cause, and anything you changed but did not
execute. Never describe a fix as working on the strength of the diff.

---

## Stop and ask

- A guard fails and the fix looks like editing the guard. That is a decision
  change, not a test fix.
- The behavior you want to change is registered in `docs/internal/decisions.md`.
- The fix would weaken a control, a schema, or a QA check to make something
  pass.
- Root cause verification (stage 2) did not reproduce the divergence. Report
  the hypothesis and what you could not confirm; do not fix on a guess.
- The consolidated plan from stage 3b contains a cross-cutting refactor, or
  challengers disagreed in a way that changes scope.
