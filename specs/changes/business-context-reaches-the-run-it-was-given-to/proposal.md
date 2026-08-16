# Business context reaches the run it was given to

## Problem

`--context` supplies business context for one run. The value is validated,
captured to `<output>/.business-context-input.md`, and read by
`build_threat_modeling_context.py`. That builder runs only under the context-v2
producer, which `resolve_runtime_generation` selects for `full` and `rebuild`
inside the compact runtime. Every other run — `--incremental`, a dry run, a
`--deadline` or `--max-cost` run, `APPSEC_THIN_ORCHESTRATOR=0`,
`APPSEC_CONTEXT_V2=0` — builds its context artifact through the
`appsec-context-resolver` agent, which reads `docs/business-context.md` and
nothing else. The file is written and never read, and the run reports nothing.

Three smaller gaps sit on the same path.

The report names its context sources from a `Business Context File` field in
the context artifact's header table. Neither the deterministic builder nor the
agent template emits that field, and the derivation rule names
`docs/business-context.md` as the source regardless of which file was read.

`threat-model.yaml` stores `meta.business_context_sha256` and not the file it
came from. A run-only source is cleaned up with its run, so the next
incremental scan finds the digest missing and reports the business context as
changed — permanently, and for an edit nobody made.

`REQ-BIZ-003` names only `docs/business-context.md` as a source although its
own guard exercises the run-only one, and its `Applies to` lists two scripts
while selection, triage, the manifest, and the model metadata all carry the
promise.

## Goal

A supplied document either reaches the analysis or the run says it cannot,
the report names the file it actually read, and the stored model says which
file its rating rests on.

## Non-goals

- Teaching the legacy `appsec-context-resolver` agent to read the run-only
  file. The producer split stays where it is; the flag is refused where the
  producer cannot honour it.
- Persisting a supplied document into the scanned repository. That stays a
  human's decision.
- Guarding the second half of `REQ-MOD-008`. Citing a supplied document as a
  finding's source still needs an evidence shape that can hold it, which the
  `state-what-the-model-is-for` change already tracks as open.

## User-visible effect

`--context` on a run that cannot apply it fails with the reason and the flag
combination that works, instead of scanning as if no context had been passed.

The report's context sources name the file that was read, so a run-only
document is no longer reported as the repository's stored context.

An incremental scan after a run-only context says that the previous model was
rated against context this scan does not have, instead of claiming the context
changed and recommending `--full`, which would not restore it either.

## Requirement changes

`REQ-BIZ-003` gains the run-only source in its sentence, the files that carry
the promise in `Applies to`, and the new guards.

`REQ-MOD-008` gains a guard for the half that is now enforceable: a supplied
document is admitted as fenced data under its own name. The catalog keeps
saying nothing about the citation half, because nothing enforces it yet.
