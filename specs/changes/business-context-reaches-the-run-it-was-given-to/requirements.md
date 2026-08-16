# Sourced constraints

## BIZCTX-002 A supplied document reaches the analysis or the run says so

Source: `docs/threat-modeler.md` → Business context; decision `RC-1`.

- Business context comes from `docs/business-context.md` or from a source
  supplied for one run.
- A run that cannot read the supplied source refuses the flag instead of
  scanning without it.
- The refusal names the producer that resolved and the flag combination that
  applies the document.

## BIZCTX-003 The run says which context file it read

Source: `AGENTS.md` → Fix the source, not the symptom; operator request.

- The context artifact names the file the analysis read, or states that there
  was none.
- The report derives its context sources from that name and never substitutes
  one source for another.
- The stored model records the file its business-context digest was taken
  from.
- A digest that is missing because a run-only source was cleaned up is not
  reported as a changed context.
