# Resume a controller assessment after a plugin change

## Problem

A headless controller assessment refuses `--resume` after any plugin change,
so checking whether a fix lets an interrupted run finish repeats every model
step. Each job already binds its prompt, schema, input and normalizer in its
request and is rechecked against today's acceptance checks.

## Goal

Change MR-4 so that `--resume` continues an unfinished assessment whose only
change is the plugin runtime, reusing each accepted job whose request still
matches and that today's checks accept, and redoing the rest.

## Non-goals

- Resuming after a change of sources, configuration or limits.
- Continuing a completed assessment, which still needs `--rebuild`.
- Clearing an unknown-cost reservation.
