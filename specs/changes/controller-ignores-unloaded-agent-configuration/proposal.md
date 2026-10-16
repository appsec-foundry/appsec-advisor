# Controller assessments ignore repository agent configuration they never load

## Problem

A headless controller assessment applies TR-2 unchanged and rejects any
repository that commits Claude Code configuration, such as a project
`CLAUDE.md`. Its model exchanges never load that configuration: each runs
tool-less with `--safe-mode --restricted` in a private directory outside the
repository. Such repositories cannot be assessed without `--trust-mode
trusted`, which also skips the checks that still matter.

## Goal

Add TR-10: controller assessments do not reject repository-owned Claude Code
configuration. Escaping symlinks, IDE-loaded files and unlisted
related-repository URLs still abort the run. A live negative control shows that
a plain host loads hostile configuration from the checkout and the controller's
transport does not, even when started inside it, and the controller refuses a
host directory inside a selected checkout.

## Non-goals

- Changing TR-2 for the session-orchestrated pipeline, whose sessions run in
  the target repository.
- Downgrading any remaining preflight finding to a warning (TR-3).
