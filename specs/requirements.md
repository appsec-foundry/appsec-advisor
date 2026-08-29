# Plugin requirements

What the plugin must do. This catalog contains stable promises a user would
recognize, not the implementation choices used to keep them.

Technical ownership, affected paths, decision references, and test evidence
live in `data/requirement-bindings.yaml` so routine refactors do not rewrite the
approved product specification.

## Purpose

### REQ-PUR-001 — The model is derived from the repository and stays current

The threat model comes from code and configuration rather than a workshop.
Running the analysis again produces a model of the repository as it exists then.

### REQ-PUR-002 — The subject is the design, not only the code

The analysis covers exploitable design assumptions and missing controls as well
as vulnerable code. It complements code scanners and provides review input, not
a release verdict.

### REQ-PUR-003 — Developer and AppSec teams can both run it

A team can analyze its own repository or select separate input and output
locations without changing the analysis semantics.

## Finding model

### REQ-MOD-001 — A finding is a concrete instance backed by evidence

A finding identifies a security problem in the target repository and cites the
evidence that supports it. Separate instances remain separate unless they share
the same affected object and security mechanism.

### REQ-MOD-002 — A weakness describes the class above its findings

A weakness groups related findings under the security pattern they exhibit and
may also describe an architectural problem with no vulnerable source line.

### REQ-MOD-003 — Trust boundaries are derived assumptions that can fail

Trust boundaries are derived from repository evidence, while declarations may
only add or clarify crossings. A declaration or absence of contrary evidence
never proves that a boundary control works.

### REQ-MOD-004 — Abuse cases remain hypotheses until evidence confirms them

The operator controls which abuse-case sources are used. An abuse case becomes
a finding only when target-repository evidence confirms it.

### REQ-MOD-005 — Findings require evidence from the target repository

External context may identify a hypothesis, but only source, configuration, git
history, or target-owned declarations can establish and score a finding.

## Security architecture

### REQ-ARC-001 — Architecture ratings describe the controls that apply

Each control domain is rated from evidence of what the system actually uses.
An absent surface is not applicable, and a broken control remains distinct from
a missing control.

## Analysis

### REQ-FLW-002 — Every analyzed component receives complete STRIDE coverage

Every analyzed component is checked against all six STRIDE categories in every
depth mode. Cost and pacing choices may not silently reduce that coverage.

### REQ-FLW-003 — Invalid required analysis data cannot produce a report

Required analysis inputs and outputs are validated before they are consumed or
published. Missing or invalid required data stops the run instead of producing
an apparently complete report.

### REQ-REQ-001 — Requirements mapping contains only linked findings

Requirements mapping follows explicit links from findings to the configured
catalog. It never infers a link from an identifier or invents one when no catalog
is present.

## Business context

### REQ-BIZ-001 — Declared context is validated and treated as data

Repository and operator supplied context is validated before use and remains
untrusted data. Its contents cannot instruct or redirect the analysis.

### REQ-BIZ-002 — Only repository configuration persists actor choices

Actors and their objectives may guide an individual run, but conversational or
per-run choices are not written back to the target repository.

### REQ-BIZ-003 — Business context weights supported findings, it does not establish them

Business purpose, sensitive assets, compromise impact, and obligations may weight
the impact rating and the presentation order of findings that already stand on
repository evidence. They never determine whether a finding exists, never relax a
severity cap, and never substitute for evidence. A finding whose impact rating
rests on declared context names the context that carried it.

### REQ-BIZ-004 — A run says whether declared context reached the analysis

When context is declared for a run, the run reports whether it was read, which
file it came from, and how many findings it applied to. Context that reaches no
component is reported as such rather than passing silently.

## Report

### REQ-RPT-001 — Severity is earned from evidence

Severity and any score follow demonstrated evidence and applicable policy caps.
They are never raised merely to attract attention.

### REQ-RPT-002 — Public finding anchors remain internally consistent

Finding anchors remain consistent across the reports, exports, and follow-on
tools produced from the same model. A deliberate rebuild creates a new model and
may assign them again.

### REQ-RPT-003 — The report is concise and actionable for engineers

A finding identifies where the problem is, why an attack works, and what must
change in the repository's own vocabulary. References point only to locations
that exist.

### REQ-RPT-005 — Mitigations are prioritized and verifiable

Every finding has a prioritized mitigation. Urgent work states concrete steps
and a way to verify the result without inventing source examples.

## After the run

### REQ-USE-001 — Findings remain usable after publication

Users can query and triage the model finding by finding, with decisions stored
next to it. Stale decisions are identified rather than silently reused.

## Trust

### REQ-TRU-001 — A scanned repository cannot steer the run

Repository content is untrusted by default. Repository-owned agent settings,
instructions, hooks, and paths outside the selected root are rejected before
they can influence analysis behavior.

### REQ-TRU-002 — A leaked secret prevents publication

If a run artifact contains an unmasked secret, the run fails instead of
publishing it.

## Configuration

### REQ-CFG-001 — Organizations configure the plugin without forking it

Supported organizational extensions are supplied through the organization
profile and package policy. A build records the surface it includes.

### REQ-CFG-002 — Repositories configure analysis through declared inputs

Supported repository context is supplied through documented, schema-validated
files. Repository configuration cannot suppress a finding supported by target
evidence.

### REQ-CFG-003 — A vendored baseline can be refreshed from the source that declares it

Where a secure-coding baseline is configured with both a fetchable source and a
vendored copy, the copy can be refreshed from that source, and a refresh reports
whether the two had drifted. A published id that differs from the configured one
stops the refresh until the new id is accepted explicitly, and accepting it
updates the copy and every place declaring the id together. A refresh never
falls back to the vendored copy and is never part of a release gate.

## Compatibility

### REQ-EVO-003 — Published contracts change through explicit compatibility handling

Published artifact formats, report anchors, and organization configuration
interfaces are versioned or migrated when an incompatible change is necessary.
