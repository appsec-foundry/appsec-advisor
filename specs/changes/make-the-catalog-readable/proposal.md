# Make the catalog readable

## Problem

`specs/requirements.md` is correct but hard to read for anyone who does not already know the code. Six problems cause this:

- The catalog starts with the first entry. Nothing says what the plugin does, who uses it, or which parts it has.
- Terms such as finding anchor, control domain, depth mode, rebuild, operator, question package, methodology profile, vendored baseline, and headless are never explained.
- Some entries hold several promises in one paragraph. `REQ-BIZ-005` has about fifteen sentences covering the dialog, file locations, a legacy fallback, and precedence rules. `REQ-RPT-003` combines the content of a finding, valid references, code formatting, and the team questions in the Management Summary.
- Many sentences describe a mechanism in the passive voice instead of what the user experiences, for example "Required analysis inputs and outputs are validated before they are consumed or published."
- Several titles do not tell a reader what is promised, for example "Public finding anchors remain internally consistent".
- Entries appear out of order (`REQ-BIZ-005` before `REQ-BIZ-001`), and numbering gaps are not explained.

## Goal

A reader without knowledge of the code understands in one sitting what the plugin promises. Every entry follows one pattern: the title states the promise, the first sentence repeats it in full, and further sentences or list items state its conditions.

## Non-goals

- Changing behavior. Every promise in the current catalog keeps its meaning. A sentence may move to another entry or be rephrased, but no condition is dropped or widened.
- Changing technical bindings beyond what the two new IDs need.
- Writing new guards.

## Proposed change

The full draft is in `requirements.md` next to this proposal. It replaces `specs/requirements.md` as a whole.

- An overview at the top explains the four ways the plugin is used and how to read the catalog. A glossary at the end explains 28 terms.
- Sections follow the user's path: purpose, findings, running the analysis, business context, report, score, follow-up, on-demand analysis, trust, configuration, compatibility.
- `REQ-ARC-001` and `REQ-REQ-001` move into the report section. Their IDs stay.
- Every entry is rewritten in the active voice from the user's point of view. Long entries get a lead sentence and a list of conditions.
- Two entries are split. IDs are never reused, so each split creates one new ID:
  - `REQ-BIZ-005` keeps the dialog. The new `REQ-BIZ-006` takes over saving the answers, the old file location, precedence, cleanup, and the run-only exception.
  - `REQ-RPT-003` keeps the content of a finding, references, and code formatting. The new `REQ-RPT-009` takes over the team questions in the Management Summary and the completion-summary pointer.

## Decisions for the operator

1. **Approve the full text.** All titles and normative sentences change. Approval covers the draft as a whole, including the two new IDs.
2. **File paths in `REQ-BIZ-006`.** `specs/README.md` keeps paths out of the catalog. The draft keeps `docs/security/business-context.md` and `docs/business-context.md` because users create and edit these files themselves, and removing them would weaken the compatibility promise for the old location. The alternative is to describe them as "the business-context file" and leave the paths to `docs/threat-modeler.md`.
3. **Command names in examples.** The draft names `/appsec-advisor:create-threat-model`, `/appsec-advisor:review-threat-model`, `/appsec-advisor:ask-threat-model`, `--skip-context`, `threat-model.yaml`, and `F-003`. These are things a user types or sees, so the draft treats them as part of the promise.

## Review

An independent readability review and a clause-by-clause comparison against the current catalog were run on the draft. Their findings are incorporated. The comparison found no condition lost in the two splits.

## Where each moved condition went

| Current entry | Condition | Draft location |
|---|---|---|
| `REQ-BIZ-005` | Dialog flow, answer options, skip, headless, uncertainty | `REQ-BIZ-005` list |
| `REQ-BIZ-005` | Saving answers, legacy file, precedence, copy without change, cleanup, run-only source, no saving in headless or `--skip-context` runs | `REQ-BIZ-006` |
| `REQ-RPT-003` | Where, why, what to change; existing references; inline-code format | `REQ-RPT-003` |
| `REQ-RPT-003` | Up to three team questions, order, references, no verification questions, empty block omitted, completion summary pointer | `REQ-RPT-009` |
| `REQ-MOD-004` | Definition of an abuse case | Glossary |

All other entries keep every condition in the same entry.
