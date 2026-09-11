# Stage 4 editorial packets: verified findings and implementation

This records the verification and implementation following `stage4-editorial-pass-measured-2026-09-11.md`. The reviewer remains a copy editor. New architecture findings remain outside its role.

## Verified observations

The September 11 reviewer transcript in session `90aba1e5`, agent `ad591cf008f8160d7`, contains four consecutive responses with 32,000 output tokens each. Each response reports 32,000 thinking tokens and no tool call. The durable run log records zero proposals and `apply_report_missing=true`. A missing-plan reproduction produced the misleading "No rewrite needed" receipt before this change.

The August 30 parent transcript in session `8192d6a5` resolves the earlier uncertainty about the 28 proposals. The initial application at 17:49 UTC rejected the entire plan because a Markdown action carried `path: null`. After the schema correction, the application at 18:18:54 UTC reported 28 applied edits. The 8.5-minute measurement describes plan generation, not a successful unattended end-to-end stage.

Stage 3 accepts triaged `manual_review` with QA exit 3 and cosmetic advisories with exit 4. Stage 4 previously treated nonzero exits as regressions. The corrected gate compares concrete observations with the accepted pre-edit state. It does not order exit codes numerically.

The old lexical guard accepted a change from "may allow unauthorized access" to "prevents unauthorized access". The updated guard rejects removed uncertainty markers and changed negation, while a separate test documents that token preservation cannot prove general semantic equivalence. No weaker model was selected on the assumption that the guard proves meaning preservation.

## Implementation

The builder creates disjoint packets bounded by block count and UTF-8 prose bytes. It balances by text size rather than source file. Oversized blocks are reported as unreviewed, never truncated. The compact runtime dispatches at most three packets concurrently and never retries a failed packet itself. Packet statistics use distinct variants so the existing statistics recorder retains every dispatch.

Each packet plan carries the run identity, batch identity, and block ids. The deterministic applier supplies file addresses and original text from the schema-validated projection. Stale runs, foreign block ids, unknown fields, duplicate actions, oversized plans, and escaping paths are rejected. Artifact paths cannot alias another file within the output directory. The original-text lock remains in force.

A malformed or missing packet does not discard valid sibling packets. Local invariant violations are rejected before application. The global guard and canonical rendering, QA, integrity, and secret gates remain release checks. A later regression restores the pass and records the discarded edits.

An explicit completed plan distinguishes "no change needed" from missing work. Receipts expose completeness separately from the controller's `pass` status. The durable `EDITORIAL_PASS` event feeds run-issue aggregation after temporary artifacts have been cleaned up.

The QA comparator preserves the accepted Stage-3 disposition and fingerprints observations rather than generated action ids. New non-cosmetic observations, increased multiplicity, actionable blockers, and tool errors cannot pass. A failed gate invalidates any earlier success. The accepted QA receipt is renewed only after fresh post-edit gates, preserving the manual-review disposition.

## Validation evidence

Before implementation, 214 focused tests passed. The final focused set passed 766 tests and covers interrupted packets, stale originals, invalid identities, partial application, missing schema validation, lost uncertainty, QA regressions under unchanged exit codes, and stale release receipts.

After the final statistics instruction was clarified, 68 statistics, dispatch, and prompt-budget tests passed again.

The September 11 projection partitions into 12 packets covering all 232 blocks without omission. Packet prose ranges from 4,959 to 5,009 UTF-8 bytes. This is a measured input bound, not a latency guarantee.

On a copy of that run, two August 30 proposals still matched their exact original text. Both applied through the new id plans. The invariant guard remained clean, the real canonical QA gate accepted the existing exit-3 state, and section integrity and the secret gate passed. This replay uses historical proposals and does not measure fresh reviewer quality or speed.

A golden fixture was frozen using the unchanged repository revision and replayed using the implementation. Markdown, SARIF, and scanner outputs showed no drift. YAML differed only in `time_local`; replaying with the unchanged revision reproduced that same clock drift. The fixture expectation was not changed.

The LLM boundary review considered prompt injection, tool misuse, output handling, context contamination, cascading failures, and misleading success reporting against the [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) and [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). Packet text cannot select a command or write destination through the applier. Prompt scoping is not a filesystem sandbox, and the host's token-cap retries are not controlled by this packet protocol.

The full-suite baseline also contains a report golden mismatch: the renderer emits `0.6.0-beta.3` while the golden still names `0.6.0-beta.2`. The unchanged checkout reproduces it. Three verbose-logging assertions depend on the per-user temporary marker; the unchanged checkout reproduces those failures when that marker exists, and the assertions pass without it. Neither unrelated mechanism was changed.

The isolated live thorough E2E initially hit the Claude session limit before analysis began. A retry completed Stage 1 and generated the report, then hit the session limit again after 3,504 seconds while repairing a Stage-3 control-subsection QA finding. Stage 4 was never dispatched. The E2E therefore supplies no fresh reviewer quality or wall-clock measurement. Its artifacts remain in the isolated verification directory; the original `juice-shop2` run was not modified.

The final `make check` completed with 14,405 passed tests, 98 skipped tests, and the one reproduced pre-existing report-golden failure. Prompt-budget, runtime-dispatch, recommender-coverage, schema, cleanup, permissions, configuration, and lint checks passed.

The coverage-enabled `make test` completed with 14,411 passed tests, 98 skipped tests, and the same reproduced pre-existing report-golden failure.
