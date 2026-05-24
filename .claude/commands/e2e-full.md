---
description: Manual full-run E2E check — runs the threat-model pipeline against the bundled synthetic-repo fixture and validates ~25 structural assertions. Costs ~30–50% of a Pro 5h-window; never auto-triggered.
---

Run `make e2e-full` from the repository root. Stream stdout/stderr so the
user sees pipeline progress.

When the command exits, report **only**:
1. Exit code (0 = pass, 1 = pipeline failed, 2 = assertions failed, 3 = pre-flight)
2. Wall-time and the artifact path printed by the driver
3. A 1-line summary per failing assertion if any (pytest already prints them)

Do **not** analyze the threat-model.md content, do not summarize findings,
do not re-run anything. The driver is the single source of truth — you are
only relaying its output to keep the calling session lightweight.

If the user asks "why did X fail", read the failing assertion's message from
`tests/test_full_run_e2e.py` and the pipeline log under
`tests/fixtures/e2e/_last-run/.agent-run.log`.
