# Plain-language wording for five requirements

## Approved requirement

The operator approved this wording and its plain-language summary on 2026-10-18. Meaning, IDs and bindings are unchanged; only internal terms are replaced.

> **REQ-FLW-008:** Every execution mode must state what happens when the budget runs out. Interrupted or incomplete work must never be reported as completed. When the budget is too small, the run must drop optional model work first and keep enough budget to finish. If the required analysis still does not fit, it must deliver a clearly marked incomplete report containing only validated results.
>
> **REQ-SCO-002:** Structured score output must show whether the scan completed, which scoring and rule-catalog versions produced the score, which rules applied, and which findings were excluded, so scores from different runs can be compared fairly.
>
> **REQ-CFG-003:** Refreshing the secure-coding baseline must use the configured source and report when the installed copy differs. A changed baseline version must be accepted explicitly before every place that declares it is updated together.
>
> **REQ-EVO-003:** A change that breaks result files, report links, or organization configuration formats must come with a new version or a migration path.
>
> **REQ-USE-004:** A full assessment must keep the history of earlier results. Only an explicitly requested rebuild from scratch may discard the model and its history.

## Behavior

No product behavior changes. The requirements previously used producer terms ("deterministic controller runs", "producer completion", "baseline IDs", "organization interfaces", "deliberate rebuilds") that a user cannot interpret. The new wording states the same obligations in user terms.
