# Reserve the controller's completion budget

## Approved requirement

The operator approved the wording and meaning of this REQ-FLW-008 extension on 2026-10-15:

> Budget behavior must be explicit for each execution mode, and interrupted or incomplete work must never be reported as successfully completed. Deterministic controller runs must reserve resources for required completion work, omit optional model work when necessary, and provide a clearly marked incomplete report of validated results when the budget cannot cover required analysis.

## Behavior

One hard budget bounds the assessment. The controller protects required completion work before dispatching optional jobs, uses their existing deterministic replacements when resources run short, and preserves money and time for the report. The deprecated soft-budget spelling retains its existing 1.25 conversion; it does not introduce another target.

A budget interruption produces a separate, explicitly incomplete snapshot of accepted analysis candidates and outstanding work. It never publishes a canonical model or signals successful completion. Source, accounting, validation and secret-protection failures remain blocking. The existing accepted-job cache supports continuation with revised limits.

The producer policy lives in `AssessmentBudget` and `AssessmentJobs`; the controller declares outstanding STRIDE work and the required report job. The lifecycle owns the incomplete snapshot and its structured state contract. No new model permissions or source access are introduced.
