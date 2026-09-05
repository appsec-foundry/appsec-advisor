# A cost budget steers the run

## Problem

A user who wants to bound what a run spends has two flags today, and neither does the job.

`--max-cost` is refused before anything happens. `_unsupported_runtime_reason` in `scripts/orchestration_controller.py` returns `--max-cost is not implemented by the compact runtime`, routing aborts with exit 2, and no output directory, run state, or dispatch is created. An organization preset carries the same value through `guardrails.max_cost_usd`, which `_apply_org_profile` writes into the same `max_cost_usd` key when no CLI flag was passed. `--config-summary` prints it as an active limit (`Limits    : cost $10.00`), and every run using that preset then aborts at routing. The example in `docs/org-profiles.md` still shows that guardrail as usable.

`--max-budget` in `scripts/run-headless.sh` is not the plugin's. It is passed through as `--max-budget-usd` to the `claude` CLI and takes effect only under API billing; under a subscription the wrapper drops it with a warning. When the host cuts the session, it cuts it wherever the run happens to be. The run is not resumable mid-analysis, and the only salvageable state is a completed Stage 1, which `--rerender` can still turn into a report. Everything earlier is spent money with no product.

So the choice is between a flag that refuses to start and a flag that destroys what the run has produced.

## Measured cost shape

One run, so the numbers are shape and not a general law: juice-shop, 2026-08-31, window 07:38–09:13 UTC, standard depth, seven components, output `docs/security`, read with `scripts/cost_running_total.py --format json`.

The run cost $29.59, of which the host session carried $9.94 and 24 sub-agents carried $19.65. Nothing was unmetered in this run and `cost_is_floor` was false, so the mid-run figure was a real total rather than a lower bound. The host session emitted 183 cumulative `SESSION_STOP` snapshots, so cost is observable continuously and not only at the end.

Per agent, recomputed from the price table: preparation before STRIDE cost $6.00 (recon $2.26 on Haiku, actor discovery $0.62, architecture $1.22, trust boundary $1.04, controls $0.86); the seven STRIDE analyzers cost $7.94 with a range of $0.77 to $1.89; merger, evidence verifier, and post-STRIDE synthesizer cost $2.03; seven abuse-case verifiers cost $2.97; the MS renderer and the security-architecture renderer cost $2.22 together. These per-agent figures sum to $21.16 against the aggregator's windowed $19.65, 8% higher because the window clips differently — they are not the same number and should not be compared as one.

Two ratios matter for a projection. The host session cost 0.51 of the sub-agent spend, and it accrues continuously rather than at a boundary. A single dispatch is the smallest steerable unit and costs $0.32 to $2.26.

## Goal

A declared budget bounds what a run spends and still leaves a complete report. A run is sized to its budget before it starts and refuses to start when it cannot fit, a run that drifts sheds declared optional work and names what it dropped, and a run that still does not fit finishes and reports the overrun rather than dying mid-analysis.

## Non-goals

- Killing a run at the cap. That is what the wrapper's hard cut already does at the host, and the product of a killed run is nothing. A budget that steers cannot also guarantee a ceiling; a user who needs the ceiling keeps that flag.
- Abandoning components mid-run. Once a component is in the dispatch plan it is analyzed or the run fails. `REQ-FLW-002` holds: every analyzed component is checked against all six categories, and `stride_dispatch_waves.claim` returning `blocked` stays a failure. A budget never converts an incomplete component into an accepted one. Sizing the analyzed set before the plan exists is a different question and is in scope.
- `--max-wall-time`. It shares the rejection path but not the mechanism, and it stays refused.
- Cost accuracy under subscription billing. The figures are price-table valuations of token counts, not money billed. Under a subscription a budget bounds modeled spend as a proxy for window consumption, and the flag has to say so.

## Where the budget is declared

The plumbing exists and is wired end to end under a name that has to change.

`--max-cost <usd>` on the skill is parsed by `resolve_config.py` and lands in `cfg["max_cost_usd"]`. `presets.<name>.guardrails.max_cost_usd` in an organization profile is in `schemas/org-profile.schema.yaml` and merged by `_apply_org_profile` whenever the flag was not passed. `run-headless.sh --max-cost` is parsed, marked `UNSUPPORTED_RUNTIME_OPTION`, and dies with "not supported by the compact runtime". Removing those three refusals is what turns the parameter on.

The name is wrong for what the flag now does. A value that may be exceeded by 20% is not a maximum, and a reader meets the name on the command line rather than in the documentation. Beside the wrapper's `--max-budget` it is worse: two flags both saying "max", one of which kills the run.

So the soft budget is `--soft-budget <usd>`, the organization key is `guardrails.soft_budget_usd`, and the wrapper's hard cut becomes `--hard-budget`. `--max-cost`, `max_cost_usd`, and `--max-budget` stay as deprecated aliases that warn.

The compatibility cost of renaming the published key is close to zero, which is why the rename is worth doing now rather than being deferred. `guardrails.max_cost_usd` is unusable today: a profile that sets it makes every run using that preset abort at routing with exit 2, so no working installation depends on it. `REQ-EVO-003` is satisfied by the alias, not by a migration. The only places carrying the old key are the fixture profiles under `tests/fixtures/org-profiles/`.

## Mechanism

The decision belongs to the controller at its existing boundaries, not to a background watcher and not to the orchestrator's judgement. `scripts/cost_running_total.py` already answers the question deterministically and with no model tokens, in 83 ms against this run's logs including interpreter startup.

Admission happens before the run starts. Project the total from the last-run cache for this output directory when one exists, otherwise parametrically from the component count the dispatch manifest will select and the depth, the way `scripts/estimate_duration.py` already projects wall time. A refusal before the first dispatch costs nothing; a refusal at $18 costs $18.

### Sizing the run at admission

A ceiling that must hold in the extreme cannot rest on mid-run shedding alone. The optional ladder is worth about 10 to 15% of a run, which covers drift but not a budget set below what the planned scope costs. The run therefore has to be sized before its plan exists, not abandoned after.

`build_stride_dispatch_manifest.select_stride_components` already does exactly this shape of work for a different reason. An operational ceiling may shed only components that `_is_internal_only`; anything that earned its place through exposure, ci-cd or supply chain, crown-jewel, auth, frontend, or the exposure-unknown fail-safe is never dropped, and the ceiling lifts instead. The returned report carries `selected`, `excluded` with a reason per component, and `lifted`.

The disclosure path for that report is also built and guarded. `aggregate_run_issues._extract_stride_ceiling_events` raises a Run Issue for a lifted ceiling and for every component an overflow dropped, and `REQ-FLW-002` binds both as guards. A budget-driven trim needs a reason on the excluded entry, not a new channel.

A budget sizes the run through that same predicate. Project, and when the projection does not fit, lower the ceiling until it does, shedding internal-only components in priority order. When the earned set alone does not fit, refuse admission and name the shortfall, the depth that would fit, and the flag to raise the cap. A budget never removes an exposed or crown-jewel component; that is a refusal, not a trim.

This inherits one blocker. Selection falls back to `passthrough` when no component in `.components.json` carries `deployment_zones`, and every component then passes with no priority order to trim along. On such an inventory a budget can only refuse, never size. This is the same zone-vocabulary gap that blocks a cheap STRIDE tier from becoming a default, and it should be fixed once for both.

### Steering the run once it is under way

Checkpoints run at boundaries the controller already owns. Compare the measured total plus the projected remainder against the budget. The remainder is the not-yet-dispatched work at this run's own observed per-agent cost, multiplied by the observed host ratio. After the first STRIDE wave the projection is calibrated on this repository's own components, which is the point where it becomes worth acting on.

Shedding follows a fixed ladder, in this order, each step disclosed in the report's run statistics and in Run Issues.

- Abuse-case verification, worth $2.97 in the measured run, about 10%. Two suppression paths already exist in `orchestration_controller.prepare_abuse`: the `skip_abuse_case_verification` config flag, and an active budget claim, which returns `run_gate` with no dispatch jobs and a receipt saying why. `REQ-MOD-004` is not harmed, because unverified abuse cases stay hypotheses, which is what the requirement already says they are.
- STRIDE retries beyond the first attempt, except where the first attempt produced no output at all. A retry of a component that already produced valid output is optional work; a component with nothing is not.
- Architect review, and repair iterations beyond one. `max_repair_iterations` is already 1 at quick and standard and 3 only at thorough, so this step bites at thorough alone. No architect agent ran in the measured run, so neither has a measured saving here.

Concurrency couples to the budget. `STRIDE_DISPATCH_CONCURRENCY` is 5 by default, so up to five components at roughly $1.20 each can be in flight when a checkpoint fires, and that spend cannot be recalled. Once the projection is within one wave of the cap, drop the concurrency to one. This is the only lever on in-flight exposure, and it costs wall-clock time.

The signal is its own file, not `.budget-critical`. That flag means "shorten" in one place and "abort" in another: `budget_watchdog.has_active_critical_claim` suppresses abuse verification in `prepare_abuse`, and the same claim in `_gate_architecture_stage` writes `phase=7 status=aborted reason=budget-critical-before-boundary` and raises a `ControllerError`. A cost-driven shed must not inherit the abort.

Cutting per-component turn ceilings is not part of the ladder. `docs/internal/cost-model.md` measured the opposite of a saving: `web3-nft` stopped at exactly its ceiling of 33 turns, produced no output, and cost a full retry. Work that is removed saves; work that is truncated costs more.

## Accuracy target and ceiling

The target is a declared budget of $30 held to within 10%, so a run finishes at or below about $33. The extreme case is 20% and not more, so about $36 is the point at which the design has failed.

Those two numbers are statements about three error terms, and the measured run says what each of them costs.

The in-flight term is the dispatches already running when a checkpoint fires. Their spend cannot be recalled. At the default concurrency of five that is up to about $6 and the target is unreachable on arithmetic alone. At concurrency one it is the most expensive single component, $1.89 in the measured run.

The reserve term is the projection error on the work that still has to happen after the checkpoint. The full tail after the last STRIDE component was $7.22 of sub-agent spend, or about $10.9 with the host share; with abuse-case verification already shed it is about $6.4. Holding $3 of tolerance while $1.89 is in flight leaves about $1.1 for this term, which is an accuracy of roughly 17% on the reserve. A last-run cache for the same repository at the same depth can deliver that. A parametric projection on a first run against an unknown repository cannot.

The floor term is not an error. A complete report for that repository costs about $25 even after everything optional is shed. A budget below the floor cannot be met by shedding, which is what admission is for.

So the target holds under three conditions, and the flag has to say so rather than promise a band it cannot keep: the budget is at or above the floor, concurrency drops to one once the projection is within a wave of the cap, and the reserve comes from a cache rather than a formula.

The case the design is actually for looks like this. The `docs/internal/cost-model.md` baseline run cost about $35 with everything on. Under a $30 budget, shedding abuse-case verification alone removes about $4.5 including the host share and lands the run near $30 with a complete report. The ladder is worth roughly the same order as the tolerance, which is why a budget slightly below a run's natural cost is the case that works and a budget far below it is the case that admission has to refuse.

Where the reserve is a formula rather than a cache, the checkpoint should take its upper bound rather than its midpoint. That sheds optional work on some runs that would have fit, and it is the right trade for a first run: a dropped abuse-case verification is disclosed and repeatable, an overrun is not.

### The ceiling is a target with a backstop, not a guarantee

Sizing at admission and shedding under way move the expected outcome to within 10% and keep the extreme inside 20%. Neither can promise that 20% is never exceeded. Once a component is dispatched its cost is committed, and the only mechanism that can stop a run at an exact number is one that cuts the session, which leaves no report and contradicts the point of the change.

So the guarantee, where a user needs one, is layered and its top layer costs the report. Set the wrapper's `--hard-budget` to about 1.25 times the soft budget, so $37.50 against a declared $30.

That factor is derived from the declared tolerances rather than chosen. A soft budget of $30 ends a normal run at or below $33 and a bad one at or below $36. The hard cut must sit above that band, because inside it a kill would destroy a run that behaved exactly as declared, and a killed run has no report. The remaining margin covers a second effect: the two sides count differently. The soft mechanism values tokens with the price table in `agent_logger._calc_cost`, while the hard cut is the CLI's `--max-budget-usd` counting what the host counts. A backstop sitting exactly on $36 could fire on that difference alone. Change the tolerances and the factor moves with them.

The host kill therefore exists only for the case where the soft mechanism was wrong. When it fires after Stage 1 completed, `--rerender` still turns the existing artifacts into a report; before that boundary the run is lost.

A run that ends inside 20% without shedding anything is the normal case, and it should say what it spent against what it declared, so the numbers can be checked rather than trusted.

## User-visible effect

`--soft-budget`, and the deprecated `--max-cost` behind it, starts a run instead of refusing one, and an organization preset that declares a budget stops disabling every run that uses it.

A run whose projected cost does not fit its budget is sized down to internal-only components before it starts, or, when the components that earned their place still do not fit, says so before it spends anything and names what would fit.

A run that drifts over its budget arrives at a complete report with less optional work, and the report says which work was dropped and why.

A run that cannot fit even after shedding finishes and reports the overrun. It does not stop mid-analysis, because a stopped run produces nothing a reader can use.

## Proposed requirement wording

Not written to `specs/requirements.md` until approved.

`REQ-FLW-004 — A declared budget sizes the run and drops only optional work`

> A run with a declared cost budget is sized to fit before it starts and does not start when the components that earned selection cannot fit. A run that drifts over its budget drops only declared optional work. The report names the components the budget excluded and the work it dropped. Coverage of an analyzed component, evidence, and validation are never reduced to meet a budget.

`REQ-FLW-002` already forbids a silent cost-driven reduction of STRIDE coverage and needs no change. Sizing the analyzed set before the plan exists is not a reduction of an analyzed component's coverage, and the naming duty above is what keeps it from being silent.

## Open questions

Whether the budget should apply to the whole run or only to the analysis stages. The measured floor is dominated by work that has to happen for any report at all, and a budget that cannot influence that work is honest but less useful.

Whether the declared budget should also set the wrapper's `--hard-budget` backstop automatically at about 1.25 times its value in headless runs, so one number is the whole interface, or whether that stays the operator's separate decision because it trades the report for the ceiling.

Whether budget-driven sizing should wait for the `deployment_zones` vocabulary or ship refusing on a passthrough inventory. Refusing is honest and useless on exactly the repositories that have not migrated.
