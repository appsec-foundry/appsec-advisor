# Non-interactive mode

Use `scripts/run-headless.sh` to run a full threat-model assessment from a
shell, CI job, or scheduled task. The wrapper owns authentication, host-level
cost and duration limits, trust preflight, terminal cleanup, and exit codes.

## Supported assessment modes

The headless wrapper uses the compact controller runtime only.

| Mode | Command | Behavior |
|---|---|---|
| Full | `run-headless.sh` or `--full` | Reassesses the repository and preserves report history. |
| Incremental | `run-headless.sh` without a mode flag over an existing model | Re-analyzes only changed components and carries the rest from the previous model; refused before output creation when the previous model cannot be carried, for example in a fresh clone without its `.appsec-cache/`. |
| Rebuild | `--rebuild` | Clears the prior model and cache before a fresh assessment; IDs may change. |
| Rerender | `--rerender` | Rebuilds the report from validated Stage-1 artifacts without analyzing source again. |

The `--incremental` flag, resume, assessment dry-run, PR mode, baseline restore,
`--max-wall-time`, and `APPSEC_LIVE_PHASE=1` are unsupported.
They fail before output creation, run-state mutation, or model dispatch. Use
`--full` after source changes, `--rebuild` for a clean restart, and `--rerender`
only when the existing Stage-1 artifacts remain authoritative.

`--dry-run` remains available with `--clean-cache` and `--clean-all`; that is a
deterministic cleanup preview rather than an assessment mode.

## Prerequisites

1. Install the Claude Code CLI and place `claude` on `PATH`.
2. Authenticate with an API key or a stored Claude subscription login.
3. Clone or install the plugin.

With API billing, supply the key through the environment and keep it in the CI
secret store. The wrapper never needs the key as a command-line argument.

```bash
export ANTHROPIC_API_KEY="<from-secret-store>"
./scripts/run-headless.sh --repo /path/to/repository --full
```

An installed wrapper can be invoked from its plugin directory. Set
`CLAUDE_PLUGIN_DIR` when several installed copies exist and the desired one is
otherwise ambiguous.

### Claude launcher wrappers

Set `APPSEC_CLAUDE_EXECUTABLE` when the environment must start Claude Code
through a gateway, authentication, or observability wrapper. The value names
one executable; command prefixes and shell fragments are not accepted. The
headless runner uses it for both the authentication preflight and the assessment
process. Without the variable, it continues to invoke `claude` from `PATH`.

For example, keep a LiteLLM-specific launcher outside the plugin:

```sh
#!/bin/sh
exec lite --base-url "${LITELLM_PROXY_URL:?}" claude "$@"
```

Then select it for one run:

```bash
APPSEC_CLAUDE_EXECUTABLE=/opt/company/bin/claude-via-lite \
LITELLM_PROXY_URL=https://litellm.example.com \
./scripts/run-headless.sh --repo /repos/team-api --full
```

Use an absolute path in unattended environments. Store proxy credentials in the
environment's secret store rather than in the launcher or plugin configuration.

## Common workflows

Scan the current repository and write to `docs/security/`:

```bash
/path/to/appsec-advisor/scripts/run-headless.sh --full
```

Scan another team's repository without writing report artifacts into it:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --full --sarif
```

Start clean when prior state is not reusable:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --rebuild
```

Rerender after a report template, renderer, or QA contract change:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --rerender
```

Rerender is not a source-code rescan. It fails closed if its required
structured Stage-1 artifacts are missing or invalid.

## Assess several repositories as one system

This mode is experimental. The report says so in its Management Summary, and the run says so when it starts.

Repeat `--repo` to assess several local Git checkouts as one system. Every selected repository is scanned freshly, and the run publishes one `threat-model.yaml`, one `threat-model.md` and one Figure 1 in the `--output` directory. `--project` sets the system name in the report, and `--slug` adds a stamped copy of the deliverables.

```bash
./scripts/run-headless.sh \
  --repo /repos/frontend \
  --repo /repos/backend \
  --output /appsec-reports/order-system \
  --soft-budget 40 \
  --sarif
```

A combined run has these requirements:

- Select 2–16 top-level Git checkouts. A checkout inside another selected checkout, or two paths that name the same directory, stop the run.
- Choose an `--output` directory outside every selected checkout. The run writes nothing into a selected checkout.
- Set `--soft-budget` or `--hard-budget`. The run reserves each model call against this budget and stops when it is exhausted. With only `--soft-budget`, the limit is 1.25 times that value.
- The untrusted-repository preflight checks every selected checkout. `--trust-mode trusted` skips it for all of them.

What the result shows:

- Each component card and source location names its repository, for example `Order API [backend]` and `backend/src/orders.ts:42`. The YAML records the repository separately in a `source_inventory` and in every source reference, and SARIF uses one location base per repository.
- The order of the `--repo` flags does not change the result. No repository takes precedence.
- A connection between repositories appears only when source evidence on both sides supports it. Matching names alone never connect two repositories, and repository membership never creates a trust boundary.
- Symbolic links, submodules and nested repositories inside a checkout are not read. The model lists each of them as an omitted path.

A combined run uses Sonnet 5.5 for STRIDE at quick and standard depth, while a single-repository scan keeps STRIDE on Sonnet 4.6. Each STRIDE result must come back from one model call, and Sonnet 4.6 exhausts its thinking there without returning one. STRIDE calls therefore cost more: Sonnet 5.5 counts the same text in about 30% more tokens at the same price per token. The run prints each role's model at the start and warns about this change, even with `--quiet`. An explicit STRIDE model through `APPSEC_STRIDE_MODEL` or `--model` is kept; if it is Sonnet 4.6, the run warns that STRIDE is expected to return no result.

The models in a combined run have no file, shell or network tools. The controller serves every source excerpt a model reads, only from the selected checkouts, with secrets masked. Each analysis step is recorded, so `--resume` continues an interrupted run without repeating accepted steps, as long as the sources, settings and plugin version are unchanged. A run whose model cost became unknown cannot resume; start a new run.

A new run in the same `--output` directory reuses every model step of an unfinished earlier run whose input is unchanged. A directory that already holds a report needs `--rebuild`, which removes only the files the earlier run wrote and refuses when any other or edited file is present; `--rebuild` also redoes every model step and cannot be combined with `--resume`. `--incremental`, `--rerender`, `--dry-run`, `--base`, `--pr-mode` and `--restore-from` are not available for combined runs and stop them before any model call. Business context, known threats and a run-wide `--requirements` catalog are supported; each repository keeps its own business context and known threats. A requirements catalog inside one of the selected repositories stops the run unless you pass `--requirements <source>`. Repository-local abuse-case files stop the run; use `--no-abuse-cases` or move the cases to the organization profile. The follow-on skills that only support single-repository models, such as fixing findings in place or publishing the model into a repository, say so when they open a combined model.

## Cost and duration limits

Headless limits are enforced outside the model runtime:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --full \
  --max-duration 3600 \
  --soft-budget 30
```

`--max-duration` uses the host `timeout` command.

`--soft-budget` rejects a run before it starts if the estimated cost exceeds the budget. Once started, the run can exceed that budget and reports the overrun. `--hard-budget` stops the session at the host level and applies to API billing. If you supply only a soft budget, the hard budget defaults to 1.25 times that value. Set `--hard-budget` to override it.

An interrupted assessment cannot resume mid-analysis. If Stage 1 finished, use `--rerender` to create the report from its validated artifacts. The run prints the applicable recovery command. `--full` and `--rebuild` require `--force` before discarding a completed Stage 1. If Stage 1 did not finish, start again with `--full` or `--rebuild`; partial component artifacts remain for diagnosis only.

## Scheduled CI example

Run full assessments on a schedule or by explicit manual trigger. Pull-request
delta mode is not supported.

```yaml
name: Threat model
on:
  schedule:
    - cron: "0 3 * * 1"
  workflow_dispatch:

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run full assessment
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          /path/to/appsec-advisor/scripts/run-headless.sh \
            --repo "$GITHUB_WORKSPACE" \
            --output "$GITHUB_WORKSPACE/docs/security" \
            --full --sarif --max-duration 7200 --max-budget 25
```

Do not execute repository-owned hooks from an untrusted checkout. The default
`--trust-mode untrusted` preflight rejects repository-resident Claude hooks and
out-of-repository symlinks, enables strict URL handling, and redacts paths in
runtime logs. Use `--trust-mode trusted` only for a repository and Claude
configuration you control.

## Requirements audit

The standalone requirements audit remains independent of threat-model runtime
modes:

```bash
./scripts/run-headless.sh --audit-requirements
./scripts/run-headless.sh --audit-requirements --category SEC-AUTH --save-report
./scripts/run-headless.sh --audit-requirements --repo /repos/team-api
```

## While the run is going

Unless you pass `--quiet`, the run prints a progress line: the phase it is in, roughly how far along it is, how long it has taken, and what it has spent so far. The spend is a lower bound, marked `≥`, because sub-agents only report when they finish. With `--soft-budget` it is shown against that budget, and passing 80 % or 100 % of it prints a warning once. A warning never stops the run; only `--hard-budget` does that.

If the host reports no usage, the run prints a notice and omits spend figures. Soft-budget tracking is then unavailable; `--hard-budget` still applies.

The final summary lists cost by model, including subagents, and duration by phase. Roles without a model override use the session model, so two billed models can account for the complete run. Compare the cost table with the initial `Models` line to identify missing usage.

## Output

A successful threat-model run writes `threat-model.md` and, unless disabled,
`threat-model.yaml`. Optional flags add SARIF, Threat Dragon, HTML, PDF, or
pentest task exports. The Markdown report is the review surface and YAML is the
structured source for deterministic exports.

The wrapper applies the same post-run secret checks, composition backstop,
cleanup, and fail-closed report gate in every supported assessment mode.
It prints the completion summary after the session's closing text.

## Flag reference

| Flag | Meaning |
|---|---|
| `--repo <path>` | Repository to analyze; defaults to the current directory. Repeat it to [assess several repositories as one system](#assess-several-repositories-as-one-system). |
| `--output <path>` | Output directory; defaults to `<repo>/docs/security`. |
| `--full` | Force a full assessment and preserve report history. |
| `--rebuild` | Clear prior model state and start fresh. |
| `--rerender` | Render validated existing Stage-1 artifacts. |
| `--assessment-depth quick\|standard\|thorough` | Select analysis depth. |
| `--reasoning-model <tier>` | Select the centrally routed reasoning tier. |
| `--sarif` | Write SARIF in addition to Markdown and YAML. |
| `--threatdragon` | Write the alpha Threat Dragon export. |
| `--slug [value]` | Also write a copy of every deliverable named `threat-model-<value>.*`, so several models can share one directory. A bare `--slug` picks a random value. |
| `--requirements [source]` | Include the requirements catalog. |
| `--context <source>` | Supply business context as untrusted data for this run. |
| `--max-duration <seconds>` | Stop the wrapper after the host deadline. |
| `--soft-budget <usd>` | Steer the run to this cost. A run that cannot fit does not start; a run that overruns still finishes. |
| `--hard-budget <usd>` | Kill the session at this cost, losing the report (API billing). Defaults to 1.25 × the soft budget. |
| `--trust-mode trusted\|untrusted` | Select repository trust preflight; default is untrusted. |
| `--clean-cache` | Delete transient cache state and exit. |
| `--clean-all` | Delete the selected output directory contents after confirmation and exit. |
| `--dry-run` with cleanup | Preview deterministic cleanup without writing. |
| `--force` | Skip the `--clean-all` confirmation; with `--full` or `--rebuild`, discard a completed Stage 1 instead of rendering it. |
| `--verbose` | Add the raw event stream to the live phase progress. |
| `--quiet` | Suppress live progress. |

`APPSEC_CLAUDE_EXECUTABLE` selects one Claude-compatible executable for the
authentication check and assessment launch. It defaults to `claude` on `PATH`.

The wrapper accepts removed mode flags only to reject them with a stable,
actionable error. There is no environment-variable opt-out that restores the
old producer or orchestration path.

## Exit behavior and diagnosis

An exit code of `0` means the requested supported operation completed and the required report artifact exists. Invalid configuration, unsupported modes, missing rerender inputs, a run that declined to discard a completed Stage 1, trust-preflight findings, validation failures, secret gate failures, and incomplete reports exit non-zero. A declined run analyzes nothing, so it never reports success even when an earlier report is still on disk.

Use these deterministic status tools against the selected output directory:

```bash
python3 scripts/runtime/appsec_status.py --live --repo /path/to/repository
python3 scripts/runtime/check_state.py /path/to/output
python3 scripts/renderers/render_completion_summary.py \
  --issues-only --output-dir /path/to/output --repo-root /path/to/repository
```

After an interrupted run, inspect the reported issue, then use the recovery command the run printed: `--rerender` when Stage 1 had finished, otherwise a new `--full` or `--rebuild` assessment. Do not copy checkpoint files into a new run or set a compatibility environment variable; neither is an admitted runtime path.
