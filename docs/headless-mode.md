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

### Assess Git URLs

Pass an HTTPS URL, an SSH URL (`ssh://git@host/team/repo.git`), or an SSH selection in `git@host:team/repo.git` form to `--repo`. Repeat `--repo` to combine remote repositories or mix URLs with local checkouts. Git URLs require Git 2.34 or newer and an explicit `--output` outside the temporary checkout area.

```bash
./scripts/run-headless.sh \
  --repo https://github.com/org/frontend.git \
  --repo git@github.com:org/backend.git \
  --output ./reports/system \
  --hard-budget 50 \
  --full
```

HTTPS authentication uses existing Git credential helpers or `APPSEC_GIT_TOKEN`, with `APPSEC_GIT_USERNAME` when the provider requires a particular username (default: `git`). Supply the token through your environment or CI secret store, never inside a URL. An environment token takes precedence over credential helpers and reaches Git through a private helper pipe; the runner does not write it to disk or pass it to the analysis process. Credential configuration comes from the operator's global/system Git configuration, including `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM`, not from a selected repository.

SSH uses the SSH agent (`SSH_AUTH_SOCK`), existing SSH identity configuration, or the existing private key file named by `APPSEC_GIT_SSH_KEY_FILE`. Unlock encrypted keys in the agent before starting. Host keys must already be trusted in `known_hosts`; missing authentication or an unknown host key fails without prompting. Use a resolvable hostname, rather than an SSH alias. The runner pins the destination address and does not use HTTP proxies, SSH jump hosts, connection multiplexing or custom `GIT_SSH_COMMAND` commands. TLS certificate verification and SSH host verification remain enabled. If `APPSEC_URL_ALLOWLIST` is set, each selected remote hostname must match an entry exactly. Explicitly selected private-network Git hosts are allowed; loopback, link-local and metadata destinations are refused.

The runner shallow-clones each remote's default branch into a private area under the system temporary directory. It neither executes checkout hooks or configured content filters nor fetches submodules or Git LFS objects. Each clone and checkout is bounded to 120 seconds, 512 MiB and 100,000 filesystem entries; exceeding a limit stops provisioning before assessment. Clone diagnostics omit raw Git output to keep credentials out of logs.

Checkout paths stay stable for the same output location, URL and temporary directory, so an unchanged source revision retains its repository identity. A concurrent remote run with the same output location is refused. Checkouts are removed on success, failure and handled interruption; reports and recovery state remain in `--output`. The existing assessment mode and source-revision checks still apply on retry. A forced kill or machine shutdown can leave a checkout behind; the next invocation refuses to reuse it and requires operator cleanup of the stale checkout beneath `appsec-remotes-<uid>` in the temporary directory. Small private directories and lock files remain to preserve safe locking and path identity.

### Assess local checkouts

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

Repeat `--repo` to assess several repositories as one system, using local Git checkouts, [Git URLs](#assess-git-urls), or both. Every selected repository is scanned freshly, and the run publishes one `threat-model.yaml`, one `threat-model.md` and one Figure 1 in the `--output` directory. `--project` sets the system name in the report, and `--slug` adds a stamped copy of the deliverables.

```bash
./scripts/run-headless.sh \
  --repo /repos/frontend \
  --repo /repos/backend \
  --output /appsec-reports/order-system \
  --hard-budget 50 \
  --sarif
```

A combined run has these requirements:

- Select 2–16 repositories. Local selections must name top-level Git checkouts. A checkout inside another selected checkout, or two paths that name the same directory, stop the run.
- Choose an `--output` directory outside every selected checkout. The run writes nothing into a selected checkout.
- Set `--hard-budget` to the total model-cost limit. The controller reserves resources for required analysis and report completion and omits optional model work when it would consume that reserve. `--soft-budget` is deprecated in controller mode; for compatibility, using it alone still sets the limit to 1.25 times its value. An explicit hard budget takes precedence.
- The untrusted-repository preflight checks every selected checkout. `--trust-mode trusted` skips it for all of them.

The completion reserve is an estimate, updated from accepted jobs under the run's fixed model selection. Running calls count against the limit. Required report authoring and local finalization also retain a time allowance. Optional work uses its existing deterministic replacement when money, time or calls are reserved for required work; the console names every affected job, and unverified findings remain unproven. A reserve improves the chance of completion but cannot guarantee that mandatory analysis fits every budget.

If the budget cannot cover required work, the run exits `3` and writes `.assessment-work/budget-report.md`. This separate, explicitly incomplete snapshot lists accepted steps, preliminary STRIDE candidates and outstanding work; it contains no final ratings, consolidated scanner results or security verdict. It does not replace `threat-model.md` or `threat-model.yaml` and produces no exports. Its bounded structured projection is recorded in `.assessment-state.json`. Increase `--hard-budget` or `--max-duration` and rerun without `--resume` or `--rebuild` to reuse compatible accepted steps; reused job costs remain part of the accounting. `--resume` retains the original limits. Invalid source state, unsettled accounting and failed security checks do not produce this snapshot.

What the result shows:

- Each component card and source location names its repository, for example `Order API [backend]` and `backend/src/orders.ts:42`. The YAML records the repository separately in a `source_inventory` and in every source reference, and SARIF uses one location base per repository.
- The order of the `--repo` flags does not change the result. No repository takes precedence.
- A connection between repositories appears only when source evidence on both sides supports it. Matching names alone never connect two repositories, and repository membership never creates a trust boundary.
- Symbolic links, submodules and nested repositories inside a checkout are not read. The model lists each of them as an omitted path.

A controller run, combined or for one repository through `/appsec-advisor:appsec-analyzer`, uses Sonnet 5.5 for STRIDE at quick and standard depth, while a scan through `/appsec-advisor:create-threat-model` keeps STRIDE on Sonnet 4.6. Each STRIDE result must come back from one model call, and Sonnet 4.6 exhausts its thinking there without returning one. STRIDE calls therefore cost more: Sonnet 5.5 counts the same text in about 30% more tokens at the same price per token. The run prints each role's model at the start and warns about this change, even with `--quiet`. An explicit STRIDE model through `--stride-model`, `APPSEC_STRIDE_MODEL` or `--model` is kept; if it is Sonnet 4.6, the run warns that STRIDE is expected to return no result.

A controller run does not follow the model of the session that started it: every role has a fixed model version, so cost, budget and later replays stay predictable. To choose other models, pass `--model <id>` for every role you do not set separately, `--stride-model`, `--triage-model` or `--merger-model` for one stage, or `--reasoning-model` for a tier; set `APPSEC_<ROLE>_MODEL`, such as `APPSEC_EVIDENCE_VERIFIER_MODEL`, for any other role. `--no-opus` turns every Opus selection into Sonnet. `/appsec-advisor:appsec-analyzer` passes these flags to the run. A stronger model can reach the budget sooner; choose an appropriate `--hard-budget`.

The models in a combined run have no file, shell or network tools. The controller serves every source excerpt a model reads, only from the selected checkouts, with secrets masked. Each analysis step is recorded, so `--resume` continues an interrupted run without repeating accepted steps, as long as the sources and settings are unchanged. After a plugin update, `--resume` reuses only the steps whose input is unchanged and redoes the rest. A run whose model cost became unknown cannot resume; start a new run.

The controller supplies component-specific analysis guides and requires a source-backed decision for each investigation target: detected handlers, outbound calls, capability and flow evidence, and component files without a detected surface. Large components use several bounded jobs within the existing run budget. An unread target prevents that component's analysis from completing; a target that was read but left unresolved is reported as a warning. This checks the supplied targets; it does not prove that every vulnerability or framework-specific mechanism was found.

While it runs, a combined run prints each phase, the component or report section in work, and a warning when a model call stalls; `--verbose` adds every step and model call with the source ranges it reads. In a terminal, one status line with a spinner and a progress bar is redrawn in place with each running model call's duration and whether it is thinking, writing or waiting for the API; output that is not a terminal, such as a CI log, gets no status line. `--width <columns>` (at least 60) wraps every console line at that width, on a terminal at most at the terminal's width and also when the output is not a terminal, so the output fits a window of fixed width. `--progress-file <path>` opens with a `run_start` record whose `lines` state the repository, output, depth, budget, time limit and models, and also writes each progress event as one JSON line (`phase_start`, `phase_done`, `component_done`, `progress`, `correction`, `warning`) with the fields `phase`, `number`, `total`, `progress`, `elapsed`, `left` and `detail`, and ends every run with an `end` record carrying `status`, `exit_code` and `resumable`; the file is replaced at start, so a program can follow it without parsing the console. A warning never ends the run.

A single `--repo` runs through this same procedure by default; the budget and `--output` rules above apply, and the flags listed below as unavailable for combined runs stop it too. Set `APPSEC_SINGLE_REPO_CONTROLLER=0` to send a single `--repo` to the single-repository scan instead.

A new run in the same `--output` directory reuses every model step of an unfinished earlier run whose input is unchanged. A directory that already holds a report needs `--rebuild`, which removes only the files the earlier run wrote and refuses when any other or edited file is present; `--rebuild` also redoes every model step and cannot be combined with `--resume`. `--incremental`, `--rerender`, `--dry-run`, `--base`, `--pr-mode` and `--restore-from` are not available for combined runs and stop them before any model call. Business context, known threats and a run-wide `--requirements` catalog are supported; each repository keeps its own business context and known threats. A requirements catalog inside one of the selected repositories stops the run unless you pass `--requirements <source>`. Repository-local abuse-case files stop the run; use `--no-abuse-cases` or move the cases to the organization profile. The follow-on skills that only support single-repository models, such as fixing findings in place or publishing the model into a repository, say so when they open a combined model.

## Cost and duration limits

Headless limits are enforced outside the model runtime:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --full \
  --max-duration 3600 \
  --hard-budget 30
```

`--max-duration` sets the controller's cumulative deadline, retained on `--resume`. The controller protects time for required report work before dispatching optional calls. The previous single-repository scan (`APPSEC_SINGLE_REPO_CONTROLLER=0`) uses the host `timeout` command.

In controller mode, `--hard-budget` is the total limit, including running reservations and reused jobs. The controller protects required completion and replaces optional work as described above. `--soft-budget` is a deprecated compatibility spelling that derives a limit of 1.25 times its value unless an explicit hard budget is supplied.

In the previous single-repository scan, `--soft-budget` rejects a run before it starts if the estimated cost exceeds the budget; an admitted run can exceed it. `--hard-budget` is the host-level API-billing cut, defaulting to 1.25 times a supplied soft budget.

In the previous single-repository scan, an interrupted assessment cannot resume mid-analysis. If Stage 1 finished, use `--rerender` to create the report from its validated artifacts. The run prints the applicable recovery command. `--full` and `--rebuild` require `--force` before discarding a completed Stage 1. If Stage 1 did not finish, start again with `--full` or `--rebuild`; partial component artifacts remain for diagnosis only.

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

In a terminal the output is coloured: phases, status marks, warnings and finding severities each have their own colour. Output that is not a terminal, such as a CI log or a file, carries no colour codes. `NO_COLOR` turns colour off, `FORCE_COLOR=1` turns it on for output that is not a terminal, and `TERM=dumb` turns it off; `NO_COLOR` wins over `FORCE_COLOR`. Terminals that set `COLORTERM=truecolor` get the full palette, others the basic terminal colours.

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
| `--repo <path\|url>` | Local repository or HTTPS/SSH Git URL; defaults to the current directory. URLs require `--output`. Repeat it to [assess several repositories as one system](#assess-several-repositories-as-one-system). |
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
| `--max-duration <seconds>` | Bound controller runtime, or the host session in the previous single-repository scan. |
| `--soft-budget <usd>` | Deprecated in controller mode: derives a limit of 1.25 × this value. In the previous scan, sets the admission target. |
| `--hard-budget <usd>` | Total controller budget with an automatic completion reserve; a host-level API-billing cut in the previous scan. |
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

An exit code of `0` means the requested supported operation completed and the required report artifact exists. Invalid configuration, unsupported modes, missing rerender inputs, a run that declined to discard a completed Stage 1, trust-preflight findings, validation failures, secret gate failures, and incomplete reports exit non-zero. A declined run analyzes nothing, so it never reports success even when an earlier report is still on disk. A combined or single-repository controller run that stopped incomplete but can continue, at its `--pause-after` boundary or on a stop request, exits `3`; continue it with `--resume`. A failure exits `1`.

Use these deterministic status tools against the selected output directory:

```bash
python3 scripts/runtime/appsec_status.py --live --repo /path/to/repository
python3 scripts/runtime/check_state.py /path/to/output
python3 scripts/renderers/render_completion_summary.py \
  --issues-only --output-dir /path/to/output --repo-root /path/to/repository
```

After an interrupted run, inspect the reported issue, then use the recovery command the run printed: `--rerender` when Stage 1 had finished, otherwise a new `--full` or `--rebuild` assessment. Do not copy checkpoint files into a new run or set a compatibility environment variable; neither is an admitted runtime path.
