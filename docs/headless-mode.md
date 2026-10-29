# Non-interactive mode

Use `scripts/run-headless.sh` to run a full security assessment from a
shell, CI job, or scheduled task. The wrapper checks authentication,
provisions Git URLs, and hands every assessment to the deterministic
controller. No Claude Code session orchestrates the run: the controller calls
each role's model itself and owns the trust preflight, cost and duration
limits, publication, and exit codes.

## Supported assessment modes

Every run is a full assessment.

| Mode | Command | Behavior |
|---|---|---|
| New run | `run-headless.sh` | Assesses the repository. A completed assessment in the same directory is replaced and its history continues; `--full` is accepted and changes nothing. |
| Resume | `--resume` | Continues an interrupted run without repeating its accepted steps, as long as sources and settings are unchanged. |
| Rebuild | `--rebuild` | Redoes every model step and resets the history; IDs may change. It cannot be combined with `--resume`. |

`--incremental`, `--rerender`, `--dry-run`, `--base`, `--pr-mode`,
`--restore-from`, `--clean-cache`, `--clean-all`, `--max-wall-time` and a
free-text focus are refused before any model call.

## Prerequisites

1. Install the Claude Code CLI and place `claude` on `PATH`.
2. Authenticate with an API key or a stored Claude subscription login.
3. Clone or install the plugin.

With API billing, supply the key through the environment and keep it in the CI
secret store. The wrapper never needs the key as a command-line argument.

```bash
export ANTHROPIC_API_KEY="<from-secret-store>"
./scripts/run-headless.sh --repo /path/to/repository --hard-budget 30
```

A headless run requires `--hard-budget`; see [Cost and duration limits](#cost-and-duration-limits).

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
./scripts/run-headless.sh --repo /repos/team-api --hard-budget 30
```

Use an absolute path in unattended environments. Store proxy credentials in the
environment's secret store rather than in the launcher or plugin configuration.

## Where results are stored

Without `--output`, a run writes to the application's private directory under the user data directory, `<base>/<repo-name>-<hash8>`, and several `--repo` selections share one `combined-<hash8>` directory. [Where results are stored](security-assessment.md#where-results-are-stored) lists the base directory per platform and the limits of this protection. Print the directory of a checkout with:

```bash
python3 scripts/shared/assessment_location.py destination --repo /path/to/repository
```

`--output <path>` writes elsewhere. It must lie outside every selected checkout; the only directory inside a checkout that a single-repository run accepts is its `docs/security`.

If `<repo>/docs/security` holds a finished assessment from an earlier release, a headless run stops until you choose: `--migrate-legacy` imports it into the destination and continues its history, and `--ignore-legacy` starts without it. Either way the files in the repository stay. An interrupted earlier run is reported as incomplete and not imported.

## Common workflows

### Assess Git URLs

Pass an HTTPS URL, an SSH URL (`ssh://git@host/team/repo.git`), or an SSH selection in `git@host:team/repo.git` form to `--repo`. Repeat `--repo` to combine remote repositories or mix URLs with local checkouts. Git URLs require Git 2.34 or newer and an explicit `--output` outside the temporary checkout area.

```bash
./scripts/run-headless.sh \
  --repo https://github.com/org/frontend.git \
  --repo git@github.com:org/backend.git \
  --output ./reports/system \
  --hard-budget 50
```

HTTPS authentication uses existing Git credential helpers or `APPSEC_GIT_TOKEN`, with `APPSEC_GIT_USERNAME` when the provider requires a particular username (default: `git`). Supply the token through your environment or CI secret store, never inside a URL. Other token variables such as `GITLAB_TOKEN` or `GITHUB_TOKEN` are deliberately not read, so an unrelated ambient token never reaches an arbitrary `--repo` host; pass it explicitly with `APPSEC_GIT_TOKEN="$GITLAB_TOKEN"`. An environment token takes precedence over credential helpers and reaches Git through a private helper pipe; the runner does not write it to disk or pass it to the analysis process. Credential configuration comes from the operator's global/system Git configuration, including `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM`, not from a selected repository.

SSH uses the SSH agent (`SSH_AUTH_SOCK`), existing SSH identity configuration, or the existing private key file named by `APPSEC_GIT_SSH_KEY_FILE`. Unlock encrypted keys in the agent before starting. Host keys must already be trusted in `known_hosts`; missing authentication or an unknown host key fails without prompting. Use a resolvable hostname, rather than an SSH alias. The runner pins the destination address and does not use HTTP proxies, SSH jump hosts, connection multiplexing or custom `GIT_SSH_COMMAND` commands. TLS certificate verification and SSH host verification remain enabled. If `APPSEC_URL_ALLOWLIST` is set, each selected remote hostname must match an entry exactly. Explicitly selected private-network Git hosts are allowed; loopback, link-local and metadata destinations are refused.

The runner shallow-clones each remote's default branch into a private area under the system temporary directory. It neither executes checkout hooks or configured content filters nor fetches submodules or Git LFS objects. Each clone and checkout is bounded to 120 seconds, 512 MiB and 100,000 filesystem entries; exceeding a limit stops provisioning before assessment. Clone diagnostics omit raw Git output to keep credentials out of logs.

Checkout paths stay stable for the same output location, URL and temporary directory, so an unchanged source revision retains its repository identity. A concurrent remote run with the same output location is refused. Checkouts are removed on success, failure and handled interruption; reports and recovery state remain in `--output`. The source-revision checks of `--resume` still apply on retry. A forced kill or machine shutdown can leave a checkout behind; the next invocation refuses to reuse it and requires operator cleanup of the stale checkout beneath `appsec-remotes-<uid>` in the temporary directory. Small private directories and lock files remain to preserve safe locking and path identity.

### Assess local checkouts

Assess the current repository; the results go to its application directory:

```bash
/path/to/appsec-advisor/scripts/run-headless.sh --hard-budget 30
```

Assess another team's repository into a directory you choose:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --hard-budget 30 --sarif
```

Start over and reset the history:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --output /appsec-reports/team-api \
  --hard-budget 30 --rebuild
```

## Assess several repositories as one system

This mode is experimental. The report says so in its Management Summary, and the run says so when it starts.

Repeat `--repo` to assess several repositories as one system, using local Git checkouts, [Git URLs](#assess-git-urls), or both. Every selected repository is scanned freshly, and the run publishes one `security-assessment.yaml`, one `security-assessment.md` and one Figure 1. `--project` sets the system name in the report, and `--slug` adds a stamped copy of the deliverables.

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
- Without `--output`, the run writes to the shared `combined-<hash8>` directory of the selection. An explicit `--output` must lie outside every selected checkout. The run writes nothing into a selected checkout.
- Set `--hard-budget` to the total model-cost limit; see [Cost and duration limits](#cost-and-duration-limits).
- The untrusted-repository preflight checks every selected checkout. `--trust-mode trusted` skips it for all of them.

What the result shows:

- Each component card and source location names its repository, for example `Order API [backend]` and `backend/src/orders.ts:42`. The YAML records the repository separately in a `source_inventory` and in every source reference, and SARIF uses one location base per repository.
- The order of the `--repo` flags does not change the result. No repository takes precedence.
- A connection between repositories appears only when source evidence on both sides supports it. Matching names alone never connect two repositories, and repository membership never creates a trust boundary.
- Symbolic links, submodules and nested repositories inside a checkout are not read. The model lists each of them as an omitted path.

Business context, known threats and a run-wide `--requirements` catalog are supported; each repository keeps its own business context and known threats. A requirements catalog inside one of the selected repositories stops the run unless you pass `--requirements <source>`. Repository-local abuse-case files stop the run; use `--no-abuse-cases` or move the cases to the organization profile. The follow-on skills that only support single-repository models, such as fixing findings in place, say so when they open a combined model.

## How the controller runs

A single `--repo` and a combined selection run through the same procedure.

Every role has a fixed model version, independent of the session that started the run, so cost, budget and later replays stay predictable. At quick and standard depth STRIDE runs on Sonnet 5.5: each STRIDE result must come back from one model call, and Sonnet 4.6 exhausts its thinking there without returning one. STRIDE calls therefore cost more: Sonnet 5.5 counts the same text in about 30% more tokens at the same price per token. The run prints each role's model at the start and warns about this change, even with `--quiet`. An explicit STRIDE model through `--stride-model`, `APPSEC_STRIDE_MODEL` or `--model` is kept; if it is Sonnet 4.6, the run warns that STRIDE is expected to return no result.

To choose other models, pass `--model <id>` for every role you do not set separately, `--stride-model`, `--triage-model` or `--merger-model` for one stage, or `--reasoning-model` for a tier; set `APPSEC_<ROLE>_MODEL`, such as `APPSEC_EVIDENCE_VERIFIER_MODEL`, for any other role. `--no-opus` turns every Opus selection into Sonnet. `/appsec-advisor:appsec-analyzer` passes these flags to the run. A stronger model can reach the budget sooner; choose an appropriate `--hard-budget`.

The models have no file, shell or network tools. The controller serves every source excerpt a model reads, only from the selected checkouts, with secrets masked. Each analysis step is recorded, so `--resume` continues an interrupted run without repeating accepted steps, as long as the sources and settings are unchanged. After a plugin update, `--resume` reuses only the steps whose input is unchanged and redoes the rest. A run whose model cost became unknown cannot resume; start a new run.

The controller supplies component-specific analysis guides and requires a source-backed decision for each investigation target: detected handlers, outbound calls, capability and flow evidence, and component files without a detected surface. Large components use several bounded jobs within the existing run budget. An unread target prevents that component's analysis from completing; a target that was read but left unresolved is reported as a warning. This checks the supplied targets; it does not prove that every vulnerability or framework-specific mechanism was found.

`--component-workers N` sets how many components the controller analyzes at once (1–4, default 3). A lower value sends fewer simultaneous model calls and can reduce rate-limit errors, but takes longer. It changes neither the selected components nor accepted job results; you can change it when resuming an interrupted run.

A new run in the same output directory reuses every model step of an unfinished earlier run whose input is unchanged. Over a completed assessment, it replaces the report and continues its history. `--rebuild` redoes every model step and resets the history.

## Cost and duration limits

The controller enforces the limits itself:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --max-duration 3600 \
  --hard-budget 30
```

`--hard-budget` is the total model-cost limit, including running reservations and reused jobs. `--soft-budget` is a deprecated compatibility spelling that derives a limit of 1.25 times its value unless an explicit hard budget is supplied. A headless run without either stops before any model call.

`--max-duration` sets the controller's cumulative deadline, 14,400 seconds by default, and is retained on `--resume`. The controller protects time for required report work before dispatching optional calls.

The completion reserve is an estimate, updated from accepted jobs under the run's fixed model selection. Running calls count against the limit. Required report authoring and local finalization also retain a time allowance. Optional work uses its existing deterministic replacement when money, time or calls are reserved for required work; the console names every affected job, and unverified findings remain unproven. A reserve improves the chance of completion but cannot guarantee that mandatory analysis fits every budget.

If the budget cannot cover required work, the run exits `3` and writes `.assessment-work/budget-report.md`. This separate, explicitly incomplete snapshot lists accepted steps, preliminary STRIDE candidates and outstanding work; it contains no final ratings, consolidated scanner results or security verdict. It does not replace `security-assessment.md` or `security-assessment.yaml` and produces no exports. Its bounded structured projection is recorded in `.assessment-state.json`. Increase `--hard-budget` or `--max-duration` and rerun without `--resume` or `--rebuild` to reuse compatible accepted steps; reused job costs remain part of the accounting. `--resume` retains the original limits. Invalid source state, unsettled accounting and failed security checks do not produce this snapshot.

## Scheduled CI example

Run full assessments on a schedule or by explicit manual trigger. Pull-request
delta mode is not supported.

A runner's user data directory does not outlive the job, so pass an explicit
`--output` into the workspace, outside the checkout, and archive that directory
in a later step if you need the results.

```yaml
name: Security assessment
on:
  schedule:
    - cron: "0 3 * * 1"
  workflow_dispatch:

jobs:
  security-assessment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          path: repo
          fetch-depth: 0
      - name: Run full assessment
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          /path/to/appsec-advisor/scripts/run-headless.sh \
            --repo "$GITHUB_WORKSPACE/repo" \
            --output "$GITHUB_WORKSPACE/assessment" \
            --sarif --max-duration 7200 --hard-budget 25
```

Do not execute repository-owned hooks from an untrusted checkout. The default
`--trust-mode untrusted` preflight rejects escaping symbolic links, IDE-loaded
files and unlisted related-repository URLs; the model sessions never load
Claude Code configuration from the repository. Use `--trust-mode trusted` only
for a repository you control.

## Requirements audit

The standalone requirements audit runs its own skill, not an assessment:

```bash
./scripts/run-headless.sh --audit-requirements
./scripts/run-headless.sh --audit-requirements --category SEC-AUTH --save-report
./scripts/run-headless.sh --audit-requirements --repo /repos/team-api
```

## While the run is going

The run prints each phase, the component or report section in work, and a warning when a model call stalls; `--verbose` adds every step and model call with the source ranges it reads, and `--quiet` suppresses progress. In a terminal, one status line with a spinner and a progress bar is redrawn in place with each running model call's duration and whether it is thinking, writing or waiting for the API; output that is not a terminal, such as a CI log, gets no status line. `--width <columns>` (at least 60) wraps every console line at that width, on a terminal at most at the terminal's width and also when the output is not a terminal, so the output fits a window of fixed width. A warning never ends the run.

`--progress-file <path>` opens with a `run_start` record whose `lines` state the repository, output, depth, budget, time limit and models, and also writes each progress event as one JSON line (`phase_start`, `phase_done`, `component_done`, `progress`, `correction`, `warning`) with the fields `phase`, `number`, `total`, `progress`, `elapsed`, `left` and `detail`, and ends every run with an `end` record carrying `status`, `exit_code` and `resumable`. The file is replaced at start, so a program can follow it without parsing the console.

In a terminal the output is coloured: phases, status marks, warnings and finding severities each have their own colour. Output that is not a terminal, such as a CI log or a file, carries no colour codes. `NO_COLOR` turns colour off, `FORCE_COLOR=1` turns it on for output that is not a terminal, and `TERM=dumb` turns it off; `NO_COLOR` wins over `FORCE_COLOR`. Terminals that set `COLORTERM=truecolor` get the full palette, others the basic terminal colours.

## Output

A successful run writes `security-assessment.md`, `security-assessment.yaml`
and the report's `security-assessment.figure*.svg` figures. Optional flags add SARIF, Threat Dragon, HTML, PDF, or pentest task
exports. The Markdown report is the review surface and YAML is the structured
source for deterministic exports.

## Flag reference

| Flag | Meaning |
|---|---|
| `--repo <path\|url>` | Local repository or HTTPS/SSH Git URL; defaults to the current directory. URLs require `--output`. Repeat it to [assess several repositories as one system](#assess-several-repositories-as-one-system). |
| `--output <path>` | Output directory; defaults to the application's private directory under the user data directory. |
| `--migrate-legacy` | Import a finished assessment from `<repo>/docs/security` before the run; its files there stay. |
| `--ignore-legacy` | Start without that assessment. |
| `--resume` | Continue an interrupted run. |
| `--rebuild` | Redo every model step and reset the history. |
| `--assessment-depth quick\|standard\|thorough` | Select analysis depth. |
| `--reasoning-model <tier>` | Select the reasoning tier. |
| `--model <id>` | Model for every role not set separately. |
| `--sarif` | Write SARIF in addition to Markdown and YAML. |
| `--threatdragon` | Write the alpha Threat Dragon export. |
| `--slug [value]` | Also write a copy of every deliverable named `security-assessment-<value>.*` and `pentest-tasks-<value>.yaml`, so several models can share one directory. A bare `--slug` picks a random value. |
| `--requirements [source]` | Include the requirements catalog. |
| `--context <source>` | Supply business context as untrusted data for this run. |
| `--max-duration <seconds>` | Cumulative deadline of the run. |
| `--hard-budget <usd>` | Total model-cost limit with an automatic completion reserve. |
| `--soft-budget <usd>` | Deprecated: derives a limit of 1.25 × this value. |
| `--pause-after <phase>` | Stop before the phase after `<phase>` (1-based); `--resume` continues the run. |
| `--trust-mode trusted\|untrusted` | Select repository trust preflight; default is untrusted. |
| `--fail-on critical\|high\|medium` | Exit non-zero when the latest changelog entry adds a finding at or above this level. |
| `--width <columns>` | Wrap console lines at most at this width. |
| `--progress-file <path>` | Also write progress events as JSON lines. |
| `--verbose` | Add every step and model call to the progress output. |
| `--quiet` | Suppress live progress. |

`APPSEC_CLAUDE_EXECUTABLE` selects one Claude-compatible executable for the
authentication check and assessment launch. It defaults to `claude` on `PATH`.

## Exit behavior and diagnosis

An exit code of `0` means the assessment completed and its report exists. A run that stopped incomplete but can continue, at its `--pause-after` boundary or on a stop request, exits `3`; continue it with `--resume`. A run whose budget could not cover required work also exits `3`. A refused invocation, such as an unsupported flag, a missing budget, trust-preflight findings or an earlier `docs/security` assessment without `--migrate-legacy` or `--ignore-legacy`, exits `2` and changes no assessment. A completed run whose new findings reach the `--fail-on` level exits `20`, an interrupt `130`; validation and other failures exit `1`. A refused run analyzes nothing, so it never reports success even when an earlier report is still on disk.

Check whether a run still holds an output directory:

```bash
python3 scripts/runtime/live_run_holder.py --output /path/to/output
```

It prints `free`, or `live` with the run ID, start time and heartbeat age. After an interrupted run, inspect the reported issue, then continue with `--resume` or start a new run. Do not copy state files into a new run; that is not an admitted runtime path.
