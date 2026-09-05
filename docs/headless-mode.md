# Non-interactive Mode

Use `scripts/run-headless.sh` to run a full threat-model assessment from a
shell, CI job, or scheduled task. The wrapper owns authentication, host-level
cost and duration limits, trust preflight, terminal cleanup, and exit codes.

## Supported assessment modes

The headless wrapper uses the compact controller runtime only.

| Mode | Command | Behavior |
|---|---|---|
| Full | `run-headless.sh` or `--full` | Reassesses the repository and preserves report history. |
| Rebuild | `--rebuild` | Clears the prior model and cache before a fresh assessment; IDs may change. |
| Rerender | `--rerender` | Rebuilds the report from validated Stage-1 artifacts without analyzing source again. |

Incremental, resume, assessment dry-run, PR mode, baseline restore,
`--max-wall-time`, `--max-cost`, and `APPSEC_LIVE_PHASE=1` are unsupported.
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

## Cost and duration limits

Headless limits are enforced outside the model runtime:

```bash
./scripts/run-headless.sh \
  --repo /repos/team-api \
  --full \
  --max-duration 3600 \
  --max-budget 10
```

`--max-duration` uses the host `timeout` command. `--max-budget` applies to API billing. An interrupted or capped assessment is not resumable mid-analysis. One boundary is recoverable: a run that stopped after Stage 1 but before the report leaves validated Stage-1 artifacts, and `--rerender` turns them into a report without analyzing the source again. The run prints the command that applies to what it left behind. `--full` and `--rebuild` refuse to discard those artifacts until you repeat the invocation with `--force`. Anything earlier than that boundary starts again with `--full` or `--rebuild`; partial component artifacts may remain for diagnosis, but they are never silently admitted as a legacy continuation.

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

## Output

A successful threat-model run writes `threat-model.md` and, unless disabled,
`threat-model.yaml`. Optional flags add SARIF, Threat Dragon, HTML, PDF, or
pentest task exports. The Markdown report is the review surface and YAML is the
structured source for deterministic exports.

The wrapper applies the same post-run secret checks, composition backstop,
cleanup, and fail-closed report gate in every supported assessment mode.

## Flag reference

| Flag | Meaning |
|---|---|
| `--repo <path>` | Repository to analyze; defaults to the current directory. |
| `--output <path>` | Output directory; defaults to `<repo>/docs/security`. |
| `--full` | Force a full assessment and preserve report history. |
| `--rebuild` | Clear prior model state and start fresh. |
| `--rerender` | Render validated existing Stage-1 artifacts. |
| `--assessment-depth quick\|standard\|thorough` | Select analysis depth. |
| `--reasoning-model <tier>` | Select the centrally routed reasoning tier. |
| `--sarif` | Write SARIF in addition to Markdown and YAML. |
| `--threatdragon` | Write the alpha Threat Dragon export. |
| `--requirements [source]` | Include the requirements catalog. |
| `--context <source>` | Supply business context as untrusted data for this run. |
| `--max-duration <seconds>` | Stop the wrapper after the host deadline. |
| `--max-budget <usd>` | Stop when the API billing budget is reached. |
| `--trust-mode trusted\|untrusted` | Select repository trust preflight; default is untrusted. |
| `--clean-cache` | Delete transient cache state and exit. |
| `--clean-all` | Delete the selected output directory contents after confirmation and exit. |
| `--dry-run` with cleanup | Preview deterministic cleanup without writing. |
| `--force` | Skip the `--clean-all` confirmation; with `--full` or `--rebuild`, discard a completed Stage 1 instead of rendering it. |
| `--verbose` | Stream detailed runtime events. |
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
python3 scripts/appsec_status.py --live --repo /path/to/repository
python3 scripts/check_state.py /path/to/output
python3 scripts/render_completion_summary.py \
  --issues-only --output-dir /path/to/output --repo-root /path/to/repository
```

After an interrupted run, inspect the reported issue, then use the recovery command the run printed: `--rerender` when Stage 1 had finished, otherwise a new `--full` or `--rebuild` assessment. Do not copy checkpoint files into a new run or set a compatibility environment variable; neither is an admitted runtime path.
