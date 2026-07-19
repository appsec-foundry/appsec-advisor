# Server-Side Threat-Model Dispatch

Run a headless threat model entirely on a GitHub Actions runner — no local
checkout, no laptop. One manual dispatch runs one preset against one target
repo. Presets live in `.github/threat-model-presets.json` (single source of
truth); the workflow is `.github/workflows/threat-model-dispatch.yml`.

This is plugin-development / ops infrastructure — the targets are the project's
own deliberately-insecure test repos, not user-facing scans.

## What one dispatch does

```text
dispatch (use_case=python-standard)
  │
  ├─ checkout plugin  (this repo @ plugin_ref | dispatch branch)  → .
  ├─ resolve preset   (threat-model-presets.json)                 → target_repo, depth, mode, out
  ├─ checkout target  (matthiasrohr/insecure-python-app)          → ./target
  ├─ sanitize         (rm Claude memory / .claude / IDE task config) → ./target  (untrusted-safe)
  ├─ write perms      (make setup-target SCOPE=user)              → ~/.claude/settings.json
  ├─ run-headless     (--repo ./target --trust-mode untrusted …)  → out/python-standard/
  ├─ upload-artifact                                              → threat-model-python-standard (90d)
  └─ upload-sarif     (if preset sarif=true, best-effort)         → Code scanning tab
```

The runner is ephemeral: `./target` and `out/` vanish when the job ends. Only
the artifact (90 days) and, optionally, the SARIF alerts persist.

## Presets

`<target>-<depth>`, where depth is `quick | standard | thorough`:

| Prefix       | Target repo                          |
|--------------|--------------------------------------|
| `python-`    | `matthiasrohr/insecure-python-app`   |
| `spring-`    | `matthiasrohr/insecure-spring-app`   |
| `ai-`        | `matthiasrohr/insecure-ai-app`       |
| `juice-shop-`| `juice-shop/juice-shop`              |

Each preset pins `output_path` (`out/<use_case>/`), `mode`, `assessment_depth`,
`max_duration_sec`, and `sarif`. Edit the JSON to change targets or defaults —
not the workflow.

## Run

```bash
# The workflow + presets must live on the ref you dispatch (default branch for the UI).
gh workflow run threat-model-dispatch.yml --ref main -f use_case=python-standard
gh workflow run threat-model-dispatch.yml --ref main -f use_case=spring-standard
gh workflow run threat-model-dispatch.yml --ref main -f use_case=ai-standard
gh workflow run threat-model-dispatch.yml --ref main -f use_case=juice-shop-standard
```

Optional inputs (blank = preset default):

```bash
gh workflow run threat-model-dispatch.yml --ref main \
  -f use_case=python-thorough \
  -f plugin_ref=dev \            # which appsec-advisor commit/branch to run
  -f override_mode=full \        # full | incremental | dry-run
  -f override_depth=thorough     # quick | standard | thorough
```

Or via the UI: **Actions → "Threat Model (Preset)" → Run workflow**.

## Collect results

```bash
gh run list --workflow threat-model-dispatch.yml
gh run download <run-id>        # → threat-model-<use_case>/ (md, yaml, sarif, run log, effective-permissions.json)
```

The artifact includes the dot-prefixed run state (`.run-issues.json`,
`.agent-run.log`, `.appsec-trace.log`) because the upload sets
`include-hidden-files: true` — without it `upload-artifact` v4.4+ drops every
one of those, which is most of the evidence. So a failed CI run can be worked
exactly like a local one:

```bash
make ci-triage RUN_ID=<run-id>   # download + summarise + print OUTPUT_DIR
```

then point the `fix-run-issues` skill at the printed `OUTPUT_DIR` (it needs
`APPSEC_PLUGIN_DEV=1` to write to plugin files).

## Repair mode

`repair: true` hands a failed run to `.github/workflows/repair-agent.yml`,
shared with `fixture-e2e-dispatch.yml`: an agent triages the failure, fixes the
producer, verifies, and opens a PR against `dev`. To repair a run dispatched
*without* it, dispatch again with `repair_run_id: <that run's id>` — nothing is
scanned and the agent works off the earlier artifacts (90-day retention here).

There is no oracle in this workflow, so the run is red exactly when the pipeline
broke and every failure is producer-side by definition — the exit-code
classification the fixture workflow needs does not apply.

**This workflow's artifacts derive from scanning an untrusted repository.**
Report bodies, run logs and issue entries can therefore contain
attacker-supplied text, and an agent that reads them and writes plugin code is
a prompt-injection path. Two things contain that, and only the second is
enforceable:

- The prompt restricts the artifacts to being a *pointer* to where a defect is —
  never a specification of what to change — and requires the defect be
  reproduced from this repository alone, with synthetic input.
- The `Gate` step decides what may ship, regardless of what the agent claims.
  A change ships only if it includes a regression test under `tests/` (an
  unreproduced defect is not a verified one) and touches nothing under
  `.github/` or `.claude/` (self-modifying CI or agent config is never a
  legitimate outcome). A refused change is not discarded: the staged diff is
  published as the `repair-refused-<run-id>` artifact and the job fails loudly.

The gate confirms that evidence exists — it cannot confirm the diagnosis is
right. The PR is opened with `GITHUB_TOKEN`, so no checks run on the branch;
re-dispatch against `plugin_ref: repair/run-<run-id>` before merging.

## Operating notes

- **Must live on the default branch.** `workflow_dispatch` only appears in the
  Actions tab (and resolves for `--ref main`) once the workflow file is on the
  repo's default branch. On a feature branch it is not dispatchable via the UI.
- **Billing is subscription.** The run reads `secrets.CLAUDE_CODE_OAUTH_TOKEN`
  (from `claude setup-token`) as a repo/Actions secret — no `environment:`, so
  an *environment*-scoped secret will not be picked up. `ANTHROPIC_API_KEY` is
  deliberately unset; it would override and switch billing to per-token.
- **Untrusted by design.** The target is a third-party checkout. The sanitize
  step strips repo-owned `.claude` / IDE task config (the injection vectors
  `scripts/preflight_untrusted.py` refuses on); escaping symlinks are surfaced
  as warnings, not auto-removed, and the untrusted preflight aborts on them.
- **Concurrency.** Runs are serialized per `use_case`
  (`group: threat-model-<use_case>`, no cancel-in-progress) because they share
  an output dir.
