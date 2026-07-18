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
  ├─ sanitize         (rm .claude / IDE task config)              → ./target  (untrusted-safe)
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
| `juice-shop-`| `juice-shop/juice-shop`              |

Each preset pins `output_path` (`out/<use_case>/`), `mode`, `assessment_depth`,
`max_duration_sec`, and `sarif`. Edit the JSON to change targets or defaults —
not the workflow.

## Run

```bash
# The workflow + presets must live on the ref you dispatch (default branch for the UI).
gh workflow run threat-model-dispatch.yml --ref main -f use_case=python-standard
gh workflow run threat-model-dispatch.yml --ref main -f use_case=spring-standard
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
