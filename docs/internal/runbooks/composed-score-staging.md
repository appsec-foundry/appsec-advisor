# Run the composed staging plugin

Use this procedure for a reviewed archive assembled under the [composition contract](../contracts/plugin-composition.md). The current selected surface contains the Analyzer-owned `appsec-analyzer` assessment entry and the portable `security-score` entry. Score-only selections remain valid. Organization packaging changes the namespace; read the delivered manifest and README for the selected identity and commands.

The [current implementation evidence](../analysis/plan-appsec-advisor-clean-composition-2026-10-18.md#committed-implementation-and-installed-evidence) records the primary composition's exact source/artifact pins and Linux offline observations. The [earlier score replay](../analysis/composition-offline-evidence-2026-10-18.md#real-engine-score-binding-replay) retains its own pins and host-discovery evidence. Neither record establishes a complete model-backed primary workflow, real-controller stop/resume, native macOS/Windows or upgrade/rollback. These are internal staging packages, not replacement releases.

## Prepare the runtime

Verify the archive against its reviewed checksum, then extract it into a dedicated plugin directory outside source checkouts. The directory must contain `.claude-plugin/plugin.json`, `components.lock.json`, the bootstrap and the selected skill resources. Use the existing Python interpreter selected by the lock; replace `python3` in the examples if that interpreter has another name or path.

Run explicit setup once, then read-only preflight. Replace `/installed/plugin` with the extracted plugin directory.

```bash
python3 "/installed/plugin/scripts/composition_runtime.py" setup --plugin "/installed/plugin"
python3 "/installed/plugin/scripts/composition_runtime.py" preflight --plugin "/installed/plugin"
```

Setup uses only the verified bundled wheels and activates its environment outside Git checkouts. The standard runtime location lets the generated Claude entry find it without additional configuration. An explicit `--runtime-home` is available for direct bootstrap invocations and must be repeated on each such call. Generated Claude entries use the standard runtime location; they do not automatically adopt a custom setup path.

## Run without a model

Select a committed top-level Git checkout. The launcher checks the installed engine's deterministic score capabilities before dispatch. The following commands preserve the engine's output and exit status.

```bash
python3 "/installed/plugin/scripts/composition_runtime.py" run --plugin "/installed/plugin" --skill security-score -- score "/source/repository"
python3 "/installed/plugin/scripts/composition_runtime.py" run --plugin "/installed/plugin" --skill security-score -- score "/source/repository" --json
python3 "/installed/plugin/scripts/composition_runtime.py" run --plugin "/installed/plugin" --skill security-score -- score "/source/repository" --yaml
```

A computed score returns 0, an undetermined score returns 2, an operational or source-admission failure returns 1, and cancellation returns 130. Argument errors can also return 2; inspect the actual output. An undetermined result has no numerical headline score. Structured output retains scoring version, coverage, comparability and evidence limitations.

## Load the Claude entry for one session

Check the manifest and inspect what Claude Code discovers without starting a model turn:

```bash
claude plugin validate "/installed/plugin" --json
claude --plugin-dir "/installed/plugin" plugin details appsec-advisor
```

Replace `appsec-advisor` in `plugin details` with the delivered manifest name for a branded package. The plain two-entry composition selects `appsec-analyzer` and `security-score`; a score-only package selects only the latter. Organization additions and exclusions can change the surface. Compare discovery with the delivered inventory. Manifest validation and discovery do not prove skill execution; the earlier score replay recorded model-free discovery, while full execution of the new primary entry through Claude remains unqualified.

To use the entry interactively, start a dedicated session:

```bash
claude --plugin-dir "/installed/plugin"
```

For a selected deterministic score entry, invoke:

```text
/appsec-advisor:security-score --repo /source/repository --json
```

Use the delivered namespace, for example `/team-appsec:security-score` in a branded package. For the primary assessment entry, follow the separate authorization and preparation procedure below.

The generated score entry delegates to `WORKFLOW.md` and binds every engine command to the verified runtime. `--repo` maps to the engine's positional repository argument; `--yaml` selects YAML and omitting either format selects text. The engine performs no model calls. A conversational Claude session has its own model usage; the offline replay did not execute that model-driven interaction.

Session-only loading can shadow a same-named marketplace plugin for that session; organization-managed plugin controls take precedence. Check the selected source with `plugin details` before using the staging session. These rules are documented in the official [plugin loading reference](https://code.claude.com/docs/en/plugins/loading#name-conflicts) and [local development guide](https://code.claude.com/docs/en/plugins/create#load-a-plugin-for-one-session), checked on 2026-10-18. End that dedicated session to stop using the staged copy; no marketplace switch is part of this procedure.

## Inspect a branded package's organization settings

This procedure applies to a newly assembled organization package whose pinned engine declares `organization_config` schema version 1. Older staging inputs must be reassembled with the reviewed new host and engine pins; packaging cannot upgrade their immutable bootstrap or wheel. After explicit setup, inspect or validate the packaged engine projection without a model:

```bash
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" -- organization-config show
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" -- organization-config validate
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" -- organization-config show --preset release
```

Use a preset actually declared by the profile. Explicit `--preset` wins over `APPSEC_ADVISOR_PRESET`; unknown or empty selections fail. Inspection shows defaults separately from mandatory policy. Score does not consume assessment depth or call models. A configured nonempty URL allowlist restricts remote Git targets before Git or credentials; a rejected target returns 2 without a score. Ordinary scored, undetermined and operational-source outcomes retain statuses 0, 2 and 1. The existing score binding command above selects this public policy path automatically for an active composed profile.

External runtime profiles follow the selection procedure below. The primary binding applies the same admitted projection to its declared assessment commands. Use the existing checkout package for currently unsupported settings. The existing explicit no-profile selection disables the engine profile; it does not restore excluded skills or change host hooks. See the [configuration dispatch contract](../contracts/plugin-composition.md#organization-configuration-dispatch) for the supported scope and remaining migration gaps.


## Select an external score profile

Use a newly assembled host containing the reviewed bootstrap and `schemas/org-profile.schema.yaml`, plus the pinned engine's public `organization_config` capability. An older archive requires reassembly. Select an operator-maintained YAML file outside the analyzed source, without links, and at most 64 KiB. This runtime profile supports identity, Advisor compatibility, base-mode presets and the two supported policy fields. Host settings such as banner, hooks, MCP and skill selection require packaging; other engine settings remain unsupported.

```bash
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" --skill security-score -- score "/source/repository" --org-profile "/operator/score-profile.yaml" --preset release --json
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" -- organization-config show --org-profile "/operator/score-profile.yaml"
```

The external file has the same Advisor profile shape, with no engine envelope:

```yaml
api_version: appsec-advisor.org-profile/v2
organization: {id: team, name: Team Security, profile_version: "1"}
compatibility: {core: ">=0.6 <0.7"}
default_preset: daily
presets:
  daily: {base_mode: standard}
  release: {base_mode: thorough}
policy: {disable_opus: true, url_allowlist: [git.example.org]}
```

`--org-profile` wins over `APPSEC_ADVISOR_ORG_PROFILE`, then the packaged profile. Relative paths resolve against the plugin root. For an external profile, `--preset` wins over `APPSEC_ADVISOR_PRESET`, then its own default; the packaged config preset does not leak into that selection. Explicit no-profile selection disables the selected engine profile as before. Invalid selections and unsupported settings fail without fallback. Runtime selection changes neither the packaged host surface nor engine code. The host validates and splits the file, snapshots only engine settings privately for that invocation, and removes the snapshot on exit. The public engine validates that projection and enforces its URL restriction before Git or credentials. Score still makes no model call and uses no assessment depth.


## Inspect full-assessment configuration without running a model

Use a newly assembled host and Analyzer declaring `assess` under `organization_config.commands`, with `profile_source_validation: true`. The admitted profile fields remain the same as for score. For a selected primary entry, use its binding when inspecting the assessment so its execution defaults match the eventual launch:

```bash
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" --skill appsec-analyzer -- organization-config show --org-profile "/operator/score-profile.yaml" --preset release -- assess --repo "/source/repository" --assessment-depth quick
```

The returned `assessment_profile` shows effective depth and model settings while retaining the selected policy. This command performs no source retrieval, credential preflight or model call. Unknown settings and unsupported destinations fail. Replace `show` with `validate` for validation. The score binding remains score-only.

The primary binding selects `--launch-defaults advisor`, Claude CLI and unattended execution separately, with a default display width of 72. Without an explicit budget, quick/standard/thorough select USD 10/20/40; explicit hard-budget options take precedence over the retained deprecated soft-budget conversion. Default component concurrency is 3; explicit worker/parallel options retain their supported bounds. Inspect the effective settings before authorizing execution. `--interactive-launch` remains a compatibility adapter; the generated primary path no longer depends on it. Unbound `run` retains the standalone engine's settings and does not select these host defaults automatically.

Profile selection uses the documented CLI/environment/package precedence, and explicit assessment depth overrides the preset default. The host passes external-profile provenance for source confinement; mandatory URL and model restrictions reach the engine. Output-scoped lifecycle and result consumers do not reload an unavailable external organization profile. Unsupported profile fields, remaining hooks/UI migration and other legacy consumers stay outside this selected surface.

## Start an authorized primary assessment

Offline setup and inspection do not authorize model use. Obtain an explicit target and finite spending budget before invoking the primary entry. The model-backed Claude path sends admitted source and supplied context, including business answers, through the selected Claude host; verify that this transfer is authorized for the selected data. For a package with the primary binding selected, start a dedicated Claude session as above and use its delivered namespace:

```text
/team-appsec:appsec-analyzer --repo /source/repository --output /private/assessment --assessment-depth quick --hard-budget 10
```

Replace the namespace, source, private output and budget with the authorized selections. The generated host entry follows the engine-owned `claude-code.md` and business-context dialogue. It gathers required choices and uses public `assessment-entry` operations for destination, trust, ownership and context. It preserves stored answers, explicit rebuild consent, legacy-import choices and compatible resume semantics. Do not substitute a PATH engine or private controller script. Direct `run --skill appsec-analyzer -- assess ...` is the bound engine invocation, not a replacement for the host's necessary questions and confirmations.

Keep the assessment owner and its display separate. The engine chooses its progress-feed location; supply only the assessment output to the host follower:

```bash
python3 "/installed/organization-plugin/scripts/composition_runtime.py" follow --plugin "/installed/organization-plugin" --output "/private/assessment"
```

The follower is bounded and reads public holder/progress responses. Display expiry or interruption leaves the assessment running. Await the owner's task notification; do not add a model-managed polling or restart loop. A requested status check uses `run --skill appsec-analyzer -- status --output DIR` and `assessment-entry holder --output DIR` through the same binding. Preserve the actual owner exit status and verify `results` before claiming completion.

For an explicit stop request, call the public operation, then use the deterministic wait action if an authorized replacement launch needs the output released:

```bash
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" --skill appsec-analyzer -- stop --output "/private/assessment"
python3 "/installed/organization-plugin/scripts/composition_runtime.py" wait --plugin "/installed/organization-plugin" --output "/private/assessment" --timeout 300
```

Wait exit 0 means no live holder; exit 3 means the holder remained live until the deadline. An invalid or unavailable response fails. A successful stop request does not by itself prove shutdown: a fresh unreleased lock can still block a new launch. Never delete a live lock to continue. For stale-state diagnosis, inspect with `run --skill appsec-analyzer -- assessment-entry clean --output DIR`, and add `--apply` only for authorized cleanup. The recorded lifecycle fixture verified signalling and conservative refusal with a controlled child; real-controller shutdown and accepted-job resume still require the authorized full run.

Use the same selected entry with `--resume` only when requested and compatible. Preserve the original source, settings and limits; never turn a failed resume into `--rebuild` or a higher budget automatically.

## Inspect and export a saved assessment

The primary binding exposes the engine's validated result consumers without another assessment or assistant session:

```bash
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" --skill appsec-analyzer -- results --output "/private/assessment"
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" --skill appsec-analyzer -- query --output "/private/assessment" --summary
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" --skill appsec-analyzer -- query --output "/private/assessment" --id F-001
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" --skill appsec-analyzer -- export --assessment "/private/assessment" --output "/private/new-export" --formats markdown yaml sarif threatdragon pentest-tasks
```

Replace `F-001` with an ID present in the selected assessment. Query also supports `--grep`, `--severity` and `--component` filters; an ID or summary cannot combine with those filters. Saved completion, model validity and deliverable hashes are checked before use; changed or incomplete results fail explicitly. Export requires a new private destination; optional HTML/PDF output also requires its external tools. Query and export do not authorize triage mutation, source changes or model spending.

The installed offline replay used a committed completed-result fixture to exercise these consumers and tampering refusals. It does not establish that the new host entry can yet complete a full assessment. Reuse the recorded observations and pinned artifacts for unchanged boundaries; do not rebuild or rerun them solely for documentation changes.
