# Run the composed score staging plugin

Use this procedure for a reviewed score-only staging archive assembled under the [composition contract](../contracts/plugin-composition.md). It retains the `appsec-advisor` namespace and provides only `security-score`. It is not a replacement release of the full Advisor plugin. The [offline evidence](../analysis/composition-offline-evidence-2026-10-18.md#real-engine-score-binding-replay) records the tested component revisions and platform.

## Prepare the runtime

Verify the archive against its reviewed checksum, then extract it into a dedicated plugin directory outside source checkouts. The directory must contain `.claude-plugin/plugin.json`, `components.lock.json`, the bootstrap and the selected skill resources. Use the existing Python interpreter selected by the lock; replace `python3` in the examples if that interpreter has another name or path.

Run explicit setup once, then read-only preflight. Replace `/installed/score-plugin` with the extracted plugin directory.

```bash
python3 "/installed/score-plugin/scripts/composition_runtime.py" setup --plugin "/installed/score-plugin"
python3 "/installed/score-plugin/scripts/composition_runtime.py" preflight --plugin "/installed/score-plugin"
```

Setup uses only the verified bundled wheels and activates its environment outside Git checkouts. The standard runtime location lets the generated Claude entry find it without additional configuration. If setup uses an explicit `--runtime-home`, every subsequent bootstrap invocation must use that same operator-selected path.

## Run without a model

Select a committed top-level Git checkout. The launcher checks the installed engine's deterministic score capabilities before dispatch. The following commands preserve the engine's output and exit status.

```bash
python3 "/installed/score-plugin/scripts/composition_runtime.py" run --plugin "/installed/score-plugin" --skill security-score -- score "/source/repository"
python3 "/installed/score-plugin/scripts/composition_runtime.py" run --plugin "/installed/score-plugin" --skill security-score -- score "/source/repository" --json
python3 "/installed/score-plugin/scripts/composition_runtime.py" run --plugin "/installed/score-plugin" --skill security-score -- score "/source/repository" --yaml
```

A computed score returns 0, an undetermined score returns 2, an operational or source-admission failure returns 1, and cancellation returns 130. Argument errors can also return 2; inspect the actual output. An undetermined result has no numerical headline score. Structured output retains scoring version, coverage, comparability and evidence limitations.

## Load the Claude entry for one session

Check the manifest and inspect what Claude Code discovers without starting a model turn:

```bash
claude plugin validate "/installed/score-plugin" --json
claude --plugin-dir "/installed/score-plugin" plugin details appsec-advisor
```

The score-only package should list one skill, `security-score`, and no agents, hooks or tool servers. Manifest validation alone does not prove skill execution; Claude Code 2.1.302 returned an empty content-validation inventory for this command. The recorded replay separately checked discovery, portable dependency declarations and local references.

To use the entry interactively, start a dedicated session:

```bash
claude --plugin-dir "/installed/score-plugin"
```

Then invoke:

```text
/appsec-advisor:security-score --repo /source/repository --json
```

The generated entry delegates to `WORKFLOW.md` and binds every engine command to the verified runtime. `--repo` maps to the engine's positional repository argument; `--yaml` selects YAML and omitting either format selects text. The engine performs no model calls. A conversational Claude session has its own model usage; the offline replay did not execute that model-driven interaction.

Session-only loading can shadow a same-named marketplace plugin for that session; organization-managed plugin controls take precedence. Check the selected source with `plugin details` before using the staging session. These rules are documented in the official [plugin loading reference](https://code.claude.com/docs/en/plugins/loading#name-conflicts) and [local development guide](https://code.claude.com/docs/en/plugins/create#load-a-plugin-for-one-session), checked on 2026-10-18. End that dedicated session to stop using the staged copy; no marketplace switch is part of this procedure.

## Inspect a branded package's organization settings

This procedure applies to a newly assembled organization package whose pinned engine declares `organization_config` schema version 1. Older staging inputs must be reassembled with the reviewed new host and engine pins; packaging cannot upgrade their immutable bootstrap or wheel. After explicit setup, inspect or validate the packaged engine projection without a model:

```bash
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" -- organization-config show
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" -- organization-config validate
python3 "/installed/organization-plugin/scripts/composition_runtime.py" run --plugin "/installed/organization-plugin" -- organization-config show --preset release
```

Use a preset actually declared by the profile. Explicit `--preset` wins over `APPSEC_ADVISOR_PRESET`; unknown or empty selections fail. Inspection shows defaults separately from mandatory policy. Score does not consume assessment depth or call models. A configured nonempty URL allowlist restricts remote Git targets before Git or credentials; a rejected target returns 2 without a score. Ordinary scored, undetermined and operational-source outcomes retain statuses 0, 2 and 1. The existing score binding command above selects this public policy path automatically for an active composed profile.

External runtime `--org-profile` and `APPSEC_ADVISOR_ORG_PROFILE` overrides are explicitly refused in composed staging. Use the existing checkout package for profiles needing that selection or currently unsupported settings. The existing explicit no-profile selection disables the engine profile; it does not restore excluded skills or change host hooks. See the [configuration dispatch contract](../contracts/plugin-composition.md#organization-configuration-dispatch) for the supported scope and remaining migration gaps.
