# Threat-model golden fixture (freeze / replay)

`scripts/threat_fixture.py` freezes a completed threat-model run as a regression fixture. Replay it after a deterministic-pipeline change to compare outputs without another LLM scan.

It is a manual developer/test tool. It is **not** part of the scanned-repo
pipeline and grants the skill no new permissions.

## Workflow (end to end)

The two scripts run in order: first produce a real run, then freeze it; replay
comes later, after you change code.

<a id="step-1--produce-a-threat-model-the-one-time-llm-backed-run"></a>
### Step 1: produce a threat model (the one-time, LLM-backed run)

Run the pipeline with **`--keep-runtime-files`**. Otherwise, cleanup removes the sidecars that `freeze` needs to rebuild the outputs.

```bash
./scripts/run-headless.sh \
  --repo   /path/to/target-repo \
  --output /tmp/run-<name> \
  --sarif \
  --assessment-depth standard \
  --keep-runtime-files
```

Notes on parameters:

- `--keep-runtime-files`: **required** (retains `.fragments/` + all sidecars).
- `--assessment-depth quick|standard|thorough`: pick what you want the fixture to represent; freeze captures whatever this run produced.
- `--sarif`: yaml is always written; this also exercises the SARIF stage.
- `--requirements`: include only if you want the Requirements-Compliance section frozen too (the run then produces its fragment).
- The run must **complete** (it must leave a `threat-model.yaml`).

The source repo should be at a **pinned commit** (a submodule or a clean
checkout) so the SHA recorded in `expected-meta.json` is meaningful.

<a id="step-2--freeze-the-run-into-a-fixture"></a>
### Step 2: freeze the run into a fixture

```bash
python3 scripts/threat_fixture.py freeze \
  --run  /tmp/run-<name> \
  --into tests/fixtures/golden/<name> \
  --repo /path/to/target-repo        # enables scanner goldens + SHA pin
  # --archive                         # optional: also write <name>.tgz
```

`freeze` rebuilds the deterministic tail and fails if a required input is missing. Commit the unpacked `tests/fixtures/golden/<name>/` directory.

<a id="step-3--later-after-changing-code-replay"></a>
### Step 3: later, after changing code, replay

```bash
python3 scripts/threat_fixture.py replay \
  --fixture tests/fixtures/golden/<name> \
  --repo    /path/to/target-repo
```

Zero drift = your change had no effect on this repo's deterministic output. A
printed diff = exactly the effect of your change. When the change is intentional
and correct, re-run **Step 2** to bless the new golden (delete the old fixture
dir first, since `freeze` refuses to overwrite).

Steps 1–2 are done once per repo (and refreshed when the run itself changes);
Step 3 is the fast inner loop and needs no LLM.

## Why a whole bundle, not just the report

Regression-testing a code change needs two things, not one:

- the producer's **inputs** (sidecars + `.fragments/`) so the tail can re-run;
- the golden **outputs** (`threat-model.yaml` / `.md` / `.sarif.json`) to diff
  against.

A report alone cannot be replayed. `freeze` retains the required inputs and rebuilds expected outputs with the current code. Later replays compare against those outputs.

<a id="what-it-covers--and-what-it-does-not"></a>
## Coverage and limits

The deterministic tail and the source scanners, all offline:

| Layer | Stage | Re-runnable offline |
|---|---|---|
| `build_threat_model_yaml.py` | `yaml` | ✅ from frozen sidecars |
| `compose_threat_model.py` | `md` | ✅ from golden yaml + `.fragments/` |
| `export_sarif.py` | `sarif` | ✅ from golden yaml |
| `route_inventory.py`, `source_auth_scanner.py` | `scanner` | ✅ against the pinned repo |

It does **not** cover the LLM layer (recon synthesis, STRIDE analysis, triage,
§7/MS narrative). Those are frozen as *fixed inputs*; you are testing everything
downstream of them, not the model output itself. For semantic quality of the
model output, see the `eval-threat-model` path instead.

## Volatile fields (scrubbed before every diff)

Verified against `build_threat_model_yaml.py`:

- `meta.generated` (`datetime.now`) → sentinel timestamp
- `meta.git.*` (read from the scanned repo's git) → sentinels
- `changelog[].date` / `current_sha` / `previous_date` (`date.today` / repo HEAD)
- `meta.project` falls back to `repo_root.name`; the work dir and no-repo placeholder use stable names so it does not drift
- compose's fallback project name is `output_dir.parent.name`; the work directory uses a fixed parent to keep the title stable
- scanner sidecars carry `generated_at` / `repo_root` → scrubbed

`compose` and `export_sarif` inherit their determinism from the scrubbed yaml.

## Storage

Commit the unpacked directory so output changes can be reviewed as text diffs. `--archive` also produces a reproducible `.tgz` (sorted, `mtime=0`) for transfer. The archive does not replace the committed directory.

Fixture layout:

```text
<fixture>/
  inputs/              # pre-tail sidecars + .fragments/ (noise/outputs excluded)
  golden/
    threat-model.yaml  # canonical, scrubbed
    threat-model.md
    threat-model.sarif.json
  scanner-golden/      # only when --repo is given
    .route-inventory.json
  expected-meta.json   # pinned repo SHA, depth, plugin_version, scanner map
  MANIFEST.json        # sha256 of every file (integrity / drift guard)
```

## Command reference

`freeze` (Step 2): `--run` must contain `threat-model.yaml`; `--repo` is **pinned by SHA**, not vendored (keep large repos as a submodule); `--archive` also writes a `.tgz`. `freeze` refuses to overwrite an existing `--into`.

`replay` (Step 3): `--stage all` or a comma list `yaml,md,sarif,scanner`; `--repo` overrides the source repo for the scanner stage. Exit `0` only when the manifest verifies **and** every selected stage shows no drift; any diff is printed as a unified diff and exits non-zero. The scanner stage is *skipped* (not failed) when the source repo is unavailable.

## In CI / pytest

`tests/test_threat_fixture.py` exercises the tool end-to-end against the
committed `tests/fixtures/e2e/_last-run` run dir and the `synthetic-repo`
fixture: it freezes, asserts the layout and scrubbing, replays for zero drift,
and verifies that golden tampering and manifest tampering are both caught.
