# Threat-Model Golden Fixture (freeze / replay)

`scripts/threat_fixture.py` turns a completed threat-model run into a reusable,
git-diffable **golden-master fixture**, and replays it to detect the effect of
**deterministic-pipeline** code changes across many repos — without re-running a
full (LLM) scan.

It is a manual developer/test tool. It is **not** part of the scanned-repo
pipeline and grants the skill no new permissions.

## Why a whole bundle, not just the report

Regression-testing a code change needs two things, not one:

- the producer's **inputs** (sidecars + `.fragments/`) so the tail can re-run;
- the golden **outputs** (`threat-model.yaml` / `.md` / `.sarif.json`) to diff
  against.

A report-only snapshot cannot be replayed. So `freeze` curates the whole run
(minus pure noise), then rebuilds the goldens with the **current** code — the
golden is "what today's code emits", so a later replay diff *is* the effect of a
code change.

## What it covers — and what it does not

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
- `meta.project` falls back to `repo_root.name`; the work dir and no-repo
  placeholder use stable names so it does not drift
- compose's last-resort project name is `output_dir.parent.name` — the work dir
  is built under a fixed parent so the title is stable
- scanner sidecars carry `generated_at` / `repo_root` → scrubbed

`compose` and `export_sarif` inherit their determinism from the scrubbed yaml.

## Storage

The canonical form is the **unpacked directory** — git diffs it, reviews it, and
delta-compresses it. A regression shows up as a normal text diff in the golden.
`--archive` additionally emits a reproducible `.tgz` (sorted, `mtime=0`) for
hand-off only; it is never the source of truth.

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

## Freeze

From the plugin root, after a completed run:

```bash
python3 scripts/threat_fixture.py freeze \
  --run  /path/to/output-dir \
  --into tests/fixtures/golden/<name> \
  --repo /path/to/scanned-repo        # optional: enables scanner goldens + SHA pin
  # --archive                          # optional: also write <name>.tgz
```

The source run must be complete (it must contain `threat-model.yaml`). The
`--repo` is **pinned by SHA**, not vendored — keep large repos as a submodule.
`freeze` rebuilds the tail itself and fails loudly if a required input was
dropped, so the fixture can never be silently incomplete.

## Replay

```bash
python3 scripts/threat_fixture.py replay \
  --fixture tests/fixtures/golden/<name> \
  --stage all                          # or a comma list: yaml,md,sarif,scanner
  --repo /path/to/scanned-repo         # override for the scanner stage
```

Exit `0` only when the manifest verifies **and** every selected stage shows no
drift. Any diff is printed as a unified diff and exits non-zero. The scanner
stage is skipped (not failed) when the source repo is unavailable.

## In CI / pytest

`tests/test_threat_fixture.py` exercises the tool end-to-end against the
committed `tests/fixtures/e2e/_last-run` run dir and the `synthetic-repo`
fixture: it freezes, asserts the layout and scrubbing, replays for zero drift,
and verifies that golden tampering and manifest tampering are both caught.
