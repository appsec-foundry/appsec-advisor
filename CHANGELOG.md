# Changelog

## 0.9.0-beta — 2026-04-23

First public release. Works well enough for guided use; not yet something
I'd leave unattended in CI overnight.

- New `publish-threat-model` skill so reports don't get committed by accident.
- Multi-repo scanning (`--repo`, `--output`, `generate-threat-summary`).
- `docs/related-repos.yaml` pulls upstream findings into STRIDE at trust boundaries.
- Headless runner for CI (`scripts/run-headless.sh`).
- Incremental mode with a noise-only fast path — docs/IDE-only changes exit immediately.
- Triage validator split: steps 1–5 are plain Python now, only ranking stays on the LLM.
  Cut triage cost by ~10x.
- Architect reviewer (Opus, advisory only) auto-runs at `--assessment-depth thorough`.
- QA reviewer with a bounded repair loop (max 3 iterations).
- SARIF v2.1.0 and pentest-task export.
- Prompt-caching contract for Phase 9 dispatches — stable payload first, volatile last.
- Schema/contract enforcement on every intermediate artefact.
- Default reasoning model is now `opus-cheap` (Opus for triage + merger, Sonnet for the rest).
- Rendering went single-source: agents emit fragments, `compose_threat_model.py` writes the report.

### Known issues

- `appsec-config-scanner` is defined but not wired up yet. Will either land
  as Phase 2.5 or be removed before 1.0.
- On a fresh install, run `/appsec-advisor:check-permissions --update` once.
  Otherwise the first assessment will stop every 30 seconds for a permission prompt.
- No full-pipeline E2E test in CI yet. Unit coverage is fine.
