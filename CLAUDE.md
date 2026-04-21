# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What This Is

A Claude Code plugin that runs automated STRIDE-based security threat modeling against any repository. Outputs to `$OUTPUT_DIR` (default: `docs/security/` inside the analyzed repo):

- `threat-model.md` — human-readable report: C4 diagrams, security use cases, threat register with severity badges, VS Code deep links
- `threat-model.yaml` — structured export (`--yaml`)
- `threat-model.sarif.json` — SARIF v2.1.0 for CI/CD (`--sarif`)
- `pentest-tasks.yaml` — task list for AI pentesters / DAST (`--pentest-tasks`)

**Two modes:**
- **Dev team** (default): run inside the repo, output to `docs/security/`.
- **AppSec team**: `--repo <path>` to analyze externally, `--output <path>` to write elsewhere.

**Status:** 0.9.0-beta — functionally complete, guided AppSec-team use. Not yet hardened for unattended CI/CD.

## Model Policy

All agents default to `claude-sonnet-4-6`. Opus is used only where deep reasoning pays off:
- `--reasoning-model opus-cheap` (auto at `--assessment-depth thorough`): Opus for triage-validator + threat-merger (~$0.07 extra).
- `--reasoning-model opus`: additionally for STRIDE analyzers (~$2–5 extra).
- `--architect-model opus` (default when Stage 3 runs): architect-reviewer.
- `--stride-model opus` — deprecated, use `--reasoning-model`.

Overrides pass via the Agent tool's `model` field, taking precedence over agent frontmatter.

## Agent Architecture

Seven-agent pipeline; only `appsec-threat-analyst` is user-facing.

```
User
 └── /appsec-plugin:create-threat-model          (skill — up to 3 stages)
      ├── Stage 1: appsec-threat-analyst        Sonnet  orchestrator (Phases 1–11)
      │     ├── appsec-context-resolver          Sonnet  Phase 1:  context
      │     ├── appsec-recon-scanner             Sonnet  Phase 2:  repo & code recon
      │     ├── scripts/dep_scan.py              Python  Phase 2:  SCA (--with-sca, bg)
      │     ├── appsec-stride-analyzer           Sonnet* Phase 9:  per component (bg)
      │     ├── appsec-threat-merger             Sonnet* Phase 9:  merge candidates
      │     └── appsec-triage-validator          Sonnet* Phase 10b: consistency
      ├── Stage 2: appsec-qa-reviewer            Sonnet  verify & fix output
      └── Stage 3: appsec-architect-reviewer     Opus    advisory review (auto @ thorough)
```

*\* reasoning-model-overridable*

**Why Stages 2 and 3 are skill-level, not orchestrator-level:** each gets its own independent turn budget so they can't be starved by Phase 9. Stage 3 is strictly advisory — it writes `.architect-review.md` and never modifies `threat-model.md/yaml/sarif.json`.

### Orchestrator phases (`appsec-threat-analyst`, 75 turns)

1. Context resolution → `.threat-modeling-context.md`
2. Recon → `.recon-summary.md`; launch dep_scan.py in background if `WITH_SCA`
3. Architecture (C4: Context / Container / Component)
4. Security use cases (sequence diagrams)
5. Asset identification
6. Attack surface
7. Trust boundaries
8. Security controls catalog (✅ / ⚠️ / 🔶 / ❌)
8b. Requirements compliance (when enabled) → FAIL threats feed Phase 9
9. STRIDE enumeration (one analyzer per component, merge, global T-IDs, dedup)
10. Dep scan synthesis
10b. Triage validation → `.triage-flags.json`
11. Finalization: write `threat-model.md` + `.yaml`, release lock, print summary

### Sub-agents (brief)

| Agent | Role |
|-------|------|
| `context-resolver` (25 turns) | Reads `SECURITY.md`, ADRs, OpenAPI, docker-compose, K8s/Terraform, schemas, `docs/known-threats.yaml`, optional external REST endpoint. |
| `recon-scanner` (25 turns) | Scans 26 security categories; keeps orchestrator out of per-file reads. |
| `dep_scan.py` (script) | Native audit tools (`npm audit`, `pip-audit`, `govulncheck`, `mvn dependency-check`); static heuristics fallback (`data/dep-scan-heuristics.yaml`); 1 h manifest-hash cache. |
| `stride-analyzer` (31 turns) | One per component; writes `.stride-<id>.json`. |
| `threat-merger` (12 turns) | Only when candidate groups exist; decides merge / consolidate / keep. |
| `triage-validator` (20 turns) | Cross-component rating consistency, severity, P1/P2 alignment. |
| `qa-reviewer` (80 turns, Stage 2) | 10+ checks on `threat-model.md`: deep links, cross-refs, placeholders, diagrams, anchors. Fixes in place. |
| `architect-reviewer` (40 turns, Stage 3, advisory) | 6 checks (skips 1/4/6 at quick). Never modifies orchestrator output. |

## Skills & Key Flags

`skills/` contains two slash commands:

| Skill | Description |
|-------|-------------|
| `/appsec-plugin:create-threat-model` | Full STRIDE assessment |
| `/appsec-plugin:check-appsec-requirements` | Verify `[SEC-*]` requirements |

**Mode defaults:** if `$OUTPUT_DIR/threat-model.md` exists, the skill runs incremental. Override with `--full` (fresh re-analysis, preserves changelog + T-IDs), `--rebuild` (wipe all prior state), or `--incremental` (explicit).

**Core flags:**

| Flag | Purpose |
|------|---------|
| `--repo <path>` / `--output <path>` | External repo / separate output dir |
| `--yaml` / `--sarif` | Additional output formats |
| `--pentest-tasks [--pentest-format strix] [--pentest-target <url>]` | Emit task list for AI pentesters; only STRIDE/dep-scan/known-vuln threats with concrete evidence and eligible CWE. All tasks carry `safety` block (read-only, no destructive probes). |
| `--requirements [<url>]` / `--no-requirements` | Enable/disable Phase 8b compliance check |
| `--with-sca` | Run dep-scanner (secrets and insecure defaults are already covered elsewhere) |
| `--assessment-depth quick\|standard\|thorough` | Scope control: 3/5/8 STRIDE components; diagram depth; QA breadth; Phase 8 grep strategy |
| `--reasoning-model sonnet\|opus-cheap\|opus` | Phase 9/10 reasoning models (see Model Policy) |
| `--architect-review` / `--no-architect-review` / `--architect-model` | Stage 3 control (auto-on at thorough) |
| `--full` / `--rebuild` / `--incremental` / `--resume` | Run-mode control |
| `--dry-run` | Full analysis, no files written to repo (temp output, console summary) |
| `--verbose` | Metadata table + Run Statistics appendix in `threat-model.md` |
| `--keep-runtime-files` | Skip Phase 11 transient-file cleanup |

## Output Conventions (what the report must contain)

- **Management Summary** before Section 1: risk distribution, strengths, top findings, priority actions, overall rating. Requirements subsection when enabled.
- **CWE ID mandatory** in every threat scenario.
- **VS Code deep links** (`vscode://file/<abs-path>:<line>`) for every referenced source file.
- **Clickable T-NNN / M-NNN** cross-references everywhere (orchestrator pre-links; QA reviewer is the safety net).
- **Severity badges** (Critical/High/Medium/Low) and control badges (✅ Adequate / ⚠️ Partial / 🔶 Weak / ❌ Missing).
- **Technology Architecture diagram** (Section 2.4) always produced; Medium+ threat nodes in pink.
- **Cross-repo dependency coverage** (Section 5): SCM siblings with existing threat models annotated green/red; SaaS purple. Missing upstream models elevate risk at shared boundaries.
- **CVSS v4.0** scoring only where groundable: required for `dep-scan` / `known-vuln`; allowed for `stride` iff CWE ∈ `data/cvss-eligible-cwes.yaml` AND evidence has file+line; forbidden for architectural / requirements / coverage-gap threats. Enforced by `validate_intermediate.py` + triage-validator Step 5.
- **Change Summary** (`+N added / ~N changed / -N resolved`) on every re-run with a baseline. T-IDs stable across `--full` runs so Jira/Linear refs don't break.

## Reliability

- **Sub-agent retry** — stride-analyzer / dep-scanner retry once on failure.
- **Concurrent-run lock** — `.appsec-lock` (< 1 h = blocks; > 1 h = stale, overwritten).
- **Stale-file cleanup is mode-aware**: full runs wipe `.stride-*.json`, `.dep-scan.json`, `.recon-summary.md`, `.appsec-cache/baseline.json`; incremental preserves them (carry-forward source). `.phase-epoch` and `.progress/` reset every run.
- **Runtime cleanup** (Phase 11): whitelist of transient files removed after success (`.dep-scan.pid/.stdout`, `.merge-candidates/decisions.json`, `.management-summary-draft.md`, `.phase-epoch`, `.session-agent-map`, `.progress/`). Gated on no `AGENT_ERROR` in last 100 log lines. **Audit artifacts never touched** (`.threat-modeling-context.md`, `.recon-summary.md`, `.dep-scan.json`, `.stride-*.json`, `.threats-merged.json`, `.triage-flags.json`, `.architect-review.md`, `.appsec-cache/`, logs). Whitelist pinned in `tests/test_runtime_cleanup.py` — drift guard.

## Logging & Progress

- Hook events (agent spawns, file writes, token/cost) → `$OUTPUT_DIR/.hook-events.log`.
- Structured agent events → `$OUTPUT_DIR/.agent-run.log`. Both rotate at 5 MB.
- `ASSESSMENT_SUMMARY` + `ASSESSMENT_PHASES` blocks appended at session end.
- **Phase banners** on every phase start/end with expected + actual duration.
- **Intra-phase progress**: `[k/N]` counters with `(+MMmSSs)` markers. Phase 9 polls `scripts/stride_progress.py` ~20 s for live per-component substep status (9 substeps → `.progress/<component>.json`).
- Enable real-time stderr mirroring via `APPSEC_VERBOSE=1`, `logging.verbose: true` in `config.json`, or `scripts/run-headless.sh --verbose`.

## Intermediate Files (persisted, in `$OUTPUT_DIR/`)

`.threat-modeling-context.md`, `.recon-summary.md`, `.dep-scan.json`, `.stride-<id>.json`, `.threats-merged.json` (canonical, annotated with `triage_flags`), `.triage-flags.json`, `.architect-review.md`, `.appsec-cache/baseline.json` (carry-forward), `.appsec-lock`, `.progress/`, `.phase-epoch`, `.agent-run.log`, `.hook-events.log`.

## External Context *(optional)*

`config.json` → `external_context.rest_url` enables a POST to your endpoint in Phase 1. Endpoint receives `{"repo_url": "..."}`, returns `{"context": "..."}`, appended to `.threat-modeling-context.md`. Dev mock: `python3 scripts/mock-context-server.py [port]`.

Teams can also drop `docs/known-threats.yaml` in the analyzed repo. STRIDE analyzer verifies `open`/`mitigated` against current code; `accepted` goes to Section 11; `false-positive` is skipped. QA reviewer ensures coverage.

## Security Requirements Baseline

Config: `skills/check-appsec-requirements/config.json` → `requirements_source.{enabled, requirements_yaml_url}`. Persistent cache at `$CLAUDE_PLUGIN_ROOT/.cache/requirements.yaml`.

Resolution for `create-threat-model`: `--no-requirements` > `--requirements[=<url>]` > config `enabled`. With explicit `<url>`: no cache fallback. Otherwise: configured URL → cache fallback → abort.

`check-appsec-requirements` always loads regardless of `enabled`. `data/appsec-requirements-fallback.yaml` (53 requirements, 10 categories) is a starting template, **not** a runtime fallback; regenerate via `scripts/harvest-requirements.py`.

## Security Steering Hook

`UserPromptSubmit` hook injects secure-by-default context on code/security prompts. Tiered matching (strong / code / action keywords) avoids false positives on prompts like "create a README". Keywords live in `hooks/steering_keywords.json`.

## No Build System

All agents and skills are plain Markdown. Phase-group files under `agents/phases/` are the **authoritative** source for phase instructions; the orchestrator prompt contains only execution flow and parameters. Edit directly.

`scripts/validate_config.py` validates `config.json` + skill configs against a schema — run in CI.

## ⚠ Maintaining the Permission Allow-List

The canonical Bash permission list lives in **`skills/create-threat-model/SKILL.md`** → "Permission auto-check". Keep in sync whenever plugin code introduces new Bash patterns.

**Update when:** new Bash block, new `VAR=$(...)` assignment, new shell builtin, changed Write/Edit target, new sub-agent.

**How:** take the first token (prefix Claude Code matches on — `FOO=` for assignments, `while` for builtins), add it to the appropriate section in SKILL.md. Paths outside `$OUTPUT_DIR` need a scoped `Write()` / `Bash(rm ...)` entry.

**Why:** users without `Bash(*)` get a prompt per unrecognized prefix — a single missing entry can cause dozens of prompts during an 80-minute assessment and block unattended runs.

**Validation:**
```bash
grep -hP '^\w+=\$|^\w+ ' agents/**/*.md agents/*.md | \
  sed 's/[=(].*//' | sort -u
```

## Roadmap (before 1.0)

- [ ] Token-budget tracking and cost estimation per assessment (runtime counters)
- [ ] End-to-end CI test against a reference repository
- [ ] MCP server authentication for team deployments
