# Phase Group: Output & Finalization (Phase 11)

This file is read by the orchestrator at runtime to load phase instructions.

## `threat-model.yaml` Schema (v1)

The yaml is the **single structured baseline** for incremental runs. It is always written when `WRITE_YAML=true` (which is now the default — see SKILL.md flag matrix). Schema version 1:

```yaml
meta:
  schema_version: 1
  generated: <ISO>                   # UTC, e.g. 2026-04-11T10:22:00Z
  mode: full | incremental
  git:
    commit_sha: <full sha>            # CURRENT_SHA at the time of this run
    branch: <branch name>
    remote_url: <git remote origin url — optional>
  baseline_ref: <sha>                 # only set when mode=incremental; equal to the previous run's meta.git.commit_sha
  model: <model id>                   # e.g. claude-sonnet-4-6
  analysis_duration_seconds: <int>

changelog:                            # append-only history, newest first
  - version: <int>                    # monotonic, 1, 2, 3, ...
    date: <ISO>
    mode: full | incremental
    baseline_sha: <sha | null>        # null for full runs
    current_sha: <sha>
    changed_files: <int>              # 0 for full-rebuild entries
    reanalyzed_components: [<id>, ...]
    carried_forward_components: [<id>, ...]
    added:
      threats: [<T-ID>, ...]
      components: [<id>, ...]
      attack_surface: [<E-ID>, ...]
    changed:
      threats: [<T-ID>, ...]
    resolved:
      threats: [<T-ID>, ...]
      reason_by_id:
        <T-ID>: "<reason>"
    note: <string>                    # only for full-rebuild entries

components:                           # NEW in v1 — file-to-component mapping
  - id: <stable-id>                   # e.g. auth-svc — MUST be stable across runs
    name: <human name>
    kind: service | library | frontend | worker | cli | infrastructure
    paths: [<glob>, ...]              # path globs used by incremental dirty-set mapping
    threat_ids: [<T-ID>, ...]         # for quick lookup; authoritative source is threats[]
    last_analyzed_sha: <sha>          # the commit sha at the last successful STRIDE run for this component

assets: [...]                         # existing structure
attack_surface: [...]                 # existing structure; each entry has a stable E-ID
trust_boundaries: [...]               # existing structure
threats: [...]                        # existing structure; T-IDs MUST be stable across incremental runs
mitigations: [...]                    # existing structure; M-IDs stable
security_controls: [...]              # existing structure
requirements_compliance: [...]        # only when CHECK_REQUIREMENTS=true
out_of_scope: [...]                   # existing structure
```

**Hard invariants** (enforced by baseline_state.py and by incremental logic in Phase 9):

1. `meta.schema_version` is 1. Bump it only alongside a migration path.
2. T-IDs, M-IDs, and E-IDs are **stable across runs**. A carried-forward component must keep every one of its T-IDs. New IDs come from `.appsec-cache/baseline.json.id_counters`.
3. `changelog[]` is **append-only**. Never rewrite or delete historical entries, even on a full rebuild — instead, prepend a new `mode: full` entry.
4. `components[].paths` is the source of truth for the Phase 9 dirty-set mapping. Keep it in sync with the actual directory layout.
5. `meta.git.commit_sha` MUST be set to `git rev-parse HEAD` at the end of Phase 11, on every write. This is what the next run uses as baseline.

The renderer (`render_threat_model.py`) does not know or care about this schema — the yaml is composed and written directly by the orchestrator in Phase 11. The schema lives here as the authoritative contract.

## Mode-Aware Write Gate

Phase 11 writes several artifacts. Which artifacts actually get written depends on the `INCREMENTAL` × `DRY_RUN` matrix. This gate is the **single source of truth** — every Write tool call in this phase must consult it.

| `INCREMENTAL` | `DRY_RUN` | `threat-model.md` | `threat-model.yaml` | `.appsec-cache/baseline.json` | `.stride-*.json` retention | `threat-model.delta.md` | changelog entry |
|---|---|---|---|---|---|---|---|
| `false` (full) | `false` | **overwrite** | **overwrite** (changelog history preserved, new `mode: full` entry appended) | **overwrite** | regenerated | — | append `mode: full` entry |
| `false` (full) | `true` | — | — | — | — | — | — |
| `true` (incremental) | `false` | **update in place** (Changelog section refreshed) | **update in place** (append new entry to `changelog[]`) | **update** (refresh fingerprints + id counters) | per-component overwrite or carry-forward | — | append `mode: incremental` entry |
| `true` (incremental) | `true` | — | — | — | — | **write preview** | — (preview only) |

**Computed flag** — set this once at the start of Phase 11:
```bash
if [ "$DRY_RUN" = "true" ] && [ "$INCREMENTAL" = "true" ]; then
  WRITE_MODE="delta-preview"
elif [ "$DRY_RUN" = "true" ]; then
  WRITE_MODE="none"          # Phase 0–1 dry-run path — Phase 11 is not reached in practice
elif [ "$INCREMENTAL" = "true" ]; then
  WRITE_MODE="incremental"
else
  WRITE_MODE="full"
fi
```

All subsequent substeps branch on `$WRITE_MODE`.

## Phase 11: Finalization

### Phase Start — capture epoch, checkpoint, and determine N

The PHASE_START Bash call for Phase 11 MUST do three things in one batch:

1. Reset the phase-epoch so all `(+MMmSSs)` elapsed timers below measure Phase 11 only, not earlier phases.
2. Write the phase-11 checkpoint.
3. Print the PHASE_START line.

```bash
date +%s > "$OUTPUT_DIR/.phase-epoch"
echo "CHECKPOINT phase=11 status=writing_output" > "$OUTPUT_DIR/.appsec-checkpoint"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  PHASE_START   [Phase 11/11] Finalization…" >> "$OUTPUT_DIR/.agent-run.log"
```

**Compute `N` (total substep count) at phase start** based on `WRITE_MODE` and active flags. Keep `N` stable for the whole phase — advance `k` even if a step is skipped so the final print shows `[N/N]`:

| `WRITE_MODE` | Base substeps | +SARIF | `N` |
|---|---|---|---|
| `full` | pre-compute, compose, write md, write yaml, write cache, update changelog, release-lock = 7 | +1 if `WRITE_SARIF=true` | **7 or 8** |
| `incremental` | pre-compute, compose, update md in place, update yaml in place (with new changelog entry), update cache, release-lock = 6 | +1 if `WRITE_SARIF=true` | **6 or 7** |
| `delta-preview` | pre-compute, compose delta, write `threat-model.delta.md`, release-lock = 4 | n/a (SARIF is not re-generated in dry-run) | **4** |
| `none` | release-lock only = 1 | n/a | **1** |

Note: the old `WRITE_YAML=false` path no longer exists — yaml is now always-on. The `--no-yaml` escape hatch (if set) simply omits the yaml write substep and subtracts 1 from `N`.

Substitute the concrete integer for every `N` below. Do not write the literal letter `N` into log lines.

**Why only 4–6 substeps (previously 7–9):** Earlier versions of this file listed "Building Management Summary", "Assembling Table of Contents", "Writing Sections 1-7", "Writing Section 8", and "Writing Sections 9-11" as five separate substeps. In reality, all of that content is composed as the single `content:` argument of one `Write` tool call — there is no way to observe the individual sections as separate tool invocations. Listing them as distinct STEP_START entries created a visible "hang" at `[1/7] Building Management Summary…` while Claude spent 1–3 minutes generating the ~90 KB markdown body in a single turn, with substeps 2–5 silently skipped. The honest substep model below names composition as one opaque step and warns the user *before* the silence begins, batched with a cheap pre-compute so the warning reaches the terminal before the Write turn starts.

### Write Output Files

**⚠ MANDATORY STEP_START CONTRACT — no exceptions:**

- Every substep below MUST emit exactly one STEP_START log line **before** performing its work.
- Each STEP_START MUST be **batched in the same Bash / tool call** as the work it describes — never spend an extra orchestrator turn on logging alone. If a substep is implemented by a `Write` tool call (not Bash), emit the log in a preceding Bash call that **also advances** something concrete (e.g. reading a count, pre-computing a variable) so the turn is not wasted.
- The format is non-negotiable and identical to Phase 3–10: `[Phase 11 +${ES}] [k/N] <description>`. Any deviation breaks the ASSESSMENT_SUMMARY parser.
- Silent substeps (no STEP_START) are treated as a Phase 11 defect — this is the single most common reason Phase 11 looks like a hang.

**Elapsed-time helper — inline at the start of every STEP_START Bash call:**
```bash
PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60)))
```

**Canonical STEP_START echo — substitute `<k>`, concrete integer for `N`, and `<description>`:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [<k>/<N>] <description>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

Also mirror each step to stdout: `  ↳ [<k>/<N>] <description>  (+${ES})`.

**Substeps (in order) — every one MUST log before doing the work:**

| `k` | Description template | Condition | Batched with |
|-----|----------------------|-----------|--------------|
| 1 | `Pre-computing final counts (threats, mitigations, sections)…` | always | the Bash count-computation block below |
| 2 | `Composing threat-model.md content (expect 1–3 min silence — generating ~90 KB markdown in one pass)…` | always | a *separate* Bash call that emits the STEP_START + runs a small second count pass (e.g. `wc -l "$OUTPUT_DIR/.recon-summary.md"`). **This Bash call MUST be its own turn, NOT batched with the Write tool call that follows** — the whole point is to put the warning in front of the user *before* the long Write turn starts |
| 3 | `Writing threat-model.md…` | always | the `Write` tool call that creates `$OUTPUT_DIR/threat-model.md` |
| 4 | `Writing threat-model.yaml…` | **always — skip ONLY when `WRITE_YAML=false` (user passed `--no-yaml`).** Yaml is the canonical baseline for future incremental runs; skipping it by default breaks the incremental pipeline. | the `Write` tool call that creates `$OUTPUT_DIR/threat-model.yaml` |
| 5 | `Updating .appsec-cache/baseline.json…` | `WRITE_MODE` in {`full`, `incremental`} (i.e. not `delta-preview` or `none`) | the Bash call that invokes `baseline_state.py update` — see "Baseline Cache Update" below |
| 5 *or* 6 | `Generating SARIF export (<n> results) and writing threat-model.sarif.json…` (substitute `<n>`) | only if `WRITE_SARIF=true` | the `Write` tool call that creates `$OUTPUT_DIR/threat-model.sarif.json` |
| N | `Releasing lock + printing summary…` | always, LAST | the lock-release Bash call below |

**Substep 1 — pre-compute counts (mandatory Bash template, batched with the `[1/N]` STEP_START):**

```bash
PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60))) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [1/<N>] Pre-computing final counts (threats, mitigations, sections)…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
CRIT=$(grep -c '"risk": *"Critical"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
HIGH=$(grep -c '"risk": *"High"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
MED=$(grep -c '"risk": *"Medium"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
LOW=$(grep -c '"risk": *"Low"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
COMPS=$(ls "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | wc -l)
MITS=$(grep -c '"mitigation_title"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
echo "COUNTS: crit=$CRIT high=$HIGH med=$MED low=$LOW comps=$COMPS mits=$MITS"
```

Use the printed `COUNTS:` line to populate concrete numbers in the Management Summary, Section 8 headings (`### 8.1 Critical (<CRIT>)`, …), and the assessment summary footer. These counts are ground truth — do not recompute them by eye during composition.

**Substep 2 — composition warning (mandatory Bash template, batched with the `[2/N]` STEP_START):**

```bash
PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60))) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [2/<N>] Composing threat-model.md content (expect 1–3 min silence)…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
RECON_LINES=$(wc -l < "$OUTPUT_DIR/.recon-summary.md" 2>/dev/null || echo 0)
CTX_LINES=$(wc -l < "$OUTPUT_DIR/.threat-modeling-context.md" 2>/dev/null || echo 0)
echo "INPUT_SIZES: recon=$RECON_LINES ctx=$CTX_LINES"
```

**This substep runs in its own turn.** Do NOT batch the `[2/<N>]` STEP_START echo with the Write tool call that immediately follows — the whole point of this substep is to land the "expect 1–3 min silence" warning in the user's terminal *before* the slow Write turn begins. The cheap `wc -l` reads exist purely to satisfy the "never waste a turn on logging alone" rule; their values are informational only.

**Substep 3 — the actual Write:** the Write tool call carries the fully composed `threat-model.md` content as its `content:` argument. Batch it with a `[3/<N>] Writing threat-model.md…` STEP_START echo in the same turn. From the user's perspective, this is the "long" turn — nothing else visible happens between the substep 2 warning and this Write completing.

**`threat-model.md` section order** (substep 3):

- Header metadata table (with `meta.git.commit_sha`, `Mode`, `Baseline SHA`, `Current SHA` for incremental runs)
- Table of Contents (including Management Summary, Changelog, Critical Attack Chain, Section 9 Attack Walkthroughs, and Section 7b if requirements enabled)
- **Changelog** — placed immediately below the header, **always rendered** when `changelog[]` in `threat-model.yaml` is non-empty (append-only history, newest entry first). See "Changelog Section" below for the exact template.
- **Management Summary** — the executive block (no `Top Findings`, no `Recommended Priority Actions` sub-sections — see phase-group-threats.md for the enforced layout).
- **Critical Attack Chain** — **unnumbered** `## Critical Attack Chain` section, placed **immediately** after the Management Summary and **before** Section 1. This is the *overview* layer: the attack-chain Mermaid diagram (`graph LR`) + the "Key takeaway" sentence + the quick-reference table linking back to Section 8.1 for full detail. The anchor is `#critical-attack-chain`. Omit the section entirely when there are 0 or 1 Critical findings (a single Critical cannot form a chain).
- **Section 3 — `## 3. Security-Relevant Use Cases`** — **two-line stub** pointing to Section 9. This slot was formerly the home of attack sequence diagrams, which have been moved to Section 9 where they belong semantically (adjacent to the Threat Register). The stub exists only to preserve the `#3-security-relevant-use-cases` anchor. Render verbatim — see `phase-group-architecture.md` → "Section 3 stub template" for the exact text.
- Sections 4–7 (Assets, Attack Surface, Trust Boundaries, Security Controls)
- **Section 7b — Requirements Compliance** (only when `CHECK_REQUIREMENTS=true`)
- Section 8 — Threat Register (8.1–8.4 by severity)
- **Section 9 — Attack Walkthroughs** (real content, renamed from the previous "Critical Findings" slot). Rendered by Phase 4 of the orchestrator (see `phase-group-architecture.md` → "Phase 4: Attack Walkthroughs"): one `sequenceDiagram` per Critical finding (max 5), each tied to its `T-NNN` anchor, ordered to match the nodes of the `## Critical Attack Chain` diagram above. Each diagram uses `alt`/`else` with fixed semantics: `alt` = current vulnerable flow tagged `%% attack-path`, `else` = post-mitigation flow labelled `After M-NNN`. Empty-state behaviour: when `CRIT_COUNT == 0`, Section 9 contains the 2-line fallback stub from `phase-group-architecture.md`; when `CRIT_COUNT >= 1`, it contains real walkthroughs. The anchor is `#9-attack-walkthroughs` — the old `#9-critical-findings` anchor is **broken** by the rename.
- Section 10 — Mitigation Register (unchanged)
- Section 11 — Out of Scope (unchanged)

**Why Section 3 is a stub and not renumbered out of existence:** Deleting Section 3 would leave a numbering gap (1, 2, 4, 5, …) which is visually ugly; renumbering Sections 4–11 down by one would break every `#4-assets`, `#5-attack-surface`, `#6-trust-boundaries`, `#7-security-controls`, `#8-threat-register`, `#10-mitigation-register`, and `#11-out-of-scope` anchor, plus `#8-1-critical` and friends — a dozen or more anchor breaks across the plugin's own docs, cached links, and external tooling. The stub approach breaks exactly one anchor (`#9-critical-findings` → `#9-attack-walkthroughs`, which is the intentional rename) and leaves every other anchor intact.

**Numbered-slot reuse (Section 9):** Section 9 is the only slot whose meaning changed. It used to be "Critical Findings" (a 2-line redirect stub), it is now "Attack Walkthroughs" (real content: sequence diagrams). The content and the anchor both change; the section number does not.

### Incremental Update Rules

When `WRITE_MODE=incremental`:

1. **Read the existing baseline** — before any composition, parse `$OUTPUT_DIR/threat-model.yaml` to extract: `meta.git.commit_sha` (= `BASELINE_SHA`), `components[]`, `threats[]`, `mitigations[]`, `changelog[]`. These are the carry-forward sources.
2. **Compute the delta** — from the dirty-set identified in Phase 9 (re-analyzed components) vs. the baseline's components/threats, derive:
   - `added_threats` — new T-IDs not in baseline `threats[]`
   - `changed_threats` — T-IDs present in both but with different `severity`, `cwe`, `evidence`, or `mitigations`
   - `resolved_threats` — baseline T-IDs whose owning component was re-analyzed but no longer produced them (or whose component was removed entirely)
   - `added_components`, `removed_components`, `reanalyzed_components`, `carried_forward_components`
   - `added_entry_points`, `changed_entry_points` (from `attack_surface[]` delta, if the block is populated)
3. **Compose the new changelog entry** in memory:
   ```yaml
   - version: <last_version + 1>
     date: <ISO now>
     mode: incremental
     baseline_sha: <BASELINE_SHA>
     current_sha: <CURRENT_SHA>
     changed_files: <count>
     reanalyzed_components: [<id>, ...]
     carried_forward_components: [<id>, ...]
     added:
       threats: [<T-ID>, ...]
       components: [<id>, ...]
       attack_surface: [<E-ID>, ...]
     changed:
       threats: [<T-ID>, ...]     # with note on what changed
     resolved:
       threats: [<T-ID>, ...]
       reason_by_id:
         <T-ID>: "<reason — component removed / no longer observed / ...>"
   ```
4. **Prepend** this entry to `changelog[]` in the yaml (newest first), then write yaml.
5. **Render the Changelog section** in `threat-model.md` (see template below).
6. **Update `.appsec-cache/baseline.json`** — refresh `recon_fingerprint`, `id_counters`, `stride_files[<id>].sha256` for all components touched in this run.
7. T-IDs of carry-forward components **must remain stable** — do not renumber.

When `WRITE_MODE=full`:

1. **Preserve the existing `changelog[]`** if `$OUTPUT_DIR/threat-model.yaml` already exists — read its current `changelog[]`, then **prepend** a new entry:
   ```yaml
   - version: <last_version + 1>
     date: <ISO now>
     mode: full
     baseline_sha: null
     current_sha: <CURRENT_SHA>
     note: "full rebuild — all sections regenerated"
   ```
2. If no existing yaml exists (first run ever), start `changelog[]` with a single `version: 1, mode: full, note: "initial assessment"` entry.
3. Rewrite the rest of the yaml normally (components, threats, assets, etc.).
4. Render the Changelog section in `threat-model.md` even for full runs — a first-run full assessment produces a changelog with one `v1 — initial assessment` entry.

When `WRITE_MODE=delta-preview` (dry-run incremental):

1. **Do not touch** `threat-model.md`, `threat-model.yaml`, `.appsec-cache/baseline.json`, `.stride-*.json`, or the changelog.
2. **Compute the delta** exactly as for `incremental` above (in memory only).
3. **Write a single file:** `$OUTPUT_DIR/threat-model.delta.md` containing:
   ```markdown
   # Threat Model — Delta Preview (dry-run)

   **Generated:** <ISO now>
   **Baseline:** <BASELINE_SHA> · <baseline date from changelog>
   **Current:**  <CURRENT_SHA> · <current date>
   **Changed files:** <count>

   > ⚠ This is a dry-run preview. No changes were written to threat-model.md, threat-model.yaml, or the changelog. Re-run without --dry-run to apply this delta to the threat model.

   ## Architecture
   <bullet list of added/removed components, new edges>

   ## Attack Surface (+<added> / -<removed> / ~<changed>)
   <bullet list>

   ## Threats (+<added> / -<removed> / ~<changed>)
   + **T-NNN** [Severity, CWE-NNN] <title>  `<component>`
   ~ **T-NNN** severity changed: <old> → <new>  (<reason>)
   - **T-NNN** resolved — <reason>

   ## Re-analyzed Components
   <list>

   ## Carried Forward
   <list>

   ---
   See <threat-model.md> for the current (unchanged) threat model.
   ```
4. Release the lock and exit without invoking the QA reviewer.

### Changelog Section Template (rendered into `threat-model.md`)

The Changelog section is inserted immediately below the header metadata table and before the Management Summary. It renders `changelog[]` in descending order (newest first). Template:

```markdown
## Changelog

_Append-only history of assessment runs. Most recent first._

### v<N> — <date> (<mode>, baseline `<short_sha>` → `<short_sha>`)

- **Added:** <n> threats (<list T-IDs>), <n> components (<list>), <n> entry points (<list E-IDs>)
- **Changed:** <n> threats (<T-ID: "reason", ...>)
- **Resolved:** <n> threats (<T-ID: "reason", ...>)
- **Re-analyzed:** <component list>
- **Carried forward:** <component list>
- **Changed files:** <count>

### v<N-1> — <date> (<mode>, ...)

...

### v1 — <date> (full — initial assessment)

- First assessment — <n> threats identified across <n> components.
```

**Rendering rules:**
- A `mode: full` entry shows only `version`, `date`, and `note` — no added/changed/resolved breakdown (everything is "new" in a full rebuild).
- A `mode: incremental` entry shows the full breakdown.
- Empty lists are omitted (don't print `Added: 0 threats`).
- T-IDs and E-IDs are rendered as clickable internal anchors to their entries in Section 5/8.
- The section is `## Changelog` (level-2), matching the other top-level sections.

### Baseline Cache Update (incremental + full modes only, NOT delta-preview)

Before the lock-release substep, refresh `$OUTPUT_DIR/.appsec-cache/baseline.json` via the `baseline_state.py` helper. Skip entirely when `WRITE_MODE=delta-preview` or `WRITE_MODE=none`:

```bash
if [ "$WRITE_MODE" = "incremental" ] || [ "$WRITE_MODE" = "full" ]; then
  mkdir -p "$OUTPUT_DIR/.appsec-cache"
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" update \
    --output-dir "$OUTPUT_DIR" \
    --repo-root "$REPO_ROOT" \
    --mode "$WRITE_MODE"
fi
```

The helper reads the freshly-written `threat-model.yaml`, computes manifest/Dockerfile/IaC hashes against `$REPO_ROOT`, increments `id_counters.next_threat_id` past the highest T-ID in the yaml, and writes sha256 for every `.stride-<id>.json`. If the helper is missing (pre-M2.6 plugin), log a warning and continue — the yaml alone is sufficient baseline for the next run, just without the Phase 2 recon-skip optimization.

### Lock Release & Duration (substep `N`)

Batch the final STEP_START echo, the lock-release, and the duration computation in one Bash call:

```bash
PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60))) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [<N>/<N>] Releasing lock + printing summary…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
rm -f "$OUTPUT_DIR/.appsec-lock"
rm -f "$OUTPUT_DIR/.appsec-checkpoint"
END_EPOCH=$(date +%s)
ELAPSED=$(( END_EPOCH - START_EPOCH ))
DURATION=$(printf "%d min %02d s" $(( ELAPSED / 60 )) $(( ELAPSED % 60 )))
```

### Assessment Log Entry

**⚠ MANDATORY — always log ASSESSMENT_END, even if earlier phases failed:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  ASSESSMENT_END   Assessment completed in ${DURATION}  threats=<N> mitigations=<N> files=[threat-model.md<, threat-model.yaml><, threat-model.sarif.json>] (CET: $(TZ=Europe/Berlin date '+%Y-%m-%d %H:%M:%S %Z'))" >> "$OUTPUT_DIR/.agent-run.log"
```
Replace `<N>` with actual counts. Include only files actually written in the `files=[...]` list.

### Print Final Summary

```
══════════════════════════════════════════════════════════════
  Assessment Summary
══════════════════════════════════════════════════════════════

  Duration       : <DURATION>
  Started (CET)  : <CET start time>
  Finished (CET) : <CET end time>
  Mode           : <full | incremental | incremental (dry-preview) | dry-run>
  Depth          : <quick | standard | thorough>
  Flags          : WITH_SCA=<true|false>  CHECK_REQUIREMENTS=<true|false>
                   WRITE_YAML=<true|false>  WRITE_SARIF=<true|false>
  Baseline SHA   : <BASELINE_SHA | n/a>           ← only for incremental modes
  Current SHA    : <CURRENT_SHA>
  Changelog      : v<N> added to threat-model.md  ← only when WRITE_MODE in {full, incremental}
                   (delta-preview: no changelog entry written)

  Context Sources:
    External context : <provided|not configured|disabled|unavailable>
    Business context : <found|not found>
    Requirements     : <remote|cached|fallback|disabled|unavailable>
    Known threats    : <n entries (<n> open, <n> accepted)|not found>
    Repo files read  : <n from context-resolver>

  Pipeline (agent · model · maxTurns · status):
    context-resolver : <model> · <maxTurns> turns · .threat-modeling-context.md written
    recon-scanner    : <model> · <maxTurns> turns · .recon-summary.md written (<n> lines)
    dep-scanner      : <model> · <maxTurns> turns · .dep-scan.json (<n> vulnerable deps)
                       ← if WITH_SCA=false: "skipped (SCA not requested)"
                       ← if cache hit: "cache hit (age: <N>m)"
    stride-analyzer  : <model> · <maxTurns> turns × <n> components — <n> threats total
                       Components: <component-id-1>, <component-id-2>, …
    qa-reviewer      : <model> · <maxTurns> turns (runs next, skill-level)

  Results:
    Complexity tier  : <Simple|Moderate|Complex>
    Diagrams         : <n> (C4 + use case + tech arch)
    Requirements     : <n> checked (<n> PASS, <n> FAIL) | not checked
    Threats          : <n> (Critical: <n>, High: <n>, Medium: <n>, Low: <n>)
    Mitigations      : <n>
    Critical findings: <n>

  Incremental Summary (only when Mode = incremental):
    Changed files        : <count>
    Re-analyzed          : <n> components (<list>)
    Carried forward      : <n> components (<list>)
    Delta                : +<n> threats, ~<n> threats, -<n> threats
    Changelog entry      : v<N> added to threat-model.md (<date>)

  Paths:
    Repository   : <REPO_ROOT>
    Output       : <OUTPUT_DIR>

  Files Written:
    <OUTPUT_DIR>/threat-model.md          (<n> lines)
    <OUTPUT_DIR>/threat-model.yaml        (<n> lines)  ← always, unless --no-yaml
    <OUTPUT_DIR>/.appsec-cache/baseline.json           ← always (WRITE_MODE ∈ {full, incremental})
    <OUTPUT_DIR>/threat-model.sarif.json  (<n> bytes)  ← only if WRITE_SARIF
    <OUTPUT_DIR>/threat-model.delta.md                 ← ONLY for WRITE_MODE=delta-preview

  Intermediate Files:
    <OUTPUT_DIR>/.threat-modeling-context.md  (<n> chars)
    <OUTPUT_DIR>/.recon-summary.md            (<n> chars)
    <OUTPUT_DIR>/.dep-scan.json               (<n> chars)  ← only if WITH_SCA
    <OUTPUT_DIR>/.stride-*.json               <n> files

  Tokens & Cost:
    Aggregated token/cost data is written automatically to
    <OUTPUT_DIR>/.hook-events.log (ASSESSMENT_SUMMARY / ASSESSMENT_TOKENS)
    and mirrored to <OUTPUT_DIR>/.agent-run.log after the session ends.
    Per-agent breakdowns are in the SESSION_STOP entries.

══════════════════════════════════════════════════════════════
```

**Note:** The QA review runs separately at the skill level after this agent completes.
