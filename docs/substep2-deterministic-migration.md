# Phase-11 Substep 2 Deterministic Migration — Sidecar Architecture

**Status:** Design, partial implementation (script exists at `scripts/build_threat_model_yaml.py`, sidecars not yet wired into phase agents)
**Erstellt:** 2026-05-24
**Trigger:** 2026-05-24 juice-shop run hit MAX_TURNS @ turn 150 mid-Phase-11 Substep 2 → bootstrap-stub yaml → forced resume. Same root cause as 2026-05-03 API streaming-stall (`stop_reason: None, output_tokens: 1` on the largest Stage-1 tool_use). The LLM-driven yaml composition burns 15-20 turns at the end of the pipeline where budget is most constrained.

**Ziel:** Eliminate LLM yaml composition in Phase 11 Substep 2 by replacing it with a Python aggregator. Preserve LLM judgement work via structured sidecars written earlier in the pipeline (Phase 3/5/6/7/8/10/10b) where budget is high. Quality parity ≥ 95% measured by acceptance gates below.

**Non-Goals:** Touching architecture-diagrams (Phase 3 mermaid), attack-walkthroughs (Phase 4), Stage 2 fragments, Phase 9 STRIDE analyzers. These remain LLM-driven per existing [migration_substep2_deterministic memory](../.claude/projects/-home-mrohr-appsec-advisor/memory/migration_substep2_deterministic.md) anti-regression list.

---

## 1. Architecture: Python Spine + LLM Sidecars

```
                  ┌─────────────────────────────────────────┐
                  │  Phases 3, 5, 6, 7, 8, 10, 10b (LLM)    │
                  │  Budget: 4-15 turns each, plenty        │
                  │                                         │
                  │  • Does judgement work (unchanged)      │
                  │  • Persists output to .X.json sidecar   │
                  │    (1 extra Bash call per phase)        │
                  └─────────────────┬───────────────────────┘
                                    │ sidecars on disk
                                    ▼
                  ┌─────────────────────────────────────────┐
                  │  Phase 11 Substep 2 (Python)            │
                  │  Budget: 1 turn (single Bash call)      │
                  │                                         │
                  │  python3 scripts/build_threat_model_    │
                  │          yaml.py $OUTPUT_DIR            │
                  │                                         │
                  │  • Reads intermediates + sidecars       │
                  │  • Three-stage merge per field          │
                  │  • Schema-validates BEFORE write        │
                  │  • Atomic tmp+fsync+rename              │
                  └─────────────────────────────────────────┘
```

### Three-stage merge per field

```python
def build_field(intermediates, sidecar):
    # Stage 1: deterministic baseline from intermediates (may be empty)
    baseline = derive_from_intermediates(intermediates)

    if not sidecar:
        return baseline  # works for fallback installs

    # Stage 2: apply LLM-provided splits/curations (refines baseline)
    if "splits" in sidecar or "curations" in sidecar:
        baseline = apply_modifications(baseline, sidecar)

    # Stage 3: apply LLM-provided additions (extends baseline)
    if "additions" in sidecar:
        for item in sidecar["additions"]:
            validate_addition_constraints(item, baseline)
            baseline.append(item)

    return baseline
```

### Why hybrid beats pure Python AND pure LLM

| | Pure Python | Pure LLM (today) | Hybrid (this design) |
|---|---|---|---|
| Substep 2 turn cost | 1 | 15-20 | 1 (Python in Substep 2) + 4-8 (sidecar writes across phases) |
| Position of LLM work | none | end of pipeline (budget critical) | early phases (budget healthy) |
| Schema-conformance | hard pre-write gate | post-hoc, can fail late | hard pre-write gate |
| Reproducibility | byte-identical | LLM drift | byte-identical for given intermediates+sidecars |
| Quality vs today | 70-80% (heuristics miss nuance) | 100% baseline | 95-100% (LLM keeps judgement) |
| Failure mode | clean exit with sidecar-missing message | MAX_TURNS bootstrap-stub | sidecar-write fails cleanly in source phase |
| API streaming-stall risk | none | high (largest tool_use of Stage 1) | none |

---

## 2. Per-field sidecar specs

Each sidecar lives at `$OUTPUT_DIR/<filename>` and is written by exactly one phase. Schema-validated by `validate_intermediate.py` BEFORE the PHASE_END marker (write-then-validate-then-mark, fail-fast).

### 2.1 `.components.json` (Phase 3 — Architecture Modeling)

```json
{
  "schema_version": 1,
  "components": [
    {
      "id": "express-backend",
      "name": "Express Backend",
      "description": "Node.js/Express REST API handling auth + business logic",
      "paths": ["routes/**/*.ts", "server.ts", "lib/**/*.ts"],
      "tier": "application",
      "complexity": "complex",
      "framework": "express"
    }
  ],
  "additions": []
}
```

**Constraints:**
- `id` must match `^[a-z][a-z0-9-]+$` (used as component_id elsewhere)
- `tier` must be one of `client` / `application` / `data` (renders 3-tier heatmap)
- `paths` is source-of-truth for Phase 9 dirty-set mapping — must reflect actual directory layout
- `complexity` enum: `simple` / `moderate` / `complex` (used to size STRIDE-analyzer turn budget)
- ≥ 1 component with `tier: data` required if app uses a database (don't subsume into application)
- `additions` empty for first-time runs; incremental runs may carry components forward from baseline

**Validation:** `schemas/fragments/components.schema.json` (NEW). Hard fail if `id` collides with existing components in baseline yaml.

### 2.2 `.assets.json` (Phase 5 — Asset Identification, PoC pilot)

```json
{
  "schema_version": 1,
  "assets": [
    {
      "id": "A-001",
      "name": "User credentials",
      "classification": "Restricted",
      "description": "Email + MD5-hashed passwords in Users table",
      "linked_threats": ["T-001", "T-008"],
      "evidence_flags": []
    }
  ],
  "additions": []
}
```

**Constraints:**
- `id` matches `^A-\d{3,}$` — assigned from `.appsec-cache/baseline.json.id_counters.next_asset_id` (NEW counter)
- `classification` enum: `Public` / `Internal` / `Confidential` / `Restricted`
- `linked_threats[]` must reference existing T-IDs (cross-ref validated at aggregator)
- `additions` allows post-merge assets emerging from cross-phase synthesis (e.g., "Build artifacts" — important asset without specific threat)

**Validation:** `schemas/fragments/assets.schema.json` (NEW).

### 2.3 `.attack-surface-overrides.json` (Phase 6 — Attack Surface Mapping)

```json
{
  "schema_version": 1,
  "curations": {
    "include_route_ids": ["r-042", "r-088", "r-103"],
    "exclude_route_ids": [],
    "rationale_by_id": {
      "r-042": "Unauthenticated user registration — primary attack vector"
    }
  },
  "additions": [
    {
      "entry_point": "Admin SSH access",
      "protocol": "SSH",
      "auth_required": true,
      "notes": "Out-of-band management surface not in route-inventory"
    }
  ]
}
```

**Constraints:**
- `curations.include_route_ids[]` filters the 112 baseline routes from `.route-inventory.json` down to ~20-30 relevant ones
- If `curations` absent, aggregator emits ALL routes (lower quality but non-breaking)
- `additions` for surfaces not in route-inventory (SSH, file watchers, scheduled jobs)
- `entry_point` required, `protocol` required (HTTP/HTTPS/gRPC/SSH/SMTP/MQTT/...)

**Validation:** `schemas/fragments/attack-surface-overrides.schema.json` (NEW).

### 2.4 `.trust-boundaries.json` (Phase 7 — Trust Boundary Analysis)

```json
{
  "schema_version": 1,
  "trust_boundaries": [
    {
      "id": "tb-1",
      "name": "Internet → Express API",
      "from": "external",
      "to": "express-backend",
      "controls": ["JWT validation", "rate limiting"],
      "description": "Public HTTPS endpoint, all client requests cross here"
    }
  ],
  "additions": []
}
```

**Constraints:**
- `id` matches `^tb-\d+$`
- `name` required (rendered in §6 Trust Boundary diagrams)
- `from`/`to` should reference existing component IDs OR the literal `external` (network ingress)
- Aggregator cross-refs to components — warns if `from`/`to` is non-existent component ID

**Validation:** `schemas/fragments/trust-boundaries.schema.json` (NEW).

### 2.5 `.security-controls.json` (Phase 8 — Security Controls Catalog)

```json
{
  "schema_version": 1,
  "security_controls": [
    {
      "category": "Authentication",
      "control": "JWT signature validation",
      "status": "deficient",
      "evidence": "lib/insecurity.ts:57 uses jws.verify (alg confusion)",
      "domain": "application",
      "rule_id": "ARCH-AUTH-001"
    }
  ],
  "additions": []
}
```

**Constraints:**
- `status` enum: `implemented` / `partial` / `missing` / `deficient`
- `domain` enum: `client` / `application` / `data` / `infrastructure`
- `rule_id` optional but RECOMMENDED — links to `.architecture-coverage.json[rules_evaluated][].rule_id` for traceability
- Aggregator joins this with `.architecture-coverage.json[control_assessments]` — sidecar wins on conflict (LLM has more context)

**Validation:** `schemas/fragments/security-controls.schema.json` (NEW).

### 2.6 `.mitigation-overrides.json` (Phase 10b — Triage Validation)

```json
{
  "schema_version": 1,
  "splits": [
    {
      "source_mid": "M-001",
      "into": [
        {
          "id_suffix": "a",
          "title": "Rotate JWT private key",
          "threat_ids": ["T-001"],
          "remediation": {"effort": "Medium", "steps": ["Remove hardcoded RSA key", "Generate new 2048-bit pair"]}
        },
        {
          "id_suffix": "b",
          "title": "Migrate JWT secrets to env-vars",
          "threat_ids": ["T-001", "T-011"],
          "remediation": {"effort": "Low", "steps": ["Update config loader", "Rotate cookie secret"]}
        }
      ]
    }
  ],
  "additions": [
    {
      "id": "M-020",
      "title": "Establish dependency-update SLA",
      "threat_ids": ["T-009", "T-010", "T-011"],
      "kind": "process",
      "priority": "P2",
      "severity": "Medium",
      "remediation": {
        "effort": "Medium",
        "steps": ["Define monthly review cadence", "Wire Dependabot/Renovate"]
      }
    }
  ]
}
```

**Constraints — splits:**
- `source_mid` MUST exist in Python baseline (cross-ref validated)
- `id_suffix` MUST be unique within the `into[]` array; aggregator assigns final ID = `source_mid + id_suffix` (e.g. `M-001` + `a` = `M-001a`)
- Each split MUST cover ≥ 1 threat from the original M-ID's threat_ids
- Union of split threat_ids MUST equal source M-ID threat_ids (no dropped threats)

**Constraints — additions:**
- `id` MUST come from `.appsec-cache/baseline.json.id_counters.next_mitigation_id` sequence (Phase 10b reads counter, Python aggregator validates)
- `threat_ids[]` MUST have ≥ 1 existing T-ID (evidence-grounded — no hallucinated mitigations)
- `kind` enum: `fix` / `review` / `process` / `architectural`
- `priority` enum: `P1` / `P2` / `P3` / `P4`
- `severity` enum: `Critical` / `High` / `Medium` / `Low` / `Informational`
- Process mitigations (`kind: process`) SHOULD have `threat_ids[]` ≥ 2 (process gaps are inherently cross-cutting)

**Validation:** `schemas/fragments/mitigation-overrides.schema.json` (NEW).

### 2.7 `.meta-findings.json` (Phase 10 — after Synthesis)

```json
{
  "schema_version": 1,
  "meta_findings": [
    {
      "id": "MF-001",
      "title": "Insufficient Secret Management",
      "category": "Insufficient Secret Management",
      "summary": "2 findings trace to secrets, keys, or tokens in source code. Architectural concern: no centralized secrets store; rotation requires code changes.",
      "derived_from": ["T-001", "T-011"],
      "severity": "High",
      "recommended_mitigation_id": "M-001b"
    }
  ]
}
```

**Constraints:**
- `id` matches `^MF-\d{3,}$` — separate counter from M-/T-/A-/HYP-IDs
- `category` enum: `Insufficient Patch Management` / `Insufficient Secret Management` / `Insufficient Configuration Hardening` (extend cautiously — each is a stable architectural concept)
- `derived_from[]` MUST have ≥ 2 T-IDs (meta-finding by definition spans multiple threats)
- `recommended_mitigation_id` optional but RECOMMENDED — must reference an existing M-ID

**Validation:** schema already exists in `threat-model.output.schema.yaml` meta_findings block; sidecar wraps with `additionalProperties: false` outer.

### 2.8 `.tier-root-causes.json` (Phase 10b — Triage Validation)

```json
{
  "schema_version": 1,
  "tier_root_causes": {
    "edge": ["missing CSP allows JS injection (frontend/src/about)"],
    "server": [
      "hardcoded crypto secrets in source",
      "missing input neutralization on raw SQL paths",
      "no auth middleware on management endpoints"
    ],
    "data": ["SQLite with no row-level encryption for PII"]
  }
}
```

**Constraints:**
- Three keys: `edge` (= client tier), `server` (= application tier), `data`
- Each value: list of 1-5 strings, each ≤ 80 characters
- Skip a tier entirely (omit the key) if it has no threats — DO NOT emit empty arrays
- Bullets MUST be plain-language root-cause class statements (NOT file:line citations — those belong in threats[])

**Validation:** `schemas/fragments/tier-root-causes.schema.json` (NEW).

---

## 3. ID Counter Management

Five ID counters live in `.appsec-cache/baseline.json[id_counters]`:

```json
{
  "id_counters": {
    "next_threat_id":     "T-035",  // managed by merge_threats.py (existing)
    "next_mitigation_id": "M-020",  // managed by Python aggregator + sidecar
    "next_asset_id":      "A-011",  // NEW
    "next_hyp_id":        "HYP-004", // NEW
    "next_meta_finding_id": "MF-002" // NEW
  }
}
```

**Counter assignment protocol:**
- LLM in source phase calls `python3 scripts/reserve_ids.py --type mitigation --count 3` to reserve N consecutive IDs, gets back `["M-020", "M-021", "M-022"]`
- LLM uses those IDs in the sidecar
- `reserve_ids.py` increments the counter atomically in `.appsec-cache/baseline.json`
- Python aggregator validates: every sidecar-claimed ID must be ≤ current counter value AND not already used in baseline

This prevents:
- ID collisions across runs (incremental baseline + new run)
- LLM hallucinating IDs that don't follow counter sequence
- Race conditions if Phase 5 and Phase 7 both reserve IDs

**Why a script (not just LLM-managed)**: counter assignment is single-source-of-truth invariant in incremental mode. Today the LLM occasionally re-uses M-001 for two different mitigations across runs (manually verified 2026-04-25 run audit). Hard counter prevents this class of drift.

---

## 4. Cross-Reference Validation

The Python aggregator runs a validation pass AFTER merging sidecars but BEFORE schema validation:

| Cross-ref | Source | Target | Failure mode |
|---|---|---|---|
| `threats[].component` | each threat | `components[].id` | warn (advisory) — see `validate_intermediate.py` existing advisory pattern |
| `mitigations[].threat_ids[]` | each mitigation | `threats[].id` | hard fail — orphan mitigation |
| `assets[].linked_threats[]` | each asset | `threats[].id` | warn — asset may legitimately predate threat-discovery |
| `meta_findings[].derived_from[]` | each MF | `threats[].id` | hard fail (≥2 T-IDs required) |
| `meta_findings[].recommended_mitigation_id` | each MF | `mitigations[].id` | warn |
| `critical_findings[].threat_id` | each critical | `threats[].id` | hard fail |
| `critical_findings[].mitigation_id` | each critical | `mitigations[].id` | warn (mitigation may not exist for new high-severity findings) |
| `trust_boundaries[].from`/`to` | each TB | `components[].id` or `external` | warn |
| `mitigation_overrides.splits[].source_mid` | each split | Python baseline `mitigations[].id` | hard fail — split target missing |

**Hard fail = aggregator exits 4 with structured error**:
```
FATAL: cross-reference validation failed
  mitigations[3] (M-008): threat_ids[2] = "T-099" — no such threat
  meta_findings[0] (MF-001): derived_from has 1 entry, schema requires ≥2

Remediation: re-run the source phase or accept the addition cannot be
applied. Run with --skip-additions to emit yaml without invalid sidecar
data (degrades quality but unblocks shipping).
```

---

## 5. Sidecar Lifecycle

| Stage | Action | Failure mode |
|---|---|---|
| **Write** (in source phase) | LLM runs `python3 reserve_ids.py` + writes `.X.json` via Bash heredoc | If `reserve_ids.py` fails: log error, continue with monotonic-fallback IDs (M-999+); aggregator will flag |
| **Validate** (immediately after write, same Bash call) | `python3 validate_fragment.py .X.json` | If invalid: re-write attempt (1 retry), then log WARN and continue — aggregator will catch |
| **Mark** (PHASE_END) | Standard phase-end checkpoint includes sidecar path in `ASSESSMENT_FILES` log | n/a |
| **Read** (Phase 11 by aggregator) | `_load_json(.X.json)` — None if missing | None triggers fallback chain (prior yaml or empty) |
| **Cleanup** (runtime_cleanup.py post-run) | Sidecars are NOT cleaned — they're audit artifacts like `.threats-merged.json` | n/a |
| **Carry-forward** (incremental run) | If new run skips a phase due to incremental gating, prior sidecar carried forward via baseline_state.py | Validates schema_version compatibility |

**Atomicity:** Every sidecar write uses `_atomic_io.atomic_write_json` (tmp + fsync + rename). A mid-write crash leaves either the OLD sidecar (from prior run) or NO sidecar (clean) — never a torn file.

**Schema versioning:** Every sidecar carries `schema_version: 1`. Aggregator checks at load — if mismatch: error with explicit upgrade path. Add new fields via `additionalProperties: true` for backward compatibility; bump version only on breaking changes.

---

## 6. Mode Interactions

### `--full` (default for first-time runs)

- All sidecars MUST be written fresh by their phases (no carry-forward source)
- If any sidecar missing AND no prior yaml on disk: aggregator exit 4 with phase-attribution message ("Phase 5 did not write .assets.json")
- If any sidecar missing AND prior yaml exists: aggregator falls back to prior yaml field (degraded freshness, but non-blocking)

### `--incremental` (re-run with baseline)

- Components/assets/trust_boundaries/security_controls: sidecars carried forward from baseline if phase didn't re-run (dirty-set mapping in Phase 9 determines which components re-run)
- Mitigations: baseline mitigations preserved, new threats may add new M-IDs via sidecar additions
- Cross-refs validated against full set (baseline + new)
- `meta.recommend_full_rerun` set by `plugin_meta.py check-compat` — separate from sidecar mechanism

### `--resume` (continue from checkpoint)

- Sidecars from completed phases preserved across resume
- Phase that was running at cut-off: sidecar may be missing OR partial — aggregator treats as missing
- After resume completes the cut-off phase, sidecar is written normally

### `--rebuild` (wipe and restart)

- ALL sidecars wiped by `runtime_cleanup.py --stage rebuild` (need to add `.X.json` patterns to whitelist)
- Fresh run produces fresh sidecars
- No incremental carry-forward (intentional)

---

## 7. Failure Modes and Recovery

| Failure | Detection | Recovery | User-visible |
|---|---|---|---|
| Sidecar missing AND no prior yaml | aggregator exit 4 | Re-run with `--full` to re-do skipped phase | Banner: "Phase X did not write .Y.json sidecar — re-run with --full" |
| Sidecar malformed JSON | `_load_json` exit 1 | Phase agent re-runs sidecar write (1 retry built in) | If retry fails: aggregator exits, run blocks |
| Sidecar schema-invalid (validate_fragment failure) | aggregator exit 5 | Same as malformed JSON | Banner: "Sidecar .Y.json failed schema — Phase X must regenerate" |
| Cross-ref validation fail (hard) | aggregator exit 4 with rule | Investigate source — usually phase ordering issue (sidecar written before its dependencies) | Detailed message with the orphan ID + remediation suggestion |
| Cross-ref validation fail (soft/advisory) | aggregator continues with WARN | Logged, but yaml written | Yellow banner: "ADVISORY: N cross-ref warnings — see .agent-run.log" |
| ID counter race | `reserve_ids.py` uses atomic file lock; if lock contention >5s, exit 1 | Phase agent retries (1 attempt) | Same UX as malformed sidecar |
| Aggregator itself crashes | Exit 1 unhandled exception | Skill-level: emit STAGE1_CUTOFF banner (already exists), preserve all intermediates + sidecars for resume | Existing red banner |
| Schema validation fail | aggregator exit 5 | Most likely a sidecar issue from prior step. If sidecars all clean: aggregator code bug (file issue) | Detailed schema violations printed |
| Partial sidecar (e.g. Phase 5 wrote 8 of 10 assets, then died) | Phase 5 incomplete → no PHASE_END marker | Resume path re-runs Phase 5, overwrites partial sidecar | Standard resume flow |
| Prior yaml is bootstrap-stub from prior failed run | `_load_yaml` detects `meta._bootstrap=true`, treats as no prior yaml | Same as no prior yaml | Aggregator exit 4 with phase-attribution if sidecars also missing |

---

## 8. Migration Sequence (8 atomic commits)

Each commit is independently revertable. Reference-run gate (juice-shop comparison) between commits 3 and 4.

| # | Commit | Files touched | Verification |
|---|---|---|---|
| 1 | `feat(scripts): build_threat_model_yaml.py` | `scripts/build_threat_model_yaml.py` | ✅ done (commit `7209ed2`) — script validates against juice-shop intermediates with prior-yaml fallback |
| 2 | `feat(scripts): reserve_ids.py — atomic ID counter assignment` | `scripts/reserve_ids.py` (NEW), `scripts/baseline_state.py` (add A-/MF-/HYP- counters) | Unit tests for atomicity (parallel processes) |
| 3 | `feat(schemas): sidecar JSON schemas` | `schemas/fragments/{components,assets,trust-boundaries,security-controls,attack-surface-overrides,mitigation-overrides,tier-root-causes}.schema.json`, `scripts/validate_fragment.py` (extend) | All schemas load + roundtrip-validate against juice-shop yaml extracted as sidecars |
| 4 | `feat(phase-5): write .assets.json sidecar` (PoC pilot) | `agents/phases/phase-group-architecture.md` Phase 5 section (~10 lines), `data/required-permissions.yaml` (add Write target) | Ref-run gate: §4 wordcount delta < 5%, all 10 assets preserved, schema validates |
| 5 | `feat(phase-3,7,8): write sidecars` (after PoC validation) | `phase-group-architecture.md` Phases 3, 7, 8 sections | Ref-run gate: §1-§7 wordcount delta < 5%, mermaid count identical, threat count identical |
| 6 | `feat(phase-6,10,10b): write override sidecars` | `phase-group-architecture.md` Phase 6, `phase-group-threats.md` Phase 10, `phase-group-finalization.md` Phase 10b | Ref-run gate: mitigation count delta ≤ 2, F-NNN gap-free |
| 7 | `feat(phase-11): replace Substep 2 LLM write with Python` | `agents/phases/phase-group-finalization.md` Substep 2 section (the actual yaml-write block) | Full juice-shop scan: VALID yaml, no MAX_TURNS in Phase 11, wall-time delta < 30s |
| 8 | `chore(builder): remove prior-yaml fallback` | `scripts/build_threat_model_yaml.py` `_carry_forward()` removed | Production-readiness gate — all 4 sidecars proven reliable for 5+ runs across 3+ repos |

**Migration is reversible at every step** — until commit 7, Substep 2 still uses the LLM path. The sidecars are written but ignored by the live pipeline; only the offline builder consumes them. Commit 7 is the cutover.

---

## 9. Acceptance Gates (Reference-Run, per migration_substep2_deterministic memory)

For each ref-run repo (juice-shop, VulnerableApp, ≥1 internal):

| Metric | Acceptance | Measurement |
|---|---|---|
| §1-§7 wordcount delta | < 5% | `diff <(rendered §1-§7) <(baseline §1-§7) | wc -l` |
| Mermaid block count | identical | `grep -c '^```mermaid' threat-model.md` |
| sequenceDiagram count | identical | `grep -c 'sequenceDiagram' threat-model.md` |
| threat count | identical | `python3 -c 'import yaml; print(len(yaml.safe_load(open("threat-model.yaml"))["threats"]))'` |
| mitigation count delta | ≤ 2 | Same with `["mitigations"]` |
| F-NNN sequence | gap-free | `qa_checks.py check_f_id_sequence` |
| SARIF result count | identical | `jq '.runs[0].results | length' threat-model.sarif.json` |
| Schema validation | VALID | `validate_intermediate.py threat_model_output` exit 0 |
| Phase 11 turn count | ≤ 3 | `agent-run.log` PHASE_END Phase 11 — was ~15-20 |
| No MAX_TURNS event | true | `grep -c MAX_TURNS .agent-run.log` = 0 |

**Failing any acceptance gate blocks the corresponding migration commit.** Quality regression is not a goal of this migration.

---

## 10. Anti-Regression Invariants (must hold throughout migration)

1. **No new failure mode for installs without sidecars.** The aggregator must fall back to prior yaml (commits 1-6) so existing installs keep working until they re-run with sidecar-emitting phases.

2. **Schema is single source of truth.** Every sidecar's structure is locked in `schemas/fragments/X.schema.json`. Agent prompts reference the schema, do not duplicate the structure inline (prevents drift).

3. **Cross-references are validated at the aggregator, not the sidecar.** A sidecar can validate its own internal shape but cannot validate against other sidecars (they may not exist yet at write time). Cross-ref validation lives in one place.

4. **ID counters are atomic.** `reserve_ids.py` MUST use file locking. Two phases never produce the same M-ID. Verified by `tests/test_reserve_ids_atomicity.py`.

5. **`.threats-merged.json` field names are the bridge contract.** `merge_threats.py` continues to emit `t_id`, `component_id`, `mitigation_title`. The aggregator handles renames. Do NOT rename in `merge_threats.py` — too many downstream consumers.

6. **Sidecars are append-only within a run.** Once Phase 5 writes `.assets.json`, no other phase modifies it. Phase 10b's `.tier-root-causes.json` does NOT edit `.assets.json`. Each sidecar has exactly one writer.

7. **The Python aggregator NEVER calls an LLM.** No subprocess to Claude, no fallback to "ask LLM to fill missing field". Determinism is non-negotiable.

8. **Renderer (`compose_threat_model.py`) is untouched.** It already consumes yaml deterministically. The migration only changes WHO writes the yaml; the rendering pipeline downstream is invariant.

---

## 11. Open Questions

1. **Should `meta_findings` synthesis be deterministic instead of sidecar-based?** Heuristic: group config-scan-findings by keyword (`secret`, `patch`, `config`) → emit MF-NNN if ≥2 findings per bucket. Pro: removes 1 sidecar. Contra: category enum requires natural-language judgement ("Insufficient Configuration Hardening" vs "Insufficient Secret Management" is sometimes ambiguous from raw findings). **Lean: keep sidecar, add Python heuristic as fallback when sidecar missing.**

2. **Should `.architecture-coverage.json[threat_hypotheses]` be carried into yaml directly, or via a sidecar?** Today it's raw; aggregator transforms via `arch_coverage_to_threats.py` bridge. Adding a `.threat-hypotheses-overrides.json` sidecar would let Phase 10 LLM override `confidence` / `proof_state` post-validation. **Lean: defer — current bridge works, add sidecar only if a real need surfaces.**

3. **Should the sidecar mechanism replace `pregenerate_fragments.py`?** Today fragments are generated from yaml. With sidecars + deterministic yaml builder, fragments could be generated directly from sidecars (skip the yaml round-trip). Pro: 1 less dependency. Contra: yaml is the canonical machine-readable export; bypassing it would split the canonical path. **Lean: NO — yaml remains canonical, fragments still derive from yaml.**

4. **Handling of M-RCA-2026-05 changelog `changed`/`resolved` for incremental runs.** Today the LLM diffs prior baseline vs new threats[] to populate `changelog[0].changed` and `changelog[0].resolved`. Deterministic version: `scripts/baseline_diff.py` (NEW?) compares baseline+new and emits the diff. Probably warrants its own commit between #6 and #7 in the migration sequence. **Action: add as commit 6.5 to migration table when implementing.**

5. **What's the upgrade path for existing baselines without sidecar data?** First incremental run after migration: prior yaml has assets/components/etc, no sidecars on disk. Aggregator falls back to prior yaml (extracts as if sidecars). No data loss. Next FULL run: sidecars get freshly written. **Verified safe by design.**

---

## 12. References

- Existing memory: [migration_substep2_deterministic.md](../.claude/projects/-home-mrohr-appsec-advisor/memory/migration_substep2_deterministic.md)
- Bug context: [bug_phase10b_triage_bash_burn.md](../.claude/projects/-home-mrohr-appsec-advisor/memory/bug_phase10b_triage_bash_burn.md)
- Builder script: [scripts/build_threat_model_yaml.py](../scripts/build_threat_model_yaml.py)
- Output schema: [schemas/threat-model.output.schema.yaml](../schemas/threat-model.output.schema.yaml)
- Per-phase docs (will be modified):
  - [agents/phases/phase-group-architecture.md](../agents/phases/phase-group-architecture.md) — Phases 3, 5, 6, 7, 8
  - [agents/phases/phase-group-threats.md](../agents/phases/phase-group-threats.md) — Phase 10
  - [agents/phases/phase-group-finalization.md](../agents/phases/phase-group-finalization.md) — Phase 10b, Substep 2 cutover
- Anti-regression list (NOT touched): architecture-diagrams Phase 3, attack-walkthroughs Phase 4, security-architecture Phase 7/8 thorough enrichment, Stage 2 fragments, Phase 9 STRIDE analyzers, compose_threat_model.py, annotate_architecture.py, annotate_sequences.py
