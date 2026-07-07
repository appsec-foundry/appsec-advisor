# Implementation Plan — Finding Consolidation & Mitigation Dedup (Variant 1)

Status: **IMPLEMENTED (branch `feat/finding-consolidation`)**. Repo: `appsec-advisor`.
Target run reference: juice-shop `docs/security/threat-model.yaml`.

## Implementation status

| Rule | Status | Files |
|---|---|---|
| A — Consolidation | ✅ | `data/consolidation-groups.yaml`, `schemas/consolidation-groups.schema.yaml`, `merge_threats.py` (`_load_consolidation_groups`, `_match_consolidation_group`, `_consolidate_by_group`, wired in `cmd_collect`) |
| B — Mitigation dedup | ✅ | `build_threat_model_yaml.py` (`dedupe_mitigation_controls`, called after `apply_mitigation_overrides`) |
| C1/C2 — Instance delta | ✅ | `build_threat_model_yaml.py` (`_instance_fingerprints`, changelog `instance_fingerprints`/`added.instances`/`resolved.instances`) |
| C4 — Renderer | ✅ (per-instance severity dots) | `compose_threat_model.py` (instances_card) |
| C3 — Affirmation-path reconciler | ⏸ deliberately deferred | see below |

**C3 deferred rationale:** The self-contained instance-fingerprint diff (C2) already
provides partial-progress visibility ("3 of 17 locations fixed") for ALL
run types (full + incremental), because it diffs against the
`instance_fingerprints` of the prior-run entry stored in the changelog —
independent of `delta_basis`. The additional instance-granular wiring in
`reconcile_incremental_threats` (analyst-affirmed single-fix acknowledgement) is a
niche path with no current test coverage; it would touch the fragile incremental
reconciler with no added value beyond C2. Documented as a follow-up.

## Verification (real juice-shop data, `merge_threats collect`)
77 raw → **46** findings. Survivors: jwt-verification (6→1), missing-route-auth
(17→1), unauth-websocket-channel (3→1), npm-install-scripts (2→1),
dependabot-ecosystems (3→1). IDOR (CWE-639): **21 kept separate** (no group).
Hardcoded-Key (798), localStorage (922), XSS (79×3): kept separate. The JWT survivor spans
3 files / Critical+High. Full test suite green (+ new tests in
test_merge_threats / test_build_threat_model_yaml / test_compose_threat_model_cov).

---

(Plan reference below — target state.)

## Guiding principle (finalized)

- **The separation criterion is the shared object/mechanism, NOT the fix.**
  - Consolidate when the locations are manifestations of *one* primitive/object
    (one JWT verifier, one route registry, one dependabot.yml, one WebSocket channel).
  - Keep separate when the same weakness class is applied to *different resources/
    objects/sinks/flows* (IDOR per resource, XSS per sink).
- **Finding ↔ mitigation is 1:n.** A consolidated finding may
  carry multiple mitigations (`mitigation_ids[]` is already a list; no schema change needed).
- **Default is `per_instance`** (safe-by-default: never silently merge). Consolidation only
  when a group is explicitly declared in the catalog.
- **No tracking regression:** consolidation introduces instance-level delta so that
  "12 of 17 fixed" stays visible (today those are 17 individually resolvable IDs).

## Scope classification for this run

| Group | Findings | Action |
|---|---|---|
| `jwt-verification` (CWE-347/287/345) | F-003, F-005, F-006, F-027, F-028, F-029 | consolidate → 1 finding, ≥2 mitigations |
| `missing-route-auth` (AUTHZ-008) | F-047…F-063 (17×) | consolidate → 1 finding |
| `dependabot-ecosystems` | F-069, F-070, F-071 | consolidate → 1 finding |
| `npm-install-scripts` (CWE-506) | F-067, F-068 | consolidate → 1 finding |
| `unauth-websocket-channel` | F-042, F-064, F-065 | consolidate → 1 finding |
| IDOR (CWE-639) | F-009…F-046 (21×) | **kept separate** (different resources) |
| XSS (CWE-79) | F-007, F-030, F-031 | **kept separate** (different sinks) — mitigation dedup only |
| Hardcoded Key (798), localStorage (922) | F-004, F-001 | **kept separate** (different object), cross-link |

Expected net: findings 72 → ~44; mitigations 61 → ~32. The F-027/F-028 duplicate
(both `lib/insecurity.ts:58`) cleanly disappears inside the JWT finding.

---

## Rule A — Generalized consolidation (`consolidation_group`)

### A1. Declarative group catalog — NEW `data/consolidation-groups.yaml`

This is where the security judgment "which locations are the same object" lives. Example:

```yaml
# First matching rule wins. No rule → per_instance (default).
groups:
  - id: jwt-verification
    title: "Insecure JWT Verification"
    match_any:
      - cwe: [CWE-347, CWE-287, CWE-345]
        title_pattern: '(?i)\b(jwt|algorithm|signature|verify|decode)\b'
    scope: cross-component          # JWT helper is shared infra
    split_by: [trust_zone]          # Exception: never merge across trust zones

  - id: missing-route-auth
    title: "Sensitive Routes Registered Without Authentication"
    match_any:
      - source_check_id: [AUTHZ-008]
    scope: per-component

  - id: dependabot-ecosystems
    title: "Dependabot Ecosystem Coverage Incomplete"
    match_any:
      - config_check_id: [DEP-DOCKER, DEP-ACTIONS, DEP-NPM]   # verify exact IDs from run
    scope: per-component

  - id: npm-install-scripts
    title: "Untrusted npm Install/Postinstall Scripts"
    match_any:
      - cwe: [CWE-506]
        file_glob: ['**/package.json', '**/Dockerfile*']
    scope: per-component

  - id: unauth-websocket-channel
    title: "Unauthenticated WebSocket Channel"
    match_any:
      - file_glob: ['**/registerWebsocketEvents.*']
        cwe: [CWE-306, CWE-862, CWE-770, CWE-703]
    scope: per-component
```

Match predicates (all optional, AND within a single `match_any` entry):
`cwe[]`, `title_pattern` (regex), `file_glob[]`, `source_check_id[]`, `config_check_id[]`.
`scope`: `cross-component` | `per-component` (default per-component).
`split_by[]`: additional bucket dimensions (e.g. `trust_zone`, `endpoint`) for the
severity-zone/flow exceptions — prevents over-merging.

Rationale for the tightness: IDOR is CWE-639 → matches no group → stays per_instance.
F-004 (798) / F-001 (922) are outside the jwt-verification CWE set → stay separate.

### A2. Schema — NEW `schemas/consolidation-groups.schema.yaml`
Validates the catalog (unique `id`, valid regex, known `scope` enum). Wired into
the pipeline's existing schema check (analogous to `source-auth-findings.schema.yaml`).

### A3. Group resolver — NEW in `scripts/merge_threats.py`

```python
def _load_consolidation_groups() -> list[dict]: ...   # reads data/consolidation-groups.yaml (cache)
def _match_consolidation_group(t: dict, groups) -> dict | None:
    # first rule whose match_any entry fully matches on (cwe, title, evidence.file,
    # source_check_id, config_check_id). Returns {id,title,scope,split_by}.
```

`_match_consolidation_group` runs on EVERY threat (STRIDE, scanner, AND
config source) — hence CWE-/source-agnostic. This solves the JWT cross-CWE case
(F-027 CWE-287, F-028 CWE-345, F-003 CWE-347 → all `jwt-verification`).

### A4. Consolidation pass — NEW `_consolidate_by_group()` (generalizes `_consolidate_config_checks`)

- Bucket key = `(group_id, *split_dims)` where `split_dims` follows from `scope`/`split_by`
  (`scope: per-component` → + `component_id`; `split_by:[trust_zone]` → + zone).
- Survivor = highest risk (tie → first-seen), exactly like `_consolidate_config_checks:783`.
- Survivor fields (reused, shape is proven — `merge_threats.py:796-799`):
  `instances[]` ({file,line,snippet?, **severity**, **local_id**}), `affected_files[]`,
  `instance_count`, `systemic: true`, `consolidation_group: <id>`.
  - NEW vs. config: carry per-instance `severity` + `local_id`/`source_scan_ref`
    (for instance delta C and per-instance suppress / FP isolation, exception 6).
- Survivor title = catalog `title` (instead of `_declassify_config_title` — the title is now
  explicitly declared in the catalog, no string-stripping guesswork).
- Survivor severity = max of the member severities; per-instance severity stays in `instances[]`.
- `mitigation_ids` = union of all member `mitigation_ids` (deduplicated; rule B
  converges them afterward). This way the one finding carries multiple mitigations.
- Members without a group match: passed through unchanged (per_instance).

### A5. Wiring in `cmd_collect` (`merge_threats.py:1263-1274`)

```
deduped = _dedupe_exact(flat)
deduped = _dedupe_evidence(deduped)
deduped = _consolidate_config_checks(deduped)     # stays (config_check_id)
deduped = _consolidate_by_group(deduped)          # NEW — after config, before _group_candidates
all_candidates = _group_candidates(deduped)
```

`_consolidate_config_checks` remains as a special case (or is later folded into
`_consolidate_by_group` with auto-generated `config_check_id` groups — not
in this step, to keep the config tests stable).

### A6. Scanner enrichment
`_source_auth_finding_to_threat` (`merge_threats.py:409`) already carries `source_check_id`
and `evidence.file/line` — sufficient for the resolver. **No** mandatory field in
`source-auth-checks.yaml` needed; the group assignment is centralized in the catalog (A1).
(Optional convenience: `consolidation_group:` allowed directly on the check, overrides catalog.)

---

## Rule B — Mitigation control dedup

### B1. Dedup in `derive_mitigations` (`build_threat_model_yaml.py:634`)

Today: 1 entry per **M-ID string**; the same control text under M-004/M-022 stays duplicated.
New: after building the `by_mid` table, a dedup pass that merges via `_mitigation_fp(m)`
(already exists, `:169`, title-based, location-stripped):

- Group all mitigation entries by `_mitigation_fp`.
- Per group: one canonical survivor (lowest M number for stability), `threat_ids[]`
  = union, `remediation`/fields from the highest-risk member.
- Build an `old_mid -> canonical_mid` remap; apply it to **all** threat `mitigation_ids[]`
  (so IDOR/XSS findings that stay separate jointly point to one M-NNN).
- Then optionally renumber compactly (M-001..M-NN) as today.

Result: 19× "Enforce object-level authorization" → 1; 7× "Enforce server-side authorization"
→ 1; 6× "Pin base image" → 1; XSS 3× → 1. Findings stay untouched — pure
mitigation convergence.

### B2. Order
B1 runs AFTER A (consolidation), in `build_threat_model_yaml` when deriving the
mitigations from the (already consolidated) threats.

---

## Rule C — Instance-level delta (regression protection)

Today: everything is finding-granular (`_threat_fingerprint :153`, `_fp_str :162`, set diff
`:1194-1196`, reconciler `:278-343`). A consolidated 17-member group would be ONE ID — without C
you lose the per-location resolvability that exists today.

### C1. Per-instance fingerprint — NEW `build_threat_model_yaml.py`

```python
def _instance_fingerprints(t: dict) -> list[str]:
    base = _fp_str(t)                       # comp|cwe|title
    insts = t.get("instances")
    if not insts:
        # Singleton finding counts as 1 instance at its evidence location
        ev = t.get("evidence") or {}
        return [f"{base}|{ev.get('file','')}:{ev.get('line','')}"]
    return [f"{base}|{i.get('file','')}:{i.get('line','')}" for i in insts]
```

### C2. Extend the changelog (`:1184-1265`)

- Additionally persist `instance_fingerprints[]` (flattened across all threats).
- Compute `added_instances` / `resolved_instances` as a set diff of the instance FPs
  (analogous to `added_threats`/`resolved_fps :1195-1196`), in addition to the existing
  finding delta (the headline stays finding-granular).
- The changelog note (`_changelog_note`) gets a line "N/M instances of a systemic
  finding new/fixed" when the finding itself is "unchanged" but its instances change.

### C3. Instance-aware reconciler (`reconcile_incremental_threats :278`, `_index_resolved_prior :260`)

- When a prior finding is still present (finding-FP match), diff its `instances[]`
  against the current ones → mark fixed instances without treating the whole finding
  as resolved.
- The `resolved_prior_findings` path (`merge_threats.py:1219`) optionally extended by an
  `instance_ref` so a single affirmed fix closes an instance rather than the whole finding.

### C4. Renderer (`compose_threat_model.py:12918-12938`)
- `instances_card` exists (cap 8 + "+N more"). Extend: per instance a status marker
  (✅ fixed / 🆕 new / open) + severity dot, fed from C2/C3.
- Ensure consolidated findings run through this path (the check is already
  `t.get("instances")` — generic, kicks in automatically).

---

## Tests

- `tests/test_merge_threats.py`
  - `_match_consolidation_group`: JWT cross-CWE matches, IDOR (639) does NOT match,
    F-004/F-001 do NOT match.
  - `_consolidate_by_group`: 17 AUTHZ-008 → 1 survivor with instance_count=17,
    affected_files, union of mitigation_ids; per-instance severity preserved;
    `split_by:[trust_zone]` separates correctly; per_instance findings unchanged.
- `tests/test_build_threat_model_yaml.py`
  - `derive_mitigations` dedup: two M-IDs with the same `_mitigation_fp` → 1 entry,
    remap of all `mitigation_ids`, multiple threats share one M-NNN.
  - Instance delta: 3 of 17 instances removed → `resolved_instances` shows 3,
    finding stays present; added_instances on a new location.
- `tests/test_compose_threat_model.py`
  - instances_card renders status/severity markers; consolidated finding shows
    "Instances (N)" + mitigation list (≥2 for JWT).
- Schema test: `consolidation-groups.schema.yaml` validates the catalog.
- Full suite run green.

## Implementation order

1. A2/A1 catalog + schema (declarative, no behavior) → schema test.
2. A3/A4 resolver + `_consolidate_by_group` + A5 wiring → merge tests.
3. B1 mitigation dedup → yaml tests.
4. C1–C3 instance delta + C4 renderer → delta/compose tests.
5. Dry run on juice-shop; verify findings/mitigations counts + changelog delta.
6. Full suite run, then recompose the `threat-model.md` (deterministic).

## Open detail points (clarify before/during implementation)

- Pull the exact `config_check_id` strings for `dependabot-ecosystems` from the real run
  (placeholder DEP-* above).
- `unauth-websocket-channel`: deliberately `scope: per-component` + file_glob; check whether all
  three findings carry the same component (realtime-channel) — otherwise `cross-component`.
- Decide whether `_consolidate_config_checks` is later folded into `_consolidate_by_group`
  (separate follow-up step, not part of this plan).
