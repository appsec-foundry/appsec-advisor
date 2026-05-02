# Threat-Modeling Variants — Overview & Decision Guide

This document compares the three `--assessment-depth` levels (`quick` / `standard` / `thorough`) and the four reasoning tiers (`sonnet` / `opus-cheap` / `haiku-economy` / `opus`) across every relevant factor — model routing, task scope, cost, wallclock time, and output depth. State: post-B2d-patch (2026-05).

---

## 1. At a glance — which variant when?

| Use case | Recommended variant |
|---|---|
| CI pipeline / PR diff check | `--assessment-depth quick` |
| Default for regular code review (repo < 400 source files) | `--assessment-depth standard` (= opus-cheap default) |
| Large enterprise repo (> 400 source files) | `--assessment-depth standard` (auto-switch B2d → haiku-economy) |
| Pre-release audit, compliance sign-off | `--assessment-depth thorough` |
| Maximum threat quality, cost no object | `--assessment-depth thorough --reasoning-model opus` |
| Tight token budget | any depth + `--reasoning-model haiku-economy` |

---

## 2. Structural parameters per depth (depth-bound)

These parameters are **independent** of the reasoning tier — they scale exclusively with `--assessment-depth`.

| Parameter | quick | standard | thorough |
|---|:-:|:-:|:-:|
| `MAX_STRIDE_COMPONENTS` | 3 | 5 (capped to 3 on large repos) | 8 |
| STRIDE turn budget (simple/moderate/complex) | 10 / 15 / 20 | 15 / 22 / 31 | 20 / 28 / 35 |
| `DIAGRAM_DEPTH` | minimal | standard | extended |
| `QA_DEPTH` | core | full | extended |
| Stage 4 architect review | opt-in | opt-in | **auto-on** |
| `ENRICH_ARCH_FRAGMENTS` | off | **on** | **on** |
| Auto-default reasoning tier | `haiku-economy` | `opus-cheap` | `opus-cheap` |
| Auto-switch B2d (capped repo) | n/a (already haiku-economy) | → `haiku-economy` | → `haiku-economy` |

### What the parameters mean

- **`MAX_STRIDE_COMPONENTS`** — how many major components Phase 9 STRIDE analyzes separately. Cap of 3 on large repos prevents long runtimes and protects the token budget.
- **STRIDE turn budget** — LLM tool calls allowed per component. Higher = deeper exploration, more threats, but linear cost growth.
- **`DIAGRAM_DEPTH`** — number/complexity of Mermaid diagrams in §2 and §3 of the report.
- **`QA_DEPTH`** — number/strictness of Stage 3 checks (links, cross-refs, contract).
- **Stage 4 architect review** — second pass by an Opus-driven reviewer, advisory only, writes `.architect-review.md`.
- **`ENRICH_ARCH_FRAGMENTS`** — composer overwrites deterministically generated `architecture-diagrams.md` and `security-architecture.md` with richer LLM-authored versions.

---

## 3. Model routing per tier (tier-bound)

This table shows **which model** each agent uses under which tier — independent of the depth (exceptions are explicitly marked).

`H` = Haiku 4.5 · `S` = Sonnet 4.6 · `O` = Opus 4.7

| Phase / Agent | sonnet | opus-cheap | haiku-economy | opus |
|---|:-:|:-:|:-:|:-:|
| Phase 1 — Context Resolver | H | H | H | H |
| Phase 2 — Recon Scanner | H | H | H | H |
| Phase 2.5 — Config Scanner | H | H | H | H |
| Phase 3-8 + 11 — Orchestrator | S | S | S | S |
| Phase 9 — STRIDE Analyzer | S | S | S | **O** |
| Phase 9 — Threat Merger | S | **O** | S | **O** |
| Phase 10b — Triage Validator¹ | S | **O** | S | **O** |
| Stage 3 — QA Routine² | S | S | H/S | S |
| Stage 3 — QA Content | S | S | S | S |
| Stage 4 — Architect Review | O | O | O | O |

¹ Since M3.1, triage runs deterministically in Python — model only relevant when `APPSEC_TRIAGE_DETERMINISTIC=0`.

² QA Routine under `haiku-economy`: **Haiku for quick + standard**, **Sonnet for thorough** (denser document, more cross-refs to reconcile).

---

## 4. What actually characterizes the four tiers

### `sonnet`
> "All Sonnet — no premium markups, no discount risk."
- STRIDE / triage / merger: all Sonnet
- Three pure-extraction agents (context/recon/config) on Haiku — same as in all tiers
- **When to pick?** When you want to avoid any Opus usage (quota constraints, audit requirements like "no premium model"), but the cost-saving defaults on extraction phases are fine.

### `opus-cheap` (default for `standard` + `thorough` on regular repos)
> "Consequence-critical phases on Opus, reasoning floor on Sonnet."
- STRIDE: Sonnet (value-generating, but Sonnet is sufficient)
- **Triage + merger: Opus** — consolidation and severity decisions are T-ID-stability-critical
- **When to pick?** Default for regular repo sizes (< 400 source files). Sweet spot for cost/quality.

### `haiku-economy` (default for `quick` + via B2d also for large repos)
> "Consistent saver variant — STRIDE stays on Sonnet, everything around it leaner."
- STRIDE / triage / merger: all Sonnet
- QA Routine on quick+standard: Haiku
- **Special on `quick`**: additional STRIDE task reduction **A-F** (see §5)
- **When to pick?** Automatic on large repos (B2d). Manually on token-tight runs or explicitly via `--reasoning-model haiku-economy`.

### `opus` (premium)
> "STRIDE on Opus for top threat quality."
- **STRIDE: Opus** — highest reasoning quality in the value-generating phase
- Triage + merger: Opus
- **When to pick?** When maximum threat quality is required and ~5× the cost of sonnet is acceptable. Recommendation: only in combination with `thorough` (8 components).

---

## 5. STRIDE task reductions A-F (only quick + haiku-economy)

These reductions activate **only** with the combination `--assessment-depth quick --reasoning-model haiku-economy` (= default on quick) and reduce the **task scope** in Phase 9, not the model quality (STRIDE stays on Sonnet).

| ID | Reduction | Effect |
|---|---|---|
| **A** | `skip_verification_greps` | No evidence-gathering in code via additional `grep` |
| **B** | `max_threats_per_category=2` | Max 2 threats per STRIDE category/component (instead of 2-5) |
| **C** | `skip_code_examples` | No code snippets in threat findings |
| **D** | `skip_evidence_excerpt` | No evidence quotes from source files (file:line stays) |
| **E** | `skip_cvss_scoring` | No CVSS scoring (compute manually afterwards) |
| **F** | `turn_budget_hard_cap=25` | Max 25 turns per component (instead of 40) |

**Impact:** Phase 9 runs ~50 % faster and produces ~30 % fewer threats per component, focused on the most important ones. Ideal for PR reviews or smoke tests.

---

## 6. Auto-switch B2d — context-dependent default behavior

When the user does **not** set `--reasoning-model`, the resolver automatically switches:

| State | Default tier | Rationale |
|---|---|---|
| `quick` | `haiku-economy` | deliberate saver variant for CI/PR use case |
| `standard`, repo < 400 source files | `opus-cheap` | triage/merger on Opus pays off at larger workload |
| `standard`, repo > 400 source files | **`haiku-economy` (B2d auto)** | 3-component cap → workload too small for Opus markup |
| `thorough` | `opus-cheap` | default — user can explicitly set `--reasoning-model opus` for premium |

Visible in the Configuration Summary as:
```
Reasoning    : haiku-economy (auto — large repo capped to 3 components,
                              Opus on merger/triage uneconomical at this scale)
```

Override always possible by explicit `--reasoning-model <tier>`.

---

## 7. Cost estimate (Juice Shop, 608 source files, post-patch)

| Depth \ Tier | sonnet | opus-cheap | haiku-economy | opus |
|---|---:|---:|---:|---:|
| **quick** | ~$1.80 | ~$2.30 | **~$1.80** ¹ | ~$5.50 |
| **standard** | ~$3.70 | ~$4.70 | **~$3.70** ² | ~$11.00 |
| **thorough** | ~$5.80 | ~$7.40 | **~$5.30** ² | ~$17.00 |

¹ = auto-default on quick. ² = via B2d auto-switch on capped repos.

### Where the cost differences come from

| Phase | sonnet | opus-cheap | haiku-economy | opus |
|---|---|---|---|---|
| Phase 1-2.5 (setup) | same (~$0.30) | same | same | same |
| Phase 3-8 (orch) | same (~$0.40) | same | same | same |
| **Phase 9 STRIDE** | $1.50 (S) | $1.50 (S) | $1.50 (S) | **$7.50** (O, +400 %) |
| **Phase 9 merger** | $0.10 (S) | **$0.50** (O) | $0.10 (S) | **$0.50** (O) |
| Phase 10/10b | same | same | same | same |
| Stage 2 compose | same (~$0.80) | same | same | same |
| Stage 3 QA | $0.40 (S) | $0.40 (S) | $0.30 (H+S split) | $0.40 (S) |
| Stage 4 architect (thorough) | $1.50 (O) | $1.50 (O) | $1.50 (O) | $1.50 (O) |

**Key insight:** The cost lever for `opus` is ~80 % Phase 9 STRIDE. The cost lever for `haiku-economy` is ~70 % the merger downgrade Opus → Sonnet (versus `opus-cheap`).

---

## 8. Wallclock time (Juice Shop, post-patch)

| Depth \ Tier | sonnet | opus-cheap | haiku-economy | opus |
|---|---:|---:|---:|---:|
| **quick** | ~12 min | ~14 min | **~10 min** | ~25 min |
| **standard** | ~22 min | ~25 min | **~22 min** | ~50 min |
| **thorough** | ~35 min | ~40 min | **~33 min** | ~75 min |

**Important:** These values hold under optimal conditions. WSL2/Modern-Standby freezes can extend a run arbitrarily — see [Modern-Standby mitigation](#10-recommended-system-configuration).

---

## 9. Output differences per depth

### quick
- 3 components × max 2 threats/category ≈ **15-25 threats**
- No code snippets, no CVSS, no evidence quotes
- 1-2 Mermaid diagrams (minimal)
- Core QA checks only
- Optimal for: PR diff reviews, fast "health check"

### standard
- 3-5 components × full STRIDE ≈ **30-50 threats**
- With code snippets, CVSS, evidence quotes
- 4-6 Mermaid diagrams (architecture, data flow, attack chains)
- Full QA incl. cross-references, contract checks
- Optimal for: regular code review, MR/PR templates

### thorough
- 8 components × extra-deep STRIDE ≈ **60-100 threats**
- Detailed code snippets + sequence diagrams per Critical
- 6-10 Mermaid diagrams (extended) + LLM-enriched architecture
- Extended QA + architect review layer
- Optimal for: pre-release audits, compliance sign-off, pen-test prep

---

## 10. Recommended system configuration (WSL2)

Long runs (`thorough`, or `standard` on large repos) are vulnerable to Windows Modern Standby, which freezes WSL2 user-space processes via cgroup-freezer. Mitigation:

**`C:\Users\<YourName>\.wslconfig` (Windows side):**
```ini
[wsl2]
autoMemoryReclaim=disabled
vmIdleTimeout=-1
```

After saving, restart WSL:
```powershell
wsl --shutdown
```

**During the run:**
- Activate "High performance" power profile
- Optional: `powercfg /requestsoverride process bash.exe SYSTEM` to prevent standby
- Alternatively: PowerToys "Awake" or a Caffeine tool

---

## 11. Per-agent override via ENV variables

Highest precedence — overrides any tier for a single run. Useful when you want to deviate from the default recommendation for one specific agent:

```bash
APPSEC_CONTEXT_RESOLVER_MODEL=claude-sonnet-4-6      # instead of Haiku
APPSEC_RECON_SCANNER_MODEL=claude-sonnet-4-6         # instead of Haiku
APPSEC_CONFIG_SCANNER_MODEL=claude-sonnet-4-6        # instead of Haiku
APPSEC_QA_ROUTINE_MODEL=claude-sonnet-4-6            # instead of Haiku/Sonnet
APPSEC_QA_CONTENT_MODEL=claude-opus-4-7              # instead of Sonnet
APPSEC_STRIDE_MODEL=claude-opus-4-7                  # instead of Sonnet
APPSEC_TRIAGE_MODEL=claude-opus-4-7                  # instead of Sonnet/Opus
APPSEC_MERGER_MODEL=claude-opus-4-7                  # instead of Sonnet/Opus
APPSEC_ORCHESTRATOR_MODEL=claude-opus-4-7            # instead of Sonnet
```

Example — STRIDE on Opus, rest unchanged:
```bash
APPSEC_STRIDE_MODEL=claude-opus-4-7 \
  /appsec-advisor:create-threat-model --rebuild --assessment-depth thorough
```

---

## 12. Decision matrix in one row

| If your goal is … | … then pick … |
|---|---|
| fast + cheap on any repo | `quick` (default) |
| solid standard review on a normal repo | `standard` (= opus-cheap auto) |
| solid standard review on a 600+-file repo | `standard` (= haiku-economy auto via B2d) |
| full depth on a normal repo | `thorough` (= opus-cheap auto + architect review) |
| premium quality regardless of cost | `thorough --reasoning-model opus` |
| token scarcity at any depth | `--reasoning-model haiku-economy` (explicit) |
| avoid any Opus usage (compliance/quota) | `--reasoning-model sonnet` |

---

## Appendix — Sources & verification

- **Model routing matrix:** `scripts/resolve_config.py` → `EXTENDED_MODEL_MATRIX`, `_DEFAULT_EXTENDED_ROUTING`, `MODEL_MATRIX`
- **Structural parameters per depth:** `scripts/resolve_config.py` → `DEPTH_PARAMS`
- **Repo-size cap (B2c):** `scripts/resolve_config.py` → `resolve_repo_size_cap`, triggers at > 400 source files
- **Auto-switch (B2d):** `scripts/resolve_config.py` → `resolve_default_tier_for_capped_repos`
- **STRIDE task reductions A-F:** `scripts/resolve_config.py` → `QUICK_STRIDE_PROFILE`
- **Tests:** `tests/test_haiku_routing_per_depth.py` (37 tests pin the matrix), `tests/test_resolve_config.py::TestResolveDefaultTierForCappedRepos` (6 tests pin B2d)

Test coverage state (post-patch): **134 green tests** in the resolver and routing area.
