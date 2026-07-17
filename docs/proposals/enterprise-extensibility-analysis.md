# Enterprise Extensibility — what's possible, what would make sense

Analysis of the config/hook/extension surface from an enterprise perspective. Not an implementation mandate — a basis for prioritization.

## Guiding principle: the trust boundary

Every extension falls into exactly one of three classes. The class decides whether it belongs in the plugin:

| Class | Example | Belongs in the plugin? |
|---|---|---|
| **Declarative data** (criteria + effect, no code) | coach topics, gate policy, requirements source | **Yes** — validated, auditable, no fork |
| **Arbitrary code** (org script runs on an event) | custom PreToolUse blocker as a shell script | **No** — native via Claude Code settings/managed |
| **Core semantics** (severity, CVSS, agent instructions) | custom severity rules | **No, never** — core, conservative by design |

Everything below is measured against this boundary.

---

## A. What's possible today

### Runtime config (`org-profile.yaml`) — no fork, validated
- **Presets**: depth, outputs (SARIF/PDF/pentest), scan, quality (QA/architect/walkthroughs/enrichment), verification, guardrails (wall-time, cost-cap, resumes, tracing), **requirements.gate** (mode/gate_on/priority_floor)
- **policy.disable_opus** (org-wide model ceiling)
- **branding** (cover: title/contact/logo)
- **requirements**: source URL, create-threat-model default-active, standalone_audit toggle
- **llm_context**: 1–20 Markdown context files (untrusted data)
- **security_coach**: enabled_by_default, max_requirements_per_topic, **baseline**, **inherit_default_topics**, **topics** (trigger → guidance + requirement IDs)
- **skill_toggles** (soft-disable user skills)
- **actors** (inherit/disable/add)
- **abuse_cases** (inherit/disable/add)
- **mcp.servers** (custom SAST/SCA endpoints in the packaged `.mcp.json`)

### Build-time (`package-policy.yaml`) — restrict only
- `plugin_surface`: **skills / hooks / mcp_servers** include|exclude. Can only **remove** hooks, not add them.

### Native in Claude Code — outside the plugin
- Arbitrary hooks via `.claude/settings.json` (project) or `/etc/claude-code/managed-settings.json` (org-wide). **Full hook flexibility already exists here.**

### Hook-specific today
- **security-coach**: fully data-driven configurable (topics/baseline/enabled/cap). ✅
- **agent-logger**: env only (`APPSEC_LOG_REDACT_PATHS`, `APPSEC_TRACING`) + `config.json` (`logging.max_log_bytes/verbose`). Not in the org-profile, hence not packageable.

---

## B. What's NOT possible (gaps)

1. **Adding a custom plugin hook / event handler** — package-policy can only remove. (Deliberate — see trust boundary.)
2. **agent-logger as policy** — redaction, retention, log destination are env/config.json, not org-profile. Compliance-relevant, but not packageable.
3. **Enforcement actions** — the coach can only *advise* (inject context), not *enforce* (warn/block a prompt).
4. **Coach is profile-level, not per-preset** — a `ci` preset can't have different coaching than `release`. `resolve()` emits `security_coach` globally.
5. **Run policy only in env, not in the profile**: `APPSEC_FAIL_ON` (severity→exit), `APPSEC_URL_ALLOWLIST` (SSRF/exfil guard on remote fetch), model routing (`APPSEC_*_MODEL`), parallelism. These are policy-worthy, but not packageable as a preset/policy.

---

## C. Enterprise view: what makes sense

An enterprise wants five things: **consistency** (every dev, same rules), **compliance** (audit trail, redaction, data residency), **governance** (not switchable off), **integration** (own SAST/ticketing), **low friction** (CI without per-dev setup).

Assessment by value × safety:

| # | Extension | Class | Enterprise value | Status |
|---|---|---|---|---|
| 1 | Coach topics/baseline (own secure-by-default guidance in company language, mapped to own catalog) | declarative | **high** | ✅ built |
| 2 | Requirements gate per preset (CI gated by policy) | declarative | **high** | ✅ built |
| 3 | **Run policy into the profile**: `guardrails.fail_on` + `policy.url_allowlist` | declarative | **high** | ✅ built (model routing dropped: ordering trap > benefit; `disable_opus` covers the core governance) |
| 4 | **agent-logger as policy**: `logging.redact_paths` + retention | declarative | medium | open |
| 5 | Per-preset coach (preset can toggle coach on/off + topic subset) | declarative | medium–low | open |
| 6 | **Enforcement vocabulary**: coach topic `action: warn\|block` | declarative (fixed vocabulary) | medium (only if enforcing > advising) | open |
| 7 | Arbitrary org hooks in the plugin | arbitrary code | — | **deliberately no** (use native) |
| 8 | Custom severity/CVSS policy | core semantics | — | **never** |

### Why #3 is the biggest open lever
`fail_on`, `url_allowlist`, model routing are **real security/cost policy** that today exists only as an env var — hence effectively **not packageable** (the packager knows nothing about env injection). An org can't bake "block findings ≥ High", "allow remote fetch only to these hosts", or "for data-residency reasons use only model X" into the branded plugin. That's exactly the governance internal packaging exists for.

### Why #6 with caution
Enforcement (blocking a prompt) is a real enterprise desire, but intrusive and easily miscalibrated. With a **fixed vocabulary** (`inject`=today / `warn` / `block`) it stays declarative and auditable — no arbitrary code. Only build it if "advising" demonstrably isn't enough.

---

## D. Recommendation / order

1. **(done)** Coach rules + gate policy.
2. **#3 run policy into the org-profile** — `guardrails.fail_on`, `policy.url_allowlist`, model routing. Highest governance value, closes the "policy stuck in env" gap. Bidirectional like the gate (schema + `resolve_config`/`resolve_org_profile` + `.env` emit + tests).
3. **#4 agent-logger compliance** — redaction/retention as policy. Small, compliance value.
4. **#6 enforcement vocabulary** — only on real demand.

Don't build: #7 (natively available), #8 (core).

### Honest overall assessment
The config surface is already **large**. Every additional option costs docs + tests + cognitive load. The clearly most valuable open step is **#3** — because that's where real policy is stuck in a non-packageable corner (env). The rest is incremental; #5 and #6 only on concrete demand, not on spec.
