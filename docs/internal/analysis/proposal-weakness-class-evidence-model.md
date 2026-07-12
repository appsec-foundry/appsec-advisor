# Proposal — Weakness-Class Evidence Model + Systemic Posture Verdict

**Status:** OPEN / design. Supersedes and subsumes
`proposal-threat-hypotheses-promotion.md` (the "promote hypotheses before
re-enabling §6.2 table" record) — that doc's ask is a special case of Layer 1
here (hypotheses become the `inferred` tier of a unified register, folded as
root-cause instead of shown as peers).

**Author framing (verbatim intent):** Findings today mix genuinely
code-confirmed vulnerabilities with architecture-derived *hypotheses*, and the
two are not reconciled — e.g. juice-shop reports SQL injection as an unproven
`ARCH-SQLI-001` hypothesis **while** two confirmed SQLi sinks sit in the same
report. The user's ask: stop maintaining a separate "hypotheses" species;
instead give every finding an explicit evidence/confidence status, document
real flaws **and** indicators under a weakness class (e.g. "Insecure SQL
handling"), and — crucially — let the reader see the **central/systemic**
problems: is this "a few incidental bugs" or "the app is systemically broken
and the developer ignored common security principles?" It should also matter
whether **standard, vetted mechanisms/protocols** are used (OAuth/OIDC,
parameterized ORM, argon2) or whether security is **home-grown**.

This proposal is analysis + design only. No code is written until this is
reviewed. All facts below are verified at `file:line` (see §2).

### 0. Non-negotiable framing (author, verbatim)

The desired output for the SQLi example is **"2 instances + 1 general design
weakness"** — NOT "2 vulnerabilities + 1 hypothesis". The word/concept
**"hypothesis" must never be surfaced to the user.** This forces a hard
distinction the tool currently blurs:

| | What it is | User-visible? |
|---|---|---|
| **Design weakness** | an *observable structural fact* — "there is no centralized input-validation layer" | **Yes** — as one general weakness carrying its instances |
| **Hypothesis** | *speculation about a specific vulnerability* — "SQLi *might* be possible" | **Never** |

Today the arch engine emits the observable design gap **framed as** a
speculative vuln ("threat-hypothesis about SQLi"). We split that: keep the
observable design fact (rendered as a **design weakness** with the confirmed
sinks as its instances); drop the speculative-vuln framing entirely. "Hypothesis"
becomes internal plumbing at most — it is not a user-facing category, section,
severity, or word.

**Emission rule:** a design weakness is shown **only** when backed by an
observable *missing-control* signal (`controls_absent_evidence` /
`positive_signals` proving the control is absent). Pure "could be vulnerable"
speculation with no observable missing-control signal is **dropped** — not
shown, not even as a weakness.

---

## 1. The problem, concretely

`examples/threat-modeler/threat-model-juice-shop-standard.yaml`:

- Confirmed SQLi findings (`source: source-scan`, real file:line):
  `SQL Injection — routes/login.ts:34` (`:1798`), `SQL Injection in Product
  Search — routes/search.ts:23` (`:2167`).
- **Simultaneously** in `threat_hypotheses[]`: `ARCH-SQLI-001`, `CWE-89`,
  `proof_state: control-derived`, `confidence: low`, `component_id: null`
  (`:6498`) — "Injection through missing centralized input validation".

So the report literally says "SQLi proven at two exact lines" **and** "SQLi is
hypothetically possible". That is redundant, self-contradicting, and
trust-damaging. It is **current intended behavior**, not a guard that failed —
there is no reconciliation between the two engines (§2, Fact R).

Two deeper problems the user surfaced:

1. **No unified evidence axis.** Confidence lives in two disjoint vocabularies
   on two different objects (findings vs hypotheses), so a reader cannot rank
   "proven" vs "suspected" vs "inferred" across the register.
2. **No systemic verdict.** The reader cannot deterministically see whether
   problems are incidental or a systemic ignoring of security principles. The
   raw material (a principle vocabulary + a control-effectiveness matrix)
   exists but is never fused into a scored verdict.

---

## 2. Verified fact base (file:line)

Confirmed by four independent verification passes. Corrections from earlier
assumptions are marked **⚠**.

### Provenance & confidence
- **Sources**: every threat carries `source`, centralized in
  `scripts/_shared_sources.py`. `CODE_LEVEL_SOURCES = {stride, dep-scan,
  known-vuln, source-scan}` (`:71-89`, "file/line evidence… CVSS/SARIF/pentest
  eligible"); `CONFIG_DEFECT_SOURCES = {configuration-defect, config-scan}`
  ("treated as code-level for CVSS", `:92-103`); `DESIGN_LEVEL_SOURCES =
  {requirements-compliance, known-threats, architecture-coverage,
  threat-hypothesis, architectural-anti-pattern, coverage-gap}` ("NOT
  CVSS-eligible", `:106-115`).
- **Evidence**: STRIDE contract forbids inventing threats without file:line
  (`agents/appsec-stride-analyzer.md:389`), but the schema permits
  `evidence: [object, "null"]` (`schemas/stride.schema.yaml:155`,
  `schemas/threats-merged.schema.yaml:89`).
- **Confidence is split**: findings carry `evidence_check` enum
  `[verified, verified-prior, refuted, ambiguous, unchecked,
  carried-unverified-shallower-depth, null]`
  (`schemas/threats-merged.schema.yaml:188`); hypotheses carry `proof_state`
  `[control-derived, evidence-backed, confirmed]` +
  `confidence [low, medium, high]`
  (`schemas/threat-model.output.schema.yaml:980,982`). **No field spans both.**
- **CVSS gating**: allowed only for `known-vuln` or `stride` + eligible CWE +
  `evidence.line` set; forbidden for `architecture-coverage`/`threat-hypothesis`
  — "design/architectural gaps cannot be honestly scored on CVSS Base metrics"
  (`schemas/threats-merged.schema.yaml:240-251`, `AGENTS.md:88-92`).

### Fact R — the reconciliation gap
- Hypothesis engine `scripts/architecture_coverage_checks.py` reads only source
  files + rules YAML + recon JSON (`:147-186`); never reads `.threats-merged.json`
  or `.stride-*.json` (grep = 0).
- Bridge `scripts/arch_coverage_to_threats.py` gates a hypothesis into
  `threats[]` **only** on `proof_state == "confirmed"` (`:188`) **and**
  `confidence == "high"` (`:197`). **No branch checks another threat's
  CWE/component.** → a confirmed same-CWE finding cannot suppress the hypothesis.

### Clustering (exists, but scoped to `threats[]` only)
- `data/weakness-classes.yaml`: 9 clusters + `_unmapped` — `injection`
  (CWE-89/943/78/94/95/611/22/23), `broken_auth`, `missing_authz`,
  `weak_crypto` (CWE-327/328/329/330/916/326), `server_side_exposure`,
  `output_xss_csp` (CWE-79/…), `sensitive_disclosure`, `dos`, `outdated_deps`.
  Consumed over `threats[]` for §1 heat-map, Operational Strengths, tier
  routing, QA (`compose_threat_model.py:5087,5127,4677`; `qa_checks.py:8205`).
  **⚠ not just the heat-map function**, but always `threats[]`, never
  `threat_hypotheses[]`.
- `data/consolidation-groups.yaml`: 15 groups collapse N findings sharing one
  mechanism into `instances[]` (incl. `sql-injection-per-component`,
  `xss-per-component`, `idor-object-authz`, `jwt-verification`,
  `missing-route-auth`, `ssrf`/`command-injection`/`path-traversal`/`xxe`
  `-per-component`, `absent-dependency-tooling`). Applied over `threats[]` in
  `merge_threats.py:853` (grep `hypothes` = 0).

### Deterministic instance detectors (per domain)
- **Access control** — `source_auth_scanner.py` ← `data/source-auth-checks.yaml`:
  AUTHZ-001/002 (IDOR/BOLA, CWE-639), AUTHZ-003/004 (mass assignment, CWE-915),
  AUTHZ-008 (missing route auth, CWE-862). Strong.
- **Authn** — AUTHZ-005 (JWT algo-allowlist missing, CWE-347), AUTHZ-006 (decode
  w/o verify, CWE-345), AUTHZ-007 (express-jwt algo-allowlist, CWE-347).
  **⚠ AUTHZ-007 is NOT a weak-secret detector; no weak-JWT-secret rule exists.**
- **Input validation** — INJ-001 (SQLi, CWE-89), **⚠ INJ-002 (command injection,
  CWE-78) IS deterministic**, INJ-003 (SSRF, CWE-918). **⚠ Path traversal
  (CWE-22) and XXE (CWE-611) have NO deterministic rule → STRIDE-only.**
- **Crypto** — **⚠ ZERO deterministic rules** anywhere (verified across
  `source-auth-checks.yaml`, `config-iac-checks.yaml`, `recon_patterns.py`,
  `architecture-coverage-rules.yaml`; the one arch hit `:231` is TLS-transport,
  not algorithm). `weak_crypto` is detectable **only via STRIDE/LLM**. Largest gap.
- **LLM/AI** — surface detection is deterministic: `recon_patterns.py` Cat-13
  (`scan_ai_integration:2565`, STRONG/WEAK signals) → `known_llm_patterns`
  (`build_stride_dispatch_manifest.py:36`) → gates OWASP-LLM-Top-10 STRIDE
  sub-block (`:279-282,342`). **⚠ No insecure-SINK detection** (no prompt
  injection taint, no unvalidated model output) → LLM instances are STRIDE-only.

### Standard-vs-custom signals (partial, ad-hoc)
- **OAuth/OIDC**: `recon_patterns.py` Cat-9 (`scan_oauth_oidc:489`) separates
  surface (`oauth-oidc-surface`) from **15 misuse subcategories** (implicit-flow,
  code-without-pkce, pkce-plain, missing-state, missing-nonce,
  claim-validation-gap, refresh-token-in-browser, ropc-grant,
  client-secret-in-frontend, insecure-redirect-uri, …). Recognizes
  Auth0/next-auth/passport/openid-client. This is the model for "standard used
  *correctly* vs misused".
- **exculpatory_signals / positive_signals**: `architecture-coverage-rules.yaml:30-31`;
  "Hard candidates require confidence=high AND positive_signals (not just absence
  of an exculpatory signal)" (`:44-45`); logic in
  `architecture_coverage_checks.py:254-263,578,611,615`. Hook for "standard
  control present".
- **⚠ No systematic standard-vetted-vs-home-grown taxonomy exists** — only inline
  comments ("hand-rolled otplib route" `architectural-controls.yaml:63`,
  "hand-rolled front-end OAuth" `:202`) and baseline prose ("Do not roll your own
  crypto" `appsec-bestpractices-baseline.yaml:154`). It is ad-hoc per rule.

### Engine architecture (reuse, don't multiply)
- `source_auth_scanner.py` is genuinely **catalog-driven**: loads
  `source-auth-checks.yaml` (`:61,157`), compiles rules, supports
  `counter_patterns` + `counter_scope ∈ {line, window, call}` (`:117,168-170,383`),
  `evidence_snippet` (`:403`), excludes `codefixes/` (`:85`). **A new rule pack
  needs no new Python.**
- `architecture_coverage_checks.py` ← `architecture-coverage-rules.yaml`
  (catalog-driven, `:726`).
- `recon_patterns.py` uses imperative per-category `scan_*` functions dispatched
  by name (`:2692`) — the pattern for flow/co-occurrence logic (Cat-9, Cat-13).
- **⚠ `config-scan` is produced by an LLM agent**, not a deterministic script
  (`scripts/normalize_config_scan.py:3`); deterministic scripts only *consume* its
  output. So the reusable deterministic instance engines are **`source_auth_scanner`
  + `recon_patterns`**.
- New scanner ⇒ update `data/required-permissions.yaml` +
  `tests/test_check_permissions.py`, plus bidirectional producer/schema/consumer/
  tests (`AGENTS.md:23,71,98,318`).

### Systemic-view machinery (exists in pieces, never fused)
- **Chaining is rich**: compound chains CC-NN (`data/compound-chain-patterns.yaml`,
  keystone/contributor effective-severity, rendered §8.F
  `compose_threat_model.py:14494`); deterministic effective-severity escalation
  (`triage_compute_ranking.py:430,378,367`); breach-distance/vector
  (`breach-distance-patterns.yaml`, `breach-vector-taxonomy.yaml`); abuse cases
  AC-NNN (`schemas/abuse-cases.schema.yaml`, `render_abuse_cases.py`, §9);
  critical attack tree T-NNN (gated `has_multi_critical`,
  `compose_threat_model.py:9438`). **All exploitability-oriented; none says "this
  recurs because principle X is absent".**
- **Principle vocabulary exists**: `architectural_theme` enum
  (`schemas/architecture-coverage.schema.json:940-958`): `Separation,
  SecretManagement, DefenseInDepth, InputValidation, Authorization,
  Authentication, NetworkSegmentation, DataProtection, AuditLogging, SupplyChain,
  SecureDefaults, LeastPrivilege, InsecureDesign, AttackSurfaceDesign,
  SessionDesign`.
- **Control-effectiveness matrix exists**: `architectural-controls.yaml`
  (`effectiveness_scale: adequate/partial/weak/missing`; `kind` incl.
  cross-cutting "Defense-in-Depth", "Secret Management"; domains
  IAM/AuthZ/DataProt/InputVal/…).
- **But the fusion is missing / discarded**: theme clustering is computed then
  used only internally — `emit_review_mitigations.py:229-260` (one investigate
  card per theme) and `architect_structural_checks.py:659-707` ("advisory input
  for architect-reviewer only; the LLM still judges", never rendered). There is
  **no user-facing "findings grouped by violated principle" and no scored posture
  verdict.**
- **`meta_findings` (MF-NNN)** is the only deterministic systemic rollup
  (`build_threat_model_yaml.py:1457`) but its `category` is a **3-value enum**
  (`Insufficient Patch/Secret Management`, `Insufficient Configuration Hardening`,
  `schemas/threat-model.output.schema.yaml:853-900`) — supply-chain only — and
  **grep found no composer consumer → currently no live renderer** (latent/dead).
- **User-facing systemic surfaces today are LLM prose**: `verdict` blockquote
  (`_render_verdict:2572`) and optional `architectural_anti_patterns` callout
  (≤6 free-form named patterns, `_render_architectural_anti_patterns:8801`).
  Persuasive but unscored, not validated against a principle taxonomy.

**Net:** the tool can *hint* "systemically broken" via LLM prose and rank the
worst individual findings, but **cannot deterministically assert** "principles
X, Y, Z were ignored across N findings." Vocabulary, clusters, and control data
all exist — the join does not. That join is the core of Layer 2.

---

## 3. The model — three orthogonal axes

Every finding is positioned on three independent axes:

1. **Finding type** — every finding is exactly one of **two types** (author's
   model). This axis is about **observability, NOT probability.** Nothing is
   shown because it *might* be bad; there is no "suspected" tier.

   **Type A — Confirmed vulnerability.** Concrete proof that a specific
   vulnerability exists: insecure code observed at file:line **and**
   exploitability established (reachable attacker input, no mitigating control).
   **CVSS-scored.** In the register it appears as an **instance under the
   weakness it belongs to** (e.g. the two proven SQLi sinks under "Insecure SQL
   handling"), not as a free-standing peer.

   **Type B — Weakness (design or implementation).** Insecure handling that
   violates a security best practice and carries real security relevance. Two
   sub-kinds (`kind: design | implementation`):
   - *implementation weakness* — a specific non-best-practice pattern observed
     in code (string concatenation instead of parametrization, weak hash,
     `Math.random()` for a token), exploitability not (yet) established → **no
     CVSS**, but a valid finding pointing at the exact code. **Not "suspected"**
     — the bad practice is definite; only the exploit chain is unproven.
   - *design weakness* — a central control is **observably absent** (missing-
     control signal), no single sink → **no CVSS**, `severity_basis:
     design-risk`, severity **not flatly capped** (§4e).
   A Type-B weakness **references its Type-A confirmed-vulnerability instances
   when they exist** ("2 instances + 1 weakness") and is **equally valid with
   zero instances** (a pure design weakness on an app that happens to have no
   proven sink yet).

   **Dropped — speculation.** No observable insecure code **and** no observable
   absent control ("SQLi might exist somewhere"). **Never a finding.** This is
   the retired `threat-hypothesis`; the word and the category leave the product.

   The register is organized as **weaknesses as headings, confirmed
   vulnerabilities as their instances.** A **new `evidence_tier` field on
   `threats[]`** records an instance's basis — `confirmed-exploitable` (CVSS) vs
   `insecure-practice` (observed, no CVSS); the weakness carries `kind`.
   "Hypothesis" appears in no user-facing field, label, or section.

2. **Implementation strategy** — is a solved problem solved with a standard?
   - `standard-vetted` — recognized protocol/lib used **correctly** (OIDC via
     IdP, Passport, parameterized ORM, DOMPurify, argon2/libsodium, Zod/Joi).
     **Exculpatory** → lowers root severity; can flip an `inferred` root to
     "control present" (suppress).
   - `standard-misused` — standard present but wrong (OAuth implicit, JWT `alg`
     unpinned, ORM present but raw query beside it). **A finding.** Detected by
     the Cat-9-style misuse layer.
   - `home-grown` — bespoke implementation of a solved problem (custom session
     tokens, hand-rolled crypto, per-handler authz). **Risk multiplier** →
     raises root severity, promotes `inferred`→`indicator` (a bespoke layer *is*
     an indicator, not mere inference).
   - `none` — no mechanism (raw concat, no auth). Strongest positive signal.
   - **Rule:** `standard-vetted` requires *lib/protocol detected* **AND** *no
     misuse signal* — never "library present" alone (else `alg:none` gets a free
     pass). New `implementation_strategy` field, populated from recon inventory +
     the misuse layer.

3. **Weakness class** — the ~10 `weakness-classes.yaml` clusters, extended to
   also span the (now-unified) inferred tier.

---

## 4. Layer 1 — finding determination & linking

### 4a. Unified register object

Replace the two-list split (`threats[]` register + separate
`threat_hypotheses[]`) with **one register of two finding types**: a
**weakness** (the heading) that **references its confirmed-vulnerability
instances** when present — exactly "2 instances + 1 weakness", never a
hypothesis beside two findings:

```
weakness:                            # THE finding — renders e.g. "Insecure SQL handling"
  id (F-NNN), weakness_class          # injection/SQLi …
  kind: design | implementation       # design = central control absent; implementation = observed bad pattern
  statement                           # observable fact: "SQL built by concatenation; no parametrized layer"
  severity, severity_basis: design-risk   # by relevance × pervasiveness × exposure (§4e); NOT flatly capped
  implementation_strategy             # none | home-grown | standard-misused | standard-vetted
  observable_backing:                 # REQUIRED — at least one, else the weakness is NOT emitted (§0)
    absent_control_signal[]           #   design: controls_absent_evidence / positive_signals
    practice_evidence[]               #   implementation: file:line of the non-best-practice sites (e.g. concat)
  cvss: none                          # the weakness itself is never CVSS-scored
  instances[]:                        # Type-A confirmed vulnerabilities, when present:
    - id (F-NNN), file, line, basis: confirmed-exploitable, cvss, poc_hint
```

Two finding types map onto this: **Type A (confirmed vulnerability)** is an
`instances[]` entry — it keeps its own F-NNN, file:line, CVSS, POC; **Type B
(weakness)** is the `weakness` heading it hangs under. A weakness is a valid
finding **with zero instances** (pure design weakness). Non-exploitable insecure
sites live as the weakness's own `practice_evidence[]`, not as separate peers.
If `observable_backing` is empty, nothing is emitted — no speculation reaches
the user.

### 4b. Reconciliation (fixes Fact R)

Before rendering, per (weakness class × component). No user-facing outcome ever
uses the word "hypothesis":

| proven | central control | → outcome (user sees) |
|---|---|---|
| ≥1 | absent | **Fold**: the design weakness ("Insecure SQL handling — no parametrized layer") is the heading; the proven sinks are its instances. → *2 instances + 1 general design weakness.* |
| ≥1 | present | Isolated deviations from an otherwise-sound layer; instances only, no systemic design weakness; remediation = fix the N + add a guard/lint. |
| 0 | absent | The **design weakness alone** ("no central X layer"), stated as an observable structural fact + recommendation. **A big problem in its own right** — if the weakness is pervasive/home-grown/exposed it can be **Critical design-risk** (§4e), not a footnote. No CVSS, out of the CVSS-scored headline count, but eligible to top the Layer-2 systemic verdict. Emitted only if an absent-control signal exists (§0). |
| 0 | present or no signal | Nothing emitted — no speculative "might be vulnerable" ever reaches the user. |

This is the logic that is entirely absent today. It requires the reconciler to
see **both** the confirmed findings and the arch-coverage design signals — so it
lives in `merge_threats.py` (which already holds `threats[]`), fed the design
signals that `arch_coverage_to_threats.py` currently routes to the separate
(and unshown) list. The separate `threat_hypotheses[]` top-level list is
retired; its observable-design content flows into `design_weakness` headings,
its speculative content is dropped.

### 4c. Explicit per-domain rules

Same template each: *systemic root · root detector · proven · indicator ·
inferred · cap · family*.

- **Access control** — root: no central authz/ownership layer. proven: AUTHZ-002/
  008/003/004. inferred cap High. Family 1 (root + instances). Strongest existing
  coverage.
- **Authentication** — root: auth not enforced-by-default / no single hardened
  verify path. proven: AUTHZ-005/006/007. **Build:** optional weak-JWT-secret
  rule. If the one central verifier is weak → Family 2 (root == instance);
  scattered/bypassed → Family 1.
- **Input validation** — **theme spanning two classes** (`injection` +
  `output_xss_csp`); **do NOT merge** (different fixes). proven: INJ-001/002/003.
  **Build:** path-traversal (CWE-22) + XXE (CWE-611) rules in
  `source-auth-checks.yaml`. Family 1 per class.
- **Cryptography** — **biggest gap.** root: no central crypto standard/helper.
  **Build:** new `data/crypto-checks.yaml` rule pack (md5/sha1 as password hash
  CWE-328/916, `Math.random()` for tokens CWE-330, `alg:'none'`, ECB mode, low
  bcrypt rounds) run through the `source_auth_scanner` engine; optional arch
  hypothesis rule for "no crypto wrapper". Until built, crypto stays inferred/
  STRIDE-only. Overlap rule: CWE-798 hardcoded key belongs to Authn/Secrets, not
  double-counted in Crypto.
- **LLM/AI** — root: no LLM guardrails (surface via Cat-13). Instances skew
  `indicator`/`inferred` because prompt-injection reachability is not statically
  provable. **Honest default:** `known_llm_patterns` non-empty + no guardrail →
  `inferred` root "unguarded LLM surface"; do **not** fake `proven`. A future
  Cat-N sink detector (user input → prompt concat) could lift specific cases to
  `indicator`.

### 4d. Build plan (no per-domain scripts)

| Need | How | New vs reuse |
|---|---|---|
| Sink instances per domain | YAML rule packs | reuse `source_auth_scanner` engine |
| Crypto instances | new `crypto-checks.yaml` | reuse engine |
| Path-traversal + XXE | extend `source-auth-checks.yaml` | reuse engine |
| strategy: vetted/misused/home-grown | recon inventory + misuse layer | extend recon + rule-schema fields |
| Flow/co-occurrence misuse | Cat-N `scan_*` function | in `recon_patterns.py`, no new script |

Stay at regex + counter-pattern level (the tool's deliberate boundary — recon is
"pure regex, no judgement"). Reasoning stays with the STRIDE LLM. **No taint/AST
engines.**

### 4d-bis. Threat merger — the anti-explosion pivot

Surfacing insecure-practice sites + new deterministic scanners (crypto, path,
xxe) would **explode the finding count** if each raw hit became a top-level
finding. The two-type model prevents this **only because the merger folds hits
under a weakness instead of emitting peers.** This is the single most important
merger change; without it the model inflates counts.

`merge_threats.py` already consolidates (`_dedupe_exact:690`, `(CWE,STRIDE,
cwe-family)` grouping `:748`, `_match_consolidation_group` +
`consolidation-groups.yaml` `:853` → collapses N per-component findings into
`instances[]`). Required adjustments:

1. **Grouping key** changes from `(CWE, STRIDE, family)` to **`(weakness_class,
   scope)`** with the **weakness as the parent**. All SQLi sites in a
   scope → one "Insecure SQL handling" weakness carrying `instances[]`
   (confirmed-exploitable) + `practice_evidence[]` (non-exploitable sites).
2. **Reconciler (the §4b fold) lives here** — the arch-coverage design signal
   collapses into that same weakness heading, never a separate hypothesis.
3. **Count is post-consolidation:** the headline counts **weaknesses +
   confirmed-vulnerability instances**, never each raw practice site. 50
   concatenation sites → **1** weakness (design-risk, possibly Critical), not 50
   findings.

**Net effect:** count goes *down* for the redundant case (juice-shop "2 findings
+ 1 hypothesis" → "1 weakness + 2 instances") and stays controlled for the
pervasive case ("everywhere unsafe" → 1 severe weakness, not N findings). It only
explodes if the merger is left unchanged.

**Open merger decision — scope granularity:** does a pervasive weakness collapse
**app-wide into one** ("no parametrized layer — 5 components affected") or **one
per component**? App-wide-when-systemic is better for both count control and the
"systemically broken" verdict; existing `-per-component` groups default to
per-component and would need a systemic-override. Resolve in the implplan.

### 4e. Design-weakness severity (design-risk, not CVSS)

A design weakness with **zero** confirmed instances can still be the single
biggest threat to the app (author's case: "input processed unsafely everywhere,
non-standard"). Severity must therefore **scale, not cap flatly at High.**

- **Same Critical/High/Medium/Low scale**, but tagged `severity_basis:
  design-risk` (vs `confirmed`) so the reader never confuses "the design is
  severely deficient" with "a proven exploit exists". No CVSS either way.
- **Driven by three observable inputs** (all already available in the pipeline —
  no new judgement):
  1. **Pervasiveness / spread** — how much of the app the absent control
     affects: single component vs app-wide. (Signal: theme cluster
     `finding_count` / component spread, `architect_structural_checks.py:659`;
     `controls_absent_evidence` hit breadth.)
  2. **Implementation strategy** — `none`/`home-grown` app-wide is worse than an
     isolated gap or a `standard-misused` single spot.
  3. **Asset exposure** — does the ungoverned surface reach a real actor /
     crown-jewel? (Signal: `critical-criteria.yaml`, breach-distance.)
- **Critical design-risk** is legitimate when pervasive **and** (`home-grown` |
  `none`) **and** exposed — a wholesale-missing control on an exposed app. This
  is defensible from observable facts; it is **not** the speculative "might be
  vulnerable" that §0 bans.
- **Honesty guardrail against alarmism:** design-risk Critical still requires the
  observable absent-control signal (§0), still shows no CVSS, and is visually
  distinct from confirmed-exploit Criticals. It claims a deficient *design*, not
  a proven *exploit*.
- **Where it surfaces:** kept out of the CVSS-scored headline finding count, but
  **eligible to rank at the top of the Layer-2 systemic verdict and Top Systemic
  Risks** — which is exactly where "everything is unsafe" belongs, above the
  isolated confirmed findings.

---

## 5. Layer 2 — systemic posture verdict (answers "incidental vs broken")

The join that does not exist today. Deterministic, built on existing data:

**Fuse** per `architectural_theme` (= security principle):
`findings-in-theme × control-effectiveness (adequate/partial/weak/missing) ×
recurrence (instance count, spread across components) × implementation_strategy`

→ **a scored principle-violation row**, e.g.:

```
InputValidation      VIOLATED (systemic)   — no central validation; 2 proven SQLi + 1 XSS across 3 components; home-grown
Authorization        WEAK                  — per-handler checks; 1 proven IDOR; home-grown
SecretManagement     ADEQUATE              — env-based, no hardcoded secrets
```

Deliverables:
- A **"Security Principles" verdict table** (deterministic, scored) — the thing
  that tells the reader "the developer systematically ignored input validation
  and least-privilege," not just "here are 12 bugs."
- A **"Top Systemic Risks"** ranked section keyed on **recurrence/principle**,
  complementing the existing per-finding "Top Threats".
- Generalize **`meta_findings`** from the 3 supply-chain buckets to any
  principle theme, **and wire the missing renderer** (the absent composer
  consumer is a latent bug regardless of this proposal).
- The existing LLM `verdict` blockquote + `architectural_anti_patterns` callout
  stay, but are now **backed by** the scored table (the LLM narrates a computed
  verdict rather than inventing one).

`implementation_strategy` feeds directly in: a `home-grown` layer with proven
instances is the strongest "principle ignored" signal.

---

## 6. Contract impact (bidirectional — AGENTS.md §4/§7)

- **Schemas**: add `evidence_tier` + `implementation_strategy` to `threats[]`
  (`stride.schema.yaml`, `threats-merged.schema.yaml`,
  `threat-model.output.schema.yaml`); new `weakness_class` register object;
  extend `meta_findings.category` enum beyond 3; new principle-verdict fragment
  schema.
- **Producers**: `merge_threats.py` (reconciler + class folding),
  `arch_coverage_to_threats.py` (route hypotheses into the reconciler, not a
  separate list), new `crypto-checks.yaml` + `source-auth-checks.yaml` rules,
  recon misuse Cat-N, a new Layer-2 posture-fusion script.
- **Consumers**: `compose_threat_model.py` (class-heading render, principle
  table, Top Systemic Risks), plus the `meta_findings` renderer that is missing.
- **Guards**: `data/required-permissions.yaml` + `tests/test_check_permissions.py`
  for any new scanner invocation; QA checks for the new fields; golden regen.
- **CVSS/severity guardrails must move from "which list" to "which tier"** —
  `inferred` items stay non-CVSS, capped, out of headline counts. Do not
  regress the false-positive discipline the two-list split currently enforces.

---

## 7. Risks / open questions

1. **Headline-count honesty.** RESOLVED (§9): all three types count as valid
   findings, shown as **one total + a basis breakdown** ("12 findings — 5
   confirmed-exploitable · 4 implementation weaknesses · 3 design weaknesses").
   The breakdown is what keeps it honest; the single total gives the "overall
   load" number. Confirmed-exploitable is the only CVSS-scored subset.
2. **`indicator` promotion pressure.** Guard against everything drifting to
   `proven`; keep the evidence-tier mapping strict and QA-checked.
3. **Crypto false positives.** md5/`Math.random()` have legitimate non-security
   uses — the crypto rule pack needs counter-patterns (e.g. non-security hashing)
   like the existing INJ/AUTHZ rules.
4. **Principle scoring formula.** How to weight recurrence vs control-effectiveness
   vs strategy into VIOLATED/WEAK/ADEQUATE — needs a calibrated, documented
   rubric (not a magic number), validated against juice-shop + the synthetic
   fixture.
5. **Migration.** Reconciler + evidence_tier can land first (fixes the juice-shop
   contradiction immediately) before Layer 2. Sequence: (a) reconciler + folding
   + evidence_tier, (b) crypto/path/xxe rule packs + implementation_strategy,
   (c) Layer-2 posture verdict + meta_findings generalization + renderer.

---

## 8. Suggested sequencing

1. **P1 (fixes the reported bug):** Layer-1 reconciler + class folding +
   `evidence_tier` on `threats[]`. Kills the "proven SQLi + SQLi hypothesis"
   contradiction. Re-enables a coherent replacement for the disabled §6.2 table.
2. **P2:** `implementation_strategy` axis — recon lib inventory + Cat-N misuse
   detectors (generalize the Cat-9 OAuth pattern to authn/crypto/input-val).
3. **P3:** crypto-checks.yaml + path-traversal/XXE rules (close deterministic
   gaps).
4. **P4:** Layer-2 posture verdict (principle fusion, Top Systemic Risks,
   meta_findings generalization + missing renderer).

---

## 9. Locked decisions (2026-07-12, author)

1. **Two finding types only** — (A) confirmed vulnerability (CVSS, appears as an
   instance) and (B) weakness (`kind: design|implementation`, references its
   instances, valid with zero instances). No "suspected/indicator" tier.
   Speculation is dropped, never a finding. "Hypothesis" is not a user-facing
   word/category.
2. **Headline count** — one total **+ basis breakdown** ("N findings — X
   confirmed-exploitable · Y implementation · Z design"). All three count;
   confirmed-exploitable is the only CVSS-scored subset. Count is
   post-consolidation (§4d-bis).
3. **Design-weakness ranking** — a pervasive design weakness with **zero**
   confirmed instances **may be the report's #1 risk** (design-risk Critical),
   above confirmed-exploitable findings. Rendered as design-risk (no exploit
   claim), never as a hypothesis.
4. **Scope of the first implplan** — **the full model incl. Layer-2 verdict**
   (P1–P4 as one deliverable). Internal build order still follows §8 for safety,
   but all four land in the same plan.

Open (resolve in implplan): merger scope-granularity (§4d-bis);
Layer-2 principle-scoring rubric (§7.4).
