# Phase Group: Architecture & Analysis (Phases 3–8)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 3: Architecture Modeling

### Section and sub-section introductory sentences (mandatory)

The reader of a static threat-model report cannot zoom into diagrams or click around to discover what they are looking at. **Every top-level section, every sub-section, and every diagram MUST be introduced by at least one sentence of prose before the first table, code block, or diagram.** This is a hard requirement, not a stylistic suggestion.

**1. Top-level sections (`## N. Title`)** — open with 1–3 sentences explaining *what* this section contains and *why* it matters for the security assessment. Write the intro before any subsection heading, table, or diagram. Examples:

- **Section 2 (Architecture Diagrams):** "The following diagrams model the system architecture at different abstraction levels using the C4 model. Security-relevant aspects are highlighted in red."
- **Section 3 (Security-Relevant Use Cases):** **STUB ONLY** — this section is now a two-line redirect to Section 9, which holds the attack walkthroughs. The orchestrator writes the stub verbatim (see "Section 3 stub template" below) and does **not** emit an intro sentence of its own.
- **Section 4 (Assets):** "The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to the threats that target them."
- **Section 5 (Attack Surface):** "All identified entry points through which an attacker can interact with the system, split by whether authentication is required."
- **Section 6 (Trust Boundaries):** "Trust boundaries mark transitions between different trust levels. Weaknesses at these boundaries are primary sources of security risk."
- **Section 7 (Identified Security Controls):** Start with a paragraph prefixed `**Gap summary:**` listing the 3–5 most critical control gaps before the controls table.
- **Section 8 (Threat Register):** Start with risk methodology note and Risk Distribution block (see Phase 9 — Section 8 layout).
- **Section 9 (Attack Walkthroughs):** "The sequence diagrams below trace each Critical finding from initial attacker action to full exploitation. Every diagram is anchored to its `T-NNN` in the Threat Register and shows the current vulnerable behaviour alongside the post-mitigation flow." (See phase-group-architecture.md → "Phase 4: Attack Walkthroughs" for the full rendering contract.)
- **Section 10 (Mitigation Register):** "Prioritised measures to address identified threats. Each mitigation lists the threats it addresses, the requirements it fulfils, the relevant Blueprint section, its rollout priority (P1–P4) and concrete implementation guidance."
- **Section 11 (Out of Scope):** "Areas deliberately excluded from this assessment, including accepted risks and items requiring separate analysis."

### Section 3 stub template

Section 3 was formerly "Security-Relevant Use Cases" and held attack sequence diagrams. Those diagrams belong adjacent to the Threat Register — they depend on threat enumeration, not on architecture — so they have been **moved to Section 9**, which used to be a stub itself. Section 3 is now the mirror-image stub. The section exists only to preserve the `#3-security-relevant-use-cases` anchor and to redirect readers. Render it **verbatim** as:

```markdown
## 3. Security-Relevant Use Cases

_Moved. Attack walkthroughs (sequence diagrams showing how each Critical finding is exploited) now live in [Section 9 — Attack Walkthroughs](#9-attack-walkthroughs), directly after the Threat Register. This section is intentionally empty — use-case-style design documentation is not part of this report's scope._
```

**Rules for the Section 3 stub:**

- Always present — even in `quick` assessments. The stub is 2 lines of body plus a heading; no token cost worth skipping.
- The body is exactly one italicised paragraph. No tables, no bullets, no Mermaid blocks, no `### 3.x` sub-sections.
- The internal link target `#9-attack-walkthroughs` is mandatory (not `#9-critical-findings` — Section 9 has been renamed alongside this move).
- **Do NOT add an intro sentence before the stub.** The body paragraph IS the intro.

**2. Section 2 sub-sections (`### 2.x Title`)** — every C4 sub-section (2.1 System Context, 2.2 Containers, 2.3/2.4 Technology Architecture, 2.x Security Architecture Assessment) MUST open with at least one sentence telling the reader what the diagram shows and at which abstraction level. Examples:

- **2.1 System Context:** "The Context view shows who interacts with the system, which external services it depends on, and which trust zones each actor sits in. Red boxes mark components that expose attack surface."
- **2.2 Containers:** "The Container view zooms into the deployable units. The critical observation here: <one-sentence security takeaway specific to this system>."
- **2.x Technology Architecture:** "This diagram shows the runtime middleware stack from top to bottom. Nodes coloured red carry at least one Medium-or-higher threat from the register."
- **2.x Security Architecture Assessment:** "The assessment below evaluates structural patterns rather than individual code defects. Each pattern is rated as present, partial, or absent."

**3. Section 9 sub-sections (`### 9.x — T-NNN title`)** — every attack walkthrough in Section 9 MUST open with at least one sentence telling the reader which Critical finding is being walked through, which component is attacked, and which attacker position is required (unauthenticated / authenticated / internal). The T-NNN in the sub-section heading must link to the Threat Register row. Examples:

- "**T-002 · SQL Injection in Login.** Unauthenticated attacker, Auth Service component. This walkthrough shows how a single crafted email parameter bypasses authentication and yields an admin session."
- "**T-006 · RCE via safeEval in B2B Order.** Authenticated B2B customer, Order Service component. This walkthrough shows how a crafted `orderLinesData` payload escapes the `notevil` sandbox via prototype pollution."

**4. Key takeaway after every diagram (Sections 2 and 9)** — directly below each Mermaid block (after the closing ` ``` `) the orchestrator MUST add a single bold-prefixed sentence:

```
**Key takeaway:** <one sentence — what is the reader supposed to remember about this diagram?>
```

The takeaway is not a caption — it is a security observation. Examples:

- "**Key takeaway:** Every external request — including the attacker — reaches the monolith directly on port 3000, with no API gateway and no WAF in front."
- "**Key takeaway:** The BFF pattern is absent — the SPA holds JWT tokens in localStorage, so any XSS anywhere on the page steals the session."
- "**Key takeaway:** The XML upload endpoint is the only path that touches the file system; disabling `noent` here closes the file disclosure vector entirely."

**Rules:**

- Adapt every sentence to the specific system — do not use the examples verbatim
- Never put two diagrams back-to-back without an intro sentence and a Key takeaway between them
- The intro sentence and the Key takeaway are *separate* — the intro tells the reader *what they are about to see*, the takeaway tells them *what to remember after they have seen it*
- A diagram with no Key takeaway is treated by the QA reviewer as incomplete and will be flagged

### Architecture modeling

**⚠ Batched-diagram rule (mandatory):** All C4 diagrams for a given complexity tier MUST be composed in a **single pass** after reading `.recon-summary.md` once. Do not re-read the recon summary between diagrams. Compose the full set (Context, Containers if Moderate+, Components if Complex, Technology Architecture, Security Architecture Assessment) in working memory, then write them as one contiguous block into Section 2 of `threat-model.md`. The per-diagram STEP_START log entries still fire in sequence (so users see progress), but the underlying data fetches happen exactly once.

Derive the system's architecture from code and config. Determine complexity:

- **Simple** (monolith, single service): one architecture diagram
- **Moderate** (multiple services, clear layers): Context + Container diagrams
- **Complex** (microservices, many bounded contexts): Context + Container + Component diagrams

**DIAGRAM_DEPTH override:** The `DIAGRAM_DEPTH` variable (from `--assessment-depth`) can restrict diagram output regardless of detected complexity:

| DIAGRAM_DEPTH | C4 diagrams produced | Attack walkthroughs (Phase 4 → Section 9) |
|---------------|---------------------|--------------------------------------------|
| `minimal` | Context + Technology Architecture only (skip Containers/Components even if Complex) | Up to 3 — top 3 Critical findings only, no walkthroughs for High/Medium/Low |
| `standard` | By detected complexity tier (default behavior) | Up to 5 — one per Critical finding, ordered to match `## Critical Attack Chain` nodes |
| `extended` | By detected complexity tier + additional drill-down for security-critical services | Up to 5 — full curation + `Note over` mitigation commentary in each `else` branch |

Section numbering by complexity tier (no gaps):

| Complexity | Sections | Numbers |
|------------|----------|---------|
| Simple | Context · Tech Arch · Security Assessment | 2.1 · 2.2 · 2.3 |
| Moderate | Context · Containers · Tech Arch · Assessment | 2.1 · 2.2 · 2.3 · 2.4 |
| Complex | Context · Containers · Components · Tech Arch · Assessment | 2.1 · 2.2 · 2.3 · 2.4 · 2.5 |

Use C4 model conventions. Every node must include concrete technology details:
```
"<Component Name>\n<Framework + Version>\n<Runtime / Language>\n<Deployment: platform/env>"
```

All diagrams: Mermaid `graph TD`, max 4–5 nodes per subgraph, edges with protocol/route labels, trust boundaries as subgraphs with **plain text labels** — no emoji prefix (`🌐` / `🔶` / `🔒` / `🔐`). The label text is sufficient; the emoji adds no information and degrades accessibility.

### Component-ID annotation contract (mandatory for annotator)

Every Mermaid node that represents an **inventoried component** — i.e. a component that will be analysed by a STRIDE analyzer in Phase 9 — MUST carry a stable ID annotation so the post-Phase-9 diagram annotator can attach threat badges, severity classes, and click links. The rules are:

1. **Label form is fixed.** Write the node as square-bracketed, double-quoted label: `NodeId["<label text with <br/> separators>"]`. Other shapes (`(...)`, `((...))`, `{...}`, `[/.../]`) are allowed for non-component decoration only (actors, external systems, trust-zone labels) — the annotator will skip them.
2. **Comment on the line directly above.** Prefix each inventoried-component node line with a Mermaid comment on its own line:
   ```
   %% component: <stable-component-id>
   RestApi["REST API<br/>Express 4<br/>Node 20"]
   ```
3. **The `<stable-component-id>` MUST match** the `component_id` that the STRIDE analyzer will use for this component — the same ID that becomes the filename suffix in `$OUTPUT_DIR/.stride-<id>.json`. Consistency across Phase 3 (architecture) and Phase 9 (STRIDE dispatch) is mandatory; mismatch means the annotator silently skips the node.
4. **One comment per node.** Do not share a comment across multiple nodes and do not annotate nodes that are actors (`Attacker`, `User`) or externals (`Auth0`, `Stripe`) — those do not have STRIDE analysis and therefore have no threats to surface.
5. **Same component, multiple diagrams.** When the same component appears in Context, Containers, and Components views, emit the `%% component: <id>` comment above every occurrence. The annotator then annotates each view consistently.
6. **Trust zones and subgraph labels** are not components — never annotate them.

Example (Containers view, moderate complexity):

```
graph TD
    subgraph Internet
        Attacker["Attacker"]
    end
    subgraph DMZ
        %% component: rest-api
        RestApi["REST API<br/>Express 4<br/>Node 20<br/>Docker"]
    end
    subgraph Private
        %% component: auth-service
        Auth["Auth Service<br/>Passport.js<br/>Node 20<br/>Docker"]
        %% component: db
        DB[("PostgreSQL 15<br/>Managed RDS")]
    end
    Attacker -->|HTTPS| RestApi
    RestApi -->|REST| Auth
    Auth -->|SQL| DB
```

The annotator runs after Phase 9 and will transform the annotated nodes (`RestApi`, `Auth`, `DB`) by appending a severity badge, assigning a severity class, and attaching a click link to the first Critical/High threat row in Section 8. Nodes without the `%% component:` comment (`Attacker`) remain untouched.

Write Security Architecture Assessment last: Architecture Patterns table, Trust Model Evaluation, Auth & Authz Architecture, Key Architectural Risks, Overall Rating.

### Cross-Cutting Architecture Findings (mandatory sub-section inside Security Architecture Assessment)

After the Architecture Patterns table and the Key Architectural Risks table, the Security Architecture Assessment MUST include a sub-section **Cross-Cutting Architecture Findings** that explains each structural security concern in prose. This sub-section is where architects and senior engineers get the *reasoning* — the tables above are the scan-ready summary; this sub-section is where the report actually earns its architecture-review claim.

**Why this sub-section exists:** The phase-group files used to scatter structural concerns across Section 2.4 (one-line table rows), Section 6 (trust boundary weaknesses), Section 7 (per-domain control ratings) and the threat register. A reader looking for "how is authentication structured, and what is wrong with it?" had to stitch three fragments together. The Cross-Cutting Architecture Findings sub-section replaces that with a single authoritative paragraph per theme.

**Mandatory themes** — always emit all six, even when one is "no systemic finding":

1. **Secret Management** — inventory of every hardcoded, env-var-only, or rotation-incapable secret; where the secret is loaded in code; the token-signing / key-management lifecycle; rotation capability; whether secrets leak via logs, error messages, metrics, or artifacts.
2. **Authentication** — the full trust chain (who issues, who validates, which library/version); token lifecycle (create → transmit → store → validate → refresh → revoke — revocation is almost always missing and must be called out); session management (sliding expiry, concurrent-session limits, anomaly detection); MFA architecture; OAuth/OIDC integration if present (flow type, known risks).
3. **Authorization & Access Control** — the underlying pattern (RBAC, ABAC, ACL, or ad-hoc-per-route); role hierarchy and where roles are defined; coverage observation (how many of the authenticated endpoints actually enforce ownership or role checks vs. relying solely on `isAuthenticated`); privilege-escalation pathways; whether a centralized authorization policy exists or every route handler re-implements checks.
4. **Input Validation & Output Encoding** — where in the request flow validation happens (gateway, middleware, per-route); whether there is a schema-validation layer or each handler validates ad-hoc; categorization of input-handling defects into *parameterization gaps* (SQLi/NoSQLi), *eval sinks* (SSTI/RCE), *parser hardening gaps* (XXE/Zip-Slip), and *output-encoding gaps* (XSS, log injection); whether sanitizer bypasses are isolated or spread across the frontend.
5. **Separation & Isolation** — network segmentation (single host vs. tiered), process isolation (does eval run in the same process as the token signer?), data-tier separation (in-process DBs, connection-level auth, encryption at rest), frontend/backend separation (BFF presence/absence, static files served by the same process as the API).
6. **Defense-in-Depth** — what sits in front of the application (WAF, API gateway, rate limiting, bot protection), what sits behind (observability, anomaly detection, structured security-event logging), and which of those layers are missing. Call out single-point-of-failure boundaries explicitly.

**Writing rules for each theme:**

- **Length:** 200–300 words per theme. One-line bullets are forbidden in this sub-section — the whole point is prose depth. If a theme genuinely has no finding, write one sentence saying so and *explaining why the system is sound in that area* (e.g. "Secret management is handled exclusively via HashiCorp Vault; all six secrets identified in recon are loaded from Vault paths with a rotation policy of 90 days. No hardcoded secrets were found in recon Section 7.12, and no secrets appear in logs or metrics. No systemic finding.").
- **Structure per theme:** Open with the *current state* in one or two sentences (what the architecture actually does today). Follow with *structural defects* (what is architecturally wrong, not just buggy code). Then *impact* (what capability this gives an attacker or what the defect enables). Then *target architecture* (one or two sentences on what the system should look like). Close with *linked threats* as clickable `[T-NNN](#t-NNN)` references — these threats are the concrete instantiations of the structural finding, not the finding itself.
- **No duplication of threat-register prose.** This sub-section does *not* re-describe individual threats. It describes the *pattern* the threats emerge from. If a reader wants the specific `routes/login.ts:34` reference, they click the T-NNN link.
- **File references** are allowed and encouraged *only* for pinning architectural statements — e.g. "The private key is loaded in [lib/insecurity.ts:27](vscode://file/...) and passed directly to `jsonwebtoken.sign()`, making the signer and the verifier live in the same process." Do not sprinkle file references for every sentence.
- **Consolidation rule for recurring defects:** When three or more threats share the same root cause (the classic example: three IDOR findings on different endpoints, all caused by the same missing ownership-check pattern), the Cross-Cutting finding becomes the *systemic* statement and links all three threats. The threats remain individual rows in the register — but the *architectural diagnosis* lives here, not repeated three times inside T-013 / T-017 / T-020.
- **Link back from the register:** Each threat that participates in a Cross-Cutting finding should surface that connection via its `Controls in Place` or `Threat Scenario` cell (e.g. "Systemic authorization gap — see Cross-Cutting Architecture Findings → Authorization & Access Control"). This is a one-sentence back-reference, not a full description.

**Structure in the rendered report:**

```markdown
#### Cross-Cutting Architecture Findings

The following six themes each synthesize the structural security concerns observed across the code base. Individual code-level instances appear as threats in Section 8; this sub-section explains the underlying architectural pattern that produces them.

##### 1. Secret Management

<200–300 words of prose — current state, structural defects, impact, target architecture, linked threats>

##### 2. Authentication

<200–300 words>

##### 3. Authorization & Access Control

<200–300 words>

##### 4. Input Validation & Output Encoding

<200–300 words>

##### 5. Separation & Isolation

<200–300 words>

##### 6. Defense-in-Depth

<200–300 words>
```

The sub-section is numbered with `#####` (H5) so it nests cleanly inside `#### Cross-Cutting Architecture Findings` (H4) inside the Security Architecture Assessment (H3).

## Phase 4: Attack Walkthroughs (renders Section 9)

> **⚠ Section assignment changed.** Phase 4 used to render its diagrams into `## 3. Security-Relevant Use Cases`, between the architecture and the assets. That position was wrong: attack walkthroughs depend on the threat enumeration in Section 8, so a reader at Section 3 had not yet seen what was being attacked. Phase 4 now renders into `## 9. Attack Walkthroughs`, positioned directly after the Threat Register and before the Mitigation Register. Section 3 is a two-line stub pointing here (see Section 3 stub template above). The Phase number stays 4 for orchestrator-ordering reasons — Phase 4 still runs between Phase 3 (architecture) and Phase 5 (assets) because it needs the architectural context — but its **output target** is Section 9.

**⚠ Batched-diagram rule (mandatory):** Phase 4 composes all applicable sequence diagrams in a **single pass** using the data already in working memory from Phase 2 (recon) and Phase 3 (architecture), plus the pre-estimate of Critical threats from Phase 9 (see "Curation — Critical only" below). Do not re-read source files per diagram — the recon scanner's Section 7.1 (auth), 7.2 (authz), 7.4 (input handling), 7.9 (OAuth), and 7.10 (SPA/BFF) provide the flow-relevant file:line references. Write all sequence diagrams as one contiguous Section 9 block.

> **⚠ Phase-ordering caveat:** Phase 4 runs before Phase 9, so Critical T-IDs do not exist yet at Phase 4 time. Resolve this with **deferred rendering**: Phase 4 composes placeholder walkthroughs keyed by a stable internal slug (e.g. `sqli-login-bypass`, `xxe-upload`, `b2b-eval-rce`) from recon evidence, and Phase 11 (Finalization) swaps placeholder keys for the real `T-NNN` assigned in Phase 9. If the stable slug never maps to a Critical finding in Phase 9 (because the STRIDE analyzer rated it High instead), the walkthrough is dropped entirely during Phase 11. This avoids producing walkthroughs for findings that did not reach Critical severity.

### Content and diagram type

Each walkthrough is a Mermaid `sequenceDiagram` block that traces one Critical finding from attacker action to exploitation outcome. The diagram MUST use the `alt`/`else` structure — but the two branches now carry fixed semantics:

- **`alt` branch** = current vulnerable behaviour (`Current state — T-NNN`). This is the attack path.
- **`else` branch** = post-mitigation behaviour (`After M-NNN — <short mitigation name>`). This is the fix.

The "normal vs attack" pattern from the old spec is **deleted**. Section 9 is about how critical findings are exploited and fixed, not about showing legitimate happy paths for unrelated flows.

Annotate arrows with actual HTTP methods/routes. Use component IDs in `participant … as` lines that match the STRIDE component IDs.

### Curation — Critical only, max 5

The previous spec emitted one diagram per recon category (auth, authz, input validation, …) regardless of how many findings existed. That produced bloated Section 3 content even for systems with only 1–2 real Critical threats. The new rule is:

- **Count Critical findings after Phase 9 merge.** Call that `CRIT_COUNT`.
- **`CRIT_COUNT == 0`** → Section 9 is a 2-line stub: `_No critical-severity attack walkthroughs — the highest-severity findings are documented in [Section 8](#8-threat-register)._`. No Mermaid, no sub-sections. Section 3 stub still points here.
- **`CRIT_COUNT == 1`** → Section 9 has exactly one walkthrough, for the single Critical finding.
- **`CRIT_COUNT >= 2`** → One walkthrough per Critical finding, in the **same order as the nodes of the `## Critical Attack Chain` Mermaid diagram** (after the Management Summary). This lets a reader jump from a chain node to the detailed walkthrough. Cap at **5** — if there are more than 5 Criticals, keep the 5 that appear as nodes in the chain diagram; document the skipped ones with a trailing footnote `_N additional Critical findings (T-NNN, T-NNN, …) are documented in Section 8.1 without a dedicated walkthrough._`

**Phase 4 does not add walkthroughs for High-, Medium-, or Low-severity findings.** Non-Critical findings are surfaced via the Section 8 table only. If a reviewer wants to understand a High finding in detail, they follow the link from Section 8.2 into the per-threat row; no sequenceDiagram is generated automatically.

### DIAGRAM_DEPTH interaction

| DIAGRAM_DEPTH | Phase 4 behaviour |
|---------------|-------------------|
| `minimal` (quick) | Max 3 walkthroughs — take the top 3 Criticals by severity+order |
| `standard` | Max 5 walkthroughs — full curation rule above |
| `extended` | Max 5 walkthroughs — full curation rule, plus every `else` branch carries an explicit `Note over` describing exactly which code change implements the mitigation (one sentence, tied to the M-NNN in Section 10) |

### `alt`/`else` — fixed semantics

Every sequence diagram in Section 9 MUST include an `alt`/`else` block with both branches populated. The labels and content are constrained:

- **`alt` branch label:** `Current state — T-NNN` (where `T-NNN` is the Critical finding's ID after Phase 11 placeholder swap)
- **`else` branch label:** `After M-NNN — <short mitigation title>` (where `M-NNN` is the primary mitigation from Section 10)
- Both branches must contain at least one message arrow. Empty branches are flagged by the QA reviewer.
- The `alt` branch is the attack path. The `else` branch is the fix. This assignment is **not** interchangeable — the QA reviewer checks this ordering because the annotator relies on the attack branch being `alt`.

Example (placeholder → `T-002` after Phase 11 swap):

```
sequenceDiagram
    %% components: rest-api, auth-service
    %% stride: S, T
    participant A as Attacker
    participant API as Express API
    participant DB as PostgreSQL
    A->>API: POST /rest/user/login (email=' OR 1=1--)
    alt Current state — T-002 %% attack-path
        API->>DB: SELECT * FROM Users WHERE email='...' (raw concat)
        DB-->>API: returns admin row
        API-->>A: 200 + JWT for admin
    else After M-002 — parameterized query
        API->>DB: SELECT * FROM Users WHERE email=$1 (bound)
        DB-->>API: no match
        API-->>A: 401 Unauthorized
    end
```

### Sequence diagram annotation contract (mandatory for annotator)

The Phase-10 sequence annotator (`plugin/scripts/annotate_sequences.py`) injects a `Note over` line into the attack branch of every sequence diagram, listing the top 3 matching threats by severity (format: `T-NNN (CWE-X)`, comma-separated; overflow shown as `+N more → §8`). For that to work, Phase 4 MUST emit three metadata comments on every `sequenceDiagram`:

1. **`%% components: <id>, <id>, …`** — placed on its own line directly after the `sequenceDiagram` keyword. Lists the stable component IDs involved in the flow. These IDs must match the `component_id` values used by the STRIDE analyzer (same as `%% component:` in Phase 3 and `.stride-<id>.json` filenames). The annotator filters threats by this list — components not listed here are excluded from the diagram's Note.
2. **`%% stride: <letters>`** — on the next line. A comma-separated list of single-letter STRIDE codes that define which threat categories this flow addresses. The mapping is fixed:
   - `S` → Spoofing
   - `T` → Tampering
   - `R` → Repudiation
   - `I` → Information Disclosure
   - `D` → Denial of Service
   - `E` → Elevation of Privilege

   A login flow is typically `S, T` (credential forgery, auth bypass). An input-validation flow is typically `T, I` (injection, leakage). An authorization flow is typically `E` (privilege escalation). Pick every letter that honestly applies — threats outside the declared categories are filtered out of this diagram's Note, so narrow lists mean narrow annotations.
3. **`%% attack-path`** — a trailing comment on the `alt` or `else` line whose branch represents the attack/vulnerable flow. Exactly one branch per `alt` block must carry this marker. Without it, the annotator cannot tell which branch is the attack path and will skip the diagram with a warning.

**Example with all three markers:**

```
sequenceDiagram
    %% components: rest-api, auth-service
    %% stride: S, T
    participant A as Attacker
    participant API as Express API
    participant DB as PostgreSQL
    A->>API: POST /rest/user/login (email=' OR 1=1--)
    alt Current state — T-002 %% attack-path
        API->>DB: SELECT * FROM Users WHERE email='...' (raw concat)
        DB-->>API: returns admin row
        API-->>A: 200 + JWT for admin
    else After M-002 — parameterized query
        API->>DB: SELECT * FROM Users WHERE email=$1 (bound)
        DB-->>API: no match
        API-->>A: 401 Unauthorized
    end
```

After Phase 10 annotation this becomes:

```
    alt Current state — T-002 %% attack-path
        %% anno-seq-start
        Note over A,DB: T-002 (CWE-89), T-001 (CWE-321)
        %% anno-seq-end
        API->>DB: SELECT * FROM Users WHERE email='...' (raw concat)
        ...
```

**Rules:**

- The three metadata comments are **mandatory** on every sequence diagram the orchestrator expects to be annotated. Missing markers do not break the pipeline — the annotator logs a warning and leaves the diagram unchanged.
- The `%% components:` list must not contain actor labels (`Attacker`, `User`) or externals (`Auth0`, `Stripe`) — only STRIDE-analyzed components.
- Do not hand-write `%% anno-seq-start` / `%% anno-seq-end` fences — they are annotator-owned and will be overwritten on re-run.
- A diagram whose flow touches components that end up with zero matching threats still passes annotation — it simply receives no Note injection (the `anno-seq-*` fence is empty and the attack branch is untouched).

## Phases 5–7: Combined single-pass execution (mandatory)

**⚠ Token-saving rule: Phases 5, 6, and 7 MUST run as a single combined pass, not three separate phases.** All three phases read the same recon baseline (`$OUTPUT_DIR/.recon-summary.md` Sections 5, 7, 9, 10) and produce sections that reference each other. Running them serially triples the recon re-read cost without adding information.

**Combined execution protocol:**

1. **Read `.recon-summary.md` once** at the start of Phase 5 and keep the parsed content in working memory for Phases 5, 6, and 7.
2. **Log all three `PHASE_START` entries** in a single batched Bash call (Phase 5, 6, 7) so the log reflects the combined execution. Same for the three `PHASE_END` entries at the end.
3. **Iterate the recon data once**, emitting rows into three in-memory tables simultaneously:
   - Phase 5 assets (Data/Code/Infra/Availability) derived from recon Section 10
   - Phase 6 entry points (split by auth requirement) derived from recon Section 7.11 + 7.1 + Section 9
   - Phase 7 trust boundaries derived from recon Section 5 (deployment) + Section 9 (components) + browser↔server when a frontend is present
4. **Issue at most one combined route grep** (see Phase 6 — single combined grep) if recon Section 7.11 is insufficient. This grep covers Phase 6 entirely; do not issue additional greps during Phase 5 or Phase 7.
5. **Emit the three sections in the final report in their canonical order** (Section 4 Assets, Section 5 Attack Surface, Section 6 Trust Boundaries) — the combined execution only changes *how* they are computed, not *how* they are rendered.

**Rules:**
- Never re-read `.recon-summary.md` between Phases 5, 6, and 7 — one read at the top, reused throughout
- Do not dispatch sub-agents during the combined pass
- Progress substep counters continue to show `[k/2]`, `[k/3]`, `[k/N]` per phase in the log so users still see per-phase progress
- If the orchestrator runs Phase 5 in isolation (e.g. incremental mode where only one phase is being refreshed), the combined-pass rule does not apply — read recon data once for that single phase

---

## Phase 5: Asset Identification

**⚠ Token-saving rule: Enrich the pre-populated list from recon — do NOT re-discover assets from source files.**

Read **Section 10 (Preliminary Asset Candidates)** of `$OUTPUT_DIR/.recon-summary.md`. The recon-scanner has already derived a first-pass inventory from schemas, manifests, deployment artifacts, and config files. Start from that table and enrich it:

1. Promote every `_none detected_` placeholder to a real row only if Phase 2/3/4 surfaced concrete evidence the recon-scanner missed (rare — document the evidence file:line inline).
2. Confirm every `(preliminary)` classification. If the Phase 2 evidence supports it, drop the suffix. If not, read **one** referenced file to verify and then re-classify.
3. Merge near-duplicate rows (e.g., "User PII" + "User profile" → one row) and split overly coarse rows (e.g., "Database" → "Postgres primary" + "Redis session store") when the Phase 2 deployment section shows distinct tiers.
4. Populate `Linked Threats` after Phase 9 — leave empty at the end of Phase 5.

**Do not re-grep** for PII patterns, schema files, or config files — the recon-scanner ran those greps in Phase 2 and the results are in Section 10 with file:line evidence. If the recon Section 10 is empty (thin proxy, no data layer) the Phase 5 table may be empty aside from infrastructure and availability assets.

Categories to cover (always emit all four, even if one is empty): Data (PII, credentials, financial), Code/IP, Infrastructure, Availability.

### Section 4 (Assets) layout — sensitivity legend mandatory

Section 4 in `threat-model.md` MUST start with a one-sentence intro followed by a sensitivity legend before the table. The legend explains what each `Classification` value means so the reader can interpret the column without leaving the document.

```markdown
## 4. Assets

The table below catalogues every asset that requires protection, classified by sensitivity, with cross-references to the threats that target it.

**Classification legend:** **Public** = no protection required · **Internal** = restricted to authenticated users · **Confidential** = restricted to specific roles or owners · **Restricted** = highest sensitivity, regulated or business-critical (passwords, signing keys, payment data).

| Asset | Classification | Description | Linked Threats |
|-------|---------------|-------------|----------------|
| ... |
```

If your project uses different classification labels, adapt the legend wording but keep the four-tier structure. Never omit the legend.

## Phase 6: Attack Surface Mapping

Enumerate all entry points. Use the route data already captured by recon Section 7.11 (exposed routes) and Section 7.1 (auth patterns) as the baseline — do not re-grep what recon has already found.

**Route discovery — single combined grep (mandatory).** When you need to supplement the recon baseline with route handler locations across the detected frameworks, run **one** combined Grep instead of per-framework calls. The pattern below matches Express, Koa, Fastify, Hapi, Spring, JAX-RS, FastAPI, Flask, Django REST, Gin, Echo, Rails, Laravel, ASP.NET Core, and generic annotations in a single pass:

```
pattern: (?:(?:app|router|server)\.(?:get|post|put|patch|delete|options|head|use)\s*\(|@(?:Get|Post|Put|Patch|Delete|Request)Mapping|@Path\(|@(?:app|router)\.(?:get|post|put|patch|delete)|@(?:GET|POST|PUT|DELETE|PATCH)|FastAPI\(|APIRouter\(|@api_view|path\(|url\(|gin\.(?:GET|POST|PUT|DELETE|PATCH)|echo\.(?:GET|POST|PUT|DELETE|PATCH)|resources\s+:|Route::|MapGet|MapPost|MapPut|MapDelete)
glob: "!{node_modules,vendor,dist,build,.git,__pycache__,target,out}/**"
```

Run this grep **once**. Then:
1. Review the results, group by framework (obvious from the file extensions and top-of-file imports)
2. Confirm auth middleware coverage by reading the **top-of-file** of each framework cluster (one Read per framework, not per route)
3. Reuse recon Section 7.11 for accidentally exposed routes (actuator, debug, API docs, admin, metrics) — do not re-grep these
4. OAuth/OIDC callback and redirect_uri audit uses recon Section 7.9 as baseline; only grep further if Section 7.9 is empty but OAuth libraries are present in the manifest

**If recon Section 7.11 already lists route files with match counts**, skip the combined grep entirely — the recon baseline is sufficient for Phase 6. Only run the combined grep when recon missed framework-specific patterns (e.g., a framework not in the recon scanner's 24-category list).

### Section 5 (Attack Surface) layout — split by authentication

The unauthenticated attack surface is the single most important number a security stakeholder reads in the report. Section 5 MUST therefore split entry points into two sub-sections — one for unauthenticated entry points, one for authenticated — and start each with a one-sentence intro.

```markdown
## 5. Attack Surface

Every identified entry point through which an attacker can interact with the system, split by authentication requirement so the unauthenticated surface (the most exposed) is visible at a glance.

### 5.1 Unauthenticated entry points (<N>)

These endpoints can be reached without any credentials and form the primary attack surface from the public internet.

| Entry Point | Protocol/Method | Notes | Linked Threats |
|-------------|----------------|-------|----------------|
| ... |

### 5.2 Authenticated entry points (<N>)

These endpoints require at least a valid session, JWT, or API key. They still represent attack surface for authenticated attackers and account-takeover follow-up.

| Entry Point | Protocol/Method | Required role | Notes | Linked Threats |
|-------------|----------------|---------------|-------|----------------|
| ... |
```

Rules:

- The count `<N>` in each H3 must match the row count of the table directly below it
- An endpoint that is reachable both unauthenticated and authenticated (e.g. cookie token optional) belongs in the unauthenticated table — most-permissive wins
- Sort each table by linked-threat severity descending, then alphabetically by path
- If a sub-section has zero entry points, still emit the H3 with `_None — every entry point on this surface requires authentication._` and skip the table — never omit the heading

## Phase 7: Trust Boundary Analysis

Identify trust level changes: External vs authenticated vs admin, public vs internal vs data tier, container boundaries, third-party integrations.

**Mandatory browser↔server boundary:** If a frontend SPA or client-side application is present, the browser↔server boundary MUST be explicitly identified as a primary trust boundary. The browser is an untrusted execution environment — all data originating from the client (URL parameters, form data, localStorage, postMessage, WebSocket messages) must be treated as attacker-controlled. This boundary shapes STRIDE analysis for the frontend component in Phase 9.

## Phase 8: Identified Security Controls

**⚠ Token-saving rule: Reuse Phase 2 findings — do NOT re-grep what the recon-scanner already found.**

**Single-read rule (mandatory):** Read Section 7 of `$OUTPUT_DIR/.recon-summary.md` **exactly once** at the start of this phase and keep the parsed content in working memory. Iterate the 14 control domains in a single pass against that snapshot — do not re-read `.recon-summary.md` per domain. The recon-scanner has already scanned 24 security categories with file:line references and observations and that data is authoritative for Phase 8.

**When `DIAGRAM_DEPTH=minimal` (quick mode):** Use recon-summary findings as-is for all domains. **Zero active greps are permitted** — rate controls purely from the recon baseline. Any "⚠️ Partial vs ✅ Adequate" judgement call resolves to ⚠️ Partial in quick mode; do not attempt to disambiguate by re-grepping. This saves 7+ turns. Mark the Section 7 heading with `<!-- Controls rated from recon baseline only (quick mode) -->`.

**Otherwise (standard/extended):**

1. For each domain below, find the matching recon-summary subsection (7.1–7.24) in the single parsed snapshot
2. If the recon summary provides file references and observations → **use them as-is** to rate the control. Do NOT re-grep these patterns.
3. **Active greps are restricted to two narrow cases** (cap: at most 2 targeted greps across all domains in standard; at most 4 in extended):
   - The recon summary says "No matches found" for a domain and you need one confirmation grep for the ❌ Missing rating
   - A specific sub-aspect is genuinely not covered by any of the 24 recon patterns (e.g., OAuth PKCE enforcement details) — document which sub-aspect in a one-line comment next to the grep
4. **Disambiguation by grep is forbidden.** A ⚠️ Partial vs ✅ Adequate judgement call is resolved downward to ⚠️ Partial, never upward via a new grep. The recon baseline is the single source of truth for observable presence.

Domains: IAM, Authorization, Data Protection, Secret Management, Frontend Security (framework config, sanitizer usage, DOM sink exposure — use recon 7.8, 7.19), Output Encoding, CSP (Content-Security-Policy presence and restrictiveness — use recon 7.18; rate ❌ if no CSP header found), CORS (origin allowlist and credential handling — use recon 7.18; rate ❌ if `Access-Control-Allow-Origin: *` with credentials), Audit & Logging, Infrastructure & Network, Dependency & Supply Chain, Security Testing, OAuth/OIDC Implementation, SPA/BFF Architecture (token storage, cookie flags, auth guards — use recon 7.10, 7.24).

Rate each: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

**Linked Threats column:** The controls table MUST include a "Linked Threats" column. For controls rated ⚠️ Partial, 🔶 Weak, or ❌ Missing, reference the T-NNN IDs of threats exploiting that control gap as clickable links (`[T-NNN](#t-NNN)`). For ✅ Adequate controls, use `—`.

### Dependency & Supply Chain — sub-controls

This domain requires checking **all** of the following sub-controls. Use recon-summary sections 7.14–7.17 as baseline (same token-saving rule as other domains).

| Sub-control | ✅ Adequate | ⚠️ Partial | ❌ Missing |
|-------------|-----------|------------|-----------|
| **CVE scanning** | SCA tool in CI (`npm audit`, `pip-audit`, Snyk, etc.) with blocking on Critical/High | SCA runs but only advisory / not blocking | No SCA in CI or manifests |
| **Lockfile pinning** | Lockfile present, committed, and CI validates integrity (`npm ci` / `pip install --require-hashes`) | Lockfile present but no integrity validation in CI | No lockfile or lockfile in `.gitignore` |
| **CI/CD action pinning** | All GitHub Actions / GitLab images pinned to commit SHA or digest | Mix of SHA-pinned and tag-only references | Actions pinned to mutable tags (`@v3`, `@latest`) or no pinning |
| **Container image hygiene** | Base images pinned to digest (`@sha256:`), official/verified images, no `latest` | Images pinned to version tags but no digest | `FROM <image>:latest` or no tag |
| **Dependency confusion** | Private registry configured, scoped packages (`@org/`), no dual-source `--extra-index-url` | Partial scoping or private registry for some ecosystems | Unscoped internal package names without private registry |
| **Postinstall scripts** | No install hooks, or hooks are audited and `ignore-scripts` configured where appropriate | Install hooks present but limited to build tasks (compilation) | Hooks run network requests or arbitrary commands without audit |

**Overall domain rating:** Derive from the sub-control ratings. If any sub-control is ❌, the domain is at most 🔶 Weak. If all are ✅, rate ✅ Adequate.

## Phase 8b: Requirements Compliance (conditional)

**Only when `CHECK_REQUIREMENTS=true`.** Read `.requirements.yaml`, verify each requirement via Grep+Read, assign PASS/PARTIAL/FAIL/UNVERIFIABLE. Generate threat candidates from FAILs for Phase 9.

### Priority-aware risk escalation

The requirement's `priority` field directly influences the risk rating of the generated threat candidate:

| Requirement priority | FAIL → minimum risk | PARTIAL → minimum risk | Rationale |
|---------------------|--------------------|-----------------------|-----------|
| `MUST` | High | Medium | Mandatory requirements — violation is a policy breach |
| `SHOULD` | Medium | Low | Recommended — violation is a gap, not a breach |
| `MAY` | Low | Low | Optional — informational only |

When computing the final risk for a requirement-sourced threat, use the higher of: (a) the priority-derived minimum from the table above, or (b) the risk derived from the standard Likelihood × Impact matrix. This ensures that a violated `MUST` requirement never appears as Low risk, even if exploitation seems unlikely.

### Architectural requirements — elevated handling

Some requirements represent **architectural decisions** rather than implementation details. Violating these has systemic impact — it means the system is built on a fundamentally weaker foundation, not just missing a control.

**Detection:** A requirement is architectural if any of the following apply:
- It mandates a specific architectural pattern (BFF, standard auth service, SSO, API gateway)
- It mandates using a standard/centralized service instead of a custom implementation
- It appears in a blueprint section whose title contains "architecture", "pattern", or "blueprint"
- Its `text` contains terms like "standard", "centralized", "approved", "must use" followed by a service or pattern name

**Examples from the baseline:**
- `SSLM-AUTN`: "Only use one of the standardized KN authentication services for SSO" — architectural (mandates standard auth)
- `SEC-USER-AUTH`: "Users MUST be authenticated using standard KN authentication mechanisms with mandatory MFA" — architectural (standard auth + MFA)
- `SEC-API-AUTH`: "APIs must mutually authenticate using a secure and standard mechanism" — architectural (standard API auth)
- BFF blueprint pattern: "Implement a Backend-for-Frontend (BFF) for user-context API access in your SPA" — architectural (mandates BFF for SPAs)

**When an architectural requirement is violated:**
1. Set `architectural_violation: true` in the threat candidate metadata
2. Escalate the risk by one level (Medium → High, High → Critical) — architectural violations have cascading impact
3. The scenario text must explain **why** this is architectural: what systemic risk the custom/missing pattern creates (e.g., "Custom auth implementation instead of standard SSO increases attack surface and loses centralized security controls")
4. These violations are surfaced prominently in the management summary (see below)

### Architectural anti-pattern detection

Beyond explicit requirements, Phase 8b should check for common architectural anti-patterns when a relevant blueprint exists in `.requirements.yaml`. These are checked regardless of whether a matching requirement exists:

| Anti-pattern | Detection signal | Why it matters |
|-------------|-----------------|---------------|
| **SPA without BFF** | Frontend framework detected (recon 7.19) + tokens in localStorage (recon 7.10) + no BFF proxy pattern (recon 7.10 shows no `bff` or `backend.for.frontend` match) | Tokens exposed to XSS in browser; no server-side session control |
| **Custom auth instead of standard SSO** | Auth mechanism is custom JWT/session (recon 7.1) + no SSO/OIDC provider detected (recon 7.9 shows no OIDC issuer, `/.well-known/`, or known SSO SDK) | Loses centralized auth management, audit trail, MFA enforcement |
| **Direct database access from frontend** | API routes that proxy raw SQL or expose ORM queries directly to client-controlled parameters without an intermediate service layer | No separation of concerns; SQL injection risk multiplied |
| **Secrets in environment variables without vault** | Secrets loaded from env vars (recon 7.6) + no vault/secrets-manager integration detected | No rotation, no access audit, no encryption at rest |

For each detected anti-pattern:
1. Generate a threat candidate with `source: "architectural-anti-pattern"`, `architectural_violation: true`
2. Set minimum risk to High (these are systemic)
3. If a matching blueprint section exists, set `remediation.blueprint` to the relevant blueprint URL
4. Add to the Section 7b table with status `❌ ANTI-PATTERN` (distinct from FAIL — indicates missing architectural pattern, not a specific requirement violation)

### Requirement metadata for Phase 9 integration

For each FAIL, PARTIAL, or ANTI-PATTERN requirement, emit a **threat candidate** that carries requirement metadata:

- `source`: `"requirements-compliance"` or `"architectural-anti-pattern"`
- `requirement_id`: the requirement's ID (e.g. `"SEC-AUTH-1"`) — for anti-patterns, use the closest matching requirement ID or `ARCH-<slug>` if no requirement matches
- `requirement_url`: the requirement's `url` from the YAML (may be null)
- `requirement_priority`: `MUST` / `SHOULD` / `MAY` (from YAML)
- `architectural_violation`: `true` / `false`
- `stride`: inferred STRIDE category
- `scenario`: derived from the FAIL evidence
- `component`: component where violation was found

This metadata is consumed by Phase 9 (Merge) to populate **Violated Requirements** fields in Sections 8, 9 and **Fulfills Requirements** fields in Section 10.

### Section 7b output format

When `CHECK_REQUIREMENTS=true`, write a **Section 7b — Requirements Compliance** in `threat-model.md` directly after Section 7. Add `- [7b. Requirements Compliance](#7b-requirements-compliance)` to the Table of Contents (after Section 7).

```markdown
## 7b. Requirements Compliance

This section summarizes the compliance status of each requirement from the [<requirements source name>](<url>) baseline. Requirements marked ❌ FAIL or ❌ ANTI-PATTERN have generated threat entries in the [Threat Register](#8-threat-register).

### Architectural Violations

<ONLY when architectural violations or anti-patterns were detected. Omit if none.>

These findings represent **systemic architectural gaps** — missing patterns or standard services that have cascading security impact beyond individual controls.

| Violation | Priority | Evidence | Risk | Linked Threats |
|-----------|----------|----------|------|----------------|
| [<ID>](<url>) — <title> | MUST | <what's missing and why it's architectural> | <High/Critical> | [T-NNN](#t-NNN) |

### Full Compliance Table

| Requirement | Priority | Title | Status | Evidence | Linked Threats |
|-------------|----------|-------|--------|----------|----------------|
| [<ID>](<url>) | MUST | <title> | ❌ ANTI-PATTERN | <architectural pattern missing> | [T-NNN](#t-NNN) |
| [<ID>](<url>) | MUST | <title> | ❌ FAIL | <brief evidence of violation> | [T-NNN](#t-NNN) |
| [<ID>](<url>) | SHOULD | <title> | ⚠️ PARTIAL | <what's present, what's missing> | [T-NNN](#t-NNN) |
| [<ID>](<url>) | MUST | <title> | ✅ PASS | <brief evidence of compliance> | — |

**Summary:** <N> requirements checked — ✅ <N> PASS · ❌ <N> FAIL · ❌ <N> ANTI-PATTERN · ⚠️ <N> PARTIAL
```

**Rules:**
- Order rows by: ❌ ANTI-PATTERN first, then ❌ FAIL, then ⚠️ PARTIAL, then ✅ PASS. Within each status group, order by priority: MUST first, then SHOULD, then MAY
- The "Priority" column shows the requirement's priority from the YAML
- The "Linked Threats" column links to threats generated from FAIL/PARTIAL/ANTI-PATTERN requirements in Phase 9
- Each requirement ID is a clickable link using the `url` from the requirements YAML. If no URL, render as plain text
- The "Evidence" column is brief (one line) — cite the file:line or config that proves compliance or violation
- The "Architectural Violations" subsection provides executive visibility into systemic gaps — keep each row to 1-2 sentences
