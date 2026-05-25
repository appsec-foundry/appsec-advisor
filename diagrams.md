# Architecture Diagrams (Mermaid Variants)

Drop-in Mermaid snippets for `README.md`. Each variant emphasizes a different facet — pick one or combine. All render natively on GitHub.

Legend used throughout:

- **Solid box / arrow** = always runs
- **Dashed box / arrow** = conditional or optional
- **Stacked icon** = parallel dispatch
- **Cylinder** = artifact on disk

---

## Variant 1 — At a glance (stakeholder view)

Plain-language overview of what happens between *"hit the button"* and *"finished report"*. Each block is one AI specialist with a clearly bounded sub-task — like a small review team walking through the repo one stage at a time.

```mermaid
flowchart LR
  classDef io fill:#eef,stroke:#558,color:#000,stroke-width:2px;
  classDef work fill:#fff,stroke:#666,color:#000;
  classDef check fill:#fff5e6,stroke:#cc8800,color:#000;
  classDef out fill:#efe,stroke:#383,color:#000,stroke-width:2px;

  In[("Your code<br/>repository")]:::io

  subgraph G1["1 · Understand"]
    direction TB
    V1["Read the repo<br/><i>languages, frameworks,<br/>business context</i>"]:::work
    V2["Find the components<br/><i>What are the building blocks?<br/>Who trusts whom?</i>"]:::work
    V1 --> V2
  end

  subgraph G2["2 · Think about threats"]
    direction TB
    B1["Per component:<br/>what can go wrong?"]:::work
    B2["Merge duplicates"]:::work
    B3["Verify evidence in code<br/><i>Does the code actually<br/>support the claim?</i>"]:::work
    B1 --> B2 --> B3
  end

  subgraph G3["3 · Prioritize & report"]
    direction TB
    P1["Set priority<br/><i>P1 = fix now …<br/>P4 = later</i>"]:::work
    P2["Write the report<br/><i>readable story<br/>+ structured YAML</i>"]:::work
    P1 --> P2
  end

  subgraph G4["4 · Quality loop"]
    direction TB
    Q1["Self-review the report<br/><i>Dead links? Gaps?<br/>Contradictions?</i>"]:::check
    Q2["Architect review<br/><i>(optional —<br/>second opinion)</i>"]:::check
    Q1 --> Q2
  end

  Out[("Threat model<br/>for your team")]:::out

  In --> G1 --> G2 --> G3 --> G4 --> Out
```

Three things to keep in mind:

- **Every finding has code evidence.** The "Verify evidence" step throws out anything that isn't provable in the repo — no fabricated threats.
- **Priority, not completeness.** Step 3 sorts by fix order. The team sees immediately what to tackle this week.
- **Self-check built in.** Step 4 catches typical LLM failure modes (hallucinations, missed placeholders, duplicate entries) before the report ships.

---

## Variant 2 — At a glance, with agents

Same shape as Variant 1, but each box names the specific agent that does the work. Solid borders = runs on every assessment; dashed borders = conditional or opt-in.

```mermaid
flowchart LR
  classDef io fill:#eef,stroke:#558,color:#000,stroke-width:2px;
  classDef work fill:#fff,stroke:#666,color:#000,stroke-width:2px;
  classDef cond fill:#fafafa,stroke:#888,color:#444,stroke-dasharray:5 4;
  classDef optin fill:#fff5e6,stroke:#cc8800,color:#000,stroke-dasharray:5 4;
  classDef check fill:#fff5e6,stroke:#cc8800,color:#000;
  classDef out fill:#efe,stroke:#383,color:#000,stroke-width:2px;

  In[("Your code<br/>repository")]:::io

  subgraph G1["1 · Understand"]
    direction TB
    V1["<b>context-resolver</b><br/><i>reads README, policy,<br/>prior findings</i>"]:::work
    V2["<b>recon-scanner</b><br/><i>finds components,<br/>routes, controls</i>"]:::work
    V2b["<b>config-scanner</b><br/><i>only if IaC present</i>"]:::cond
    V2c["<b>actor-discoverer</b><br/><i>maps trust actors</i>"]:::work
    V1 --> V2 --> V2c
    V2 --> V2b
  end

  subgraph G2["2 · Think about threats"]
    direction TB
    B1["<b>stride-analyzer × N</b><br/><i>one pass per component</i>"]:::work
    B2["<b>threat-merger</b><br/><i>only when duplicates exist</i>"]:::cond
    B3["<b>evidence-verifier</b><br/><i>code-backs every claim</i>"]:::work
    B1 --> B2 --> B3
  end

  subgraph G3["3 · Prioritize & report"]
    direction TB
    P1["<b>triage-validator</b><br/><i>sets P1–P4</i>"]:::work
    P2["<b>threat-renderer</b><br/><i>writes prose<br/>(Python glues the rest)</i>"]:::work
    P1 --> P2
  end

  subgraph G4["4 · Quality loop"]
    direction TB
    Q1["<b>qa-reviewer</b><br/><i>only if Python pre-pass<br/>flags issues</i>"]:::cond
    Q2["<b>architect-reviewer</b><br/><i>opt-in — thorough mode<br/>or --architect-review</i>"]:::optin
    Q1 --> Q2
  end

  Out[("threat-model.md<br/>+ .yaml")]:::out

  In --> G1 --> G2 --> G3 --> G4 --> Out
```

**Reading the borders:**

- ━━ **Always runs** — 7 agents on every assessment: context-resolver, recon-scanner, actor-discoverer, stride-analyzer, evidence-verifier, triage-validator, threat-renderer.
- ┄┄ **Conditional** — `config-scanner` only fires when IaC files exist; `threat-merger` only when duplicates are found across components; `qa-reviewer` only when the deterministic Python pre-pass flags issues worth a second look.
- ┄┄ **Opt-in** — `architect-reviewer` runs only in `--assessment-depth thorough` (or when explicitly requested). It comments but never overwrites — recommendations only.

---

## Variant 3 — High-level pipeline (flowchart, with outputs)

Simplest mental model: repo in, 4 stage groups, reports out. Same shape as Variant 1, but with the optional output deliverables made explicit.

```mermaid
flowchart LR
    Repo[(Repository)] --> R
    Ctx[(Policy & prior findings)] -.-> R

    subgraph R[Recon & Context]
        direction TB
        R1[Context resolution]
        R2[Reconnaissance scan]
        R3[Config / IaC scan]
    end

    R --> A

    subgraph A[Architecture Modeling]
        direction TB
        A1[Components & data flows]
        A2[Trust boundaries]
        A3[Assets & attack surface]
        A4[Security controls]
    end

    A --> T

    subgraph T[Threat Analysis]
        direction TB
        T1[STRIDE enumeration]
        T2[Triage & ranking]
        T3[Evidence verification]
    end

    T --> F

    subgraph F[Finalization]
        direction TB
        F1[QA review]
        F2[Architect review<br/><i>thorough only</i>]
        F3[Render report]
    end

    F --> MD[threat-model.md]
    F --> YAML[threat-model.yaml]
    F -.-> SARIF[threat-model.sarif.json]
    F -.-> PDF[threat-model.pdf]
    F -.-> HTML[threat-model.html]
    F -.-> PEN[pentest-tasks.yaml]

    classDef optional stroke-dasharray: 4 3
    class SARIF,PDF,HTML,PEN,Ctx optional
```

---

## Variant 4 — Phase pipeline with agents

One step deeper: shows the 11 numbered phases and which agent runs each. Useful as a replacement for `docs/images/threat-model-pipeline.png`.

```mermaid
flowchart TB
    Start([create-threat-model]) --> P12

    subgraph P12[Phase 1 + 2 — Parallel dispatch]
        direction LR
        P1["Phase 1<br/>Context resolution<br/><i>context-resolver</i>"]
        P2["Phase 2<br/>Reconnaissance<br/><i>recon-scanner</i>"]
        P25["Phase 2.5<br/>Config / IaC<br/><i>config-scanner</i>"]
    end

    P12 --> P26["Phase 2.6<br/>Arch coverage pre-pass"]
    P26 --> P27["Phase 2.7<br/>Actor discovery<br/><i>actor-discoverer</i>"]

    P27 --> P3["Phase 3<br/>Architecture model<br/><i>threat-analyst</i>"]
    P3 --> P4["Phase 4<br/>Attack walkthroughs"]
    P4 --> P5["Phase 5<br/>Assets"]
    P5 --> P6["Phase 6<br/>Attack surface"]
    P6 --> P7["Phase 7<br/>Trust boundaries"]
    P7 --> P8["Phase 8<br/>Security controls"]
    P8 --> P8b["Phase 8b<br/>Requirements compliance"]

    P8b --> P9["Phase 9<br/>STRIDE enumeration<br/><i>stride-analyzer × N</i>"]
    P9 --> P10["Phase 10<br/>Secret & dep synthesis"]
    P10 --> P10a["Phase 10a<br/>Evidence verifier"]
    P10a --> P10b["Phase 10b<br/>Triage validator"]
    P10b --> Merge["threat-merger"]

    Merge --> P11["Phase 11<br/>Render + QA<br/><i>renderer → qa-reviewer</i>"]
    P11 --> Arch["Architect review<br/><i>thorough only</i>"]
    Arch --> Done([threat-model.md + .yaml])

    classDef conditional stroke-dasharray: 4 3,fill:#fafafa
    class P25,P26,P27,P8b,Arch conditional
```

---

## Variant 5 — Agent map (who does what)

If the README's audience is AppSec teams sizing up the plugin, this is the most useful single diagram. Groups the 12 specialized agents by role, shows shared schemas as the contract.

```mermaid
flowchart TB
    subgraph RECON[Recon & Context]
        CR[context-resolver]
        RS[recon-scanner]
        CS[config-scanner]
        AD[actor-discoverer]
    end

    subgraph ANALYSIS[Analysis]
        TA[threat-analyst<br/><b>orchestrator</b>]
        SA[stride-analyzer]
        TM[threat-merger]
    end

    subgraph QA[Validation & QA]
        EV[evidence-verifier]
        TV[triage-validator]
        QR[qa-reviewer]
        AR[architect-reviewer<br/><i>thorough only</i>]
    end

    subgraph OUT[Output]
        TR[threat-renderer]
    end

    SCHEMAS[(Shared schemas<br/>+ templates)]

    RECON --> TA
    TA --> SA
    SA --> TM
    TM --> EV
    EV --> TV
    TV --> QR
    QR --> AR
    AR --> TR
    QR --> TR

    SCHEMAS -.-> RECON
    SCHEMAS -.-> ANALYSIS
    SCHEMAS -.-> QA
    SCHEMAS -.-> OUT

    classDef optional stroke-dasharray: 4 3
    class AR optional
```

---

## Variant 6 — Sequence diagram (parallel dispatch + checkpoints)

Time-ordered view. Best for the **CI integration** or **Manual full-run check** section where readers care about *what happens when*. Shows that recon agents run concurrently.

```mermaid
sequenceDiagram
    participant U as User / CI
    participant O as Orchestrator<br/>(threat-analyst)
    participant CR as context-resolver
    participant RS as recon-scanner
    participant CS as config-scanner
    participant SA as stride-analyzer
    participant V as evidence-verifier<br/>+ triage-validator
    participant R as renderer + QA

    U->>O: create-threat-model
    par Parallel recon
        O->>CR: Phase 1 (policy + prior findings)
        O->>RS: Phase 2 (codebase scan)
        O->>CS: Phase 2.5 (IaC, if present)
    end
    CR-->>O: .threat-modeling-context.md
    RS-->>O: .recon-summary.md
    CS-->>O: .config-findings.md

    O->>O: Phases 3–8 (architecture model)
    O->>SA: Phase 9 (STRIDE × N components)
    SA-->>O: threats.yaml fragments

    O->>V: Phase 10a/10b (verify + rank)
    V-->>O: validated findings

    O->>R: Phase 11 (render + QA)
    R-->>U: threat-model.md + .yaml

    Note over U,R: SARIF / PDF / HTML / pentest-tasks<br/>are deterministic exports — no LLM tokens
```

---

## Variant 7 — Depth modes (what runs when)

Compact matrix-style view of what `quick` vs `standard` vs `thorough` actually changes. Good companion to the depth table in the README.

```mermaid
flowchart LR
    subgraph Quick[Quick<br/>~$8 / 33 min]
        direction TB
        Q1[Recon]
        Q2[Architecture]
        Q3[STRIDE<br/><i>reduced</i>]
        Q4[Triage]
        Q5[Render]
    end

    subgraph Standard[Standard — default<br/>~$17 / 53 min]
        direction TB
        S1[Recon]
        S2[Architecture]
        S3[STRIDE<br/><i>full</i>]
        S4[Evidence verify]
        S5[Triage]
        S6[QA review]
        S7[Render]
    end

    subgraph Thorough[Thorough<br/>~$50+ / 72 min]
        direction TB
        T1[Recon — larger scope]
        T2[Architecture]
        T3[STRIDE — full]
        T4[Evidence verify]
        T5[Triage]
        T6[QA review]
        T7[Architect review]
        T8[Render]
    end

    Quick -.->|Pre-commit,<br/>early design| Standard
    Standard -.->|Pre-release,<br/>high-risk services| Thorough

    classDef added fill:#e8f5e9,stroke:#2e7d32
    class S4,S6,T7 added
```

Green-shaded steps are the ones each mode **adds** over the lighter mode below it.

---

## Variant 8 — LLM vs deterministic split

The plugin's design rule: **Python does everything mechanical, LLMs do everything that requires interpretation.** Whenever a task can be solved deterministically (deduplicate findings with the same CWE, assign stable IDs, scan dependency manifests against osv.dev, classify breach-vectors from a CWE table, validate schema, regex-scan for unmasked secrets) a Python script owns it — cheaper, repeatable, no token spend.

What's important to notice: **threats themselves come from two parallel sources** — STRIDE enumeration per component (LLM) AND a set of deterministic emitters (SCA, architecture-coverage, meta-findings). They merge into a single threat list before the renderer ever sees them.

This split is invisible in the other variants. Use this diagram when the question is *"how much of this is actually AI, and what's just code?"* — common in security review, procurement, and AI-governance discussions.

```mermaid
flowchart TB
    Repo[(Repository)] --> S1

    subgraph S1["Stage 1 · Discover, analyze, merge"]
        direction LR
        subgraph S1L["LLM — interpretation"]
            direction TB
            L1["<b>context-resolver</b><br/>reads README, policy"]
            L2["<b>recon-scanner</b><br/>components, routes, controls"]
            L3["<b>actor-discoverer</b><br/>trust-actor mapping"]
            L4["<b>stride-analyzer × N</b><br/>per-component threats"]
            L5["<b>evidence-verifier</b><br/>re-reads cited evidence"]
            L1 --> L2 --> L3 --> L4 --> L5
        end
        subgraph S1P["Python — mechanical"]
            direction TB
            P1["<b>dep_scan.py</b><br/>SCA — npm/pip/osv.dev<br/><i>(replaces former LLM agent)</i>"]
            P2["<b>arch_coverage_to_threats.py</b><br/>architecture anti-patterns<br/>→ threat candidates"]
            P3["<b>emit_meta_findings.py</b><br/>cross-cutting MF-NNN"]
            P4["<b>emit_threat_vektors.py</b><br/>CWE → breach-vector"]
            P5["<b>merge_threats.py</b><br/>CWE-based dedup, stable IDs"]
            P6["<b>triage_validate_ratings.py</b><br/>severity rule-checks"]
            P7["<b>baseline_state.py</b><br/>fingerprint + incremental skip"]
        end
        L5 -. threats[] .-> P5
        P1 -. threats[] .-> P5
        P2 -. threats[] .-> P5
        P3 -. threats[] .-> P5
        P5 --> P4
        P4 --> P6
    end

    S1 --> S2

    subgraph S2["Stage 2 · Report"]
        direction LR
        subgraph S2L["LLM — interpretation"]
            L6["<b>threat-renderer</b><br/>prose sections only"]
        end
        subgraph S2P["Python — mechanical"]
            P8["<b>compose_threat_model.py</b><br/>fragment assembly"]
            P9["<b>build_threat_model_yaml.py</b><br/>structured export"]
            P10["<b>emit_review_mitigations.py</b><br/>mitigation synthesis"]
        end
        L6 --> P8
        P10 --> P8
        P8 --> P9
    end

    S2 --> S3

    subgraph S3["Stage 3 · QA gate"]
        direction LR
        subgraph S3L["LLM — interpretation"]
            L7["<b>qa-reviewer</b><br/>only when Python flags"]
        end
        subgraph S3P["Python — mechanical"]
            P11["<b>qa_checks.py</b><br/>~40 checks: links, anchors,<br/>schema, secret-leak gate"]
            P12["<b>secret_scan.py</b><br/>regex backstop"]
            P11 --> P12
        end
        P11 -. flags .-> L7
    end

    S3 --> S4

    subgraph S4["Stage 4 · Architect review (opt-in)"]
        L8["<b>architect-reviewer</b><br/>second opinion, advisory only"]
    end

    S4 --> Out[("threat-model.md<br/>+ .yaml")]

    Out -.-> Exp["<b>Deterministic exports</b><br/>SARIF · PDF · HTML · pentest-tasks<br/><i>no LLM tokens spent</i>"]

    classDef llm fill:#fff5e6,stroke:#cc8800,color:#000;
    classDef py  fill:#e8f0ff,stroke:#3355aa,color:#000;
    classDef io  fill:#eef,stroke:#558,color:#000,stroke-width:2px;
    classDef det fill:#efe,stroke:#383,color:#000,stroke-width:2px;

    class L1,L2,L3,L4,L5,L6,L7,L8 llm;
    class P1,P2,P3,P4,P5,P6,P7,P8,P9,P10,P11,P12 py;
    class Repo,Out io;
    class Exp det;
```

**Reading the colors:**

- 🟠 **LLM agents** (orange) own anything that needs judgment: reading code, naming components, enumerating per-component STRIDE threats, writing prose, the optional architect second opinion.
- 🔵 **Python scripts** (blue) own anything mechanical: SCA against vulnerability databases, deriving threats from architecture coverage, deduplication by CWE, breach-vector classification, severity rule-checks, schema validation, regex secret-leak detection, fragment assembly. The plugin ships ~110 Python scripts; the diagram names only the most load-bearing.
- 🟢 **Deterministic exports** (green) — SARIF, PDF, HTML, and pentest-tasks are converted from the already-validated YAML/MD. No LLM is invoked, so they cost nothing to regenerate.

**Why this matters for cost and trust:**

- **Two parallel threat sources, one merge.** SCA findings, architecture anti-patterns, and meta-findings enter the pipeline as deterministic Python output — never went through an LLM, no hallucination surface.
- **Breach-vector is rule-based.** Reachability tags like `internet-anon` / `repo-read` come from a CWE → vector table, not from an LLM guess.
- **A re-export is free.** `/appsec-advisor:export-threat-model` produces SARIF / PDF / HTML / pentest-tasks without any model call.
- **Repeat runs skip the LLM-heavy phase.** `baseline_state.py` fingerprints the repo; an unchanged scope short-circuits Phase 2 entirely.
- **Every LLM-authored claim is checked by at least one Python script** before release: schema, evidence integrity, secret masking, link validity, ~40 rules total.

---

## Picking a variant

| Where in the README | Use variant |
|---|---|
| Top of `## Architecture` — non-technical readers | **Variant 1** — stakeholder view, plain language |
| Top of `## Architecture` — technical readers | **Variant 2** — same shape, agents named |
| Section intro / overview block | **Variant 3** — pipeline + output deliverables |
| Replacing `threat-model-pipeline.png` | **Variant 4** — all 11 phases |
| `## What it checks` or AppSec-team-facing intro | **Variant 5** — agent map |
| `## CI integration` or `## Manual full-run check` | **Variant 6** — runtime / sequence view |
| `## Assessment depth & cost control` | **Variant 7** — depth comparison |
| AI-governance / cost discussions / procurement | **Variant 8** — LLM vs deterministic split |

Mix is fine — Variant 1 (or 2) at the top of the README and Variant 5 deeper in the Architecture section is a common pattern. Variant 8 pairs well with the **Assessment depth & cost control** section.
