# appsec-advisor — Developer Guide

Dieses Dokument erklärt, wie das Plugin intern funktioniert. Schwerpunkt: der
Skill `create-threat-model`, sein Orchestrator `appsec-threat-analyst`, die
Sub-Agenten, die deterministischen Python-Helfer und der Datenfluss zwischen
den Phasen.

Quellen für jede Aussage stehen im Repo:

- Plugin-Metadaten: `.claude-plugin/plugin.json`
- Plugin-Config & Permissions: `config.json`, `permissions.md`
- Skills: `skills/<skill-name>/SKILL.md` (+ ggf. `SKILL-impl.md`)
- Agent-Definitionen: `agents/appsec-*.md`
- Phasen-Gruppen (lazy-loaded): `agents/phases/phase-group-*.md`
- Skript-Tooling: `scripts/*.py`
- Daten-Kataloge: `data/*.yaml`
- Schemas: `schemas/*.json`
- Hooks: `hooks/hooks.json`, `scripts/hooks/*.py`
- Verbindliche Regeln für Agenten: `AGENTS.md`

---

## 1. Plugin auf einen Blick (Ebene 0)

Das Plugin liefert eine kleine Familie von Skills. Der zentrale Skill ist
`create-threat-model`. Er lädt einen Orchestrator-Agenten, der eine feste
Phasenpipeline gegen ein Repository fährt und am Ende einen
Architekur- + Bedrohungsbericht produziert.

```mermaid
flowchart LR
  user["Claude Code User"]
  cc["Claude Code CLI"]
  plugin["appsec-advisor Plugin"]
  repo[("Ziel-Repository")]
  out[("OUTPUT_DIR\n(docs/security/)")]

  user -- "/appsec-advisor:create-threat-model" --> cc
  cc -- "lädt Skill" --> plugin
  plugin -- "liest Code, Konfig, Manifeste" --> repo
  plugin -- "schreibt Artefakte" --> out
  out -- "threat-model.md / .yaml / .sarif.json / .pdf" --> user
```

Outputs (siehe `README.md` → *What you get*):

| Datei                       | Zweck                                                |
|-----------------------------|------------------------------------------------------|
| `threat-model.md`           | Engineer-lesbarer Hauptbericht                       |
| `threat-model.yaml`         | Maschinenlesbarer Export (Inkrement-Baseline)        |
| `threat-model.sarif.json`   | Optional, via `--sarif`                              |
| `threat-model.pdf` / `.html`| Optional, via `--pdf` / `export-threat-model`        |
| `pentest-tasks.yaml`        | Optional, für AI-Pentester (Strix etc.)              |

---

## 2. Skill- und Agent-Layer (Ebene 1)

Das Plugin trennt drei Schichten: **Skills** (User-Einstiege),
**Agents** (LLM-getriebene Worker mit Turn-Budget) und
**Python-Scripts** (deterministische Logik, kein LLM).

```mermaid
flowchart TB
  subgraph Skills["skills/"]
    S1["create-threat-model<br/><i>Haupt-Pipeline</i>"]
    S2["export-threat-model"]
    S3["publish-threat-model"]
    S4["threat-model-health"]
    S5["clean-run-state"]
    S6["fix-run-issues"]
    S7["status"]
    S8["check-permissions"]
    S9["audit-security-requirements"]
  end

  subgraph Agents["agents/ (alle Sonnet als Frontmatter-Pin;<br/>Runtime-Routing per .skill-config.json)"]
    A_TA["appsec-threat-analyst<br/><b>Orchestrator</b> (250 turns)"]
    A_CR["appsec-context-resolver (25)"]
    A_RS["appsec-recon-scanner (25)"]
    A_CS["appsec-config-scanner (15)"]
    A_ST["appsec-stride-analyzer (40, ×N parallel)"]
    A_TM["appsec-threat-merger (12)"]
    A_EV["appsec-evidence-verifier (30)"]
    A_TV["appsec-triage-validator (20)"]
    A_TR["appsec-threat-renderer (80)"]
    A_QA["appsec-qa-reviewer (120)"]
    A_AR["appsec-architect-reviewer (40, opt-in)"]
  end

  subgraph Scripts["scripts/ (deterministisch)"]
    P1["resolve_config.py"]
    P2["baseline_state.py"]
    P3["merge_threats.py"]
    P4["triage_validate_ratings.py"]
    P5["compose_threat_model.py"]
    P6["qa_checks.py"]
    P7["plugin_meta.py"]
    P8["runtime_cleanup.py"]
    P9["route_inventory.py"]
    P10["pregenerate_fragments.py"]
    P11["build_threat_model_yaml.py<br/><i>Phase 11 Substep 2 aggregator</i>"]
    P12["reserve_ids.py<br/><i>atomic ID counter for sidecars</i>"]
    P13["validate_fragment.py<br/><i>schema gate for sidecars + render-fragments</i>"]
  end

  subgraph Data["data/ (Kataloge)"]
    D1["cwe-taxonomy.yaml"]
    D2["threat-category-taxonomy.yaml"]
    D3["config-iac-checks.yaml"]
    D4["sections-contract.yaml"]
    D5["walkthrough-templates/*.yaml"]
    D6["component-canonical.yaml"]
  end

  S1 --> A_TA
  A_TA --> A_CR & A_RS & A_CS
  A_TA --> A_ST
  A_TA --> A_TM
  A_TA --> A_EV
  A_TA --> A_TV
  S1 --> A_TR
  S1 --> A_QA
  S1 -. "opt-in --architect-review" .-> A_AR

  A_TA --> P1 & P2 & P3 & P4
  A_TR --> P5 & P10
  A_QA --> P6
  A_TA --> P7 & P8 & P9
  A_ST -. liest .-> D1 & D2 & D6
  A_CS -. liest .-> D3
  A_TR -. liest .-> D4 & D5
```

Modell-Routing (`AGENTS.md` → *Runtime model routing*): Frontmatter ist nur
Fallback. Der Orchestrator überschreibt pro Aufruf aus
`.skill-config.json`. Default-Tier `opus-cheap`:

| Agent                       | Default-Modell  |
|-----------------------------|-----------------|
| `appsec-context-resolver`   | **Haiku**       |
| `appsec-recon-scanner`      | **Haiku**       |
| `appsec-config-scanner`     | **Haiku**       |
| `appsec-stride-analyzer`    | **Sonnet**      |
| `appsec-threat-merger`      | **Opus**        |
| `appsec-evidence-verifier`  | Sonnet          |
| `appsec-triage-validator`   | Sonnet          |
| `appsec-threat-renderer`    | Sonnet          |
| `appsec-qa-reviewer`        | Sonnet (split intern in qa_content/qa_routine) |
| `appsec-architect-reviewer` | **Opus**        |
| `appsec-threat-analyst`     | Sonnet (immer)  |

---

## 3. `create-threat-model` — Pipeline-Stages (Ebene 2)

Der Skill ist in **vier Hauptstages** und **17 Phasen** organisiert. Die
Phasen leben in vier *lazy-loaded* Phase-Group-Dateien unter
`agents/phases/`, die der Orchestrator zur Laufzeit liest.

```mermaid
flowchart TB
  start([User: /appsec-advisor:create-threat-model])

  subgraph Stage0["Stage 0 — Preamble"]
    direction TB
    Z1["resolve_config.py emit-file<br/>(args → .skill-config.json)"]
    Z2["pre-flight stale-state<br/>recovery (Locks, Caches)"]
    Z3["Rebuild / Full Wipe<br/>(--rebuild / --full)"]
    Z1 --> Z2 --> Z3
  end

  subgraph Stage1["Stage 1 — Threat Analysis & Triage<br/>(appsec-threat-analyst, 250 turns)"]
    direction TB
    ST1A["Recon Phase Group<br/>Phasen 1, 2, 2.5, 2.6"]
    ST1B["Architecture Phase Group<br/>Phasen 3, 3b, 4, 5–7, 8, 8b"]
    ST1C["Threats Phase Group<br/>Phasen 9, 10, 10a, 10b"]
    ST1A --> ST1B --> ST1C
  end

  subgraph Stage2["Stage 2 — Report Rendering<br/>(appsec-threat-renderer, fresh budget)"]
    direction TB
    R1["LLM-Fragmente schreiben<br/>(ms-verdict, ms-architecture-assessment, …)"]
    R2["compose_threat_model.py --strict<br/>→ threat-model.md"]
    R3["qa_checks all"]
    R1 --> R2 --> R3
  end

  gate{{"Hard inline-shortcut gate<br/>check_inline_shortcut.py"}}

  subgraph Retry["Auto-Retry Loop (M2.13)<br/>max 2 Iterationen"]
    direction TB
    RT1["recovery: merge + triage<br/>+ pregenerate"]
    RT2["Stage 2 erneut dispatchen"]
    RT3["Hard-Gate erneut"]
    RT1 --> RT2 --> RT3
  end

  subgraph Stage3["Stage 3 — QA Review<br/>(appsec-qa-reviewer, 120 turns)"]
    direction TB
    QA1["deterministic pre-pass<br/>(qa_checks.py)"]
    QA2["LLM-QA (nur falls nötig)"]
    QA3["Re-Render Loop<br/>(max 3 Iter.)"]
    QA1 --> QA2 --> QA3
  end

  subgraph Stage4["Stage 4 — Architect Review<br/>(opt-in --architect-review, advisory)"]
    AR1["appsec-architect-reviewer<br/>.architect-review.md / .architect-status.json"]
  end

  done([threat-model.md / .yaml / Exports])

  start --> Stage0 --> Stage1 --> Stage2 --> gate
  gate -- exit 0 --> Stage3
  gate -- exit 2 --> Retry --> gate
  Stage3 --> Stage4 --> done
  Stage3 -- ohne --architect-review --> done
```

Wichtige Compliance-Garantie (`SKILL-impl.md` → *Pipeline Overview*):
es wird **niemals** ein malformes `threat-model.md` persistiert. Jeder Pfad
endet entweder mit einem schema-validierten Dokument oder exit 2 mit
strukturiertem Repair-Plan (`.inline-shortcut-repair-plan.json`).

---

## 4. Stage 1 im Detail — Phasen 1–10b (Ebene 3)

Der Orchestrator-Agent (`appsec-threat-analyst.md`) führt 11 nummerierte
Phasen aus. Phasen 1, 2 und 2.5 laufen **parallel** im selben
Orchestrator-Turn. Phase 9 fächert per **Sub-Agent-Fan-out** auf (eine
STRIDE-Instanz pro Komponente).

```mermaid
flowchart TB
  subgraph Recon["Phasengruppe: Recon (phase-group-recon.md)"]
    direction TB
    PRE["Pre-Checks:<br/>• CTX_SKIP (Context-Cache)<br/>• HAS_IAC_SURFACE (compgen)<br/>• Fingerprint-Skip (Recon)"]
    P1P2P25["Phasen 1 + 2 + 2.5 — Parallel-Dispatch<br/>(bis zu 3 Background-Agents in einem Turn)"]
    P26["Phase 2.6 — route_inventory.py<br/>(deterministisches Coverage-Pre-pass)"]
    PRE --> P1P2P25 --> P26
  end

  subgraph Arch["Phasengruppe: Architecture (phase-group-architecture.md)"]
    direction TB
    P3["Phase 3 — Architecture Modeling<br/>(Components, Trust Boundaries skizziert)"]
    P3B["Phase 3b — F-only architecture-derived findings<br/>(source=architecture-coverage, architectural_theme)"]
    P4["Phase 4 — Attack Walkthroughs"]
    P567["Phasen 5–7 — Assets, Attack Surface, Trust Boundaries<br/>(single-pass, gemeinsamer Timestamp)"]
    P8["Phase 8 — Identified Security Controls"]
    P8B{"Phase 8b — Requirements Audit<br/>(nur falls CHECK_REQUIREMENTS=true)"}
    P3 --> P3B --> P4 --> P567 --> P8 --> P8B
  end

  subgraph Threats["Phasengruppe: Threats (phase-group-threats.md)"]
    direction TB
    P9["Phase 9 — STRIDE Enumeration<br/>(Sub-Agent-Fan-out, siehe §5)"]
    P10["Phase 10 — Scan Synthesis<br/>(merge_threats.py collect + ggf. appsec-threat-merger)"]
    P10A["Phase 10a — appsec-evidence-verifier<br/>(verified / refuted / ambiguous)"]
    P10B["Phase 10b — appsec-triage-validator<br/>(Ranking, Effective Severity)"]
    P9 --> P10 --> P10A --> P10B
  end

  Recon --> Arch --> Threats
```

### 4a. Phasen 1+2+2.5 parallel — Sequenzdiagramm

`phase-group-recon.md` definiert: alle drei Recon-Agents werden in **einem
Orchestrator-Turn** als `run_in_background: true` gestartet. Das Wait-Gate
wartet auf Agent-Returns, nicht auf File-Polling.

```mermaid
sequenceDiagram
  autonumber
  participant O as Orchestrator<br/>(appsec-threat-analyst)
  participant CR as context-resolver<br/>(Haiku)
  participant RS as recon-scanner<br/>(Haiku)
  participant CS as config-scanner<br/>(Haiku, conditional)
  participant FS as $OUTPUT_DIR

  O->>O: Pre-Check CTX_SKIP, HAS_IAC_SURFACE,<br/>Recon-Fingerprint
  Note over O: PHASE_START für 1, 2, (2.5)<br/>im selben Bash-Batch (gleicher TS)

  par Parallel-Dispatch (ein Turn)
    O->>CR: Agent (run_in_background=true)
    O->>RS: Agent (run_in_background=true)
    O->>CS: Agent (run_in_background=true,<br/>nur wenn HAS_IAC_SURFACE)
  end

  CR-->>FS: .threat-modeling-context.md
  RS-->>FS: .recon-summary.md
  CS-->>FS: .config-scan-findings.json

  Note over O: Wait-Gate: warte auf Agent-Returns<br/>(keine File-Polls währenddessen)

  CR-->>O: returned
  RS-->>O: returned
  CS-->>O: returned

  O->>FS: read .recon-summary.md (Manifeste,<br/>preliminary components, security findings)
  O->>O: PHASE_END mit „(parallel with …)“-Suffix<br/>damit ASSESSMENT_PHASES-Aggregator<br/>Wallclock nicht doppelt zählt
```

Begründung für die Suffix-Pflicht steht in `phase-group-recon.md` →
*Phase 2.5: Configuration & IaC Scan*: ohne `(parallel with Phases 1+2)`
addiert der `ASSESSMENT_PHASES`-Aggregator die Phase fälschlich sequentiell.

---

## 5. Phase 9 — STRIDE-Fan-out (Ebene 4)

Phase 9 ist der teuerste LLM-Schritt. Der Orchestrator startet **eine
STRIDE-Instanz pro Komponente** (begrenzt durch `--assessment-depth`:
quick=3, standard=5, thorough=8 Komponenten). Jede Instanz schreibt eine
eigene Output-Datei und wird über das Prompt-Cache-Layout optimiert.

```mermaid
flowchart LR
  subgraph Pre["Pre-Dispatch (Orchestrator)"]
    direction TB
    SEL["Component Selection<br/>(Top-N nach Depth-Profil)"]
    SLICE["Taxonomy-Slice je Komponente<br/>(threat-category-taxonomy.yaml)"]
    FOCUS["FOCUS_PATHS aus<br/>recon-summary Zitaten"]
    SEL --> SLICE --> FOCUS
  end

  subgraph Dispatch["Fan-out: N parallele Agents"]
    direction TB
    S1["stride-analyzer #1<br/>component=auth-service<br/>(simple, MAX_TURNS=15)"]
    S2["stride-analyzer #2<br/>component=payment-handler<br/>(complex, MAX_TURNS=31)"]
    S3["stride-analyzer #3<br/>component=data-persistence<br/>(moderate, MAX_TURNS=22)"]
    SN["…"]
  end

  subgraph Out["Outputs pro Komponente"]
    O1[".stride-auth-service.json"]
    O2[".stride-payment-handler.json"]
    O3[".stride-data-persistence.json"]
    ON["…"]
  end

  Pre --> Dispatch
  S1 --> O1
  S2 --> O2
  S3 --> O3
  SN --> ON
```

**Cache-freundliches Prompt-Layout** (`phase-group-threats.md` → *Dispatch*):
Parameter werden in drei Gruppen sortiert, damit der Claude-Code-Prompt-Cache
greift:

```mermaid
flowchart LR
  A["Group A — Stable Prefix<br/>REPO_ROOT, OUTPUT_DIR,<br/>COMPLIANCE_SCOPE, ASSET_TIER,<br/>TAXONOMY_SLICE_DIR (Pfad),<br/>STRIDE_PROFILE (JSON)"]
  B["Group B — Component-spezifisch<br/>COMPONENT_ID, _NAME, _DESCRIPTION,<br/>_COMPLEXITY, _PATHS (Globs)"]
  C["Group C — volatile Kontext-Pfade<br/>(Context-Files, Bulletins)"]
  A --> B --> C
  note["Group A ist über alle N Dispatches identisch<br/>→ Prefix-Hit im Prompt-Cache"]
  A -.-> note
```

Die `COMPONENT_PATHS`-Globs sind der **Anti-Drift-Anker**: der Analyzer
verweigert Threats, deren `evidence[0].file` außerhalb der Globs liegen
würde (Root-Cause-Fix gegen das alte „SQL-Injection in `routes/search.ts`
als `data-layer` getaggt“-Problem).

---

## 6. Phasen 10 / 10a / 10b — Synthese (Ebene 4)

Aus N STRIDE-Outputs wird ein konsistenter, deduplizierter, gewichteter
Threat-Register. Die Schritte sind so geschnitten, dass **deterministische
Python-Logik den Großteil übernimmt** und LLMs nur dort einspringen, wo
Semantik nötig ist.

```mermaid
flowchart TB
  STRIDE[("N × .stride-<id>.json")]

  subgraph P10["Phase 10 — Scan Synthesis"]
    direction TB
    M1["merge_threats.py collect<br/>(deterministisch: gruppiert Kandidaten<br/>per CWE + STRIDE + threat_category_id)"]
    M2{"Kandidaten-Gruppen ≥ 1?"}
    M3["appsec-threat-merger<br/>(LLM, Opus@cheap, 12 turns)<br/>Regel-Reihenfolge:<br/>1. identische Semantik → merge/consolidate<br/>2. distinct-but-related → keep<br/>3. unclear → keep"]
    M4["merge_threats.py finalize<br/>(weist globale T-IDs zu,<br/>preserviert highest-risk Survivor)"]
    M1 --> M2
    M2 -- ja --> M3 --> M4
    M2 -- nein --> M4
  end

  subgraph P10a["Phase 10a — Evidence Verification"]
    direction TB
    EV["appsec-evidence-verifier (Sonnet, 30 turns)<br/>• Sampling-Strategie nach DEPTH<br/>• re-read evidence.file ±5 Zeilen<br/>• Verdict: verified | refuted | ambiguous"]
    EV2["Refuted-Findings können kein<br/>Compound-Chain mehr eskalieren"]
    EV --> EV2
  end

  subgraph P10b["Phase 10b — Triage Validation"]
    direction TB
    T1["triage_validate_ratings.py<br/>(deterministic floor)"]
    T2["appsec-triage-validator (Sonnet, 20 turns)<br/>• L/I-Outlier-Detection<br/>• P1/P2-Konsistenz<br/>• Rating-Completeness"]
    T3[".triage-flags.json +<br/>annotiertes .threats-merged.json"]
    T1 --> T2 --> T3
  end

  STRIDE --> M1
  M4 --> EV
  EV2 --> T1
```

Stabile IDs (`AGENTS.md` → *Drift-Guarded Runtime Contracts*): T-IDs, M-IDs
und E-IDs sind **über Runs stabil**. Eine carry-forward Komponente behält
jede ihrer T-IDs; neue IDs kommen aus `.appsec-cache/baseline.json.id_counters`.

---

## 7. Stage 2 — Renderer + Repair Loop (Ebene 4)

Der Renderer ist explizit **schmal** geschnitten: er rennt keine Analyse
noch einmal. Er liest validierte Fragmente und ruft `compose_threat_model.py`
mit `--strict`. Wenn das Hard-Gate kippt, geht eine Auto-Retry-Schleife los.

```mermaid
stateDiagram-v2
  [*] --> Render
  Render: Stage 2<br/>appsec-threat-renderer<br/>schreibt LLM-Fragmente<br/>(ms-verdict, ms-architecture-assessment, …)
  Render --> Compose
  Compose: compose_threat_model.py --strict
  Compose --> QAchecks
  QAchecks: qa_checks all
  QAchecks --> HardGate
  HardGate: check_inline_shortcut.py<br/>--write-repair-plan
  HardGate --> Stage3 : exit 0
  HardGate --> Retry  : exit 2

  state Retry {
    [*] --> RecoverArtifacts
    RecoverArtifacts: merge_threats +<br/>triage_validate +<br/>pregenerate_fragments
    RecoverArtifacts --> Render2
    Render2: Stage 2 erneut dispatchen
    Render2 --> HardGate2
    HardGate2: Hard-Gate erneut
    HardGate2 --> [*] : pass
    HardGate2 --> Fail : 2× gescheitert
    Fail: exit 2 +<br/>.inline-shortcut-repair-plan.json
  }

  Stage3: Stage 3 — QA
  Stage3 --> [*]
```

Repair-Mode (`appsec-threat-renderer.md` → *Repair-Mode*): wenn QA oder
Architect einen strukturierten Repair-Plan schreiben, wird der Renderer mit
`REPAIR_MODE=true` *erneut* aufgerufen. Er überspringt dann Phasen 1–10
komplett und arbeitet nur die im Plan benannten Fragmente neu auf.

**Prose-Qualität — zwei Style-Anchors.** Vor jedem Fragment-Write mit
LLM-Prosa (`ms-verdict.json`, `ms-architecture-assessment.json`,
enriched §7-Narrativ) lädt der Renderer ZWEI Files:
- `agents/shared/prose-style.md` — 6 normative Regeln
  (Specificity, Falsifiability, Information-density, Scannable
  structure, No boilerplate, Code identifiers in monospace).
- `agents/shared/prose-samples.md` — 5 Before/After-Pairs aus echten
  Reports plus Banned-Vocabulary-Liste, Voice-Statement, 5-Frage
  Pre-Write Self-Check.

Diese Trennung ist Absicht: prose-style.md trägt die Regeln, prose-samples.md
zeigt sie angewandt. Sonnet imitiert konkrete Beispiele zuverlässiger als
es abstrakten Regeln folgt. Beide Files sind drift-guarded durch
`tests/test_agent_definitions.py::TestProseStyleAnchor` — Renderer und
phase-group-finalization MÜSSEN beide referenzieren, sonst CI rot.

Neue AI-Floskeln, die im Output auftauchen, werden als neues
Before/After-Pair in `prose-samples.md` ergänzt (nicht als neue Regel
in prose-style.md). Regeln ohne Beispiele driften; Beispiele nicht.

---

## 8. Stage 3 + 4 — QA und Architect Review (Ebene 3)

```mermaid
flowchart TB
  comp["compose_threat_model.py geschrieben"]
  comp --> det["qa_checks.py deterministic pre-pass<br/>(Links, Anker, Placeholder, YAML↔MD Konsistenz)"]
  det --> ok{"alle Checks grün?"}
  ok -- ja --> QAskip["QA-LLM überspringen<br/>.qa-status.json source=deterministic-pre-agent"]
  ok -- nein --> qaLLM["appsec-qa-reviewer (Sonnet, 120 turns)<br/>• qa_content (immer Sonnet)<br/>• qa_routine (Haiku in haiku-economy)"]
  qaLLM --> softfix["soft fixes inline anwenden"]
  softfix --> structural{"strukturelle Defekte?"}
  structural -- ja --> repair["repair-plan schreiben → Re-Render Loop<br/>(max 3 Iter.)"]
  structural -- nein --> done1
  QAskip --> done1
  repair --> done1

  done1["threat-model.md final"]
  done1 --> archOpt{"--architect-review gesetzt?"}
  archOpt -- nein --> outFinal
  archOpt -- ja --> arch["appsec-architect-reviewer (Opus, 40 turns)<br/>• schreibt nur .architect-review.md /<br/>  .architect-status.json /<br/>  ggf. .architect-repair-plan.json<br/>• nie threat-model.md/.yaml/SARIF"]
  arch --> archDef{"technischer Defekt?"}
  archDef -- ja --> repair
  archDef -- nein --> outFinal

  outFinal["fertige Artefakte + runtime_cleanup.py"]
```

Wichtig: Der Architect ist **advisory**. Er hat keinen Schreibzugriff auf
die finalen Berichtsartefakte. Bei technischen Defekten gibt er einen
Repair-Plan an die Renderer-Loop.

---

## 9. Artefakt-Datenfluss (Ebene 3)

Welche Datei wird von wem geschrieben, von wem gelesen? Alle Pfade unter
`$OUTPUT_DIR` (default `<repo>/docs/security/`).

```mermaid
flowchart LR
  classDef artifact fill:#eef,stroke:#557,color:#000;

  CR["context-resolver"] -->|schreibt| TMC[".threat-modeling-context.md"]:::artifact
  RS["recon-scanner"]   -->|schreibt| RSU[".recon-summary.md"]:::artifact
  CS["config-scanner"]  -->|schreibt| CSF[".config-scan-findings.json"]:::artifact

  TMC --> O["threat-analyst (Orchestrator)"]
  RSU --> O
  CSF --> O

  O -->|dispatcht je Komponente| ST["stride-analyzer × N"]
  ST -->|schreibt| SJ[".stride-<id>.json"]:::artifact

  SJ --> MT["merge_threats.py collect"]
  MT -->|Kandidaten| TM["threat-merger (LLM)"]
  TM --> MT2["merge_threats.py finalize"]
  MT2 -->|schreibt| TMJ[".threats-merged.json"]:::artifact

  TMJ --> EV["evidence-verifier"]
  EV --> TMJ
  TMJ --> TV["triage-validator"]
  TV -->|schreibt| TF[".triage-flags.json"]:::artifact
  TV --> TMJ

  TMJ --> PG["pregenerate_fragments.py"]
  PG --> FRAG[".fragments/*.{md,json}"]:::artifact

  FRAG --> R["threat-renderer"]
  R --> FRAG
  FRAG --> CMP["compose_threat_model.py --strict"]
  CMP --> MD["threat-model.md"]:::artifact

  %% Substep-2 deterministic migration: sidecars + aggregator
  %% (see §9a below for protocol detail).
  P3X["Phase 3 (Architecture)"] -.-> AC[".components.json"]:::artifact
  P5X["Phase 5 (Assets)"]       -.-> AA[".assets.json"]:::artifact
  P6X["Phase 6 (Attack Surf.)"] -.-> AAS[".attack-surface-overrides.json"]:::artifact
  P7X["Phase 7 (Trust Boun.)"]  -.-> ATB[".trust-boundaries.json"]:::artifact
  P8X["Phase 8 (Sec. Controls)"]-.-> ASC[".security-controls.json"]:::artifact
  TV -.-> AM[".mitigation-overrides.json"]:::artifact
  TV -.-> ATR[".tier-root-causes.json"]:::artifact

  AC & AA & AAS & ATB & ASC & AM & ATR & TMJ --> BLD["build_threat_model_yaml.py<br/>(Phase 11 Substep 2)"]
  BLD --> YML["threat-model.yaml"]:::artifact
  CMP --> CS2[".compose-stats.json"]:::artifact

  MD --> QA["qa-reviewer"]
  YML --> QA
  QA --> QS[".qa-status.json"]:::artifact

  MD --> ARCH["architect-reviewer (opt-in)"]
  YML --> ARCH
  ARCH --> AR[".architect-review.md"]:::artifact
  ARCH --> AS[".architect-status.json"]:::artifact
```

`runtime_cleanup.py` räumt am Ende Transientes auf (Liste:
`docs/cleanup-whitelist.md`), bewahrt aber Audit-Artefakte und
Inkrement-Anker.

---

## 9a. Substep-2 Sidecar-Architektur (Hybrid Python + LLM)

**Problem:** Phase 11 Substep 2 hat historisch das komplette
`threat-model.yaml` vom LLM aus Working-Memory neu komponiert. Das
kostet 15–20 turns am Pipeline-Ende — exakt dort wo das Budget am
knappsten ist (verifiziert: 2026-05-24 juice-shop MAX_TURNS @ turn 150
mid-Phase-11 → bootstrap-stub yaml → forced resume; gleicher root cause
wie 2026-05-03 API-streaming-stall).

**Lösung:** Deterministischer Python-Aggregator
(`scripts/build_threat_model_yaml.py`) liest Intermediates + neue
Phase-Output-Sidecars und schreibt `threat-model.yaml` in 1 turn.
Vollständige Spec: [`docs/substep2-deterministic-migration.md`](substep2-deterministic-migration.md).

```mermaid
flowchart TB
  subgraph EarlyPhases["Phasen 3–10b (LLM, Budget reichlich)"]
    direction TB
    L1["Phase 3 — Architecture Modeling"]
    L2["Phase 5 — Asset Identification (PoC pilot)"]
    L3["Phase 6 — Attack Surface Mapping"]
    L4["Phase 7 — Trust Boundary Analysis"]
    L5["Phase 8 — Security Controls Catalog"]
    L6["Phase 10b — Triage Validation"]
  end

  subgraph Sidecars["Sidecars ($OUTPUT_DIR/.X.json)"]
    direction TB
    SC1[".components.json"]
    SC2[".assets.json"]
    SC3[".attack-surface-overrides.json"]
    SC4[".trust-boundaries.json"]
    SC5[".security-controls.json"]
    SC6[".mitigation-overrides.json"]
    SC7[".tier-root-causes.json"]
  end

  subgraph Builder["Phase 11 Substep 2 (Python, 1 turn)"]
    direction TB
    B1["build_threat_model_yaml.py<br/>• read intermediates + sidecars<br/>• three-stage merge per field<br/>  (baseline → splits/curations → additions)<br/>• cross-ref validate<br/>• schema validate<br/>• atomic write"]
  end

  L1 -- "reserve_ids + cat heredoc<br/>+ validate_fragment" --> SC1
  L2 -- same --> SC2
  L3 -- same --> SC3
  L4 -- same --> SC4
  L5 -- same --> SC5
  L6 -- same --> SC6
  L6 -- same --> SC7

  Sidecars --> B1
  B1 --> YML["threat-model.yaml<br/>(schema-VALID)"]
```

**Drei-Stufen-Merge pro Feld** (Aggregator):
1. **Baseline** aus Intermediates (`.threats-merged.json`, `.route-inventory.json`, `.architecture-coverage.json`, …) — deterministisch
2. **Splits / Curations** aus Sidecar — z.B. M-001 wird zu M-001a + M-001b zerlegt, oder 112 Routes werden auf 21 relevante gefiltert
3. **Additions** aus Sidecar — z.B. Process-Mitigation "Establish dependency-update SLA" die zu keinem einzelnen threat gehört aber ≥ 2 T-IDs adressiert

**Sidecar-Protokoll pro Phase (3 Bash-Calls am PHASE_END)**:
```bash
# 1. ID-Reservierung (atomic via fcntl.LOCK_EX)
IDS=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/reserve_ids.py" \
      asset --count <N> --output-dir "$OUTPUT_DIR")
# 2. Heredoc-Write der strukturierten Daten
cat > "$OUTPUT_DIR/.assets.json" <<'JSON'
  { "schema_version": 1, "assets": [...] }
JSON
# 3. Schema-Gate
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_fragment.py" \
      --type assets "$OUTPUT_DIR/.assets.json"
```

**Wichtige Invarianten**:
- **Single writer pro sidecar.** Phase 5 schreibt `.assets.json`, keine andere Phase modifiziert sie.
- **ID-Counter sind atomic.** `reserve_ids.py` nutzt `fcntl.LOCK_EX` — 20 parallele Prozesse × 5 IDs ergeben 100 unique IDs (verifiziert in `tests/test_reserve_ids.py`).
- **Cross-Refs werden im Aggregator validiert.** Sidecars validieren nur ihre eigene Form. M-IDs in Splits/Additions müssen existierende T-IDs referenzieren (≥1 für evidence-Grounding; ≥2 bei process-Mitigations).
- **Aggregator ruft nie ein LLM auf.** Determinismus ist non-negotiable. Schema-Validierung ist hartes Pre-Write-Gate.
- **Fallback-Pfad.** Solange ein Sidecar fehlt UND prior `threat-model.yaml` existiert, übernimmt der Aggregator das Feld aus dem prior yaml. Damit funktioniert die Migration inkrementell: jeder Schritt ist isoliert revertierbar, bestehende Installations brechen nicht.

**Migrations-Status (2026-05-24)**:
- ✅ `build_threat_model_yaml.py` (Aggregator) — schema-VALID gegen juice-shop
- ✅ `reserve_ids.py` (atomic ID counters) — 11/11 Tests grün
- ✅ 7 Sidecar-Schemas in `schemas/fragments/` — roundtrip-validiert
- ✅ Phase 5 PoC-Wiring — sidecar wird geschrieben, aber Substep 2 nutzt noch LLM-Pfad
- ⏳ Phase 3/6/7/8/10b Wiring — pending nach Ref-Run-Gate-Validierung des Phase-5-PoC
- ⏳ Substep-2-Cutover (commit 7 der Migration) — pending nach Phase-Wiring-Complete

Acceptance-Gates pro Ref-Run-Repo (juice-shop, VulnerableApp, ≥1 internal):
§1-§7 wordcount Δ < 5%, Mermaid-Count identisch, Threat-Count identisch,
Mitigation-Count Δ ≤ 2, F-NNN gap-free, SARIF identisch, Phase 11 ≤ 3 turns,
zero MAX_TURNS events. Details in
[`docs/substep2-deterministic-migration.md` §9](substep2-deterministic-migration.md).

---

## 10. Inkrementelle Runs & Baseline

Inkrementelle Wiederläufe (`--incremental`) sind erste-Klasse-Bürger:

```mermaid
flowchart TB
  s["start"]
  s --> bs["baseline_state.py read<br/>(prior .baseline.json + threat-model.yaml)"]
  bs --> diff["git diff --name-only baseline_sha…HEAD<br/>+ Security-Relevance-Filter"]
  diff --> fp["Inputs-Fingerprint vergleichen<br/>(profile, plugin_version, focus_paths)"]
  fp --> dec{"Änderungen sicherheitsrelevant?"}
  dec -- nein --> fastpath["Fast-Path No-Op-Exit<br/>(keine Phase startet)"]
  dec -- ja --> dirty["Pro Komponente: dirty/clean?"]
  dirty --> dispatchOnly["nur dirty-Komponenten<br/>als STRIDE-Pods dispatchen"]
  dispatchOnly --> carry["clean-Komponenten:<br/>Threats unverändert übernehmen<br/>(T-ID-Stabilität)"]
  carry --> stage1["Stage 1 weiter ab Phase 10"]
```

Verträge:
- `threat-model.yaml` `meta.schema_version: 1` — Bump nur mit Migration.
- T-IDs bleiben stabil; neue IDs kommen aus `id_counters` in
  `.appsec-cache/baseline.json`.
- `changelog[]` ist **append-only**, nie überschreiben.
- `meta.git.commit_sha` = `git rev-parse HEAD` am Ende von Phase 11.

---

## 11. Konfiguration & Depth-Profile

`resolve_config.py emit-file` materialisiert die finalen Run-Parameter in
`.skill-config.json`. Drei Hauptachsen:

**Assessment-Depth** (`--assessment-depth quick|standard|thorough`):

| Depth      | Max Komponenten | STRIDE-Turns (simple/moderate/complex) | Diagramme | QA              |
|------------|-----------------|-----------------------------------------|-----------|-----------------|
| `quick`    | 3               | 10 / 15 / 20                            | minimal   | core only (Stage 3 übersprungen) |
| `standard` | 5               | 15 / 22 / 31                            | standard  | full            |
| `thorough` | 8               | 20 / 28 / 35                            | extended  | extended        |

**Reasoning-Tier** (`--reasoning-model haiku-economy|opus-cheap|sonnet|opus`):
verschiebt das Modell-Routing in der Tabelle aus §2. `haiku-economy` schiebt
zusätzlich `qa_routine` auf Haiku und den Merger auf Sonnet; `opus` hebt
STRIDE/Triage/Merger auf Opus.

**Per-Agent-Overrides** (Env-Vars): `APPSEC_CONTEXT_RESOLVER_MODEL`,
`APPSEC_RECON_SCANNER_MODEL`, `APPSEC_CONFIG_SCANNER_MODEL`,
`APPSEC_ARCHITECT_MODEL`, …

Quick-Mode-Profil (`QUICK_STRIDE_PROFILE`, nur bei
`quick` + `haiku-economy`):
A skip verification greps · B max 2 threats/category · C keep code examples ·
D keep evidence excerpts · E skip CVSS scoring · F turn-budget hard-cap 25.

---

## 12. Hooks & Logging

`hooks/hooks.json` registriert einen `PreToolUse`/`PostToolUse`/`Stop`/
`SubagentStop`-Handler (`scripts/hooks/agent_logger.py`). Er schreibt nach
`docs/security/.hook-events.log` (getrennt von `.agent-run.log`, das die
Agents selbst per Bash-`echo` schreiben).

Ereignisse:
- `AGENT_SPAWN` — jeder Agent-Tool-Aufruf (alle Depths)
- `SCAN_START` / `SCAN_COMPLETE` — top-level threat-analyst
- `AGENT_INVOKE` — non-orchestrator Agents, top-level
- `CONTEXT_READY` — context-resolver hat `.threat-modeling-context.md` geschrieben
- `FILE_WRITE` / `FILE_READ` / `GREP_RUN` / `GLOB_RUN` / `BASH_OK` —
  PostToolUse mit `dur=<sek>` zur Hotspot-Diagnose

Phasen-Logging-Vertrag (`phase-group-architecture.md` →
*MANDATORY PHASE LOGGING CONTRACT*):
- Jede Phase 3–8 bekommt ein eigenes `PHASE_START`/`PHASE_END`-Paar,
  **unmittelbar** vor/nach der Arbeit.
- **Kein Look-Ahead-Logging** (alle PHASE_START vorab dumpen ist Vertrags-
  bruch — verhindert Silent-Death-Diagnose).
- Auto-Repair-Validator am Ende der Gruppe füllt fehlende Marker auf.

---

## 13. Erweitern — wo füge ich was hinzu?

| Vorhaben                                          | Anlaufstelle                                                       |
|---------------------------------------------------|--------------------------------------------------------------------|
| Neue STRIDE-Heuristik / CWE-Schwerpunkt           | `agents/appsec-stride-analyzer.md` + `data/cwe-taxonomy.yaml` / `data/threat-category-taxonomy.yaml` |
| Neue IaC-/Config-Regel                            | `data/config-iac-checks.yaml` (regelbasiert, Haiku-tauglich)       |
| Neuer Walkthrough für CWE-X                       | `data/walkthrough-templates/cwe-X.yaml`                            |
| Neue Sektion im Bericht                           | `data/sections-contract.yaml` + ggf. `pregenerate_fragments.py`    |
| Architektur-Coverage-Check                       | `data/architecture-coverage-rules.yaml`                            |
| Neue Skill                                        | `skills/<name>/SKILL.md` (Routing-File, optional `SKILL-impl.md`)  |
| Bash-Allow-List für unattended runs               | `permissions.md` und `/appsec-advisor:check-permissions`           |
| Schema-Änderung an `threat-model.yaml`            | `schemas/threat-model.schema.json` + Migration + `analysis_version` Bump in `.claude-plugin/plugin.json` |
| Neuer Sub-Agent                                   | `agents/appsec-<name>.md` + Eintrag in `AGENTS.md` (Roster + Routing) + Dispatch im passenden `phase-group-*.md` |

Drift-Guards (`AGENTS.md` → *Drift-Guarded Runtime Contracts*):
- Turn-Budgets sind in `tests/test_agent_definitions.py::TestAgentsMdDocDrift`
  gepinnt.
- Always-cleaned-Pfade sind in `docs/cleanup-whitelist.md` und
  `scripts/runtime_cleanup.py` doppelt gepinnt (Test: `tests/test_runtime_cleanup.py`).
- Schema-Invarianten (T-ID-Stabilität, Append-Only-Changelog) sind in
  `baseline_state.py` validiert.

---

## 14. Glossar (Kurzform)

| Begriff                       | Bedeutung                                                            |
|-------------------------------|----------------------------------------------------------------------|
| **Orchestrator**              | `appsec-threat-analyst`, fährt Phasen 1–11.                          |
| **Phase-Group**               | `agents/phases/phase-group-*.md`, lazy vom Orchestrator gelesen.     |
| **Sub-Agent**                 | Vom Orchestrator per `Agent`-Tool gestarteter Worker mit Turn-Cap.   |
| **Stage 1 / 2 / 3 / 4**       | Threat-Analyse / Rendering / QA / Architect-Review.                  |
| **F-NNN / T-NNN / M-NNN / E-NNN** | Stable IDs für Findings, Threats, Mitigations, Evidence.        |
| **Fragment**                  | Vorgerenderter Markdown/JSON-Baustein für den Composer.              |
| **Dirty-Set**                 | Komponenten, deren `paths` im Git-Diff betroffen sind (incremental). |
| **`--reasoning-model`**       | Wählt das Modell-Tier (Haiku-economy / Opus-cheap / Sonnet / Opus).  |
| **`--assessment-depth`**      | Wählt Komponentencap, STRIDE-Tiefe, Diagrammtiefe, QA-Tiefe.         |
| **Hard-Gate**                 | `check_inline_shortcut.py` nach Stage 2 — exit 0/2 entscheidet.      |
| **Repair-Mode**               | `REPAIR_MODE=true`-Re-Dispatch des Renderers, überspringt 1–10.      |

