# Threat-Modeling-Varianten — Übersicht & Entscheidungshilfe

Dieses Dokument vergleicht die drei `--assessment-depth`-Stufen (`quick` / `standard` / `thorough`) und die vier Reasoning-Tiers (`sonnet` / `opus-cheap` / `haiku-economy` / `opus`) anhand aller relevanten Faktoren — Modell-Routing, Aufgabenumfang, Kosten, Wallclock-Zeit und Output-Tiefe. Stand: post-B2d-Patch (2026-05).

---

## 1. Auf einen Blick — welche Variante wann?

| Use Case | Empfohlene Variante |
|---|---|
| CI-Pipeline / PR-Diff-Check | `--assessment-depth quick` |
| Default für reguläres Code-Review (Repo < 400 Source-Files) | `--assessment-depth standard` (= opus-cheap default) |
| Großes Enterprise-Repo (> 400 Source-Files) | `--assessment-depth standard` (Auto-Switch B2d → haiku-economy) |
| Pre-Release-Audit, Compliance-Sign-off | `--assessment-depth thorough` |
| Maximale Threat-Qualität, Kosten egal | `--assessment-depth thorough --reasoning-model opus` |
| Token-Budget knapp | beliebige Tiefe + `--reasoning-model haiku-economy` |

---

## 2. Strukturparameter pro Tiefe (depth-bound)

Diese Parameter sind **unabhängig** vom Reasoning-Tier — sie skalieren ausschließlich mit `--assessment-depth`.

| Parameter | quick | standard | thorough |
|---|:-:|:-:|:-:|
| `MAX_STRIDE_COMPONENTS` | 3 | 5 (auf großen Repos auf 3 gecappt) | 8 |
| STRIDE-Turn-Budget (simple/moderate/complex) | 10 / 15 / 20 | 15 / 22 / 31 | 20 / 28 / 35 |
| `DIAGRAM_DEPTH` | minimal | standard | extended |
| `QA_DEPTH` | core | full | extended |
| Stage 4 Architect-Review | opt-in | opt-in | **auto-on** |
| `ENRICH_ARCH_FRAGMENTS` | aus | **an** | **an** |
| Auto-Default Reasoning-Tier | `haiku-economy` | `opus-cheap` | `opus-cheap` |
| Auto-Switch B2d (capped repo) | n/a (schon haiku-economy) | → `haiku-economy` | → `haiku-economy` |

### Was die Parameter bedeuten

- **`MAX_STRIDE_COMPONENTS`** — wieviele Major-Komponenten Phase 9 STRIDE separat analysiert. Cap auf 3 bei großen Repos verhindert lange Laufzeiten und schützt das Token-Budget.
- **STRIDE-Turn-Budget** — pro Komponente erlaubte LLM-Tool-Calls. Höher = tieferes Eindringen, mehr Threats, aber lineare Kosten.
- **`DIAGRAM_DEPTH`** — Anzahl/Komplexität der Mermaid-Diagramme in §2 und §3 des Reports.
- **`QA_DEPTH`** — Anzahl/Strenge der Stage-3-Checks (Links, Cross-Refs, Contract).
- **Stage 4 Architect-Review** — zweite Sicht eines Opus-getriebenen Reviewers, advisory only, schreibt `.architect-review.md`.
- **`ENRICH_ARCH_FRAGMENTS`** — Composer überschreibt deterministisch generierte `architecture-diagrams.md` und `security-architecture.md` mit LLM-authored richeren Versionen.

---

## 3. Modell-Routing pro Tier (tier-bound)

Diese Tabelle zeigt **welches Modell** jeder Agent unter welchem Tier benutzt — unabhängig von der Tiefe (Ausnahmen sind explizit markiert).

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

¹ Triage läuft seit M3.1 deterministisch in Python — Modell relevant nur bei `APPSEC_TRIAGE_DETERMINISTIC=0`.

² QA Routine bei `haiku-economy`: **Haiku bei quick + standard**, **Sonnet bei thorough** (denser document, mehr Cross-Refs zu reconciliieren).

---

## 4. Was die vier Tiers wirklich charakterisiert

### `sonnet`
> "Alles Sonnet — keine Premium-Aufpreise, keine Discount-Risiken."
- STRIDE/Triage/Merger: alle Sonnet
- Drei pure-extraction Agents (Context/Recon/Config) auf Haiku — gleich wie in allen Tiers
- **Wann nehmen?** Wenn du jeglichen Opus vermeiden willst (Quota-Knappheit, Audit-Vorgaben "kein Premium-Modell"), aber die Spar-Defaults bei extraction-Phasen schon ok sind.

### `opus-cheap` (Default bei `standard` + `thorough` für reguläre Repos)
> "Konsequenz-kritische Phasen auf Opus, Reasoning-Floor auf Sonnet."
- STRIDE: Sonnet (Wert-erzeugend, aber Sonnet ausreichend)
- **Triage + Merger: Opus** — Konsolidierungs- und Severity-Entscheidungen sind T-ID-stabil-kritisch
- **Wann nehmen?** Default für reguläre Repo-Größen (< 400 Source-Files). Sweet-Spot für Cost/Quality.

### `haiku-economy` (Default bei `quick` + via B2d auch bei großen Repos)
> "Konsequente Sparvariante — STRIDE bleibt Sonnet, alles drumherum schlanker."
- STRIDE/Triage/Merger: alle Sonnet
- QA Routine bei quick+standard: Haiku
- **Spezial bei `quick`**: zusätzliche STRIDE-Aufgabenreduktion **A-F** (siehe §5)
- **Wann nehmen?** Bei großen Repos automatisch (B2d). Manuell bei Token-knappen Runs oder explizit per `--reasoning-model haiku-economy`.

### `opus` (Premium)
> "STRIDE auf Opus für Top-Threat-Quality."
- **STRIDE: Opus** — höchste Reasoning-Qualität in der wertschöpfenden Phase
- Triage + Merger: Opus
- **Wann nehmen?** Wenn maximale Threat-Qualität gefordert ist und ~5× Kosten gegenüber sonnet akzeptabel sind. Empfehlung: nur in Kombination mit `thorough` (8 Komponenten).

---

## 5. STRIDE-Aufgabenreduktion A-F (nur quick + haiku-economy)

Diese Reduktionen schalten **nur** bei der Kombination `--assessment-depth quick --reasoning-model haiku-economy` (= Default bei quick) und reduzieren den **Aufgabenumfang** in Phase 9, nicht die Modell-Qualität (STRIDE bleibt auf Sonnet).

| ID | Reduktion | Effekt |
|---|---|---|
| **A** | `skip_verification_greps` | Keine Beweissuche im Code per zusätzlichem `grep` |
| **B** | `max_threats_per_category=2` | Max 2 Threats pro STRIDE-Kategorie/Komponente (statt 2-5) |
| **C** | `skip_code_examples` | Keine Code-Snippets in Threat-Findings |
| **D** | `skip_evidence_excerpt` | Keine Evidence-Zitate aus Quelldateien (file:line bleibt) |
| **E** | `skip_cvss_scoring` | Kein CVSS-Scoring (manuell nachrechnen) |
| **F** | `turn_budget_hard_cap=25` | Max 25 Turns pro Komponente (statt 40) |

**Auswirkung:** Phase 9 läuft ~50 % schneller und produziert ~30 % weniger Threats pro Komponente, fokussiert auf die wichtigsten. Ideal für PR-Reviews oder Smoke-Tests.

---

## 6. Auto-Switch B2d — kontextabhängiges Default-Verhalten

Wenn der User **kein** `--reasoning-model` setzt, schaltet der Resolver automatisch:

| Zustand | Default-Tier | Begründung |
|---|---|---|
| `quick` | `haiku-economy` | bewusste Sparvariante für CI/PR-Use-Case |
| `standard`, Repo < 400 Source-Files | `opus-cheap` | Triage/Merger auf Opus rentabel bei größerem Workload |
| `standard`, Repo > 400 Source-Files | **`haiku-economy` (B2d auto)** | 3-Component-Cap → Workload zu klein für Opus-Aufpreis |
| `thorough` | `opus-cheap` | Default — User kann gezielt `--reasoning-model opus` setzen für Premium |

In der Configuration Summary erkennbar an:
```
Reasoning    : haiku-economy (auto — large repo capped to 3 components,
                              Opus on merger/triage uneconomical at this scale)
```

Override jederzeit möglich durch explizites `--reasoning-model <tier>`.

---

## 7. Kosten-Schätzung (Juice-Shop, 608 Source-Files, post-Patch)

| Tiefe \ Tier | sonnet | opus-cheap | haiku-economy | opus |
|---|---:|---:|---:|---:|
| **quick** | ~$1,80 | ~$2,30 | **~$1,80** ¹ | ~$5,50 |
| **standard** | ~$3,70 | ~$4,70 | **~$3,70** ² | ~$11,00 |
| **thorough** | ~$5,80 | ~$7,40 | **~$5,30** ² | ~$17,00 |

¹ = Auto-Default bei quick. ² = via B2d Auto-Switch bei capped repos.

### Wo die Kosten-Unterschiede entstehen

| Phase | sonnet | opus-cheap | haiku-economy | opus |
|---|---|---|---|---|
| Phase 1-2.5 (Setup) | gleich (~$0,30) | gleich | gleich | gleich |
| Phase 3-8 (Orch) | gleich (~$0,40) | gleich | gleich | gleich |
| **Phase 9 STRIDE** | $1,50 (S) | $1,50 (S) | $1,50 (S) | **$7,50** (O, +400 %) |
| **Phase 9 Merger** | $0,10 (S) | **$0,50** (O) | $0,10 (S) | **$0,50** (O) |
| Phase 10/10b | gleich | gleich | gleich | gleich |
| Stage 2 Compose | gleich (~$0,80) | gleich | gleich | gleich |
| Stage 3 QA | $0,40 (S) | $0,40 (S) | $0,30 (H+S split) | $0,40 (S) |
| Stage 4 Architect (thorough) | $1,50 (O) | $1,50 (O) | $1,50 (O) | $1,50 (O) |

**Schlüssel-Insight:** Der Kosten-Hebel bei `opus` liegt zu ~80 % an Phase 9 STRIDE. Der Kosten-Hebel bei `haiku-economy` liegt zu ~70 % am Merger-Downgrade Opus → Sonnet (gegenüber `opus-cheap`).

---

## 8. Wallclock-Zeit (Juice-Shop, post-Patch)

| Tiefe \ Tier | sonnet | opus-cheap | haiku-economy | opus |
|---|---:|---:|---:|---:|
| **quick** | ~12 min | ~14 min | **~10 min** | ~25 min |
| **standard** | ~22 min | ~25 min | **~22 min** | ~50 min |
| **thorough** | ~35 min | ~40 min | **~33 min** | ~75 min |

**Wichtig:** Diese Werte gelten unter optimalen Bedingungen. WSL2/Modern-Standby-Freezes können einen Run beliebig in die Länge ziehen — siehe [Modern-Standby-Mitigation](#10-empfohlene-system-konfiguration).

---

## 9. Output-Unterschiede pro Tiefe

### quick
- 3 Komponenten × max 2 Threats/Kategorie ≈ **15-25 Threats**
- Keine Code-Snippets, kein CVSS, keine Evidence-Zitate
- 1-2 Mermaid-Diagramme (minimal)
- Nur Core-QA-Checks
- Optimal für: PR-Diff-Reviews, schneller "Health-Check"

### standard
- 3-5 Komponenten × volle STRIDE ≈ **30-50 Threats**
- Mit Code-Snippets, CVSS, Evidence-Zitaten
- 4-6 Mermaid-Diagramme (Architecture, Data Flow, Attack Chains)
- Volle QA inkl. Cross-References, Contract-Checks
- Optimal für: regulärer Code-Review, MR/PR-Templates

### thorough
- 8 Komponenten × extra-tiefes STRIDE ≈ **60-100 Threats**
- Detailed Code-Snippets + Sequenz-Diagramme pro Critical
- 6-10 Mermaid-Diagramme (extended) + LLM-enriched Architecture
- Extended QA + Architect-Review-Layer
- Optimal für: Pre-Release-Audits, Compliance-Sign-off, Pen-Test-Vorbereitung

---

## 10. Empfohlene System-Konfiguration (WSL2)

Lange Runs (`thorough`, oder `standard` auf großen Repos) sind anfällig für Windows Modern Standby, das WSL2-Userspace-Prozesse über cgroup-freezer einfriert. Mitigation:

**`C:\Users\<DeinName>\.wslconfig` (Windows-seitig):**
```ini
[wsl2]
autoMemoryReclaim=disabled
vmIdleTimeout=-1
```

Nach dem Speichern WSL neu starten:
```powershell
wsl --shutdown
```

**Während des Runs:**
- "Hochleistung"-Energieprofil aktivieren
- Optional: `powercfg /requestsoverride process bash.exe SYSTEM` zur Standby-Verhinderung
- Alternativ: PowerToys "Awake" oder Caffeine-Tool

---

## 11. Per-Agent-Override via ENV-Variablen

Höchste Präzedenz — überschreibt jeden Tier für genau einen Run. Nutzbar wenn man für einen einzelnen Agent von der Default-Empfehlung abweichen will:

```bash
APPSEC_CONTEXT_RESOLVER_MODEL=claude-sonnet-4-6      # statt Haiku
APPSEC_RECON_SCANNER_MODEL=claude-sonnet-4-6         # statt Haiku
APPSEC_CONFIG_SCANNER_MODEL=claude-sonnet-4-6        # statt Haiku
APPSEC_QA_ROUTINE_MODEL=claude-sonnet-4-6            # statt Haiku/Sonnet
APPSEC_QA_CONTENT_MODEL=claude-opus-4-7              # statt Sonnet
APPSEC_STRIDE_MODEL=claude-opus-4-7                  # statt Sonnet
APPSEC_TRIAGE_MODEL=claude-opus-4-7                  # statt Sonnet/Opus
APPSEC_MERGER_MODEL=claude-opus-4-7                  # statt Sonnet/Opus
APPSEC_ORCHESTRATOR_MODEL=claude-opus-4-7            # statt Sonnet
```

Beispiel — STRIDE auf Opus, Rest unverändert:
```bash
APPSEC_STRIDE_MODEL=claude-opus-4-7 \
  /appsec-advisor:create-threat-model --rebuild --assessment-depth thorough
```

---

## 12. Entscheidungsmatrix in einer Zeile

| Wenn dein Ziel … | … dann nimm … |
|---|---|
| schnell + billig auf jedem Repo | `quick` (Default) |
| solides Standard-Review auf normalem Repo | `standard` (= opus-cheap auto) |
| solides Standard-Review auf 600+-File-Repo | `standard` (= haiku-economy auto via B2d) |
| volle Tiefe auf normalem Repo | `thorough` (= opus-cheap auto + Architect-Review) |
| Premium-Quality unabhängig von Kosten | `thorough --reasoning-model opus` |
| Token-Knappheit egal welcher Tiefe | `--reasoning-model haiku-economy` (explizit) |
| jegliches Opus vermeiden (Compliance/Quota) | `--reasoning-model sonnet` |

---

## Anhang — Quellen & Verifikation

- **Modell-Routing-Matrix:** `scripts/resolve_config.py` → `EXTENDED_MODEL_MATRIX`, `_DEFAULT_EXTENDED_ROUTING`, `MODEL_MATRIX`
- **Strukturparameter pro Tiefe:** `scripts/resolve_config.py` → `DEPTH_PARAMS`
- **Repo-Size-Cap (B2c):** `scripts/resolve_config.py` → `resolve_repo_size_cap`, Trigger bei > 400 Source-Files
- **Auto-Switch (B2d):** `scripts/resolve_config.py` → `resolve_default_tier_for_capped_repos`
- **STRIDE-Aufgabenreduktion A-F:** `scripts/resolve_config.py` → `QUICK_STRIDE_PROFILE`
- **Tests:** `tests/test_haiku_routing_per_depth.py` (37 Tests pinnen die Matrix), `tests/test_resolve_config.py::TestResolveDefaultTierForCappedRepos` (6 Tests pinnen B2d)

Test-Coverage-Stand (post-Patch): **134 grüne Tests** im Resolver- und Routing-Bereich.
