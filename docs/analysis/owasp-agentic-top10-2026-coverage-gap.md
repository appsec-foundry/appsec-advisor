# OWASP Top 10 for Agentic Applications 2026 (ASI) — Coverage-Gap-Analyse

**Datum:** 2026-07-16 · **Status:** Analyse (nichts umgesetzt) · **Frage:** Bildet das Plugin die
OWASP Agentic Top 10 (2026, ASI01–ASI10) vollständig ab, und werden Findings mit passenden Referenzen verlinkt?

Quelle: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
(veröffentlicht 2025-12-09; Item-Details verifiziert über die DeepTeam-Framework-Doku).

> **Nachtrag 2026-07-16 — Vergleich mit den etablierten Katalogen** (Web/API/LLM):
> siehe Abschnitt „Reifegrad aller OWASP-Kataloge im Plugin" am Ende. Kernaussage: der
> Reifegrad fällt stark ab — **Web 2021 (stark) › LLM 2025 (mittel) › API 2023 (dekorativ) › ASVS (nur Vokabular) › ASI 2026 (fehlt)**.

---

## TL;DR — Verdikt

**Nein, nicht vollständig — und die vorhandene Abdeckung ist der *falsche* OWASP-Katalog.**

Das Plugin implementiert die **OWASP Top 10 for LLM Applications (2025)** (LLM01–LLM10), *nicht* die
**Agentic Top 10 (2026)** (ASI01–ASI10). Im gesamten Repo gibt es **null ASI-Referenzen**
(`grep -rniE 'ASI[0-9]|inter-agent|rogue agent|goal hijack'` → nur LLM-Treffer).

- Die LLM-2025-Linse ist **prompt-/modell-zentrisch** (Prompt Injection, Excessive Agency, Output-Handling …).
- Die ASI-2026-Linse ist **verhaltens-/autonomie-zentrisch** (Goal-Hijack über mehrere Schritte,
  Agent-zu-Agent-Trust, persistentes Memory, Multi-Agent-Kommunikation, kaskadierende Ausfälle, Rogue Agents).

Die Überschneidung deckt **~3 von 10** ASI-Kategorien brauchbar ab. Sechs Kategorien haben **keine oder nur
marginale** Abdeckung — genau die, die *agentisch* (nicht bloß LLM-basiert) sind.

**Referenz-Verlinkung (Nachfrage):** Findings tragen heute `CWE`, `owasp_top10_2021`/`owasp_api2023`/`owasp_asvs`
(über TH-NN), `finding_type` (FT-NNN) und — nur im MS-Fragment — `owasp_llm_id` (LLM01–LLM10). Ein
**`owasp_asi_id`-Feld existiert nicht**. Selbst dort, wo ASI inhaltlich getroffen wird, fehlt also das Referenz-Badge.

---

## Was das Plugin heute abdeckt (Ist-Zustand)

| Baustein | Ort | Wirkung |
|---|---|---|
| AI-Surface-Detektion (deterministisch) | `scripts/recon_patterns.py:2468` `scan_ai_integration` / `_CAT13_GROUPS` | erkennt LLM-SDKs, Vector-DBs, **Agent-Frameworks** (`AgentExecutor`, `ReActAgent`, `create_tool_calling_agent`), Prompt-Frameworks, Tokenizer, Modellnamen; **crewai/autogen** (Multi-Agent) als `llm-sdk` strong (Zeile 2510); weak: `tool-use`, `embedding` |
| MCP-Config-Detektion | `scripts/recon_patterns.py:2184` **Cat-28** `scan_ai_assistant_configs` (`_MCP_CONFIG_NAMES`, `mcp-local/remote/registry-server`, `mcp-hardcoded-secret`) | erkennt `.mcp.json` etc. — **aber** als *Supply-Chain-Signal für die Dev-/IDE-Tooling*, **explizit von der App-AI-Surface ausgeschlossen** (Cat-13-local skip, Kommentar Z. 2555–2566) und **nicht** in `_is_llm`/LLM-Linse verdrahtet (verifiziert: kein Bezug) |
| Role-Floor „AI/LLM mandatory" | `scripts/build_stride_dispatch_manifest.py` `_is_llm` | LLM-Komponente wird auf jeder Tiefe analysiert, nie als „internal-only" verworfen |
| Analyse-Linse | `agents/shared/owasp-llm-top10.md` | **OWASP LLM Top-10 (2025)** als Zusatzlinse über STRIDE; LLM01–LLM10 mit Grep-Ankern + Fix-Patterns |
| Executive-Surfacing + Referenz-Badge | `schemas/fragments/ai-exposure.schema.json`, `agents/appsec-threat-renderer.md:268` | MS-Callout „AI / LLM Exposure" mit `owasp_llm_id`-Badge (Enum LLM01–LLM10) |
| CWE-Anker | `data/cwe-taxonomy.yaml:575` „Excessive Agency" | einzelner agentischer CWE bereits im Katalog |

Fazit Ist-Zustand: Solide **LLM-App-Sicht**, agentische Konstrukte werden zwar teils *detektiert*
(Agent-Framework, Multi-Agent-SDK, Tool-Use), aber die nachgelagerte **Analyse-Linse fragt keine
agent-spezifischen Fragen** — sie bleibt auf Prompt/Modell/Output.

---

## ASI01–ASI10 → Ist-Abdeckung

Legende: 🟢 brauchbar · 🟡 partiell (über LLM-Linse gestreift) · 🔴 keine/marginale Abdeckung

| ASI | Kategorie | Nächste Ist-Abdeckung | Verdikt | Lücke |
|---|---|---|---|---|
| **ASI01** | Agent Goal Hijack | LLM01 Prompt Injection (direkt/indirekt) | 🟡 | Recursive/Cross-Context-Hijack, Zielpersistenz über Multi-Step-Pläne nicht modelliert |
| **ASI02** | Tool Misuse & Exploitation | LLM06 Excessive Agency (Tool-Permission-Frage) | 🟡 | Tool-Chain-Komposition, unsichere Delegation, **Tool-Output als Injection-Vektor** fehlen |
| **ASI03** | Agent Identity & Privilege Abuse | generische AuthZ/BOLA (TH-Kategorien, web) | 🔴 | Agent-zu-Agent-Trust, geerbte/gecachte Credentials, Identity-Inheritance über Agent-Ketten |
| **ASI04** | Agentic Supply Chain | Supply-Chain (Deps/CI/Container) stark; LLM03 Model Supply Chain | 🟡 | **Tool-Deskriptoren, MCP-Server, Agent-Personas/Plugins** als Tamper-Vektor fehlen |
| **ASI05** | Unexpected Code Execution | RCE/CWE-94 stark; LLM05 Improper Output Handling (`eval(response)`) | 🟡 | Agent-generierter Code, Code-Interpreter-Tool, Sandbox-Isolation nicht agent-spezifisch |
| **ASI06** | Memory & Context Poisoning | LLM04 Data/Model Poisoning + LLM08 Vector/Embedding (RAG) | 🔴 | **Persistentes Agent-Memory** über Sessions, State-/Context-Korruption nicht modelliert |
| **ASI07** | Insecure Inter-Agent Communication | — | 🔴 | Keine Multi-Agent-Topologie-/A2A-Protokoll-Analyse |
| **ASI08** | Cascading Agent Failures | LLM10 Unbounded Consumption (nur Single-Agent) | 🔴 | Fehler-/Feedback-Propagation, Ressourcen-Erschöpfung über Agenten hinweg |
| **ASI09** | Human-Agent Trust Exploitation | LLM09 Misinformation (streift) | 🔴 | Over-Trust in Agent-Output, UI-Deception, Social-Engineering-via-Agent |
| **ASI10** | Rogue Agents | — | 🔴 | Misaligned/kompromittiertes Agent-Verhalten, Autonomie-Grenzen, Kill-Switch |

**Score: 🟢 0 · 🟡 4 · 🔴 6.** Die agentischen Kernrisiken (ASI03/06/07/08/09/10) sind die Lücke.

---

## Referenz-Verlinkung — der zweite Befund

Der bestehende Verlinkungs-Mechanismus ist sauber gebaut und **direkt als Vorbild nutzbar**:

- Finding → CWE → `TH-NN` (`data/threat-category-taxonomy.yaml`) → trägt `owasp_top10_2021`, `owasp_api2023`, `owasp_asvs`.
- LLM-Risiken → `owasp_llm_id` (LLM01–LLM10) im MS-Fragment, gerendert als führendes Badge, an Findings verankert
  (`agents/appsec-threat-renderer.md:268`).

Es fehlt exakt das analoge Glied für ASI: **kein `owasp_asi_id`-Feld**, keine ASI-Vokabular-Datei, kein Badge.
Wenn ASI-Nachschärfung kommt, muss die Referenz-Verlinkung von Anfang an mitgezogen werden (siehe unten R3) —
sonst entsteht wieder eine Kategorie ohne klickbare Referenz, genau das, was vermieden werden soll.

---

## Empfehlungen zum Nachschärfen (Vorschlag — nicht umgesetzt)

Reihenfolge = Aufwand/Nutzen. Jede Empfehlung nennt das existierende Muster, dem sie folgt.

**R1 — ASI als eigene Analyse-Linse (Kern).**
Neue Datei `agents/shared/owasp-asi-top10.md` analog zu `owasp-llm-top10.md`: pro ASI01–ASI10 eine
Analyse-Frage + Evidence-Anker + Fix-Pattern. Wird — wie die LLM-Linse — *zusätzlich zu STRIDE* nur
dann aktiviert, wenn `_is_llm`/Agent-Signale feuern. Kein neuer Pflicht-Overhead für Nicht-Agent-Repos.

**R2 — Detektions-Signale für agentische Konstrukte erweitern.**
Was **fehlt** (verifiziert): persistentes Memory (`ConversationBufferMemory`, `memory=`, Checkpointer,
LangGraph-State), Multi-Agent-Topologie (`Crew(`, `AgentGraph`, `handoff`, `swarm`). Diese in `_CAT13_GROUPS`
ergänzen — sie differenzieren, *welche* ASI-Fragen relevant sind (z. B. ASI06 nur bei Memory-Store, ASI07/08
nur bei Multi-Agent-Topologie).
Beim **MCP** liegt es anders: `.mcp.json` wird bereits erkannt, aber nur unter **Cat-28** als
*Dev-Tooling-Supply-Chain* und **absichtlich** von der App-AI-Surface (Cat-13) ausgeschlossen. Für ASO
müsste MCP-als-Laufzeit-Tool-Surface der *analysierten App* separat als Cat-13-Signal aufgenommen werden —
nicht der Cat-28-Skip aufgeweicht (der ist korrekt: die MCP-Config des Entwicklers ≠ Agent-Surface des Zielsystems).
Agent-Framework/crewai/autogen werden bereits als AI-Surface erkannt.

**R3 — Referenz-Feld `owasp_asi_id` (die konkrete Nachfrage).**
Enum `ASI01`–`ASI10` spiegelbildlich zu `owasp_llm_id`:
- Schema: `ai-exposure.schema.json` um optionales `owasp_asi_id` erweitern (bzw. separates Fragment/Feld).
- Renderer: `appsec-threat-renderer.md` — ASI-Namensvokabular + Badge-Rendering wie bei LLM.
- Anker: jede ASI-kategorisierte Finding trägt das Badge und verlinkt auf die konkrete Finding/§7.
- **Bidirektionaler Contract** (AGENTS.md §4): Producer + Schema + Consumer + Validation + Tests zusammen.

**R4 — Crosswalk-Tabelle statt Doppelpflege.**
OWASP liefert selbst einen ASI↔LLM/AIVSS-Crosswalk. Für die 🟡-Fälle (ASI01/02/04/05) genügt eine
Mapping-Tabelle (LLM0x → ASI0y), damit bestehende LLM-Findings automatisch das ASI-Badge erben. Nur die
🔴-Fälle (ASI03/06/07/08/09/10) brauchen echte neue Analyse-Logik aus R1/R2.

**R5 — Scope-Ehrlichkeit dokumentieren.**
Bis R1–R4 stehen: in `docs/threat-modeler.md` (Zeile ~80, „GenAI / LLM Security") klarstellen, dass die
Abdeckung *LLM App Top-10 (2025)* ist, nicht *Agentic Top-10 (2026)* — damit der Report keine
Vollständigkeit suggeriert, die er nicht hat.

---

## Aufwands-/Risiko-Notiz

- R3 + R4 sind **klein** (Feld + Mapping, folgt exakt dem `owasp_llm_id`-Muster) und liefern sofort die
  gewünschte Referenz-Verlinkung für die bereits getroffenen Kategorien.
- R1 + R2 sind **mittel** und bringen die 🔴-Kategorien inhaltlich hinein.
- ASI07/08/10 sind konzeptionell am härtesten: sie brauchen ein **Multi-Agent-Topologie-Modell**, das das
  Plugin (heute Single-System-STRIDE) nicht besitzt — hier ehrlich als „erkannt, nicht tief analysiert"
  ausweisen statt vortäuschen.
- Contract-Disziplin beachten: neue IDs additiv, `owasp_asi_id`-Enum stabil, keine Schema-Aufweichung nur
  um Output durchzuwinken (AGENTS.md §4/§5/§12).

---

## Reifegrad aller OWASP-Kataloge im Plugin (verifiziert 2026-07-16)

| Katalog | Edition | Ref-Feld | Feld-Abdeckung | Auf Findings gerendert/verlinkt | Analyse-Linse | Deterministisches Completeness-Gate |
|---|---|---|---|---|---|---|
| **Web Top 10** | **2021** | `owasp_top10_2021` | **19/19 TH** ✅ | ✅ klickbar `[A0x:2021](owasp.org/…)` (`compose:14655`, §8-Cards `phase-group-finalization.md:1623+`) | über STRIDE→TH-Mapping (implizit) | ✅ **ja** — `coverage_checks.py` Check A: jede A01–A10 braucht ≥1 Threat, sonst `source: coverage-gap` (Basis: `owasp-top10-cwes.yaml`) |
| **LLM Top 10** | **2025** | `owasp_llm_id` (LLM01–10) | Enum, MS-Fragment | ✅ Badge im MS-Callout „AI/LLM Exposure", an Findings verankert | ✅ **ja** — `agents/shared/owasp-llm-top10.md` (aktiv wenn `_is_llm` feuert) | ⚠️ **nein** — bleibt LLM-Judgement (`coverage_checks.py:20`: „C … conditional") |
| **API Top 10** | **2023** | `owasp_api2023` | **nur 3/19 TH** ⚠️ | ❌ **nirgends gerendert** (Taxonomie-Kommentar: „Pure label field") | ❌ **keine** (kein `owasp-api-top10.md`) | ❌ **kein Gate** |
| **ASVS** | v4 | `owasp_asvs` | 19/19 TH | ⚠️ nur §6-H4-Titel-*Vokabular*-Alignment (`pregenerate_fragments.py:4003`), **kein Ref-Link** | ❌ | ❌ |
| **Agentic (ASI)** | **2026** | — | **0** | ❌ | ❌ | ❌ |

### Befunde je Katalog

- **Web 2021 = Goldstandard im Plugin.** Vollständige Feldabdeckung, klickbare Referenzen *und* ein
  deterministisches Gate, das fehlende Kategorien als Gap-Threat injiziert. Einziger Punkt: **Edition 2021** —
  eine OWASP-Top-10-**2025**-Ausgabe existiert; Katalog + URLs sind eine Edition alt (prüfen/aktualisieren,
  aber additiv, IDs stabil halten).
- **LLM 2025 = zweitbest.** Aktuelle Edition, echte Analyse-Linse, Badge + Verankerung — **aber** nur bei
  vorhandener LLM-Surface, nur im MS-Fragment, und **ohne** deterministisches Completeness-Gate (LLM-Urteil).
- **API 2023 = de facto dekorativ — die eigentliche Überraschung.** Nur 3 von 19 TH tragen `owasp_api2023`,
  es wird **nie gerendert**, es gibt **keine API-Linse** und **kein Gate**. Gleichzeitig *findet* das Plugin
  API-Top-10-Klassen bereits (BOLA=API1, Mass-Assignment=API6, JWT/Auth=API2 — vgl. Access-Control-Overhaul).
  Die Analyse ist also da, nur das **Referenz-Label + Rendering fehlt** → geringer Aufwand, hoher Nutzen,
  **höher priorisiert als ASI**, weil keine neue Analyse-Logik nötig ist (analog R3/R4: Feld rendern + Crosswalk).
- **ASVS = Metadaten.** 19/19 getaggt, aber nur zur H4-Titel-Benennung genutzt; keine klickbare Referenz.
- **ASI 2026 = fehlt komplett** (Hauptteil oben).

### Priorisierung über alle Kataloge (Referenz-Verlinkung als Leitmotiv)

1. **API-2023-Badges rendern + `owasp_api2023` auf alle relevanten TH ausweiten** (Analyse existiert schon) — *quick win*.
2. **`owasp_asi_id` + ASI-Crosswalk** für die bereits getroffenen 🟡-ASI-Kategorien (R3/R4).
3. **Web-Top-10-Edition 2025** prüfen/nachziehen (additiv).
4. **LLM- und (neu) ASI-Completeness-Gate** deterministischer machen (heute nur Web hat ein echtes Gate).
5. **ASI-Kern-Analyse** (R1/R2) für die 🔴-Kategorien — größter Aufwand.
