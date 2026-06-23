# Analyse: Modell-Platzierung — Orchestrator (Opus vs Sonnet) und STRIDE (Opus vs Sonnet)

> **⚠ KORREKTUR 2026-06-22 — der STRIDE-Teil dieser Analyse ist unvalidiert.**
> Später wurde verifiziert (`_agent_model`-Auflösung + Real-Logs), dass der
> Parallel-STRIDE-Dispatch den Agent-`model`-Parameter **nicht setzt**, sodass die
> STRIDE-Analyzer still auf ihren Frontmatter-Default **Sonnet** zurückfallen — auch
> in den hier ausgewerteten Läufen lief STRIDE faktisch auf **Sonnet**, nur Triage auf
> Opus. Die Kernaussage „Opus-STRIDE ist besser **und** billiger" beruht damit auf
> Läufen, in denen Opus-STRIDE **nie ausgeführt wurde** — sie ist **nicht belegt**.
> Der `$9 opus`-Anteil von V3 war vermutlich Triage/Merger, nicht STRIDE. Erst ein Lauf
> mit beweisbar auf Opus laufendem STRIDE (Dispatch-Fix + `stride_model_mismatch`-Gate,
> umgesetzt 2026-06-22) erlaubt eine echte Messung. Die Orchestrator-Aussagen (§3/§4)
> sind davon unberührt.
>
> **UPDATE 2026-06-23 — diese Messung liegt jetzt vor (§10): die A/B widerlegt §5a.**
> Mit beweisbar auf Opus laufendem STRIDE und sonst identischen Flags ist Opus-Reasoning
> **$40.78 vs $30.01 = $10.77 teurer**, nicht billiger. Die „Opus-billiger"-These ist falsch;
> es bleibt ein reiner Qualität-gegen-Kosten-Trade-off. Details + Severity-/Surface-Daten in §10.

Status: **Analyse / Empfehlung — Code NICHT umgesetzt.** Die Doku-Klarstellungen zur
Orchestrierungs-Kostenformel sind umgesetzt (siehe §8); die Modell-Default-Änderung
(`opus` fürs Reasoning + B2d-Invertierung) ist offen und an eine Verifikation (Stufe 0)
gebunden.

Empirische Basis: **N = 1 Repo** (OWASP Juice Shop), drei Standard-Full-Läufe vom
2026-06-21. Richtungsaussagen sind belastbar; exakte Prozent-/Kostenwerte sind
benchmark-abhängig und nicht zu verallgemeinern. Quelle der Rohdaten: die drei
`/cost`-Ausgaben + Run-State unter `~/scans2/juice-shop/{standard-opus-orchestrator,
standard-stride-orchestrator,standard-stride-orchestrator-opus-reasoning}/`.

---

## 0. TL;DR

- **Gleiches Modell — der Hebel ist die *Platzierung*, nicht das Modell.**
- **Opus auf den Orchestrator = verbranntes Geld.** Die Orchestrierungsschicht ist
  ~40–50 % eines Opus-getriebenen Laufs; sie auf Opus zu fahren addiert grob **+25–55 %
  aufs Total** (proportional, wächst mit Lauf-Länge/Repo-Größe — kein Fixbetrag) und
  vertieft die Analyse **nicht**.
- **Opus auf STRIDE/Triage/Merge = der einzige Hebel, der die Qualität hebt** — und auf
  diesem (großen) Repo war es sogar **billiger** als reines Sonnet.
- **Empfehlung:** Default `standard`/`thorough` → STRIDE auf **Opus**; den
  größen-getriggerten Auto-Downgrade (`B2d`) **abschalten/invertieren**; `opus-cheap`
  deprecaten. Sonnet-STRIDE nur noch in `quick` + explizitem Opt-out.

---

## 1. Versuchsaufbau

Drei Läufe, alle `--assessment-depth standard --full`, gegen dasselbe Juice-Shop-Repo.
Der Verzeichnisname beschreibt die **treibende Claude-Code-Session**, nicht die interne
Pipeline. Intern ist `orchestrator_model` in allen drei `sonnet` (per Matrix immer
`claude-sonnet-4-6`).

| Variante | Treiber-Session | `reasoning_model` | `stride/triage/merger` |
|---|---|---|---|
| **V1** `standard-opus-orchestrator` | **Opus** | sonnet-economy (auto) | sonnet / sonnet / sonnet |
| **V2** `standard-stride-orchestrator` | Sonnet | sonnet-economy (auto) | sonnet / sonnet / sonnet |
| **V3** `…-opus-reasoning` | Sonnet | **opus** | **opus / opus / opus** |

Wichtig: V1 und V2 haben **byte-identische interne Pipeline-Configs** — der einzige
Unterschied ist das Modell der Treiber-Session. Das macht **V1 − V2 = Effekt von
Opus-als-Orchestrator** und **V3 − V2 = Effekt von Opus-im-Reasoning** (gegen dieselbe
Sonnet-Treiber-Session) zu zwei sauberen natürlichen Experimenten.

Beleg, dass V1/V2 intern keine Analyse-Phase auf Opus hatten — das `reasoning_label`
aus `.skill-config.json`:

> sonnet-economy (auto — large repo: economy tier across all criteria-selected
> components; **Opus on merger/triage uneconomical at this scale, STRIDE stays Sonnet**)

Der Auto-Switcher hat die Pipeline wegen Repo-Größe heruntergestuft; `.agent-run.log`
zeigt in V1/V2 **0 Opus-Subagenten** (nur sonnet+haiku). In V1 ging der gesamte
Opus-Betrag also in die äußere Session (Glue/Dispatch), nicht in die Analyse.

---

## 2. Rohdaten

| | V1 opus-orchestrator | V2 sonnet (Kontrolle) | V3 opus-reasoning |
|---|---|---|---|
| **Kosten** | **$42.01** | $33.66 | **$31.78** |
| davon Opus | $21.46 | – | $9.08 |
| davon Sonnet | $20.36 | $33.66 | $22.06 |
| davon Haiku | $0.19 | – | $0.64 |
| API-Dauer | 1h 55m | 2h 10m | 2h 05m |
| Wall-Dauer | 1h 12m | 1h 44m | *8h 42m ⚠️* |
| **Findings** | 71 | 50 | **74** |
| Mitigations | 74 | 50 | **76** |
| Severity (C/H/M/L) | 13 / 50 / 5 / 3 | 14 / 27 / 8 / 1 | **8 / 38 / 18 / 10** |
| % Crit/High | 89 % | 82 % | **62 %** |
| „✓ verified"-Marker | 64 / 71 | 45 / 50 | **70 / 74 (95 %)** |
| STRIDE-Komponenten | 8 (+ai-chatbot, +b2b-api) | 7 (+marsdb) | 8 (**+web3**, +llm-chat) |

⚠️ **V3-Wall (8h 42m) ist kontaminiert** — die Session lag idle/suspended. Nur API-Zeit
und Kosten sind belastbar. V1s 1h 12m Wall ist auffällig niedrig (API-Latenz-Glück,
nicht strukturell schneller); alle drei API-Zeiten liegen im Band 1h55–2h10.

Token-Deltas (aus `/cost`, autoritativ über den ganzen Lauf):

| Sonnet-Verbrauch | V2 | V3 | Δ |
|---|---|---|---|
| output | 355.2k | 220.5k | **−38 %** |
| cache-read | 67.4m | 41.6m | **−38 % (−25.8m)** |
| input | 145.3k | 68.3k | −53 % |

---

## 3. Befund A — Opus als Orchestrator: kein analytischer Mehrwert, hoher Preis

V1 (Opus-Session) liefert 71 Findings gegen V2s 50 — aber da Opus in V1 **null Analyse**
machte (Pipeline byte-identisch zu V2, 0 Opus-Subagenten), ist dieser Vorsprung nur
zuzuordnen auf (a) bessere Orchestrierungs-/Inventar-Urteile der Opus-Session oder
(b) Lauf-zu-Lauf-Rauschen (N=1). **Qualitativ** zeigt sich, dass Opus-als-Orchestrator
die Kernschwäche *nicht* behebt:

- **Severity-Inflation bleibt:** 89 % aller V1-Findings sind Crit/High (13 C + 50 H),
  nur 8 Med/Low. Das kann Opus nicht reparieren, weil `triage_model` = Sonnet war.

→ **$21.46 für einen indirekten, teils-Rausch-Effekt, der die Qualität nicht hebt.**
Geld in den Glue.

---

## 4. Befund B — Orchestrierungs-Kostenformel (proportional, nicht fix)

V1 trennt die Kosten sauber nach Modell, weil Opus dort *nur* die Orchestrierung war:

- **Orchestrierung (Opus) = $21.46 = 51 % des $42.01-Laufs.**
- Pipeline (Sonnet) = $20.36 = 48 %.

Also ist die Orchestrierungsschicht **~40–50 % eines Opus-getriebenen Laufs** — kein
kleiner Posten, sondern dominiert von **cache-read** der Langzeit-Session (der
Orchestrator liest den wachsenden gecachten Kontext bei *jedem* Dispatch erneut).

**Aufpreis Opus- vs Sonnet-Orchestrierung:**
- Unser Lauf: V1 − V2 = $42.01 − $33.66 = **$8.35 ≈ +25 %** aufs Total.
- Doku-Benchmark (`docs/threat-modeler.md`): $47 (Opus-Session) vs $30 (Sonnet-Session)
  ≈ **+57 %**.

→ Der Aufpreis ist **proportional, nicht fix**: er skaliert mit Lauf-Länge × Kontext-
größe, also mit Repo-Größe. Auf größeren/längeren Läufen wächst der absolute Aufpreis.
Faustregel: **+25–55 % aufs Total, für null Gegenwert.** Orchestrator daher **immer
Sonnet** (Haiku ist zu schwach — treibt JSON-Contracts/Gates/Repair-Loops).

**Vorbehalt / nicht sauber isolierbar:** V2 faltet Orchestrierung + Pipeline in *einen*
Sonnet-Betrag, daher ist der Sonnet-Orchestrierungs-Anteil nicht exakt bestimmbar. Die
„+25 %" unterstellen V1-Pipeline ≈ V2-Pipeline (gleiches Sonnet); die „5×"-Aussage der
Altdoku ist die *Per-Token-Rate* (Opus ≈ 5× Sonnet), kein Gesamtlauf-Faktor. Beide
Lesarten ergeben dieselbe Richtung, unterschiedliche Magnitude → Spanne statt Punktwert.

---

## 5. Befund C — Opus vs Sonnet für STRIDE: besser UND (hier) billiger

### 5a. Kosten-Inversion (V3 < V2)

V3 (Opus-Reasoning) war **billiger** als V2 (reines Sonnet): **$31.78 < $33.66**.
Mechanik:

- Sonnet-Seite fiel um **−$11.60** ($33.66 → $22.06), weil die churn-intensivsten Phasen
  (STRIDE/Triage/Merge) den Sonnet-Zähler verließen: Sonnet-output −38 %, Sonnet-
  cache-read −38 % (−25.8m).
- Opus + Haiku addierten nur **+$9.72**. Opus' eigener cache-read war nur **7.0m** —
  weit unter den 25.8m, die dieselbe Arbeit auf Sonnet erzeugt hätte, weil Opus in
  **weniger Tool-Iterationen** konvergiert.
- Netto **−$1.88**.

Rechenbeispiel zur Verdeutlichung (Per-Modell-Summen aus `/cost`):

```
                 V2 (alles Sonnet)     V3 (STRIDE/triage/merge → Opus)
  sonnet         $33.66                $22.06        (−$11.60)
  opus           –                     $9.08
  haiku          –                     $0.64
  ───────        ──────                ──────
  Σ              $33.66                $31.78        (netto −$1.88)

  Treiber = Sonnet-cache-read:   67.4m  →  41.6m   (−25.8m)
```

Warum `cache-read` der Treiber ist: Es ist der **mit Abstand größte Kostenposten** des
Laufs — bei V2 grob **~$20 von $33.66** (geschätzt: 67.4m Tokens × ~$0.30/M Sonnet-
cache-read-Rate; `/cost` liefert nur Per-Modell-Summen, keine Per-Zeilen-Dollar, daher
abgeleitet). Jeder Subagenten-Turn liest den gesamten gecachten Kontext (Millionen
Tokens) erneut → mehr Turns = mehr cache-read-Dollar. Opus erledigt dieselben Reasoning-
Phasen in **weniger Turns** und erzeugt deshalb nur **7.0m** Opus-cache-read statt der
~25m, die das auf Sonnet kostet. Der Opus-Aufpreis (**+$9.72**) ist kleiner als die so
freigesetzte Sonnet-Ersparnis (**−$11.60**) → der Lauf wird unterm Strich billiger.

Kernpunkt: Der teuerste Posten ist **cache-read**, der mit der Turn-Zahl skaliert. Ein
Sonnet, das STRIDE stemmt, „thrasht" (viele Re-Reads/Retries → viel cache-read). Opus
ist *token-effizienter* auf genau dem teuersten Posten. **Es ist nicht „Opus < Sonnet
pro Token" — es ist „weniger, aber entscheidendere Turns".**

Anmerkung: `estimate_duration._MODEL_FACTOR` kodiert `opus: 1.40` (= 1,4× teurer/
langsamer). Die **Kosten**seite dieser Annahme widerlegt der Lauf; die **Zeit**seite
(Opus-Latenz) bleibt plausibel, ist aber wegen der kontaminierten V3-Wall ungemessen.

### 5b. Qualität (nicht nur Anzahl)

- **Severity-Kalibrierung deutlich besser:** V3 hat 8 Critical (vs 13/14) und einen
  echten Med/Low-Schwanz (28 Findings) statt der 89 %/82 %-Crit/High-Inflation von
  V1/V2. Konservativere, prioritisierbarere Verteilung — und das ist **direkt kausal**,
  denn `triage_model = opus` *ist* die Severity-Zuweisungsstufe.
- **Mehr verifizierte Evidenz:** 70/74 (95 %) „✓ verified" vs 90 %/90 %.
- **Reale neue Angriffsfläche:** eigene Web3-Komponente analysiert (Wallet-Ownership aus
  Request-Body, Web3-Endpoints ohne Auth/Rate-Limit, NFT-Mint-Error-Leak, Alchemy-RPC
  ungeprüft) + LLM-Chat (Prompt Injection, Excessive Agency). Das sind echte
  Juice-Shop-Challenges, die V2 (reines Sonnet) komplett verfehlt.

Qualitätsranking: **V3 ≳ V1 > V2.**

---

## 6. Wodurch ist Sonnet für STRIDE überhaupt gerechtfertigt?

Stress-Test der naheliegenden Gründe — die meisten kollabieren:

1. **Latenz (Opus ~1,4× langsamer):** schwach. STRIDE läuft parallel-fan-out pro
   Komponente (default-on), der Wall-Aufschlag ist *eine* Komponenten-Latenz, nicht N×;
   bei einem ~2h-Lauf für ein periodisches Dokument vernachlässigbar. Zudem **ungemessen**
   (V3-Wall kontaminiert).
2. **Kleine/einfache Repos (Sonnet billiger, kein Thrash):** ökonomisch irrelevant. Dort
   ist Sonnet zwar *relativ* billiger, aber *absolut* reden wir über ~$1,50 statt ~$3 —
   Kostenoptimierung lohnt nur, wo Kosten groß sind, und das sind die **großen** Repos,
   wo Opus gewinnt. (Hypothese — auf kleinen Repos ungetestet.)
3. **Kapazität / Rate-Limit / harter Cost-Cap:** überlebt — aber als **degradierter
   Notfallmodus** beim Massen-Scan, nicht als Default.

Schärfer noch: **`opus-cheap` ist verkehrt herum allokiert.** Es gibt Opus an den
**merger** (eine Phase, die der Code selbst als „zu klein für Opus-Raten" beschreibt) und
lässt **STRIDE — die wertschöpfende Reasoning-Phase — auf Sonnet hungern**. Opus auf die
billige, strukturierte Phase; Sonnet auf die offene, wertbestimmende. Das widerspricht der
eigenen Code-Begründung.

**Legitime Heimat für Sonnet-STRIDE:** nur **`quick`** (nutzergewählt schnell/flach, mit
ohnehin reduzierter STRIDE-Tiefe) + explizites `--reasoning-model sonnet-economy` /
`--max-cost-usd`. **Nie** als automatischer, größen-getriggerter Downgrade von `standard`.

---

## 7. Heutiges Verhalten im Code (`scripts/resolve_config.py`)

- **Default `standard`/`thorough`** = `opus-cheap` (`resolve_reasoning_model`, ~Z. 498) →
  `MODEL_MATRIX["opus-cheap"]` = **stride: sonnet, triage: sonnet, merger: opus**.
- **`LARGE_REPO_SOURCE_FILE_THRESHOLD = 400`** (Z. 343). Juice-Shop > 400 →
  `resolve_repo_size_cap` setzt `repo_size_capped = True`.
- **`resolve_default_tier_for_capped_repos` (B2d, ~Z. 415)** stuft dann (ohne explizites
  `--reasoning-model`) `opus-cheap` → `sonnet-economy` herunter — **alles Sonnet**. Das
  hat V1/V2 auf die *schlechteste* Reasoning-Variante gezwungen. Der Größen-Trigger steht
  **verkehrt**: groß ist genau das Regime, in dem Opus-STRIDE sich rechnet.
- `MODEL_MATRIX["opus"]` = stride/triage/merger **alle opus** (= V3, via explizitem
  `--reasoning-model opus`).

---

## 8. Empfehlung & Einbau

### Bereits umgesetzt (2026-06-21) — nur Doku/Prosa, keine Test-Pins betroffen
Klarstellung der Orchestrierungs-Kostenformel an vier Stellen: bare „~5×" → „+25–55 %
aufs Total, proportional zur Repo-Größe; Orchestrierung ≈ halber Opus-Lauf":
`docs/threat-modeler.md` (×2), `skills/create-threat-model/SKILL.md`,
`scripts/run-headless.sh` (×2).

### Offen — Modell-Routing (an Verifikation gebunden)

**Stufe 0 — Verifikation (vor jeder Code-Änderung):** 3×3-Matrix
(klein / mittel / groß × `sonnet-economy` / `opus-cheap` / `opus`). Schließt die
fehlende `opus-cheap`-Zelle auf Juice-Shop und isoliert, ob **STRIDE-auf-Sonnet** der
Kostentreiber ist (oder triage/merger). Bestätigt die *Magnitude*; die *Richtung* steht
schon.

**Stufe 1 — risikoarm, direkt belegt:** B2d-Größen-Downgrade (`:415`) streichen/neutral
schalten, damit große Repos nicht auf alles-Sonnet gezwungen werden. Test-Pins
bidirektional (`test_resolve_config.py`, `test_reasoning_model_resolution.py`,
`test_haiku_routing_per_depth.py`).

**Stufe 2 — der eigentliche Hebel:** Default `standard`/`thorough` → **`opus`**
(STRIDE auf Opus). `opus-cheap` deprecaten/neu definieren. `estimate_duration`-Anker
nach echtem Opus-Standard-Lauf neu kalibrieren (`_MODEL_FACTOR`-Dauer ggf. bei 1.40
lassen — nur die Kostenannahme war falsch). Sonnet-STRIDE bleibt für `quick` + Opt-out.

Kein neuer Tier nötig — eher **weniger** (Default umstellen + Auto-Switch invertieren).

---

## 9. Grenzen der Aussagekraft

- **N = 1 Repo, eine Sprache (Node/Express), drei Einzelläufe.** Keine Varianz-Kontrolle
  (API-Latenz, Tageszeit, Repair-/Retry-Churn). V2 könnte mehr Churn gehabt haben, was
  seinen cache-read aufbläht.
- **V3-Wall kontaminiert** (8h Idle) → Dauer-Vergleich nur über API-Zeit.
- **Orchestrierungs-Split nicht exakt isolierbar** (V2 faltet alles in Sonnet).
- **Kleine-Repo-Regime ungetestet** → das „absolut trivial"-Argument ist Schluss, nicht
  Messung.
- Belastbar ist die **Richtung** (Opus aufs Reasoning hebt Qualität und ist auf großen
  Repos mindestens kostenneutral; Opus auf den Orchestrator ist reiner Aufpreis). Die
  **exakten Prozentwerte** sind benchmark-abhängig.

---

## 10. VALIDIERT 2026-06-23 — saubere A/B-Messung widerlegt die Kosten-These (§5a)

Die in §5a fehlende saubere Messung wurde nachgeholt: zwei Läufe gegen dasselbe
Juice-Shop-Repo, **identische Flags** (`--rebuild --assessment-depth standard --stride-cap 2`,
gleiche Code-Version mit Dispatch-Fix), beide **clean** (0 Resumes), **gleiche Threat-Zahl**.
Einzige Variable: der Reasoning-Tier. Erstmals lief Opus-STRIDE **beweisbar** (12 Opus-Dispatches);
der Sonnet-Lauf hatte **0 Opus** (reasoning_model=sonnet-economy, stride/triage/merger=sonnet).

| | Opus-Reasoning | Sonnet-economy | Δ |
|---|---|---|---|
| **Kosten (`/cost`)** | **$40.78** | **$30.01** | **Sonnet −$10.77 (−26 %)** |
| Threats | 53 | 52 | ~gleich |
| Opus-Dispatches | 12 (STRIDE+triage+merger) | 0 | — |
| Lauf | clean (77 min) | clean (API 2h09; Wall kontaminiert) | — |

**Befund: §5a ist falsch.** Bei sonst gleichen Bedingungen ist Opus-Reasoning **$10.77 teurer**,
nicht billiger. Die ursprüngliche „Kosten-Inversion" (V3 $31.78 < V2 $33.66) war ein Artefakt —
in V1/V2/V3 lief STRIDE faktisch auf Sonnet; der $1.88-Unterschied war opus- vs sonnet-**Triage/Merger**
+ Rauschen, kein STRIDE-Effekt. Mechanik der Widerlegung: der dominante Kostenposten cache-read sitzt
beim **immer-Sonnet-Orchestrator** (im Sonnet-Lauf ~$17.70 von $30, 59.0m Tokens) — der ist invariant
gegen das STRIDE-Modell. Opus auf dem Reasoning **senkt** diesen Block nicht, es **addiert** nur seine
eigene Schicht. Opus = strikt additive Kosten.

**§5b (Qualität) bleibt — aber gehört zu Triage, nicht STRIDE, und der Trade-off ist real und gemessen.**
Der günstige Sonnet-economy-Lauf zeigt genau die in §5b benannten Schwächen, weil `triage_model` jetzt
ebenfalls Sonnet ist:

- **Severity-Inflation:** 11 Critical / 31 High / 8 Medium / **2 Low** = **81 % Crit/High** (vs. der
  opus-triage-kalibrierten 62 % mit 10 Low). Schlechter priorisierbar.
- **Surface-Lücke:** **keine** Web3/NFT-Komponente analysiert (der verifizierte Opus-Standardlauf hatte
  eine). LLM/AI-Chatbot-Surface ist abgedeckt.

**`--stride-cap 2` verifiziert (live, key-gated):** 43 STRIDE-Threats, **kein** Cap-Verstoß
(≤2 pro Kategorie/Komponente, Criticals exempt — Critical-safe hält). Die 9 CI/CD-Threats stammen aus
`source=architectural-anti-pattern` und unterliegen dem STRIDE-Cap korrekt **nicht**.

**Konsequenz für die offene Default-Empfehlung (§8 Stufe 2):** Die Begründung „Opus-STRIDE besser **und**
billiger" trägt nicht mehr — billiger ist es nicht. Es bleibt ein reiner **Qualität-gegen-Kosten**-Trade-off
($10.77 / +36 % für bessere Severity-Kalibrierung + Web3-Surface). Ein Opus-Default ist damit **nicht**
durch Kosten gedeckt; sinnvoller Mittelweg wäre **Opus nur auf Triage** (die Kalibrierungsstufe) bei
**Sonnet-STRIDE** — ungemessen, nächster Test.
