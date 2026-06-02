# Abuse Cases — Mehrwert-Plan (Analyse-Wirksamkeit)

**Status:** P0 + P1-B-Kern + Aktivierungs-Hook (Weg 2a) UMGESETZT & getestet · **nur noch 1 E2E-Run zur Bestätigung offen**
**Datum:** 2026-06-02

---

## Umsetzungsstand (2026-06-02)

**ERLEDIGT & getestet (sicher gelandet, ändert ohne Aktivierung nichts):**
- **P0** — Falschaussage-Prosa gefixt: `render_abuse_cases.py` `_INTRO`, `abuse-cases.schema.yaml`
  (AC-NNN als „reserved, kein Generator"), `abusecases.md` (Mockup gebannert).
- **P1-B-Kern** — `triage_compute_ranking.py`: `_detect_verified_abuse_chains()` speist
  code-verifizierte `fully_viable`-Ketten in den bestehenden `effective_severity`-Eskalator;
  Findings tragen `verified_chain_ids`; Persistenz via Ranking-View-Re-Apply (Z. ~892).
  **19 Tests** (inkl. ID-Key-Mismatch-Regression + Re-Run-Idempotenz). 200 Tests grün
  (3 vorbestehende agent-def-Failures, nicht von hier).

**Diskrepanzen zum ursprünglichen Plan (beim Verifizieren gefunden):**
- **ID-Key-Mismatch (echter Bug):** Matcher bindet `f_id`, Triage keyt `t_id` → Eskalation wäre
  in Prod stumm ausgefallen. Detektor löst jetzt über alle ID-Keys auf.
- **Persistenz läuft über Ranking-Views**, nicht über In-Place-Mutation (Re-Read bei Z. 882
  verwirft In-Memory-Writes). `verified_chain_ids` dort ergänzt.
- **Sequencing ist komplexer:** Abuse läuft als eigene **Stage 1c NACH der Triage-Stage**
  (`SKILL-impl.md:2112`), nicht als simple Phase. Staged-Reorder (Weg 1) = großer Eingriff.
- **`effective_severity`-Ownership:** im **deterministischen Triage-Modus** (Default, Fast-Path
  `appsec-triage-validator.md:92`) ist `triage_compute_ranking.py` **alleiniger** Owner → ein
  Re-Run nach Stage 1c ist sauber (kein LLM-Clobbering). Clobbering nur im LLM-Fallback-Modus.

**AKTIVIERUNG (Weg 2a) — VERDRAHTET:**
- `SKILL-impl.md` Stage 1c, neuer Schritt **3b2** (zwischen finalize/Eskalation und §9-Render):
  re-runt `triage_compute_ranking.py "$OUTPUT_DIR"` (self-gated auf `APPSEC_TRIAGE_DETERMINISTIC`,
  non-fatal `|| true`, Guard auf `.abuse-case-verdicts.json`). Sidecars existieren jetzt →
  verifizierte `fully_viable`-Ketten heben `effective_severity` (§8) + Ranking (§1 top_findings /
  Mgmt-Summary), bevor §9-Render und Stage-2-Compose die finale yaml lesen. Idempotent
  (upward-only), no-op unter `.budget-critical`.

**OFFEN — nur noch E2E-Bestätigung:**
- 1 echter Run (deterministischer Modus) → prüfen: ein verifiziertes Chain-Member zeigt
  `effective_severity` erhöht + `verified_chain_ids` gesetzt, und die Kette erscheint in §1 oben.
  Einzige nicht unit-testbare Stelle (Orchestrierung). Fallback bei Bedarf: Weg-2b Amender
  (upward-only, nur Ketten-Mitglieder, auch im LLM-Fallback-Modus clobber-frei).

---

**Datum:** 2026-06-02
**Frage, die das Doc beantwortet:** Wie hebt man den analytischen Mehrwert der Abuse Cases über den
Ist-Zustand (terminales §9-Dokumentationsartefakt), insbesondere damit sie die **Findings** des
Threat Models beeinflussen (neue finden / Relevanz erhöhen)?

---

## TL;DR — der entscheidende Befund

Es existieren **zwei parallele, ~50 % überlappende Chain-Systeme**:

| System | Quelle | Matching | Wirkt auf `effective_severity`? | Wo verdrahtet |
|---|---|---|---|---|
| **Compound-Chains (CC)** | `data/compound-chain-patterns.yaml` (6 Chains) | CWE/Titel-Keyword (`_match_chain_role`) | **JA** — keystone→chain-severity, contributor→cap | `triage_compute_ranking.py` (Phase 10b) |
| **Abuse Cases (AC-T)** | `data/abuse-cases/default-library.yaml` (6 Cases) | Regex/CWE über Finding-Prosa, **plus code-verifiziert durch Agent** | **NEIN** — rein kosmetisch in §9 | `match_/verify_/render_abuse_cases.py` (Phase 10c, nach der Triage) |

**Konsequenz:** Der „Finding-Relevanz durch Zusammenhang erhöhen"-Effekt, den wir bauen wollten,
**existiert schon** — aber er wird vom *schwächeren* (keyword-only) CC-System getrieben. Das
*stärkere* (code-verifizierte) AC-System ist davon abgekoppelt und macht nur Doku ganz hinten.

→ Die richtige Maßnahme ist **nicht** „einen Eskalator bauen" (existiert), sondern
**konsolidieren**: die code-verifizierten AC-Verdicts zum autoritativen Treiber der **bereits
existierenden** `effective_severity`-Chain-Eskalation machen.

### Überlappung der zwei Libraries (Evidenz)

| Compound-Chain | Abuse Case | gleiche Sache? |
|---|---|---|
| CC-01 Stored XSS → Session Theft via localStorage JWT | AC-T-001 Account Takeover via Stored XSS + Token Hijacking | **ja** |
| CC-02 Hardcoded Crypto Key → Offline Token Forgery | AC-T-005 Auth Bypass via Exposed Secret Material | **ja** |
| CC-06 Mass Assignment → Self-Promotion to Admin | AC-T-002 / AC-T-004 Mass Assignment / Priv-Esc | **ja** |
| CC-03 SQLi → Credential Dump → Hash Cracking | — | nur CC |
| CC-04 SSRF → Cloud Metadata | — | nur CC |
| CC-05 Unauthenticated Management Plane | — | nur CC |
| — | AC-T-003 JWT Algorithm Confusion | nur AC |
| — | AC-T-006 RCE via Server-Side Injection | nur AC |

Zwei Libraries, die teils dieselben Ketten in zwei Schemata pflegen — Wartungs- und
Konsistenzkosten, plus Doppel-Rendering desselben Konzepts (CC eskaliert Severity still; AC
erzählt es in §9 nach).

---

## Empfehlung — konsolidieren statt neu bauen

**Kern:** AC-Verdicts werden Input des bestehenden `_compute_effective`-Chain-Eskalators. Die
code-verifizierte Kette ist ein *stärkeres* Signal als das CC-Keyword-Match und sollte die
Severity mindestens so stark treiben — mit Provenienz und denselben Guardrails, die schon da sind
(no-downgrade-Invariante, `evidence_refuted`-Suppression, contributor-cap).

Das liefert genau das gewünschte Verhalten:
- **Relevanz erhöhen:** ein Finding, das `required`-Step einer code-verifizierten `fully_viable`
  AC-Kette ist, bekommt `effective_severity` hochgesetzt mit Begründung
  `elevated:verified_chain(AC-T-001)` — intrinsische Severity bleibt unangetastet (B2).
- **Auditierbar:** reason-string + Provenienz wie bei den existierenden `elevated:keystone(...)`.
- **Entdoppelt:** mittelfristig ersetzt das verifizierte AC-System die keyword-CC-Heuristik
  (oder CC wird auf die 3 Ketten reduziert, die kein AC-Pendant haben: CC-03/04/05).

### Das Sequencing-Problem (der Knackpunkt)

AC-**Verifikation** läuft in Phase 10c, **nach** der Triage (10b) — die Eskalation braucht das
Verdict aber **in** der Triage. Zwei Wege:

- **Option S1 (pragmatisch, empfohlen):** Der **deterministische AC-Matcher**
  (`match_abuse_cases.py match`, kein LLM) läuft **vor** der Triage und liefert
  *Kandidaten*-Ketten als Triage-Chain-Input — epistemisch auf demselben Niveau wie CC heute
  (Keyword/Match, unverifiziert). Die spätere 10c-Code-Verifikation kann in §9 **herabstufen**
  (refuted), analog zur bestehenden `evidence_refuted`-Suppression. Kleinster Eingriff: nur der
  Matcher wandert vor, der teure Verifier bleibt, wo er ist.
- **Option S2 (sauberer, teurer):** Die ganze AC-Engine (match → verify → finalize) vor die
  Triage ziehen, sodass `effective_severity` auf **verifizierten** Verdicts basiert. Bedeutet:
  Verifier-Fan-out wird Triage-Vorbedingung → **Non-fatal-Eigenschaft muss erhalten bleiben**
  (bei `.budget-critical`: skip → keine Eskalation → Triage läuft wie heute).

S1 zuerst; S2 nur, wenn S1 zeigt, dass unverifizierte Kandidaten zu viel Severity-Inflation
verursachen.

---

## Konkrete Touchpoints (verifiziert)

### A. Falschaussage fixen (trivial, unabhängig, zuerst)
- `scripts/render_abuse_cases.py:321-329` (`_INTRO`) — „**discovered** (synthesised from the
  finding register)" entfernen: es existiert **kein** Discovered-Generator (bestätigt: weder in
  `scripts/`, `agents/` noch `skills/`; `resolve_abuse_cases.py` ist reine Datei-Montage).
- `scripts/render_abuse_cases.py:326-328` — „verified end-to-end … never rated by hand" →
  ehrlicher: „code-confirmed per step; chain verdict folded deterministically".
- `schemas/abuse-cases.schema.yaml:34-36` — Doc-Kommentar zu `AC-NNN (discovered)` entschärfen
  oder als „reserved / not yet produced" markieren.
- `abusecases.md` (Repo-Root) — ist ein **hand-geschriebenes Mockup** mit altem Schema
  (`T-ID`, `§8 Threat Register`, `AC-001`, Discovered-Case `AC-002`). Quelle der geleakten
  Prosa. Als veraltet kennzeichnen oder löschen.

### B. AC-Verdict → effective_severity (der eigentliche Finding-Effekt)
- `scripts/triage_compute_ranking.py:241` `_detect_chains` — heute über
  `data/compound-chain-patterns.yaml`. **Erweitern/ersetzen** um AC-Match-Ergebnisse:
  die `matched_finding_ids` + `step_matches[].required` einer AC-Kette auf das
  keystone/contributor/members-Modell mappen.
- `scripts/triage_compute_ranking.py:346` `_compute_effective` — neuer Zweig analog
  `chain_role == "keystone"`: `verified_chain` → `eff = chain_combined_risk`,
  reason `elevated:verified_chain(<AC-ID>)`. Guardrails wiederverwenden: no-downgrade-Invariante
  (Z. 388), `evidence_refuted`-Suppression (Z. 361), contributor-cap (Z. 367).
- `scripts/triage_compute_ranking.py:495` — wo `compound-chain-patterns.yaml` geladen wird:
  zusätzlich `.abuse-case-matches.json` laden (setzt **Option S1** voraus: Matcher vor Triage).
- `scripts/triage_compute_ranking.py:545,609,775` — `compound_chain_ids`-Annotation am Finding;
  spiegelbildlich `verified_chain_ids` ergänzen, damit §8 nach oben verlinken kann.

### C. Gap-Hunt (NEU — neue Findings; nur falls Daten es rechtfertigen, s. „Out of scope")
- Trigger: `structural_verdict == "partial_candidate"` in
  `scripts/match_abuse_cases.py:177` (`match_case`).
- Neuer Schritt zwischen Phase-9-Merge und 10a: pro fehlendem `required`-Step ein schmaler
  Hunt-Agent mit dessen `probe` (`entry_points`/`sink_patterns`/`control_patterns`).
- Guardrail: Finding nur emittieren bei **code-bestätigtem** Sink (kein `inconclusive→Finding`).
- Append vor 10a, damit neue Findings normal durch Evidence-Verify + Triage laufen.

### D. Sequencing-Wiring (Option S1)
- `agents/phases/phase-group-threats.md:1797` (Phase 10c) — `match_abuse_cases.py match`
  herauslösen und **vor** Phase 10b (`:1578`) ausführen; `.abuse-case-matches.json` wird
  Triage-Input. Verifier-Fan-out + finalize bleiben in 10c.
- Non-fatal erhalten: bei `.budget-critical` Matcher-Skip → Triage ohne AC-Eskalation = Ist-Stand.

### E. Routing nach oben (teils vorhanden)
- `scripts/compose_threat_model.py:5407` `_build_ms_abuse_chain_line` — **existiert schon**:
  surft verifizierte Ketten als 1 MS-Zeile mit §9-Link. Behalten.
- **Neu:** §8-Findings, die `verified_chain_ids` tragen, nach oben zur Kette cross-verlinken
  (Gegenrichtung zum bestehenden Down-Link).
- **Optional:** verifizierte `fully_viable`-Ketten als Knoten in den Critical Attack Tree
  (`compose_threat_model.py:7339` ff. `_ATTACK_TREE_*`) einspeisen, statt nur §9.

### F. Instrumentierung (billig, bevor C/S2 entschieden wird)
- Run-Stats-Zähler: `#candidate` / `#partial_candidate` / `#not_applicable` / `#fully_viable`
  und Findings-pro-Kette. Quelle: `.abuse-case-matches.json` + `.abuse-case-verdicts.json`.
  Touchpoint: `scripts/record_stage_stats.py` bzw. der Run-Statistics-Appendix in
  `compose_threat_model.py`.

---

## Phasen-Rollout (nach ROI)

1. **P0 — Ehrlichkeit (trivial):** Touchpoint **A**. Falschaussage raus. Unabhängig, sofort.
2. **P1 — Finding-Effekt billig (niedrig/mittel):** Touchpoint **B + D(S1)**. AC-Match-Kandidaten
   treiben `effective_severity` über den **bestehenden** Eskalator. Plus **E**-Cross-Link.
   → Abuse Cases beeinflussen ab hier die Findings (Relevanz/Ranking), auditierbar, gedeckelt.
3. **P2 — Messen (niedrig):** Touchpoint **F**. 3–5 echte Runs. Entscheidungsgrundlage für P3.
4. **P3 — bedingt:** je nach P2-Daten — entweder **Gap-Hunt (C)** bauen (wenn `partial_candidate`
   real Ertrag bringt) **oder** **CC↔AC konsolidieren** (eine Library als Quelle der Wahrheit)
   **oder** **S2** (Verifikation vor Triage), falls S1 zu viel Inflation zeigt.

---

## Offene Entscheidungen (brauchen Input)

1. **B1 vs. B2:** intrinsische Severity anfassen (B1) **oder** nur `effective_severity` mit
   Provenienz, intrinsisch ehrlich (B2). → **Empfehlung B2** (nutzt die existierende
   effective/raw-Trennung; no-downgrade-Invariante schützt schon).
2. **CC vs. AC als autoritativ:** Ersetzt das verifizierte AC-System das keyword-CC-System,
   oder koexistieren sie (CC nur für CC-03/04/05 ohne AC-Pendant)? → Entscheidung in P3, nicht
   vorwegnehmen.
3. **S1 vs. S2:** unverifizierte Kandidaten vs. verifizierte Verdicts als Severity-Treiber.
   → **S1 zuerst.**

---

## Explizit NICHT im Scope (bewusst)

- **Discovered-Case-Generator** — teuer, app-spezifische Abuse macht der threat-analyst inline
  (`phase-group-threats.md:634`). Nicht bauen.
- **Gap-Hunt vor Messung (F)** — `partial_candidate`-Ertrag ist unbelegt; erst Daten, dann Code.
- **Eigener neuer Severity-Eskalator** — existiert bereits (`_compute_effective`); wiederverwenden.

---

## Risiken / Guardrails

- **Severity-Inflation:** nur `fully_viable` (bzw. bei S1: candidate mit allen required gematcht)
  + nur `required`-Steps eskalieren; `partially_blocked`/`inconclusive` nicht; gedeckelt
  (Floor auf `combined_risk`, kein Pauschal-Critical). Re-use contributor-cap.
- **Idempotenz:** Eskalation provenienz-gestempelt; Re-Run darf nicht doppelt eskalieren
  (vgl. bekannte qa_checks-Idempotenz-Gotcha).
- **Non-fatal bleibt non-fatal:** S1/S2 müssen bei `.budget-critical` auf Ist-Verhalten
  degradieren (keine Eskalation), sonst blockiert ein AC-Stall die Triage.
- **Zwei Chain-Libraries driften auseinander** — genau deshalb ist Konsolidierung (Entscheidung 2)
  der mittelfristig richtige Schritt, nicht dauerhafte Koexistenz.
