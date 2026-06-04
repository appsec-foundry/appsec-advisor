# Abuse-Cases Integration — Verbesserungs-Analyse (2026-06-03)

**Frage:** Lässt sich die Abuse-Case-Integration verbessern, ohne die Performance zu verschlechtern?

**Kurzantwort:** Die Integration ist **bereits ausgereift und performance-optimiert**. Es gibt
**keinen** offenen *Performance*-Hebel mehr (der LLM-Schritt ist single-pass + parallel, alles
andere deterministisches Python, ~2 s). Die verbleibenden Verbesserungen sind **Qualität/Korrektheit**
und allesamt **performance-neutral**.

---

## Verifizierter Ist-Zustand (Code-Ebene, nicht Doku)

| Baustein | Status | Beleg |
|---|---|---|
| Perf: Verifier-Fan-out | **single-pass sonnet, parallel** (haiku-Welle 2026-06 entfernt) | `SKILL-impl.md:2150ff`, `appsec-abuse-case-verifier.md` Model-ID |
| Effekt: verified chains → `effective_severity` | **landed + getestet** | `triage_compute_ranking.py:289` `_detect_verified_abuse_chains`, `:605` Einspeisung |
| Aktivierungs-Hook (re-run nach Stage 1c) | **verdrahtet** | `SKILL-impl.md:2177` Schritt 3b2 (self-gated deterministisch, non-fatal, budget-safe, idempotent) |
| Doppel-Eskalation CC + AC | **sicher by construction** | `:638` `chain_sev_rank = max(...)` über ALLE Chains — nie Summe; Caps + no-downgrade |
| Provenienz | Findings tragen `verified_chain_ids` getrennt von `compound_chain_ids` | `:648`, `:713` |
| Tests | 65 abuse + 19 verified-chain grün | `pytest tests/test_*abuse*` |

**Einziger laut Plan offener Punkt:** *E2E-Bestätigung* — 1 echter deterministischer Run, der zeigt
dass ein verifiziertes Chain-Member tatsächlich erhöhte `effective_severity` + gesetzte
`verified_chain_ids` trägt und in §1 oben erscheint. (Nicht unit-testbar = Orchestrierung.)

---

## Performance-Budget der Integration (warum kein Perf-Hebel offen ist)

- **Match / finalize / fold (Schritt 3b2 re-run):** deterministisches Python, ~2 s gesamt. Vernachlässigbar.
- **Verifier-Fan-out:** der einzige LLM-Kostenpunkt. Bereits **parallel in EINER Message**
  → Wall-Clock ≈ langsamster Einzelfall (nicht Summe). Bereits optimal.
- Frühere 83-%-Verschwendung (haiku→sonnet-Eskalation sequenziell) ist **eliminiert**.

→ Ein „Performance verbessern"-Auftrag hätte hier kaum Substrat. Wall-Time ist bereits am Boden.

---

## Verbesserungs-Optionen (alle performance-neutral oder -positiv)

### Option 1 — E2E-Aktivierung bestätigen *(Validierung, nicht Perf)*
Den dokumentiert-offenen Punkt schließen: ein realer deterministischer Run + Assertion auf
`effective_severity`-Hebung. Kosten: `e2e-full` = ~30–50 % eines Pro-Fensters → **NICHT gratis**,
aber es ist der fehlende Korrektheits-Gate. Alternativ: gezielter Mini-Fixture-Test der
3b2-Re-Run-Kette (deterministisch, gratis) statt voller E2E.

### Option 2 — Konsolidierung CC ↔ AC *(perf-neutral, Qualität)*
Heute laufen zwei ~50 % überlappende Chain-Systeme parallel (Keyword-CC + code-verified-AC),
beide eskalieren. `max()` verhindert Doppelzählung, aber:
- das **schwächere** Keyword-System (CC) kann Findings heben, die das code-verifizierte (AC) NICHT heben würde → mögliche Falsch-Eskalation.
- zwei Libraries driften auseinander (Wartungslast).
Plan-Empfehlung („Entscheidung 2"): AC zum autoritativen Treiber machen. **Perf-neutral** (beide bereits deterministisch). Mittlerer semantischer Eingriff.

### Option 3 — Verifier nur für nicht-evidenzierte / kontroll-behaftete Steps *(perf-positiv bei Token, neutral bei Wall-Time)*
Steps, deren `matched_finding_id` bereits code-evidenziert ist (file:line:excerpt aus evidence-verify)
**und** ohne `control_patterns`, könnten deterministisch vor-bestätigt werden; sonnet nur noch für
Steps mit Kontroll-Prüfung oder ohne Finding-Evidenz. **Spart Token/Kosten**, aber kaum Wall-Time
(Fan-out ist ohnehin parallel). Risiko: Regex-Match ist schwächer als sonnet-Code-Read → Verdict-Präzision sinkt. **Mittleres Korrektheitsrisiko, geringer Wall-Time-Gewinn → niedrigste Priorität.**

---

## Empfehlung

Performance ist erschöpft — kein Perf-Hebel offen. Der **wertvollste perf-neutrale** Schritt ist
**Option 1 (E2E/Mini-Fixture-Bestätigung)**, weil sie den einzigen dokumentiert-offenen
Korrektheits-Gate schließt und damit erst belegt, dass die ganze Integration in Prod wirkt.
Option 2 (Konsolidierung) ist die richtige mittelfristige Qualitätsverbesserung, aber ein größerer
Eingriff. Option 3 bringt nur Token-, keinen Wall-Time-Gewinn bei höherem Risiko → optional.
