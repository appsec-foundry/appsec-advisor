# Implementierungsplan — Fragment-Invarianten-Registry (M1) + Paritätstest (M1b)

Status: UMGESETZT (Schritte 1-5) · 2026-08-29
Anlass: `juice-shop-standard-v0.6.0b2`, Stage-1b-Abbruch nach 4 Agenten (~276k Subagent-Tokens)

Umgesetzt in `scripts/validate_fragment.py` (`fragment_invariant_errors`),
`scripts/prepare_trust_boundary_context.py` (Gate delegiert),
`agents/appsec-trust-boundary-analyst.md` (`--context`),
`tests/test_fragment_invariant_parity.py` + `tests/fixtures/fragment_invariants/`.
Zehn Regeln verschoben, alle Meldungstexte wortgleich, 11 Paritätsfälle grün.

## 1. Problem

Ein agent-geschriebenes Fragment muss relationale Invarianten erfüllen, die

1. JSON Schema strukturell nicht ausdrücken kann,
2. nur im deterministischen Konsumenten durchgesetzt werden,
3. im Kontrakt des schreibenden Agenten nicht formuliert sind,
4. für den vorgeschriebenen Selbstcheck des Agenten unsichtbar sind.

Verletzung kostet den gesamten Lauf.

Empirisch belegt am `trust-boundary-analyst` (alle vier Mutationen: `VALIDATE_OK`,
Gate bricht ab):

| Invariante | Gate | Agent-`.md` | Schema |
|---|---|---|---|
| Disposition↔Kandidat gegenseitig deckend | `prepare_trust_boundary_context.py:2298` | — | unmöglich |
| Nicht-`boundary` ⇒ `candidate_keys` leer | `:2293` | nur `boundary`-Fall (md:45-51) | `required`, kein `if/then` |
| Dispositionsmenge == mandatory-Menge | `:2272` | nur „for every mandatory" (md:45) | unmöglich |
| `candidate_key` eindeutig | `:2263` | — | `uniqueItems` greift nicht |

`validate_fragment.py:338-357` macht ausschließlich `jsonschema.validate` plus —
nur bei übergebenem `--repo-root` — `repository_path_errors`. Keine semantische
Prüfung, für keinen Fragmenttyp.

## 2. Zielarchitektur — der Erweiterungspunkt existiert bereits

`validate_fragment.py:210` `repository_path_errors(fragment_type, data, repo_root)`

- Docstring: *„Validate repository-backed paths that JSON Schema cannot resolve."*
- bereits pro Fragmenttyp verzweigt (`:220` `components`, `:234` `data-flows`)
- bereits über Pfade hinausgewachsen: `_tier_contradiction_errors` (`:226`) ist rein semantisch
- bereits von deterministischen Konsumenten mitbenutzt:
  `finalize_component_inventory.py:21`, `build_trust_boundary_assessment_input.py:19`

Das Muster „eine Prüffunktion pro Fragmenttyp für alles, was JSON Schema nicht
kann, aufgerufen von Selbstcheck **und** Gate" ist etabliert. Die relationalen
Invarianten stehen nur nicht drin — sie liegen privat im Prolog von
`promote_candidates` (`prepare_trust_boundary_context.py:2226`, Prüfblock
`:2255-2303`).

**Kein neues Modul.** Schwesterfunktion in `validate_fragment.py`, gleiche Form,
gleiches Importziel. `prepare_trust_boundary_context.py` importiert bisher nichts
aus `validate_fragment` (`:10-23`); `validate_fragment` importiert nur
`_ms_component_refs` (`:34`) — kein Zirkelrisiko.

## 3. API

```python
def fragment_invariant_errors(
    fragment_type: str,
    data: Any,
    *,
    context: Any | None = None,
) -> list[str]:
    """Relational invariants JSON Schema cannot express."""
```

`context` ist das begleitende Eingangsartefakt, das der Agent ohnehin besitzt —
beim Trust-Boundary-Analysten sein eigener `ASSESSMENT_INPUT_PATH`. Damit sind
auch die artefaktübergreifenden Regeln für den Agenten prüfbar, nicht nur die
internen.

Rückgabe: Liste von Klartextfehlern, gleiche Konvention wie
`repository_path_errors`. Keine Exceptions — der Aufrufer entscheidet über
Abbruch, Heilung oder Report.

### CLI

`validate_fragment.py` bekommt im Legacy-Pfad (`main`, `:617-665`) ein optionales
`--context <pfad>`. `validate()` ruft `fragment_invariant_errors` **unbedingt**
auf — anders als `repository_path_errors`, das an `--repo-root` hängt.

> Nebeneffekt, erwünscht: die drei Agenten, die heute ohne `--repo-root`
> validieren (`trust-boundary-analyst`, `post-stride-synthesizer`,
> `fragment-fixer`), erhalten die relationalen Prüfungen ohne weitere Änderung.

## 4. Migration der Invarianten

Aus `prepare_trust_boundary_context.py:2255-2303`:

| # | Invariante | Zeile | Ziel | Tier |
|---|---|---|---|---|
| 1 | duplicate signal IDs *im Assessment-Input* | 2258 | **bleibt** | fremdes Artefakt |
| 2 | candidate keys eindeutig | 2263 | Registry | intra |
| 3 | genau eine Disposition je Signal | 2266 | Registry | intra |
| 4 | Dispositionsmenge == mandatory | 2269 | Registry | cross (`context`) |
| 5 | Endpunkte sind bekannte Komponenten/`external` | 2278 | Registry | cross (`context`) |
| 6 | Kandidat deckt ≥1 Signal oder Flow | 2282 | Registry | intra |
| 7 | referenziert bekanntes Signal / bekannten Flow | 2284, 2286 | Registry | cross (`context`) |
| 8 | `boundary` ⇒ ≥1 Kandidat | 2290 | Registry | intra |
| 9 | nicht-`boundary` ⇒ keine Kandidaten | 2292 | Registry | intra |
| 10 | Disposition↔Kandidat gegenseitig deckend | 2298 | Registry | **intra** |
| 11 | jeder Kandidat von `boundary` referenziert | 2302 | Registry | intra |

Zehn von elf wandern. Nr. 10 — die, die diesen Lauf getötet hat — ist rein
intra-artefaktlich: der Agent hätte sie ohne jeden Zusatzkontext selbst finden
können.

**Nicht in die Registry:** `did not promote to a canonical boundary` (`:2423`).
Sie ist post-Konsolidierung und ex ante nicht prüfbar; sie gehört in die
Heilbehandlung (M3), nicht in den Selbstcheck.

## 5. Aufrufstellen

1. `validate_fragment.validate()` — unbedingt, nach `jsonschema.validate`.
2. `promote_candidates()` — Prüfblock `:2255-2303` ersetzt durch einen Aufruf;
   nichtleere Rückgabe → `ValueError` mit denselben Meldungstexten (Bestandstests
   bleiben grün).
3. `agents/appsec-trust-boundary-analyst.md:242-249` — Validierungskommando um
   `--context "$OUTPUT_DIR/.trust-boundary-assessment-input.json"` ergänzt.

Meldungstexte bleiben wortgleich. Der Umbau ist verhaltensneutral für den Gate
und additiv für den Agenten.

## 6. M1b — Paritätstest als Regressionssperre

Ohne ihn reißt die nächste direkt im Konsumenten ergänzte Prüfung die Lücke
wieder auf. Die zu sichernde Eigenschaft:

> **Was der Gate ablehnt, muss der Selbstcheck ablehnen.**

Fixture-Korpus, wächst mit jeder neuen Invariante:

```
tests/fixtures/fragment_invariants/<fragment_type>/
    valid.json
    context.json           # optional
    bad-<invariante>.json
```

Test je Fragmenttyp:

- `valid.json` → beide Pfade akzeptieren.
- jede `bad-*.json` → **beide** Pfade lehnen ab.

Der zweite Teil ist der eigentliche Wächter: Eine neue Invariante, die jemand
inline im Konsumenten ergänzt, lässt den Test rot werden, weil der Validator-Pfad
die Mutation noch akzeptiert. Grün wird er erst, wenn die Regel in der Registry
steht — also dort, wo der Agent sie sieht.

Startkorpus für `trust-boundary-candidates` (in dieser Sitzung bereits gegen
beide Pfade gefahren, alle vier: `VALIDATE_OK` + Gate-Abbruch):
`bad-mutual-coverage`, `bad-nonboundary-has-candidates`,
`bad-extra-disposition`, `bad-duplicate-candidate-key`.

## 7. Reihenfolge und Abnahme

| Schritt | Verifikation |
|---|---|
| 1. `fragment_invariant_errors` mit Regeln 2-11 anlegen | Unit-Tests je Regel |
| 2. Fixture-Korpus + Paritätstest (M1b) | rot vor Schritt 3, grün danach |
| 3. `promote_candidates`-Prolog auf Aufruf umstellen | bestehende Suite unverändert grün |
| 4. `validate()` + `--context` verdrahten | Originaldatei des Laufs liefert jetzt `VALIDATE_FAILED` statt `VALIDATE_OK` |
| 5. Agent-`.md` um `--context` ergänzen | — |

Schritt 4 hat eine harte, reproduzierbare Abnahme: die unveränderte
`.trust-boundary-candidates.json` dieses Laufs liegt vor. Sie muss nach dem Umbau
vom Selbstcheck **abgelehnt** werden — mit derselben Meldung, die der Gate
ausgibt. Vorher: `VALIDATE_OK`.

## 8. Ausdrücklich nicht in diesem Plan

- **Regeln in Agent-Prosa schreiben.** Allein in einer Datei stehen 20
  `raise`-Stellen; Prosa driftet und ist nicht prüfbar. Falls agentenlesbarer
  Text gewünscht ist, aus der Registry **generieren**.
- **Den Cross-Ref-Check entfernen.** Die Konsistenz ist real: `candidate_keys`
  speist die Coverage-Zeilen (`:2394-2397`). Falsch ist der Ort der Durchsetzung,
  nicht die Regel.
- **M2** (Inverse-Indizes abschaffen — betrifft nur
  `trust-boundary-candidates` und `mitigation-overrides`), **M3** (Heil-/Repair-
  Kontrakt für Stage-1-Gates, Muster aus `SKILL-thin-stage3.md:64-68`),
  **M5** (`agent_logger.py:2322` nach Rollenfähigkeit statt `is_agent_call`).
  Eigene Pläne.
