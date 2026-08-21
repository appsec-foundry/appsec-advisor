# Analyse — Terminaler Run-Abbruch durch Titel-Pattern eines komponierten Artefakts

**Datum:** 2026-08-21 · **Revision 2** (eigene Befunde nachgeprüft; zwei
Aussagen der ersten Fassung widerlegt, davon eine an der empfohlenen Maßnahme
selbst — siehe §5a)
**Auslöser:** `/create-threat-model --slug insecure-large-spring-app-v0.5.2` bricht nach
~75 min in `context-v2-finalize` terminal ab — nach vollständig gelaufener Stage 1
(10 Komponenten STRIDE, Merge, Evidence, Triage, Root-Cause).
**Konsolenmeldung:** `internal action-manifest validation failed: '…' is too long`
**Tatsächliche Ursache (aus `.agent-run.log`):**
`build_threat_model_yaml.py failed with exit 5: INVALID: threats[27].title:
'14 Named Accounts Seeded with Hardcoded Password "password"' does not match '^[A-Z]…'`

Schwesteranalyse: `analysis-producer-schema-abort-2026-08-21.md` (juice-shop,
Recon-Enum). Verhältnis beider Läufe in §4.

Jede Aussage ist am Code oder empirisch verifiziert.

---

## 1. Kausalkette — sechs Defekte

### D1 · `_clean_title` ist für nicht-kasusfähige Erstzeichen ein No-Op *(die Ursache)*

`scripts/build_threat_model_yaml.py:1019-1020`:

```python
if s and not s[0].isupper():
    s = s[0].upper() + s[1:]
```

Die Zeile existiert genau dafür, das Schema-Pattern `^[A-Z]…`
(`schemas/threat-model.output.schema.yaml:659`) zu erfüllen. Für ein
nicht-kasusfähiges Erstzeichen ist sie wirkungslos: `"1".isupper()` ist `False`,
also wird der Zweig betreten — und `"1".upper()` ist `"1"`. Der Cleaner meldet
Erfolg und liefert einen Titel, den das Schema nie akzeptieren kann.

**Reproduziert** (`_clean_title` direkt aufgerufen, Pattern-Match geprüft):

| Eingabe (Erstzeichen) | Ausgabe | Pattern |
|---|---|---|
| `14 Named Accounts Seeded with Hardcoded Password "password" (…)` | `14 Named Accounts…` | **FAIL** |
| `3 admin endpoints unauthenticated (…)` | `3 admin endpoints…` | **FAIL** |
| `/etc/passwd readable via path traversal (…)` | `/etc/passwd readable…` | **FAIL** |
| `stored XSS in profile (Profile.java:1)` | `Stored XSS in profile (…)` | OK |

Betroffen ist **jedes** nicht-kasusfähige Erstzeichen — die Aussage folgt aus dem
Code, nicht aus der Stichprobe. An zwölf handverlesenen, realistischen
Titelformen fallen neun durch: `.env file committed…`, `/admin routes are
unauthenticated…`, `404 handler leaks stack traces…`, `"password" is the seeded
credential…`, `__init__ exposes a debug route…`, `'admin' role assignable…`,
`<script> injection…`, `$JWT_SECRET committed…` sowie der reale Fall. Ein
Patch, der nur Ziffern behandelt, ließe acht weitere Auslöser scharf.

Der Cleaner ist ansonsten vollständig: er behandelt `@` (:1010), Backticks
(:993), Parenthesen (:1012-1017), Blocklist-Token (:998-1003) und Länge
(:1031-1045). Die Lücke ist genau diese eine Zeile.

**Umfang der Korrektur:** siehe N1/N1b. Die naheliegende Form — ein Präfix
voranstellen oder den führenden Nicht-Buchstaben-Lauf abschneiden — erfüllt zwar
den Regex, beschädigt aber in beiden Varianten die Bedeutung (§5a/V3). Die
Korrektur muss daher zweiteilig sein: garantierte Gültigkeit **plus** ein Signal,
wenn sie verlustbehaftet erkauft wurde.

### D2 · Docstring-Absicht ≠ Code — Residuen sind nicht „warnings", sondern terminal

`build_threat_model_yaml.py:985-987`:

> *„Titles that still fail after cleanup are surfaced as schema warnings — the
> migration plan moves first-class title cleanup into stride-analyzer output
> later. For v1 we accept residual warnings on edge cases."*

Tatsächlich: `:2658-2662` schreibt `FATAL: schema validation failed` und gibt
`5` zurück; `orchestration_controller.py:4746` ruft den Builder über
`_run_script` ohne `acceptable`-Erweiterung → `ControllerError` → `RUN_ABORTED`.
Ein „akzeptierter Edge Case" kostet einen vollständigen Stage-1-Lauf.

Dies ist strukturell identisch mit **D4b** der Schwesteranalyse (Docstring
behauptet erlaubte Diagnose, Code verweigert sie). Zwei unabhängige Stellen,
dasselbe Muster: die dokumentierte Semantik ist die beabsichtigte, die
implementierte die härtere.

### D3 · Zwei Titel-Normalisierer; der dokumentierte ist nicht der wirksame

Das Repo hat zwei:

| Normalisierer | Läuft | Regeln | Am Gate wirksam? |
|---|---|---|---|
| `_clean_title` / `_clamp_title` (im Builder, `:1126`) | **vor** der Schema-Validierung | Pattern, `@`, Backtick, Parens, Blocklist, Länge | **ja** |
| `emit_clean_finding_titles.py` (`auto_emitter_pass.sh:94`) | **nach** dem Gate (`orchestration_controller.py:4765`) | Weakness-Klasse + Locator, Länge | **nein** |

`agents/shared/finding-title-contract.md:4-20` erklärt ausdrücklich
*„Deterministically enforced — authoring is a soft guide, not the guard"* und
benennt als Garanten **`emit_clean_finding_titles.py`** — also den, der erst
nach dem tödlichen Gate läuft. Der tatsächliche Garant `_clean_title` wird im
Contract-Dokument nicht erwähnt.

**Empirisch** — der dokumentierte Normalisierer auf das abgelehnte Modell
angesetzt:

```
$ python3 scripts/emit_clean_finding_titles.py <copy-of-output-dir>
emit_clean_finding_titles: cleaned 52 finding title(s)
→ Pattern-/Längenverstöße: 25 vorher → 1 nachher
→ verbleibend: '14 Named Accounts Seeded with Hardcoded Password — SecurityConfig.java:71'
```

Er bereinigt 52 von 55 Titeln und beseitigt 24 der 25 Verstöße — **genau den
fatalen nicht**, weil ihm die `^[A-Z]`-Regel fehlt. Eine bloße Umsortierung
(Emitter vor das Gate) hätte diesen Lauf also *nicht* gerettet. Notwendig ist
D1.

### D4 · Der Titel-Contract erreicht den erzeugenden Agenten nicht

`agents/shared/finding-title-contract.md` wird referenziert von:

```
$ grep -rl "finding-title-contract" agents/ skills/ scripts/
agents/appsec-reviewer.md
agents/appsec-eval-judge.md
```

**Nicht** von `appsec-stride-analyzer-v2.md` — dem Agenten, der die Titel
tatsächlich schreibt. Der bekommt (`:186-187`) nur:

> *„Titles follow `<weakness class> (<relative path[:line]>)`, maximum 80
> characters."*

Kein Wort zu Erstzeichen, `@`, Backticks, Doppelpunkten außerhalb der Klammer
oder Blocklist. Der Producer kann den Contract nicht erfüllen, weil er ihn nicht
kennt — dieselbe Achse wie **D0/D1** der Schwesteranalyse (Vorlage und
erzwungenes Vokabular fallen auseinander), hier durch Nicht-Zustellung statt
durch Kollision.

Auch das STRIDE-Attempt-Schema (`schemas/stride.schema.yaml`) constraint den
Titel **gar nicht** — `pattern` existiert dort nur für CVSS, Pfade und
`tb-\d+`. Die Regel greift erstmals ~40 Minuten nach dem verursachenden Write,
am komponierten Artefakt.

### D5 · Die Abbruchmeldung maskiert ihre eigene Ursache

`_validate_action` (`orchestration_controller.py:786-798`) validiert die
Abort-Action gegen `schemas/orchestration-action.schema.json`, wo
`reason` `maxLength: 1000` trägt. `_run_script:1120-1123` legt die **volle**
stdout/stderr des Builders in den Reason. Der Builder gibt zusätzlich zum
`INVALID`-Befund neun Zeilen Normalisierungs-Receipts und eine ADVISORY aus →
über 1000 Zeichen → die Abort-Action wird selbst verworfen, und was die Konsole
erreicht, ist:

```
internal action-manifest validation failed: '<gesamter Text>' is too long
```

Die Ursache steht darin, aber als Beifang einer Meta-Fehlermeldung. Das Log
(`.agent-run.log`, `RUN_ABORTED`) enthält die saubere Fassung — Konsole und Log
divergieren also genau im Diagnosefall. Behebung: Reason vor `_validate_action`
kappen und auf das Log verweisen (~3 Zeilen).

### D6 · Advisory ohne Wirkung *(nachrangig)*

`[advisory] T-032: component='web-ui' but evidence file(s) ['package-lock.json']
do not match any of its paths globs … Likely Stage-1 classified by attack-target
tier instead of control-location tier.` — korrekt erkannt, korrekt als Advisory
eingestuft, kein Beitrag zum Abbruch. Bestätigt die bekannte
Tier-Fehlklassifikation von Supply-Chain-Funden.

---

## 2. Zustand nach dem Abbruch

`RUN_ABORTED` steht im Log; der Latch aus **D4a** der Schwesteranalyse greift
(`_context_v2_guard`). Stage 1 ist vollständig auf Platte
(`.threats-merged.json`, `.evidence-verification.json`, `.tier-root-causes.json`,
alle `.stride-attempts/*`), aber nicht fortsetzbar. `threat-model.yaml` liegt in
einer **ungültigen Vorlieferform** auf Platte (keine `id`, kein `meta`) — der
Builder schreibt vor der Validierung.

Der inhaltliche Schaden ist null, der Kostenschaden ein kompletter Lauf.

---

## 3. Warum das repo-unabhängig ist

1. `_clean_title` läuft für **jedes** Repo an derselben Stelle.
2. Ziffern-initiale Titel sind eine natürliche LLM-Formulierung für
   Mengenbefunde (*„N Accounts", „N Endpunkte"*) — die Wahrscheinlichkeit
   **wächst mit der Fundzahl**, also mit der Repo-Größe.
3. Der Contract erreicht den STRIDE-Analyzer in **keinem** Tier.
4. Der Reason-Overflow (D5) tritt bei **jedem** Builder-Fehlschlag auf, weil die
   Receipt-Zeilen allein schon nahe an das 1000-Zeichen-Limit reichen.

---

## 4. Verhältnis zur Schwesteranalyse

**Gemeinsame Wurzel, verschiedene Pipeline-Ebene.** Beide Läufe sterben daran,
dass ein **inhaltlicher Fehler eines LLM-Producers terminal klassifiziert wird**,
und in beiden ist die dokumentierte Semantik weicher als die implementierte.

| Achse | juice-shop (Schwesteranalyse) | dieser Lauf |
|---|---|---|
| Verletztes Feld | `signal_classification` (Enum) | `threats[].title` (Pattern) |
| Producer des Werts | Recon-Scanner (Haiku), **direkt** | STRIDE-Analyzer, **indirekt über Komposition** |
| Validierender Producer | derselbe LLM-Artefakt-Validator | `build_threat_model_yaml.py` (**deterministisch**) |
| Zeit bis Abbruch | ~4 min | ~75 min |
| Deterministischer Normalisierer vorhanden? | nein | **ja, aber lückenhaft** (D1) |
| Contract dem Producer bekannt? | ja, aber verwechselbar (D1 dort) | **nein** (D4 hier) |
| Von M3/M4 abgedeckt? | **ja** | **nein** — siehe unten |

### Die Lücke, die M3/M4 offen lassen

M3 („Fehlerklasse am Erkennungsort nach `producer=llm` wählen") und M4
(„Retry rollen-generisch") knüpfen daran, dass der **Schreiber der validierten
Datei** ein LLM ist. Bei `context-v2-finalize` ist der Schreiber
`build_threat_model_yaml.py` — ein Skript. Nach der Invariante `:474-476`
(*„Deterministische Producer bleiben terminal"*) bliebe dieser Abbruch also auch
**nach vollständiger Umsetzung von M3 und M4 terminal**.

> **Korrigiert in Revision 2 (§5a/V2).** Die erste Fassung schloss hieraus, die
> Trennlinie müsse **Urheber des Inhalts** statt **Schreiber der Datei** heißen,
> und komponierte Artefakte gehörten per JSON-Pointer als Producer-Fehler
> klassifiziert. Das ist für diesen Abbruch falsch: der Titel war
> deterministisch reparierbar, ein Retry hätte ihn nur neu gewürfelt. Die
> tragfähige Achse ist **normalisierbar vs. nicht normalisierbar** — sie
> schneidet quer zu „LLM vs. Skript" und liefert für beide Läufe die richtige
> Antwort. Begründung und Belege in §5a/V2.

M2 (Validierung zur Schreibzeit) greift hier ebenfalls nicht: zur Schreibzeit
des STRIDE-Attempts ist der Titel **schemakonform**, weil `stride.schema.yaml`
ihn nicht constraint. Die Regel entsteht erst stromabwärts.

---

## 5. Maßnahmen

> **Revision 2 (nach `bb8e158c` / `ba2436c5`).** Die Nachprüfung in §5a hat zwei
> Aussagen der ersten Fassung widerlegt und die eigentliche Ursache eine Ebene
> tiefer verschoben. Die Tabelle unten ist die korrigierte Fassung; die
> zurückgezogene N5 steht in §5a mit Begründung.

| # | Maßnahme | Umfang | Wirkung |
|---|---|---|---|
| **N1** | `_clean_title`/`_clamp_title` **total** machen: für jede Eingabe erfüllt die Komposition den vollen Constraint-Satz (Pattern ∧ 10 ≤ len ≤ 80 ∧ ¬Blocklist). Abnahme als **Eigenschaft**, nicht als Beispielliste | ~10 + ~20 Zeilen | **beseitigt die Abbruchklasse**, nicht nur den Ziffernfall |
| **N1b** | Verlustbehaftete Notreparatur **sichtbar** machen: Event + `_title_source`-Stash statt stiller Umschrift | ~5 Zeilen | liefert die Messung, die N3 begründet (Doktrin „Instrumentierung vor M4", `ba2436c5` §5b) |
| **N2** | Reason vor `_validate_action` kappen, auf `.agent-run.log` verweisen | ~3 Zeilen | Ursache wird wieder sichtbar (D5) |
| **N3** | `finding-title-contract.md` in `appsec-stride-analyzer-v2.md` einbinden | ~5 Zeilen | **Qualität, nicht Sicherheit** — senkt die Rate verlustbehafteter Reparaturen |
| **N4** | Contract-Doku korrigieren: `_clean_title` als tatsächlichen Garanten benennen; den nicht existierenden `title_substring_blocklist`-Check aus dem Schema-Kommentar entfernen oder bauen | Doku + ggf. Check | D3 — die Doku zeigt auf den unwirksamen Normalisierer und auf einen Check, den es nicht gibt |
| **N6** | **Reparaturdoktrin festschreiben** (ersetzt N5): pro Constraint-Art ist verbindlich, ob normalisiert, verworfen, gewarnt oder abgebrochen wird — siehe §5a/V4 | Design + Regel | behebt die Ursache, aus der der No-Op überhaupt tödlich werden konnte |

**Reihenfolge:** N1 → N2 → N6 → N1b → N4 → N3.

N1 zuerst, weil es die Abbruchklasse schließt. N2 unmittelbar danach, weil ohne
es jede künftige Diagnose dieser Klasse mit einer maskierten Meldung beginnt.
N6 ist die strukturelle Arbeit und gehört mit M3 der Schwesteranalyse zusammen
geplant. N3 zuletzt und **nur mit der Messung aus N1b** — ohne sie wäre es
dieselbe unbelegte Vermutung, aus der `ba2436c5` M4 zurückgestellt hat.

**Ausdrücklich nicht empfohlen: das Schema lockern.** Ein Titel wie
*„14 Named Accounts Seeded with …"* ist nach den eigenen Regeln des Schemas
(`:626-630`, „library-agnostic CWE-canonical noun phrase") tatsächlich falsch —
er benennt eine Anzahl statt einer Schwächenklasse. Das Schema urteilt korrekt;
defekt ist der Reparaturweg. `^[A-Z]` zu streichen wäre die Symptombehandlung:
sie erkauft Lauffähigkeit mit schlechteren Deliverables.

---

## 5a. Nachprüfung der eigenen Befunde

Vier gezielte Angriffe auf die erste Fassung. Zwei Aussagen fielen.

### V1 — „`title` ist das einzige schema-beschränkte Prosafeld" · **zu eng**

Für `pattern` stimmt es: von 41 Pattern-Constraints im Output-Schema binden
**40 IDs und Maschinen-Token** (`^T-\d{3,}$`, `^tb-\d+$`, `^CVSS:4\.0…`), die
deterministischer Code erzeugt. `title` ist der einzige Regex auf Prosa.

Die **Klasse** ist damit aber nicht n=1. Rund zwanzig Prosafelder tragen
`maxLength`, mehrere zusätzlich `minLength` — `attack_steps` (15), `rationale`
(20), `enforcement_point` (3), `generic_threat_title` (5). Das sind ebenso
inhaltsgetriebene Constraints, die nur ein LLM verletzen kann.

### V2 — „N5 vollständig zurückziehen" · **zu stark; korrigierte Trennlinie**

Aus V1 folgt die richtige Achse. Sie ist weder *„wer hat die Datei geschrieben"*
noch *„direkt vs. komponiert"*, sondern:

> **Kann eine deterministische Transformation den Verstoß beheben?**

* **Normalisierbar** (`pattern`, `maxLength`, Blocklist): Kürzen, Umschreiben und
  Ersetzen sind immer möglich. Hier ist **Totalität** die Antwort und Retry
  falsch — ein Redispatch würfelt neu, wo eine Funktion garantieren kann.
* **Nicht normalisierbar** (`minLength` auf Prosa, semantisch leere
  Pflichtfelder): kein Skript kann Inhalt erfinden. Nur der Producer kann das
  beheben — hier ist die Producer-Klassifikation aus `bb8e158c` das **einzig**
  richtige Mittel, und Terminalität wäre der Fehler.

N5 bleibt also gültig, aber **nur für die zweite Hälfte**. Für meinen Abbruch
war sie falsch: der Titel war normalisierbar, ein Retry hätte STRIDE nach 75 min
neu gestartet und mit gleicher Wahrscheinlichkeit erneut einen ziffern-initialen
Titel erzeugt — Budget verbrannt, Lauf trotzdem tot.

### V3 — „Totalisieren genügt" · **nur für Sicherheit, nicht für Qualität**

Zwei Totalisierungsstrategien, empirisch gegen das Pattern geprüft: beide
erfüllen den Regex, beide beschädigen Bedeutung.

| Eingabe | Präfix voranstellen | führenden Nicht-Buchstaben-Lauf kürzen |
|---|---|---|
| `404 handler leaks stack traces (…)` | `Finding: 404 handler leaks …` | `Handler leaks stack traces (…)` — *welcher* Handler ist weg |
| `"password" is the seeded credential (…)` | `Finding: "password" is …` | `Password" is …` — kaputtes Anführungszeichen |
| `__init__ exposes a debug route (…)` | `Finding: __init__ exposes …` | `Init__ exposes …` — verstümmelt |

**Es gibt keine rein syntaktische Totalisierung, die zugleich semantisch sauber
ist.** Daraus folgt die Schichtung: N1 garantiert, dass nie ein Lauf stirbt;
N1b macht die verlustbehaftete Notreparatur sichtbar statt still; N3 senkt die
Rate an der Quelle — und wird durch N1b belegt statt geraten.

### V4 — die eigentliche Ursache liegt tiefer als D1

Der No-Op ist die *proximate* Ursache. Dass er **tödlich** wurde, liegt daran,
dass das Repo für denselben Sachverhalt — „ein Feld eines komponierten
Artefakts verletzt sein Schema" — **vier nebeneinander bestehende Doktrinen**
kennt, ohne Regel, welche gilt:

| Doktrin | Stelle | Verhalten |
|---|---|---|
| normalisieren | `build_threat_model_yaml.py:1126` | Titel wird umgeschrieben |
| verwerfen | `merge_threats.py:262` | zu kurze `attack_steps` fliegen raus |
| normalisieren + warnen | `orchestration_controller.py:3589` (`RECON_KEY_FILES_NORMALIZED`) | Wert wird korrigiert, Event gesetzt |
| **abbrechen** | `build_threat_model_yaml.py:2658-2662` | Lauf stirbt |

Welche greift, ist eine Frage dessen, welcher Codepfad wann geschrieben wurde —
keine Entscheidung. Mein Lauf ist der Fall, in dem der Zufall auf „abbrechen"
fiel, obwohl derselbe Constraint-Typ zwei Zeilen weiter oben normalisiert wird.
**Das ist der Root Cause auf Systemebene**, und N6 adressiert ihn; N1 allein
würde ihn ungelöst lassen und nur diese eine Fundstelle sanieren.

### V5 — `bb8e158c` verschlechtert nichts

Geprüft, weil naheliegend: die bis zu 32 Validator-Fehler, die `_document_fault`
jetzt mitführt, landen in einer Datei (`_write_producer_repair_brief:526`), nicht
im `reason` der Action. Kein neues Overflow-Risiko. D5 bleibt unverändert offen
und hat durch den neuen Pfad einen zweiten Weg dorthin: ist das Retry-Budget
erschöpft, geht die `_document_fault`-Meldung mit bis zu fünf jsonschema-Messages
in eine Abort-Action mit `maxLength: 1000`. Dass diese Grenze praktisch erreicht
wird, hat dieser Lauf bewiesen.

---

## 5b. Umsetzungsstand

**Umgesetzt — N1, N1b, N2:**

| Datei | Änderung |
|---|---|
| `scripts/build_threat_model_yaml.py` | `_ensure_pattern_lead()` totalisiert den `^[A-Z]`-Lead und meldet, ob das verlustbehaftet war; `_fallback_title()` deckt den unrettbaren Rest; `_conform_title()` ersetzt die Zeile am Aufrufort, stasht bei Verlust das Original in `_title_source` und zählt die Fälle; ein `warnings`-Eintrag macht die Rate sichtbar |
| `scripts/orchestration_controller.py` | `_cap_reason()` hält den Abbruchgrund unter `reason.maxLength`; Kopf **und** Ende bleiben erhalten, weil das Urteil eines Subprozesses an beiden Enden stehen kann |
| `tests/test_build_threat_model_yaml.py` | Property-Test über 14 feindliche Leads gegen das **aus dem Schema geladene** Pattern; Identitätstest auf konformen Titeln; Tests für Verlustmeldung, `_title_source`, Anführungszeichen-Waise, Fallback und Locator-Rückgewinnung |
| `tests/test_orchestration_controller.py` | `TestFailureReasonFitsTheActionSchema` — gekappter Grund erhält beide Enden und die Abort-Action besteht ihr eigenes Schema |

**End-to-End gegen das Artefakt, das den Lauf getötet hat:** der Build läuft
durch (`EXIT=0`), `validate_intermediate.py threat_model_output` meldet
`VALID: 53 threats, 53 mitigations`, und der Receipt weist die Reparatur aus:

```
threats: 1 title(s) repaired lossily to satisfy the schema pattern
  (original kept in _title_source) — the STRIDE analyzer is authoring titles the contract rejects
14 Named Accounts Seeded with Hardcoded Password "password" (…)
  → Named Accounts Seeded with Hardcoded Password "password"
```

**Zwei Befunde aus der Umsetzung:**

*Der Locator-Verlust ist kein Defekt.* Dass `(SecurityConfig.java:71)` in
diesem Fall wegfällt, ist die dokumentierte und richtige Abwägung von
`_clean_title:1106-1121`: bei Überlauf wird lieber der Locator geopfert als die
Schwächenformulierung mit „…" abgeschnitten, weil ein gekappter Titel in jede
Cross-Reference und jeden Anker propagiert. Der Pfad lebt in `evidence_file`
weiter. Dieser Titel überschreitet die Grenze auch ohne den Lead.

*Die Lead-Entfernung gibt Längenbudget zurück — und das ändert Ausgelieferte.*
Im Band 81–83 Zeichen fällt der Locator **nur** wegen des nicht konformen Leads
weg. `_conform_title` reinigt deshalb das lead-bereinigte Original ein zweites
Mal und holt ihn zurück; verifiziert und als Test verankert. Die Reihenfolge ist
dabei bindend: der erste Durchgang muss `_clean_title` bleiben, sonst würde ein
Backtick- oder `@`-Lead, den dieser verlustfrei entfernt, fälschlich als
verlustbehaftet gezählt — und damit die Messung aus N1b verfälschen.

## 5c. Der Titel war kein Sonderfall — gemessen

Die Suche nach gleichartigen Defekten wurde nicht als Code-Lektüre geführt,
sondern als Experiment: je **ein** plausibler Analysten-Schreibfehler wird in
`.threats-merged.json` injiziert und der Builder darauf angesetzt. Zehn Sonden,
sonst identische Eingabe.

| Sonde | Wert | vorher | nachher |
|---|---|---|---|
| `cwe` als Liste | `CWE-79, CWE-80` | **KILL** | ok → `CWE-79` |
| `cwe` nackt | `79` | **KILL** | ok → `CWE-79` |
| `cwe` mit Gloss | `CWE-798 (Hardcoded Credentials)` | **KILL** | ok → `CWE-798` |
| `risk` mit Zusatz | `Critical (see notes)` | **KILL** | ok → `Critical` |
| `likelihood` frei | `very high` | **KILL** | ok → Fallback, gemeldet |
| `impact` frei | `catastrophic` | **KILL** | ok → Fallback, gemeldet |
| `scenario` zu kurz | `x` | **KILL** | **KILL** (siehe unten) |
| `finding_type_id` frei | `TH-UNCLASSIFIED` | ok | ok |
| `mitigation_title` leer | `""` | ok | ok |
| `component_id` mit Großbuchstaben | `Web UI` | ok | ok |

**Sieben von zehn töteten den Lauf.** Der Titel war eine von mindestens sieben
Stellen, an denen ein gewöhnlicher Formulierungsunterschied eines LLM einen
bezahlten Lauf am Stage-2-Handoff beendet — repo-unabhängig, denn keine dieser
Sonden hat etwas mit diesem Repository zu tun.

Das ist der empirische Beleg für V4: nicht ein No-Op war das Problem, sondern
das Fehlen einer Regel, was bei einem Verstoß zu geschehen hat.

**Geschlossen (normalisierbar):** `_normalize_cwe()` und
`_normalize_severity_word()`, angewandt am selben Aufrufort wie der Titel und im
Stil des vorhandenen `_normalize_cvss_v4`. Jede beobachtete Schreibweise trägt
ihren Wert eindeutig, also wird sie überführt statt verworfen. `cwe` ist nicht
`required` — ein unlesbarer Wert entfällt und wird gemeldet.

**Bewusst nicht geraten:** eine Schwere zu ranken *ist* eine
Sicherheitsaussage. Nur eindeutige Schreibweisen werden abgebildet
(`moderate`→`Medium`, `info`→`Informational`, Groß-/Kleinschreibung, ein
angehängter Klammerzusatz). `very high` oder `catastrophic` nimmt den
`Medium`-Rückfall, den diese Schleife schon für eine *fehlende* Schwere
verwendet — und meldet ihn, statt eine fremde Einschätzung stillschweigend zu
erfinden.

**Bewusst offen: `scenario` unter `minLength`.** Kein Skript kann ein Szenario
erfinden. Automatisch reparieren hieße den Fund verwerfen oder Text erfinden —
beides schlechter als der Weg zurück zum Producer. Das ist exakt die zweite
Hälfte aus V2 und damit der Anwendungsfall für die Producer-Klassifikation aus
`bb8e158c`; N6 muss ihn abdecken.

**Ein Defekt in der eigenen Umsetzung, in der Nachprüfung gefunden.** Die erste
Fassung von `_normalize_cwe` schrieb `CWE-0079` auf `CWE-79` um — ein Wert, den
das Schema **bereits akzeptiert**. `cwe` ist Teil des Cross-Run-Fingerprints
(`_threat_fingerprint`), also hätte ein unveränderter Fund im nächsten
inkrementellen Lauf als *resolved und neu hinzugekommen* gelesen. Das ist genau
die Identitätsregel, die ich für den Titel aufgestellt und getestet, für `cwe`
aber nicht gehalten hatte. Korrigiert: ein schemakonformer Wert wird
byte-identisch zurückgegeben, Nullpolsterung eingeschlossen; nur Werte, die
abgelehnt worden **wären**, werden angefasst. Der Test, der die alte Fassung
festschrieb, war selbst der Defekt und wurde ersetzt.

**Zwei weitere Befunde aus der Suche:**

*Der Auto-Emitter-Pass läuft nach der einzigen Schema-Validierung.*
`_context_v2_finalize` prüft das Modell (`validate_intermediate.py`,
`orchestration_controller.py:4792`), lässt danach **neun Emitter** darüber
laufen (`:4800`) und validiert nie erneut. Das Dokument, für das die Garantie
gilt, existiert nach dem Pass nicht mehr. Geprüft und derzeit unschädlich:
`emit_clean_finding_titles` trägt denselben `s[0].upper()`-No-Op (`:138`), kann
aber aus konformer Eingabe keine unzulässige Ausgabe erzeugen — und seit N1 ist
seine Eingabe garantiert konform. Die Absicherung fehlt trotzdem.

*`mitigations[].title` ist unkritisch.* Der Verdacht, `_clamp_mitigation_title`
(90) überschreite die Schemagrenze, ist widerlegt: das Feld trägt nur
`minLength: 1`, keine Obergrenze.

*Der Severity-Floor liest den rohen Wert (vorbestehend, nicht verändert).*
`build_threats:1264` stuft mit `_SEVERITY_FLOOR_RANK.get(str(sev).lower(), 2)`
ein — **vor** jeder Normalisierung. Jede unbekannte Schreibweise erhält damit
Rang 2. Beim Default-Floor (`medium`, Rang 2) ist das folgenlos: es wird nichts
fälschlich verworfen, höchstens ein als `info` geschriebener Fund
fälschlich behalten. Wird `register_severity_floor` jedoch auf `high` gehoben,
fällt ein als `Critical (see notes)` geschriebener kritischer Fund als Rang 2
**stillschweigend aus dem Register**. Die Korrektur wäre, die Normalisierung
vor die Floor-Prüfung zu ziehen; das ändert aber, was ausgeliefert wird, und
gehört deshalb als eigene Entscheidung entschieden — nicht als Nebenwirkung
eines Abbruch-Fixes.

## 5d. M6b und N7 — Umsetzung und was N7 sofort fand

**M6b — der Abbruch ist reversibel.** `detect_abort()` wertet nicht mehr das
erste `RUN_ABORTED` aus, sondern das **jüngste** Abbruch/Clear-Paar im
Lauffenster; `orchestration_controller.py clear-abort --reason …` hängt ein
`RUN_ABORT_CLEARED` an. Es wird **nichts gelöscht** — die `RUN_ABORTED`-Zeile
bleibt stehen. Ein zweiter Abbruch nach einem Clear latcht wieder.

Der Anlass war messbar, nicht prinzipiell: auf einer Kopie dieses Laufs liefert
`context-v2-finalize` nach dem Clear `run_gate` — Stage 1 abgeschlossen, in
Sekunden. Die 75 Minuten lagen unversehrt auf Platte. Der Latch hat für einen
reparierbaren Feldfehler einen vollständigen Neuscan berechnet und zugleich den
einzigen Fortsetzungsweg zur Audit-Manipulation gemacht (`RUN_ABORTED` aus dem
Log filtern). Genau deshalb gibt es jetzt den sanktionierten Pfad.

> Die Zurückstellung von M6b in `ba2436c5` §5b war folgerichtig — sie stützte
> sich darauf, dass Producer-Aborts nach M3 selten würden. Das galt für Recon.
> Für den Finalize-Boundary zeigen die Sonden aus §5c eine eigene, größere
> Fläche, die M3 **nicht** abdeckt: dort schreibt ein Skript. Die Datenlage,
> die §5b als fehlend benannte, liegt damit vor.

**N7 — Re-Validierung nach dem Emitter-Pass**, fatal nach dem Vorbild von
`orchestration_controller.py:5284` („the yaml on disk is invalid and must not
reach Stage 2"). Mit M6b darunter kostet ein Fehlschlag hier die Diagnose, nicht
den Lauf.

**N7 fand beim ersten Lauf einen Defekt — meinen eigenen.**
`emit_clean_finding_titles` leitet den Titel laut Vertrag bei **jedem** Lauf aus
`_title_source` neu ab (seine Idempotenz-Zusage). Der Stash aus N1b enthält das
rohe Original, und der Emitter trägt dieselbe Lücke wie der Builder — `:137`
prüfte `s[0].islower()`, was für eine Ziffer ebenfalls `False` ist. Ergebnis:
der reparierte Titel wurde **nach** dem Schema-Gate auf
`14 Named Accounts … — SecurityConfig.java:71` zurückgeschrieben, und ohne N7
wäre genau dieses ungültige YAML nach Stage 2 gegangen. Der Fehler war eine
Kopplung, die ich beim Wiederverwenden eines fremden Feldes nicht geprüft habe.

Behoben an der Stelle, die sich selbst als „single point responsible for
producing schema-clean titles" bezeichnet (`:143-147`): `_force_pattern_lead()`
als Geschwister des Builder-Helfers, mit Property-Test über dieselben feindlichen
Leads. Danach: Wiederherstellung über `clear-abort` → `context-v2-finalize` →
`run_gate`, **0 schema-verletzende Titel** unter 53 Funden.

Das ist zugleich der Beleg für den Wert von N7: der Defekt war ohne diese
Prüfung unsichtbar, und die Klasse „Emitter beschädigt das validierte Modell"
war vorher nur theoretisch benannt.

**Offen:** N6 (Reparaturdoktrin, jetzt mit `scenario` als konkretem Fall), N4
(Contract-Doku und der nicht existierende `title_substring_blocklist`-Check), N3
(Contract an den STRIDE-Analyzer, erst mit der Messung aus N1b zu begründen).
Nicht in Angriff genommen, weil außerhalb des Auftrags: die Titelqualität des
Emitters bei zerlegten Quellen (`package-lock.json present and committed` →
`On present and committed`, hängengebliebene Präposition in `… exposed at —`).
Vorbestehend, unabhängig von diesen Änderungen.

---

## 6. Symptom → Ursache

| Symptom | Ursache | Maßnahme |
|---|---|---|
| `internal action-manifest validation failed: '…' is too long` | D5 — Reason > 1000 Zeichen; echte Ursache nur im Log | N2 |
| `INVALID: threats[N].title … does not match '^[A-Z]…'` | D1 — Cleaner-No-Op bei **jedem** nicht-kasusfähigen Erstzeichen (Ziffer, `/`, `.`, `_`, `$`, `<`, `"`, `'`) | N1 |
| Titel-Defekt überlebt den Auto-Emitter | D3 — der dokumentierte Normalisierer läuft nach dem Gate und kennt die Regel nicht | N1 + N4 |
| Schemaverstoß eines Prosafelds ist mal tödlich, mal nicht | **V4** — vier Reparaturdoktrinen ohne Regel, welche gilt | N6 |
| `minLength`-Verstoß auf Prosa (`attack_steps`, `rationale`) | nicht deterministisch reparierbar — nur der Producer kann das | N6 (Producer-Klassifikation, `bb8e158c`) |
| Titel wird still zu Unsinn umgeschrieben | V3 — verlustbehaftete Notreparatur ohne Signal | N1b |
| Lauf stirbt erst in `context-v2-finalize`, Stage 1 komplett bezahlt | D4 — Regel existiert nicht am Attempt-Schema | N3 (Qualität), N1 (Sicherheit) |
