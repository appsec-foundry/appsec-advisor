# Verlinkte Maßnahmen (M-NNN) — einheitliche, farblose Prioritäts-Annotation

> **STATUS (2026-06-04): Variante B umgesetzt — eingekreiste Ziffern.** Jede
> verlinkte Maßnahme trägt jetzt ein farbloses Prioritäts-Prefix aus *einer*
> monochromen eingekreisten Ziffer, deren Zahl die Priorität IST: `❶` P1 …
> `❹` P4 — das colourless Pendant zum farbigen Severity-Kreis der Findings,
> selbsterklärend, daher **ohne** `P1`-Text und **ohne** Füll-Kreis (die frühere
> `● P1 ·`-Form ist abgelöst). Verifiziert DejaVu-/PDF-sicher (U+2776–2779); die
> gefüllten `❶❷❸❹` grenzen sich von den Outline-`①②③④` der Attack-Path-Klassen
> ab. Umgesetzt am Chokepoint `linkify_with_label` (Voll-Form) plus die
> Bare-Chip-Sites via `_measure_prio_prefix`: §2 Top-Threats-Fix, §7b
> Requirements-Traceability, Top-Findings-Maßnahmen, §9 Mitigations-Index,
> Top-Mitigations-Tabelle. Findings sind parallel überall mit ihrem farbigen
> Kritikalitätskreis annotiert (u.a. §7b find_cell ergänzt). Verbleibende
> Bewusst-Ausnahme: Top-Findings-Findings-Spalte (eigene Criticality-Spalte
> zeigt den Kreis 1:1 → kein doppelter Dot am Link).


**Frage (2026-06-03):** Gibt es eine einheitliche und sinnvolle Möglichkeit, im Report
*verlinkte* Maßnahmen ähnlich wie Findings zu annotieren — nur **ohne Farben** und mit
**Priorität statt Kritikalität**? Dieses Dokument analysiert den Ist-Zustand und arbeitet
mehrere Varianten aus.

---

## 1. Ist-Zustand: warum es heute *nicht* einheitlich ist

Findings haben **einen** Chokepoint, der jede Referenz konsistent annotiert:

`RenderContext.linkify_with_label(ref)` — `scripts/compose_threat_model.py:397`

```python
dot = ""
if re.match(r"^F-\d+$", r):                       # nur Findings
    emoji = self.severity_emoji(self.severity_for_ref(r))
    if emoji:
        dot = f"{emoji} "
...
return f"{dot}[{r}](#{anchor}) — {label}"          # 🔴 [F-009](#f-009) — SQL Injection …
```

Egal wo ein `F-NNN` verlinkt wird (§7-Traceability, §8-Cards, §9-Addresses-Bullets,
Fließtext), es bekommt **automatisch** denselben farbigen Severity-Kreis. Eine einzige
Quelle der Wahrheit.

Für `M-NNN` gibt es **keinen** solchen Chokepoint. Die Priorität wird heute an **vier
verschiedenen Stellen unterschiedlich** (oder gar nicht) dargestellt:

| Ort | Datei:Zeile | Was M-NNN heute zeigt |
|---|---|---|
| Finding-Card **Fix:**-Zeile | `_build_threat_card` (~11523) | **gar nichts** — nur `· [M-001](#m-001) · [M-007](#m-007)` |
| Top-Mitigations-Tabelle | `mitigations.md.j2:35` + `_compute_top_mitigations_rows` | eigene **Spalte** `Priority` = `P1` |
| §9 Mitigations-Index | `_render_mitigation_register` (12206-12247) | **Text-Tag** `P1 ·` (Kreis unterdrückt, `show_icon=False`) |
| §9 Register-Block Meta | 12370 | Lang-Text `**Priority:** P1 — Immediate` |

Die Priorität *selbst* ist bereits sauber definiert und ableitbar:

- Explizites `priority`-Feld (`P1..P4`) in `threat-model.yaml`, sonst
- abgeleitet aus max. Severity der adressierten Findings:
  `_derive_priority` (`6332`) bzw. die Index-Variante (12216-12232):
  `Critical→P1, High→P2, Medium→P3, Low→P4`.
- Bedeutung: **P1** vor Deployment · **P2** aktueller Sprint · **P3** nächstes Quartal · **P4** Backlog.

**Kernproblem ist also nicht „fehlende Daten", sondern fehlende *Einheitlichkeit*** —
dieselbe Priorität wird in 4 Formen (nichts / Spalte / Text-Tag / Langtext) gezeigt, und
an der wichtigsten Verlinkungsstelle (Finding-Card Fix-Zeile) **gar nicht**.

---

## 2. Der einheitliche Mechanismus (Grundlage aller Varianten)

Spiegele exakt die Findings-Mechanik, nur farblos und prioritätsbasiert:

1. **`priority_for_ref(ref)`** — neuer Helper als Geschwister von `severity_for_ref`
   (`336`). Nimmt `M-NNN`, liefert `p1..p4` (explizit oder abgeleitet — Logik aus
   12216-12232 in eine wiederverwendbare Methode ziehen, statt sie im Index inline zu haben).

2. **`linkify_with_label` erweitern** (`397`): aktuell `if F-\d+ → dot`. Ergänze
   `elif M-\d+ → badge` (farbloses Prioritäts-Badge, Form = eine der Varianten unten).
   Damit erbt **jede** M-Verlinkung im ganzen Report automatisch dieselbe Annotation —
   genau wie Findings.

3. **Doubling-Guard** (analog zum bestehenden Dot-Guard-Kommentar bei 423-427): Kontexte,
   die bereits eine **eigene** Priority-Spalte/Meta-Zeile führen, dürfen das Inline-Badge
   *nicht* zusätzlich rendern:
   - Top-Mitigations-Tabelle (hat `Priority`-Spalte) → Badge unterdrücken **oder** Spalte streichen.
   - §9 Register-Meta `**Priority:** P1 — Immediate` → bleibt als Langform, Heading-Badge optional.
   Das Badge gehört primär dorthin, wo Priorität heute **fehlt**: Finding-Card Fix-Zeile,
   Fließtext, §7-Traceability.

> Ohne diesen Guard verdoppelt sich die Priorität (gleicher Fehlertyp wie der Severity-Dot-
> Doubling-Bug, den der Kommentar bei 423 explizit verhindert).

Die **Varianten unterscheiden sich nur in der visuellen Form des farblosen Badges.**

---

## 3. Varianten für das farblose Prioritäts-Badge

Referenz-Zeile zum Vergleich (Finding, heute, farbig):

> `🔴 [F-009](#f-009) — SQL Injection in routes/login.ts`

### Variante A — Text-Tag als Prefix (Plain `P1`)
```
P1 · [M-001](#m-001) — SQL Parameterization
P3 · [M-014](#m-014) — Input Validation Layer
```
- **Pro:** Schon heute im §9-Index im Einsatz → null neues Vokabular. PDF-sicher (reiner Text,
  keine Glyph-/Tofu-Risiken — siehe `bug_pdf_renderer_five_defects`). Eindeutig, selbsterklärend.
- **Contra:** Optisch **nicht** parallel zu Findings (die mit einem *Glyph* führen, nicht mit Text).
  „Ähnlich wie Findings" nur konzeptionell, nicht visuell.

### Variante B — Monochromer Füll-Kreis (Form statt Farbe) — *engste Analogie*
Severity nutzt Hue (🔴🟠🟡🟢). Priorität nutzt **Füllgrad** desselben Kreises:
```
● P1 · [M-001](#m-001) — SQL Parameterization      (● = voll, dringend)
◕ P2 · [M-007](#m-007) — CSRF Token Enforcement
◑ P3 · [M-014](#m-014) — Input Validation Layer
◔ P4 · [M-022](#m-022) — Security Headers           (◔ = fast leer, Backlog)
```
Mapping: `P1=● P2=◕ P3=◑ P4=◔` (oder `P4=○` leer).
- **Pro:** Visuell **exakt** parallel zur Findings-Zeile (führender Kreis-Glyph), aber farblos —
  Magnitude über Füllung. Erfüllt „ähnlich wie Findings … nur ohne Farben" am direktesten.
- **Contra:** **PDF-Render-Risiko.** `●` ist verifiziert-sicher (Glyph-Swap-Fix im PDF-Renderer),
  aber `◕ ◑ ◔ ○` sind im Print-Font ungetestet → Tofu-Gefahr. Müsste vor Einsatz im PDF geprüft
  werden. Füllgrad-Semantik ist ohne Legende nicht selbsterklärend (`◑` = welche Prio?).

### Variante C — Bracket-Tag als Prefix
```
[P1] [M-001](#m-001) — SQL Parameterization
```
- **Pro:** Kompakt, farblos, PDF-sicher.
- **Contra:** `[P1] [M-001]` — zwei Bracket-Gruppen direkt nebeneinander lesen sich wie zwei
  Links; ein Markdown-Viewer könnte `[P1]` als kaputten Reference-Link interpretieren. **Abraten.**

### Variante D — Prioritäts-Suffix in Klammern
```
[M-001](#m-001) — SQL Parameterization (P1)
[M-014](#m-014) — Input Validation Layer (P3)
```
- **Pro:** Stört den Link-Anfang nicht; liest sich im Fließtext natürlich. PDF-sicher.
- **Contra:** Annotation **trailing** statt **leading** → nicht scan-bar in einer langen Liste
  (man muss bis Zeilenende lesen). Bricht die Findings-Parallele (dort führt der Kreis).

### Variante E — Text-Tag mit Bedeutungswort (Variante A + Legende inline)
```
P1 jetzt   · [M-001](#m-001) — SQL Parameterization
P2 Sprint  · [M-007](#m-007) — CSRF Token Enforcement
P3 Quartal · [M-014](#m-014) — Input Validation Layer
P4 Backlog · [M-022](#m-022) — Security Headers
```
- **Pro:** Selbsterklärend ohne separate Legende; macht die Priorität *handlungsleitend*
  (was der ganze Sinn von Priorität statt Severity ist). PDF-sicher.
- **Contra:** Breiter → in schmalen Tabellenzellen (Top-Mitigations) unschön; besser für
  Index/Fließtext als für Tabellen. Inkonsistente Breite zwischen den Zeilen (`jetzt` vs `Backlog`).

---

## 4. Vergleichsmatrix

| Kriterium | A Text `P1` | B Füll-Kreis | C Bracket | D Suffix | E Tag+Wort |
|---|---|---|---|---|---|
| Visuell parallel zu Findings (führender Glyph) | ◑ | ✅ | ◑ | ❌ | ◑ |
| Farblos | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scan-bar (Prio am Zeilenanfang) | ✅ | ✅ | ✅ | ❌ | ✅ |
| PDF-sicher (kein Tofu-Risiko) | ✅ | ⚠️ | ✅ | ✅ | ✅ |
| Selbsterklärend ohne Legende | ✅ | ❌ | ✅ | ✅ | ✅✅ |
| Tabellen-tauglich (schmal) | ✅ | ✅ | ✅ | ✅ | ❌ |
| Markdown-robust | ✅ | ✅ | ❌ | ✅ | ✅ |
| Bereits im Code vorhanden | ✅ | (teilw.) | ❌ | ❌ | ❌ |

---

## 5. Empfehlung

**Mechanismus:** unbedingt vereinheitlichen via `priority_for_ref` + `linkify_with_label`-
Erweiterung + Doubling-Guard (Abschnitt 2). Das ist der eigentliche Gewinn — eine Quelle der
Wahrheit statt 4 Darstellungen.

**Form:** **Variante A** als Default (farbloses `P1 ·`-Prefix) — sie ist bereits etabliert
(§9-Index), PDF-sicher, scan-bar und in jeder Zelle/Fließtext robust. Sie maximiert
*Einheitlichkeit* (Anforderung Nr. 1) bei null Render-Risiko.

**Falls die visuelle Findings-Parallele wichtiger ist** als PDF-Sicherheit: **Variante B**
(Füll-Kreis) — aber erst nach einem PDF-Render-Test von `◕ ◑ ◔` im Print-Font; sonst
Fallback `P1=● … P4=○` auf zwei verifizierte Glyphen reduzieren.

**Nicht empfehlen:** C (Markdown-Bruch), D (nicht scan-bar).

Pragmatisch lässt sich A→B später kostenlos umstellen, weil beide denselben Chokepoint nutzen —
die Form steckt in *einer* Tabelle (`_PRIO_ICON_TBL` / `_PRIO_LABEL_TBL`, `4181`/`4250`).

---

## 6. Offene Entscheidungen (für den User)

1. **Doubling-Guard-Politik:** In der Top-Mitigations-Tabelle die `Priority`-**Spalte streichen**
   (Badge übernimmt) oder Spalte behalten und Badge dort unterdrücken? (Spalte streichen =
   konsequenter „einheitlich", aber ändert eine etablierte Tabelle.)
2. **Finding-Card Fix-Zeile:** Soll die Prio dort überhaupt erscheinen? Heute bewusst nackt
   (`· [M-001] · [M-007]`). Badge dort = stärkster Nutzen, aber macht die Card-Zeile dichter.
3. **Variante A vs. B** — reine Text-Konsistenz vs. visuelle Findings-Parallele (PDF-Test nötig).
4. **§9 Register-Meta** (`**Priority:** P1 — Immediate`): als Langform behalten (empfohlen,
   trägt Bedeutung) oder auf Badge reduzieren?
