# Option B — Attack-Paths-Bullet-Block durch kompakte Pfad-Tabelle ersetzen

## Kontext

Das Management Summary listet Findings heute an zwei Stellen mit vollem Titel:

1. **Security Posture at a Glance → Attack paths** (per-Pfad-Bullets mit `Findings:` Sub-Liste, jedes Finding mit Titel)
2. **Top Findings** (Tabelle mit `Pfad`-Spalte und Finding-Titel)

Verifiziert am juice-shop-Beispiel:
- Attack-Paths-Block: 49 Zeilen, 23 distinkte F-IDs
- Top-Findings-Tabelle: 31 Zeilen, 20 F-IDs
- Überschneidung: **18 Finding-Titel doppelt im Dokument**

Option A (umgesetzt) hat den Pfad-Lookup repariert, sodass die `Pfad`-Spalte in der Top-Findings-Tabelle korrekt mit Glyphen `①–⑦` befüllt wird. Das macht die Doppelung als bewussten Pivot lesbar, eliminiert sie aber nicht.

Option B entfernt die Titel-Doppelung, indem der Attack-Paths-Bullet-Block durch eine kompakte Pfad-Tabelle ersetzt wird. Finding-Titel erscheinen dann nur noch in der Top-Findings-Tabelle; im Attack-Paths-Block stehen nur noch F-IDs.

## Vorbedingung

Option A (Pfad-Spalte-Fix in `_build_finding_to_path_map`) muss vorher gemerged sein — sonst sind die Glyphen in der Tabelle weiterhin leer und der Pivot zwischen den beiden Sichten existiert nur konzeptuell.

## Ziel-Layout

**Heute (Bullet-Block, ~49 Zeilen):**

```
**Attack paths (numbered arrows in the diagram):**

- ① Injection (Anonymous Internet Attacker → Data Tier) — user input flows into ...
  - Findings:
    - F-003 — Login SQL Injection Enables Auth Bypass
    - F-005 — SQL Injection in Product Search
    - F-016 — NoSQL Injection in Product Reviews
  - Impact: Customer Data Exfiltration, Full Admin Takeover

- ② Auth Bypass (Repository Reader → Application Tier) — authentication can be ...
  - Findings:
    - F-001 — JWT Forgery via Hardcoded RSA Private Key
    - F-002 — alg:none JWT Algorithm Bypass
    - F-006 — RSA Private Key Exposed in Public Repository
    - F-014 — MD5 Password Hashing Without Salt
  - Impact: Full Admin Takeover, Customer Data Exfiltration

... (4 weitere Pfade in gleicher Struktur)
```

**Nachher (Tabelle + Pfad-Narrative, ~14 Zeilen):**

```
**Attack paths (numbered arrows in the diagram):**

| Pfad | Vektor | Akteur → Tier | Findings | Attack Chain | Impact |
|------|--------|---------------|----------|--------------|--------|
| <a id="path-injection"></a>① | **Injection** | Anon → Data Tier | F-003, F-005, F-016 | — | Data Exfiltration, Admin Takeover |
| <a id="path-auth-bypass"></a>② | **Auth Bypass** | Repo Reader → App Tier | F-001, F-002, F-006, F-014 | — | Admin Takeover, Data Exfiltration |
| <a id="path-privilege-escalation"></a>③ | **Privilege Escalation** | Auth User → App Tier | F-007, F-010, F-022, F-028 | — | Admin Takeover, Data Exfiltration |
| <a id="path-sensitive-data-exposure"></a>④ | **Sensitive Data Exposure** | Anon → Data Tier | F-018, F-020, F-025, F-026, F-031 | — | Data Exfiltration |
| <a id="path-remote-code-execution"></a>⑤ | **Remote Code Execution** | Auth User → App Tier | F-008, F-009, F-019 | — | Server Compromise, Data Exfiltration |
| <a id="path-cross-site-scripting"></a>⑥ | **Cross-Site Scripting** | Shop User → Client Tier | F-011, F-012, F-013, F-017 | — | Session Hijack, Admin Takeover |

**① Injection** — user input flows into a server-side SQL or NoSQL interpreter without parameterisation, enabling auth bypass, full user-table extraction, and cross-user data modification.

**② Auth Bypass** — authentication can be circumvented or forged because the RSA signing key is committed to the public repository and express-jwt 0.1.3 accepts alg:none tokens.

(weitere 4 Beschreibungen, je 1 Zeile)
```

→ Information vollständig erhalten (Vektor, Akteur, Tier, Findings, Chain, Impact, Pfad-Narrative). Anchors `path-<slug>` bleiben emittiert, sodass Querverweise aus der Top-Findings-`Pfad`-Spalte heil bleiben. Finding-Titel verschwinden — diese stehen ab jetzt nur noch in der Top-Findings-Tabelle.

## Änderungen pro Datei

### 1. `templates/fragments/security-posture-attack-paths.md.j2` — Rewrite

**Heute:**

```jinja
{{ data.attack_paths_header }}

{% for ap in data.attack_paths -%}
- <a id="path-{{ ap.class_slug }}"></a>**{{ ap.glyph }} {{ ap.class_label }}** ({{ ap.actor_label }} → {{ ap.target_label }}) — {{ ap.description }}
  - Findings:
{%- for f in ap.findings %}
    - [{{ f.id }}](#{{ f.id | lower }}) — {{ f.title }}
{%- endfor %}
{%- if ap.attack_chains %}
  - Attack chain:
{%- for ch in ap.attack_chains %}
    - [{{ ch.id_label }}](#{{ ch.id }}) — {{ ch.title }}
{%- endfor %}
{%- endif %}
  - Impact: {{ ap.impact_string }}

{% endfor -%}
```

**Vorgeschlagen:**

```jinja
{{ data.attack_paths_header }}

| Pfad | Vektor | Akteur → Tier | Findings | Attack Chain | Impact |
|------|--------|---------------|----------|--------------|--------|
{%- for ap in data.attack_paths %}
| <a id="path-{{ ap.class_slug }}"></a>{{ ap.glyph }} | **{{ ap.class_label }}** | {{ ap.actor_label }} → {{ ap.target_label }} | {% for f in ap.findings %}[{{ f.id }}](#{{ f.id | lower }}){% if not loop.last %}, {% endif %}{% endfor %} | {% if ap.attack_chains %}{% for ch in ap.attack_chains %}[{{ ch.id_label }}](#{{ ch.id }}){% if not loop.last %}, {% endif %}{% endfor %}{% else %}—{% endif %} | {{ ap.impact_string }} |
{%- endfor %}

{% for ap in data.attack_paths %}
**{{ ap.glyph }} {{ ap.class_label }}** — {{ ap.description }}
{% endfor %}
```

Renderer-Output-Dict in `_render_security_posture_at_a_glance` (Z. 4080–4128) liefert bereits alle Felder, die das neue Template konsumiert — keine Renderer-Änderung nötig. Verifiziert: `glyph, class_slug, class_label, actor_label, target_label, description, findings:[{id,title}], attack_chains, impact_string` sind alle vorhanden.

### 2. `scripts/qa_checks.py` — B2-Regel umschreiben

**Defekte Regel heute (Zeile ~7194):**

```python
if "  - Findings:" not in block:
    report.issues.append(f"B2: attack-class bullet missing `Findings:` sub-bullet — {first_line[:80]!r}")
```

→ Diese Regel erzwingt aktiv die alte Bulletform. Greift auf jedem generierten Dokument an, sobald das Template auf Tabelle umgestellt ist.

**Vorgeschlagener Ersatz** — strukturelle Prüfung der neuen Tabellenform:

```python
# B2 (table form): the attack-paths section must render a table with the
# canonical 6-column header (Pfad | Vektor | Akteur → Tier | Findings |
# Attack Chain | Impact) and at least one row whose Findings cell carries
# F-NNN/T-NNN references.
EXPECTED_AP_HEADER = "| Pfad | Vektor | Akteur → Tier | Findings | Attack Chain | Impact |"
if EXPECTED_AP_HEADER not in block:
    report.issues.append("B2: attack-paths table header missing or malformed")
if not re.search(r"\|\s*\[[FT]-\d+\]\(", block):
    report.issues.append("B2: attack-paths table rows carry no F-NNN/T-NNN links")
```

Außerdem N1–N4-Narrative-Check (Z. ~6975 — Kommentar erwähnt "attack-paths header"): prüfen ob dortige Annahmen die Bulletform pinnen oder nur den Header. Falls Bulletform: analog umstellen.

### 3. `tests/test_qa_checks.py` — 7 Fixtures anpassen

Treffer auf `- Findings:` in Zeilen 1681, 1686, 1691, 2018, 2023, 2073, 2120. Jede Fixture muss von der Bulletform auf die Tabellenform umgeschrieben werden:

```diff
- - ① Injection (Anon → Data Tier) — ...
-   - Findings:
-     - F-001 — title
-     - F-002 — title
-   - Impact: ...
+ | Pfad | Vektor | Akteur → Tier | Findings | Attack Chain | Impact |
+ |------|--------|---------------|----------|--------------|--------|
+ | <a id="path-injection"></a>① | **Injection** | Anon → Data Tier | [F-001](#f-001), [F-002](#f-002) | — | ... |
```

### 4. `tests/test_compose_threat_model.py` — Test umbenennen + Logik tauschen

- **Zeile 1039** (Docstring): *"1–7 attack-class bullets each with `Findings:` + `Impact:`"* → *"attack-paths table with canonical 6-column header"*
- **Zeile 1243** `test_v2_attack_paths_bullets_below_diagram` → `test_v2_attack_paths_table_below_diagram`
  - Assertion-Block umschreiben: nicht mehr nach Bulletform suchen, sondern nach Header-String + Mindestanzahl Tabellenzeilen + Pfad-Anchors innerhalb der ersten Spalte.

### 5. `tests/test_reference_parity.py` — Goldens neu aufnehmen

Drei Snapshot-Dateien betroffen:
- `examples/threat-modeler/threat-mode-juice-shop-quick.md`
- `examples/threat-modeler/threat-model-juice-shop-standard.md`
- `examples/threat-modeler/threat-model-juice-shop-thorough.md`

Workflow: `pytest -k reference_parity --update-goldens` (oder Projekt-Äquivalent) nach allen Code-Changes.

### 6. `agents/shared/ms-template.md` — Author-Guidance angleichen (optional)

Beschreibung des Security-Posture-at-a-Glance-Blocks von *"per-class bullet block with `Findings:` sub-list"* auf *"compact path table + per-path description sentences"*. Nicht blockierend für den Render — die Agents schreiben Fragment-JSON, nicht Markdown.

## Was NICHT geändert wird

| Artefakt | Status | Grund |
|---|---|---|
| `schemas/fragments/security-posture-attack-paths.schema.json` | unverändert | `findings:[string]` + alle benötigten Felder existieren |
| `data/sections-contract.yaml` | unverändert | Section-Definition unverändert |
| `scripts/compose_threat_model.py` `_render_security_posture_at_a_glance` Output-Dict | unverändert | Liefert bereits alle Template-Inputs |
| `scripts/compose_threat_model.py` `_compute_top_findings_rows` | unverändert | Pfad-Spalte-Befüllung wird durch Option A bereits geliefert |
| LLM-Fragment-Format (`findings:[T-NNN]` Array) | unverändert | Schema-Konvention bleibt |
| `templates/fragments/top-findings.md.j2` | unverändert | Pfad-Spalte ist bereits implementiert |
| Anchors `path-<slug>` | bleiben emittiert | Querverweise aus Top-Findings-Tabelle bleiben heil |
| Schema-Version, Contract-Version | kein Bump | Keine breaking changes am Datenmodell |

## Verifizierte Voraussetzungen

Verifiziert am 2026-05-21 gegen den aktuellen Codestand:

- `scripts/compose_threat_model.py:4080–4128` liefert im Render-Output-Dict alle Felder, die das neue Template braucht — kein Renderer-Patch nötig
- `templates/fragments/top-findings.md.j2` rendert die `Pfad`-Spalte korrekt, sobald `path_glyph` populiert ist (Option A)
- `scripts/qa_checks.py:1465` mappt die Section korrekt auf das Fragment-File — keine Pipeline-Konfiguration berührt
- `scripts/qa_checks.py:7194` ist die einzige strukturelle Bullet-Form-Erzwingung — nur eine Stelle zu patchen
- Fragment-Daten (`security-posture-attack-paths.json`) tragen `findings:[T-NNN]` — die Template-Iteration `{% for f in ap.findings %}` funktioniert unverändert

## Aufwandsschätzung

| Aufgabe | LoC | Bemerkung |
|---|---|---|
| Template-Rewrite (§1) | ~10 | Diff klein, Layout-Wechsel |
| QA-Regel-Rewrite (§2) | ~15 | Regex + Header-Check statt Substring-Check |
| Test-Fixture-Anpassung (§3) | ~50 | 7 Fixtures, mechanische Übersetzung |
| Test-Logik-Umbau (§4) | ~20 | Eine Methode, Assertion-Block austauschen |
| Snapshot-Goldens (§5) | — | Pytest-Command, 3 Dateien |
| Agent-Doku (§6) | ~10 | Optional |
| **Summe** | **~105 LoC + 3 Goldens** | |

## Risiko & Reihenfolge

| Aspekt | Bewertung |
|---|---|
| Daten-Modell-Eingriff | keiner |
| API-Bruch | keiner |
| Schema-Bruch | keiner |
| Pipeline-Bruch | keiner (Render-Output stabil, nur Template ändert sich) |
| Visueller Bruch | spürbar (Bullets → Tabelle) |
| Test-Bruch | groß: 1 QA-Regel + 7 Fixtures + 1 Test + 3 Goldens — alles lokal, mechanisch |

**Empfohlene Reihenfolge** in einem PR:
1. Template `security-posture-attack-paths.md.j2` rewrite
2. QA-Regel `qa_checks.py:7194` umschreiben (B2-Regel auf Tabellenform)
3. Test-Fixtures in `tests/test_qa_checks.py` aktualisieren
4. Test in `tests/test_compose_threat_model.py:1243` umbauen + umbenennen
5. Goldens neu aufnehmen
6. Agent-Doku (optional, kann nachgezogen werden)

Alle Schritte in einem Commit landen, sonst bricht CI zwischendurch (Template-Change ohne QA-Update → B2-Regel feuert auf allen Goldens).

## Empfehlung

Option B nur umsetzen, wenn der vertikale Platzverbrauch oder die textuelle Titelwiederholung wirklich stören. Mit Option A bereits gemerged ist die Doppelung als bewusster Pivot funktional erklärbar — der primäre Defekt ist behoben. Option B ist ein reines Layout-Refactoring ohne semantischen Mehrwert über das hinaus, was Option A bereits liefert.

Falls B gewollt: ein PR, ~105 LoC, lokales Refactoring, kein Schema-Eingriff, beherrschbares Risiko.
