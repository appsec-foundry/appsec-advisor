# Umsetzungsplan — Finding-Konsolidierung & Mitigation-Dedup (Variante 1)

Status: **UMGESETZT (Branch `feat/finding-consolidation`)**. Repo: `appsec-advisor`.
Ziel-Run-Referenz: juice-shop `docs/security/threat-model.yaml`.

## Implementierungsstatus

| Regel | Status | Dateien |
|---|---|---|
| A — Konsolidierung | ✅ | `data/consolidation-groups.yaml`, `schemas/consolidation-groups.schema.yaml`, `merge_threats.py` (`_load_consolidation_groups`, `_match_consolidation_group`, `_consolidate_by_group`, wired in `cmd_collect`) |
| B — Mitigation-Dedup | ✅ | `build_threat_model_yaml.py` (`dedupe_mitigation_controls`, gerufen nach `apply_mitigation_overrides`) |
| C1/C2 — Instanz-Delta | ✅ | `build_threat_model_yaml.py` (`_instance_fingerprints`, Changelog `instance_fingerprints`/`added.instances`/`resolved.instances`) |
| C4 — Renderer | ✅ (per-Instanz Severity-Dots) | `compose_threat_model.py` (instances_card) |
| C3 — Affirmation-Pfad Reconciler | ⏸ bewusst deferred | siehe unten |

**C3 deferred-Begründung:** Der self-contained Instanz-Fingerprint-Diff (C2) liefert
die Partial-Progress-Sichtbarkeit ("3 von 17 Stellen behoben") bereits für ALLE
Run-Typen (full + incremental), da er gegen die im Changelog gespeicherten
`instance_fingerprints` der Vorrun-Entry diffed — unabhängig vom `delta_basis`. Die
zusätzliche instanz-granulare Verdrahtung in `reconcile_incremental_threats`
(analyst-affirmierte Einzelfix-Quittung) ist ein Nischenpfad ohne aktuelle
Testabdeckung; sie würde den fragilen Inkrement-Reconciler anfassen ohne Mehrwert
über C2 hinaus. Als Follow-up dokumentiert.

## Verifikation (echte juice-shop-Daten, `merge_threats collect`)
77 raw → **46** Findings. Survivors: jwt-verification (6→1), missing-route-auth
(17→1), unauth-websocket-channel (3→1), npm-install-scripts (2→1),
dependabot-ecosystems (3→1). IDOR (CWE-639): **21 getrennt** (keine Gruppe).
Hardcoded-Key (798), localStorage (922), XSS (79×3): getrennt. JWT-Survivor spannt
3 Dateien / Critical+High. Voller Test-Suite grün (+ neue Tests in
test_merge_threats / test_build_threat_model_yaml / test_compose_threat_model_cov).

---

(Plan-Referenz unten — Soll-Zustand.)

## Leitprinzip (final abgestimmt)

- **Trenn-Kriterium ist das geteilte Objekt/Mechanismus, NICHT der Fix.**
  - Konsolidieren, wenn die Stellen Ausprägungen *eines* Primitivs/Objekts sind
    (ein JWT-Verifier, eine Route-Registry, eine dependabot.yml, ein WebSocket-Kanal).
  - Getrennt lassen, wenn dieselbe Schwächenklasse auf *unterschiedliche Ressourcen/
    Objekte/Sinks/Flows* angewandt wird (IDOR pro Ressource, XSS pro Sink).
- **Finding ↔ Maßnahme ist 1:n.** Ein konsolidiertes Finding darf mehrere Maßnahmen
  tragen (`mitigation_ids[]` ist bereits eine Liste; kein Schema-Change nötig).
- **Default ist `per_instance`** (safe-by-default: nie still mergen). Konsolidierung nur,
  wenn eine Gruppe explizit im Katalog deklariert ist.
- **Keine Tracking-Regression:** Konsolidierung führt Instanz-Level-Delta ein, damit
  „12 von 17 gefixt" sichtbar bleibt (heute sind es 17 einzeln auflösbare IDs).

## Scope-Klassifikation für diesen Run

| Gruppe | Findings | Aktion |
|---|---|---|
| `jwt-verification` (CWE-347/287/345) | F-003, F-005, F-006, F-027, F-028, F-029 | konsolidieren → 1 Finding, ≥2 Maßnahmen |
| `missing-route-auth` (AUTHZ-008) | F-047…F-063 (17×) | konsolidieren → 1 Finding |
| `dependabot-ecosystems` | F-069, F-070, F-071 | konsolidieren → 1 Finding |
| `npm-install-scripts` (CWE-506) | F-067, F-068 | konsolidieren → 1 Finding |
| `unauth-websocket-channel` | F-042, F-064, F-065 | konsolidieren → 1 Finding |
| IDOR (CWE-639) | F-009…F-046 (21×) | **getrennt** (verschiedene Ressourcen) |
| XSS (CWE-79) | F-007, F-030, F-031 | **getrennt** (verschiedene Sinks) — nur Mitigation-Dedup |
| Hardcoded Key (798), localStorage (922) | F-004, F-001 | **getrennt** (anderes Objekt), verlinken |

Erwartetes Netto: Findings 72 → ~44; Mitigations 61 → ~32. Das F-027/F-028-Duplikat
(beide `lib/insecurity.ts:58`) verschwindet sauber innerhalb des JWT-Findings.

---

## Regel A — Generalisierte Konsolidierung (`consolidation_group`)

### A1. Deklarativer Gruppen-Katalog — NEU `data/consolidation-groups.yaml`

Hier lebt die Security-Judgment-„welche Stellen sind dasselbe Objekt". Beispiel:

```yaml
# Erste passende Regel gewinnt. Keine Regel → per_instance (Default).
groups:
  - id: jwt-verification
    title: "Insecure JWT Verification"
    match_any:
      - cwe: [CWE-347, CWE-287, CWE-345]
        title_pattern: '(?i)\b(jwt|algorithm|signature|verify|decode)\b'
    scope: cross-component          # JWT-Helper ist geteilte Infra
    split_by: [trust_zone]          # Ausnahme: nie über Trust-Zonen mergen

  - id: missing-route-auth
    title: "Sensitive Routes Registered Without Authentication"
    match_any:
      - source_check_id: [AUTHZ-008]
    scope: per-component

  - id: dependabot-ecosystems
    title: "Dependabot Ecosystem Coverage Incomplete"
    match_any:
      - config_check_id: [DEP-DOCKER, DEP-ACTIONS, DEP-NPM]   # exakte IDs aus Run prüfen
    scope: per-component

  - id: npm-install-scripts
    title: "Untrusted npm Install/Postinstall Scripts"
    match_any:
      - cwe: [CWE-506]
        file_glob: ['**/package.json', '**/Dockerfile*']
    scope: per-component

  - id: unauth-websocket-channel
    title: "Unauthenticated WebSocket Channel"
    match_any:
      - file_glob: ['**/registerWebsocketEvents.*']
        cwe: [CWE-306, CWE-862, CWE-770, CWE-703]
    scope: per-component
```

Match-Prädikate (alle optional, UND innerhalb eines `match_any`-Eintrags):
`cwe[]`, `title_pattern` (regex), `file_glob[]`, `source_check_id[]`, `config_check_id[]`.
`scope`: `cross-component` | `per-component` (Default per-component).
`split_by[]`: zusätzliche Bucket-Dimensionen (z. B. `trust_zone`, `endpoint`) für die
Ausnahmen Severity-Zone/Flow — verhindert Über-Mergen.

Begründung der Tightness: IDOR ist CWE-639 → matcht keine Gruppe → bleibt per_instance.
F-004 (798) / F-001 (922) sind außerhalb der jwt-verification-CWE-Menge → bleiben getrennt.

### A2. Schema — NEU `schemas/consolidation-groups.schema.yaml`
Validiert den Katalog (eindeutige `id`, gültige Regex, bekannte `scope`-Enum). Wired in
den bestehenden Schema-Check der Pipeline (analog zu `source-auth-findings.schema.yaml`).

### A3. Group-Resolver — NEU in `scripts/merge_threats.py`

```python
def _load_consolidation_groups() -> list[dict]: ...   # liest data/consolidation-groups.yaml (cache)
def _match_consolidation_group(t: dict, groups) -> dict | None:
    # erste Regel, deren match_any-Eintrag voll auf (cwe, title, evidence.file,
    # source_check_id, config_check_id) passt. Gibt {id,title,scope,split_by} zurück.
```

`_match_consolidation_group` läuft auf JEDEN Threat (STRIDE- *und* Scanner- *und*
Config-Quelle) — deshalb CWE-/quellen-agnostisch. Das löst den JWT-Cross-CWE-Fall
(F-027 CWE-287, F-028 CWE-345, F-003 CWE-347 → alle `jwt-verification`).

### A4. Konsolidierungs-Pass — NEU `_consolidate_by_group()` (generalisiert `_consolidate_config_checks`)

- Bucket-Key = `(group_id, *split_dims)` wobei `split_dims` aus `scope`/`split_by` folgt
  (`scope: per-component` → + `component_id`; `split_by:[trust_zone]` → + Zone).
- Survivor = höchstes Risiko (Tie → first-seen), exakt wie `_consolidate_config_checks:783`.
- Survivor-Felder (wiederverwendet, Shape ist bewährt — `merge_threats.py:796-799`):
  `instances[]` ({file,line,snippet?, **severity**, **local_id**}), `affected_files[]`,
  `instance_count`, `systemic: true`, `consolidation_group: <id>`.
  - NEU ggü. config: per-Instanz `severity` + `local_id`/`source_scan_ref` mitführen
    (für Instanz-Delta C und per-Instanz-Suppress / FP-Isolation, Ausnahme 6).
- Survivor-Titel = Katalog-`title` (statt `_declassify_config_title` — Titel ist jetzt
  explizit im Katalog deklariert, kein String-Stripping-Raten).
- Survivor-Severity = max der Member-Severities; per-Instanz-Severity bleibt in `instances[]`.
- `mitigation_ids` = Union aller Member-`mitigation_ids` (dedupliziert; Regel B
  konvergiert sie danach). So trägt das eine Finding mehrere Maßnahmen.
- Member ohne Gruppen-Match: unverändert durchreichen (per_instance).

### A5. Verdrahtung in `cmd_collect` (`merge_threats.py:1263-1274`)

```
deduped = _dedupe_exact(flat)
deduped = _dedupe_evidence(deduped)
deduped = _consolidate_config_checks(deduped)     # bleibt (config_check_id)
deduped = _consolidate_by_group(deduped)          # NEU — nach config, vor _group_candidates
all_candidates = _group_candidates(deduped)
```

`_consolidate_config_checks` bleibt als Spezialfall bestehen (oder wird später in
`_consolidate_by_group` mit auto-generierten `config_check_id`-Gruppen aufgehen — nicht
in diesem Schritt, um die config-Tests stabil zu halten).

### A6. Scanner-Anreicherung
`_source_auth_finding_to_threat` (`merge_threats.py:409`) trägt schon `source_check_id`
und `evidence.file/line` — reicht für den Resolver. **Kein** Pflichtfeld im
`source-auth-checks.yaml` nötig; die Gruppenzuordnung ist zentral im Katalog (A1).
(Optionaler Komfort: `consolidation_group:` direkt am Check erlaubt, überschreibt Katalog.)

---

## Regel B — Mitigation-Control-Dedup

### B1. Dedup in `derive_mitigations` (`build_threat_model_yaml.py:634`)

Heute: 1 Eintrag pro **M-ID-String**; gleicher Control-Text unter M-004/M-022 bleibt doppelt.
Neu: nach dem Aufbau der `by_mid`-Tabelle ein Dedup-Pass, der über `_mitigation_fp(m)`
(existiert bereits, `:169`, title-basiert location-stripped) zusammenführt:

- Gruppiere alle Mitigation-Einträge nach `_mitigation_fp`.
- Pro Gruppe: ein kanonischer Survivor (niedrigste M-Nummer für Stabilität), `threat_ids[]`
  = Union, `remediation`/Felder vom risikohöchsten Member.
- Baue `old_mid -> canonical_mid` Remap; wende es auf **alle** Threat-`mitigation_ids[]`
  an (so zeigen IDOR-/XSS-Findings, die getrennt bleiben, gemeinsam auf eine M-NNN).
- Danach optional Renumbering kompakt (M-001..M-NN) wie heute.

Damit: 19× „Enforce object-level authorization" → 1; 7× „Enforce server-side authorization"
→ 1; 6× „Pin base image" → 1; XSS 3× → 1. Findings bleiben unangetastet — reine
Maßnahmen-Konvergenz.

### B2. Reihenfolge
B1 läuft NACH A (Konsolidierung), in `build_threat_model_yaml` beim Ableiten der
Mitigations aus den (bereits konsolidierten) Threats.

---

## Regel C — Instanz-Level-Delta (Regressions-Schutz)

Heute: alles Finding-granular (`_threat_fingerprint :153`, `_fp_str :162`, Set-Diff
`:1194-1196`, Reconciler `:278-343`). Eine konsolidierte 17er-Gruppe wäre EINE ID — ohne C
verlierst du die heute vorhandene Auflösbarkeit pro Stelle.

### C1. Per-Instanz-Fingerprint — NEU `build_threat_model_yaml.py`

```python
def _instance_fingerprints(t: dict) -> list[str]:
    base = _fp_str(t)                       # comp|cwe|title
    insts = t.get("instances")
    if not insts:
        # Singleton-Finding zählt als 1 Instanz an seiner evidence-Stelle
        ev = t.get("evidence") or {}
        return [f"{base}|{ev.get('file','')}:{ev.get('line','')}"]
    return [f"{base}|{i.get('file','')}:{i.get('line','')}" for i in insts]
```

### C2. Changelog erweitern (`:1184-1265`)

- Persistiere zusätzlich `instance_fingerprints[]` (flatten über alle Threats).
- Berechne `added_instances` / `resolved_instances` als Set-Diff der Instanz-FPs
  (analog zu `added_threats`/`resolved_fps :1195-1196`), zusätzlich zum bestehenden
  Finding-Delta (Headline bleibt finding-granular).
- Changelog-Note (`_changelog_note`) bekommt eine Zeile „N/M Instanzen eines systemischen
  Findings neu/behoben", wenn das Finding selbst „unchanged" ist aber Instanzen sich ändern.

### C3. Reconciler instanz-aware (`reconcile_incremental_threats :278`, `_index_resolved_prior :260`)

- Wenn ein Prior-Finding weiter präsent ist (Finding-FP match), diffe seine `instances[]`
  gegen die aktuellen → markiere behobene Instanzen, ohne das ganze Finding als resolved
  zu werten.
- `resolved_prior_findings`-Pfad (`merge_threats.py:1219`) optional um `instance_ref`
  erweitern, damit ein einzeln affirmierter Fix eine Instanz statt das ganze Finding schließt.

### C4. Renderer (`compose_threat_model.py:12918-12938`)
- `instances_card` existiert (Cap 8 + „+N more"). Erweitern: pro Instanz Status-Marker
  (✅ behoben / 🆕 neu / offen) + Severity-Dot, gespeist aus C2/C3.
- Sicherstellen, dass konsolidierte Findings durch diesen Pfad laufen (Check ist bereits
  `t.get("instances")` — generisch, greift automatisch).

---

## Tests

- `tests/test_merge_threats.py`
  - `_match_consolidation_group`: JWT cross-CWE matcht, IDOR (639) matcht NICHT,
    F-004/F-001 matchen NICHT.
  - `_consolidate_by_group`: 17 AUTHZ-008 → 1 survivor mit instance_count=17,
    affected_files, Union der mitigation_ids; per-Instanz-Severity erhalten;
    `split_by:[trust_zone]` trennt korrekt; per_instance-Findings unverändert.
- `tests/test_build_threat_model_yaml.py`
  - `derive_mitigations`-Dedup: zwei M-IDs gleicher `_mitigation_fp` → 1 Eintrag,
    Remap aller `mitigation_ids`, mehrere Threats teilen eine M-NNN.
  - Instanz-Delta: 3 von 17 Instanzen entfernt → `resolved_instances` zeigt 3,
    Finding bleibt present; added_instances bei neuer Stelle.
- `tests/test_compose_threat_model.py`
  - instances_card rendert Status-/Severity-Marker; konsolidiertes Finding zeigt
    „Instances (N)" + Maßnahmen-Liste (≥2 für JWT).
- Schema-Test: `consolidation-groups.schema.yaml` validiert den Katalog.
- Voller Suite-Lauf grün.

## Reihenfolge der Umsetzung

1. A2/A1 Katalog + Schema (deklarativ, kein Verhalten) → Schema-Test.
2. A3/A4 Resolver + `_consolidate_by_group` + A5 Verdrahtung → merge-Tests.
3. B1 Mitigation-Dedup → yaml-Tests.
4. C1–C3 Instanz-Delta + C4 Renderer → delta/compose-Tests.
5. Trockenlauf auf juice-shop; Findings/Mitigations-Zahlen + Changelog-Delta verifizieren.
6. Voller Suite-Lauf, dann Recompose der `threat-model.md` (deterministisch).

## Offene Detailpunkte (vor/ während Umsetzung klären)

- Exakte `config_check_id`-Strings für `dependabot-ecosystems` aus dem echten Run holen
  (Platzhalter DEP-* oben).
- `unauth-websocket-channel`: bewusst `scope: per-component` + file_glob; prüfen ob alle
  drei Findings dieselbe Komponente tragen (realtime-channel) — sonst `cross-component`.
- Entscheiden, ob `_consolidate_config_checks` später in `_consolidate_by_group` aufgeht
  (separater Folge-Schritt, nicht Teil dieses Plans).
