# Enterprise-Erweiterbarkeit — was geht, was sinnvoll wäre

Analyse der Konfig-/Hook-/Extension-Fläche aus Unternehmenssicht. Kein Implementierungsauftrag — Grundlage für Priorisierung.

## Leitprinzip: die Trust-Grenze

Jede Erweiterung fällt in genau eine von drei Klassen. Die Klasse entscheidet, ob sie ins Plugin gehört:

| Klasse | Beispiel | Gehört ins Plugin? |
|---|---|---|
| **Deklarative Daten** (Kriterien + Wirkung, kein Code) | Coach-Topics, Gate-Policy, Requirements-Quelle | **Ja** — validiert, auditierbar, kein Fork |
| **Arbitrary Code** (org-Skript läuft auf Event) | eigener PreToolUse-Blocker als Shell | **Nein** — nativ via Claude-Code-Settings/managed |
| **Kern-Semantik** (Severity, CVSS, Agent-Instruktionen) | eigene Severity-Regeln | **Nein, nie** — Kern, konservativ by design |

Alles unten wird an dieser Grenze gemessen.

---

## A. Was heute geht

### Runtime-Config (`org-profile.yaml`) — kein Fork, validiert
- **Presets**: depth, outputs (SARIF/PDF/pentest), scan, quality (QA/architect/walkthroughs/enrichment), verification, guardrails (wall-time, cost-cap, resumes, tracing), **requirements.gate** (mode/gate_on/priority_floor)
- **policy.disable_opus** (org-weite Modell-Decke)
- **branding** (Cover: Titel/Kontakt/Logo)
- **requirements**: Quelle-URL, create-threat-model default-active, standalone_audit-Toggle
- **llm_context**: 1–20 Markdown-Kontextdateien (untrusted data)
- **security_coach**: enabled_by_default, max_requirements_per_topic, **baseline**, **inherit_default_topics**, **topics** (Trigger → Guidance + Requirement-IDs)
- **skill_toggles** (User-Skills soft-disablen)
- **actors** (inherit/disable/add)
- **abuse_cases** (inherit/disable/add)
- **mcp.servers** (eigene SAST/SCA-Endpoints ins gepackte `.mcp.json`)

### Build-time (`package-policy.yaml`) — nur einschränken
- `plugin_surface`: **skills / hooks / mcp_servers** include|exclude. Kann Hooks nur **entfernen**, nicht hinzufügen.

### Nativ in Claude Code — außerhalb des Plugins
- Beliebige Hooks via `.claude/settings.json` (Projekt) oder `/etc/claude-code/managed-settings.json` (org-weit). **Volle Hook-Flexibilität existiert hier bereits.**

### Hook-spezifisch heute
- **security-coach**: voll datengetrieben konfigurierbar (Topics/Baseline/Enabled/Cap). ✅
- **agent-logger**: nur Env (`APPSEC_LOG_REDACT_PATHS`, `APPSEC_TRACING`) + `config.json` (`logging.max_log_bytes/verbose`). Nicht im org-profile, also nicht paketierbar.

---

## B. Was NICHT geht (Lücken)

1. **Eigenen Plugin-Hook / Event-Handler hinzufügen** — package-policy kann nur entfernen. (Bewusst — siehe Trust-Grenze.)
2. **agent-logger als Policy** — Redaction, Retention, Log-Ziel sind Env/config.json, nicht org-profile. Compliance-relevant, aber nicht paketierbar.
3. **Enforcement-Actions** — der Coach kann nur *raten* (Kontext injizieren), nicht *durchsetzen* (Prompt warnen/blocken).
4. **Coach ist profile-level, nicht per-preset** — ein `ci`-Preset kann kein anderes Coaching haben als `release`. `resolve()` emittiert `security_coach` global.
5. **Run-Policy nur in Env, nicht im Profil**: `APPSEC_FAIL_ON` (Severity→Exit), `APPSEC_URL_ALLOWLIST` (SSRF/Exfil-Guard bei Remote-Fetch), Modell-Routing (`APPSEC_*_MODEL`), Parallelität. Sind Policy-tauglich, aber nicht als Preset/Policy paketierbar.

---

## C. Enterprise-Sicht: was ist sinnvoll

Ein Unternehmen will fünf Dinge: **Konsistenz** (jeder Dev, gleiche Regeln), **Compliance** (Audit-Trail, Redaction, Data-Residency), **Governance** (nicht abschaltbar), **Integration** (eigenes SAST/Ticketing), **niedrige Reibung** (CI ohne Per-Dev-Setup).

Bewertung nach Wert × Sicherheit:

| # | Erweiterung | Klasse | Enterprise-Wert | Status |
|---|---|---|---|---|
| 1 | Coach-Topics/Baseline (eigene secure-by-default-Guidance in Firmensprache, auf eigenen Katalog gemappt) | deklarativ | **hoch** | ✅ gebaut |
| 2 | Requirements-Gate pro Preset (CI gated per Policy) | deklarativ | **hoch** | ✅ gebaut |
| 3 | **Run-Policy ins Profil**: `guardrails.fail_on` + `policy.url_allowlist` | deklarativ | **hoch** | ✅ gebaut (Modell-Routing verworfen: Ordering-Falle > Nutzen; `disable_opus` deckt die Kern-Governance) |
| 4 | **agent-logger als Policy**: `logging.redact_paths` + Retention | deklarativ | mittel | offen |
| 5 | Per-Preset-Coach (Preset kann Coach an/aus + Topic-Subset) | deklarativ | mittel–niedrig | offen |
| 6 | **Enforcement-Vokabel**: Coach-Topic `action: warn\|block` | deklarativ (feste Vokabel) | mittel (nur wenn Durchsetzen > Raten) | offen |
| 7 | Beliebige org-Hooks im Plugin | Arbitrary Code | — | **bewusst nein** (nativ nutzen) |
| 8 | Eigene Severity-/CVSS-Policy | Kern-Semantik | — | **nie** |

### Warum #3 der größte offene Hebel ist
`fail_on`, `url_allowlist`, Modell-Routing sind **echte Sicherheits-/Kostenpolitik**, die heute nur als Env-Var existiert — also faktisch **nicht paketierbar** (der Packager kennt keine Env-Injection). Eine Org kann „blocke Findings ≥ High", „erlaube Remote-Fetch nur zu diesen Hosts", „nutze aus Data-Residency-Gründen nur Modell X" nicht ins gebrandete Plugin gießen. Das ist genau die Governance, für die Internal-Packaging existiert.

### Warum #6 mit Vorsicht
Enforcement (Prompt blocken) ist ein realer Enterprise-Wunsch, aber intrusiv und leicht falsch kalibriert. Mit **fester Vokabel** (`inject`=heute / `warn` / `block`) bleibt es deklarativ und auditierbar — kein Arbitrary-Code. Nur bauen, wenn „raten" nachweislich nicht reicht.

---

## D. Empfehlung / Reihenfolge

1. **(erledigt)** Coach-Regeln + Gate-Policy.
2. **#3 Run-Policy ins org-profile** — `guardrails.fail_on`, `policy.url_allowlist`, Modell-Routing. Höchster Governance-Wert, schließt die „Policy steckt in Env fest"-Lücke. Bidirektional wie das Gate (Schema + `resolve_config`/`resolve_org_profile` + `.env`-Emit + Tests).
3. **#4 agent-logger-Compliance** — Redaction/Retention als Policy. Klein, Compliance-Wert.
4. **#6 Enforcement-Vokabel** — nur bei echtem Bedarf.

Nicht bauen: #7 (nativ vorhanden), #8 (Kern).

### Ehrliche Gesamteinschätzung
Die Config-Fläche ist bereits **groß**. Jede weitere Option kostet Doku + Test + kognitive Last. Der klar wertvollste offene Schritt ist **#3** — weil dort echte Policy in einer nicht-paketierbaren Ecke (Env) feststeckt. Der Rest ist inkrementell; #5 und #6 nur auf konkreten Bedarf, nicht auf Vorrat.
