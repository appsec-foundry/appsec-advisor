# Finding-Consolidation — Verbesserungen & verifizierte Befunde (2026-06-26)

Investigation ausgelöst durch die Beobachtung, dass ein `--standard`-Scan von
OWASP Juice Shop 94 Findings produzierte (Sonnet-Merger) gegenüber 78 bei
`--thorough` (Opus-Merger) — Verdacht auf unzureichende Konsolidierung. Ziel war
es, **generelle** Konsolidierungsregeln abzuleiten, nicht scan-spezifisch zu
overfitten.

Alle Zahlen unten wurden gegen das **korrekte Merge-Zeit-Artefakt**
(`.threats-merged.json`, dict-shaped `evidence`, `component_id` gefüllt) gemessen,
nicht gegen das finale komponierte YAML.

## Strukturelle Ursache der Duplikation

Der Scan fächert **per-Komponente × per-STRIDE** auf. Ein geteiltes Code-Objekt
(z.B. der RSA-Key in `lib/insecurity.ts:21`) wird dadurch unter mehreren
STRIDE-Linsen analysiert und tritt als N Findings mit verschiedenen CWEs auf. Der
Dedup-Layer keyte bisher auf `(CWE, STRIDE)` und `(/api-endpoint, cwe_family)` —
keiner fängt „gleiches Objekt, andere Linse".

## Umgesetzt (verifiziert, getestet)

### 1. Katalog-Regeln (`data/consolidation-groups.yaml`)
Vier neue Gruppen, 6 → 10:
- `missing-audit-logging` (CWE-778/223, cross-component) — 5 → 1
- `absent-dependency-tooling` (CWE-1104/937 + Tooling-Keywords, cross-component) — 4 → 1
- `ci-workflow-supply-chain` (CWE-829/1357 + Pin-Keywords, per-component) — 2 → 1
- `xss-per-component` (CWE-79/80, per-component) — kehrt bewusst die frühere
  „alle XSS getrennt"-Policy um: Same-Component-XSS teilt einen Root-Cause; jeder
  Sink bleibt als `instances[]`. Cross-Component-XSS bleibt getrennt.

Effekt Thorough-Scan: 78 → 71. Bei Standard größer (Sonnet konsolidiert weniger
vor). **Nicht** konsolidiert: CWE-798 Hardcoded Secrets (RSA/HMAC/CI-Creds =
verschiedene Fix-Owner, Critical nicht unter Niedrigeres begraben).

### 2. Family-keyed Evidence-Dedup (`merge_threats.py`)
`_evidence_identity_key` keyt jetzt auf die **Exploitation-Familie** (`_cwe_family`)
statt der exakten CWE, mit `other`→CWE-Fallback. Damit reunifiziert dasselbe
Objekt unter Geschwister-CWEs:
- RSA-Key: CWE-321 (Spoofing) + CWE-798 (Information Disclosure) → 1 Finding
- MD5: CWE-327 + CWE-328 (CWE-328 zur crypto-Familie ergänzt) → 1 Finding

`other`-Familie behält den konservativen exakt-CWE-Guard, sodass `Dockerfile:1`-
/`ci.yml:1`-Platzhalter getrennt bleiben (verifiziert gegen **alle** Same-Line-
Paare des Scans: 0 Falsch-Merges). Abgeworfene CWE wird in `merged_cwes` für
Nachvollziehbarkeit festgehalten.

Effekt: 78 → 76 vor Katalog-Konsolidierung; **Criticals 10 → 9** (RSA-Doppel-
zählung entfernt).

### 3. Fix: GE--Apply-Bug (`merge_threats.py`)
`_apply_decisions` rekonstruierte Gruppen nur über `(CWE,STRIDE)` → `G-`-IDs.
Merge-Entscheidungen des Sekundärpasses (`GE-`-Endpoint-Gruppen, RC.G.2) liefen
auf `gid_to_key.get("GE-…") → None → continue` und wurden **stillschweigend
verworfen** — der gesamte Sekundärpass war im Apply-Pfad tot.

Bewiesen mit synthetischer GE--Gruppe: Merge-Entscheidung 2→2 (verworfen) vs.
G--Kontrolle 2→1 (funktioniert). Auf dem Juice-Shop-Scan **schlafend** (0 GE--
Gruppen erzeugt), aber real, sobald der Endpoint-Pass feuert.

Fix: neuer Helper `_reconstruct_group_member_indices` baut die
`{group_id: member_indices}`-Map für **beide** Pässe (`G-` und `GE-`) nach —
exakt gespiegelt von `_group_candidates`. Trägt auch einen künftigen `LC-`-Pass.

## Verifikations-Korrekturen (Befunde, die sich als falsch erwiesen)

Festgehalten, weil sie zukünftige Analysen vor denselben Fehlern bewahren:

- **„component_id ist unzuverlässig/leer" → FALSCH.** `component_id` ist zur
  Merge-Zeit vollständig gefüllt (78/78 in `.threats-merged.json`, 9 Komponenten).
  Leer ist er nur im *finalen komponierten* YAML — nach der Konsolidierung,
  irrelevant fürs Mergen. **Lehre:** Konsolidierungs-Verhalten immer gegen
  `.threats-merged.json` messen, nie gegen `threat-model.yaml`.
- **„evidence ist eine Liste, file_glob-Regeln sind tot" → FALSCH.** `evidence`
  ist zur Merge-Zeit ein Dict; erst die Komposition wandelt es in eine Liste.
- **„zweiter Defekt: /user/login-Paar bildet fälschlich keine GE--Gruppe" →
  FALSCH.** Korrektes Verhalten: die beiden Threats haben unterschiedliche
  Familien (other vs authn) und unterschiedlichen `eps[0]`.

## Offen (vorgeschlagen, NICHT umgesetzt)

- **Regel 2 — Allowlist→Default-Flip.** Statt Konsolidierung nur bei Treffer in
  einer handgelisteten CWE-Gruppe: Default = ≥2 Findings mit gleicher
  (CWE, Komponente) → systemic, mit kleiner Ausschluss-Denylist für Klassen, wo
  jeder Sink einzeln angreifbar ist (Injection: 89/79/94/78/22/611). Generalisiert
  auf CWEs, die der Katalog nie vorgesehen hat — der größte Hebel gegen das
  Standard-Mode-Aufblähen. Ungeprüft, größerer Design-Eingriff.
- **Regel 4 — Severity-Spread-Guard.** Eine Konsolidierungsgruppe, die Critical +
  Niedrigeres spannt, darf das Critical nicht als Instanz verschwinden lassen.
  Vorsorglich; in den untersuchten Scans nicht ausgelöst.
- **Vollwertiger agent-adjudizierter `LC-`-Location-Pass.** Der deterministische
  Family-Dedup (#2) deckt den hochsicheren Fall ab. Ein additiver `LC-`-Kandidaten-
  pass (file:line, Zeile>1, distinct CWE/STRIDE → an den Merger-Agent) würde auch
  unsichere Co-Location-Paare abdecken. Der Apply-Pfad ist dafür jetzt vorbereitet
  (siehe #3).
