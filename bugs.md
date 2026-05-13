# Bug-Report — appsec-advisor (kompletter Repo-Scan)

**Stand:** 2026-05-13
**Branch:** main
**Methodik:** 6 parallele Audit-Agents (Subprocess, Path-Traversal, Deserialisierung, Concurrency, Schema, Crash/Logic). Jeder Kandidat anschließend am realen Source geöffnet, Eingabe-Provenance verfolgt, Exploitability empirisch geprüft (u.a. argparse-Verhalten mit `-`-Präfix getestet).

**Trust-Boundary aus SECURITY.md:** Plugin scannt potenziell *nicht-vertrauenswürdige* Target-Repos. Bundled `data/`/`schemas/` ist vertrauenswürdig; LLM-Output und Repo-Inhalte sind es nicht.

---

## P0 – Critical

### 1. TOCTOU-Race in `acquire_lock.py` — zwei Prozesse können denselben Lock halten

**Datei:** `scripts/acquire_lock.py:377–415`

```python
state, info = _classify_lock(lock_path)   # READ
if state == "fresh":
    return 1                              # blocked
...                                        # reap branches
_write_lock(lock_path, os.getpid(), int(time.time()))  # WRITE
```

Zwischen Klassifikation und `_write_lock` existiert kein `O_CREAT|O_EXCL`-atomarer Create. Zwei concurrente Aufrufe sehen beide `state == "absent"` (oder beide reapen denselben hung/dead-Lock), beide schreiben ihre PID, der zweite Rename gewinnt. Beide glauben den Lock zu halten — Heartbeats clobbern sich, Pipeline-State wird parallel mutiert.

**Verifiziert:** keine `flock(2)`/`open(O_EXCL)` im Pfad.

**Fix-Skizze:** `os.open(path, O_CREAT|O_EXCL|O_WRONLY)` mit Fallback auf Stale-Reap.

---

## P1 – Problematisch

### 2. Path-Traversal in `dep_scan.py` über `--manifests`

**Datei:** `scripts/dep_scan.py:448–450`

```python
p = (repo_root / entry).resolve() if not Path(entry).is_absolute() else Path(entry)
if p.exists():
    items.append(p)
```

`entry` stammt aus dem komma-separierten `--manifests`-CLI-Arg (Z.463). Aufrufer in `agents/phases/phase-group-recon.md:165–168` setzt `--manifests "$MANIFESTS"` aus der **vom Recon-Agent (LLM) gelieferten Liste** — also aus Target-Repo-Inhalten ableitbar.

Kein `relative_to(repo_root)`-Check nach `resolve()`. Ein bösartiges Target-Repo, das den Recon-Agent dazu bringt `../../etc/passwd` zu emittieren, führt zu beliebigem File-Read (Datei wird in `_hashes_for` → `_md5_hash` → `path.open("rb")` gelesen). Der MD5 landet in `.dep-scan.json`. Content-Exfil ist limitiert, aber die Datei *wird* gelesen — und absolute Pfade werden explizit *passthrough* akzeptiert.

Vergleichs-Pattern korrekt umgesetzt in `apply_content_repair.py:179–187`.

**Fix-Skizze:** nach `resolve()` ein `candidate.relative_to(repo_root)` mit `ValueError`-Raise, plus Absolute-Pfade ablehnen.

---

### 3. Git-Ref f-string-Interpolation — Option-Injection-Latenz

**Dateien:**
- `scripts/security_relevance_filter.py:374, 397, 571, 678` (`f"{baseline_sha}..HEAD"` und `f"{ref}:{file_path}"`)
- `scripts/baseline_state.py:536` (`f"{base_ref}..HEAD"`)

Werte werden ohne Validierung in den ersten Rev-Argument-Slot interpoliert; `--` zur Option-Terminierung steht erst *nach* dem Rev.

Empirisch getestet (Python 3):
```
--baseline-sha --output=/tmp/x     → argparse error: expected one argument
--baseline-sha=--output=/tmp/x     → akzeptiert, value='--output=/tmp/x'
```

Alle aktuellen Aufrufer (`run-headless.sh:370`, `appsec-threat-analyst.md:179`) verwenden Space-Form, sodass die Lücke **derzeit nicht direkt exploitable** ist. Aber: jede zukünftige Equals-Form-Konstruktion (z.B. wenn ein Skill Args programmatisch zusammenbaut) öffnet sie wieder.

Gefährliche Git-Optionen, die so erreichbar wären: `--output=PATH` (File-Overwrite-Primitive), `--ext-diff` (External-Diff-Driver aus `.gitattributes`).

**Fix-Skizze:** Ref-Regex `^[A-Za-z0-9_/.\-]+$` validieren UND `--end-of-options` (git ≥2.24) oder explizit `git rev-parse --verify` vor Nutzung.

---

### 4. Eval-Sandbox-Escape via Regex-Whitelist

**Dateien:**
- `scripts/compose_threat_model.py:342, 355–363`
- `scripts/qa_checks.py:1110–1114`

```python
_COND_SAFE_TOKENS = re.compile(r"^[\sA-Za-z0-9_\.\(\)\[\]'\",<>=!&|+\-]*$")
...
return bool(eval(expr, {"__builtins__": {}}, locals_))  # noqa: S307
```

Die Regex erlaubt `( ) [ ] . ' " ,` — und damit den klassischen Python-Sandbox-Escape:

```python
(1).__class__.__bases__[0].__subclasses__()
```

`__builtins__={}` blockt nur Globals-Lookups, **nicht** Attribut-Access auf existierende Objekte. Über `__subclasses__()` lassen sich `subprocess.Popen` o.ä. erreichen.

`expr` stammt aus `data/sections-contract.yaml` (bundled, Z.58 `DEFAULT_CONTRACT`). Es gibt jedoch ein `--contract`-CLI-Flag (Z.6386), das den Trust-Path bricht, falls der Aufrufer einen externen Contract liefert.

**Fix-Skizze:** Statt Regex-Whitelist auf String-Ebene besser AST-Whitelist (`ast.parse(expr, mode="eval")` und Node-Typen prüfen) oder `simpleeval`-Library.

---

### 5. Lost-Update Race in `agent_logger.py` (`.session-agent-map`)

**Datei:** `scripts/agent_logger.py:393–423`

```python
lines = []
if os.path.exists(map_file):
    with open(map_file) as fh:
        lines = fh.readlines()[-20:]
lines.append(f"{sid}={agent}\n")
fd, tmp_path = tempfile.mkstemp(...)
with os.fdopen(fd, "w") as fh:
    fh.writelines(lines[-20:])
os.replace(tmp_path, map_file)
```

Klassisches Read-Modify-Write ohne Lock. Zwei parallele PreToolUse-Hooks lesen denselben Stand, appendieren je eine eigene Zeile, der zweite Rename überschreibt den ersten. Folge: ein Session→Agent-Mapping geht verloren → falsche Attribution beim SESSION_STOP-Summary.

Tritt zuverlässig auf, sobald ≥2 Subagents parallel laufen (im Phase-Pipeline der Normalfall).

Der Docstring (Z.394–397) behauptet, der atomare Write schütze gegen parallele Schreiber — das stimmt nur für Datei-Korruption, nicht für Lost-Updates.

**Fix-Skizze:** Append-Open mit `O_APPEND` (atomar bis PIPE_BUF) statt RMW; oder `fcntl.flock` um die ganze Operation.

---

### 6. `merge_threats._apply_decisions` — Empty `keep_indices` löscht still alle Gruppenmitglieder

**Datei:** `scripts/merge_threats.py:429–435`

```python
elif action == "keep":
    keep_positions = d.get("keep_indices")
    if not isinstance(keep_positions, list):
        continue
    for pos, idx in enumerate(member_indices):
        if pos not in keep_positions:
            drop.add(idx)
```

Docstring (Z.381–384) behauptet *"safe-by-default: every threat survives"* bei malformed decisions. Realität: `keep_indices: []` ist ein gültiger leerer List-Wert → der Guard greift nicht → alle Group-Member werden gedroppt.

LLM-generierte `.merge-decisions.json` ist Trust-relevant (Prompt-Injection-Vektor laut SECURITY.md).

**Fix-Skizze:** zusätzlich `if not keep_positions: continue` oder explizites Min-Survivor-Invariant.

---

## P2 – Minor / Härtung

### 7. Edge-case `coverage_checks.py:436–444`

`_load_merged_threats` toleriert `data.get("threats", [])` über einen String-Wert (`"null"` statt `null` im JSON). Anschließend iteriert Code über Zeichen einzeln. Edge-Case, nicht praktisch exploitable.

**Hinweis:** Der ursprüngliche Audit-Befund („silent OWASP-False-Negatives") war fehlinterpretiert — eine leere Threat-Liste produziert *mehr* Gaps, nicht weniger. Failure-Mode ist lautstark, nicht silent.

---

### 8. `xml.etree.ElementTree.fromstring(pom.xml)` ohne defusedxml

**Datei:** `scripts/compose_threat_model.py:1340–1341`

Python-Doku warnt explizit vor untrusted XML in `xml.etree`. Realistisch nur DoS (Billion-Laughs); XXE im modernen Python-Default i.d.R. nicht resolved. ParseError wird abgefangen → graceful.

**Fix-Skizze:** Drop-in-Replace mit `defusedxml.ElementTree`.

---

### 9. `shutil.rmtree(.progress, ignore_errors=True)` Race

**Datei:** `scripts/acquire_lock.py:143–146`

Wird nur unter `--reset-dirs` (Schritt 7, nach Lock-Hold) aufgerufen — andere Schreiber im normalen Flow nicht vorhanden. Edge-Case.

---

### 10. Wall-Clock-Staleness ohne `time.monotonic()`

**Datei:** `scripts/acquire_lock.py:254, 274, 286`

Bei NTP-Rückwärtssprung kann ein stale Lock als „fresh" eingestuft werden → blockiert neuen Run. Selten realistisch (Rückwärtssprünge sind im NTP-Default verboten/gedämpft). Heartbeat-Wert wird selbst in Wall-Clock geschrieben, also intern konsistent.

---

### 11. `apply_content_repair._validate_plan` enforced kein `additionalProperties: false`

**Datei:** `scripts/apply_content_repair.py:134–167`

Extra-Felder im Plan werden ignoriert; aktuelle Op-Handler greifen nicht auf unbekannte Felder zu. Future-Compat-Risiko, kein direkter Bug.

---

### 12. Datei-Handle ohne Context-Manager

**Datei:** `scripts/agent_logger.py:759`

```python
owner_sid = open(owner_path, encoding="utf-8").read().strip()
```

Unter CPython-Refcount sofort geschlossen, kosmetisch. Unter PyPy oder bei festgehaltenen Refs Leak.

---

### 13. `run-headless.sh` — ungequotete `$BASE_REF`/`$OUTPUT_PATH` in CHECK_ARGS

**Datei:** `scripts/run-headless.sh:368, 370, 373`

```sh
CHECK_ARGS="check-changes --output-dir $OUTPUT_PATH --repo-root $REPO_PATH"
if [ -n "$BASE_REF" ]; then
    CHECK_ARGS="$CHECK_ARGS --base-ref $BASE_REF"
fi
FAST_PATH_OUTPUT="$(python3 ... $CHECK_ARGS ...)"
```

Pfade/Refs mit Leerzeichen brechen das Word-Splitting. Robustness, kein Security-Issue (User kontrolliert seinen eigenen CLI-Aufruf).

---

## False Positives / Befunde der Audit-Agents, die ich verworfen habe

- **Git-Ref-Injection als „CRITICAL" gemeldet:** überstated — durch argparse-Space-Form-Rejection aktuell nicht direkt exploitable; herabgestuft auf #3 (Härtung).
- **Path-Traversal in `dep_scan.py` als „CRITICAL":** Schritt-2 stimmt, aber Impact ist „Datei wird gemd5sumt", nicht „Content exfiltriert" → P1 statt P0.
- **Eval-Calls als FP eingestuft:** falsch — Regex-Whitelist erlaubt `__class__`-Escape; korrigiert in #4.
- **`coverage_checks.py` „Critical: silent OWASP-False-Negatives":** falsch — leere Threat-Liste produziert MEHR Gaps, nicht weniger.
- **`agent_logger.py:759` Resource-Leak als „problematic":** unter CPython-Refcount harmlos; herabgestuft.
- **Jinja `autoescape=False`:** intentional (Markdown-Output, Templates bundled) → FP.
- **`harvest-requirements.py verify_ssl`:** admin-controlled Config → FP.

---

## Zusammenfassung

| ID | Datei:Zeile | Klasse | Severity | Direkt exploitable? |
|----|-------------|--------|----------|---------------------|
| 1 | acquire_lock.py:377–415 | TOCTOU-Race | P0 | Ja, bei concurrentem Run |
| 2 | dep_scan.py:448 | Path-Traversal | P1 | Ja, über LLM-Recon-Output |
| 3 | security_relevance_filter.py:374,397,571,678 / baseline_state.py:536 | Git-Option-Injection | P1 | Latent (Equals-Form) |
| 4 | compose_threat_model.py:355 / qa_checks.py:1110 | Eval-Sandbox-Escape | P1 | Latent (`--contract`) |
| 5 | agent_logger.py:393 | Lost-Update Race | P1 | Ja, bei Parallel-Agents |
| 6 | merge_threats.py:429 | Logic – silent threat-drop | P1 | Ja, via LLM-Output |
| 7 | coverage_checks.py:436 | Edge-case `"null"`-String | P2 | Theoretisch |
| 8 | compose_threat_model.py:1340 | XML ohne defusedxml | P2 | DoS only |
| 9 | acquire_lock.py:143 | rmtree-Race | P2 | Edge-Case |
| 10 | acquire_lock.py:254/274/286 | Wall-Clock-Staleness | P2 | Selten |
| 11 | apply_content_repair.py:134 | additionalProperties | P2 | Future-Compat |
| 12 | agent_logger.py:759 | Fehlender Context-Manager | P2 | Kosmetisch |
| 13 | run-headless.sh:368/370/373 | Ungequotete Vars | P2 | Robustness |

---

## Nicht vollständig auditiert

- `compose_threat_model.py` (~7000 Zeilen) — nur Hotspots (eval, XML, Jinja, Contract-Load) geprüft
- `qa_checks.py` (~5200 Zeilen) — nur eval-Stelle geprüft
- `pregenerate_fragments.py` (~3650 Zeilen) — nicht inhaltlich geprüft

In diesen drei Files können noch Logic-Bugs verborgen sein, die der Agent-Audit nicht als „wird unter Normalbetrieb feuern" verifizieren konnte. Falls gezielter Deep-Dive gewünscht: bitte konkrete Phase/Funktion benennen.
