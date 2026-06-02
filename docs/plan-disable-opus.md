# Implementierungsplan: Opus global deaktivieren (Variante B — ODER)

**Status:** Plan, noch nicht umgesetzt. Ergänzt `docs/analysis-disable-opus.md`.
**Precedence:** `disable_opus = (CLI --no-opus) OR (Env APPSEC_DISABLE_OPUS) OR (Org-Profile policy.disable_opus)`.
Niemand kann lockern; jede Quelle kann verschärfen. Kein „force-opus"-Pfad.
**Erfolgskriterium:** Bei aktivem Schalter enthält die emittierte
`.skill-config.json` in **keinem** `*_model`-Feld mehr `opus`, und
`reasoning_model` ist nie `opus`/`opus-cheap` → verify: neuer pytest + manueller
`resolve_config.py --reasoning-model opus --no-opus` JSON-Check.

---

## Architektur in einem Satz
Ein **Clamp** ganz am Ende von `resolve_config.resolve()` zieht jeden
opus-haltigen Wert auf Sonnet. Alle drei Quellen setzen nur dasselbe Bool
`cfg["disable_opus"]`. Damit ist der Schalter nicht umgehbar (läuft nach Env,
`--stride-model`, `--reasoning-model` und Org-Merge).

---

## Schritt 1 — Kern: `scripts/resolve_config.py`

### 1a. CLI-Flag im Parser (`build_parser`, bei den Model/Depth-Flags ~Z. 899)
```python
p.add_argument("--no-opus", action="store_true", dest="no_opus",
               help="Forbid Opus anywhere in the run; downgrade every "
                    "Opus selection to Sonnet (cost/compliance ceiling). "
                    "Also settable org-wide via policy.disable_opus or "
                    "env APPSEC_DISABLE_OPUS=1.")
```

### 1b. Clamp-Funktion (neu, neben den anderen Resolvern ~Z. 470)
```python
_OPUS_TOKEN = "opus"          # matcht "opus", "opus-cheap", "claude-opus-4-7"
_MODEL_FIELDS = (
    "stride_model", "triage_model", "merger_model",
    "architect_model", "orchestrator_model",
    "context_resolver_model", "recon_scanner_model",
    "qa_routine_model", "qa_content_model", "config_scanner_model",
)

def apply_opus_ban(cfg: dict, disable_opus: bool) -> dict:
    """Single, non-bypassable ceiling: rewrite every Opus selection to Sonnet.

    Runs LAST in resolve() — after env overrides, --stride-model,
    --reasoning-model resolution, repo-size auto-switch, and org-profile merge.
    Idempotent and safe when disable_opus is False (no-op).
    """
    cfg["opus_disabled"] = bool(disable_opus)
    if not disable_opus:
        return {}
    patch: dict = {}
    # 1) Tier coercion (drives labels + downstream "is opus?" checks).
    if cfg.get("reasoning_model") in ("opus", "opus-cheap"):
        patch["reasoning_model"] = "sonnet"
    # 2) Field clamp: any *_model carrying an opus token -> sonnet.
    for f in _MODEL_FIELDS:
        v = cfg.get(f)
        if v and _OPUS_TOKEN in str(v).lower():
            patch[f] = "sonnet"
    # 3) Architect: if it was the opus default, it is now sonnet (above);
    #    keep the enabled/disabled state untouched.
    # 4) Labels — make the downgrade visible, not silent.
    base_mode = patch.get("reasoning_model", cfg.get("reasoning_model"))
    patch["reasoning_label"] = (
        f"{base_mode} (no-opus: Opus→Sonnet ceiling active)"
    )
    if cfg.get("architect_review"):
        patch["architect_label"] = "enabled (sonnet, no-opus ceiling)"
    return patch
```

### 1c. Quelle des Bool + Aufruf am Ende von `resolve()` (nach `_apply_org_profile`, ~Z. 1186, vor `_compute_total_stages`)
```python
disable_opus = bool(
    getattr(ns, "no_opus", False)
    or os.environ.get("APPSEC_DISABLE_OPUS", "").strip().lower()
        in ("1", "true", "yes", "on")
    or cfg.get("disable_opus")              # aus Org-Profile (Schritt 3)
)
cfg.update(apply_opus_ban(cfg, disable_opus))
```
**Reihenfolge zwingend:** *nach* `cfg.update(_apply_org_profile(...))` (liefert
`cfg["disable_opus"]`) und *nach* allen Modell-Resolvern. `_compute_total_stages`
bleibt unberührt (Stage-Zahl hängt nicht am Modell).

### 1d. Anzeige `_format_reasoning_summary` (~Z. 1887)
Eine Zeile früh einschieben, damit die Box das Downgrade zeigt:
```python
if cfg.get("opus_disabled"):
    return f"{cfg.get('reasoning_model','sonnet')}; no-opus ceiling → all Sonnet"
```
(vor der bestehenden `haiku-economy`-Sonderbehandlung).

### 1e. Kein Konflikt mit Auto-Switch
`resolve_default_tier_for_capped_repos` läuft vorher und kann auf
`haiku-economy` schalten — dort ist ohnehin kein Opus. Der Clamp ist danach
idempotent. Nichts zu ändern.

---

## Schritt 2 — Schema: `schemas/org-profile.schema.yaml`

Top-Level hat `additionalProperties: false` → neuer Key muss registriert werden.
Unter `properties:` (z. B. nach `compatibility`) einfügen:
```yaml
  policy:
    type: object
    additionalProperties: false
    properties:
      disable_opus:
        type: boolean
        description: |
          Org-wide ceiling. When true, every Opus model selection in any
          preset/run is downgraded to Sonnet, regardless of CLI flags.
```
Optional zukunftssicher statt Bool: `max_model: {enum: [opus, sonnet, haiku]}`.
Für die jetzige Anforderung reicht `disable_opus` (YAGNI).

Kein neuer semantischer Check in `validate_org_profile.py` nötig — jsonschema
(Draft202012) validiert den Bool. (Nur falls `max_model` gewählt wird, ist die
Enum dort ebenfalls abgedeckt.)

---

## Schritt 3 — Org-Resolver: `scripts/resolve_org_profile.py`

`policy` ist **Profil-Ebene** (nicht Preset) → getrennt von `flatten_preset`
durchreichen. In `resolve()` beim Aufbau des aktiven `base`-Dicts (~Z. 384):
```python
policy = profile.get("policy") or {}
...
"defaults": {**defaults, "disable_opus": bool(policy.get("disable_opus"))},
```
(oder als eigener `base["policy"]`-Block — dann Schritt 4 entsprechend lesen).
Inaktives Profil: `disable_opus` bleibt False (base-Zweig Z. 338–352 unverändert).

---

## Schritt 4 — Merge: `_apply_org_profile` in `resolve_config.py`

Im aktiven Zweig (~Z. 1261, wo `defaults` gelesen wird) durchreichen:
```python
org_block["disable_opus"] = bool(defaults.get("disable_opus"))
```
Damit ist `cfg["disable_opus"]` gesetzt, bevor Schritt 1c es OR-verknüpft.
Inaktives Profil liefert kein `disable_opus` → `cfg.get` = None → harmlos.

---

## Schritt 5 — Doku / Anzeige (Drift-Gates halten sonst nicht)

- `skills/create-threat-model/SKILL-impl.md` — Flag-Tabelle (~Z. 588):
  Zeile `--no-opus` ergänzen; bei `--reasoning-model`/`--architect-model`
  vermerken „wird durch `--no-opus`/`policy.disable_opus` auf Sonnet gedeckelt".
- `AGENTS.md` — Flag-Matrix + `opus-cheap`-Beschreibung um die Decke ergänzen.
- `agents/appsec-architect-reviewer.md` (Z. 56) — Default-`opus`-Satz um
  „außer no-opus aktiv" ergänzen.
- `agents/phases/phase-group-threats.md` (Z. 515) — Merger-Opus-Bedingung:
  Hinweis, dass bei no-opus nie der Opus-Merge-Pfad greift.

(Reine Stringänderungen; die Tests unter `test_reasoning_model_resolution.py`
prüfen Cross-Doc-Konsistenz dieser Begriffe.)

---

## Schritt 6 — Tests

Neu / zu erweitern:
- `tests/test_resolve_config.py`:
  - `--no-opus` + `--reasoning-model opus` → alle drei Modelle `sonnet`,
    `reasoning_model == "sonnet"`.
  - `--no-opus` + default standard → `merger_model == "sonnet"` (statt opus).
  - `--no-opus` + `--architect-review` → `architect_model == "sonnet"`.
  - Env `APPSEC_DISABLE_OPUS=1` ohne Flag → gleiches Ergebnis.
  - Env `APPSEC_STRIDE_MODEL=claude-opus-4-7` + `--no-opus` → `stride_model`
    wird trotz Env-Override auf `sonnet` gedeckelt (beweist „Clamp läuft nach Env").
  - Ohne Schalter → unverändert (Idempotenz/No-op).
- Org-Profile-Tests (Fixture + Resolver):
  - Fixture-Profil mit `policy: {disable_opus: true}` → `cfg["disable_opus"]`
    True → Modelle gedeckelt, auch ohne CLI-Flag.
  - Schema akzeptiert `policy.disable_opus`; unbekannter Key unter `policy`
    schlägt fehl (additionalProperties:false).
- `tests/test_haiku_routing_per_depth.py` — sicherstellen, dass extended-Agenten
  (per Env auf opus gesetzt) ebenfalls gedeckelt werden (Feld-Liste deckt sie ab).

---

## Aufwand & Risiko
- Logik: ~40 Zeilen in 1 Script + 1 Resolver-Zeile + 1 Merge-Zeile + Schemablock.
- Rest: Doku-Strings + Tests.
- Risiko niedrig: additiv, ein zentraler idempotenter Clamp, kein Eingriff in
  Dispatch-/Renderer-Pfad. Hauptfehlerquelle wäre **Reihenfolge** (Clamp muss
  letzter Modell-Schritt sein) — durch den Platz nach `_apply_org_profile`
  abgedeckt und durch den Env-Override-Test abgesichert.

## Was Variante A zusätzlich bräuchte (nur falls später gewünscht)
Hartes Fail-loud statt stiller Deckelung: in `resolve()` *vor* dem Clamp prüfen
`if disable_opus and ns.reasoning_model in ("opus","opus-cheap"): raise SystemExit(...)`.
Für „Firma blockt Opus" nicht nötig — B deckelt bereits nicht-umgehbar.
