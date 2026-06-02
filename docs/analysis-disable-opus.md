# Analyse: Opus global deaktivieren → Sonnet-Fallback

**Status:** Nur Analyse, keine Implementierung. Stand 2026-06-02.

**Ziel:** Ein Schalter, der erzwingt, dass **überall, wo im normalen Lauf Opus
gewählt würde, stattdessen Sonnet** verwendet wird — über
(1) einen expliziten Parameter (CLI/Env) und (2) die Org-Schema-Config.

---

## 1. Wo Opus heute überhaupt entstehen kann

Architektonisch wichtig: Die Modell-Strings (`opus` / `sonnet` / `haiku` bzw.
voll `claude-opus-4-7`) werden **direkt** als `model`-Parameter an den Agent-
Tool-Dispatch durchgereicht (SKILL-impl.md: „pass the `model` field explicitly").
Es gibt **keine** zwischengeschaltete ID-Auflösungsschicht im Dispatch-Pfad —
`render_completion_summary.py` mappt `opus→opus-4-7` etc. nur fürs **Anzeigen**.

`scripts/resolve_config.py` ist der **einzige** Ort, der alle modellführenden
Felder der `.skill-config.json` erzeugt. Opus kann nur in genau diesen Feldern
auftauchen:

| Feld | Quelle in resolve_config.py | Opus-Pfad |
|---|---|---|
| `stride_model` | `resolve_reasoning_model` via `MODEL_MATRIX` | nur Tier `opus` (Z. 57–61) |
| `triage_model` | dito | nur Tier `opus` |
| `merger_model` | dito | Tier `opus-cheap` **und** `opus` (Z. 48–61) → **Default bei standard/thorough!** |
| `architect_model` | `resolve_architect_review` | Default `opus` wenn Stage 4 an (Z. 646–657) |
| `*_model` (extended/orchestrator) | `resolve_extended_models` | nie Opus per Default; aber per `APPSEC_*_MODEL`-Env überschreibbar |

Zusätzliche Eintrittspfade, die der Schalter mit abdecken muss:
- **Env-Overrides** `APPSEC_STRIDE_MODEL` / `_TRIAGE_` / `_MERGER_` / `_ARCHITECT_`
  / `_ORCHESTRATOR_` / `_CONTEXT_RESOLVER_` / `_RECON_SCANNER_` / `_QA_*` / `_CONFIG_SCANNER_`
  (alle in `resolve_reasoning_model` / `resolve_extended_models` / `resolve_architect_review`)
  können beliebig `opus`/`claude-opus-4-7` einsetzen.
- **`--stride-model <model>`** (punktueller Override, Z. 447–449).
- **`--reasoning-model opus|opus-cheap`** (explizite User-Wahl des Tiers).

Hartcodierte `model: haiku` (Evidence-/Abuse-Case-Verifier in
`phase-group-threats.md`) sind irrelevant — kein Opus.

### Konsequenz fürs Design
Weil **alle** Opus-Werte durch genau vier Felder fließen und alle in `resolve()`
final zusammenlaufen, genügt **ein einziger Clamp am Ende von `resolve()`** als
„Modell-Decke". Er muss **nach** allen Resolvern (inkl. Env-Overrides und
Org-Profile-Merge) laufen, damit ihn nichts umgehen kann.

---

## 2. Mechanismus (1): Expliziter Parameter

### Empfehlung: `--no-opus` (Bool) + Env `APPSEC_DISABLE_OPUS=1`

- CLI-Flag `--no-opus` (store_true) im Parser (`build_parser`).
- Env-Spiegel `APPSEC_DISABLE_OPUS` (truthy: `1/true/yes/on`) — für CI/Org-Shells,
  die ohne argv-Eingriff erzwingen wollen (z. B. wenn das Unternehmen Opus aus
  Kostengründen sperrt).
- Beide setzen ein internes `disable_opus = True`.

Alternative/erweiterbar: `--max-model {opus,sonnet,haiku}` als allgemeine
„Modell-Decke". `--no-opus` ist dann exakt `--max-model sonnet`. Für die jetzige
Anforderung (nur Opus→Sonnet) ist das Bool-Flag das einfachere, ausreichende
Mittel; `--max-model` nur bauen, wenn auch eine Haiku-Decke absehbar gebraucht
wird (YAGNI).

### Der Clamp (konzeptuell, am Ende von `resolve()`)
```
if disable_opus:
    # 1) Tier-Coercion: explizite/Default-Tiers herunterziehen
    #    "opus"       -> "sonnet"
    #    "opus-cheap" -> "sonnet"   (merger wäre sonst Opus)
    # 2) Feld-Clamp: jedes *_model-Feld, das "opus" enthält
    #    (kurz "opus" ODER voll "claude-opus-4-7"), -> "sonnet"
    #    betrifft: stride_model, triage_model, merger_model,
    #              architect_model, orchestrator_model, *_model (extended)
    # 3) Labels neu setzen: reasoning_label / architect_label so umschreiben,
    #    dass das Downgrade sichtbar ist (z. B. "opus-cheap→sonnet (no-opus)")
    cfg["opus_disabled"] = True
```
Matching über Substring `"opus"` deckt Kurz- und Voll-IDs sowie beide Tiers ab.

### Warum am Ende, nicht in den Resolvern
Env-Overrides und `--stride-model` werden **innerhalb** der Resolver angewandt;
das Org-Profile wird via `_apply_org_profile` **danach** gemerged. Nur ein Clamp
ganz am Schluss ist eine echte, nicht umgehbare Decke. (Bonus: der bestehende
Auto-Switch `resolve_default_tier_for_capped_repos` schaltet ohnehin schon auf
`haiku-economy` — kollidiert nicht, da dort kein Opus mehr übrig ist.)

---

## 3. Mechanismus (2): Org-Schema-Config

### Ausgangslage
`schemas/org-profile.schema.yaml` kennt **heute keinerlei** Modell-/Reasoning-Key.
Presets erlauben nur `base_mode` + `target/outputs/scan/requirements/quality/
verification/guardrails`. Modellwahl läuft bisher ausschließlich über
`base_mode` + CLI-Flags. Es gibt also nichts zu „überschreiben", sondern ein
neues Feld einzuführen.

### Empfehlung: org-weite Policy, nicht pro-Preset
Da der Use-Case „Unternehmen sperrt Opus" **global** gilt, gehört der Schalter
auf **Profil-Ebene** (eine `policy:`-Sektion), nicht in jedes Preset:

```yaml
# org-profile.yaml (neu)
organization: { id: ..., name: ..., profile_version: ... }
policy:
  disable_opus: true          # alle Presets, alle Läufe → kein Opus
default_preset: ...
presets: { ... }
```
(Variante, falls feinere Steuerung gewünscht: `policy.max_model: sonnet`
analog zum CLI `--max-model`.)

### Datenfluss (drei kleine Erweiterungen)
1. **`schemas/org-profile.schema.yaml`**: optionales `policy`-Objekt mit
   `disable_opus: bool` (bzw. `max_model: enum[opus,sonnet,haiku]`).
   `scripts/validate_org_profile.py` muss den Key kennen/validieren.
2. **`scripts/resolve_org_profile.py`**: in `resolve()` das `policy`-Objekt
   auslesen und in `effective` mitführen (z. B. `base["defaults"]["disable_opus"]`
   oder eigener `policy`-Block). `flatten_preset` hat heute keine Modellfelder —
   `disable_opus` ist Profil- (nicht Preset-)Ebene, also separat durchreichen.
3. **`scripts/resolve_config.py` → `_apply_org_profile`**: den Wert in `cfg`
   übernehmen (`cfg["disable_opus"] = ... or defaults.get("disable_opus")`).
   Der Clamp aus §2 liest dann `cfg["disable_opus"]` — **identische Logik**,
   nur andere Quelle.

So teilen sich CLI/Env und Org-Profile **denselben** Clamp; nur die Herkunft
des Bool unterscheidet sich.

---

## 4. Precedence — Designentscheidung (offen)

Standard im Codebase: „direkter CLI-Flag gewinnt, Org-Profile füllt nur Lücken".
Für eine **Kosten-/Compliance-Sperre** ist das aber oft falsch herum — die Org
will eine **harte Decke**, die der einzelne Nutzer nicht per `--reasoning-model
opus` aushebeln kann.

Zwei saubere Optionen (bewusst zu entscheiden, nicht still wählen):

- **A — Org als harte Decke (empfohlen für „Unternehmen blockt Opus"):**
  `disable_opus` aus dem Org-Profile gewinnt **immer**. Eine explizite
  `--reasoning-model opus` schlägt fehl bzw. wird mit Hinweis auf Sonnet
  heruntergezogen. CLI `--no-opus` kann zusätzlich ad hoc verschärfen, aber nie
  lockern.
- **B — ODER-Verknüpfung (lockerer):** `disable_opus = CLI/Env OR Org-Policy`.
  Niemand kann die Sperre aufheben, aber es gibt auch keinen „force-opus"-Pfad.
  Einfachste Semantik, deckt den genannten Use-Case vollständig ab.

Für die reine Anforderung („überall Sonnet statt Opus") ist **B** die kleinste
korrekte Lösung. **A** nur nötig, wenn es einen legitimen User-Opus-Pfad gibt,
den die Org überstimmen muss.

---

## 5. Betroffene Stellen (Implementierungs-Surface, falls später umgesetzt)

Kern (Pflicht):
- `scripts/resolve_config.py` — Flag `--no-opus` + Env-Read + **Clamp** am Ende
  von `resolve()` + Label-Anpassung in `_format_reasoning_summary` /
  `resolve_architect_review`.
- `schemas/org-profile.schema.yaml` + `scripts/validate_org_profile.py` —
  `policy.disable_opus`.
- `scripts/resolve_org_profile.py` — Policy auslesen + durchreichen.

Doku/Anzeige (Konsistenz, sonst brechen Drift-Tests):
- `skills/create-threat-model/SKILL-impl.md` — Flag-Tabelle (Z. ~588, ~595),
  Default-Beschreibungen `opus-cheap`/`architect=opus`.
- `agents/appsec-architect-reviewer.md` (Z. 56), `agents/phases/phase-group-threats.md`
  (Z. 515 Merger-Bedingung), `phase-group-finalization.md` (Anzeige).
- `AGENTS.md` (beschreibt Flag-Matrix + `opus-cheap`).

Tests (würden neue Erwartungen brauchen):
- `tests/test_resolve_config.py`, `tests/test_reasoning_model_resolution.py`,
  `tests/test_haiku_routing_per_depth.py` (Env-Override-Matrix),
  Org-Profile-Tests unter `tests/` + Fixtures `tests/fixtures/org-profiles/`.

---

## 6. Kurzfazit

- **Ein** Chokepoint genügt: ein Clamp am Ende von `resolve_config.resolve()`,
  der jeden `opus`-haltigen Modellwert + die Tiers `opus`/`opus-cheap` auf
  `sonnet` zieht. Nachgelagert zu Env/CLI/Org → nicht umgehbar.
- **(1)** Expliziter Parameter: `--no-opus` (+ Env `APPSEC_DISABLE_OPUS`).
  Optional generalisierbar zu `--max-model sonnet`.
- **(2)** Org-Schema: neues optionales `policy.disable_opus` auf Profil-Ebene,
  validiert + via `resolve_org_profile` → `_apply_org_profile` in denselben Clamp.
- **Offene Entscheidung:** Precedence — Org als harte Decke (A) vs. einfaches
  ODER (B). Für den genannten Use-Case reicht B.
- Aufwand klein und lokal; das meiste „Surface" sind Doku-/Anzeige-Strings und
  Tests, nicht Logik.
