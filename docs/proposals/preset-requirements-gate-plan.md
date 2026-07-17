# Implementierungsplan — Gate-Policy in `preset_requirements` paketierbar machen

**Ziel:** Eine Org soll die Requirements-Gate-Policy (`--gate` an/aus, `--gate-on`,
`--priority-floor`) **pro Preset** im org-profile packen können, statt sie bei
jedem CI-Lauf per CLI mitzugeben. Betrifft **beide** Requirements-Skills
(`verify-requirements` diff-scoped, `audit-security-requirements` full-repo).

Status quo (verifiziert):
- `schemas/org-profile.schema.yaml:394` `preset_requirements` kennt nur `enabled`.
- Beide Skills parsen `gate_mode`/`gate_on`/`priority_floor` **nur aus CLI**,
  Hard-Defaults `false` / `fail` / `MUST`
  (`skills/audit-security-requirements/SKILL.md` Step 1a,
  `skills/verify-requirements/SKILL.md:74-76`).
- `scripts/requirements_gate.py:61-69` nimmt `--priority-floor`/`--gate-on` als Args,
  Default `MUST`/`fail`.
- `resolve_org_profile.flatten_preset()` (`:183-230`) surfaced heute aus dem
  Requirements-Preset nur `check_requirements = requirements.enabled`.
- `resolve_config._apply_org_profile` liest `defaults` selektiv per `.get()` und
  reicht den Blob als `org_profile_defaults` durch → neuer Key ist für
  `create-threat-model` **kein** Regressionsrisiko (verifiziert `:1851-1852`).

---

## Design-Entscheidung (bitte bestätigen)

Zwei Semantiken für die gepackte Gate-Policy:

**A. Default-Seed (empfohlen, v1):** Preset liefert die *Default*-Werte; eine
explizite CLI-Flag überschreibt sie weiterhin. Präzedenz
`CLI > Preset > Hard-Default`. Einfach, spiegelt den Charakter von
`gate_on`/`priority_floor` als Per-Run-Knöpfe, keine neue Sperr-Mechanik.

**B. Governance-Lock (später optional):** zusätzliches `enforce: true`, das —
analog `policy.disable_opus` (OR-kombiniert, nicht abschaltbar) — den Gate
**erzwingt**, sodass ein Entwickler ihn per CLI nicht deaktivieren kann.

→ **Empfehlung: A jetzt umsetzen**, B als dokumentiertes Follow-up vermerken.
Der Plan unten setzt A um.

---

## Contract-Änderung (bidirektional: Producer + Schema + Consumer + Validation + Tests)

### 1. Schema — `schemas/org-profile.schema.yaml`

`$defs/preset_requirements` (aktuell nur `enabled`) erweitern:

```yaml
preset_requirements:
  type: object
  additionalProperties: false
  properties:
    enabled:
      type: boolean
    gate:
      type: object
      additionalProperties: false
      description: |
        Default gate policy for this preset, consumed by both requirements
        skills (verify-requirements, audit-security-requirements). Per-run CLI
        flags (--gate / --gate-on / --priority-floor) still override these.
      properties:
        mode:
          enum: [advisory, enforce]     # advisory = exit 0; enforce = gate (like --gate)
        gate_on:
          enum: [fail, partial]
        priority_floor:
          enum: [MUST, SHOULD, MAY]
```

Keine Pflichtfelder → v1-Profile und Presets ohne `gate` bleiben unverändert
(Verhalten: advisory/fail/MUST). Kein `api_version`-Bump nötig (rein additiv,
optional).

### 2. Producer — `scripts/resolve_org_profile.py`

In `flatten_preset()` (nach `:217 check_requirements`) einen **nested** Block
in `defaults` ergänzen — nur wenn das Preset ihn setzt, sonst `None`, damit die
Skills auf ihre Hard-Defaults zurückfallen:

```python
_gate = (requirements.get("gate") or {})
defaults["requirements_gate"] = {
    "mode": _gate.get("mode"),                 # advisory | enforce | None
    "gate_on": _gate.get("gate_on"),           # fail | partial | None
    "priority_floor": _gate.get("priority_floor"),  # MUST|SHOULD|MAY | None
} if _gate else None
```

Der Key landet in `.org-profile-effective.json` unter `defaults.requirements_gate`.
`create-threat-model` ignoriert ihn (nur `.get()` bekannter Keys).

### 3. Consumer — beide SKILL.md (Step 1a Gate-Resolution)

Beide Skills emittieren bereits `.org-profile-effective.json` via
`resolve_org_profile.py --emit-file` und kennen `$AUDIT_OUTPUT_DIR` /
Output-Dir. **Nach** dem Emit und **vor** dem Gate-Aufruf die Preset-Defaults
lesen und nur dort anwenden, wo die CLI-Flag **nicht** gesetzt wurde:

```bash
EFFECTIVE="$OUTPUT_DIR/.org-profile-effective.json"
if [ -f "$EFFECTIVE" ]; then
  # jeweils nur seed'en, wenn CLI-Flag nicht explizit übergeben wurde
  read PRESET_GATE_MODE PRESET_GATE_ON PRESET_FLOOR < <(python3 - "$EFFECTIVE" <<'PY'
import json,sys
d=(json.load(open(sys.argv[1])).get("defaults") or {}).get("requirements_gate") or {}
print(d.get("mode") or "", d.get("gate_on") or "", d.get("priority_floor") or "")
PY
)
  [ -z "$GATE_ON_SET" ]      && [ -n "$PRESET_GATE_ON" ] && GATE_ON="$PRESET_GATE_ON"
  [ -z "$PRIORITY_FLOOR_SET" ] && [ -n "$PRESET_FLOOR" ] && PRIORITY_FLOOR="$PRESET_FLOOR"
  [ -z "$GATE_MODE_SET" ] && [ "$PRESET_GATE_MODE" = "enforce" ] && GATE_MODE=true
fi
```

Präzedenz-Regel im Prosa-Text beider Step-1a festhalten:
**explizite CLI-Flag > aktives Preset > Hard-Default (advisory / fail / MUST)**.
Die `*_SET`-Marker werden beim CLI-Parsen in Step 1a gesetzt (Prosa-Ergänzung:
„merke dir, ob der Nutzer die Flag explizit übergeben hat").

Optional (empfohlen für Transparenz): im Startup-Banner eine Zeile
`Gate     : enforce · gate-on=partial · floor=SHOULD (from preset ci-standard)`
zeigen, wenn ein Preset die Policy liefert — sonst weglassen.

Gate-Aufruf selbst (`requirements_gate.py "${GATE_ARGS[@]}"`) bleibt unverändert;
er bekommt die bereits aufgelösten Werte.

---

## Dokumentation („alles sauber dokumentieren")

1. **`docs/org-profiles.md`** — im `presets.<name>.requirements`-Abschnitt die
   neuen `gate.{mode,gate_on,priority_floor}`-Felder dokumentieren, inkl.
   Präzedenz (CLI überschreibt) und einem CI-Preset-Beispiel.
2. **`docs/internal-plugin-packaging.md`** — im `ci-standard`-Preset-Beispiel
   (aktuell `:181-186`) einen `gate:`-Block ergänzen und im Fließtext erwähnen,
   dass die Gate-Policy jetzt paketierbar ist (bisher CLI-only).
3. **`docs/security-requirements-audit-skill.md`** — Präzedenz-Kette um „aktives
   Preset liefert Gate-Defaults" ergänzen.
4. **Beide `SKILL.md` `--help`-Blöcke** — bei `--gate/--gate-on/--priority-floor`
   notieren: „Default kann aus dem aktiven Preset stammen; die Flag überschreibt."
5. **`AGENTS.md`** — Editing-Guidance-Tabelle prüfen; falls eine
   org-profile-/requirements-Zeile existiert, auf die neue Gate-Fläche verweisen.
6. **CHANGELOG / `check_release_meta.py`** — Eintrag „preset requirements gate
   policy" (additiv, kein Breaking).

---

## Tests

- **`tests/test_org_profile_schema.py`**: (a) Preset mit gültigem `gate`-Block
  validiert; (b) ungültiges `gate_on: yes` / `priority_floor: HIGH` /
  `mode: block` wird abgelehnt; (c) `additionalProperties` im gate-Block wird
  abgelehnt.
- **`tests/test_resolve_org_profile.py`**: `flatten_preset` surfaced
  `defaults.requirements_gate` korrekt aus einem Preset; Preset ohne gate →
  `requirements_gate is None`.
- **`tests/fixtures/org-profiles/`**: eine Fixture mit CI-Preset (`enforce`,
  `partial`, `SHOULD`) und einem Preset ohne gate.
- **`tests/test_resolve_config_org_profile.py`**: Regressions-Guard —
  `create-threat-model` bleibt unbeeinflusst vom neuen `defaults`-Key (grün).
- Skills sind Prosa → keine Unit-Tests; Präzedenz wird über den
  resolve/flatten-Layer abgedeckt. Bei Bedarf ein kleiner Integrationstest, der
  aus einem Fixture-Profil das effective-JSON emittiert und den Gate-Block prüft.

## `data/required-permissions.yaml`

Kein neuer Bash-Command / Write-Target / Sub-Agent-Dispatch — die Skills rufen
`resolve_org_profile.py`, `requirements_gate.py` etc. bereits auf. **Keine
Änderung** (in der Umsetzung final gegenprüfen).

## Reihenfolge & Verify

1. Schema erweitern → `tests/test_org_profile_schema.py` grün.
2. `flatten_preset` + Fixture → `tests/test_resolve_org_profile.py` grün.
3. Beide SKILL.md Step 1a + `--help` + Präzedenz-Prosa.
4. Docs 1–6.
5. `test_resolve_config_org_profile.py` (Regression) + targeted subset + `make test` / `make lint`.
6. Manueller Smoke: Fixture-Profil mit CI-Preset → `audit-security-requirements --status`
   zeigt Gate-Banner; `--gate-on fail` auf der CLI überschreibt Preset-`partial`.
