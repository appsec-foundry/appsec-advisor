# Umsetzungsplan — org-eigene Hooks über das Plugin ausrollen

> **Status: umgesetzt** (2026-07-17). Alle Punkte gebaut; Tests grün. Event-Satz
> voll, org-Hooks included-by-default (exclude-bar). Details siehe CHANGELOG.


**Ziel:** Ein Unternehmen deklariert eigene Claude-Code-Hooks im org-profile; der
Packager legt die Skripte + hooks.json-Einträge ins gebrandete Artefakt und
protokolliert sie (org-owned) in `package-surface.json`. Ein zentrales Plugin
enthält alles, volle Flexibilität — ohne die Auditierbarkeit zu opfern.

**Muster:** 1:1 gespiegelt an `mcp.servers` (org-gelieferte ausführbare Fläche,
`${CLAUDE_PLUGIN_ROOT}`-Pfade, im Surface-Manifest geführt, Smoke-Test-verifiziert).

---

## Der Knackpunkt (zuerst, weil er das Design bestimmt)

`package_internal_plugin.py:_hook_id()` **und** `smoke_test_package.py:_hook_id()`
leiten die Hook-ID ausschließlich aus `/scripts/<name>` ab. Org-Hooks unter
`/org-profile/<name>/hooks/` liefern dort `None` → sie sind unsichtbar für:
- `apply_hook_policy` (behält `hook_id is None` bedingungslos, gated nie),
- `write_surface_manifest` (nicht im Manifest),
- den Smoke-Test (`_registered_hook_ids` + `check_surface_manifest`).

**Konsequenz:** Org-Hook-IDs dürfen nicht aus dem Command abgeleitet werden,
sondern kommen aus der **Deklaration** und werden explizit durch alle drei
Schichten getragen. Das ist die Leitentscheidung des Plans.

---

## Deklaration (Schema)

Profil-weiter `hooks:`-Block (nicht preset-scoped), Map `id → {event, command, matcher?}`:

```yaml
hooks:
  block-risky-bash:
    event: PreToolUse
    matcher: Bash                                   # nur PreToolUse/PostToolUse
    command: ${CLAUDE_PLUGIN_ROOT}/org-profile/hooks/guard.py
```

Skripte liegen unter `org-profile/hooks/` — `overlay_org_profile()` kopiert den
Profil-Ordner ohnehin komplett nach `build/org-profile/`.

Schema-Regeln (`schemas/org-profile.schema.yaml`, neuer Top-Level `hooks`):
- `propertyNames` `^[a-z0-9][a-z0-9_-]{0,62}$`, `additionalProperties:false` pro Hook.
- `event`: enum `[UserPromptSubmit, PreToolUse, PostToolUse, Stop, SubagentStop, Notification, SessionStart, SessionEnd, PreCompact]`.
- `command`: string, required. `matcher`: string, optional.
- `maxProperties` (z.B. 32) als Runaway-Backstop.

---

## Contract-Änderungen (bidirektional)

### 1. Schema — `schemas/org-profile.schema.yaml`
Neuer `hooks`-Block wie oben.

### 2. Validation — `scripts/validate_org_profile.py` (neues `_check_hooks`, mirror `_check_mcp`)
Strukturchecks, die JSON-Schema nicht ausdrückt:
- `command` **muss** mit `${CLAUDE_PLUGIN_ROOT}/org-profile/` beginnen (org-Skript
  im Profil-Ordner) — Host-Pfade, absolute Pfade, `..` ablehnen.
- Das aufgelöste Skript **muss existieren** unter dem Profil-Verzeichnis
  (reuse `_resolve_under`, gegen den Pfad-Rest nach `${CLAUDE_PLUGIN_ROOT}/org-profile/`).
- `matcher` nur bei `PreToolUse`/`PostToolUse`.
- ID darf nicht mit den Upstream-IDs kollidieren (`security-coach`, `agent-logger` reserviert).
- In die Doc-Aufzählung oben (`validate_org_profile.py:8-16`) eine Zeile ergänzen.

### 3. Packager — `scripts/package_internal_plugin.py`
- **`_org_profile_hooks(build) -> dict`** — liest `hooks` aus dem overlaid Profil
  (analog `_org_profile_mcp_servers`, `:415`).
- **`apply_hook_policy` erweitern** (`:367`):
  - `available = _available_hook_ids(build) ∪ set(org_hooks)` — org-IDs werden
    Teil der Keep-Menge, damit `plugin_surface.hooks` include/exclude sie **auch
    gated**.
  - Nach dem Filtern der Upstream-Hooks: gekeepte org-Hooks in `filtered_events`
    mergen. Pro Hook ein outer-Eintrag `{matcher?, hooks:[{type:"command", command}]}`
    unter `event`.
  - Rückgabe erweitern: `{"included", "removed", "events", "org": [{id, event, command}]}`
    (nur gekeepte org-Hooks).
- Reihenfolge stimmt bereits: `overlay_org_profile` läuft vor
  `apply_package_surface_policy` (MCP liest denselben overlaid Profil-Stand).

### 4. Surface-Manifest — `write_surface_manifest` (`:449`)
Das `hooks`-Dict trägt jetzt `org: [...]` — **keine Signaturänderung** (hooks-Dict
wird schon durchgereicht). Das Manifest führt org-Hooks getrennt von den
Upstream-`included/removed`. Ohne Manifest-Eintrag kein org-Hook — harte Bedingung.

### 5. Smoke-Test — `scripts/smoke_test_package.py:check_surface_manifest` (`:129`)
Für jeden `hooks.org`-Eintrag prüfen:
- der `command` steht in der gebauten `hooks/hooks.json` unter dem deklarierten `event`,
- das referenzierte Skript existiert unter `org-profile/` im Build.
Neuer Helper `_commands_for_event(root, event)` scannt hooks.json. Fehlt ein
deklarierter org-Hook (oder umgekehrt) → `_die`.

### 6. `required-permissions.yaml`
**Keine Änderung.** Das ist Build-Zeit; die org-Hooks laufen im gepackten
Artefakt als Claude-Code-Hooks (org-Fläche, im Manifest geführt), nicht über den
Upstream-Permission-Contract der Skills.

---

## Doku (knapp, Muster wie MCP-Sektion)

- **`docs/internal-plugin-packaging.md`** — neue Sektion „Bundle your own hooks"
  neben der MCP-Sektion: `hooks:`-Beispiel, Skript unter `org-profile/hooks/`,
  `${CLAUDE_PLUGIN_ROOT}`-Regel, package-surface-Eintrag, Smoke-Test.
- **`docs/org-profiles.md`** — kurzer `## Hooks`-Abschnitt (Deklaration +
  ein Satz: läuft auf Claude-Code-Event-Ebene, kann keine Findings/Severity/Schemas
  ändern; im Surface-Manifest geführt).
- Präzedenz/Trust in einem Satz: org-Hook-Code ist org-vertraut (ihr Artefakt);
  die Analyse-Pipeline bleibt core-owned.

---

## Tests

- **`tests/test_org_profile_schema.py`**: valider `hooks`-Block; ungültiges `event`;
  `command` ohne `${CLAUDE_PLUGIN_ROOT}`; `matcher` auf `Stop`; ID-Kollision mit `agent-logger`.
- **`tests/fixtures/org-profiles/acme/`**: `hooks`-Block + winziges
  `hooks/guard.py` (No-op, gibt `{}` aus).
- **`tests/test_package_internal_plugin.py`**: org-Hook landet in gebauter
  hooks.json unter dem Event **und** im Surface-Manifest (`hooks.org`);
  `plugin_surface.hooks` exclude entfernt ihn wieder.
- **`tests/test_smoke_test_package.py`** (falls vorhanden): org-Hook-Verifikation
  grün; manipuliertes Manifest (Hook fehlt in hooks.json) → Fehler.
- Falls `_check_hooks` in einem eigenen Validator-Test lebt: missing-script /
  host-path / reserved-id ablehnen.

---

## Offene Design-Punkte (vor Bau kurz bestätigen)

1. **Event-Allowlist** — voller Claude-Code-Satz (oben) oder engerer Safe-Subset?
   Vorschlag: voller Satz (es sind die Hooks der Org).
2. **Nur `type: command`** für org-Hooks (keine anderen Hook-Typen). Vorschlag: ja.
3. **package-policy-Default** — org-Hooks standardmäßig **eingeschlossen** (wie
   MCP-Server), exclude-bar. Vorschlag: ja.
4. **Reservierte IDs** — `security-coach`, `agent-logger` gesperrt. Vorschlag: ja.

---

## Reihenfolge & Verify

1. Schema + `_check_hooks` → `test_org_profile_schema` grün.
2. Packager-Merge + Surface → `test_package_internal_plugin` grün.
3. Smoke-Test → grün, inkl. Negativfall.
4. Fixture-Integration: Paket mit org-Hook bauen, `hooks.json` + `package-surface.json` inspizieren.
5. Doku.
6. `make test` / `make lint`.
7. Manuell: acme-Fixture paketieren, `hooks/hooks.json` (org-Eintrag) + `package-surface.json` (`hooks.org`) prüfen; `smoke_test_package.py` laufen lassen.

## Aufwand / Risiko
Größer als Gate/Coach: berührt Packager, Validator, Smoke-Test, Schema, Doku,
Tests. Risiko konzentriert sich auf die ID-Tracking-Schicht (Knackpunkt oben) —
wenn org-IDs nicht durch alle drei Schichten getragen werden, wird ein Hook
still nicht auditiert. Deshalb: Packager + Surface + Smoke-Test **zusammen**
bauen und testen, nicht einzeln. Empfehlung: Worktree.
