# Template-Update nach dem 0.5-Release

Kleiner Follow-up-Plan für das Beispiel-Packaging-Repo
`/home/mrohr/appsec-advisor-packaging-template` (eigenes Git-Repo). **Erst
ausführen, wenn appsec-advisor 0.5 getaggt ist** — vorher bricht es den Build.

## Warum erst nach 0.5

Beim echten Build validiert das Template sein Profil gegen den gepinnten
Upstream (`APPSEC_ADVISOR_REF`). Das Root-Schema ist `additionalProperties:
false` — ein 0.4-Validator lehnt `hooks:` / `gate:` / `fail_on` / `url_allowlist`
ab. Also: **zuerst den Pin auf den 0.5-Tag heben, dann die Felder ergänzen.**

## Schritte

1. **Pin heben** — `APPSEC_ADVISOR_REF` auf den 0.5-Tag (CI-Variable bzw. lokaler
   Default). `scripts/upstream-check.sh` gegen den neuen Ref laufen lassen
   (Drift-Check).
2. **Compatibility anziehen** — in `org-profile/org-profile.yaml`
   `compatibility.core` von `">=0.4 <0.6"` auf `">=0.5 <0.6"`. So schlägt ein
   versehentlicher 0.4-Pin mit einer klaren Compat-Meldung fehl statt mit einer
   Schema-Ablehnung.
3. **Neue Felder als Showcase ins Profil** (`org-profile/org-profile.yaml`):
   - `policy.url_allowlist: [security.example.internal, raw.githubusercontent.com]`
   - `security_coach:` mit `enabled_by_default: true` + einem `topics`-Beispiel
     (Trigger → Guidance + Requirement-IDs), passend zum Acme-Kontext.
   - am `ci-standard`-Preset: `requirements.gate` (`mode: enforce`, `gate_on: fail`,
     `priority_floor: MUST`) und `guardrails.fail_on: high`.
4. **Org-Hooks als Kern-Showcase** (die eigentliche „ein zentrales Plugin"-Story):
   - Neues Skript `org-profile/hooks/guard.py` (kleiner No-op-PreToolUse-Hook,
     analog dem Fixture in appsec-advisor).
   - `hooks:`-Block im Profil:
     ```yaml
     hooks:
       block-risky-bash:
         event: PreToolUse
         matcher: Bash
         command: python3 ${CLAUDE_PLUGIN_ROOT}/org-profile/hooks/guard.py
     ```
   - **Keine Template-Skript-Änderung nötig** — der Upstream-Packager kopiert
     `org-profile/` komplett und merged den `hooks:`-Block selbst. `package-local.sh`
     wrappt ihn nur.
5. **Doku im Template** — falls `README.example.md` / `AGENTS.md` / `CLAUDE.md` die
   Profil-Felder aufzählen, die vier neuen kurz ergänzen (auf die Upstream-Doku
   `docs/org-profiles.md` verweisen, nicht duplizieren).

## Verify

- `make` bzw. `scripts/package-local.sh` gegen den 0.5-Upstream bauen.
- Im Build prüfen: `hooks/hooks.json` enthält den org-Hook unter `PreToolUse`;
  `.claude-plugin/package-surface.json` führt ihn unter `hooks.org`.
- `smoke_test_package.py` auf dem Build laufen lassen (grün).
- `tests/run.sh` (Template-eigene Shell-Tests) grün — die stubben den Upstream,
  sollten unberührt bleiben.

## Aufwand

Klein: ein neues Skript + Profil-Ergänzungen + optional Template-Doku. Kein
Code, keine Test-Logik im Template. Risiko steckt allein in der Pin-Reihenfolge
(Schritt 1–2 vor 3–4).
