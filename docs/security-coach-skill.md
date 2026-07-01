# Security Coach

The Security Coach adds relevant security guidance to Claude Code prompts during a coding session.

## Contents

- [What it does](#what-it-does)
- [When to use it](#when-to-use-it)
- [When AGENTS.md is enough](#when-agentsmd-is-enough)
- [Activation](#activation)
- [Trigger logic](#trigger-logic)
- [Topic keywords and injected guidance](#topic-keywords-and-injected-guidance)
- [Example injection](#example-injection)
- [Non-triggering prompts](#non-triggering-prompts)
- [Requirements-aware mode](#requirements-aware-mode)
- [Known limitations](#known-limitations)
- [Telemetry](#telemetry)
- [Tuning false positives](#tuning-false-positives)
- [Disabling](#disabling)

## What it does

The hook checks each prompt for security-related topics. On a match, it adds a short baseline and guidance for topics such as authentication, cryptography, injection, IaC, or secrets.

The coach is a prompt-augmentation hook. It never blocks a prompt, and it does not call the model on its own.

## When to use it

- Long coding sessions in which only some prompts need security guidance.
- Short implementation prompts that would otherwise omit relevant requirements.
- Teams that update a central requirements catalog.
- Sessions where the team needs a record of which guidance was added.

## When AGENTS.md is enough

- Solo projects without a requirements catalog.
- Fewer than ~10 requirements, where topic routing adds overhead without saving tokens.
- Teams on Claude Code forks or clients that do not support `UserPromptSubmit` hooks.
- Short baselines (< 20 lines) where every prompt can carry the full text.

In these cases, copy the `baseline` value from `hooks/steering_keywords.json` into `AGENTS.md`.

## Activation

The coach is disabled by default. Enable it for one session, an organization profile, or the plugin installation.

**Per session (environment variable):**

```bash
APPSEC_COACH=1 claude --plugin-dir /path/to/appsec-advisor
```

**Per team / org profile:**

```yaml
# org-profile.yaml
security_coach:
  enabled_by_default: true
  max_requirements_per_topic: 3  # optional, default 3
```

An org profile enables the coach for all users of that package.

**Globally (hook config):**

```json
// hooks/steering_keywords.json
{
  "enabled": true,
  ...
}
```

The environment variable takes precedence over the org profile and hook config. Use `APPSEC_COACH=0` to disable the coach for one session.

## Trigger logic

The coach combines topic keywords, code terms, and action verbs to avoid triggering on unrelated prompts.

| Tier | Example keywords | Threshold |
|------|------------------|-----------|
| **Topic triggers** | `auth`, `jwt`, `sql`, `xss`, `csp`, `tls`, `dockerfile`, `jailbreak`, … | 1 match activates the topic (and the coach) |
| **Code** | `api`, `endpoint`, `database`, `docker`, `route`, `middleware`, `schema`, `migration` | ≥ 2 matches required |
| **Action + code** | Action verbs (`write`, `create`, `build`, `fix`) combined with code keywords | 1 action + 1 code required |

Thresholds are configured under `thresholds` in `hooks/steering_keywords.json`.

## Topic keywords and injected guidance

Topics are defined in `hooks/steering_keywords.json` under `topics.<name>`. Each topic lists:

- `triggers` — keywords that route to this topic
- `guidance` — the bullet list injected into the prompt when the topic matches
- `requirements` — `SEC-*` IDs resolved at runtime against the requirements YAML

Default topics:

| Topic | Scope |
|-------|-------|
| `general` | Broad security intent (vulnerability, exploit, privilege) — injects baseline only |
| `auth` | Authentication, session, tokens, OAuth/OIDC, MFA |
| `injection` | SQL/NoSQL injection, ORM, input sanitization, parameterized queries |
| `crypto` | Hashing, encryption, TLS, certificates, password storage |
| `xss_csrf` | XSS, CSRF, CORS, CSP, cookies, output encoding, clickjacking |
| `secrets` | Credentials, API keys, secret storage, vaults |
| `iac` | Kubernetes, Terraform, Dockerfile, Helm, Compose |
| `llm` | Prompt injection, jailbreaks, OWASP LLM Top 10 |

`severity.max_injected_chars` limits the injected text to 2,500 characters by default.

## Example injection

**Prompt:**

```
implement a refresh endpoint for our JWT auth
```

**Added context:**

```
Security steering active. Always implement secure-by-default:
- Treat all input as untrusted
- Enforce authentication and least privilege
- Never hardcode or expose secrets
- Use secure defaults
- Prevent common vulnerabilities
- Do not suggest insecure shortcuts

[auth] Authentication & session guidance: short-lived tokens with
rotation on refresh; validate issuer/audience/signature/expiry on
every JWT check; MFA for admin paths; Secure+HttpOnly+SameSite=Strict
on session cookies.

Applicable requirements:
  - SEC-API-AUTH (MUST): Authenticate all API endpoints using your SSO
    provider or internal IdP; service-to-service via mTLS or signed JWTs
    with short TTL.
```

**System message:**

```
AppSec Coach active (via env): auth.
```

The system message lists the matched topics. Requirement text comes from the same catalog as `/appsec-advisor:audit-security-requirements`.

## Non-triggering prompts

These prompts do not trigger the coach:

- `"create a README"` — action verb with no code-density
- `"rename the button"` — UI change, no security-relevant tokens
- `"why is this test failing"` — no triggers, no action+code combo
- `"add a logger"` — 1 action + 1 code word, below the combined threshold
- `"what is an API"` — single code keyword alone
- `"hello, how are you?"` — conversational
- `"summarize this meeting"` — unrelated domain

If you see a prompt firing that shouldn't, see [Tuning false positives](#tuning-false-positives).

## Requirements-aware mode

When a requirements catalog is active, matching requirements are added with their ID, priority, and text. See the [harvester guide](harvester.md) for catalog setup.

`severity.max_requirements_per_topic` limits the number of requirements per topic to 3 by default. An org profile can override it with `security_coach.max_requirements_per_topic`.

The first available catalog is used:

1. the cached catalog from the org profile's `requirements_yaml_url`
2. `data/appsec-requirements-fallback.yaml`
3. `data/appsec-bestpractices-baseline.yaml`

Set `requirements.source.requirements_yaml_url` in the org profile to distribute a company catalog. The coach uses the active catalog on the next prompt.

## Known limitations

- Matching is keyword-based, so unfamiliar paraphrases or project-specific terms can be missed.
- The baseline is included with every matched topic.
- The log confirms that guidance was added, not that the model followed it.

## Telemetry

Each injection appends a `COACH_INJECTED` event to the hook log:

```
2026-04-19T10:14:27Z  [--------]  INFO   COACH_INJECTED     topics=auth req_ids=SEC-API-AUTH chars=412 prompt=7f3a2b1c
```

Fields:

- `topics` — matched topic names (sorted, comma-separated)
- `req_ids` — requirement IDs resolved and injected, or `-` if none
- `chars` — length of the injected context block
- `prompt` — first 8 hex chars of a SHA-256 of the prompt (stable reference without logging the prompt text)

The event does not include the prompt body. It can be used to review trigger frequency and tune topic keywords.

If the log directory is not writable, the event is skipped and the prompt continues.

## Tuning false positives

Edit `hooks/steering_keywords.json`:

- Remove overly generic terms from `code_keywords` (e.g. `config`).
- Raise the `code_min` threshold (default 2) if the coach fires too often.
- Add project-specific triggers to the relevant `topics.<name>.triggers` list instead of widening the code tier.
- Use the telemetry log (see above) to identify which topics fire unexpectedly before tweaking.

After edits, validate the file:

```bash
python3 scripts/validate_config.py
pytest tests/test_security_steering.py
```

## Disabling

To disable the coach for one session:

```bash
APPSEC_COACH=0 claude ...
```

To disable globally, set `enabled` to `false` in `hooks/steering_keywords.json` (the same flag used to enable it under [Activation](#activation)):

```json
// hooks/steering_keywords.json
{ "enabled": false, ... }
```

To disable for a team, set `security_coach.enabled_by_default: false` (or remove the block) in the org profile.
