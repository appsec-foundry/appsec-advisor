# Security Coach

Background guidance during a coding session. A `UserPromptSubmit` hook scans each prompt for security-relevant keywords and injects short, context-aware advice before the model processes the prompt.

## Contents

- [What it does](#what-it-does)
- [When the coach helps most](#when-the-coach-helps-most)
- [When a static AGENTS.md baseline is enough](#when-a-static-agentsmd-baseline-is-enough)
- [Activation](#activation)
- [Trigger logic](#trigger-logic)
- [Topic keywords and injected guidance](#topic-keywords-and-injected-guidance)
- [Example injection](#example-injection)
- [Prompts that correctly do NOT trigger](#prompts-that-correctly-do-not-trigger)
- [Requirements-aware mode](#requirements-aware-mode)
- [Known limitations](#known-limitations)
- [Telemetry](#telemetry)
- [Tuning false positives](#tuning-false-positives)
- [Disabling](#disabling)

## What it does

Before Claude sees a prompt, the hook checks whether the prompt is security-relevant. If so, it prepends a secure-by-default baseline plus topic-specific guidance (authentication, crypto, injection, IaC, secrets, etc.). Claude answers the original question with the injected context in its working memory.

The coach is a prompt-augmentation hook only — it does not block prompts and does not call the model on its own.

## When the coach helps most

- **Mixed sessions.** Long coding sessions where only some prompts touch security: `"explain the architecture"` injects nothing, while `"implement OAuth refresh"` pulls in `SEC-API-AUTH`. A static AGENTS.md baseline would pay tokens on every turn regardless.
- **Short, time-pressured prompts.** Requests like `"quickly wire up Stripe"` receive a focused nudge (`SEC-SECRETS`, three lines) rather than requiring Claude to extract the relevant rule from a long static baseline.
- **Teams with a living requirements catalog.** When the harvester refreshes `appsec-requirements-fallback.yaml`, the coach picks up the new text on the next prompt — no AGENTS.md edit, no PR, no pull required across the team.
- **Multi-agent pipelines.** Sub-agents that do not run `UserPromptSubmit` (STRIDE analyzers, QA reviewer) receive requirement context through the orchestrator's selective injection. The coach covers the user-facing surface; per-component logic stays with the orchestrator.
- **Sessions requiring an audit trail.** Each injection is logged (see [Telemetry](#telemetry)), so questions like "did Claude see the auth requirement when this code was written?" are answerable from `.hook-events.log` rather than from inference.

## When a static AGENTS.md baseline is enough

- Solo projects without a requirements catalog.
- Fewer than ~10 requirements, where topic routing adds overhead without saving tokens.
- Teams on Claude Code forks or clients that do not support `UserPromptSubmit` hooks.
- Short baselines (< 20 lines) where every prompt can carry the full text.

For those cases, copy the `baseline` string from `steering_keywords.json` into your AGENTS.md and skip the coach entirely.

## Activation

Disabled by default. Three ways to enable.

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

When a packaged plugin bundles an org profile with `enabled_by_default: true`, the coach is active for all team members without any per-session opt-in.

**Globally (hook config):**

```json
// hooks/steering_keywords.json
{
  "enabled": true,
  ...
}
```

Precedence: environment variable wins (including as kill switch `APPSEC_COACH=0`), then org profile, then hook config. Use `APPSEC_COACH=0` to force-disable for a single session without touching any file.

## Trigger logic

Tiered keyword matching activates on security-relevant intent, not on any prompt that merely mentions a code word.

| Tier | Example keywords | Threshold |
|------|------------------|-----------|
| **Topic triggers** | `auth`, `jwt`, `sql`, `xss`, `csp`, `tls`, `dockerfile`, `jailbreak`, … | 1 match activates the topic (and the coach) |
| **Code** | `api`, `endpoint`, `database`, `docker`, `route`, `middleware`, `schema`, `migration` | ≥ 2 matches required |
| **Action + code** | Action verbs (`write`, `create`, `build`, `fix`) combined with code keywords | 1 action + 1 code required |

Thresholds live in `hooks/steering_keywords.json` under `thresholds`. Default values avoid false positives on prompts like "create a README" while still firing on "create an API endpoint".

## Topic keywords and injected guidance

Topics are defined in `hooks/steering_keywords.json` under `topics.<name>`. Each topic lists:

- `triggers` — keywords that route to this topic
- `guidance` — the bullet list injected into the prompt when the topic matches
- `requirements` — `SEC-*` IDs resolved at runtime against the requirements YAML

Default topics (names as they appear in config and in the `systemMessage`):

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

Injected guidance is capped at `severity.max_injected_chars` (default 2500) to avoid inflating the context window.

## Example injection

**Prompt (what the user types):**

```
implement a refresh endpoint for our JWT auth
```

**Context prepended to Claude's input (what the model actually sees before the prompt):**

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
  - SEC-API-AUTH (MUST): Authenticate all API endpoints using KN SSO
    or KNITE; service-to-service via mTLS or signed JWTs with short TTL.
```

**System message shown to the user:**

```
AppSec Coach active (via env): auth.
```

The system message lists every matched topic so the user can see at a glance which guidance set was applied. Requirements are resolved from the same YAML that powers `/appsec-advisor:audit-security-requirements`, so their text stays in sync with the baseline.

## Prompts that correctly do NOT trigger

The trigger logic is tuned to stay silent on non-security prompts. These examples all return an empty hook response:

- `"create a README"` — action verb with no code-density
- `"rename the button"` — UI change, no security-relevant tokens
- `"why is this test failing"` — no triggers, no action+code combo
- `"add a logger"` — 1 action + 1 code word, below the combined threshold
- `"what is an API"` — single code keyword alone
- `"hello, how are you?"` — conversational
- `"summarize this meeting"` — unrelated domain

If you see a prompt firing that shouldn't, see [Tuning false positives](#tuning-false-positives).

## Requirements-aware mode

When a security requirements catalog is loaded (see [`docs/harvester.md`](harvester.md)), matching `SEC-*` requirements are injected alongside the generic guidance. Each rendered line includes the ID, the priority tag (`MUST` / `SHOULD` / `MAY`), and the requirement text taken verbatim from the YAML.

The number of requirements injected per topic is capped at `severity.max_requirements_per_topic` (default 3). The org profile can lower or raise this cap with `security_coach.max_requirements_per_topic`.

Requirement text is resolved at runtime from whichever YAML is found first along `requirements_source.paths`:

1. `.cache/requirements.yaml` (populated by the harvester — URL set via `requirements.source.requirements_yaml_url` in the org profile)
2. `data/appsec-requirements-fallback.yaml` (shipped with the plugin — company `SEC-*` requirements)
3. `data/appsec-bestpractices-baseline.yaml` (shipped with the plugin — OWASP-derived `BP-*` best practices, used when no company catalog is present)

The active catalog is exclusive: the first readable file wins. Which catalog is loaded therefore depends on the org profile configuration:

- **Org profile with `requirements_yaml_url`** → harvester populates `.cache/requirements.yaml` → company `SEC-*` / `SSDLC-*` requirements are injected.
- **No org profile or no URL configured** → falls through to `appsec-requirements-fallback.yaml` (if shipped) or the OWASP `BP-*` baseline.

To control this via packaging, set `requirements.source.requirements_yaml_url` in the org profile. The coach picks up the active catalog on the next prompt.

The topic keyword lists in `hooks/steering_keywords.json` carry both `SEC-*` and `BP-*` IDs per topic. The coach filters at runtime to only inject IDs present in the active catalog, so the same plugin build works correctly with either a company catalog or the OWASP baseline.

## Known limitations

- **Lexical matching.** Paraphrased prompts may miss even when semantically equivalent. "sanitize the payload" triggers `injection` only if `sanitize` is in the trigger list. The shipped config covers common paraphrases; project-specific jargon should be added to the relevant topic's `triggers`.
- **Sub-agent prompts are not hooked.** STRIDE analyzers and other internal agents invoked by the orchestrator do not pass through `UserPromptSubmit`. They receive requirement context through a different channel (selective per-component injection). This is intentional — see `AGENTS.md` → "Selective STRIDE context".
- **Baseline always loads when any topic matches.** Even a single-topic match prepends the 6-line secure-by-default baseline. In tight contexts this adds ~250 characters on top of topic guidance.
- **No visibility into whether Claude actually used the guidance.** The injection is logged, but whether the model weighted it is only observable through behavior.

## Telemetry

When the coach injects, it appends a `COACH_INJECTED` event to `docs/security/.hook-events.log` alongside the standard hook events written by `agent_logger.py`. The line format matches the surrounding log:

```
2026-04-19T10:14:27Z  [--------]  INFO   COACH_INJECTED     topics=auth req_ids=SEC-API-AUTH chars=412 prompt=7f3a2b1c
```

Fields:

- `topics` — matched topic names (sorted, comma-separated), excluding internal `_legacy`
- `req_ids` — requirement IDs resolved and injected, or `-` if none
- `chars` — length of the injected context block
- `prompt` — first 8 hex chars of a SHA-256 of the prompt (stable reference without logging the prompt text)

The event is append-only and never includes the prompt body, so the log is safe to share with a platform team for tuning reviews. For example, a frequency analysis over `topics=…` shows which topics actually fire in your team's sessions, and comparing injection counts before and after a config change shows whether newly added trigger words catch anything.

Telemetry is best-effort: if the log directory is not writable (e.g. read-only filesystem, external working directory), the event is silently dropped. The hook never fails because of a logging error.

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

Any of the three activation mechanisms can be set to `false` / unset. To disable the hook entirely without touching the plugin:

```bash
APPSEC_COACH=0 claude ...
```

Or in `config.json`:

```json
{ "security_coach": { "enabled": false } }
```
