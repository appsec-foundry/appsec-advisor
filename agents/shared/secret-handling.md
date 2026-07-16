# Secret Handling — Mandatory Output Hygiene

This rule applies to **every agent and every artifact** in the pipeline:
recon-summary, intermediate JSON sidecars, prose fragments, `threat-model.md`,
`threat-model.yaml`, logs, and console output.

A deterministic backstop (`scripts/secret_scan.py`, wired into
`scripts/qa_checks.py → check_unmasked_secrets`) blocks release if a raw,
unmasked secret slips through. The rule below ensures you do not trigger it.

## The rule

**Never emit the full value of a discovered secret.** Apply the masking format
below before any value reaches an artifact or chat output.

| Secret type | What to emit | Example |
|---|---|---|
| API key / token with type prefix (AWS, GitHub, Stripe, Google, Slack, …) | Identifying prefix (max 4 chars) + `****` | `AIza****`, `ghp_****`, `AKIA****` |
| Generic high-entropy key (≥ 16 chars, no known prefix) | First 4 chars + `****` | `TRwz****` |
| Short generic secret (8–15 chars) | `****` + length only | `**** (12 chars)` |
| Password / passphrase (any length) | `****` + length only — **no characters of the value** | `**** (8 chars)` |
| Private key block (`-----BEGIN … PRIVATE KEY-----`) | The literal string `[REDACTED — private key in <file>:<line>]` | `[REDACTED — private key in src/keys/host.pem:1]` |
| JWT (3 base64 segments) | `eyJ****` | `eyJ****` |

Always pair the masked snippet with `file:line` so reviewers can verify.

## Why passwords are special

Tokens with type prefixes (`AKIA`, `ghp_`, `sk_live_`, `AIza`) have a useful
identifying prefix — `AIza****` tells a reviewer "Google API key" without
enabling reuse. Passwords have no such structure. Showing 4 characters of an
8-character password leaks 50% of the secret with zero diagnostic benefit.

## Examples

✅ Correct:

```
**§6.9** — Hardcoded JWT signing key in `lib/insecurity.ts:18` (`L8T1****`).
**§6.2** — Default admin password in `data/seed-users.ts:4` (`**** (8 chars)`).
**§6.12** — Stripe live secret in `config/payments.yaml:12` (`sk_live_****`).
```

❌ Wrong (will be blocked by the per-run QA gate):

```
Hardcoded JWT signing key in `lib/insecurity.ts:18` (`L8T1XF31TBuvWBpHubV`).
Default admin password in `data/seed-users.ts:4` (`admin123`).
Stripe live secret: sk_live_51HzMxKLuNgT4Y...
```

## Backstop behavior

`scripts/secret_scan.py` recognizes the following masking markers and treats
matched values as already-redacted:

```
****   [REDACTED]   <REDACTED>   <...>   <…>   MASKED   XXXX   xxxx   …
```

Use **any** of these markers in the value portion of an emitted secret. Do
not invent new markers — the scanner does not know about them and will
classify the value as raw.

## When in doubt

Prefer `file:line + type` and **no value** at all. The masked snippet is a
convenience for triage, not a requirement.
