# Architect coverage signals — recon-signal → expected threat category

Used by `appsec-architect-reviewer` Check 4 (Threat Coverage Gaps). For each signal present in `.recon-summary.md` or `.threat-modeling-context.md`, the threat register must contain at least one threat matching one of the expected categories (by CWE or title pattern).

| Recon signal | Expected threat category (at least one) |
|---|---|
| `tenant_id`, `organization_id`, `workspace_id` appear in code | Multi-tenancy / horizontal authorization (CWE-639 / CWE-284) |
| Incoming webhook endpoint detected | Webhook replay, signature verification (CWE-294 / CWE-347) |
| File upload endpoint detected | Content-type spoofing, storage traversal, virus-laden uploads (CWE-434 / CWE-22) |
| OAuth / OIDC integration detected | State parameter / PKCE / open redirect on callback (CWE-352 / CWE-601) |
| JWT / session token handling detected | Token validation, algorithm confusion, replay (CWE-347 / CWE-384) |
| Background job / queue consumer detected | Job poisoning, unbounded consumer, queue TOCTOU |
| Multi-region or data-residency hints in context | Data residency violation, cross-region leakage |
| Customer-facing admin UI detected | Admin route authz, CSRF, mass assignment |
| AI/LLM integration patterns detected (`KNOWN_LLM_PATTERNS`) | OWASP LLM Top 10 coverage |
| CI/CD pipeline component with supply-chain findings | Supply-chain Tampering / EoP threats |

**Severity:** `warning` when the signal is unambiguous (e.g. file-upload endpoint with no file-upload threat); `info` when the signal is inferred (e.g. "multi-region mentioned in docs but no regional split in recon"). If `.merge-decisions.json` exists, consult it before flagging — a "missing" threat may have been consolidated into another ID.
