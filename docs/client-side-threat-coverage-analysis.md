# Client-Side Threat Coverage Analysis

Assessment of how well the plugin covers SPA and browser-side threats — what's adequate, what's partial, and what's missing entirely.

## Verdict

**Partial coverage (~40–50% of SPA-specific threat surface).** The plugin handles token storage patterns and basic DOM sinks well, and the requirements baseline is solid. But it lacks detection for most browser-specific attack vectors: CSP, CORS, DOM-based XSS source-to-sink flows, framework-specific vulnerabilities, postMessage/iframe, WebSockets, service workers, and client-side routing security.

The gap is not in the methodology (STRIDE applies to frontends) but in the **reconnaissance patterns** — the recon scanner doesn't collect enough client-side signal for downstream phases to reason about.

---

## Coverage Summary

| Client-Side Threat | Recon | Controls (Phase 8) | STRIDE (Phase 9) | Requirements | Status |
|---|---|---|---|---|---|
| localStorage/sessionStorage misuse | Explicit grep | SPA/BFF domain | Implicit | SEC-CLIENT-STORAGE | **Adequate** |
| Dangerous DOM sinks (innerHTML, eval) | Explicit grep | Output Encoding domain | Implicit | SEC-UI-ENCODE | **Adequate** |
| Cookie security (SameSite, flags) | Explicit grep | SPA/BFF domain | Implicit | SEC-ANTI-CSRF | **Partial** |
| DOM-based XSS (source→sink) | Sinks only, no sources | Generic | Not guided | SEC-UI-ENCODE | **Partial** |
| XSS output encoding | Sinks only | Output Encoding domain | Implicit | SEC-UI-ENCODE | **Partial** |
| CSRF beyond SameSite | SameSite only | Cookie config only | Not guided | SEC-ANTI-CSRF | **Partial** |
| CSP | Not scanned | Not checked | Not guided | SEC-CSP | **Missing** |
| CORS misconfiguration | Not scanned | Not checked | Not guided | SEC-CORS | **Missing** |
| Framework-specific vulns (Angular/React/Vue) | Not detected | Generic only | Not guided | Generic only | **Missing** |
| postMessage / iframe security | Not scanned | Not checked | Not guided | No requirement | **Missing** |
| WebSocket security | Not scanned | Not checked | Not guided | No requirement | **Missing** |
| Service workers | Not scanned | Not checked | Not guided | No requirement | **Missing** |
| Client-side secrets / API key exposure | Backend-focused grep | Not checked | Not guided | Env var focus only | **Missing** |
| SPA routing / auth guards | Not scanned | Not checked | Not guided | No requirement | **Missing** |
| Third-party scripts / SRI | Not scanned | Not checked | Not guided | No requirement | **Missing** |
| Client-side template injection | Not scanned | Not checked | Not guided | No requirement | **Missing** |

---

## Detailed Analysis

### What's Working Well

**1. Token Storage Detection (Recon Category 10: SPA/BFF)**

The recon scanner explicitly greps for:
```
(?i)(localStorage|sessionStorage|document\.cookie|withCredentials|SameSite|bff|backend.for.frontend|proxy.*auth|forward.*token)
```

This catches the most common SPA anti-pattern (JWT in localStorage) and feeds into Phase 8 controls and Phase 9 STRIDE analysis. The Juice Shop example threat model demonstrates this producing concrete threats like "T-005: JWT in localStorage + stored XSS" with a specific mitigation "M-004: Move JWT from localStorage to HttpOnly cookie".

**2. Dangerous DOM Sinks (Recon Category 8)**

```
(?i)(eval\(|exec\(|innerHTML|document\.write|subprocess|os\.system|shell=True)
```

Catches the most exploitable DOM sinks. When these appear in recon results, the STRIDE analyzer can reason about XSS impact.

**3. Requirements Baseline (SEC-FRONTEND_SECURITY category)**

Seven requirements covering anti-CSRF, client storage, CORS, CSP, HSTS, framework selection, and output encoding. This is a solid foundation — the problem is that recon doesn't validate most of them.

**4. Phase Structure**

Phase 4 (Use Cases) lists "Frontend Security" as a mandatory sequence diagram. Phase 8 includes "Frontend Security" and "SPA/BFF Architecture" as control domains. The SPA frontend is listed as a STRIDE component candidate at standard/thorough depth. The *structure* supports client-side analysis — the *detection patterns* are what's lacking.

### Where Coverage Falls Short

**5. DOM-Based XSS: Sinks Without Sources**

The scanner finds DOM sinks (`innerHTML`, `document.write`) but not DOM sources — the user-controlled inputs that feed them. Without source detection, the STRIDE analyzer can note that `innerHTML` is used but cannot trace whether attacker-controlled data reaches it.

Missing source patterns:
- `location.hash`, `location.search`, `location.pathname`
- `window.name`, `document.referrer`, `document.URL`
- URL parameters parsed by client-side routing
- `window.postMessage` data

**6. No Framework Detection**

The recon scanner has no category for identifying which frontend framework is in use or its version. Framework identity matters because:
- **Angular**: `bypassSecurityTrustHtml()` defeats the built-in sanitizer; the DomSanitizer has version-specific behaviors
- **React**: `dangerouslySetInnerHTML` is the primary XSS vector; JSX auto-escapes by default
- **Vue**: `v-html` directive bypasses template escaping
- **Svelte**: `{@html}` tag renders raw HTML

The Juice Shop example shows the orchestrator *did* identify Angular-specific issues ("bypassSecurityTrustHtml() defeats Angular sanitizer"), but this happened through general code reading, not systematic scanning. For repositories where the STRIDE analyzer doesn't happen to stumble on the framework-specific anti-pattern, it will be missed.

**7. CSP: Required but Never Verified**

The requirements baseline includes `SEC-CSP: Activate CSP headers on Internet-facing applications`, but neither the recon scanner nor Phase 8 checks for CSP presence. This means:
- A repository with no CSP at all won't have this flagged in recon
- Phase 8 won't rate CSP as ❌ Missing unless it happens to grep for it
- Phase 8b requirements compliance would flag it (if `--requirements` is enabled), but only as a pass/fail — not with evidence of what's misconfigured

**8. CORS: Required but Never Scanned**

Same pattern as CSP. `SEC-CORS` requires restrictive CORS configuration, but the recon scanner doesn't look for CORS headers or middleware (`cors()`, `Access-Control-Allow-Origin`, etc.). Phase 8 doesn't verify CORS restrictiveness.

**9. CSRF: Only SameSite, No Token Verification**

The recon scanner catches `SameSite` cookie attributes but doesn't look for:
- CSRF token middleware (e.g., `csurf`, `csrf_token`, `AntiForgeryToken`)
- Double-submit cookie patterns
- Custom header verification (e.g., `X-Requested-With`)
- Whether state-changing endpoints accept GET requests

### What's Not Covered At All

**10. postMessage / iframe Communication**

No scanning for `window.postMessage`, `addEventListener('message', ...)`, iframe `sandbox` attributes, or cross-origin frame communication. These are common in SPA architectures that embed third-party widgets, payment forms, or SSO flows.

**11. WebSocket Security**

No detection of WebSocket endpoints (`ws://`, `wss://`), Socket.IO usage, origin validation in WebSocket handlers, or authentication in WebSocket connections. The Juice Shop example uses Socket.IO but the WebSocket layer receives no security analysis.

**12. Service Workers**

No detection of service worker registration, scope analysis, cache poisoning risks, or update mechanisms. Service workers can intercept all network requests and serve cached responses — a compromised or misconfigured service worker is a persistent XSS equivalent.

**13. Client-Side Secrets**

Category 12 (Hardcoded Secrets) greps for `password=`, `api_key=`, `secret=` patterns that are backend-focused. It doesn't detect:
- API keys in frontend bundles (Google Maps, Firebase, Stripe, Auth0)
- Backend URLs hardcoded in frontend config
- OAuth client secrets accidentally included in browser code

**14. SPA Routing and Auth Guards**

No detection of client-side route guards (`canActivate`, `beforeEach`, `useAuth` guards), route-level authorization, or sensitive data exposed in URL parameters/fragments. Client-side routing bypasses are a common vulnerability in SPAs where authorization is checked client-side but not server-side.

**15. Third-Party Scripts and SRI**

No scanning for third-party script inclusion, CDN integrity (`integrity` attribute for SRI), analytics libraries, or tracking pixels. Supply chain attacks via compromised CDN-hosted scripts are a growing threat vector.

---

## Gaps in the STRIDE Analysis Pipeline

### Component Selection (Phase 9)

The phase-group-threats.md instructions say:

> Always include: Auth/identity, Authorization, components handling PII/payments, Admin panel, Public API gateway.
> For Moderate/Complex: each backend service, **frontend SPA**, queue consumers, CI/CD pipeline.

The SPA is a STRIDE component candidate — but only at moderate/complex depth. At `--assessment-depth quick`, the frontend may not be selected at all.

### No SPA-Specific Threat Patterns

The STRIDE analyzer receives component interfaces and trust boundaries but has no specialized guidance for client-side threat enumeration. For a backend API component, the analyzer naturally reasons about injection, auth bypass, and data exposure. For a frontend SPA component, it needs explicit prompting to examine:

- Browser-specific attack vectors (XSS variants, clickjacking, CSRF)
- Client-side state management vulnerabilities
- Framework-specific misconfigurations
- Browser storage abuse
- Cross-origin communication

Without these patterns, the STRIDE analyzer falls back to generic reasoning, which produces lower-quality client-side threats.

### Trust Boundary Gap

Phase 7 (Trust Boundary Analysis) should identify the browser↔server boundary as a primary trust boundary. The instructions don't specifically call this out — it's implied but not mandated. When the trust boundary analysis is thin on the client side, Phases 8–9 inherit that gap.

---

## Recommendations

### Tier 1: High-impact, low-effort fixes

These changes improve coverage significantly with minimal prompt changes.

**R1. Expand Recon Category 10 (SPA/BFF) with security header and CORS patterns**

Add to the existing SPA/BFF grep:
```
(?i)(Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy|Access-Control-Allow-Origin|cors\(|enableCors|CorsMiddleware)
```

This enables Phase 8 to rate CSP and CORS as control domains with actual evidence.

**R2. Add Recon Category 18: Frontend Framework Detection**

```
(?i)(dangerouslySetInnerHTML|v-html|bypassSecurityTrust|@html|\{\{.*\|.*safe\}\}|DomSanitizer|sanitize.*html|ng-bind-html)
```

Combined with a `package.json` read for framework name/version. Feeds Phase 8 and Phase 9 with framework-specific risk signals.

**R3. Add DOM-based XSS sources to Category 8 or a new Category 19**

```
(?i)(location\.(hash|search|href|pathname)|window\.name|document\.(referrer|URL|documentURI)|URLSearchParams|hashchange|popstate)
```

When both sources AND sinks appear in the same codebase, the STRIDE analyzer can reason about source→sink flows.

**R4. Add client-side secrets patterns to Category 12**

```
(?i)(REACT_APP_|NEXT_PUBLIC_|VITE_|NUXT_ENV_|firebase.*apiKey|google.*maps.*key|stripe.*publishable)
```

Frontend environment variable prefixes are intentionally exposed to the browser — they should be checked for sensitive values.

### Tier 2: Medium-effort structural improvements

**R5. Add SPA-specific threat patterns to the STRIDE analyzer**

Add a conditional section to `appsec-stride-analyzer.md` for frontend components:

```markdown
### When analyzing a frontend/SPA component, additionally check:
- DOM-based XSS: Do user-controlled URL parameters reach innerHTML/document.write?
- Client storage: Are tokens, PII, or session data in localStorage/sessionStorage?
- Framework sanitizer bypasses: Is the framework's XSS protection disabled anywhere?
- CSP: Is Content-Security-Policy set? Is it restrictive (no unsafe-inline/unsafe-eval)?
- CORS: Does the server allow overly broad origins? Does the client send credentials cross-origin?
- postMessage: Are message event listeners validating origin?
- Auth guards: Are route guards client-side only, or backed by server-side checks?
- Third-party scripts: Are external scripts loaded without SRI integrity attributes?
```

**R6. Mandate browser↔server trust boundary in Phase 7**

Add to phase-group-architecture.md:

```markdown
If a frontend SPA or client-side application is present, the browser↔server boundary
MUST be explicitly identified as a trust boundary. The browser is an untrusted execution
environment — all data from the client must be treated as attacker-controlled.
```

**R7. Add Phase 8 control sub-domains for CSP and CORS**

Currently "Frontend Security" is one domain. Split into:
- Frontend Security: framework config, output encoding, DOM sink usage
- CSP: policy presence, directive restrictiveness, nonce usage
- CORS: origin allowlist, credential handling, preflight configuration

Each gets its own ✅/⚠️/🔶/❌ rating.

### Tier 3: New requirements and extended coverage

**R8. Add missing requirements to the baseline**

```yaml
- id: SEC-POSTMESSAGE
  text: Validate origin in all postMessage event listeners
  priority: SHOULD
  cwe_url: https://cwe.mitre.org/data/definitions/345.html

- id: SEC-WEBSOCKET
  text: Authenticate WebSocket connections and validate message origin
  priority: SHOULD
  cwe_url: https://cwe.mitre.org/data/definitions/306.html

- id: SEC-SRI
  text: Include Subresource Integrity attributes on all third-party script and stylesheet references
  priority: SHOULD
  cwe_url: https://cwe.mitre.org/data/definitions/830.html

- id: SEC-SERVICE-WORKER
  text: Restrict service worker scope and validate cached responses
  priority: MAY
  cwe_url: https://cwe.mitre.org/data/definitions/524.html

- id: SEC-CLIENT-ROUTING
  text: Enforce server-side authorization for all routes, not just client-side route guards
  priority: MUST
  cwe_url: https://cwe.mitre.org/data/definitions/862.html
```

**R9. Add Recon categories for WebSocket and postMessage**

Category 20: `(?i)(WebSocket|socket\.io|ws://|wss://|onmessage.*socket)`
Category 21: `(?i)(postMessage|addEventListener\s*\(\s*['"]message|window\.opener|parent\.postMessage)`

**R10. Quick depth should still select the SPA as a STRIDE component**

If the recon scanner detects a frontend framework, the SPA should be a mandatory STRIDE component even at `--assessment-depth quick`. Client-side attack surface is too large to skip.

---

## Implementation Priority

| # | Recommendation | Files to change | Impact |
|---|---|---|---|
| R1 | Expand SPA/BFF grep (CSP, CORS) | `appsec-recon-scanner.md` | High — unlocks Phase 8 ratings for two missing control domains |
| R2 | Framework detection category | `appsec-recon-scanner.md` | High — enables framework-specific STRIDE threats |
| R3 | DOM XSS source patterns | `appsec-recon-scanner.md` | High — completes source→sink analysis capability |
| R5 | SPA threat patterns for STRIDE | `appsec-stride-analyzer.md` | High — directly improves frontend threat quality |
| R4 | Client-side secrets patterns | `appsec-recon-scanner.md` | Medium — catches common SPA anti-pattern |
| R6 | Browser trust boundary mandate | `phase-group-architecture.md` | Medium — structural improvement |
| R7 | Split frontend control domains | `phase-group-architecture.md` | Medium — finer-grained control ratings |
| R10 | SPA mandatory at quick depth | `phase-group-threats.md` | Medium — prevents skipping largest attack surface |
| R8 | New requirements | `appsec-requirements-fallback.yaml` | Low (indirect) — only affects `--requirements` users |
| R9 | WebSocket/postMessage recon | `appsec-recon-scanner.md` | Low — niche but important for specific architectures |
