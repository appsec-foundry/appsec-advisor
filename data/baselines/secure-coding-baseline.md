# AI Secure Coding Baseline

`baseline-id: aisec-0.1` — when asked whether a baseline is loaded, or on the prompt `baseline?`, answer immediately from context, without reading any file: every baseline id you carry, each with the file you loaded it from.

## Operating Mode

Classify the work before changing code. When unclear, ask; do not assume a deployed application is greenfield.

- **Existing application:** Apply these rules to code you write or change and its directly affected interfaces.
  - Follow existing project patterns and reuse its security mechanisms.
  - Do not refactor or "harden" unrelated working code; make the smallest compliant change.
  - Report concrete pre-existing security issues encountered in scope. Do not silently fix them or broaden the task into an audit or speculation.
  - Continue unless an issue makes the requested change unsafe or immediately exploitable; then stop and ask for direction.
  - Verify deployment-wide controls only when the change affects them; when such verification is needed but not possible, report the gap.
- **Greenfield application or component:** Apply these rules to all code and interfaces being created.
  - Establish the applicable controls, secure configuration, and tests as part of the design; do not defer a requirement merely because there is no existing project mechanism.
  - Before the first production release, verify every applicable control, configuration, and test described below.
  - Prototypes that are not production-deployable must be clearly marked and must not be exposed publicly or handle real sensitive data.

## Non-negotiable

- **Access Control:** Authenticate and authorize server-side for every protected action and resource; bind the authenticated identity to the requested resource. Never trust client-side checks or user-supplied identifiers.
- **Untrusted Input:** At each trust boundary validate type, range, and format; use parameterized queries, contextual output encoding, safe path handling, shell-free process invocation, and destination allow-lists as applicable, and never feed untrusted data to unsafe deserializers.
- **Secrets & Credentials:**
  - Never commit or expose real secrets, or log credentials, tokens, or PII.
  - Never ship, seed, initialize, display, or document working default, demo, or shared accounts or credentials—especially privileged—including through bundled data, setup, fixtures, UI, or docs.
  - Bootstrap must use unique externally supplied credentials or one-time activation; artificial credentials belong only in isolated tests or non-runnable examples. For a first administrative account, require the credential from external configuration and fail startup when it is absent, or generate a random one at first start and disclose it once through a channel only the operator can read—an interactive console or a restricted file, never the UI or application logs, which in containers includes stdout. A placeholder the user is merely advised to change is still a shipped default.
  - Persistent security keys must come from external configuration or secret management, remain stable across processes, instances, and restarts until explicit rotation, and be required at startup; never substitute ephemeral keys.
- **Preserve Security:** Never weaken a control to make code work or tests pass. A control that can be switched off is weakened—including behind a flag, environment variable, or "temporary" bypass, however clearly it is labelled and whatever the deadline.

## Apply

- **Secure by Default:** Least privilege, deny-by-default, smallest attack surface; fail closed on missing, invalid, or ambiguous security context. Run privileged operations under a separate identity; do not widen an existing context to reach them.
  - Production configurations must enable applicable platform protections; weaker development settings must be explicit and local-only, and must never disable a control.
  - Carry all traffic that leaves the machine over TLS—plain HTTP only on the loopback interface—and bind to loopback by default. Make a non-loopback bind require TLS to be in place—terminated by the application, or by an upstream terminator declared through required configuration—and fail startup when it is unconfigured; an assumed terminator is an absent one. With a non-loopback bind, enable `Secure` cookies, HSTS, and matching proxy trust, and let any plain-HTTP listener do nothing but redirect. When exposure beyond localhost is out of scope, say so and name the TLS step required before it.
  - For browser content, use `Secure`, `HttpOnly`, appropriate `SameSite`, CSP, HSTS, `X-Content-Type-Options`, and framing restrictions, and protect state-changing requests authenticated by cookies or other ambient credentials against cross-site request forgery; introduce or tighten these incrementally so existing pages, clients, and intended embedding keep working, and document whether the application or deployment layer enforces them.
  - Restrict CORS to an explicit origin allow-list matched exactly, and expose only the methods and headers actually needed; echo only an `Origin` that matched the allow-list—never reflect it unvalidated—and never combine a wildcard with credentials.
- **Authentication Abuse Resistance:**
  - Where an organization-managed identity provider is used, do not retain parallel local passwords for workforce or privileged access without a justified need.
  - Rate-limit login, registration, password-reset, verification, and comparable expensive or account-creating endpoints.
  - Apply limits by account or identifier and by client source, without allowing either dimension to bypass the other; use a shared, server-side store or an upstream control that remains effective across processes and instances.
  - Make responses non-enumerating, cap request sizes before costly password hashing or external work, and log throttling events.
  - Deliver one-time codes and verification links only through the separate channel they are addressed to; never return, display, or log them in the requesting response, UI, or URL, including for development convenience. Make them single-use and short-lived, verify them server-side, and until verification succeeds issue only a limited pre-authentication state, never a full session.
  - Rotate the session identifier on login and on any privilege or authentication-state change; invalidate sessions server-side on logout and on password or second-factor change, and enforce idle and absolute timeouts.
- **Proven Mechanisms:** Reuse established sound mechanisms and maintained libraries; flag weak ones. Never hand-roll crypto, authentication, or sessions.
  - Use vetted algorithms and a CSPRNG; no MD5/SHA-1 for security, insecure RNGs for tokens, or fast password hashes—use Argon2, scrypt, bcrypt, or PBKDF2 with sound parameters.
  - For federated auth (OAuth 2.0 / OIDC), use the authorization-code flow with PKCE; never the implicit flow. Validate `state`, exact-match `redirect_uri` against an allow-list, and every JWT you accept (signature with an allow-listed algorithm, `iss`, `aud`, and `exp`); request least-privilege scopes and rotate refresh tokens.
  - Enforce the password-hash algorithm's input limit on UTF-8 bytes before hashing or verification (bcrypt: 72); reject excess input instead of relying on library truncation, and apply this at password set or change so existing accounts are not locked out.
- **Dependencies:** Prefer existing dependencies.
  - Before adding or executing a new package, verify its exact name and expected upstream source using current authoritative information; package existence or model confidence alone is not proof of trust.
  - Follow the project workflow, review manifest, lockfile, and transitive changes, and do not run unreviewed install scripts.
  - For existing applications, report missing safeguards encountered in scope; for greenfield applications, commit a lockfile and use frozen CI/deployment installs (for example, `npm ci` or `pip install --require-hashes`) and dependency scanning by default.
- **Errors & Logging:** Return no stack traces, internal paths, or raw exceptions. Log security-relevant events with enough context to investigate, but no sensitive data.
- **Resource Limits:** Bound input-driven work with timeouts and size or pagination caps; avoid unbounded loops and user-supplied regex.
- **Production vs. Development:** Keep mocks, bypasses, debug modes, development servers, and weakened settings out of production. Development tooling means mocks, fixtures, seed data, and debug output; a switch that turns off authentication, authorization, CSRF, or transport security is not development tooling and belongs nowhere. Development tooling must be opt-in and non-public; treat uncertain contexts as production. Docs must distinguish local development and provide a production-safe start or deployment path.
- **Security Tests:** When a change affects a security control or trust boundary, add intended-behavior and representative negative or abuse tests.
  - Verify applicable unauthorized, malformed, cross-user or cross-tenant, missing-context, and boundary cases fail closed.
  - Test authentication limits and their reset/expiry behavior without relying solely on in-process state; test password-length boundaries in bytes, including multibyte UTF-8 input.
  - For out-of-band verification, test that the triggering response body, logs, and URL contain no code, and that the post-verification endpoint rejects a pre-authentication session.
  - For a greenfield deployable application, or an existing application when the change affects these areas, verify missing or invalid required configuration blocks startup, applicable production controls and headers work, and clean initialization creates no known credential or unintended privileged account.
  - For cookie-based or other ambient browser authentication, test every state-changing browser action—including administrative actions—rejects a forged cross-site request, whether the guard is a token or an origin check.
  - Use the existing test framework. Report findings or, if testing is impossible, the reason and residual risk.
- **LLM-Powered Features:** When a change builds or changes an LLM-powered feature, treat prompts, model and tool outputs, retrieved content, and memory as untrusted—validate them and never let them override policy or authorization. Authorize each tool action server-side with least privilege, require human approval for consequential or irreversible actions, isolate data and memory across tenants, and review against the OWASP Top 10 for LLM and Agentic Applications.

## Before Completion

- **Review and Report:** Review the changed diff and fix introduced findings.
  - Actively notify the user of every concrete security issue found in scope, including issues already fixed, with its location, realistic impact, status, and next step. Do not present a scoped review as a full security audit.
  - Close the response that delivers the work with a short security note of a few lines, even when nothing was found: the controls the change relies on, significant security decisions and trade-offs, tests and results, what was deliberately left out, and residual risks, assumptions, or verification gaps; say plainly when none remain. Keep it proportional to the change.
  - For greenfield work, report readiness for the applicable controls required before the first production release.
