# Threat Model — Full Change Log

> Complete, uncapped audit trail of every assessment run for this threat
> model: all added, changed, and removed findings, mitigations, abuse
> cases, instances, and components. The report's own Change Log section is
> a summarized window of this history. Generated deterministically from
> `threat-model.yaml`; do not hand-edit.

## v1 — 2026-07-07 05:56 CEST · full · standard · sonnet-economy

_commit `e04c6c1` · 59 findings · delta basis: initial_

### Added
- **Findings (59):**
  - T-001 — SQL injection authentication bypass — AuthLoginService.java:42
  - T-002 — Insecure JWT Verification — JWTValidator.java:104
  - T-003 — Hardcoded H2 Admin Credentials — application-unsafe.properties:2
  - T-004 — SQL Injection — AuthenticationVulnerability.java:68
  - T-005 — Unauthenticated H2 Web Console Allows — application-unsafe.properties:9
  - T-006 — OS command injection — CommandInjection.java:47
  - T-007 — XXE with external DTD access enabled globally — XXEVulnerability.java:59
  - T-008 — Hardcoded JWT HMAC key 'pass**** (8 chars)' on:6 — SymmetricAlgoKeys.json:6
  - T-009 — Hardcoded H2 database credentials committed — application-unsafe.properties:1
  - T-010 — SSRF attacker-controlled URL fetched without scheme — SSRFVulnerability.java:97
  - T-011 — Phishing credential-harvester hosted in static directory — fake-login.js:6
  - T-012 — Open redirect attacker-controlled — Http3xxStatusCodeBasedInjection.java:92
  - T-013 — Unauthenticated Ollama Management API Exposed on Host — docker-compose.yml:21
  - T-014 — Unpinned GitHub Actions Tag-Only References Across All Workflows — docker.yml:19
  - T-015 — No SCA Tooling in CI Vulnerable Dependencies Shipped Undetected — gradle.yml:28
  - T-016 — Persistent XSS comment content — PersistentXSSInHTMLTagVulnerability.java:100
  - T-017 — LDAP injection — LDAPInjectionVulnerability.java:115
  - T-018 — Unrestricted file upload with no type or — UnrestrictedFileUpload.java:165
  - T-019 — Prompt Injection — docker-compose.yml:57
  - T-020 — Mutable :latest Image Tags Allow Supply-Chain — docker-compose.yml:19
  - T-021 — Cross-Site Scripting — vulnerableApp.js:82
  - T-022 — No structured security audit log for authentication — AuthLoginService.java:86
  - T-023 — Missing Security Event Logging — AuthLoginService.java:66
  - T-024 — Plaintext pass**** (8 chars) returned in API — AuthenticationVulnerability.java:145
  - T-025 — RSA private key and PKCS12 keystore accessible as — JWTAlgorithmKMS.java:41
  - T-026 — MD5/SHA-1 pass**** (8 chars) hash and algorithm — AuthenticationVulnerability.java:182
  - T-027 — GH_TRAFFIC_TOKEN Embedded in Git Remote URL Credential Exposure — stats.yml:92
  - T-028 — GitHub Actions workflow-level permissions block — docker.yml:1
  - T-029 — Third-party GitHub Actions pinned to commit SHA — docker.yml:25
  - T-030 — Base image must be digest-pinned — Dockerfile.base:1
  - T-031 — Unauthenticated Mailpit Web UI exposes all captured — docker-compose.yml:82
  - T-032 — Plaintext Passwords Committed in SQL Data Files — data.sql:7
  - T-033 — Path traversal attacker-controlled — PathTraversalVulnerability.java:82
  - T-034 — Username enumeration — AuthenticationVulnerability.java:286
  - T-035 — MD5 and SHA-1 used for pass**** (8 chars) hashing — AuthenticationVulnerability.java:171
  - T-036 — Ollama API Host-Port Binding Exposes Model Inventory — docker-compose.yml:21
  - T-037 — No rate limiting or account lockout on — AuthLoginService.java:86
  - T-038 — H2 Console Permits Heap-Exhaustion and — application.properties:4
  - T-039 — No rate limiting or account lockout on — AuthenticationVulnerability.java:61
  - T-040 — Unbounded file upload size enables disk — UnrestrictedFileUpload.java:364
  - T-041 — No Rate Limiting on Inference Endpoints Allows CPU/GPU — docker-compose.yml:65
  - T-042 — No rate limiting at Nginx edge all backend — docker-compose.prod.yml:31
  - T-043 — User role stored in non-HttpOnly, client-mutable — IDORLoginController.java:141
  - T-044 — MD5 pass**** (8 chars) hashing enables offline cracking and — AuthLoginService.java:149
  - T-045 — Container Runs as Root No USER Directive — Dockerfile.base:1
  - T-046 — Pull_request_target EoP Privileged CI Execution on — onboard_sasanlabs.yml:4
  - T-047 — Missing Workflow Permissions Block Implicit Full GITHUB_TOKEN — docker.yml:12
  - T-048 — H2 Admin User Enables OS-Level File Write — application-unsafe.properties:1
  - T-049 — Insecure Direct Object Reference — IDORVulnerability.java:71
  - T-050 — Unauthenticated Ollama Model Management API Permits — docker-compose.yml:21
  - T-051 — SMTP sender identity not verified any container can — docker-compose.yml:86
  - T-052 — Open redirect pass-through Nginx — Http3xxStatusCodeBasedInjection.java:57
  - T-053 — Container image signing — onboard_sasanlabs.yml:1
  - T-054 — Npm/pnpm/yarn uses --ignore-scripts — Dockerfile.base:1
  - T-055 — GITHUB_TOKEN scope minimization — onboard_sasanlabs.yml:1
  - T-056 — SMTP cleartext transmission with insecure auth enabled — docker-compose.yml:87
  - T-057 — Unauthenticated Mailpit REST API allows bulk message — docker-compose.yml:82
  - T-058 — Mailpit container lacks user namespace restriction and — docker-compose.yml:76
  - T-062 — Data disclosure — docker-compose.yml:41
- **Mitigations (58):**
  - M-001 — Architecture review: validate Data disclosure through cleartext transport
  - M-002 — Apply least-privilege permissions
  - M-003 — Pin third-party dependencies to immutable versions
  - M-004 — Pin the container base image to an immutable digest
  - M-005 — Sign and verify release artifacts
  - M-006 — Disable untrusted package install scripts
  - M-007 — Apply least-privilege permissions
  - M-008 — Use parameterized database queries
  - M-009 — Enforce JWT signature and algorithm verification
  - M-010 — Move secrets to a managed secret store
  - M-011 — Use parameterized database queries
  - M-012 — Disable H2 web console entirely in non-development deployments and enforce network-level
  - M-013 — Invoke `ping` with an argument array rather than a shell string, and validate input
  - M-014 — Disable XML external entity (XXE) resolution
  - M-015 — Move cryptographic keys to a managed secret store
  - M-016 — Move secrets to a managed secret store
  - M-017 — Validate and allowlist outbound request targets
  - M-018 — Validate redirect targets against an allowlist
  - M-019 — Validate redirect targets against an allowlist
  - M-020 — Require authentication on every exposed endpoint
  - M-021 — Pin the container base image to an immutable digest
  - M-022 — Pin the container base image to an immutable digest
  - M-023 — Encode output instead of bypassing the framework sanitizer
  - M-024 — Apply `Filter.encodeValue` escaping to all user-supplied LDAP filter components
  - M-025 — Validate uploaded file content type and extension against a strict allowlist before
  - M-026 — Implement input validation and system-prompt isolation on the LLMForge inference endpoint
  - M-027 — Pin all Docker image references to immutable SHA256 digests and verify signatures
  - M-028 — Encode output instead of bypassing the framework sanitizer
  - M-029 — Emit a structured security audit log entry on every login success, failure, and session
  - M-030 — Add security audit logging
  - M-031 — Stop storing sensitive data in cleartext
  - M-032 — Move cryptographic keys to a managed secret store
  - M-033 — Replace the weak cryptographic algorithm
  - M-034 — Replace credential-in-URL git push with GITHUB_TOKEN or SSH deploy key
  - M-035 — Require authentication on every exposed endpoint
  - M-036 — Move secrets to a managed secret store
  - M-037 — Constrain file paths to a safe base directory
  - M-038 — Return a single generic error message for all authentication failures regardless of the
  - M-039 — Hash pass**** (8 chars)s with a strong, salted algorithm
  - M-040 — Stop exposing internal information to clients
  - M-041 — Rate-limit and lock out repeated authentication attempts
  - M-042 — Offload CPU-bound work and bound execution time
  - M-043 — Rate-limit and lock out repeated authentication attempts
  - M-044 — Configure a global multipart file size limit and enforce per-upload size validation in
  - M-045 — Add per-IP and per-session rate limiting on the Nginx facade for /llmforge routes and
  - M-046 — Add limit_req_zone and limit_req directives to the Nginx facade template for all proxy
  - M-047 — Move authorization role to server-side session or a signed/encrypted token; never trust
  - M-048 — Hash pass**** (8 chars)s with a strong, salted algorithm
  - M-049 — Drop unnecessary privileges in build and runtime
  - M-050 — Pin third-party dependencies to immutable versions
  - M-051 — Enforce server-side authorization on every endpoint
  - M-052 — Drop unnecessary privileges in build and runtime
  - M-053 — Enforce object-level (ownership) authorization
  - M-054 — Enforce server-side authorization on every endpoint
  - M-055 — Restrict SMTP relay to the application backend container by disabling accept-any-auth in
  - M-056 — Validate redirect targets against an allowlist
  - M-057 — Enable SMTP TLS and remove insecure auth allowance for any shared or multi-host deployment
  - M-058 — Enable web UI authentication to protect the Mailpit REST API from unauthenticated
- **Abuse cases (6):** AC-T-001, AC-T-002, AC-T-003, AC-T-004, AC-T-005, AC-T-006
- **Components (7):** auth, ci-cd-pipeline, email-service, h2-database, java-backend, llm-service, nginx-facade

### Scope
- **Re-analyzed:** auth, ci-cd-pipeline, email-service, h2-database, java-backend, llm-service, nginx-facade

> first full scan
