# Example Application Behavior Specification

## Purpose

This example translates the observable, mandatory application behavior from `appsec-requirements-example.yaml` into a single OpenSpec specification. Implementation-only secure-coding guidance remains in the YAML catalog.

## Requirements

### Requirement: AC-003

Login, registration, credential recovery, verification, token issuance, and other abuse-prone endpoints MUST apply bounded request sizes and rate limits by both account or identifier and client source using a control effective across application instances.

**Category:** Authentication & Access Control

**Source:** <https://appsec.int.example.com/req/authentication-access-control#ac-003>

#### Scenario: Repeated authentication attempts are throttled

- **GIVEN** repeated authentication attempts target one account from changing client sources
- **WHEN** either the account or a client source exceeds its permitted rate
- **THEN** the application MUST throttle the attempts across every application instance

### Requirement: AC-004

Workforce and privileged users MUST authenticate through the organization-managed identity provider using OIDC authorization code with PKCE or SAML, and privileged access MUST require phishing-resistant MFA where supported. A parallel local password path requires a documented operational need.

**Category:** Authentication & Access Control

**Source:** <https://appsec.int.example.com/req/authentication-access-control#ac-004>

#### Scenario: Privileged workforce user starts a session

- **GIVEN** a privileged workforce user has no authenticated session
- **WHEN** the user signs in
- **THEN** the application MUST use the organization-managed identity provider
- **AND** privileged access MUST require phishing-resistant MFA where supported

### Requirement: AC-006

Every request for a protected object MUST authorize the authenticated identity against that object's owner, tenant, state, and requested action. User-supplied identifiers and token possession alone MUST NOT grant access.

**Category:** Authentication & Access Control

**Source:** <https://appsec.int.example.com/req/authentication-access-control#ac-006>

#### Scenario: User requests a resource from another tenant

- **GIVEN** an authenticated user supplies the identifier of a resource owned by another tenant
- **WHEN** the user requests that resource by its identifier
- **THEN** the application MUST deny access regardless of token possession or identifier validity

### Requirement: EH-002

Client error responses MUST NOT expose stack traces, query text, internal paths, credentials, tokens, or raw exceptions. Diagnostic details MAY be recorded only in access-controlled server-side logs after sensitive values are removed.

**Category:** Error Handling & Security Events

**Source:** <https://appsec.int.example.com/req/error-handling-security-events#eh-002>

#### Scenario: Request processing fails unexpectedly

- **WHEN** request processing raises an unexpected error
- **THEN** the application MUST return a generic error response without internal details
- **AND** any retained diagnostic MUST be access-controlled and contain no sensitive values

### Requirement: WEB-001

Applications that use cookie-based or other ambient browser credentials MUST reject forged cross-site state-changing requests with a framework CSRF control, a session-bound token, or a validated same-origin signal. SameSite cookies provide defense in depth and state-changing actions MUST NOT use HTTP GET.

**Category:** Web & Frontend Security

**Source:** <https://appsec.int.example.com/req/web-frontend-security#web-001>

#### Scenario: Cross-site state-changing request

- **GIVEN** a user has an authenticated browser session
- **WHEN** another site submits a state-changing request without a valid token or same-origin signal
- **THEN** the application MUST reject the request
