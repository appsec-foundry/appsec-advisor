# Example Application Behavior Specification

## Purpose

This example translates the observable, mandatory application behavior from `appsec-requirements-example.yaml` into a single OpenSpec specification. Implementation-only secure-coding guidance remains in the YAML catalog.

## Requirements

### Requirement: AC-003

The application MUST rate-limit every externally reachable API endpoint.

**Category:** Authentication & Access Control

**Source:** <https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html>

#### Scenario: Repeated API requests are throttled

- **GIVEN** a client is sending requests to an externally reachable API endpoint
- **WHEN** the client exceeds the permitted request rate
- **THEN** the application MUST throttle further requests from that client

### Requirement: AC-004

The application MUST authenticate end users through a central identity provider using OIDC or SAML and mandatory MFA.

**Category:** Authentication & Access Control

**Source:** <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html>

#### Scenario: End user starts a session

- **GIVEN** an end user has no authenticated session
- **WHEN** the user signs in
- **THEN** the application MUST authenticate the user through the central identity provider
- **AND** the identity provider MUST require MFA

### Requirement: AC-006

The application MUST authorize access to each requested resource against the authenticated identity.

**Category:** Authentication & Access Control

**Source:** <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>

#### Scenario: User requests another user's resource

- **GIVEN** an authenticated user does not own the requested resource and has no delegated access
- **WHEN** the user requests that resource by its identifier
- **THEN** the application MUST deny access

### Requirement: EH-002

The application MUST return generic error messages to clients and retain detailed diagnostics only in server-side logs.

**Category:** Error Handling & Security Events

**Source:** <https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html>

#### Scenario: Request processing fails unexpectedly

- **WHEN** request processing raises an unexpected error
- **THEN** the application MUST return a generic error response without internal details
- **AND** the application MUST record the detailed diagnostic server-side

### Requirement: WEB-001

The application MUST protect session-authenticated state changes against cross-site request forgery and MUST NOT perform them through HTTP GET.

**Category:** Web & Frontend Security

**Source:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>

#### Scenario: Cross-site state-changing request

- **GIVEN** a user has an authenticated browser session
- **WHEN** another site submits a state-changing request without valid CSRF proof
- **THEN** the application MUST reject the request
