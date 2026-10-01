# Proposal: classify route guards by their effect

Status: proposal, not implemented. Decisions marked **D1–D3** need operator confirmation before any change to FE-14 or the route-inventory contract.

## Problem

Route authorization is decided from guard names. `route_inventory.py` matches identifiers such as `isAuthorized` or `requireRole` and never looks at what the guard does, so `authz_signal` is regex-derived only and `handler_resolver.py` decides authentication alone. On the juice-shop replay every one of 246 routes has `authz_signal: unknown`, and three guard shapes produce most of the remaining false positives:

- A role gate (`isAccounting()`: compares a claim, answers 403) is invisible, so its routes are `missing_authz_suspect` and AUTHZ-301 fires on `PUT /rest/order-history/:id/delivery-status`.
- A deny-all gate (`denyAll()`: rejects unconditionally) counts as authentication, so deny-all routes with an id are IDOR suspects.
- An identity injector (`appendUserId()`: overwrites `req.body.UserId` from the verified token) is invisible to `source_auth_scanner.py`, which raises 17 AUTHZ-001 findings on bodies whose owner id the middleware already set.

A fourth shape became visible when the resolver started reading handler factories completely: a global middleware that reads and verifies a token but never rejects (`updateAuthenticatedUsers()`). FE-14 requires "no credential read" for `absent`, so 51 juice-shop routes that were `absent` only because the resolver used to stop at the factory's first line are now `unknown`, and AUTHZ-302 drops from 17 to 1 there.

## Proposal

### 1. One classifier for every resolved chain element

`handler_resolver.py` already resolves each middleware and handler to code bodies. Add one classification per element with a closed vocabulary:

| Effect | Evidence required in the element's code |
|---|---|
| `authenticates` | credential read, verify call, rejecting branch (today's `verified`) |
| `optional_identity` | credential read or verify call, no rejecting branch anywhere in the element |
| `role_gate` | comparison of a role, scope or claim of the verified identity, followed by a 401/403 reject |
| `deny_all` | a reject on every path, no `next()` / handler continuation |
| `identity_injection` | assignment of a request field (`req.body.X`, `req.params.X`, `req.query.X`) from the verified identity |
| `decode_only` | token decoded without verification (today's value) |
| `neutral` | fully resolved, none of the above |
| `unresolved` | not every body resolved |

Each effect cites the file and line that proves it, like `authn_handler_evidence` does today. The classifier reads code only, never names, so `isAccounting` and `requireRole` are treated alike.

### 2. Route inventory carries the effects

Add an optional `guard_effects` list (`{effect, file, line}`) and `identity_fields` (request fields set by an injector) to each route in `schemas/route-inventory.schema.json`. Derive the existing signals from them so current consumers keep working:

- `authz_signal` becomes `present` for a `role_gate` or `deny_all` element; name matches stay as the fallback when the chain is unresolved.
- `missing_authz_suspect` is not set when a `role_gate` or `deny_all` element is present.
- `authn_signal` keeps FE-14 semantics; D1 decides the `optional_identity` case.

### 3. Consumers

- `authz_confirm.py`: no AUTHZ-301 on a route with `role_gate` or `deny_all`. A route with only an authenticating gate stays eligible, because a role gate does not prove object ownership.
- `source_auth_scanner.py`: suppress AUTHZ-001 when the finding's handler belongs to a route whose `identity_fields` contains the field the rule matched. This needs a handler-file-and-line to route join, which the inventory already provides.
- `architecture_coverage_checks.py`: no rule change; the rules read the derived signals.
- CWE: a route with a `role_gate` but a failed ownership check stays CWE-639; CWE-863 is reserved for a later rule that compares gate roles across routes and is out of scope here.

## Decisions needed

- **D1 (FE-14):** Does an `optional_identity` element keep a route from `absent`? (a) Yes, keep FE-14 as is: such routes stay `unknown` and remain hypotheses. This is the safe default and the current behavior. (b) No: an element with no rejecting branch anywhere in its resolved code does not authenticate, like `decode_only`. This restores the juice-shop AUTHZ-302 findings, but a reject hidden in unresolved helper code would then produce a hard finding. Recommendation: (b), limited to elements whose helpers all resolved.
- **D2:** Does `deny_all` also set `authn_signal: present`? Recommendation: yes, because no caller reaches the handler.
- **D3:** Is a `role_gate` enough to clear `missing_authz_suspect`? Recommendation: yes for the suspect flag, but AUTHZ-301 still requires an ownership predicate in the handler.

## Evidence plan

Each effect gets a neutral fixture pair in `tests/test_handler_resolver.py`: the effect's code shape under two unrelated names, plus a negative case whose name suggests the effect but whose code does not (`requireRole` that only logs). Replay juice-shop before and after and record the deltas for AUTHZ-001, AUTHZ-301, AUTHZ-302 and `missing_authz_suspect`. Expected: AUTHZ-001 17 → 0 on `appendUserId` routes, AUTHZ-301 on `delivery-status` removed, deny-all routes leave the IDOR suspect list.

## Out of scope

Framework coverage (Rails, Laravel, Go, NestJS `@UseGuards`, Spring `SecurityFilterChain`), mount-guard affinity to its router object, and the shared CWE/severity table.
