# Design proposal: provider-neutral assessment engine

**Status:** concept only, not implemented. This revision changes no requirements or registered decisions. Formal wording and its plain-language summary need operator confirmation before changes to those sources.

**Scope:** the deterministic controller path (`orchestration_controller.py assess`), not the legacy skill/agent path selected with `APPSEC_SINGLE_REPO_CONTROLLER=0`.

**Goal:** run assessments through Claude CLI, direct model APIs, or an operator-selected AI gateway such as LiteLLM. Configure hosts and models in one place while preserving deterministic validation, budget accounting, and source authorization. Extract an installable Python engine only after a second provider works through the complete pipeline.

## Current state

The implementation references below were checked on 2026-10-17. They describe the controller path, not every plugin entry point.

### Transport and schema boundaries

- [The headless launcher](../../../scripts/run-headless.sh) hands controller assessments to `orchestration_controller.py assess`, but still checks Claude availability and, in subscription mode, Claude authentication before that handoff.
- [The transport protocol](../../../scripts/runtime/analyst_host.py) exposes `invoke(system, prompt, schema, timeout_s, should_stop) -> HostReply(payload, usd)`.
- [The controller](../../../scripts/orchestrator/orchestration_controller.py) constructs `ClaudeCliTransport` in `_assessment_cli_host_factory`; `assess_repositories` also accepts an injected host factory. Semantic roles and renderers obtain their transports through this seam.
- This factory configures tool-less calls in private work directories. Claude-specific options include effort, thinking limits, prompt caching, environment handling, and diagnostic events. Authentication hints also name Claude.
- [The assessment exchange](../../../scripts/runtime/assessment_host.py) already separates the complete artifact contract from a projected host schema through `response_schema()` and `host_schema()`. It validates the complete contract outside the model and distinguishes correctable model answers from transport contract failures.
- The projection is currently tailored to the Claude host. A second provider needs an explicit projection and decoding contract; passing existing JSON Schemas unchanged is insufficient.

### Model selection and depth

The controller selects models through [the resolver](../../../scripts/runtime/resolve_config.py), `SEMANTIC_ROLE_MODEL_KEYS`, and `RENDERER_MODEL_KEYS`. Agent frontmatter does not select models on this path. The controller still supplies an `actor_discovery_model` fallback outside the resolver.

Depth controls both model defaults and the amount of work, including evidence-verifier limits, abuse-case verification, and cheap STRIDE. These concerns can be separated without changing either behavior.

The effective defaults include controller-specific corrections in `resolve_assessment()`: the default STRIDE selection moves from Sonnet 4.6 to Sonnet 5, and default Recon moves from Haiku to Sonnet 5. Explicit overrides remain subject to the current precedence. The source comments record unsuccessful runs behind those corrections. Migration must preserve the fully resolved role matrix for each depth, including these corrections, rather than copy only `resolve_reasoning_model()` defaults.

### Budget accounting

[AssessmentBudget](../../../scripts/runtime/assessment_jobs.py) reserves resources for required completion work under REQ-FLW-008 and learns estimates from accepted jobs. Its [DiscoveryBudget base](../../../scripts/runtime/multi_repo_discovery.py) reserves each call before creating the transport.

A successful reply requires finite, nonnegative numeric cost accounting. A transport failure, timeout, or cancellation without a cost report is charged the full reservation. Invalid accounting blocks further calls. The fallback depends on the backend enforcing a known spending bound; actual billed cost and conservative budget charge are different quantities.

### Packaging dependencies

The controller is executable on its own inside the plugin checkout, but is not yet an independent package. It starts scripts by filesystem path, fingerprints runtime files plus `.claude-plugin/plugin.json`, and uses plugin-relative resource paths. The resolver reads functional configuration under `skills/audit-security-requirements/`. Moving data to `importlib.resources` alone does not remove these dependencies.

## Proposed architecture

The provider-neutral core owns orchestration, source grants, canonical artifact schemas, validation, budgets, retries, and run state. Provider adapters own protocol encoding, provider settings, credentials, authentication preflight, schema projection, usage decoding, and failure hints. Only an adapter handles its provider-specific environment variables, including `CLAUDE_*` where required.

### Host profiles and protocols

A host profile selects a registered adapter and supplies validated data: endpoint, credential reference, model mappings, capabilities, and pricing policy. Configuration cannot name arbitrary Python classes, import paths, shell commands, or authentication executables.

| Host profile | Adapter or protocol | Intended role |
|---|---|---|
| `claude-cli` | Existing Claude CLI transport | Default; preserve current behavior. |
| `openai-api` | Direct OpenAI API adapter | First independent provider to validate the abstraction. |
| `organization-gateway` | Explicit OpenAI-compatible API dialect | Gateway access, including LiteLLM; qualify the configured route separately. |
| `anthropic-api` | Direct Anthropic API adapter | Additional adapter after the first complete API path. |
| `claude-cli/bedrock` | Claude CLI with Bedrock configuration | Additional profile with its own authentication and capability checks. |

One assessment selects one host. Roles may use different models on that host. Mixing direct providers and gateways within one run is outside the first delivery. A host name identifies a configured service, not necessarily the company that operates the underlying model.

Use direct, tool-less APIs for the initial alternative provider. A different agent CLI would need independent evidence that it satisfies the same isolation contract; no claim about current Codex CLI restrictions is needed for this design.

### Gateway access, including LiteLLM

The intended data flow is `controller -> API adapter -> authorized gateway -> authorized model backend`. Source excerpts and business context cross both service boundaries. The client authenticates to the gateway; the gateway manages upstream provider credentials. LiteLLM documents this separation and configuration by gateway base URL and model name in its [client setup guide](https://docs.litellm.ai/docs/proxy/client_setup/overview).

The engine connects to an existing gateway. Installing, deploying, or administering LiteLLM is outside this proposal, and using its HTTP API does not require embedding its Python SDK.

Gateway compatibility is qualified per protocol, gateway version, route, and model. An OpenAI-compatible label does not establish support for structured output, token limits, cancellation, or accurate usage. Profiles explicitly select an API dialect, such as Responses or Chat Completions; the adapter does not silently switch protocols after sending repository data.

The first gateway integration uses fixed, versioned model aliases backed by approved model deployments, including Claude. Gateway-side retries, fallbacks, and dynamic model routing are disabled for those routes unless their complete spending bound and destination policy can be established. A gateway budget dashboard does not replace per-call admission in the controller. Supporting dynamic routing is a later extension, not an implicit benefit of compatibility.

The gateway operator owns upstream access, retention, logging, and route configuration. Before qualification, record the approved upstream destination set and a route revision supplied by that operator. A client cannot infer those properties from an alias or prove them from a successful response. If routing identity cannot be established, the profile cannot promise stable resume behavior or a fixed backend. A changed route revision requires a new run identity.

### Transport and schema contract

The core sends only bounded text and an adapter-neutral response contract. Adapters expose no model-executable tools. Trusted adapters may read credential configuration and maintain private transport files; this does not grant the model filesystem access.

Keep three distinct representations:

1. The canonical artifact schema and exchange envelope, owned and validated by the controller.
2. A provider-compatible wire schema, derived by the adapter without changing the canonical contract.
3. A deterministic decoder that maps wire output back to the canonical representation before controller validation.

For example, optional properties may need an explicit nullable wire representation and schema-aware decoding. Do not drop arbitrary nulls or unknown fields to make an answer validate. Preserve canonical meanings for absent and null values. Full-schema rejection remains eligible for the existing bounded correction path when it is a model answer error; a broken wire contract is a transport failure.

OpenAI Strict Structured Outputs requires all properties to be required and supports only a JSON Schema subset. Existing merger and renderer schemas therefore need deliberate adaptation. The current host projection is a starting point, not proof of compatibility. See the [official structured-output documentation](https://developers.openai.com/api/docs/guides/structured-outputs).

Before spending on a run, qualify the schemas for all selected roles and exchanges, including retrieval envelopes, correction calls, and optional synthesis. Reject only where no supported projection and decoder preserve the canonical contract. Do not require the provider to enforce every semantic constraint that the controller already validates.

Each adapter also:

- Maps provider failures to the controller's error categories, preserving authentication failures, refusals, truncated output, timeouts, and malformed responses as distinguishable outcomes.
- Honors the call deadline and cancellation without assuming a client disconnect stops remote billing.
- Enforces response-size limits during receipt, before parsing an unbounded response.
- Supplies validated usage and cost metadata on successful calls; preserves unknown usage on failures rather than inventing zero cost.
- Leaves retry admission to the controller. SDK retries are disabled; any gateway-internal attempts need the qualification described above.

### Unified configuration

One schema-validated user file, for example `~/.config/appsec-advisor/models.yaml`, selects the host and model overrides. Built-in profiles provide complete role mappings for every supported depth. The first migration preserves Claude's effective defaults and current explicit overrides exactly.

The following is an illustrative configuration overlay, not an implemented format or complete gateway setup. The reserved example domain and model aliases must be replaced with an operator-approved service. `pricing_policy` references a separately validated policy with real bounds; it is not a price value or a bundled free model. A configured gateway needs its complete qualified host/depth defaults in addition to this overlay.

```yaml
host: organization-gateway
hosts:
  organization-gateway:
    adapter: openai-compatible
    protocol: chat-completions
    base_url: https://models.example.org/v1
    credential_env: APPSEC_GATEWAY_API_KEY
    route_revision: assessment-route-v1
    pricing_policy: organization-assessment-v1
    tiers:
      standard: assessment-standard-v1
      reasoning: assessment-reasoning-v1
profiles:
  thorough:
    stride_analyzer: {tier: reasoning}
role_overrides:
  evidence_verifier: {model: assessment-verifier-v1}
```

Role settings use a discriminated choice: either a tier or an explicit model ID/alias, never both. A tier resolves through the selected host. Existing model environment variables and CLI options are explicit model overrides. Unspecified roles inherit the complete qualified host/depth profile; unresolved roles, tiers, prices, or capabilities fail before model calls.

Resolution happens once in `resolve_assessment()`, including actor discovery. Preserve existing precedence among CLI options and environment variables, then apply user configuration over host/depth defaults. Organization restrictions constrain the final selection and cannot be overridden by a higher-precedence model choice. Depth continues to control work volume independently of the model mapping.

The selected endpoint, API dialect, role-to-model mapping, adapter capabilities, schema adapter version, pricing policy revision, and gateway route revision enter the non-secret run identity. Resume compares that identity before reusing work. Reports name the selected host and requested model alias; a validated resolved backend may also be shown, but an unknown backend is not presented as known. Credentials never enter identity, reports, or logs.

### Configuration trust and destinations

Host selection, endpoint URLs, credential references, and routing policies come only from explicit operator configuration or a trusted organization profile. Target repositories and model output cannot set or override them, including through repository-local configuration discovery. A profile path supplied by the operator does not make repository-controlled contents authoritative automatically.

Validate destination scheme, host, port, and allowed network ranges before connection and at connection time. Remote endpoints use verified TLS. Disable redirects so credentials and source excerpts cannot move to another origin. Private gateways are supported through explicit operator-approved destination ranges; metadata endpoints and unrelated internal destinations remain denied. No arbitrary header map or repository-supplied credential forwarding is part of the initial configuration.

Use a gateway credential restricted to the required model aliases, not an administration key. Credentials are supplied externally, with only their configured reference in the file. Missing or invalid authentication fails before source transmission. Authentication preflight belongs to the selected adapter; API and gateway runs must not require a Claude executable or Claude login.

### Prices, reservations, and unknown costs

Keep USD-denominated budgets for this phase. Token-only budgets and changes to the product promise of REQ-FLW-008 are outside this revision.

Admission requires a conservative cost bound before transmission. An API adapter accounts for the complete input, all billable output including reasoning, and applicable cache charges or gateway markups. It derives the provider's output limit from the remaining allowance and rejects calls whose input plus minimum output cannot fit. Missing or invalid pricing, or a backend that cannot enforce the required bound, stops the call.

Successful calls provide known or explicitly estimated cost using validated usage and the selected dated pricing policy. Failed calls with unknown usage retain the entire reservation, following existing behavior. If the reservation no longer bounds the possible charge, accounting becomes unsettled and further calls stop. Do not label a reservation retained after timeout as measured spend.

Claude CLI retains its host-reported accounting. API and gateway profiles require a validated price policy for admission even when a response supplies cost. LiteLLM documents [spend tracking](https://docs.litellm.ai/docs/proxy/cost_tracking) and an `x-litellm-response-cost` header in its [logging reference](https://docs.litellm.ai/docs/proxy/logging); those are post-call observations, not proof of a pre-call ceiling. A gateway alias with unknown underlying tariffs cannot silently use a zero price.

Run statistics distinguish reported or estimated cost from conservative budget charges and identify the pricing source and revision. Aggregate gateway budgets may add a limit, but never replace the controller's completion reserve.

## Delivery order and acceptance

Provider neutrality is the first project. Package extraction follows only after the complete API path works.

1. Finalize the concept and prepare any necessary product requirement or long-lived decision proposals separately. Obtain confirmation of their exact wording and summaries before editing their authoritative sources.
2. Define the core/adapter boundary around the existing Claude transport. Capture the effective role matrix, explicit overrides, schema correction behavior, accounting, and resume semantics as compatibility expectations. Keep the existing resource layout.
3. Introduce host profiles and unified resolution with Claude CLI as the default. Move provider preflight behind host selection. Establish contract tests for schema projection/decoding, error mapping, deadline/cancellation, response bounds, credentials, and cost admission.
4. Add a direct OpenAI API path and prove the complete assessment pipeline before packaging. Use the independent provider to expose assumptions hidden by Claude CLI.
5. Qualify an OpenAI-compatible gateway path, with LiteLLM as a concrete target, including a fixed alias serving Claude. Verify the selected dialect and backend separately from direct OpenAI. Gateway delivery remains part of the provider-neutral project; it does not wait for PyPI packaging.
6. Add further profiles such as direct Anthropic or Claude CLI on Bedrock as needed, each with its own evidence. Bedrock through Claude CLI alone does not establish protocol independence.
7. Extract and publish the Python package as the follow-up project described below.

Acceptance for implementation is scoped to changed boundaries and consumers:

- Neutral reproductions, a variant with different incidental names, and negative cases for each producer change; existing fixture runs provide additional replay evidence.
- Offline adapter contract tests with fake endpoints and fake CLI processes. Cover malformed output, canonical-schema rejection, refusal, authentication errors, unknown failure costs, hidden-retry prevention, cancellation, and concurrent completion reservations.
- Destination tests for repository-controlled host attempts, redirects, credential forwarding, disallowed networks, and connection-time DNS changes. Explicit private-gateway access remains a positive case.
- Gateway contract cases for missing usage, alias revisions, unexpected routing metadata, unsupported structured output, and absent price policies. Client tests do not establish server-side retention or routing policy.
- Complete pipeline replay including discovery, STRIDE, correction, synthesis, rendering, interruption, resume, and affected exports. Follow the existing golden-fixture runbook when deterministic-tail behavior changes.
- A real qualified provider/gateway run and `eval-threat-model` evidence for each promised depth. Record versions, model identities, costs, and quality results. Passing protocol tests alone does not qualify arbitrary models behind a gateway.

These are future implementation acceptance criteria. No runtime checks or provider calls are performed by this concept revision.

## Follow-up: engine and plugin separation

Keep the engine and plugin in this repository while they share releases and ownership. The engine contains orchestration, scanners, validators, renderers, exports, schemas, data, templates, role prompts, and provider adapters. The Claude Code plugin retains skills, hooks, and interactive integration and calls the same engine as the standalone CLI.

The intended entry point is `appsec-assess`; its installation and invocation remain proposed. A marketplace install cannot assume that it runs `pip install`. Prefer a plugin artifact that vendors the engine at the same version; define its dependency bootstrap and version check before changing distribution.

Package extraction includes:

- Loading packaged data through `importlib.resources` and replacing checkout-relative script execution with package module entry points or explicit APIs.
- Moving runtime metadata and fingerprinting away from `.claude-plugin/plugin.json`, while binding resumed work to engine code, resources, adapters, and resolved configuration.
- Moving engine-owned functional configuration out of `skills/`, including requirements-source settings, without changing enablement behavior.
- Maintaining one source for role prompts while retaining valid Claude agent definitions for the legacy path. Preserve existing slicing and prompt contracts until their consumers migrate.
- Defining the business-context input interface consistently with REQ-BIZ-010 and preserving optional external export tools with explicit unavailable-tool errors.
- Testing an installed wheel outside the source checkout through assessment, resume, rendering, and affected exports; repeat the relevant integration checks for the plugin's vendored artifact.
- Preparing dependency locking, trusted publication and release provenance under the [release runbook](../../releasing.md), with compatibility and rollback behavior defined before publication.

Other skills need an individual ownership assessment before moving into the engine. Removing the legacy path and splitting repositories are outside this proposal.

## Open work before implementation

- Specify the exact configuration schema, preserving existing CLI/environment precedence and separating organization restrictions from defaults.
- Inventory selected-role schemas and prove each required projection/decoder preserves canonical semantics, especially absent versus null fields.
- Select and qualify the first direct API and gateway dialects, models, pricing policies, gateway route revision mechanism, and quality thresholds per depth.
- Establish how an operator supplies trustworthy gateway routing and retention evidence without giving the engine gateway administration access.
- Trace remaining plugin resource, subprocess, metadata, and environment dependencies before starting the packaging follow-up.
- Prepare formal product and architectural proposals only after those boundaries are clear; this document does not register new requirements or decisions.
