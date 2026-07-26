# Analysis: Trust boundaries as first-class objects with derived impact

> **Status: analysis / not started.** Feasibility check for the roadmap item
> "Integrate trust boundaries more deeply — treat each as a first-class object
> and tie findings to the specific boundary they violate." No code changed.
> Written 2026-07-21.

## Verdict

Feasible, and cheaper than it looks — most infrastructure already exists. Trust
boundaries are **not** free-text prose: `trust_boundaries[]` is a first-class
array carrying `id` (tb-N), `from`/`to` (component ids or literal `external`),
`enforcement`, `trust_level`, `controls[]`. The real gap is that the ids are
**write-only**: no finding, weakness, or mitigation ever references a `tb-N`.

The key lever: the reverse join can be **derived deterministically**, not
re-asked from the LLM. Threats already carry `component` + `actor_ids`;
boundaries already carry `from`/`to` on the same component ids. The
component→boundary edge is already present — the builder only has to fold it
together. This keeps the LLM doing *less*, per the standing preference for
deterministic Python over LLM for final artifacts (AGENTS.md).

## Value — why bother

1. **Reachability dimension on findings.** Today a finding names a component but
   not whether an attacker can reach it or what they cross to get there. With the
   boundary join it states the broken trust assumption and the attacker gain
   ("reachable via tb-2 internet→application, enforcement: none → unauth access to
   the data tier").
2. **Defensible severity.** The same flaw behind an enforced boundary is a
   different risk than behind `enforcement: none`. Boundary crossing becomes a
   likelihood modulator, parallel to the existing `actor_adjusted_likelihood`.
3. **Bundling instead of scatter.** N instance findings crossing one broken
   boundary collapse into one design weakness + one prioritized measure ("secure
   tb-2") instead of N scattered code fixes.
4. **Catches the design gap SAST misses.** Over-trust / unenforced boundaries are
   not a single line of code — no instance finding, no SAST hit. This is the whole
   "component with too much trust" premise of the tool.

## Current state (evidence)

- **Object**: `trust_boundaries[]` with `id/from/to/enforcement/trust_level/controls`
  — `schemas/fragments/trust-boundaries.schema.json`. Produced by the Phase 7
  LLM as sidecar `.trust-boundaries.json`
  (`agents/phases/phase-group-architecture.md:1311–1360`,
  `agents/appsec-threat-analyst.md:414`), aggregated deterministically into the
  master yaml (`scripts/build_threat_model_yaml.py:1969–2133`, with
  `_carry_forward` fallback for incremental runs).
- **Forward join**: `from`/`to` → `components[].id`. Consumed by the Figure 1
  attack diagram (🛡 marker on the tier-pair edge,
  `scripts/compose_threat_model.py:6528–6598`;
  `scripts/figure1_svg.py:117–163,442`) and injected as **per-component STRIDE
  dispatch context** (`scripts/build_stride_dispatch_manifest.py:100,1023,1068`).
- **Latent weakness hook**: emitted boundary objects already carry a `weakness`
  field — declared in **neither** schema, pure `additionalProperties` passthrough
  (`docs/security/threat-model.yaml` boundary rows).

## Three blockers

1. **Schema drift.** Two competing schemas: the canonical output schema requires
   only `name` (`schemas/threat-model.output.schema.yaml:317–325`); the sidecar
   schema is the rich one. `enforcement`/`weakness` are declared in neither and
   only survive via `additionalProperties: true`. Consolidate first, or every
   addition compounds the mess.
2. **No reverse link.** No `threats[]`/`weaknesses[]`/`mitigations[]` field
   references a `tb-N`. Grep for `boundary_id|tb-\d` in findings returns nothing;
   the id is minted in Phase 7 and never read downstream.
3. **No report section — by design.** The standalone Trust Boundaries section was
   removed 2026-05 as duplicated content and is now **forbidden**
   (`data/sections-contract.yaml:691,701,1407`). Do **not** re-add a section;
   enrich existing finding cards / Figure 1 instead.

## Two kinds of trust boundary (the central distinction)

Not one concept but two, with different detection problems and different value:

1. **Topological boundary (perimeter).** Where traffic enters and which network
   zones are separated. "Internet-facing" lives here — coarse, and mostly *not*
   provable from code (a deployment fact: is this LB public?).
2. **Provenance boundary (data trust).** A component *trusts* data whose origin
   is actually untrusted — independent of network position. A component deep in
   the "internal" network can still be the victim, because it treats
   attacker-influenceable data as clean.

**Provenance is the higher-value class** — it is exactly the "component with too
much trust" the README promises and that SAST does not see as a *design* problem.
It shows up as: second-order/stored data trusted at the read site; trust-conferring
inputs used without verification (`X-Forwarded-For`, `X-User-Id`, unverified JWT
claims, client-supplied role/price/flags); "internal, therefore safe" endpoints
with no authZ (SSRF pivot, flat network, confused deputy); client-as-first-party;
deserialization of "internal" queue messages an attacker can enqueue.

## How boundaries are determined in practice

A boundary sits wherever the trust level changes on a data-flow edge. Find the
edges, then place a boundary at each transition. Signal types, by strength:

1. **Deployment/topology artifacts** (strongest, when in-repo): Dockerfile
   `EXPOSE`, compose networks, k8s `Ingress`/`Service: LoadBalancer`/`NetworkPolicy`,
   Terraform/cloud (security groups, API gateway, LB), reverse-proxy config.
2. **Network edges between services**: HTTP/gRPC clients, queues, DB connection
   strings, service URLs.
3. **AuthN/AuthZ transitions**: where auth is required = boundary between unauth
   and auth. **Already captured** by `route_inventory` `authn_signal`/`authz_signal`
   — boundary evidence not yet used as such.
4. **Datastore edges**: app → DB/cache/blob/secrets.
5. **Input entry points**: HTTP handlers, webhooks, uploads, queue consumers,
   deserialization.
6. **Privilege/identity changes**: service accounts, IAM role assume, subprocess,
   `setuid` — in-process boundaries, often missed.
7. **Third-party/external integrations**: payment, OAuth provider, LLM API.

For the **provenance** class (#2 above), detection is by *origin*, not topology:
does data from an untrusted entry point reach a trust-assuming sink (SQL, template,
command, auth decision, downstream service) with **no validation/sanitization
boundary in between**? If not, the boundary exists conceptually but is unenforced.

**Honest layering — what is provable:**

| Signal | Source |
|---|---|
| Entry points, datastore edges, service calls, auth gates, third-party, deserialization | provable from **code** |
| Deployment topology (ingress/LB/segmentation) | provable from **config** — *if* in the repo; often partial or absent |
| internet-vs-internal, real network segmentation, tenancy intent, true crown-jewel status | needs **human / deployment truth** |

The *existence* of most boundaries is deterministically derivable from code+config,
because they sit at concrete edges. Only the *height of the trust drop* — above all
"reachable from the internet?" — is the human's contribution. Full taint-path proof
is a SAST problem; this tool is a threat modeler, so the provenance class is flagged
as a design-level **assumption** (`insecure-practice`, or `confirmed-exploitable`
with code evidence) — not a proven path per instance. This fits the existing
`evidence_tier` model.

## Exposure sourcing (how "internet-facing" is known)

Today there is **no** `internet_facing` field. Exposure is LLM-guessed via
`components[].deployment_zones[]` (Phase-3) and `trust_boundaries[].from: external`
(Phase-7); recon supplies only deterministic *route/management* facts (Cat 11
exposed routes, `authn_signal`), not reachability. The only hard-wired
deterministic zone is `mobile-device`. Dockerfile is scanned for base images but
**`EXPOSE`/ports/ingress are not turned into an exposure signal** — a cheap
deterministic win left on the table. Unknown exposure **fail-safes toward
inclusion** (`build_stride_dispatch_manifest.py:375`), so nothing is silently
dropped, but exposure is over-included rather than precise.

**Recommendation — deterministic-first, human confirms only the residual:**
- Upgrade the already-scanned Dockerfile/compose (`EXPOSE`, ingress) into a
  recon-backed exposure fact where possible.
- For what code cannot prove: an optional, authoritative pre-seed file
  `.appsec/exposure.yaml` (`component → internet|internal|unknown`), same pattern
  as `actors.yaml`. Absent → today's fail-safe, headless-safe, no break.
- **Not** blanket annotation and **not** a mandatory prompt: confirm the proposed
  default as an enum **selection**, scoped to the `exposure-unknown` subset only.
  Confirming what code already proves is wasted effort and invites contradiction.
- An attended `AskUserQuestion` confirm is a thin later layer that writes the same
  file — the file stays the single source of truth.

## Derived impact per target

**Findings (`threats[]`)** — deterministic in the builder:
- Add `crossed_boundary_ids[]`, derived from the attack path: `primary_actor`
  reach zone → `component` tier, intersected with the `from`/`to` edges. No new
  LLM output.
- Impact = likelihood modulation, parallel to the existing
  `actor_adjusted_likelihood`: a finding reachable only behind
  `enforcement: none` across `untrusted→data` shifts up; behind an enforced
  boundary, down. Finding text then names *which* trust assumption breaks
  ("reachable via tb-2 internet→application, enforcement: none") instead of only
  the component.

**Weaknesses** — mostly reinforcement, plus the provenance class:
- **Reinforcement (the ~90% case).** A boundary crossing is not itself a weakness;
  the *missing control* at it is, and that almost always maps to an existing class
  (`missing_authz`/`broken_auth` for unauth crossing, `weak_crypto`/`server_side_exposure`
  for unencrypted, `injection` for unvalidated input). Here the boundary is a
  **lens/severity modulator** on the existing finding, **not** a new W-NNN. A broad
  new `trust_boundary_violation` class would duplicate these and cause alert fatigue.
- **The genuinely new part — provenance over-trust.** A component that trusts data
  whose origin is untrusted, where no single sink finding captures the *design*
  assumption (second-order/stored, unverified trust-conferring headers/claims,
  "internal, therefore safe"). Emit as a design weakness (`kind: design`) via the
  **existing** Weakness Register pipeline, `affected_components[]` = the trusting
  component. This — not network segmentation — is where the real added value sits.
- A new `weakness_class` enum value (e.g. `insufficient_segmentation` /
  `over_trusted_input`) only if a real boundary finding maps to **no** existing
  class; default conservative to avoid duplication.

**Measures (`mitigations[]`)**:
- Boundary-scoped `review_target` instead of a bare file path ("enforce authN at
  tb-2"). `priority` (P1–P4) derivable from the `trust_level` delta across the
  boundary.

## Sequencing / effort

1. **Consolidate the schema** (sidecar → canonical; declare
   `enforcement/weakness/trust_level`). Precondition, cheap.
2. **Derive `crossed_boundary_ids[]`** deterministically in the builder. The join
   key that unlocks everything. High leverage.
3. **Auto-emit design weaknesses** from unenforced boundaries — reuse the
   existing `weakness` field.
4. Likelihood modulation + finding-card / Figure 1 enrichment. Medium.

## Traps (contract + prior lessons)

- **Bidirectional contract**: `crossed_boundary_ids` = producer + schema +
  consumer + validation + tests together (AGENTS.md §4).
- **`from`/`to` crossrefs are advisory** (unknown component → warning). The
  derived link must stay **nullable/advisory** — do not coerce `unknown` to
  `absent` (the known route-inventory anti-pattern).
- **Incremental**: `_carry_forward` exists for boundaries; derived links must
  survive shallower re-scans and the T-id renumbering on merge.
- **No new section** — `sections-contract` blocks it; enrich existing views only.

## Key files

`schemas/fragments/trust-boundaries.schema.json`,
`schemas/threat-model.output.schema.yaml:317`,
`scripts/build_threat_model_yaml.py:1969–2133`,
`scripts/build_stride_dispatch_manifest.py:100–1068`,
`scripts/compose_threat_model.py:6528–6598`, `scripts/figure1_svg.py:117–163`,
`scripts/pregenerate_fragments.py:485–734`,
`agents/phases/phase-group-architecture.md:65,1311–1360`,
`agents/appsec-threat-analyst.md:414`,
`data/sections-contract.yaml:691–701,1407`.
