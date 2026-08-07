# Context Routing Contract

`data/context-routing-catalog.yaml` is the reviewable Stage-1 context map. It
answers four questions without requiring knowledge of controller code:

1. What kind of context is this?
2. Which named agent receives or must not receive it?
3. Does the assignment cover the whole run, one component, or one candidate?
4. Why is the assignment required, optional, or forbidden?

## Human configuration surface

The catalog uses ten task-oriented categories:

- Target and run
- Business context and requirements
- Repository discovery
- Architecture, assets, and data flows
- Actors and abuse cases
- Trust boundaries
- Security controls and evidence
- Threat analysis
- Verification and risk
- Prior runs and identity

An agent has a stable ID, display name, purpose, scope, and stage. A context has
a stable ID, display name, category, description, and scope. An assignment has
the context, receiving agents, delivery policy, importance, target, and a
plain-language reason.

`delivery` has only three meanings:

- `required`: the agent cannot run safely without this context;
- `optional`: absence is recorded and the agent continues under its existing
  fallback; and
- `forbidden`: the context must not enter that focused agent's input.

`importance` declares the admission priority of optional context. `essential`
is reserved for required or forbidden core policy. Optional context is
`supporting` or `background`. Shadow mode records this value; source migrations
enforce it when their bounded projections become active.

`applies_to` names the threat-modeling unit directly: `whole_run`,
`current_component`, or `current_candidate`. Component and candidate context
cannot be assigned to a broader unit. Component-type and capability selectors
are intentionally absent until a resolver can validate and enforce them.

Run `python3 scripts/context_routing.py validate` after editing the catalog.
The command checks its schema and every context, agent, target, dependency, and
internal binding against the current runtime registries.

## Threat-modeling and context-economy rationale

The categories follow the analysis decisions a reviewer recognizes: business
purpose and requirements; repository facts; architecture, assets, and flows;
actors and abuse cases; trust boundaries; controls and evidence; threats; and
risk decisions. Actors and abuse cases share a category because an abuse-case
candidate is indexed by an actor and goal. Trust boundaries remain separate
because they use a dedicated bounded handoff and must not inherit the complete
business or architecture context.

Categories organize review but never grant access. `scope` limits the natural
unit of a context, `delivery` decides whether an agent needs it, and
`applies_to` prevents a component or candidate projection from becoming
run-wide. `importance` distinguishes useful optional evidence from broad
background discovery. `reason` makes each inclusion, omission, or prohibition
reviewable without reading the controller.

Migration state, paths, schemas, models, commands, projectors, trust labels,
and limits are not human routing choices. They stay in internal contracts or
the implementation plan. Effective-plan receipts report what the runtime
actually delivered.

## Internal bindings are not human parameters

`data/context-routing-bindings.json` owns schemas, artifact paths, semantic
roles, model-setting keys, producers, projectors, trust and sensitivity
classes, and byte, token, item, line, path, and aggregate limits. These values
are implementation and security contracts. A catalog editor does not repeat or
override them.

Repository declarations remain data inputs. They cannot edit the core catalog,
assign agents, choose paths or schemas, change models or tools, relax limits,
or remove required or forbidden context. A trusted packaged extension that
introduces a new context needs a separately reviewed internal binding.

## Shadow behavior

The current resolver records context-v2 actions without changing them. Every
declared action input must map to exactly one human assignment. Declared and
available implicit artifacts receive byte hashes. Plugin-owned fixed files and
scalar settings receive bounded receipts. Direct source reads and plugin
registries that have not migrated are recorded as `legacy_unreceipted` rather
than being represented as delivered.

The local `.context-routing-plan.json` repeats human category, agent, context,
scope, target, delivery, importance, and reason fields beside the internal
receipt metadata.
`scripts/context_routing.py inspect <output-dir>` prints a content-free summary
grouped by category, agent, and status.
