# Weakness derivation

The merger owns the weakness register. Architecture observations, reviewed source practices, and verified finding mechanisms provide its backing. A CWE alone does not establish a shared cause or application-wide control absence.

## Producer and consumer boundaries

`arch_coverage_to_threats.py` preserves control names and source locations and classifies specific CWEs through the canonical weakness vocabulary. `detect_impl_strategy.py` records dependency inventory and bounded JS/TS implementation observations. `weakness_signals.py` corroborates catalogued mechanisms at verified finding locations. `merge_threats.py` validates those observations, reconciles their scopes, and rebuilds the register after evidence verification and triage, before synthesis consumes it.

| Artifact | Contract | Use |
|---|---|---|
| `.arch-design-signals.json` | `schemas/weakness-signals.schema.json` | Architecture backing when current coverage is unavailable |
| `.impl-design-signals.json` | `schemas/weakness-signals.schema.json` | Source practices with explicit instance scope |
| `.finding-design-signals.json` | `schemas/weakness-signals.schema.json` | Verified finding mechanisms with source locations and finding IDs |
| `.impl-strategy.json` | `schemas/impl-strategy.schema.json` | Runtime dependency inventory and bounded source evidence |

`weakness_signals.validate_document` validates emitted and consumed observation documents. Invalid documents stop reconciliation. Refresh replaces stale source observations. Runtime cleanup preserves these audit artifacts. Missing repository configuration permits architecture-only reconciliation; a configured but unavailable repository fails instead of claiming a source inspection.

## Evidence and scope

The verified finding owns the security claim, including privileged attributes, attacker influence, reusable credentials, and missing request-authenticity enforcement. The finding-mechanism producer corroborates the cited implementation API; it does not independently repeat taint analysis or establish the absence of middleware. Its selectors and supported CWEs live in `data/weakness-classes.yaml`. Unsupported or unverified findings remain findings without a newly inferred mechanism.

Source observations retain relative production paths and positive line numbers. They exclude tests, generated code, dependencies, unsafe paths, and escaping symlinks. Refuted finding evidence cannot back a new finding-derived weakness. Refuted source sites are removed from implementation observations. Finding-derived observations attach only their admitted finding IDs; a bounded source sample does not restrict independently backed architecture scope.

Dependencies describe inventory, not enforcement. Source directory names do not establish component identity or pervasiveness. Implementation observations carry no CVSS and preserve the existing finding severity when a confirmed instance is attached. Unrelated practices without curated mechanism guidance retain their own title and source scope instead of borrowing class-wide remediation.

## Scanner exclusions and delivery

The implementation catalog owns inspected patterns, CWE mappings, and mechanism wording. Its emitter excludes parameterized SQL, non-executed comments and string examples, direct supported HTML sanitizers and their locally established aliases, display-only token decoding, and local role checks as proof of missing authorization. A source practice without confirmed exploitation stays an implementation observation. Architecture control absence requires separate architecture backing.

The composer displays source-backed architecture locators and lists each confirmed finding once within a weakness card. YAML and report validation retain their existing evidence, identifier, and severity contracts. Neutral positive cases, renamed variants, safe controls, refutation, schema failures, cleanup, and orchestration regressions live in the corresponding producer and consumer tests.
