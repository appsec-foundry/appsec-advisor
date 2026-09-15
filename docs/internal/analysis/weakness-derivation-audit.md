# Weakness derivation audit

The 2026-09-15 audit identified missing mechanism producers, lost source provenance, and a classification defect. The implementation now derives narrowly scoped weaknesses from verified findings and source observations. The supplied Juice Shop run is additional reproduction evidence; production rules use no target names or paths.

## Observed symptom and result

The reviewed model was generated on 2026-09-13 with plugin version `0.6.0-beta.3` at thorough depth. It contains 68 delivered threats and 12 weaknesses. None of the five operator-selected findings appeared in a weakness's `instances` list. An isolated rebuild with the corrected producers retains 68 delivered threats, produces 18 weaknesses, and links all five findings through YAML and Markdown delivery.

| Finding | Mechanism | Corrected derivation |
|---|---|---|
| F-012, CWE-915 | Privileged attribute binding | `unrestricted-attribute-binding`, corroborated at the verified write/binding site |
| F-011, CWE-94 | Application data executed as code | `application-data-as-code`, corroborated at the verified evaluation site |
| F-001, CWE-79 | Unsafe HTML rendering | `frontend-output-encoding`, retaining the canonical XSS class |
| F-002, CWE-922 | Browser-readable reusable credentials | `browser-readable-session-credentials`, corroborated at the verified browser-storage site |
| F-045, CWE-352 | Cookie-authenticated changes without request authenticity | `unprotected-cookie-mutations`, corroborated at the verified request/session site |

The source APIs corroborate the implementation mechanism. The verifier's admitted finding evidence owns the complete security claim, including attacker control, privileged attributes, state mutation, and missing protection. An isolated API match does not establish application-wide control absence.

## Producing defects and permanent fixes

`arch_coverage_to_threats.build_design_signals` previously selected a broad architecture theme before the specific CWE. That assigned XSS to injection and insecure storage to cryptography, violating canonical classification and preventing compatible findings from attaching. The bridge now classifies the CWE first and retains the theme only as an unmapped-CWE fallback. It also preserves control names together with source locations instead of selecting only the first nonempty backing field.

The merger previously had no observations for the four additional mechanisms. `weakness_signals.finding_signals` now checks catalogued selectors at verified production source locations and emits scoped mechanism records. `merge_threats.py finalize` invokes the producers after assigning finding IDs. The controller refreshes and validates the register again after evidence verification and triage, before synthesis consumes it. Refuted findings and their source observations cannot reintroduce the same weakness backing.

`detect_impl_strategy.py` previously had no regular runtime invocation. Enabling it unchanged would have treated parameterized queries, display-only token decoding, test fixtures, and local role checks as structural weaknesses. It now excludes those cases and preserves bounded implementation evidence without inventing components from directory names. Dependency inventory neither suppresses weaknesses nor establishes enforcement. A strategy observed for one mechanism does not change unrelated mechanisms in the same CWE class.

Fallback grouping previously combined unrelated CWE-400 practices and borrowed broad class prose for different mechanisms. Practices without curated guidance now retain separate source scope and their own titles. Reviewed cookie and template mechanisms have specific prose. Finding attachment respects explicit source scope, while independently backed architecture coverage retains its own scope even when a bounded source sample observes fewer sites.

The composer displays architecture source locators and avoids repeating a confirmed finding as a practice entry in the same card. New observation sidecars have schemas and validation at their producer and consumer boundaries. Cleanup preserves them for audit. Existing plugin permissions cover the fixed refresh command and its sidecars; the permission inventory and regression tests document that use.

## Regression evidence

Eight neutral confirmed cases cover attribute binding, dynamic evaluation, browser credential storage, and cookie-authenticated changes, with an alternate API or identifier for each mechanism. Running the old finalizer from Git HEAD yields no weakness for all eight; the new finalizer produces the expected mechanism and finding link. Literal-only evaluation and non-secret browser preferences remain negative before and after.

A separate old/new detector comparison reproduces false positives for two parameterized-query variants, test-only HTML rendering, and display-only token decoding. The new detector excludes all four while retaining concatenated SQL as the positive control. Additional tests cover sanitizer aliases and reassignment, comments and string examples, source path containment, exact finding ownership, refutation, stale-state replacement, malformed sidecars, source provenance, runtime invocation, and cleanup.

The focused bridge/merger/strategy selection passed 364 tests during implementation. After the final producer scope fixes and SQL exclusions, the two producer test modules passed 67 tests. Lint and configuration, registry, target-neutrality, requirement-binding, and test-inventory validators passed. `make check` completed successfully with 15,917 passing tests and 98 skips in 1,034 seconds. Three additional SQL negative cases were added after full-suite collection and are included in the separate 67-test producer run. The final catalog passed lint and all configuration and contract validators again. The final SQL exclusions preserve the replayed weakness register unchanged.

## Replay and limits

The isolated source replay and frozen deterministic report retain all five selected links, with severity inherited from their confirmed findings. Two previously attached resource-exhaustion findings remain standalone because same-CWE practices do not establish their shared cause; their findings and severity remain in the delivered register. The operator's retained run and delivered report remain unchanged. This is an offline replay of existing analysis, not a fresh model-backed security assessment.

A replay of the earlier audit fixture also includes independently edited Figure 2 presentation and repository-metadata changes in the shared workspace. Those differences do not establish a weakness regression. A new fixture freezes the current deterministic outputs and the refreshed register. Its replay shows no drift in Markdown, SARIF, or scanner results. YAML differs only in generated `changelog[].time_local`, which the existing fixture normalizer does not scrub. The replay therefore returns nonzero for this timestamp difference; it is not reported as an entirely green fixture gate.

The implementation detector's supported patterns cover JS/TS source. Finding-mechanism selectors can corroborate matching syntax in other production files, but do not promise full language coverage or independent taint analysis. Unknown or unverified mechanisms remain findings without a newly inferred parent weakness.

Figure 1 already derived four selected mechanisms from High/Critical findings independently of the register. F-045 remains Medium and outside that selector's existing severity policy. This fix does not raise finding severity to force a diagram annotation.

See the [weakness derivation contract](../contracts/weakness-derivation.md) for artifact ownership, scope, and validation boundaries.
