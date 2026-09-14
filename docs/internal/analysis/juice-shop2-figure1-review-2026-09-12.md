# Juice Shop Figure 1 review

This review checks the eight operator observations against the latest completed run in the sibling `juice-shop2` checkout and the current Figure 1 implementation. The observations below record the initial state. The implementation section records subsequent operator-approved source changes; the target run and frozen expectations remain unchanged.

## Evidence and verification scope

The reviewed run is `juice-shop2/docs/security/threat-model.yaml`, with its Markdown report, Figure 1 SVG, attack-path fragment, actor artifacts, and retained STRIDE outputs. It records analysis version 5, plugin version `0.6.0-beta.3`, depth `thorough`, generation time `2026-09-11T13:55:39Z`, and target commit `33518f5a0911e25d9df747b1e70fb7af279a755c`. The target checkout still has that commit. The run contains 79 findings, eight components, seven flows, and seven trust boundaries. Its invocation includes `--skip-context`, and its metadata records no business-context source.

Verification inspected source and retained artifacts without executing exploits or contacting external providers. Challenge-controlled paths establish conditional source-level attack surfaces, not proof that every deployment enables or exposes them. Finding references below use the report's `F-NNN` names; the YAML uses corresponding `T-NNN` IDs.

The diagram was replayed through `figure1_dfd.check_diagram` using the canonical YAML, retained attack-path fragment, current taxonomy, and actor labels. Its existing checks returned no problems. All 18 tests in `tests/test_figure1_dfd.py` passed. These checks cover current rendering invariants; they do not establish correct component ownership, complete discovery, or justified asset placement.

## 1. Merge equivalent internet attackers

The observation is supported for an anonymous visitor and a regular account holder when registration is open. The run's `.recon-signals.json` sets `has_open_self_registration: true`. Its `.actors-resolved.json` already marks ACT-D-01 and ACT-D-02 as equivalent with `collapse_reason: open-self-registration`. The target registers public `POST /api/Users` handlers in `server.ts:419` and creates the corresponding resource in `server.ts:502`. The user model defaults the role to `customer` in `models/user.ts:81`.

The implementation is inconsistent. [Actor equivalence rules](../../../data/actors/default-library.yaml) fold the two reach positions. [Report composition](../../../scripts/compose_threat_model.py) explicitly stopped collapsing authenticated actors in `_render_security_posture_at_a_glance`, retaining an older unused helper that would also collapse privileged users. [The DFD renderer](../../../scripts/figure1_dfd.py) derives actors directly from attack-path slugs and does not consult the resolved equivalence class. The canonical YAML also lacks `meta.open_user_registration`, although recon and actor resolution retain the positive signal.

Proposed correction: represent this equivalence class once in the overview as an internet attacker who can self-register. Preserve the account prerequisite on each finding and attack step. Derive the overview projection from the same validated equivalence result used by the actor inventory, and preserve its provenance through export. Apply it consistently to actor cards, scenario legends, and arrow origins.

Do not revive the old helper unchanged: open registration alone does not grant administrator rights. Invitation, operator approval, tenant membership, paid entitlement, or privileged credentials can remain meaningful prerequisites. Juice Shop's separate role-assignment weakness should appear as an escalation path, not become a generic rule that registration implies administrative access. Account creation also does not make a request authenticated until the attacker actually obtains a session.

Acceptance cases: open regular registration produces one overview attacker; invitation-only registration preserves two; an admin-only path preserves its privileged prerequisite; finding provenance and scenario numbers survive the projection.

## 2. Distinguishable attacker arrows

This is feasible in the existing SVG renderer. `_layout` already assigns a separate bus per attacker and distinct target ports. Rendering nevertheless gives all attack edges the same red color and arrowhead. Dashed edges currently mean a victim-directed attack, so simply assigning each attacker a different dash pattern would overload that notation.

Proposed correction: retain separate lanes, assign each displayed actor a stable stroke and matching arrowhead color, and repeat a short actor identifier at the bus and ambiguous branches. Derive styles from canonical actor identity rather than discovery order. Preserve the separate victim-edge meaning. Distinct colors alone cannot distinguish perfectly coincident paths, so spacing and identifiers are necessary for print and color-vision accessibility.

This review establishes implementation feasibility, not a measured readability improvement. Accept the change only after a rendered overlap example remains readable in SVG and PDF and in grayscale. Test several actors sharing targets and one actor with both ordinary and victim-directed edges.

## 3. Missing injections and authentication findings

The observation combines hidden findings, lost component attribution, and actual coverage gaps.

### Findings present but hidden or consolidated

C-02 has five findings classified as `injection`, six as `missing_authz`, and five as `broken_auth`. `_top_weak` sorts by worst severity, count, and class ID, then keeps only two classes through `WEAK_MAX = 2`. Consequently, C-02 shows `missing authz 6` and `broken authn 5`, hiding injection entirely. The badge count is a count of consolidated findings, not vulnerable source locations.

- F-011 contains SQL injection in both `routes/search.ts:23` and `routes/login.ts:34`. Its four instances include duplicate scanner/STRIDE observations at those two locations. The report's main scenario emphasizes search, while the login authentication bypass remains in an instance.
- F-027 consolidates six frontend XSS instances, including product descriptions and administrator user-list rendering. The diagram shows one XSS finding, not six sinks.
- C-03 already has two findings rated Critical in the run, F-008 and F-057, and three classified as broken authentication. This describes the run's ratings, not an independent endorsement of every rating. F-057 itself has evidence tier `insecure-practice` despite its effective Critical rating.
- F-001 consolidates JWT-verification observations from both auth and backend components but retains `component: backend-api`. Figure 1 counts only that primary component. The auth component also omits `routes/login.ts` from its paths, despite the architecture prompt requiring all files implementing the assigned role.

Proposed correction: disclose additional weakness classes with a readable overflow reference or expandable detail rather than silently presenting two classes as the complete picture. Preserve distinct attack consequences and prerequisite differences when consolidating. Show affected-component relationships without counting duplicate observations as independent vulnerabilities. Authentication ownership must include the actual login handler.

### Actual source coverage gaps

No finding evidence or instance in the final YAML references `routes/userProfile.ts`, `routes/saveLoginIp.ts`, `routes/trackOrder.ts`, or `routes/showProductReviews.ts`.

- `routes/updateUserProfile.ts:39` persists request-controlled usernames. `routes/userProfile.ts:54` conditionally extracts an expression from the stored username and executes it with `eval` at line 61. It also replaces template source before `pug.compile` at line 87. This deserves an explicit server-side injection assessment with the challenge condition and authenticated prerequisite recorded.
- `routes/trackOrder.ts:18` interpolates a route value into a `$where` expression. The permissive branch at line 15 depends on the challenge flag; the alternative strips non-word/non-hyphen characters.
- `routes/showProductReviews.ts:36` concatenates a route value into `$where`. The challenge-disabled branch converts it to a number; the enabled branch merely truncates it. Treat those branches separately.
- `routes/saveLoginIp.ts:18` accepts a client-controlled header and persists it, with sanitization conditional on a challenge flag. The frontend last-login display is represented under F-027, but this backend producer leg is absent from the finding instances.

The two `$where` consumers use MarsDB collections from `data/mongodb.ts:8`, not SQLite. That datastore is also absent from the component inventory. The current Node injection rules cover SQL interpolation, shell execution, SSRF, and other selected patterns; the inspected ordinary injection rules do not provide complete `$where` or stored-value-to-`eval` coverage. The backend STRIDE output likewise omits these source locations, so rendering cannot recover them.

Proposed correction: add application-agnostic source-to-sink coverage for these patterns, including safe numeric conversion, constrained values, parameterized queries, constant expressions, and test-only code as exclusions. Preserve configuration conditions and distinguish persisted attacker input from a direct request field. Classify NoSQL query injection as CWE-943, code execution as CWE-94 where supported, and browser execution as CWE-79 only with a demonstrated output sink. Severity must follow demonstrated reach and impact, not the presence of `eval` or a challenge name alone. Replay a golden fixture after any scanner or deterministic-tail implementation change.

## 4. XSS assigned to SQLite

The diagram makes an incorrect ownership claim. F-026 originates in the database STRIDE output as `database-003`, is assigned to `database`, and therefore produces the `XSS/CSP 1` badge on C-05. Its evidence is `models/product.ts:45`, a JavaScript model setter. The scenario describes stored markup later executing in catalog and administration pages.

SQLite stores the value but does not render HTML or execute browser JavaScript. The producer and consumer are application code and browser code. The architecture inventoried all `models/**/*.ts` under the datastore, mixing an embedded database with ORM logic. It also calls that component “SQLite Database via TypeORM”, although `models/index.ts:28` and `models/user.ts:14` import Sequelize. The report's bcrypt password descriptions likewise contradict the MD5 setter and hash helper.

Proposed correction: separate datastore identity from code ownership. Attribute unsafe model-setter behavior to server-side application code, preserve the datastore as an intermediate persistence node, and link the frontend rendering sink. Keep the XSS finding when its complete chain is supported. Do not fix the picture with a rule that hides every CWE-79 on data-tier components while leaving the producer and finding attribution wrong.

Acceptance cases: stored XSS retains its server and browser evidence without claiming the database executes it; an independent SQL injection finding points to the query-building application code; ORM names come from imports rather than inferred prose.

## 5. Data flows in the legend

They are used. The diagram draws `df-001`, `df-002/006`, `df-003`, `df-004`, `df-005`, and `df-007`. The legend expands all seven canonical flows. `_build_model` bundles flows with the same endpoints, so HTTP API calls and WebSocket traffic share the `df-002/006` edge. These are data-flow identities, not attack-scenario numbers.

Keeping the lookup is justified, but the present rendering truncates descriptions heavily. Make the distinction between data-flow IDs and attack-scenario badges explicit and provide full text through an accessible detail view or report reference. A bundle should disclose its constituent protocols.

There is also a source inconsistency: df-006 still targets `backend-api`, although finalization introduced the separate `realtime-channel` component owning the WebSocket implementation. Review flow ownership when component finalization changes the inventory; validating that an old component ID still exists is insufficient.

## 6. “Handles sensitive data”

The flag is not inferred exclusively from secrets. [The component schema](../../../schemas/fragments/components.schema.json) explicitly includes credentials, PII, payment data, and secrets. Concrete address and card models support identifying personal and payment data without business prose. Nevertheless, arbitrary business sensitivity cannot be established from a component name or generic inventory description. This run intentionally omitted business context.

The schema stores only a Boolean, without category, evidence, confidence, or distinction between an observed security-sensitive type and an operator-declared business asset. `_is_crown_jewel` in [the dispatch manifest builder](../../../scripts/build_stride_dispatch_manifest.py) uses that flag for analysis selection and unions it with declared business assets. Removing it globally could silently reduce analysis coverage. The builder's own documentation already acknowledges that the inventory flag over-tags.

Proposed correction: retain conservative selection internally, but require a named data category and supporting evidence for an affirmative diagram marker. Distinguish observed credentials/payment/PII from declared business sensitivity. If that evidence is absent, omit the marker or show uncertainty rather than claim knowledge. Do not infer that unknown data is public.

A separate deterministic error makes the picture worse: when exactly one datastore exists, `_build_model` assigns the four highest-classified assets to it without an asset-to-component relationship. Here it asserts that SQLite stores the JWT signing secret, CI/CD secrets, user credentials, and browser JWT session tokens. The first two are sourced from key material and build configuration, and localStorage tokens are not evidence of database storage. All asset `linked_threats` lists are empty in this run. Remove the location inference in a future fix; assets without a supported location belong in an unassigned asset list. Add a validated storage/processing relationship before claiming a specific location.

## 7. Missing external identity provider

Google social login is present in source. `frontend/src/app/login/login.component.ts:31` declares the Google authorization endpoint, and line 148 redirects the browser there. `frontend/src/app/Services/user.service.ts:68` calls Google's user-info API. `frontend/src/app/oauth/oauth.component.ts:28` consumes that profile and creates/logs into a local account. `config/default.yml:64` defines client configuration and allowed redirect origins. Visibility depends on the configured origin, so this is verified integration code, not a live provider availability check.

The recon template already explicitly requires frontend-only OAuth integrations. The run's security-architecture fragment even has an OAuth control row with F-010, F-018, and F-020. Yet `.data-flows.json` contains no frontend-to-provider flow, and df-003 conflates local authentication with OAuth exchange. Discovery reached one output but not the architecture graph.

The renderer can create a generic third party only for `to: external`, groups it by originating component, places it in column 2, and maps every `from: external` to the legitimate User. Thus it cannot faithfully identify multiple independent providers or distinguish a returning provider assertion from a human request. The flow and boundary contracts currently accept only registered component IDs or the literal `external`.

Proposed correction: model external entity identity and role explicitly, preserve observed browser-to-Google authorization/user-info traffic, and show the identity provider on the left with external participants as requested. Do not invent a backend token exchange: this implementation calls Google from the browser and performs local account login afterward. Add a coordinated entity/endpoint contract before extending producers, validation, normalization, diagrams, exports, and any new runtime sidecar cleanup or permissions. Merely recognizing “Google” in a label would not establish identity safely. MarsDB from point 3 is an embedded datastore, not another third-party service.

## 8. Legitimate roles beyond User

The application has `customer`, `deluxe`, `accounting`, and `admin` roles in `lib/insecurity.ts:142` and `models/user.ts:79`. `frontend/src/app/app.guard.ts:48` implements an AdminGuard. The backend enforces an accounting role for quantity and order-management routes, including `server.ts:431` and `server.ts:624`. The run recognizes a role concept and a privileged attacker, but neither is a legitimate-role inventory.

Figure 1 unconditionally creates one `actor:user` named “User” and sends every human inbound flow there. An administrator cannot appear as a distinct legitimate participant under that model. A malicious privileged actor is not a substitute for an administrator who uses the application legitimately or becomes the victim of stored XSS.

Proposed correction: derive legitimate participants from supported roles with materially distinct privileges, workflows, data access, or victim impact. For this application, customer, administrator, and accounting are supported candidates. Deluxe needs a separate card only if its entitlement and flows contribute useful distinctions. Preserve roles independently of malicious reach-equivalence classes; a stolen or escalated admin session is an attack result, not a reason to erase the legitimate administrator.

## Suggested implementation order

Correct component and source ownership first, including Sequelize, the login handler, and the missing MarsDB surface. Repair injection coverage and retain distinct sink/impact evidence through consolidation. Unify the actor-equivalence projection while preserving account and privilege prerequisites. Introduce supported external-entity, legitimate-role, and asset-location relationships across their consumers. Then adjust weakness overflow, arrow styles, and legend readability against replayed output.

## Implementation and targeted reassessment

The implementation now carries evidenced external entities and asset locations through the architecture contracts. An offline identity-integration producer reconciles OAuth/OIDC/SAML clients before boundary assessment. Figure 1 uses at most three High/Critical cause annotations and one short, unambiguous attack-pattern suffix per annotation. Patterns such as XSS, SQLi, LDAPi, XXE, and SSRF come from the central catalog; mixed or unsupported patterns remain generic. Authentication variants share one badge per component.

A targeted source reassessment withdraws T-056 as an authentication-bypass finding. `frontend/src/app/Services/request.interceptor.ts:23` sets a client-controlled identity header, but the repository contains no executable authentication consumer of that header. The corresponding helper in `lib/insecurity.ts:93` is unused outside its tests. The merged review intermediate retains the refuted verdict, and the canonical builder excludes the candidate. The STRIDE producer and evidence-verifier instructions now require evidence of security-relevant identity consumption, rather than treating a client-controlled assertion as proof of bypass.

T-010 is classified as weak credentials (`CWE-1391`), rather than credential protection (`CWE-522`). The OAuth callback derives a password from the public email address at `frontend/src/app/oauth/oauth.component.ts:30` and submits it to local login at line 46. The normal password comparison occurs in `routes/login.ts:34`. The targeted reassessment corrects the STRIDE fragments and merged intermediate, removes the CVSS object disallowed for this CWE by the existing eligibility catalog, and rebuilds the canonical model. It is a review of the stored analysis, not a new full scan.

One bounded architecture-contract review used a GPT-5.6 Sol subagent. The primary agent evaluated its findings against local source, artifacts, and deterministic replay; no Astra subagent was needed.

## Initial approved implementation

The source changes address the eight observations through producers, schema validation, reconciliation, and rendering. They do not repair the frozen target report in place.

| Observation | Implemented behavior | Evidence |
|---|---|---|
| Equivalent regular internet access | Validated actor resolution supplies canonical registration metadata; overview origins merge regular accounts with anonymous access while preserving privileged actors and finding prerequisites. | Builder, actor-projection, and Figure 1 tests |
| Overlapping attacker paths | Separate buses use actor colours and A1/A2 identifiers; named roles and services remain left of application components. | Geometry checks and a visually inspected neutral SVG example |
| Hidden and missing injections | Figure 1 displays every observed weakness class and merged component ownership; SQL/XSS consolidation requires the same sink or explicit shared control; bounded executable-expression checks add unproven practice evidence. | Scanner replay and consolidation tests |
| XSS on SQLite | The output validator rejects XSS on data-tier components; reconciliation moves an incorrectly assigned rendering sink only when source ownership resolves; executable ORM code needs an application owner regardless of the framework label. | Ownership and source-backed validation regressions |
| Data-flow legend | Every displayed flow ID resolves to its endpoint, protocol, and full wrapped label; ambiguous role-specific boundary placement becomes a component tag. | Diagram semantic and geometry checks |
| Sensitive data and asset locations | Visible sensitivity requires categories and evidence; business sensitivity requires declared context; asset placement requires an evidenced storage relation. | Schema alignment, evidence-path, and renderer tests |
| External services | Optional named entities and endpoint references travel through architecture, boundary input, YAML, Figure 1, and Threat Dragon; browser OAuth direction is explicit in the producer instructions. | Schema, builder, export, and geometry tests |
| Legitimate roles | Evidenced roles use separate entity identities and flows; generic legacy identities remain available without inventing privileges. | Role rendering and unresolved-reference tests |

The source scanner against the pinned target adds four locations: CWE-943 at `routes/showProductReviews.ts:36` and `routes/trackOrder.ts:18`, CWE-94 at `routes/userProfile.ts:61`, and CWE-1336 at `routes/userProfile.ts:87`. These are `insecure-practice` observations, with path conditions and unresolved access/configuration prerequisites retained; no exploitation test was performed. The scanner replay changes 48 observations to 52. Direct inventory reconciliation also finds `marsdb-store` at `data/mongodb.ts` and adds `routes/login.ts` to the existing auth component.

The complete frozen replay now fails closed at the existing `T-026` XSS assignment to the database. It cannot recover missing roles or Google OAuth topology from old LLM-authored sidecars. A new full target analysis is required for a corrected target report; a rendering-only replay is not that analysis.

The full repository check completed with 14,595 passing tests, 98 skips, and one failing golden Markdown comparison in `test_compose_matches_golden`. That failure was reproduced separately from an untouched `HEAD` archive; the snapshot already disagrees with the checked-in plugin version and report output. Subsequent focused checks cover the final source-ownership and schema refinements, and lint passes. The frozen target expectations and existing golden Markdown were not changed.

## Live integration verification

An isolated quick analysis of the bundled synthetic application completed and produced Markdown, YAML, SVG, HTML, PDF, SARIF, and pentest outputs. Its canonical model contains three named external entities, twelve flows (nine with named external endpoints), six component sensitivity records, and eight asset-to-component references. This exercises the new relationships through real agent output; it is not a new Juice Shop analysis.

The live diagram initially exposed an outbound boundary-tag bug when multiple external destinations shared an application source. The renderer now attaches that ambiguous boundary to the application component. A regression test covers this case, all 25 Figure 1 tests pass, and recomposition of the live artifacts reports no diagram geometry or semantic errors. The stronger source-backed ORM ownership gate was added after this run's initial architecture stage, so its coverage comes from focused regression tests rather than that stage of the live run.

The live assertion suite reports 53 passes and eight failures. Recomposition and assertion replay with the same generated artifacts through an untouched `HEAD` archive reproduce all eight failing tests. They concern checkpoint completion, a skipped configuration-scan sidecar, a secret-redaction warning, report QA, phase/agent logging, and the fixture oracle's missing hardcoded-secret signal and unmasked synthetic secret in runtime sidecars. This comparison establishes that the assertion failures persist with the previous consumers; it does not establish that every producing-stage issue predates this change. The overall live gate remains red, and those failures were not suppressed or repaired by editing artifacts.

## Operator review of the PNG

The operator refined the presentation after inspecting the first PNG. Figure 1 now omits the sensitive-data-handling marker entirely, including its legend symbol. Attacker colours use only red and purple hues. Components show concrete parent weakness titles and report IDs, with specific finding causes for uncovered entries; broad class-only legacy parents do not replace those causes. The data-flow legend remains, as explicitly confirmed in the follow-up. Evidenced stored assets stay on their datastore, with full wrapped names rather than truncated labels.

Datastore reconciliation now detects bounded executable ORM source from imports and model/query/initialization operations, excluding comments, tests, oversized files, and paths outside the repository. Unowned ORM code receives an application data-access component. Reclassification repairs primary findings, consolidated instance ownership, parent weakness scope, and their mirrored register metadata. Explicit at-rest storage protection findings remain on the datastore. The generic detector finds Sequelize application logic separately from SQLite in this target; it does not remove database findings merely because a component is a store.

The targeted preview uses the last target model, deterministic inventory and attribution reconciliation, validated prior actor resolution, and newly inspected asset-storage evidence. `models/index.ts:34` selects SQLite, line 41 identifies its storage file, and the model initialization chain starts at line 46. The stored asset relations cite `models/user.ts:56` and line 73, `models/address.ts:58`, `models/card.ts:38`, `models/challenge.ts:170`, `models/feedback.ts:39`, and `models/complaint.ts:36`. Browser token storage instead cites `frontend/src/app/login/login.component.ts:101`. No storage relation puts signing keys or CI secrets in SQLite. This is a targeted architecture refresh for the preview, not a new complete threat analysis; the original target report remains unchanged.

The operator rejected full W/T titles on nodes as unreadable. The final presentation therefore replaces that intermediate design with at most three short High/Critical causes per component, without finding IDs, full titles, or annotation counts. Equivalent annotations collapse, concrete interpreter defects remain visible ahead of broad input-control gaps, and generic credential warnings give way to equally severe specific credential defects. Supporting practice sites do not extend a parent mechanism beyond its linked instances. The PNG was inspected for label wrapping, asset placement, edge readability, and legend density; its height fell from 2,874 to about 1,300 logical pixels. Control-status badges remain a possible future design, requiring separate evidence for absence, bypass, and verification rather than inferring safety from missing findings.

The broader check after attribution changes completed with 14,606 passes, 98 skips, and the previously reproduced golden Markdown failure. Focused renderer tests cover the subsequent compact-annotation refinements. The frozen replay still rejects the old database XSS attribution; the original expectations remain unchanged.

The initial generic vocabulary replaced implementation-specific annotations. Subsequent operator review refined authentication and authorization into evidence-dependent variants and query defects into `Unsafe Query Construction`. The central annotation catalog defines the current wording. Parent mechanisms and individual CWE-backed findings use the same catalog, so equivalent defects occupy one annotation.

## Final scan readiness review

The final `make check` passes lint, formatting, configuration, registry, target-specificity, requirement-binding validation, and the full deterministic suite: 15,106 passed and 98 skipped. The focused annotation, catalog, agent-definition, and prompt-budget checks also pass with 696 tests. These results supersede the earlier repository-gate results recorded above.

The final targeted preview is rebuilt from reviewed architecture and threat intermediates, followed by deterministic ranking. Its canonical model passes schema validation with 78 findings and ten components. Figure 1 passes its semantic and geometry checks. Visual inspection confirms at most three short cause annotations per component, readable asset locations, and external OAuth services on the left. The SPA shows `Insecure Output Handling (XSS)`, `Insecure Secret Management`, and `Weak Authentication`. SQLite shows only `Missing Data Encryption` and evidenced stored assets. Named legitimate roles still require fresh architecture discovery; the old run supplied only a generic user.

The frozen scanner replay adds the four expected executable-expression observations, increasing its count from 48 to 52. The complete old-run replay stops at the unsupported SQLite XSS assignment. Its frozen inputs and expectations remain unchanged. The E2E Markdown snapshot was separately regenerated through its test helper; its only changes are two plugin version strings from `0.6.0-beta.2` to `0.6.0-beta.3`.

The earlier live integration gate remains unresolved: eight assertions failed around checkpoint/configuration artifacts, phase and agent logging, report QA, and the planted-secret recall and masking checks. The same failures reproduce when the generated artifacts are consumed by the previous code. This is not proof that every producing-stage issue predates the change. The next full scan must validate these runtime outcomes as well as fresh semantic discovery; a passing deterministic suite alone cannot establish a clean live run.

Start the next scan from the updated plugin checkout with `--full` and `--keep-runtime-files`. These options force fresh analysis and retain the evidence needed to inspect any remaining failure. Rendering the old report again cannot assess the revised architecture and STRIDE producer instructions.
