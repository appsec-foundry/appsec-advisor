# Composition offline implementation evidence

This records the first P2 source preparation and P3 assembly/bootstrap checks under the operator-approved offline sequence. It is not a release or public cutover record. The [staging contract](../contracts/plugin-composition.md) defines the implemented boundary; the [inventory](appsec-advisor-composition-inventory-2026-10-18.md) retains outstanding consumers and acceptance conditions.

## Portable skill sources

AppSec Skills commit `557f16fa07beead21267a3b220f7e4d608e11b2c` on local `dev` adds independent `security-score`, `authnz-review` and `analyze-threats` workflows, per-skill dependency declarations, their schema, compatibility references and README entries. The independent `create-threat-model` skill is unchanged. The primary `appsec-analyzer` entry and internal analysis contracts remain Analyzer-owned.

The three skill directories were copied outside all repositories. Their local references and dependency declarations were checked against the declared schema, committed Analyzer interface/capabilities and public command help. Inspection used an exported committed Analyzer revision rather than its concurrently modified working tree. These checks do not establish model-backed end-to-end behavior, host binding, every legacy option, or live quality. Existing Advisor entries remain in place; missing legacy AuthN/AuthZ options are explicitly documented without fallback to private scripts.

## Staging primitives

The new composition builder validates selected inputs, explicit file mappings and complete archive metadata, verifies artifact hashes and wheel distribution versions, rejects collisions and incompatible interfaces, and emits normalized staging ZIP/checksum/notice/manifest outputs. Tests exercise two identical builds, archive traversal variants, Windows path aliases, special files, expanded-size/entry bounds, tampering, missing selections and command collisions. This does not qualify native operating systems.

The standard-library bootstrap provides explicit offline setup, read-only preflight and exact-interpreter invocation. Tests use a neutral synthetic wheel to exercise actual venv/pip installation, missing runtime, read-only plugin files, spaces, a shadow executable on `PATH`, setup failure/retry, competing setup, identity/capability mismatch and Unix descendant cancellation. Additional cases reject duplicate metadata fields, mismatched delivered file sizes before hashing, runtime storage in Git checkouts and POSIX storage writable by other users. The synthetic wheel is isolated test data and never a release component. Real-engine inspection corrected the executable module to `appsec_analyzer.cli`; Analyzer does not provide a package `__main__`.

## Real engine installation replay

The following separate replay exercised the implementation against an actual Analyzer wheel, not only the synthetic wheel.

| Input or observation | Recorded value |
| --- | --- |
| Analyzer source | `7602a7fb3d5dd0717746ed235762cbea206306ab`, exported from Git with required source resources and packaging metadata; no uncommitted changes. |
| Engine artifact | `appsec_analyzer-0.1.0a0-py3-none-any.whl`, SHA-256 `0d061a5d4df9df8e7d86738d2bb63062a01b70de1c2a08360967190c1832ee06`. |
| Build | Existing tools, no network or isolation downloads: setuptools `80.9.0`, wheel `0.46.3`, build `1.2.2.post1`, pip `22.0.2`. Tool wheel artifacts are not yet locked; this is not a reproducible release-build qualification. |
| Runtime | Existing CPython 3.10 on Linux x86_64; the final bootstrap replay used a fresh user-owned runtime outside Git checkouts. The local `/tmp` directory itself contains a Git marker, so storage-boundary tests and this final replay used a separate temporary location. This is one replay environment, not the supported runtime matrix. |
| Dependencies | Existing local wheelhouse, each file verified against its prior recorded checksum and selected by exact content digest; offline hashed installation and dependency-closure check passed. |
| Engine handshake | Installed module returned engine `0.1.0a0`, interface 1, and the selected deterministic capabilities. |
| Deterministic execution | A new neutral Git repository returned structured score output with exit 2 (`undetermined`), preserving the engine's status rather than inventing a headline score. |
| Launcher | The bootstrap's `run ... -- version` selected the installed engine through the exact environment interpreter and returned the matching version/interface. |
| Model calls | None. |

Replay files are local disposable evidence, not build inputs or artifacts to publish. Its host artifact contains committed Advisor manifest/license metadata and its skill artifact contains committed collection files; it intentionally does not establish a complete plugin invocation binding. No sibling checkout is used by the installed engine. Earlier temporary source-export omissions were corrected before building; the first failed build supplied no passing evidence.

## Remaining acceptance evidence

The operator explicitly approved stopping the broad test-route audit and completing only focused packaging checks. At cancellation, 442 of 444 test modules had measurement results; two unchanged controller modules were unfinished. Three completed modules recorded test failures whose causes and baseline status were not established. This is incomplete route-audit evidence, not a passing full-suite result. The updated routes include consumers observed in the completed measurements. Focused composition/runtime checks and the real-engine offline replay passed; malformed DEFLATE regression cases additionally verify controlled rejection for two distinct member paths while preserving valid compressed input.

P2 still needs full installed host workflows, public lifecycle behavior and option parity where recorded gaps remain. P3 still needs an approved complete component/dependency/build-tool lock, license declarations for collection distribution, exact plugin invocation bindings, organization packaging from the assembled tree, the full native platform/interpreter matrix, failed-setup/cancellation/locking coverage on those platforms, and upgrade/rollback. P4 public hook/result/configuration migration is separate pending work. A7 live qualification still gates release, public cutover and removal. No push, publication or paid assessment was performed.

## Score invocation binding follow-up

The optional composition selection `skill_bindings: [security-score]` now generates an Advisor entry that delegates to the unchanged portable workflow through the pinned bootstrap. The delivered inventory records the original component for `WORKFLOW.md` and the host component for the binding. Missing selected resources, generated-path collisions, unsupported declarations and a missing locked score operation stop assembly. Compositions without a binding retain their existing entries.

The bootstrap now requires explicit boolean operation availability. Bound score invocations additionally require scoring version 2 and no model calls before dispatch; the selected binding permits only version, capabilities and score. It does not enable model-backed workflows or perform implicit setup.

Fourteen selected pytest node IDs expanded to 36 passing cases in 9.49 seconds. These cover deterministic bound assembly with two independent source layouts, retained workflow bytes and provenance, resource/declaration failures, strict availability with two operation names, incompatible score metadata, disallowed operations, missing binding selection, and setup refusal for an unavailable required operation. One real offline venv installation with the neutral synthetic wheel exercised the installed binding, read-only plugin files, spaces and shell metacharacters, shadow PATH, text/JSON/YAML argument forwarding, and unchanged exit statuses 0, 1, 2 and 130. The unbound invocation path also remained usable. Lint and format checks passed on the four changed Python files. Temporary installation storage was outside Git checkouts because the local `/tmp` directory contains a Git marker.

This follow-up did not rerun unrelated scanner/report tests, the descendant-cancellation test, broad route audits or release gates. No test routes changed. The synthetic wheel proves launcher behavior, not real score content or Claude-host execution. Actual installed score outcomes, complete legacy option parity, native platform qualification and the remaining phase acceptance conditions stay open.

## Real-engine score binding replay

A subsequent score-only staging archive exercised the binding with real committed component artifacts. The [staging runbook](../runbooks/composed-score-staging.md) gives the model-free commands and session-only Claude entry. The archive and its selection lock remain local internal staging artifacts, not publication inputs or a qualified production lock.

| Input or check | Result |
| --- | --- |
| Advisor host | `140e1c8f4688b95279a9b93f1b89312ef6cef38f`; manifest, license, type declarations and bootstrap exported directly from Git. |
| Analyzer | Reused the previously recorded committed `7602a7fb3d5dd0717746ed235762cbea206306ab` wheel, SHA-256 `0d061a5d4df9df8e7d86738d2bb63062a01b70de1c2a08360967190c1832ee06`. No mutable Analyzer working-tree files were used. |
| Portable workflow | Reused collection artifact from `557f16fa07beead21267a3b220f7e4d608e11b2c`; selected only score resources and their dependency schema. Delivered `WORKFLOW.md` matched the committed source byte for byte. |
| Dependencies | Reused the exact previously reviewed wheel selection; each artifact matched its recorded digest before assembly. No package update, resolution or download. |
| Selection lock SHA-256 | `61ada99a0fc052087b868b6e9cf5c56f70362324f1f188c76402c126fb0ebf75`. |
| Staging ZIP SHA-256 | `eb765282d67221df1cc09bebef3b4d6a5b8c28306daa165cbba9a8836271748d`. |
| Installation | CPython 3.10, Linux x86_64; offline setup from the extracted archive with read-only payload files and spaces in its path. The standard runtime location also passed preflight and the bound version command without a custom runtime-home argument. |
| Text, JSON and YAML | A neutral committed document-service fixture produced score 17 with exit 0 in all three formats. JSON and YAML were equal and passed the schema from the pinned engine wheel. Six checks applied; scoring version 2, unverified evidence and `assessment_status: not_run` remained visible. |
| Undetermined | A separate sparse repository produced `verdict: undetermined`, a null score and exit 2; its JSON passed the same schema. |
| Invalid source | An absent selected repository returned exit 1, empty stdout and an error without a traceback. |
| Source and invocation | Source hashes and Git status were unchanged. A shadow engine executable and shadow Claude executable on PATH were not invoked. Credential variables were excluded from the replay environment. |
| Claude host | Claude Code 2.1.302 accepted the manifest and discovered `appsec-advisor:security-score` with one skill and no agents, hooks, MCP servers or LSP servers. An isolated host configuration prevented changes to installed-plugin settings. |
| Host validation scope | The manifest had no errors and two warnings for the existing Advisor metadata fields `analysis_version` and `compatible_analysis_versions`, which the host ignores. The CLI returned no content-validation records; discovery and deterministic local-reference checks supplied the skill evidence. |
| Model calls | None. No live slash-command session or assessment was started. |

This closes the local installed real-engine score-output gap for the selected Linux composition and establishes model-free Claude discovery. It does not close complete legacy input/option parity, authorized remote-source cases, real-engine cancellation, live host invocation, native macOS/Windows, upgrade/rollback, build-tool provenance or release acceptance. Existing focused regression evidence was reused; no synthetic test suite, scanner suite or broad audit was rerun for this documentation and replay work.
