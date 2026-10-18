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
