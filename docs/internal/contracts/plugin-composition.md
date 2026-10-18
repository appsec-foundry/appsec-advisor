# Offline staging composition

This contract covers the first P3 assembly and bootstrap primitives. The [composition plan](../analysis/plan-appsec-advisor-composition-2026-10-18.md) permits offline P2–P4 work before A7 after explicit operator approval. It still requires qualification before release, public cutover, or removal of the existing runtime. The marketplace, existing skills, hooks, organization packager, and public runtime remain on the current implementation.

## Selected inputs

[`components-lock.schema.json`](../../../schemas/components-lock.schema.json) defines a reviewed selection, not a discovered package inventory. A composition has exactly one host and one engine; additional skill ZIPs, dependency wheels, and build-tool wheels are explicit inputs. Each selection records an HTTPS source identifier, immutable revision, package version, SHA-256, license identification, interface version, required capabilities, and explicit source-to-destination file mappings. Host, engine and skill code require a full committed revision; published dependency/build-tool artifacts may instead identify their reviewed source by `sha256:<digest>`. Source identifiers are provenance records, never download instructions. The builder performs no network request and executes no component code.

Only interface 1 and `unqualified-staging` are accepted. Capability names record required operations; their presence does not establish provider or workflow qualification. Runtime Python minor versions and OS/architecture combinations are selected staging targets, not claims of supported platforms. No production lock or runtime matrix is provided until actual component/dependency artifacts and native platform evidence exist. This format intentionally cannot label an offline build qualified.

The operator supplies artifact files from reviewed committed revisions and verifies their build provenance before approving the lock. A matching digest proves equality with the reviewed artifact; it does not independently prove how an upstream wheel was built. Build tools are locked and delivered for provenance, but are never installed by runtime setup. Source-only packages and implicit runtime dependency resolution are not supported.

## Assembly boundary

Run the builder from the Advisor checkout with the existing Python dependencies already installed:

```bash
python3 scripts/compose_plugin.py --lock /reviewed/components.lock.json --artifacts /reviewed/artifacts --output /staging/new-output-directory
```

The output directory must not exist, and its parent must exist. Failure before assembly validation creates no output. The builder does not read sibling checkouts, copy the repository tree, or rewrite component namespaces. The lock must explicitly select the host manifest, entry skill, host bootstrap, all referenced skill resources, and license texts required by each component's license. Engine implementation remains inside its pinned wheel; engine-owned entry instructions can be selected from that same wheel.

Artifact admission verifies the digest and all ZIP members, including unselected members. It rejects traversal, absolute/drive/stream paths, links and special files, encrypted entries, Windows reserved names, ambiguous separators, duplicate/case-colliding names, file/directory collisions, and non-ASCII paths. File, entry, expanded-byte, total-input and delivered-byte limits are enforced by the builder. Output collisions and reserved generated paths fail closed. Wheel metadata must match the locked version; duplicate distribution names fail. A staging composition cannot include two implementations at the same command path.

Outputs are the staging ZIP, `SHA256SUMS`, license notices, and a delivered [`component-manifest.json`](../../../schemas/component-manifest.schema.json). The archive contains its canonical lock and the same notices and manifest. The manifest identifies selected components and records hashes and sizes of all selected payload files; generated metadata is not self-hashed. Bootstrap verification rejects size mismatches before hashing. ZIP ordering, timestamps and modes are normalized. Build tools and dependency wheels are distributed as opaque verified wheel files, not unpacked into the plugin source namespace.

The host artifact must include `scripts/composition_runtime.py` unchanged from its reviewed Advisor revision. The command invocation binding is deliberately host-specific; portable skills must not embed `CLAUDE_PLUGIN_ROOT` or checkout-relative engine paths. Portable source preparation is recorded in the [offline evidence](../analysis/composition-offline-evidence-2026-10-18.md); complete host workflow qualification and organization packaging adaptation remain pending. Assembling arbitrary legacy skill files does not establish compatibility.

The optional lock selection `"skill_bindings": ["security-score"]` enables the first host binding. The lock must select the portable `skills/security-score/SKILL.md`, `dependencies.json`, `references/compatibility.md`, and the host bootstrap. Assembly preserves the portable entry byte for byte as adjacent `WORKFLOW.md`, retaining relative references and source-component provenance, and emits a separate Advisor entry with the pinned invocation. A pre-existing `WORKFLOW.md` is a collision. Other skills and compositions without this selection keep their selected entries unchanged. The binding requires interface 1, scoring version 2, no model calls or model prerequisites, and only the public version, capabilities and score commands; incompatible dependency declarations stop assembly.

## Explicit runtime lifecycle

After extracting a staging archive into a dedicated installed location, select an existing Python interpreter matching the lock. The bootstrap uses the Python standard library and does not need system `jsonschema`. These are separate actions:

```bash
python3 /installed/plugin/scripts/composition_runtime.py setup --plugin /installed/plugin
python3 /installed/plugin/scripts/composition_runtime.py preflight --plugin /installed/plugin
python3 /installed/plugin/scripts/composition_runtime.py run --plugin /installed/plugin -- score /source/repository --json
```

On Windows, use the selected Python executable instead of assuming `python3`. Arguments and paths containing spaces must be quoted by the invoking host. The launcher passes engine arguments as a list without a shell. The `--` separator distinguishes bootstrap options from public engine arguments. `--runtime-home` is an explicit operator override; storage inside any Git checkout or the plugin is rejected. POSIX storage must belong to the current user and must not be writable by other users; Windows storage stays under the current user's directory, with native ACL qualification still pending. Default storage uses the operating system's user application-data location.

Setup verifies payload integrity, interpreter and platform selection before writing. Runtime identity binds the canonical lock, full Python version, interpreter path, and platform. Setup serializes creation per identity and creates the venv at its final path; no environment is relocated. Installation copies only verified locked engine/dependency wheels into private temporary input storage and uses `pip --no-index --no-deps --only-binary=:all: --require-hashes`. Dependency closure is checked offline afterward; missing wheels or incompatible dependencies fail setup. No source distribution is compiled. Inherited Python paths and pip index/configuration settings are removed from subprocess environments.

The installed engine must report the locked version and interface before a receipt is atomically activated. Setup failure removes its incomplete environment. Existing completed environments are reused only through preflight. A setup lock left by an externally killed bootstrap requires operator inspection; setup does not guess that another process is dead. Concurrent setup is rejected without deleting another process's state.

Required operation declarations must explicitly report boolean `available: true`. A selected score binding additionally checks the portable requirements against the installed engine before activating a receipt. Bound invocations use `run --skill security-score -- <engine arguments>`; each invocation rechecks scoring version 2 and the absence of model calls, and refuses other workflows or a binding absent from the lock. The bootstrap invokes the selected interpreter directly and returns engine stdout, stderr and exit status. The binding does not grant source retrieval, model use or setup permission.

Preflight verifies selection, file hashes and the completed receipt without installing packages, executing the engine, invoking a model, or writing runtime state. `run` requires successful preflight and invokes the exact venv interpreter with isolated Python mode and the public `appsec_analyzer.cli` module. A different engine executable on `PATH` is irrelevant. Model credentials and host prerequisites remain a separate Analyzer responsibility; no qualified model is implied by a successful Python setup.

Invocation has a bounded deadline. On timeout or interruption it attempts bounded public cancellation when an explicit `--output` is supplied, then terminates the launched process tree. This is recovery, not successful assessment completion. Native Windows process-tree cancellation, all selected platform/interpreter combinations, and upgrade/rollback remain unqualified until exercised on those systems. No platform support is declared by Unix tests or mocked platform branches.

## Verification and remaining integration

`tests/test_compose_plugin.py` covers deterministic assembly, delivered inventory, tampering, mismatches, collisions and archive abuse. `tests/test_composition_runtime.py` uses a neutral synthetic wheel to exercise a real offline venv/pip installation outside source checkouts, read-only plugin files, spaces, shadow executables, setup recovery and Unix descendant cancellation. The synthetic wheel is test data only; no plugin build consumes it. These checks establish bootstrap behavior, not installed Analyzer assessment quality or cross-platform qualification.

Pending P3/P4 work includes a real reviewed composition lock and artifact set, dependency/build-tool qualification, portable entry skill bindings and references, organization packaging from the assembled tree, public hook/result operations, settings dispatch, permission updates, native platform checks, and archive upgrade/rollback. No existing workflow may switch or producer be deleted merely because these staging primitives pass.
