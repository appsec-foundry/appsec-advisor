# Script layout

Runtime modules are grouped by responsibility. Existing filenames identify each command within its package. Shell entry points and maintainer tools remain directly under `scripts/`.

| Directory | Responsibility |
|---|---|
| `orchestrator/` | Pipeline transitions, dispatch admission, waves and waiters. |
| `analyzers/` | Repository discovery, scanners and architecture checks. |
| `contexts/` | Bounded context construction and projection for analysis. |
| `model/` | Canonical model construction, enrichment, ranking and queries. |
| `renderers/` | Report composition, diagrams, fragments and console summaries. |
| `exporters/` | HTML, PDF, SARIF and Threat Dragon output. |
| `validators/` | Artifact validation, QA and publication gates. |
| `repairs/` | Contracted repairs and preservation of authored sections. |
| `runtime/` | Configuration, hooks, lifecycle, telemetry, status and cleanup. |
| `requirements/` | Requirements retrieval, state, assessment and traceability. |
| `baseline/` | Secure-coding baseline installation and maintenance. |
| `shared/` | Cross-domain parsing, paths, atomic IO and policy helpers. |

Run a command by its full path, for example `python3 scripts/orchestrator/orchestration_controller.py --help`. Direct CLI entry points add the plugin's `scripts/` directory to the import path. Imports use the qualified package name, for example `from shared._atomic_io import atomic_write_text`; they do not search every domain directory or use compatibility wrappers.

Paths to plugin data and schemas are resolved from the plugin root, independent of the caller's working directory. Hook identifiers and artifact provenance labels remain stable when their implementation moves.

When moving a module, update imports, subprocess paths, skill and agent commands, hook commands, permissions, requirement bindings and reviewed source-to-test routes together. Tests keep their existing names under `tests/`; `scripts/run_tests.py` records their source paths. Packaging copies the complete directory tree.
