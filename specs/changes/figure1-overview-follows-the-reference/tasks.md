# Tasks

- [x] Boundary lines only at resolved crossings; overview without boundary IDs, legend or interface count (`scripts/figure1_dfd.py`, `RA-15`, `docs/internal/contracts/schema-invariants.md`).
- [x] In-process process-to-process calls move to the detail views (`scripts/figure1_dfd.py`).
- [x] One badge per scenario number on nodes, assets and victim labels; the scenario legend lists each actor once (`scripts/figure1_dfd.py`).
- [x] Header total and node severity counts from `_severity_rollup` (`RA-7`).
- [x] A single classified regular role replaces the generic victim (`RA-11`).
- [x] Component titles use up to three lines before shortening.
- [x] Capability and service-role vocabulary, schemas, evidence validation, producer prompt and figure labels (`data/security-capabilities.yaml`).
- [x] Reconciliation no longer injects an embedded store that a framework-less data component already owns (`scripts/build_stride_dispatch_manifest.py`).
- [x] The architecture analyst receives the role units finalization would add before it writes flows; a unit still added without flows is a run issue (`OR-27`).
- [x] Open accesses to linked embedded engines record `none` with the instantiation as evidence (`scripts/embedded_store_access.py`).
- [x] The architecture prompt states access-group variants, `none` for demonstrably unchecked handlers, and token schemes for resource calls; its budget rose to 13000 bytes.
- [x] Figure 2 shows one statement per card and one card per actor; details stay in tooltips (`scripts/figure2_svg.py`).

## Open

- [ ] Confirm with a fresh juice-shop run that the analyst now emits the login sequence, the public/authenticated API alternative, `none` for the Socket.IO handler, and the OAuth profile call's scheme. These are prompt rules, so only a run shows their effect.
- [ ] The report changelog row counts `threats[]` itself (a run showed "56→50" while the reports led with 54 and 48); it should take its tally from `_severity_rollup` like the other reader-facing totals (`RA-7`).
- [ ] Per-component `.dispatch-context/<component>/` directories from an earlier run survive a full run with `--keep-runtime-files`, and the run-issue aggregator reports evidence coverage for components that no longer exist.
- [ ] Long flow labels still move into "Additional flow labels" when a boundary line splits their straight segment.
- [ ] `discover_identity_providers.py` could assign the service role of the identity providers it generates.
