# Implementation plan — Mass-assignment (CWE-915) detector

**Status:** ready to implement in a clean session
**Owner:** TBD
**Prereqs read:** this file is self-contained; no prior session context needed.

Part of the P1 (STRIDE bespoke-recall) track. Sibling work already landed on
`dev`: `CRYPTO-JAVA-002B` (weak-RNG field pattern) and `CRYPTO-HOMEGROWN-XOR`
(hand-rolled cipher). This is the next bespoke class the STRIDE pass reliably
misses.

---

## 1. Problem & ground truth

The STRIDE analyzer finds textbook CWEs but misses **mass assignment** — a write
handler that binds a request body **directly to a privileged persistence
entity**, letting a normal user set fields like `role`/`admin` they should never
control. No detector emits a CWE-915 finding today, so it never appears.

Ground truth in the reference fixture (`insecure-spring-app/EXPECTED-FINDINGS.md`
§ Access Control):

| Classification | Location | Endpoint | Note |
|---|---|---|---|
| **CONFIRMED-EXPLOITABLE** | `accesscontrol.ProfileController#update` | `PUT /api/profile/me` → `GET /api/profile/admin-preferences` | Direct `@RequestBody AppUser` binding lets a normal user set `role` and `admin`, then pass a DB-admin-gated check. |
| **IMPLEMENTATION-WEAKNESS** | `accesscontrol.AdminUserController#create`, `web.AdminUsersPageController` | `POST /api/admin/users` | Accepts role/admin fields, but the endpoint is admin-guarded → not exploitable by a normal user. |
| **must NOT flag** (counter-example) | `clean.*` | — | Uses `@Valid` DTOs, field allowlists, `@PreAuthorize`. |

Concrete anchors (verified):

- **Sink** — `.../accesscontrol/ProfileController.java:35`
  `@PutMapping("/me") public ResponseEntity<ProfileResponse> update(Authentication authentication, @RequestBody AppUser incoming)` → line 48 `appUserRepository.save(current)`.
- **Entity** — `.../*/AppUser.java`: `@Entity` (line 10), `private String role` (28), `private boolean admin` (31), setters `setRole`/`setAdmin`.

## 2. Why the existing engine cannot do this

`source_auth_scanner.py` and the crypto pack (`data/source-auth-checks.yaml`,
`data/crypto-checks.yaml`) are a **single-line regex engine**: each check is one
`pattern` matched per line, with optional `counter_patterns` in a small window.

Mass assignment is inherently **two-pass / cross-symbol**:

1. Discover which *types* are privileged entities (an `@Entity`/model class that
   carries security-relevant fields).
2. Find write handlers that bind a request body to **one of those types**.

A single regex cannot correlate "`@RequestBody X`" with "`X` is a privileged
entity discovered in another file". → **A dedicated detector script is required**
(single-regex heuristics were considered and rejected: `@RequestBody \w+` +
same-line `role` either over-fits or floods FPs).

## 3. What is ALREADY wired downstream (do NOT rebuild)

CWE-915 is fully supported everywhere **except detection**. Verified:

- `data/weakness-classes.yaml:74,83` — CWE-915 ∈ `missing_authz` cluster (label
  "mass assignment"). A CWE-915 finding folds into the missing_authz weakness
  class automatically.
- `data/compound-chain-patterns.yaml:208` — chain "Mass Assignment →
  Self-Promotion to Admin", keystone `cwe_any: [CWE-915, CWE-285, CWE-862, …]`.
- `data/pentest-eligible-cwes.yaml:107` — CWE-915, technique `mass-assignment`.
- `data/critical-criteria.yaml:59` — CWE-915 "Mass Assignment".
- `classify_cwe("CWE-915") → missing_authz` (confirmed).

**Implication:** emitting one well-formed CWE-915 finding at the sink is enough —
chains, pentest tasks, critical-criteria, and the weakness register light up on
their own. The work is the detector, not the plumbing.

## 4. Design — entity-aware two-pass detector

New script `scripts/mass_assignment_scanner.py`, structured like
`source_auth_scanner.py` (CLI `--repo-root`, `--dry-run`, writes a findings
sidecar). Backed by a small declarative catalog
`data/mass-assignment-signatures.yaml` so patterns are data, not code.

**Pass 1 — privileged-entity discovery.** For each source file, record a type as
a *privileged entity* when BOTH hold:
- it is a persistence entity / model — framework signal: `@Entity` (JPA),
  `extends Model` / Sequelize `sequelize.define` / Mongoose `Schema` (JS),
  `models.Model` (Django), `ActiveRecord::Base` (Rails), EF `DbSet<T>` (.NET); and
- it declares ≥1 **privileged field** from the vocabulary (see §5): `role`,
  `admin`/`isAdmin`, `authorities`/`roles`/`permissions`, `enabled`, `verified`,
  `owner`/`ownerId`/`userId`, `tenant`/`tenantId`, `balance`/`credit`, `price`.

Emit the set `PRIV_ENTITIES = {TypeName → {file, privileged_fields[]}}`.

**Pass 2 — unsafe binding sink.** Find write handlers binding a request body to a
`PRIV_ENTITIES` type without a field allowlist:
- **Spring/Java**: a handler annotated `@PostMapping|@PutMapping|@PatchMapping`
  (or `@RequestMapping(method=…)`) whose signature has `@RequestBody <PrivEntity>`
  or `@ModelAttribute <PrivEntity>`.
- **JS/Express**: `Object.assign(<privEntityInstance>, req.body)`,
  `<Model>.update(req.body)`, `new <Model>(req.body)`, `{ ...req.body }` spread
  into a model save.
- **Django/DRF**: `Model.objects.create(**request.data)` / serializer with
  `fields = '__all__'` on a privileged model.
- **Rails**: `Model.new(params[...])` / `update(params.permit!)` (no strong
  params) on a privileged model.

**Suppress (not a finding)** when a field allowlist / masking is present in the
same handler or on the entity: `params.permit(:a,:b)` (Rails), a request **DTO**
type that is NOT a `PRIV_ENTITY` (Spring — the safe pattern), DRF explicit
`fields = [...]`, `@JsonIgnore`/`@JsonProperty(access=READ_ONLY)` on the
privileged fields, or an explicit `.pick()`/allowlist before assign (JS).

**Emit** one finding per sink handler:
- `cwe: CWE-915`, `severity: High` (raise to reflect exploitability during
  triage — the finding itself is severity-only; the abuse-case verifier + chain
  fold handle exploitability), `finding_type`: reuse/introduce an FT for mass
  assignment (check `data/finding-types.yaml` — add `FT-…` if none), `breach_vector`:
  "Internet User" (needs an authenticated normal user), evidence = handler
  `file:line`, and a scenario naming the privileged fields (`role`, `admin`) and
  the bound entity so the report is actionable.

## 5. Data catalog — `data/mass-assignment-signatures.yaml`

Sketch (a clean session refines):

```yaml
privileged_fields:            # case-insensitive identifiers that make an entity "privileged"
  - role
  - roles
  - admin
  - is_admin
  - isadmin
  - authorities
  - permissions
  - enabled
  - active
  - verified
  - owner
  - owner_id
  - user_id
  - tenant
  - tenant_id
  - balance
  - credit
  - price
entity_signals:               # per-language "this type is a persistence entity"
  java:   ['@Entity', '@Document', '@Table']
  js:     ['sequelize.define', 'extends Model', 'mongoose.Schema', 'new Schema(']
  python: ['models.Model', 'class .*\(.*Model\)']
  ruby:   ['ApplicationRecord', 'ActiveRecord::Base']
  csharp: ['DbSet<', ': IdentityUser']
binding_sinks:                # per-language "request body → entity, no allowlist"
  java:
    write_mapping: '@(Post|Put|Patch)Mapping|@RequestMapping\([^)]*method'
    bind: '@(RequestBody|ModelAttribute)\s+{ENTITY}\b'
  js:
    bind: 'Object\.assign\(\s*\w+\s*,\s*req\.body|{ENTITY}\.update\(\s*req\.body|new\s+{ENTITY}\(\s*req\.body'
  python:
    bind: '{ENTITY}\.objects\.(create|update)\(\s*\*\*request\.(data|POST)|fields\s*=\s*[\'"]__all__[\'"]'
  ruby:
    bind: '{ENTITY}\.(new|update)\(\s*params(?!\.permit\()'
suppressors:                  # presence → not a finding
  - 'params\.permit\('
  - '@JsonIgnore'
  - 'access\s*=\s*READ_ONLY'
  - 'fields\s*=\s*\['        # DRF explicit allowlist
```

`{ENTITY}` is templated per discovered `PRIV_ENTITIES` type in Pass 2.

## 6. Pipeline integration

1. **Run** the scanner in the same phase that runs `source_auth_scanner.py`
   (recon / source-auth scan, Phase 8/9). Confirm the exact call site in
   `agents/phases/phase-group-*.md` and mirror it.
2. **Output** `$OUTPUT_DIR/.mass-assignment-findings.json`. Two clean options —
   pick one after reading `merge_threats.py`'s ingestion of
   `.source-auth-findings.json`:
   - (a) **fold into `.source-auth-findings.json`** (same schema
     `schemas/source-auth-findings.schema.yaml`) so the existing ingestion picks
     it up with zero new wiring — **preferred**; or
   - (b) a separate sidecar that `merge_threats.py` also reads.
3. **Mandatory bridge (critical — the plugin distrusts soft prompts).** Add a row
   to `agents/appsec-stride-analyzer.md` § "Mandatory recon-derived findings":
   *"If the mass-assignment scanner flags a handler → you MUST emit a CWE-915
   Mass Assignment finding."* Mirror the existing AUTHZ / OAuth bridge rows and
   the "Why this is mandatory and not a heuristic" rationale. Without the bridge
   the LLM analyzer will skip it even with the deterministic signal present
   (observed pattern — see the STRIDE inline-shortcut history).
4. **Verify the fold**: after a run, `weaknesses[]` should show `missing_authz`
   gaining the CWE-915 instance, and the compound-chain "Mass Assignment →
   Self-Promotion to Admin" should activate if the admin-gated sink is reachable.

## 7. Test plan

Unit tests (new `tests/test_mass_assignment_scanner.py`, tmp_path fixtures like
`tests/test_crypto_path_xxe_checks.py`):

- **Spring positive** — `@Entity AppUser{role,admin}` + `@PutMapping @RequestBody AppUser` → CWE-915 emitted. (Mirror the real ProfileController/AppUser.)
- **Spring safe DTO** — same handler but `@RequestBody ProfileUpdateDto` (a non-entity with only `email`) → NOT flagged (this is the core FP guard).
- **Entity without privileged fields** — `@Entity Note{title,body}` bound → NOT flagged.
- **Suppressor present** — privileged fields carry `@JsonIgnore` → NOT flagged.
- **JS/Express positive** — `Object.assign(user, req.body)` where `user` is a Sequelize model with `isAdmin` → flagged.
- **Django DRF positive** — serializer `fields = '__all__'` on a model with `is_staff` → flagged.
- **`clean.*` counter-example** — must produce zero findings.

Acceptance: run the scanner `--dry-run` against `insecure-spring-app` and confirm
**exactly** ProfileController (and AdminUserController as a lower-severity
implementation-weakness) are flagged, and `clean.*` is silent.

## 8. Scope / phasing

- **Phase 1 (this plan):** Java/Spring detection end-to-end (sink + entity +
  suppressors) — that closes the reference-fixture gap and proves the two-pass
  design. Ship JS/Express + Django as best-effort in the same catalog but gate
  acceptance on Java.
- **Phase 2 (follow-up):** harden JS/Python/Rails/.NET, add the AdminUser
  admin-guarded case as IMPLEMENTATION-WEAKNESS (lower severity — the sink is
  behind an admin guard; detect the guard to downgrade, don't drop).

## 9. Risks

- **False positives** are the main risk (binding a DTO that happens to be named
  like an entity, or an entity with an incidental `owner` field). Mitigations:
  require BOTH entity-signal AND privileged-field for Pass 1; treat any non-entity
  bound type as safe; honor suppressors. Prefer **under-reporting** (miss ⇒ status
  quo) over FP noise — tune on a corpus before enabling by default.
- **Entity/DTO ambiguity across languages** — Java is cleanest (`@Entity`);
  dynamic languages need conservative signals. Keep non-Java gated.

## 10. Reference index (verified this session)

- Single-regex engine: `scripts/source_auth_scanner.py` (`scan_repo`, glob
  `_glob_to_regex`, `counter_scope` line|window|call). Catalogs:
  `data/source-auth-checks.yaml`, `data/crypto-checks.yaml`.
- Findings ingestion: `merge_threats.py` reads `.source-auth-findings.json`.
- Mandatory-bridge mechanism + rationale: `agents/appsec-stride-analyzer.md`
  § "Mandatory recon-derived findings" (~line 309) and "Why this is mandatory
  and not a heuristic" (~line 372).
- Downstream CWE-915 support: `data/weakness-classes.yaml`,
  `data/compound-chain-patterns.yaml:208`, `data/pentest-eligible-cwes.yaml:107`,
  `data/critical-criteria.yaml:59`.
- Ground truth + anchors: `insecure-spring-app/EXPECTED-FINDINGS.md` (Access
  Control), `accesscontrol/ProfileController.java:35`, `*/AppUser.java`.
