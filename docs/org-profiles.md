# Org Profiles

Org profiles package organization-specific presets, requirements, context, actors, and skill settings without changing the core plugin.

The current format is `api_version: appsec-advisor.org-profile/v2`. Version 1 profiles continue to work and inherit the default actors.

See the [packaging runbook](internal-plugin-packaging.md) to bundle a profile in a company-branded plugin.

## What an org profile can and cannot do

**Can**

- set per-preset defaults: scan depth, outputs (SARIF / PDF / pentest tasks), quality knobs (QA, architect review, walkthroughs), and guardrails (wall time, cost cap)
- gate CI on failing requirements (`requirements.gate`) or on new threats at a chosen severity (`guardrails.fail_on`)
- apply profile-wide policy: an Opus ceiling (`policy.disable_opus`) and a remote-fetch allowlist (`policy.url_allowlist`)
- declare a single requirements source URL, the default active state for create-threat-model, and a separate standalone-audit toggle
- attach 1–3 short Markdown files with organization, identity, or platform context
- enable a default-on Security Coach, and define its baseline and its own steering topics (triggers → guidance + requirement IDs)
- bundle its own Claude Code hooks that run at the event layer (`hooks`)
- soft-disable optional user-facing skills with a human-readable reason

**Cannot**

- define free-form severity policy or override CVSS eligibility
- override `quick` / `standard` / `thorough` semantics
- inject agent instructions or prompt overrides
- override schemas, QA gates, permissions, or any renderer template
- ship remote markdown context, or code that runs inside the analysis pipeline (bundled hooks run only at Claude Code's event layer, and are listed in the package surface)

## Packaging

The [packaging runbook](internal-plugin-packaging.md) creates a self-contained plugin. The layouts below are for a manual setup.

Two layouts are supported:

```
internal-appsec-advisor/
  appsec-advisor/                       # upstream core, not forked
    config.json                         # sets organization_profile.path
    schemas/org-profile.schema.yaml     # core-owned
    scripts/validate_org_profile.py     # core-owned
  org-profile/
    org-profile.yaml
    context/
      organization.md
      sso.md
      platform.md
```

or, bundled directly in the plugin tree:

```
appsec-advisor/
  org-profiles/
    acme/
      org-profile.yaml
      context/
        organization.md
        sso.md
        platform.md
```

The plugin's `config.json` carries the pointer:

```json
{
  "organization_profile": {
    "enabled": true,
    "path": "../org-profile/org-profile.yaml",
    "default_preset": null
  }
}
```

`organization_profile.path` is resolved relative to the plugin root when not absolute. `default_preset: null` means "use the profile's own `default_preset`."

## CLI and environment

`create-threat-model` accepts these profile flags:

| Flag | Meaning |
|------|---------|
| `--org-profile <path>` | use this profile instead of the packaged default |
| `--preset <name>` | use this preset instead of the profile default |
| `--no-org-profile` | ignore the packaged or env-pointed profile |

For tri-state output toggles:

| Flag | Meaning |
|------|---------|
| `--no-sarif` | disable SARIF even if a preset enables it |
| `--no-pdf` | disable PDF even if a preset enables it |
| `--no-pentest-tasks` | disable pentest-tasks even if a preset enables it |

Environment variables mirror the CLI for headless / CI use:

```
APPSEC_ADVISOR_ORG_PROFILE=/abs/path/to/org-profile.yaml
APPSEC_ADVISOR_PRESET=release-review
APPSEC_ADVISOR_NO_ORG_PROFILE=1
```

Precedence (highest wins):

```
1. core defaults
2. packaged default org profile from config.json
3. APPSEC_ADVISOR_ORG_PROFILE / APPSEC_ADVISOR_PRESET / APPSEC_ADVISOR_NO_ORG_PROFILE
4. --org-profile / --preset / --no-org-profile
5. values from the selected preset
6. direct CLI flags (--sarif, --no-requirements, --max-cost, …)
```

Profile and preset selection happen before preset values are applied. Direct command-line flags always win.

## Schema overview

The schema lives in `schemas/org-profile.schema.yaml`. Highlights:

```yaml
api_version: appsec-advisor.org-profile/v2
organization:
  id: acme
  name: Acme Corp
  profile_version: "2026.05.1"
compatibility:
  core: ">=0.0 <999.0"
default_preset: ci-standard
requirements:
  source:
    requirements_yaml_url: "https://security.acme.example/appsec-requirements.yaml"
    label: "Acme AppSec Requirements"
    fail_mode: cache_fallback
  create_threat_model:
    default_active: true
    quick_default_active: false
llm_context:
  documents:
    - id: sso
      path: context/sso.md
      purpose: identity_ecosystem
      max_bytes: 50000
      applies_to_components: [identity-api]
skill_toggles:
  publish-threat-model:
    enabled: false
    reason: "Publishing is restricted to the AppSec release job."
presets:
  ci-standard:
    base_mode: standard
    outputs:
      yaml: true
      sarif: true
    requirements: { enabled: true }
    quality: { qa_review: auto }
    context:
      document_ids: [sso]
    guardrails: { max_wall_time: 1h, max_cost_usd: 20, tracing: true }
```

`llm_context.documents` declares organization Markdown sources.
`presets.<name>.context.document_ids` selects which sources a run uses;
omitting the list selects all declared documents. The selected documents are
loaded once as untrusted reference data. Context-v2 then projects only
applicable component facts: business purpose, compromise impact, sensitive
assets, security obligations, and explicit assumptions. These facts cannot
select files, agents, tools, models, permissions, threat ratings, actors, abuse
cases, trust boundaries, or controls.
`applies_to_components` can place a hard upper bound on which final component
IDs may receive facts from one document. Omit it when the control analyst must
determine applicability from the document and component semantics.

These rules apply in addition to the schema:

- `default_preset` must exist in `presets`.
- `compatibility.core` must accept the current plugin version.
- `llm_context.documents[].path` must stay under the profile directory and may not traverse symlinks that escape it.
- `presets[].context.document_ids[]` must reference declared documents.
- `target.repo == profile_default` requires `target.repo_path`.
- `target.output_dir` may only use the tokens `{repo_name}`, `{repo_slug}`, `{preset}`, `{date}`, and may not resolve into `.git/`.
- `requirements_yaml_url` must not embed credentials and must be http/s.
- `skill_toggles` keys must name a skill this build ships (or one the package policy removed); disabled toggles must carry a reason.
- `baseline` needs an `id` whenever it sets a source; `baseline.url` must be http/s without credentials; `baseline.file` must exist under the profile directory and must declare the configured id.

## CI gates

Two gates turn a run's outcome into a CI exit code. Each stays advisory until a
preset opts in, and each is overridden by its own command-line flag.

The requirements gate fails when graded requirements come back FAIL — or PARTIAL
too, if you ask for it. It covers both `verify-requirements` and
`audit-security-requirements`.

```yaml
presets:
  ci-standard:
    requirements:
      enabled: true
      gate:
        mode: enforce          # default: advisory (exits 0)
        gate_on: partial       # default: fail
        priority_floor: SHOULD # default: MUST
```

Overridden by `--gate` / `--gate-on` / `--priority-floor`.

The severity gate fails a headless run that adds threats at or above a level.
Interactive runs never gate.

```yaml
presets:
  ci-standard:
    guardrails:
      fail_on: high            # critical | high | medium
```

Overridden by `--fail-on`.

## Policy

`policy:` sits above the presets and applies to every run.

```yaml
policy:
  disable_opus: true
  url_allowlist: [security.acme.example, raw.githubusercontent.com]
```

`disable_opus` downgrades every Opus selection to Sonnet — a cost or compliance
ceiling. The profile can only turn it on: `--no-opus` and `APPSEC_DISABLE_OPUS`
add to it, but nothing switches it back off for a run.

`url_allowlist` limits where the tool fetches from — the requirements catalog and
related-repo threat models. A host matches exactly or as a dotted subdomain, and
a listed internal host is allowed even on a private address. Unlisted
related-repo URLs still hit the full SSRF block (loopback, RFC1918,
cloud-metadata).

## Branding

Cover-page fields for the PDF and HTML report, shared across presets:

```yaml
branding:
  report_title: "Security Assessment"
  contact_name: "AppSec Team"
  contact_email: "appsec@acme.example"
  logo: context/logo.png       # local path or https URL
```

Each field has a matching flag (`--report-title`, `--contact-name`,
`--contact-email`, `--logo`) that wins for one run. Whatever you leave out uses
the default cover.

## Session banner

Every session opens with a short status banner:

1. **Identity** — plugin name and version (or your `headline`) plus `help` when packaged.
2. **Threat model** — findings, age, drift, and the one skill that state calls for.
3. **Coding baseline** — only when the expected baseline is missing or mismatched.

There are no status glyphs. Commands sit on the domain they act on. Two fields
customize the banner, and one turns it off:

```yaml
banner:
  headline: "ACME AppSec Advisor"          # replaces the plugin name on the identity line
  url: "https://git.acme.internal/appsec"  # printed by the help skill
  enabled: true                            # false ships a build that opens silently
```

`headline` is branding on the identity line only. Threat-model facts are always
computed from the repository, so a configured headline can never claim a state
that is not there.

`url` is not printed in the banner; the `help` skill prints it under "More
information". Point it at an internal repository or runbook.

Packaging resolves these fields into the packaged `config.json`, because the
banner runs as a SessionStart hook and must not depend on PyYAML. `--info-url`
overrides `url` for one build; `--info-url ""` drops the line.

Developers have the last word through `APPSEC_BANNER` in the `env` block of
their `~/.claude/settings.json`: `0` silences a banner the organization enabled,
`1` restores one it turned off.

```json
{ "env": { "APPSEC_BANNER": "0" } }
```

Removing the hook from `plugin_surface.hooks` also removes the banner, and drops
the code with it.

## Secure-coding baseline

A secure-coding baseline is an instruction file the coding assistant loads
before it writes code, so an organization's rules apply on every prompt rather
than only on the ones that mention security. The plugin ships one — the
[AI Secure Coding Baseline](https://github.com/matthiasrohr/ai-secure-coding-baseline),
id `aisec-0.1` — installs it with `/appsec-advisor:install-baseline`, and the session
banner flags it when it is missing or mismatched.

Use the `baseline:` block to ship your own instead:

```yaml
baseline:
  id: acme-sec-1.0
  name: "ACME Secure Coding Baseline"
  url: "https://security.acme.example/secure-coding-baseline.md"
  file: baselines/acme-sec.md          # offline fallback, inside the profile dir
```

`name` is what the session banner and both skills call it. Leave it out and they
say `secure-coding baseline` — declaring your own baseline never puts the
plugin's product name on your rules.

Or point at a git repository, for a baseline that is not served as a raw file:

```yaml
baseline:
  id: acme-sec-1.0
  git:
    url: "git@git.acme.internal:appsec/baseline.git"
    ref: main
    path: secure-coding-baseline.md
```

The clone is shallow and uses the machine's existing git credentials; an
unauthenticated clone fails rather than prompting.

### The id is the contract

`id` is what the session banner and `/appsec-advisor:verify-baseline` look for,
and the baseline file must declare it as a line reading:

```markdown
`baseline-id: acme-sec-1.0` — when asked whether a baseline is loaded, answer
from context: every baseline id you carry, with the file you loaded it from.
```

Nothing is installed unless the fetched document carries that marker. That is
what stops a captive-portal login page, a 404 body, or a URL that has moved on
to something else from being written into `CLAUDE.md` as security rules — and
it is why `baseline.file` is validated at package time rather than at install
time on somebody's laptop.

The convention is `<name>-<version>[+<derivative>]`. A derivative of the
configured id (`aisec-0.1+acme`, your adaptation of the published baseline)
counts as installed and is reported with its suffix, so a reader can see the
adaptation. A *newer* version of the same baseline counts as loaded and is
reported as ahead of the id you declared — a baseline is published on its own
schedule, and a machine that updated before your profile did is not broken. An
older version, or a different baseline, stays visible as drift.

Declaring any source replaces the plugin's default baseline everywhere —
banner, verify, and what install writes. The upstream URL and the upstream
bundled copy both carry the upstream id, which your own id check would refuse,
so packaging clears them rather than leaving a source that can only fail.
Ship a `file:` if your users need to install without reaching your server.

### Making it a gate

By default the check reports and nothing fails: which rules a machine loads is
the reader's own configuration. Set `enforce: true` when your organization
requires it — `/appsec-advisor:verify-baseline` then exits non-zero where no
configured baseline is loaded, which is what a CI step gates on. A newer version
of your baseline never fails, because failing it would demand a downgrade.

```yaml
baseline:
  id: acme-sec-1.0
  url: "https://security.acme.example/secure-coding-baseline.md"
  enforce: true
```

Without the profile flag anyone can still ask for a verdict at the call site
with `/appsec-advisor:verify-baseline --enforce`.

`enabled: false` turns the feature off: the banner drops its baseline line and
all three baseline skills report that none is configured. Removing
`install-baseline`, `verify-baseline` and `remove-baseline` through
`skill_toggles` drops the commands as well.

An organization that mandates the baseline should disable `remove-baseline`
that way, with a reason naming the policy. The stronger answer is Claude Code's
managed policy below, which no local command can undo.

### Rolling it out centrally

Nothing is installed twice. Where the baseline already applies, the plugin says
so and installs nothing.

The widest option is Claude Code's own managed policy, which needs no plugin
skill at all: deploy the baseline as the organization-wide `CLAUDE.md`, or put
its text in the `claudeMd` key of `managed-settings.json`. Either applies to
every session on the machine, in every repository, and cannot be switched off
by a user.

| Platform | Managed-policy `CLAUDE.md` |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/CLAUDE.md` |
| Linux and WSL | `/etc/claude-code/CLAUDE.md` |
| Windows | `C:\Program Files\ClaudeCode\CLAUDE.md` |

Both skills report that deployment as the `policy` scope and stop: there is
nothing for a developer to install or keep current, and a second local copy
would only be another file to maintain. Distribute the file with MDM, Group
Policy, or Ansible.

`install-baseline` also reuses what a repository already carries. A baseline in
`AGENTS.md` for Codex and Cursor, in `.github/copilot-instructions.md` for
Copilot, or in a copy somebody committed and never imported is wired up with an
import rather than duplicated — two files with the same rules diverge the day
one of them is edited. `--no-reuse` opts out.

## Actors

Use the `actors:` block to add actors or disable default actor classes:

```yaml
actors:
  inherit_defaults: true              # keep plugin's 9 default actor classes (default)
  disable: []                          # explicitly deactivate by ID (with audit)
  add: actors/*.yaml                  # glob for custom actor definition files
```

Actor definition files live in `org-profile/<name>/actors/` (parallel to `context/`). Each file contains a top-level `actors:` array of actor objects:

```yaml
# org-profile/acme/actors/insiders.yaml
actors:
  - id: ACT-E-01
    label: acme-privileged-contractor
    access: [internal-network, ci-cd-secrets, staging-env]
    trust_positions: [contractor-internal-authority]
    capabilities:
      sophistication: medium
      tooling: [off-the-shelf]
      dwell_time: weeks
      surface_reach: [local, lateral]
    motivation: financial
    heatmap_slug: repo-read
    description: "External contractor with temporary elevated access."
```

Rules:

- Custom actors are merged with plugin defaults. Matching IDs update the default actor.
- `access[]` describes reachable deployment zones; `trust_positions[]`
  describes the actor's stable credential, authority, control, possession, or
  membership position. Declare both so discovery can reject semantic
  duplicates.
- A repository cannot re-enable an actor disabled by the organization profile.
- A disabled actor requires `disable_reason`.

With `inherit_defaults: false`, use `replaces: ACT-D-NN` to identify the default actor class covered by each custom actor.

## Markdown context

Each `llm_context.documents` file:

- must be inside the profile directory
- must fit `max_bytes` (default 50,000; maximum 200,000)
- is scanned for common secret formats
- is treated as untrusted reference data

## LLM policy

Two lists state what your organization allows a language model to receive and to do.
The analysis compares each component with an LLM surface against them; without a list
it records nothing, because neither question can be answered from code.

```yaml
llm_policy:
  permitted_data_classes:
    - internal-documentation
    - pseudonymised-usage-metrics
  approval_required_actions:
    - payment or refund
    - deletion of customer data
    - outbound message to a customer
```

A data class the component sends to a prompt, tool call, retrieval index, or shared
memory but that is not on the list becomes a finding. For each approval-required
action, the analysis checks whether an enforced gate exists in code — an instruction
in a system prompt does not count as one.

## Adding your own skills

An organization can ship its own skills alongside the upstream ones. Put each
in the profile directory and point at them:

```yaml
skills:
  add: "skills/*/SKILL.md"     # the default; relative to the profile directory
```

```text
org-profile/
  org-profile.yaml
  skills/
    acme-release-check/
      SKILL.md
```

Claude Code discovers skills by convention — every `skills/<name>/SKILL.md`
under the plugin root — so packaging copies each matched directory into the
build. An added skill is a skill in every other respect: it appears in the
packaged README, `plugin_surface.skills` can exclude it, `skill_toggles` can
disable it, and the `skill-policy-gate` hook enforces that toggle.

Two things abort the build rather than resolve quietly:

- **A name that collides with an upstream skill.** Replacing, say,
  `create-threat-model` would change what its command does without anyone
  deciding to.
- **Frontmatter that would not pass for an upstream skill.** `name` must match
  the directory, `description` must be non-empty and at most 1024 characters,
  and no other keys are allowed. The description is the only text the model
  sees when choosing a skill, so a malformed one degrades routing silently.

Write your skill's commands in your own namespace. The namespace-leak check
fails the build if the upstream one appears anywhere in the package.

Added skills are listed under `skills.org_added` in `package-surface.json`, kept
distinct from the upstream ones so the artifact surface stays auditable.

## Skill toggles

Skills can be disabled with a reason. The policy is enforced by the
`skill-policy-gate` hook, which covers both ways a skill is reached: a person
typing `/<plugin>:<skill>`, and Claude invoking it through the `Skill` tool.
Enforcement sits outside the model on purpose — a check written into a skill's
prose is an instruction, and an instruction can be skipped.

A disabled skill is refused with the organization's reason:

- **User skills** (e.g. `export-threat-model`, `publish-threat-model`): blocked with the reason printed. Exit code 30.
- **Help-only**: `--help` still renders even when the skill is disabled. Exit code 10.
- **Operational / repair skills** (`status`, `check-permissions`, `clean-run-state`, `fix-run-issues`, `threat-model-health`): the org profile can warn but never hard-blocks them. Exit code 20.

Any skill this build ships can be named. The key set is derived from
`skills/*/SKILL.md` rather than kept as a list, so a skill added upstream — or
one your profile adds — is togglable the moment it exists. A skill your
package policy removed may still be named, so the toggle that documents *why*
it is gone does not contradict the exclusion; a typo is still rejected.

Without a skill policy, all skills remain enabled.

### Where the policy is read from

Two sources, in this order:

1. `.org-profile-effective.json` — what the current run resolved, including
   preset and CLI effects.
2. `skill_toggles` in the packaged `config.json`, which packaging resolves from
   this profile at build time.

The second matters more than it looks. The effective profile is written by a
`create-threat-model` run into its output directory, so before the first scan
there was nothing to read and every skill ran — while `status` reported it as
disabled. The packaged copy gives a fresh clone the same answer as a scanned
one, the way the banner and baseline blocks already work.

### Toggle or remove?

Skill toggles block a command at runtime and explain why. To take a skill out
of the package entirely — no command, no code, not in the README — use
`plugin_surface.skills` in `org-profile/package-policy.yaml`, described in the
packaging runbook. Use a toggle when people should learn what the policy is;
use the package policy when the command should not exist.

## Security Coach

`security_coach.enabled_by_default: true` activates the coach for the team. `APPSEC_COACH=0` still disables it for one session.

`security_coach.max_requirements_per_topic` overrides the static default (3) for per-prompt requirement injection.

### Your own steering rules

Define your own coaching behaviour instead of forking the plugin. A topic is a
trigger (which prompts it fires on) and what it injects (guidance text and
requirement IDs from your catalog):

```yaml
security_coach:
  enabled_by_default: true
  baseline: "Follow Acme secure defaults on every change."   # optional, replaces the built-in
  topics:
    payments:
      triggers: [payment, payout, refund]
      guidance: Post to the ledger idempotently; refunds need dual approval.
      requirements: [SEC-PAY-IDEMPOTENT, SEC-PAY-DUAL-APPROVAL]
```

Your topics are added to the built-in ones (auth, injection, crypto, …); an org
topic with the same name replaces the built-in. Set `inherit_default_topics: false`
to use only your own. Guidance is injected as advice — like the packaged context,
it never overrides tool behaviour, gates, or severity.

## Status output

`/appsec-advisor:status` adds an *Org Profile* section when a profile is active or merely configured:

```
Org Profile
-----------
  Status         active
  Organization   acme
  Version        2026.05.1
  Path           /workspace/internal-appsec-advisor/org-profile/org-profile.yaml
  Preset         ci-standard (base: standard)
  Requirements   Acme AppSec Requirements
  LLM context    organization, sso, platform
  Disabled skills publish-threat-model
```

Before the first run resolves the profile, the status is `configured (not yet resolved)`.

## Examples

Use a different preset for a single run:

```
/appsec-advisor:create-threat-model --preset release-review
```

Scan an external repo with an AppSec preset:

```
/appsec-advisor:create-threat-model --preset appsec-verification --repo ../payments-api
```

Force a specific profile for a single run:

```
/appsec-advisor:create-threat-model --org-profile ./security/org-profile.yaml --preset ci-fast
```

Ignore the packaged profile for one run:

```
/appsec-advisor:create-threat-model --no-org-profile
```

Override requirements for one run:

```
/appsec-advisor:create-threat-model --requirements https://security.example.test/r.yaml
/appsec-advisor:create-threat-model --no-requirements
```

## Abuse cases

The plugin loads cases in this order:

1. **Plugin standard library** — `data/abuse-cases/default-library.yaml` (the
   `AC-T-NNN` mandatory set), unless an org profile sets
   `abuse_cases.inherit_defaults: false`.
2. **Org profile** — `abuse_cases.add` is a glob (relative to the org-profile
   directory) of extra case files; `abuse_cases.disable` removes ids. Use the
   `ORG-AC-NNN` ID prefix.
3. **Repository** — any `*.yaml` under
   `<repo>/.appsec/abuse-cases/` in the target repository is loaded
   automatically. Use the `REPO-AC-NNN` ID prefix. IDs must be unique.
4. **One scan** — `--abuse-case-file <repo-relative-path>` adds a YAML file
   below the target repository. Repeat `--only-abuse-case <ID>` to run selected
   cases only.

Example repo-local case (`<repo>/.appsec/abuse-cases/payments.yaml`):

```yaml
schema_version: 1
abuse_cases:
  - id: REPO-AC-001
    title: Refund replay via idempotency-key reuse
    source: mandatory
    attacker:
      actor_id: authenticated-user
      initial_access: authenticated_low_priv
    goal: Issue duplicate refunds to an attacker-controlled balance.
    chain:
      - step: 1
        label: Reuse a prior idempotency key
        grants: replayed-request
        finding:
          title: Refund endpoint accepts a reused idempotency key
          cwe: CWE-841
          stride: Tampering
          severity: High
          mitigation_title: Enforce one-time idempotency keys per payment intent
          remediation: Bind each key to one payment intent and reject reuse after a successful refund.
        probe:
          sink_patterns: ["idempotenc(y|e)[-_ ]?key"]
```

Use `scope_qualifier.required_signals` and `path_patterns` to limit a case to
relevant repositories. `probe.sink_patterns` match existing findings first; a
direct source match is checked by the verifier before it is reported.

Add `finding` when a direct source match should become a normal finding after
verification. It supplies the classification and mitigation and links the
resulting finding to the abuse-case step. Without it, the case remains a
scenario check and no finding is created.

Add `release_gate` to fail CI for selected final verdicts:

```yaml
release_gate:
  fail_on: [fully_viable]
  applies_to_presets: [release-review]
```

## Hooks

An org can bundle its own Claude Code hooks in the packaged plugin — one central
artifact carrying its own event handlers. Declare them and put the scripts under
`org-profile/hooks/`:

```yaml
hooks:
  block-risky-bash:
    event: PreToolUse
    matcher: Bash                                   # PreToolUse / PostToolUse only
    command: python3 ${CLAUDE_PLUGIN_ROOT}/org-profile/hooks/guard.py
```

Each hook is recorded in `package-surface.json` (org-owned, separate from the
upstream hooks) so the artifact surface stays auditable; `plugin_surface.hooks`
can exclude one by id. Hooks run at Claude Code's event layer — they can add
context or block a tool call, but never reach the analysis pipeline; findings,
severity, and schemas stay core-owned. The full mechanism and rules live in the
[packaging runbook](internal-plugin-packaging.md).

## MCP servers

The `mcp` block lets an org wire its own MCP servers — e.g. an internal SAST or
SCA service — into the packaged plugin. At build time the packager emits the
declared servers into the plugin's `.mcp.json`, so Claude Code loads them
whenever the internal plugin is active. Which servers are emitted can be narrowed
by the [package policy](internal-plugin-packaging.md) allowlist
(`plugin_surface.mcp_servers`); by default every declared server is included.

```yaml
mcp:
  servers:
    acme-sast:                       # http/sse transport
      type: http
      url: ${ACME_SAST_MCP_URL}
      headers:
        Authorization: Bearer ${ACME_SAST_TOKEN}
    acme-sca:                        # stdio transport
      command: ${CLAUDE_PLUGIN_ROOT}/bin/sca
      args: ["--json"]
```

Rules:

- Each server sets **either** `url` (http/sse) **or** `command` (stdio).
- **Secrets never go in the profile.** Reference tokens and internal URLs as
  `${ENV_VAR}`; Claude Code expands them at load time, and `${CLAUDE_PLUGIN_ROOT}`
  resolves to the installed plugin directory. A credential embedded directly in a
  server `url` (`user:pass@host`) is rejected at validation time.
- **MCP tool output is untrusted reference data.** Like markdown context, it can
  inform findings but never changes severity rules, QA gates, schemas,
  permissions, or tool behavior. Only wire in endpoints you trust.
