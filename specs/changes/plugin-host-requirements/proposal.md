# Plugin host requirements

## Approved requirement

The operator approved this wording and its plain-language summary on 2026-10-18:

> **REQ-HST-001:** **Install and change versions.** Installing the plugin from the marketplace provides every engine, skill, and command it advertises. Updating to a newer release or returning to an earlier one replaces them together, and the earlier release then works as it did before.
>
> **REQ-HST-002:** **Use only the bundled components.** The plugin runs only the Analyzer and skills shipped with it, never another copy found on the machine or in a neighboring checkout, and can show which component versions it contains.
>
> **REQ-HST-003:** **Build an organization version.** An organization can publish its own version of the plugin, with its own name, default settings, and selection of skills, from a configuration file without copying or changing plugin code. Settings that the bundled components cannot honor are rejected instead of being silently ignored.
>
> **REQ-HST-004:** **Keep the secure-coding rules current.** The plugin can install, update, and remove the secure-coding baseline in Claude Code's instructions. An update uses the configured source and asks before switching to a changed baseline version.
>
> **REQ-HST-005:** **Switch engines without losing work.** When the plugin moves to a new engine, earlier reports, their history, and saved decisions remain available in the new version.

REQ-HST-004 replaces REQ-CFG-003, which is retired.

## Behavior

Assessment behavior now belongs to [AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer), whose own requirements catalog has absorbed the other entries of this catalog. The Analyzer has retired REQ-CFG-003 as an Advisor responsibility. These five requirements state what the plugin promises as the package around the bundled Analyzer and skills: installation and version changes, pinned components, organization packaging, the baseline lifecycle and migration without data loss.

The engine requirements in this catalog stay in place while the in-repository runtime remains the marketplace runtime. They are retired when the plugin switches to the packaged Analyzer (extraction plan step B3). REQ-HST-001, REQ-HST-002 and REQ-HST-005 are partially guarded: rollback, the absence of sibling-checkout discovery and migration to the packaged engine have no direct regression evidence yet.
