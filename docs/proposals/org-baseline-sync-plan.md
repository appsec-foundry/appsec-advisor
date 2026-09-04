# Implementation plan — re-vendor an org profile's baseline from its configured source

**Status: Scope A done** (2026-08-28). `sync_baseline.py --profile` ships, the requirement is confirmed as REQ-CFG-003, and `docs/org-profiles.md` documents the command. Scope B belongs to the packaging repository and is not done here. Scope C was decided against.

**Goal:** An organization that ships its own secure-coding baseline can refresh the copy it vendors into its org profile from the `url` or `git` source that same profile declares, and learns when the two have drifted apart — the way `make baseline-sync` already does for the upstream baseline bundled in this repository.

## What already works

`_org_profile_baseline` in `scripts/package_internal_plugin.py` resolves the profile's `baseline` block into the packaged `config.json`, replacing the upstream id, source, and fallback path wholesale. Everything downstream therefore already speaks the organization's baseline:

- `/appsec-advisor:verify-baseline` compares what is loaded against the organization's `id`, not the upstream one.
- `/appsec-advisor:install-baseline --refresh` fetches the organization's `url` or `git` source and overwrites the installed copy.
- `validate_org_profile._check_baseline` fails the build when `baseline.file` is missing or declares an id that is not the profile's `id` (equal, or an `id+derivative` suffix).

## The gap

Nothing ever compares `baseline.file` with the `url` or `git` source beside it in the same profile. Text edited under an unchanged id passes every check above, so an organization's package can vendor a copy that is months behind the source it advertises, and the packager reports success. This is exactly the drift `sync_baseline.py` exists to surface, but that script can only address this repository: it reads `plugin_root/config.json`, writes `fallback_file` under the plugin root, and bumps an id in `config.json` plus the README table in `data/baselines/`.

A second gap follows from the first: an org build has no offline install path anyway when its own copy is stale, because `install-baseline --offline` would install text the organization no longer publishes.

## Scope A — generalize `scripts/sync_baseline.py` (this repository)

Introduce one resolved sync target and two loaders behind it, so the fetch, id comparison, write, and reporting stay exactly as they are today.

| Aspect | Plugin mode (today) | Profile mode (new) |
|---|---|---|
| Selector | `--plugin-root <dir>` (default: this repo) | `--profile <path>/org-profile.yaml` |
| Source config | `config.json` → `baseline` | profile YAML → `baseline` |
| Vendored file | `fallback_file`, resolved under the plugin root | `file`, resolved under the profile directory |
| Id lives in | `config.json` and `data/baselines/README.md` | the profile YAML |
| Follow-up gate named in the report | `make check` | `scripts/validate_org_profile.py` |

Behavior that must not change: the fetch never falls back to the vendored copy, a document without a `baseline-id:` marker is refused, a published id that does not match stops with exit code 3 until `--accept-id` names it, and every edit is computed before the first write.

Profile-mode specifics:

- Resolve `file` with the same containment guard `validate_org_profile` uses, so a path escaping the profile directory is refused identically. Promote `_resolve_under` to a public helper and call it from both places rather than writing a second guard.
- A profile that declares no `file` is refused with a message naming the consequence: there is nothing to vendor, and the package has no offline install path.
- A profile that declares neither `url` nor `git` is refused by the existing check in `fetch_published`.
- An accepted id change rewrites the `id:` line in the profile YAML by targeted substitution, so comments, ordering, and quoting survive. Require exactly one line matching the old id inside the `baseline` block; on zero or several, refuse and tell the maintainer to make the edit by hand rather than guessing which line is meant.
- There is no README table in a profile, so the corresponding step is dropped instead of warned about.

`--dry-run` and `--accept-id` keep their meaning in both modes. `--plugin-root` and `--profile` are mutually exclusive.

## Scope B — the invocation (packaging repository)

The org profile lives in the packaging repository, so the refresh commits there and is driven from there. Nothing in this plan calls the script during a build:

```
python3 <plugin>/scripts/sync_baseline.py --profile org-profile/org-profile.yaml [--dry-run] [--accept-id <id>]
```

Wire it as a `make baseline-sync` equivalent plus a scheduled CI job that runs it with `--dry-run` and fails when the vendored file has drifted. Keep it out of the packaging build itself: `package_internal_plugin.py` copies the profile into a temporary build directory, so a refresh there would be written to a directory that is discarded, and it would make packaging depend on a reachable host. That is the same reason `baseline-sync` is not part of `make check` or `make release-check`.

## Scope C — build-time freshness check (optional, decide before building)

`package_internal_plugin.py` could take an opt-in `--check-baseline-freshness` that fetches the configured source and reports when the packaged file differs. It stays off by default and never writes.

Recommendation: leave it out for now. The scheduled job in Scope B answers the same question earlier and without a network call in the build. Build it only if packages are cut from environments where that job cannot run.

## Tests

Extend `tests/test_sync_baseline.py`, reusing the existing `serves` fixture that stubs `install_baseline._fetch`:

- profile mode rewrites the vendored file when the id is unchanged and the text differs;
- identical text writes nothing;
- `--dry-run` writes nothing;
- a derivative id (`acme-1.0+team`) counts as the same version;
- a new published id stops with no writes, and `--accept-id` then moves the file and the profile YAML together;
- an ambiguous or absent id line in the YAML refuses instead of editing;
- a `file` outside the profile directory, a missing `file`, and a profile without `url`/`git` are each refused with their own message;
- unchanged plugin-mode coverage stays green.

No test may reach the network. The suite stays inside `make check`; the script itself stays out of every gate.

## Documentation

- `docs/org-profiles.md`: how an organization keeps its vendored baseline current, and what a stale copy costs (offline installs serve withdrawn rules).
- `CHANGELOG.md`: one bullet — the baseline sync command also refreshes an org profile's own baseline.
- `data/requirement-bindings.yaml`: bind the new requirement to `scripts/sync_baseline.py` and the tests above.

## Contract — proposed requirement wording (unconfirmed)

Proposed for `specs/requirements.md`, to be confirmed verbatim by the operator before anything is written:

> **REQ-CFG-00x — A vendored baseline can be refreshed from the source that declares it.** Where a secure-coding baseline is configured with both a fetchable source and a vendored copy, the copy can be refreshed from that source, and a refresh reports whether the two had drifted. A published id that differs from the configured one stops the refresh until the new id is accepted explicitly, and accepting it updates the copy and every place declaring the id together. A refresh never falls back to the vendored copy and is never part of a release gate.

This wording covers the plugin's own bundled baseline as well, which the script already does, so one requirement binds both modes.
