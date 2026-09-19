# Bundled secure-coding baselines

A secure-coding baseline is an instruction file that a coding assistant loads
before it writes code, so the rules apply on every prompt rather than only on
the ones that mention security. The plugin installs one into your assistant's
instruction files and reports at session start whether it is actually loaded.

## What is in here, and when it is used

`/appsec-advisor:install-baseline` installs the latest signed release named in the `baseline` block of `config.json`, and only after its signature and checksum verify, so an installed copy tracks the published releases. The file in this directory is the **fallback** used when that release cannot be fetched or does not verify, for example on an air-gapped machine, behind a proxy, or during an outage. The installer always says which of the two it used.

Because the fallback is pinned at whatever the plugin release shipped, it can be older than the latest release. `--refresh` fetches the release again once it can be read.

Re-vendor the file here with `make baseline-sync`. It stops instead of writing
when the published baseline id has changed, because that id also stands in
`config.json` and in the table below; `make baseline-sync ACCEPT_ID=<new id>`
moves all three together.

| File | Baseline id | Source |
|---|---|---|
| `secure-coding-baseline.md` | `aiscb-0.1.17` | <https://github.com/appsec-foundry/aiscb> |

## Modular releases and compatibility

New official installations use core and discovery first, with modules loaded on demand by the verified Python loader. `aiscb/` carries the signed release manifest, its signature, the complete compatibility file, and the self-contained upstream installer as an authenticated data container. The plugin extracts embedded policy resources without executing that installer. `make baseline-sync` refreshes this bundle together with the complete fallback and configured id.

Use `install-baseline --complete` when the client cannot execute a loader. Updates preserve the installed mode. `install-baseline --migrate` explicitly switches an unchanged plugin-owned installation; altered or unrecorded text is refused. Close affected sessions first and start fresh ones afterward. Upstream aiscb installations remain managed by their own installer.

Project adapters use repository-relative loader commands and require the repository root as working directory. Commit `.appsec-baseline/releases/` with the carrier and import. User snapshots live under `~/.claude/.appsec-baseline/`. Updates and removal retain snapshots for existing sessions. Verification checks the adapter and pinned artifacts; it reports module bodies loaded in the current session as unknown.

## Attribution

The files under `aiscb/` are unmodified assets from the signed upstream release listed above, including its installer data container. They retain the upstream CC BY 4.0 attribution. Do not edit these assets locally; their signatures and hashes must continue to verify.

`secure-coding-baseline.md` is a verbatim copy of the AI Secure Coding Baseline
by Matthias Rohr, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). It is redistributed
here unmodified; edit it upstream, not in this directory. A build that adapts
the rules must change the baseline id (`aiscb-0.1.17+acme`) so the id no longer
claims the published text — see the id convention in the upstream README.

## Shipping a different baseline

An organization does not have to use this one. `baseline` in the org profile
takes an id, a name, and a URL — see `docs/org-profiles.md`. The id is what the
session banner and `/appsec-advisor:verify-baseline` check for, so a company
baseline is verified exactly like this one.
