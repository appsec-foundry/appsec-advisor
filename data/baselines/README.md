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
| `secure-coding-baseline.md` | `aiscb-0.1.14` | <https://github.com/appsec-foundry/aiscb> |

## Attribution

`secure-coding-baseline.md` is a verbatim copy of the AI Secure Coding Baseline
by Matthias Rohr, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). It is redistributed
here unmodified; edit it upstream, not in this directory. A build that adapts
the rules must change the baseline id (`aiscb-0.1.14+acme`) so the id no longer
claims the published text — see the id convention in the upstream README.

## Shipping a different baseline

An organization does not have to use this one. `baseline` in the org profile
takes an id, a name, and a URL — see `docs/org-profiles.md`. The id is what the
session banner and `/appsec-advisor:verify-baseline` check for, so a company
baseline is verified exactly like this one.
