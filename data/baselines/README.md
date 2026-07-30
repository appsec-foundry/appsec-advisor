# Bundled secure-coding baselines

A secure-coding baseline is an instruction file that a coding assistant loads
before it writes code, so the rules apply on every prompt rather than only on
the ones that mention security. The plugin installs one into your assistant's
instruction files and reports at session start whether it is actually loaded.

## What is in here, and when it is used

`/appsec-advisor:install-baseline` fetches the baseline from the URL in the
`baseline` block of `config.json`, so an installed copy tracks the published
text. The file in this directory is the **fallback** used when that URL cannot
be reached — an air-gapped machine, a proxy, an outage. The installer always
says which of the two it used.

Because the fallback is pinned at whatever the plugin release shipped, it can
be older than the URL. `--refresh` re-fetches an installed copy once the network
is back.

| File | Baseline id | Source |
|---|---|---|
| `secure-coding-baseline.md` | `aisec-0.1` | <https://github.com/matthiasrohr/ai-secure-coding-baseline> |

## Attribution

`secure-coding-baseline.md` is a verbatim copy of the AI Secure Coding Baseline
by Matthias Rohr, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). It is redistributed
here unmodified; edit it upstream, not in this directory. A build that adapts
the rules must change the baseline id (`aisec-0.1+acme`) so the id no longer
claims the published text — see the id convention in the upstream README.

## Shipping a different baseline

An organization does not have to use this one. `baseline` in the org profile
takes an id, a name, and a URL — see `docs/org-profiles.md`. The id is what the
session banner and `/appsec-advisor:verify-baseline` check for, so a company
baseline is verified exactly like this one.
