# CVSS v4.0 scoring (evidence-gated)

Applied by `appsec-stride-analyzer` and any sub-agent emitting threat findings. Populate `cvss_v4` **only** when **both** conditions hold:

1. The threat's `cwe` appears in `data/cvss-eligible-cwes.yaml` (injection, XSS, SSRF, path traversal, deserialization, auth-bypass, hardcoded credentials, crypto misuse, similar concrete-sink weaknesses). Read this file once at the start of threat enumeration from `$CLAUDE_PLUGIN_ROOT/data/cvss-eligible-cwes.yaml` (not sliced — always read from the data dir). Keep the CWE set in working memory.
2. `evidence.file` **and** `evidence.line` both point at the exploitable code location — not an inferred or absent line.

For design-only threats, architectural anti-patterns, missing logging/monitoring, policy gaps, coverage observations: **leave `cvss_v4` as `null`.** A missing CVSS score is honest; a guessed one is not.

## Output shape

```json
"cvss_v4": {
  "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
  "base_score": 9.3,
  "severity": "Critical",
  "source": "stride-analyzer",
  "version_fallback": null
}
```

## Base metric derivation

Strictly from the evidence — never guess.

| Metric | How to derive |
|--------|---------------|
| `AV` (Attack Vector) | `N`etwork if the sink is reachable via a public endpoint; `A`djacent for LAN-only; `L`ocal for CLI/file-only; `P`hysical only when physical access is required |
| `AC` (Attack Complexity) | `L`ow if a straightforward request triggers it; `H`igh only if racing, precomputation, or non-trivial preconditions are required |
| `AT` (Attack Requirements) | `N`one unless the codebase shows specific preconditions (non-default config, specific target state) |
| `PR` (Privileges Required) | `N`one for unauthenticated endpoints; `L`ow for authenticated user role; `H`igh for admin role — judged from router/middleware code |
| `UI` (User Interaction) | `N`one for server-side sinks; `A`ctive/`P`assive for client-side XSS, CSRF, open redirect |
| `VC/VI/VA` (Vulnerable System CIA) | Judge from the data or operation at the sink: query results → `VC`; writes → `VI`; crash/resource exhaustion → `VA` |
| `SC/SI/SA` (Subsequent System) | Default `N` unless the threat clearly pivots to another trust zone (e.g. SSRF to internal services) |

## Severity band

Must match the FIRST.org CVSS v4 rubric: `0.0 → None`, `0.1–3.9 → Low`, `4.0–6.9 → Medium`, `7.0–8.9 → High`, `9.0–10.0 → Critical`. Must stay within one band of the threat's qualitative `risk` rating — the triage-validator flags larger gaps.

## Score

**Do not compute `base_score` from scratch.** Build the vector, then copy the score from the FIRST.org CVSS v4 calculator table in your reference knowledge. If unsure, omit `cvss_v4` entirely — the qualitative L/I/Risk rating remains authoritative.
