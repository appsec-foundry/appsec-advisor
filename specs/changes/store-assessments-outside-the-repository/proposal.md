# Store assessments outside the repository

## Problem

Assessment results name exploitable weaknesses with file and line, attack paths, and pentest tasks. They are written to `docs/security/` inside the analyzed checkout, where an ignore rule protects only against `git add .`, not against forced adds, copied or archived checkouts, synchronized folders, CI workspace uploads, or other tools reading the repository. `REQ-PUR-004` still names the deliverable "threat model" although the result is now the Security Assessment Report described in the [assessment concept](../../../docs/proposals/application-security-assessment-concept.md).

## Goal

- `REQ-PUR-004`: "The assessment report must help developers, architects, and AppSec reviewers understand risks and plan remediation."
- New `REQ-TRU-005`: "Assessment results must be stored outside the analyzed repository by default and be readable only by the current user." Coverage is advisory until the storage resolver and its boundary tests exist.
- New decision `AS-1`: "Assessments are stored per application under the user data directory as `<repo-name>-<hash8>`, hashed from the normalized origin URL (or the canonical root path without a remote); `--output` overrides."

## Non-goals

- Implementing the storage resolver, the artifact rename, or the legacy migration; those follow as their own changes with guards.
- Moving repository-owned inputs such as business context, known threats, abuse cases, or actors out of the checkout.

## Approval

The operator approved all three wordings on 2026-10-17.
