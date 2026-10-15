# Accept Git URLs in headless assessments

## Approved requirement

The operator approved this wording and its summary in the implementation conversation:

> **REQ-PUR-003:** Users must be able to select local repositories or Git URLs and a separate output location, including combined assessments of multiple repositories.

Single and combined headless assessments accept local repositories and Git URLs. HTTPS tokens, SSH authentication, temporary checkout ownership and cleanup are implementation contracts documented in `docs/headless-mode.md`.

## Scope

Provision explicitly selected HTTPS and SSH repositories before the existing headless runner. Keep assessment admission, source capture, trust checks and publication with their existing owners. Preserve output and recovery state outside the temporary checkouts.
