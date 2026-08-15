# Align requirements, documentation, and enforcement

## Problem

Several requirements and decision rows describe older behavior than the
current contracts and implementation. User documentation also understates the
default trust posture, actor configuration, incremental lifecycle, model
routing, and secret gate. The requirements hook exists but is not wired into
project settings, so its protection never runs.

## Goal

Make each current requirement say what the pipeline does, make user and
internal documentation describe the same behavior, validate documentation
source references, and require an explicit user permission decision before an
LLM changes the requirements catalog or decision register.

## Non-goals

- Expanding producer retries beyond recon and the existing STRIDE retry budget.
- Changing the four-state trust-boundary verdict algorithm.
- Making optional enrichment failures blocking.
- Shipping the development-only requirements hook with the plugin.

## User-visible effect

Cross-repository expectation mismatches remain hypotheses until evidence from
the target repository supports a finding. Documentation now states the default
untrusted posture, rebuild identity exception, actor configuration, and
incremental resolution behavior accurately.
