# Export functional requirements as specifications

## Problem

The requirements harvester emits only the YAML catalog consumed by the
requirements audit and threat modeler. Teams that keep observable application
behavior in the same source pages cannot reuse those entries as a compact
specification for coding agents.

Treating every security-catalog entry as application behavior would be wrong.
Authentication and authorization requirements may define observable behavior,
while hashing algorithms, framework choices, SAST configuration, and similar
secure-coding prescriptions do not.

## Goal

Render explicitly selected functional sources as one OpenSpec file, one SpecDD
file, or both without changing the existing catalog output.

## Non-goals

- Inferring whether a requirement is functional from keywords or topic names.
- Turning advisory `SHOULD` or `MAY` guidance into a hard behavior contract.
- Generating SpecDD ownership, modification permission, or repository paths.
- Installing the OpenSpec or SpecDD CLI as a harvester runtime dependency.
- Splitting the generated SpecDD root file across implementation directories.

## User-visible effect

`harvest_requirements.py --format openspec`, `--format specdd`, or repeated
format flags emit the selected single-file specifications. `--format all`
emits the catalog and both specifications.

Each requirement source declares its destinations with `outputs`. Sources
without that field remain catalog-only.
