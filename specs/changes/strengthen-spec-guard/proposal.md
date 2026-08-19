# Strengthen the specification guard

## Problem

The development hook only recognizes writes to two files. It does not protect
other specifications, PowerShell, or mutating MCP tools, and the checked-in
Claude permissions pre-approve unrelated filesystem and shell access.

## Goal

Protect identifiable mutations below `specs/` with the upstream guard contract
and reduce the project settings to its explicit specification prompt.

## Non-goals

- Changing the plugin runtime permission catalog.
- Removing requirement context from implementation edits.
- Treating shell permission settings as a containment boundary.
