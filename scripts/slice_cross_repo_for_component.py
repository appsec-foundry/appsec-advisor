#!/usr/bin/env python3
"""
slice_cross_repo_for_component.py — deterministic per-component slice of the
cross-repo register for STRIDE dispatch.

Replaces the LLM-driven "match via interfaces/trust boundaries" step in
``agents/phases/phase-group-threats.md``. The orchestrator runs this
script per component before dispatching the STRIDE analyzer; the output
goes to ``$OUTPUT_DIR/.dispatch-context/<COMPONENT_ID>/cross-repo.json``.

Matching is layered, in order:

  1. Explicit ``interfaces[].cross_repo`` list on the component (when the
     classifier or recon writes structured interface metadata, this is the
     authoritative signal).
  2. Substring match of the dependency name in any of:
       * component name (case-insensitive)
       * component description
       * any string in ``component.interfaces[]``
       * any string in ``component.trust_boundaries[]``
  3. Substring match of the dependency interface text in any of the same
     fields.

When neither (1), (2), nor (3) matches, the dependency is not part of the
slice. Empty slices are emitted as ``[]`` so the dispatcher always has a
stable file shape.

CLI usage::

    python3 slice_cross_repo_for_component.py \\
        --register <PATH-to-.cross-repo-register.json> \\
        --component-id <ID> \\
        --component-name <NAME> \\
        [--component-description <TEXT>] \\
        [--interface <STR>]... \\
        [--trust-boundary <STR>]... \\
        --output <PATH-or-->
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _component_text_corpus(
    name: str,
    description: str,
    interfaces: list[str],
    trust_boundaries: list[str],
) -> str:
    pieces = [name, description, *interfaces, *trust_boundaries]
    return " | ".join(p for p in pieces if p).lower()


def _entry_matches(entry: dict[str, Any], corpus: str) -> bool:
    name = (entry.get("name") or "").strip().lower()
    interface = (entry.get("interface") or "").strip().lower()
    if name and name in corpus:
        return True
    if interface and interface in corpus:
        return True
    return False


def slice_for_component(
    register: dict[str, Any],
    *,
    component_name: str,
    component_description: str = "",
    interfaces: list[str] | None = None,
    trust_boundaries: list[str] | None = None,
    explicit_names: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Return the cross-repo deps that apply to a single STRIDE component.

    The output mirrors the documented ``CROSS_REPO_CONTEXT`` shape consumed
    by ``appsec-stride-analyzer``. Findings are included only for declared
    entries (siblings/submodules/recon are metadata-only).
    """
    corpus = _component_text_corpus(
        component_name,
        component_description,
        interfaces or [],
        trust_boundaries or [],
    )
    explicit_set = {n.lower() for n in (explicit_names or [])}

    out: list[dict[str, Any]] = []
    for entry in register.get("entries", []):
        name = entry.get("name") or ""
        if explicit_set and name.lower() in explicit_set:
            match = True
        else:
            match = _entry_matches(entry, corpus)
        if not match:
            continue
        sliced: dict[str, Any] = {
            "name": name,
            "source": entry.get("source"),
            "type": entry.get("type"),
            "interface": entry.get("interface"),
            "threat_model": (entry.get("threat_model") or {}).get("status"),
            "threats_open": (entry.get("threat_model") or {}).get("threats_open"),
            "threats_critical": (entry.get("threat_model") or {}).get("threats_critical"),
        }
        if entry.get("source") == "declared" and entry.get("interface_findings"):
            sliced["findings"] = (entry.get("interface_findings") or {}).get("findings", [])
            sliced["findings_excluded"] = (entry.get("interface_findings") or {}).get("excluded_count", 0)
        out.append(sliced)
    return out


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    p.add_argument("--register", required=True, type=Path)
    p.add_argument("--component-id", required=True)
    p.add_argument("--component-name", required=True)
    p.add_argument("--component-description", default="")
    p.add_argument("--interface", action="append", default=[])
    p.add_argument("--trust-boundary", action="append", default=[])
    p.add_argument("--explicit-name", action="append", default=[])
    p.add_argument("--output", required=True, help="destination JSON path, or '-' for stdout")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not args.register.is_file():
        # Stable behaviour: missing register → empty slice, exit 0.
        register: dict[str, Any] = {"entries": []}
    else:
        try:
            register = json.loads(args.register.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"slice_cross_repo_for_component: {exc}", file=sys.stderr)
            return 2
    sliced = slice_for_component(
        register,
        component_name=args.component_name,
        component_description=args.component_description,
        interfaces=args.interface,
        trust_boundaries=args.trust_boundary,
        explicit_names=args.explicit_name,
    )
    rendered = json.dumps(sliced, indent=2)
    if args.output == "-":
        print(rendered)
    else:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
