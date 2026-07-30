#!/usr/bin/env python3
"""Compare a Copilot-produced .components.json against the Claude oracle.

Usage:  compare.py <produced.json> <oracle.json>

Reports the numbers the capacity spike records: component count, id overlap,
tier agreement on the ids both sides found, and how much of the oracle's path
coverage the produced inventory reproduces. Exit code is always 0 — this
measures, it does not gate. The gate is validate_fragment.py.
"""

import json
import sys
from pathlib import Path


def load(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("components") or []


def norm_paths(comp: dict) -> set[str]:
    return {p.rstrip("/*").rstrip("/") for p in comp.get("paths") or []}


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    produced_path, oracle_path = Path(sys.argv[1]), Path(sys.argv[2])
    if not produced_path.is_file():
        print(f"MISSING  {produced_path} was not produced")
        return 0

    produced, oracle = load(produced_path), load(oracle_path)
    p_ids = {c.get("id") for c in produced}
    o_ids = {c.get("id") for c in oracle}

    print(f"count      produced={len(produced)}  oracle={len(oracle)}")
    print(f"ids        produced={sorted(p_ids)}")
    print(f"           oracle  ={sorted(o_ids)}")
    print(f"           exact overlap={sorted(p_ids & o_ids)}")

    p_by_id = {c.get("id"): c for c in produced}
    shared = sorted(p_ids & o_ids)
    if shared:
        agree = sum(
            1
            for c in oracle
            if c.get("id") in p_by_id and p_by_id[c["id"]].get("tier") == c.get("tier")
        )
        print(f"tier       agreement on shared ids: {agree}/{len(shared)}")
    else:
        print("tier       no shared ids — compare by hand")

    # Path coverage: how much of each oracle component's path set appears
    # anywhere in the produced inventory. Slug names differ between runs, so
    # this is the id-independent signal.
    all_produced = set().union(*(norm_paths(c) for c in produced)) if produced else set()
    for c in oracle:
        want = norm_paths(c)
        hit = {p for p in want if p in all_produced}
        print(f"paths      {c.get('id'):<18} {len(hit)}/{len(want)}  missing={sorted(want - hit)}")

    print(f"zones      off-vocabulary values: {sorted(_bad_zones(produced))}")
    return 0


_ZONES = {
    "internet", "dmz", "client-device", "mobile-device", "internal-network",
    "peer-service", "prod-env", "prod-write-db", "ci-cd-runtime",
    "ci-cd-secrets", "build-pipeline", "deployment-pipeline",
}


def _bad_zones(components: list[dict]) -> set[str]:
    seen: set[str] = set()
    for c in components:
        seen |= {z for z in (c.get("deployment_zones") or []) if z not in _ZONES}
    return seen


if __name__ == "__main__":
    raise SystemExit(main())
