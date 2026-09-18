#!/usr/bin/env python3
"""Finalize the component registry before trust-boundary assessment.

This command is the stage handoff between architecture discovery and every
consumer that uses component IDs. It validates and reconciles the inventory,
writes it atomically, and emits a deterministic fingerprint receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import jsonschema
from _atomic_io import atomic_write_json
from build_stride_dispatch_manifest import reconcile_inventory
from validate_fragment import fragment_invariant_errors, repository_path_errors

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
COMPONENT_SCHEMA = PLUGIN_ROOT / "schemas" / "fragments" / "components.schema.json"
RECEIPT_SCHEMA = PLUGIN_ROOT / "schemas" / "component-inventory-finalization.schema.json"
FINGERPRINT_FIELDS = (
    "id",
    "name",
    "paths",
    "tier",
    "deployment_zones",
    "handles_sensitive_data",
    "sensitive_data",
)
# Code categories that do not say which language implements a component.
NON_IMPLEMENTATION_LANGUAGES = frozenset(
    {"C/C++ header", "C++ header", "CSS", "CSS (Less)", "CSS (Sass)", "Gradle", "HTML", "Jupyter", "Protobuf", "SQL"}
)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read valid JSON from {path}: {exc}") from exc


def _validate(document: Any, schema_path: Path) -> None:
    schema = _load_json(schema_path)
    jsonschema.Draft202012Validator(schema).validate(document)


def component_inventory_fingerprint(components: list[dict[str, Any]]) -> str:
    """Fingerprint only fields that can change boundary endpoint semantics."""
    cards = [
        {key: row.get(key) for key in FINGERPRINT_FIELDS if key != "sensitive_data" or key in row} for row in components
    ]
    payload = json.dumps(cards, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _own_files(repo_root: Path) -> list[tuple[str, int]]:
    """Repository files with sizes, without `.git`, dependency or build directories, never following links."""
    from repo_profile import VENDOR_DIRS

    files = []
    for directory, subdirs, names in os.walk(repo_root):
        subdirs[:] = sorted(d for d in subdirs if d != ".git" and d not in VENDOR_DIRS)
        base = Path(directory)
        for name in names:
            path = base / name
            try:
                if not path.is_symlink() and path.is_file():
                    files.append((path.relative_to(repo_root).as_posix(), path.stat().st_size))
            except OSError:
                continue
    return sorted(files)


# A tool list handed to a model call: a `tools` / `tool_choice` argument inside
# the call's parentheses, or a bind of tools to a chat model. Empty or null
# values enable no tool.
_TOOL_ARGUMENT_RE = re.compile(
    r"(?<![\w.$])(?:tools|tool_choice)\s*[:=](?!=)(?!\s*(?:\[\s*\]|\{\s*\}|None\b|null\b|undefined\b|false\b|False\b))"
)
_TOOL_BIND_RE = re.compile(r"\.bind_?tools\s*\(", re.IGNORECASE)
_TOOL_CALL_WINDOW = 30
_MAX_CAPABILITY_FILE_BYTES = 1_500_000
_MAX_CAPABILITY_EVIDENCE = 4


def _code_line(line: str) -> str:
    return "" if line.strip().startswith(("//", "#", "*", "/*")) else line


def tool_enabled_call_lines(lines: list[str]) -> list[int]:
    """1-based lines where a model call in this file receives tools.

    A `tools` argument counts only while the nearest preceding model call
    (within 30 lines) is still open; a key of an unrelated object or a later
    statement does not. Comment lines prove nothing.
    """
    from source_auth_scanner import _GENERIC_LLM_CALL_RE, _STRONG_LLM_CALL_RE

    code = [_code_line(line) for line in lines]
    found = []
    for idx, line in enumerate(code):
        if _TOOL_BIND_RE.search(line):
            found.append(idx + 1)
            continue
        argument = _TOOL_ARGUMENT_RE.search(line)
        if not argument:
            continue
        for start in range(idx, max(-1, idx - _TOOL_CALL_WINDOW), -1):
            call = _STRONG_LLM_CALL_RE.search(code[start]) or _GENERIC_LLM_CALL_RE.search(code[start])
            if not call or (start == idx and call.end() > argument.start()):
                continue
            if start == idx:
                opened = line[call.end() - 1 : argument.start()]
            else:
                opened = "\n".join([code[start][call.end() - 1 :], *code[start + 1 : idx], line[: argument.start()]])
            if opened.count("(") > opened.count(")"):
                found.append(idx + 1)
            break
    return found


def _repository_lines(repo_root: Path, relative: str) -> list[str]:
    try:
        path = (repo_root / relative).resolve()
        if not path.is_relative_to(repo_root) or not path.is_file() or path.stat().st_size > _MAX_CAPABILITY_FILE_BYTES:
            return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return []


def refine_model_capabilities(components: list[dict[str, Any]], repo_root: Path) -> None:
    """Replace `llm-calls` with `llm-tools` where the evidenced file hands tools to a model call.

    The producer names the model call; whether that call receives executable
    tools is read deterministically from the files its `llm-calls` evidence
    names, so the more specific value does not depend on the producer noticing
    it. The item count stays unchanged.
    """
    for component in components:
        items = component.get("capabilities")
        if not isinstance(items, list) or any(
            isinstance(item, dict) and item.get("capability") == "llm-tools" for item in items
        ):
            continue
        calls = [
            index
            for index, item in enumerate(items)
            if isinstance(item, dict) and item.get("capability") == "llm-calls"
        ]
        files = sorted(
            {
                row["file"]
                for index in calls
                for row in items[index].get("evidence") or []
                if isinstance(row, dict) and isinstance(row.get("file"), str)
            }
        )
        evidence = [
            {"file": relative, "line": line}
            for relative in files
            for line in tool_enabled_call_lines(_repository_lines(repo_root, relative))
        ]
        if calls and evidence:
            items[calls[0]] = {"capability": "llm-tools", "evidence": evidence[:_MAX_CAPABILITY_EVIDENCE]}


def annotate_languages(components: list[dict[str, Any]], repo_root: Path) -> None:
    """Set each non-data component's `language` to the implementation language holding most of its bytes.

    The value comes only from file extensions under the component's own paths;
    a producer-authored value never survives. Stores name their engine in
    `framework` instead.
    """
    from reclassify_components import _glob_to_regex
    from repo_profile import classify

    files = _own_files(repo_root)
    for component in components:
        component.pop("language", None)
        paths = [p for p in component.get("paths") or [] if isinstance(p, str)]
        if component.get("tier") == "data" or not paths:
            continue
        patterns = [_glob_to_regex(p) for p in paths]
        directories = tuple(p.rstrip("/") + "/" for p in paths if "*" not in p and "?" not in p)
        totals: dict[str, int] = {}
        for path, size in files:
            if not (path.startswith(directories) or any(rx.match(path) for rx in patterns)):
                continue
            language, category = classify(path)
            if category == "code" and language not in NON_IMPLEMENTATION_LANGUAGES:
                language = language.split(" (")[0]
                totals[language] = totals.get(language, 0) + size
        if totals:
            component["language"] = min(totals, key=lambda name: (-totals[name], name))


def finalize(repo_root: Path, output_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    component_path = output_dir / ".components.json"
    document = _load_json(component_path)
    _validate(document, COMPONENT_SCHEMA)
    original = document["components"]
    original_ids = [row.get("id") for row in original if isinstance(row, dict)]
    finalized, injected = reconcile_inventory(original, repo_root)
    annotate_languages(finalized, repo_root)
    refine_model_capabilities(finalized, repo_root)
    payload = dict(document)
    payload["components"] = finalized
    _validate(payload, COMPONENT_SCHEMA)
    path_errors = repository_path_errors("components", payload, repo_root) + fragment_invariant_errors(
        "components", payload
    )
    if path_errors:
        raise ValueError("reconciled component path validation failed: " + "; ".join(path_errors))

    collapsed = max(0, len(original_ids) + len(injected) - len(finalized))
    receipt = {
        "schema_version": 1,
        "component_inventory_fingerprint": component_inventory_fingerprint(finalized),
        "component_ids": [row["id"] for row in finalized],
        "injected_component_ids": [row["id"] for row in injected],
        "collapsed_duplicate_count": collapsed,
    }
    _validate(receipt, RECEIPT_SCHEMA)
    atomic_write_json(component_path, payload, sort_keys=False)
    atomic_write_json(output_dir / ".component-inventory-finalization.json", receipt, sort_keys=False)
    return payload, receipt


def validate_receipt(output_dir: Path, repo_root: Path | None = None) -> dict[str, Any]:
    """Validate the receipt and ensure it still describes `.components.json`."""
    output_dir = output_dir.resolve()
    components = _load_json(output_dir / ".components.json")
    receipt = _load_json(output_dir / ".component-inventory-finalization.json")
    _validate(components, COMPONENT_SCHEMA)
    _validate(receipt, RECEIPT_SCHEMA)
    if repo_root is not None:
        path_errors = repository_path_errors("components", components, repo_root.resolve())
        if path_errors:
            raise ValueError("component repository path validation failed: " + "; ".join(path_errors))
    actual_ids = [row["id"] for row in components["components"]]
    actual_fp = component_inventory_fingerprint(components["components"])
    if receipt["component_ids"] != actual_ids:
        raise ValueError("component ID set/order changed after inventory finalization")
    if not set(receipt["injected_component_ids"]) <= set(actual_ids):
        raise ValueError("finalization receipt names an injected component that is not present")
    if receipt["component_inventory_fingerprint"] != actual_fp:
        raise ValueError("component inventory fingerprint changed after finalization")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.validate_only:
            receipt = validate_receipt(args.output_dir, args.repo_root)
        else:
            _payload, receipt = finalize(args.repo_root, args.output_dir)
    except (ValueError, jsonschema.ValidationError) as exc:
        print(f"COMPONENT_FINALIZATION_FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        "COMPONENT_FINALIZATION_OK: "
        f"{len(receipt['component_ids'])} components "
        f"({len(receipt['injected_component_ids'])} injected, "
        f"{receipt['collapsed_duplicate_count']} duplicates collapsed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
