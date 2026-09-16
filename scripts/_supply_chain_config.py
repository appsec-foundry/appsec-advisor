"""Passive parsing of automation configuration, with no imports or execution."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from _path_guard import is_safe_to_read
from _source_lex import without_comments

RENOVATE_PATHS = (
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.json5",
    ".github/renovate.json",
    ".github/renovate.json5",
)


def renovate_configs(root: Path) -> list[tuple[str, dict]]:
    """Read local JSON/JSONC and ordinary JSON5 config objects; reject invalid shapes."""
    configs = []
    for rel in RENOVATE_PATHS:
        path = root / rel
        if not is_safe_to_read(path, root):
            continue
        try:
            text = without_comments(path.read_text(encoding="utf-8"))
            try:
                value = json.loads(text)
            except ValueError:
                text = re.sub(r"([{,]\s*)([A-Za-z_$][\w$]*)(\s*:)", r'\1"\2"\3', text)
                value = yaml.safe_load(text)
            if isinstance(value, dict):
                configs.append((rel, value))
        except (OSError, ValueError, yaml.YAMLError):
            continue
    return configs


def ci_steps(text: str) -> list[tuple[str, bool]]:
    """Executable CI values with inherited advisory policy; prose fallback only for non-mappings."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        doc = None
    if not isinstance(doc, (dict, list)):
        return [
            (line, False) for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("#", "//"))
        ]
    # Recon snippets use repeated top-level run keys, unlike workflow objects.
    if isinstance(doc, dict) and set(doc) <= {"run", "CI runs"}:
        return [
            (line.split(":", 1)[1].strip(), False)
            for line in text.splitlines()
            if line.startswith(("run:", "CI runs:"))
        ]
    steps: list[tuple[str, bool]] = []

    def walk(node, advisory=False):
        if isinstance(node, list):
            for child in node:
                walk(child, advisory)
        elif isinstance(node, dict):
            if node.get("if") is False:
                return
            advisory = advisory or node.get("continue-on-error") is True or node.get("allow_failure") is True
            for key, value in node.items():
                if key in {"run", "script", "before_script", "after_script", "uses"}:
                    commands = value if isinstance(value, list) else [value]
                    for command in commands:
                        if isinstance(command, str):
                            steps.extend(
                                (line, advisory)
                                for line in command.splitlines()
                                if line.strip() and not line.lstrip().startswith("#")
                            )
                elif key not in {"name", "if", "with", "env", "variables"}:
                    walk(value, advisory)

    walk(doc)
    return steps
