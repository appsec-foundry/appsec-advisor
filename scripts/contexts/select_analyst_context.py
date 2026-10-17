#!/usr/bin/env python3
"""contexts/select_analyst_context.py — deterministic surrounding code for a change review.

Before the first model call the controller admits a bounded set of files the
change most likely depends on, so the model does not have to guess which file
to request:

* files a changed file imports through a relative path (JavaScript,
  TypeScript, Python), in the order the changed files appear;
* files the threat model cites as evidence for findings on the components the
  change touches.

Candidates come only from the frozen view; the caller admits them through the
snapshot, which applies its exclusion, redaction, and job limits. Package
imports, aliases, and dynamic paths are not resolved, so a dependency reached
only that way stays for the model's evidence requests. Nothing here reads
outside the view or runs repository code.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import posixpath
import re
from pathlib import Path, PurePosixPath

JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_JS_SPECIFIER = re.compile(
    r"""(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|^\s*import\s*)['"](\.{1,2}/[^'"\n]+)['"]""", re.M
)
_PY_FROM = re.compile(r"^\s*from\s+(\.+)([A-Za-z_][\w.]*)?\s+import\s+([^\n#]+)", re.M)
IMPORT_REASON = "imported by changed file {path}"
EVIDENCE_REASON = "threat model evidence for {threat} on a touched component"


def _inside(path: str) -> str | None:
    """Normalized repository-relative path, or None when it escapes the root."""
    norm = posixpath.normpath(path)
    return None if norm.startswith("../") or norm in ("..", ".") or norm.startswith("/") else norm


def relative_imports(path: str, text: str, available: set[str]) -> list[str]:
    """Files of ``available`` that ``path`` imports through a relative specifier."""
    base = PurePosixPath(path).parent
    suffix = PurePosixPath(path).suffix
    candidates: list[list[str]] = []
    if suffix in JS_SUFFIXES or suffix in (".vue", ".svelte"):
        for spec in _JS_SPECIFIER.findall(text):
            target = _inside(str(base / spec))
            if target is None:
                continue
            candidates.append(
                [target, *(target + ext for ext in JS_SUFFIXES), *(f"{target}/index{ext}" for ext in JS_SUFFIXES)]
            )
    elif suffix == ".py":
        for dots, module, names in _PY_FROM.findall(text):
            package = base
            for _ in range(len(dots) - 1):
                package = package.parent
            if module:
                target = _inside(str(package.joinpath(*module.split("."))))
                if target is not None:
                    candidates.append([f"{target}.py", f"{target}/__init__.py"])
            else:
                for name in re.split(r"[\s,()]+", names):
                    target = _inside(str(package / name)) if name.isidentifier() else None
                    if target is not None:
                        candidates.append([f"{target}.py", f"{target}/__init__.py"])
    found = []
    for options in candidates:
        hit = next((option for option in options if option in available and option != path), None)
        if hit and hit not in found:
            found.append(hit)
    return found


def select(snapshot: dict, available: set[str], source_dir: Path, threat_model: dict | None, limit: int) -> list[dict]:
    """Ordered ``{path, reason}`` candidates, at most ``limit``, none already admitted on the proposed side."""
    admitted = {e["path"] for e in snapshot["admitted"] if e["side"] == "proposed"}
    chosen: list[dict] = []

    def add(path: str, reason: str) -> None:
        if (
            len(chosen) < limit
            and path in available
            and path not in admitted
            and all(c["path"] != path for c in chosen)
        ):
            chosen.append({"path": path, "reason": reason[:160]})

    for entry in snapshot["admitted"]:
        if entry["side"] != "proposed" or entry["change"] == "context":
            continue
        try:
            text = (source_dir / "proposed" / entry["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for target in relative_imports(entry["path"], text, available):
            add(target, IMPORT_REASON.format(path=entry["path"]))
    focus = set((threat_model or {}).get("focus_components") or [])
    for threat in (threat_model or {}).get("threats") or []:
        if str(threat.get("component")) in focus:
            for path in threat.get("files") or []:
                target = _inside(str(path))
                if target is not None:
                    add(target, EVIDENCE_REASON.format(threat=threat.get("id")))
    return chosen
