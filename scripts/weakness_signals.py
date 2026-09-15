"""Validated, source-backed observations for the weakness reconciler.

Finding classification owns the security claim. This producer additionally
checks the cited implementation mechanism, limits its scope, and preserves the
finding identity so later refutation removes its backing too. It does not scan
for new vulnerabilities or infer application-wide control absence.
"""

from __future__ import annotations

import functools
import json
import re
from pathlib import Path

from _path_guard import is_safe_to_read
from jsonschema import Draft202012Validator
from source_auth_scanner import _JS_LEXEME, _without_js_comments
from weakness_classifier import classify_cwe, load_weakness_classes

_SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"
_NONPRODUCTION = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "out",
    "coverage",
    ".next",
    ".nuxt",
    "__pycache__",
    ".venv",
    "venv",
    "test",
    "tests",
    "__tests__",
    "fixtures",
    "examples",
    "testdata",
}
MAX_SOURCE_BYTES = 2_000_000


def production_path(path: Path) -> bool:
    """Exclude generated, dependency, and test code using relative paths."""
    return not (
        any(part.lower() in _NONPRODUCTION for part in path.parts)
        or re.search(r"(?:^test_|[._-](?:test|spec)\.)", path.name, re.I)
        or path.name.endswith(("Test.java", "Tests.java", "_test.go", ".min.js"))
    )


@functools.lru_cache(maxsize=2)
def _validator(name: str) -> Draft202012Validator:
    if name not in {"weakness-signals", "impl-strategy"}:
        raise ValueError("Unknown weakness artifact contract")
    schema = json.loads((_SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def validate_document(document: dict, name: str = "weakness-signals") -> None:
    """Fail closed on malformed artifacts at both producer and consumer."""
    errors = sorted(_validator(name).iter_errors(document), key=lambda e: str(e.path))
    if errors:
        raise ValueError(f"{name}: {errors[0].message}")
    classes = {c["id"] for c in load_weakness_classes()["clusters"]}
    values = (
        document.get("strategies", {})
        if name == "impl-strategy"
        else (s.get("weakness_class") for s in document["design_signals"])
    )
    if any(value not in classes for value in values):
        raise ValueError(f"{name}: unknown weakness class")


def _source_window(repo_root: Path, evidence: dict) -> str:
    file, line = evidence.get("file"), evidence.get("line")
    if not isinstance(file, str) or not file or type(line) is not int or line < 1:
        return ""
    relative = Path(file)
    if relative.is_absolute() or ".." in relative.parts or not production_path(relative):
        return ""
    path = repo_root / relative
    if not is_safe_to_read(path, repo_root):
        return ""
    try:
        if not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            return ""
        source = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}:
            source = _without_js_comments(source)
        lines = source.splitlines()
    except OSError:
        return ""
    if line > len(lines):
        return ""
    # Preserve the cited site. Adjacent context establishes what an API consumes;
    # a matching API elsewhere in the file cannot validate an unrelated locator.
    if lines[line - 1].lstrip().startswith(("//", "#", "/*", "*")):
        return ""
    return "\n".join(lines[line - 1 : line + 5])


def finding_signals(threats: list[dict], repo_root: Path) -> list[dict]:
    """Derive narrow implementation observations from admitted finding evidence.

    Catalog selectors require a specific CWE plus an observed API at the cited
    site. Refuted/ambiguous evidence, non-code sources, unsafe paths, and safe
    expressions never establish a mechanism. Exploitability remains the
    finding's existing evidence tier; no CVSS or severity is invented here.
    """
    guidance = load_weakness_classes().get("mechanism_guidance") or {}
    signals = []
    for threat in threats:
        if threat.get("source") not in {"stride", "source-scan", "config-scan", "config-scan-finding"}:
            continue
        if threat.get("evidence_check") not in {"verified", "verified-prior"}:
            continue
        tid = threat.get("t_id") or threat.get("id")
        if not isinstance(tid, str) or not re.fullmatch(r"T-\d{3,}", tid):
            continue
        cwe = str(threat.get("cwe") or "").strip().upper()
        evidence = threat.get("evidence") or []
        if isinstance(evidence, dict):
            evidence = [evidence]
        for mechanism, entry in guidance.items():
            selector = entry.get("finding_signal")
            if not selector or cwe not in entry.get("cwes", []):
                continue
            backing = []
            for site in evidence:
                if not isinstance(site, dict):
                    continue
                text = _source_window(repo_root, site)
                first_line_end = len(text.split("\n", 1)[0])
                literals = [(m.start(), m.end()) for m in _JS_LEXEME.finditer(text)]
                if not text or not any(
                    match.start() < first_line_end and not any(start <= match.start() < end for start, end in literals)
                    for pattern in selector["any_pattern"]
                    for match in re.finditer(pattern, text)
                ):
                    continue
                if any(re.search(pattern, text) for pattern in selector.get("counter_patterns", [])):
                    continue
                backing.append({"file": site["file"], "line": site["line"], "id": tid})
            if not backing:
                continue
            component = threat.get("component_id") or threat.get("component")
            signals.append(
                {
                    "rule_id": "FINDING-MECHANISM",
                    "mechanism_id": mechanism,
                    "weakness_class": classify_cwe(cwe, warn=False),
                    "cwe": cwe,
                    "title": entry["weakness_name"],
                    "statement": entry["description"],
                    "practice_evidence": backing,
                    "instance_ids": [tid],
                    "affected_components": [component] if component else [],
                    "severity": threat.get("risk") or "Medium",
                }
            )
    validate_document({"version": 1, "design_signals": signals})
    return signals
