"""Regression tests for scripts/emit_clean_finding_titles.py (2026-06-12).

Finding titles must read `<weakness class> — <file:line>` — not the verbose,
code-laden, parameter-suffixed form Stage-1 authors.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "scripts" / "emit_clean_finding_titles.py"


def _load():
    spec = importlib.util.spec_from_file_location("emit_clean_finding_titles", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["emit_clean_finding_titles"] = mod
    spec.loader.exec_module(mod)
    return mod


ecf = _load()


def _t(title, file="routes/x.ts", line=10, **extra):
    t = {"id": "T-001", "title": title, "evidence": {"file": file, "line": line}}
    t.update(extra)
    return t


def test_strips_via_mechanism_and_param():
    t = _t("Server-Side Template Injection via eval (routes/userProfile.ts:62)",
           file="routes/userProfile.ts", line=62)
    assert ecf.build_clean_title(t["title"], t) == "Server-Side Template Injection — routes/userProfile.ts:62"


def test_strips_embedded_file_and_bypass_phrasing():
    t = _t("Stored XSS via DomSanitizer.trust HTML bypass in last-login-ip.component.html:10",
           file="frontend/src/app/last-login-ip/last-login-ip.component.html", line=10)
    assert ecf.build_clean_title(t["title"], t) == "Stored XSS — last-login-ip.component.html:10"


def test_does_not_mistake_code_identifier_for_file():
    """`yaml.load` / `vm.runInContext` must NOT be parsed as a file token."""
    assert "yaml.load" not in ecf.clean_weakness("YAML Bomb via yaml.load routes/fileUpload.ts:117")
    # weakness keeps the real words, drops only the file
    assert ecf.clean_weakness("ZIP Slip Path Traversal routes/fileUpload.ts:45") == "ZIP Slip Path Traversal"


def test_acronym_casing_fix():
    t = _t("Vm sandbox escape via notevil routes/b2bOrder.ts:23", file="routes/b2bOrder.ts", line=23)
    assert ecf.build_clean_title(t["title"], t) == "VM sandbox escape — routes/b2bOrder.ts:23"


def test_evidence_file_wins_over_truncated_title():
    t = _t("SSRF via Unvalidated URL in Profile Image Upload routes/profileImageUrlUpload.t…",
           file="routes/profileImageUrlUpload.ts", line=24)
    assert ecf.build_clean_title(t["title"], t) == "SSRF — routes/profileImageUrlUpload.ts:24"


def test_deep_path_basenamed():
    t = _t("Stored XSS", file="frontend/src/app/x/y/z/comp.component.html", line=5)
    assert ecf.build_clean_title("Stored XSS", t) == "Stored XSS — comp.component.html:5"


def test_idempotent():
    d = {"threats": [_t("SQL Injection (routes/login.ts:34)", file="routes/login.ts", line=34)]}
    assert ecf.apply(d) == 1
    first = d["threats"][0]["title"]
    assert ecf.apply(d) == 0
    assert d["threats"][0]["title"] == first == "SQL Injection — routes/login.ts:34"
    assert d["threats"][0]["_title_source"] == "SQL Injection (routes/login.ts:34)"
