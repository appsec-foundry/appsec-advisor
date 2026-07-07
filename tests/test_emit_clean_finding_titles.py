"""Regression tests for scripts/emit_clean_finding_titles.py (2026-06-12).

Finding titles must read `<weakness class> — <file:line>` — not the verbose,
code-laden, parameter-suffixed form Stage-1 authors.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

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


def _write_yaml(output_dir: Path, data: dict) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _read_yaml(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


def test_strips_via_mechanism_and_param():
    t = _t("Server-Side Template Injection via eval (routes/userProfile.ts:62)", file="routes/userProfile.ts", line=62)
    assert ecf.build_clean_title(t["title"], t) == "Server-Side Template Injection — routes/userProfile.ts:62"


def test_strips_embedded_file_and_bypass_phrasing():
    t = _t(
        "Stored XSS via DomSanitizer.trust HTML bypass in last-login-ip.component.html:10",
        file="frontend/src/app/last-login-ip/last-login-ip.component.html",
        line=10,
    )
    assert ecf.build_clean_title(t["title"], t) == "Stored XSS — last-login-ip.component.html:10"


def test_does_not_mistake_code_identifier_for_file():
    """`yaml.load` / `vm.runInContext` must NOT be parsed as a file token."""
    assert "yaml.load" not in ecf.clean_weakness("YAML Bomb via yaml.load routes/fileUpload.ts:117")
    # weakness keeps the real words, drops only the file
    assert ecf.clean_weakness("ZIP Slip Path Traversal routes/fileUpload.ts:45") == "ZIP Slip Path Traversal"


def test_strips_quoted_value_and_on_line_artefact():
    # "Hardcoded JWT HMAC key 'pass**** (8 chars)' on:6 — file:6" — the single-quoted
    # value and the on:<line> artefact must be stripped; weakness class is clean.
    t = _t(
        "Hardcoded JWT HMAC key 'pass**** (8 chars)' on:6 — SymmetricAlgoKeys.json:6",
        file="SymmetricAlgoKeys.json",
        line=6,
    )
    result = ecf.build_clean_title(t["title"], t)
    assert result == "Hardcoded JWT HMAC key — SymmetricAlgoKeys.json:6"  # lowercase 'key' preserved from source
    assert "pass" not in result
    # "on:6" as a standalone artefact is gone; it still appears as part of ".json:6" which is correct
    assert result.startswith("Hardcoded JWT HMAC key")


def test_acronym_casing_fix():
    t = _t("Vm sandbox escape via notevil routes/b2bOrder.ts:23", file="routes/b2bOrder.ts", line=23)
    assert ecf.build_clean_title(t["title"], t) == "VM sandbox escape — routes/b2bOrder.ts:23"


def test_evidence_file_wins_over_truncated_title():
    t = _t(
        "SSRF via Unvalidated URL in Profile Image Upload routes/profileImageUrlUpload.t…",
        file="routes/profileImageUrlUpload.ts",
        line=24,
    )
    assert ecf.build_clean_title(t["title"], t) == "SSRF — routes/profileImageUrlUpload.ts:24"


def test_deep_path_basenamed():
    t = _t("Stored XSS", file="frontend/src/app/x/y/z/comp.component.html", line=5)
    assert ecf.build_clean_title("Stored XSS", t) == "Stored XSS — comp.component.html:5"


def test_fallback_uses_embedded_file_when_evidence_has_no_file():
    t = _t("open redirect in routes/redirect.ts:12", file="", line=12)
    assert ecf.build_clean_title(t["title"], t) == "Open redirect — routes/redirect.ts:12"


def test_source_auth_class_qualifier_name_keeps_class_only():
    # Source-auth scanner check names arrive as "Class — qualifier clause" with
    # their own em-dash; the title must carry only the weakness class.
    t = _t(
        "Broken authorization — attacker-controlled owner ID in resource query — routes/address.ts:11",
        file="routes/address.ts",
        line=11,
    )
    assert ecf.build_clean_title(t["title"], t) == "Broken authorization — routes/address.ts:11"


def test_over_length_title_capped_to_schema_limit():
    # Regression (2026-06): verbose source-auth / config titles shipped >80
    # chars and failed validate_intermediate. The emitter must enforce the cap.
    raw = (
        "Broken authorization attacker controlled owner identifier in resource "
        "query without ownership enforcement filter"
    )
    t = _t(raw, file="routes/payment.ts", line=70)
    out = ecf.build_clean_title(t["title"], t)
    assert len(out) <= 80
    assert out.endswith("— routes/payment.ts:70")
    # word-boundary truncation: no dangling separator / ellipsis
    assert not out.split(" — ")[0].endswith(("-", "—", ":", ","))


def test_missing_or_malformed_evidence_falls_back_to_weakness_only():
    assert ecf.build_clean_title("", {"evidence": "not-a-list"}) == ""
    assert ecf.build_clean_title("open redirect", {"evidence": [{"line": 12}]}) == "Open redirect"


def test_apply_skips_non_dict_and_empty_title_entries():
    d = {"threats": ["not-a-threat", {"id": "T-001", "title": ""}, {"id": "T-002", "title": "Already clean"}]}
    assert ecf.apply(d) == 0
    assert d["threats"][2]["_title_source"] == "Already clean"


def test_idempotent():
    d = {"threats": [_t("SQL Injection (routes/login.ts:34)", file="routes/login.ts", line=34)]}
    assert ecf.apply(d) == 1
    first = d["threats"][0]["title"]
    assert ecf.apply(d) == 0
    assert d["threats"][0]["title"] == first == "SQL Injection — routes/login.ts:34"
    assert d["threats"][0]["_title_source"] == "SQL Injection (routes/login.ts:34)"


def test_main_writes_cleaned_yaml(tmp_path, capsys):
    _write_yaml(
        tmp_path,
        {
            "threats": [
                _t("SQL Injection via string concatenation (routes/login.ts:34)", file="routes/login.ts", line=34)
            ]
        },
    )

    assert ecf.main([str(tmp_path)]) == 0

    data = _read_yaml(tmp_path)
    assert data["threats"][0]["title"] == "SQL Injection — routes/login.ts:34"
    assert "cleaned 1 finding title" in capsys.readouterr().out


def test_main_report_only_prints_preview_without_writing(tmp_path, capsys):
    _write_yaml(
        tmp_path,
        {
            "threats": [
                _t("SQL Injection via string concatenation (routes/login.ts:34)", file="routes/login.ts", line=34),
                "not-a-threat",
            ]
        },
    )

    assert ecf.main([str(tmp_path), "--report-only"]) == 0

    out = capsys.readouterr().out
    assert "T-001:" in out
    assert "'SQL Injection — routes/login.ts:34'" in out
    assert _read_yaml(tmp_path)["threats"][0]["title"] == "SQL Injection via string concatenation (routes/login.ts:34)"


def test_main_best_effort_noops_for_missing_and_unreadable_yaml(tmp_path, capsys):
    assert ecf.main([str(tmp_path)]) == 0
    assert "no threat-model.yaml" in capsys.readouterr().err

    (tmp_path / "threat-model.yaml").write_text("threats: [\n", encoding="utf-8")
    assert ecf.main([str(tmp_path)]) == 0
    assert "unreadable yaml" in capsys.readouterr().err
