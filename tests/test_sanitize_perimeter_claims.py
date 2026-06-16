from __future__ import annotations

from pathlib import Path

import sanitize_perimeter_claims as sanitizer


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _load_yaml(path: Path) -> dict:
    return sanitizer.yaml.safe_load(path.read_text(encoding="utf-8"))


def test_sanitize_string_removes_speculative_clauses_and_normalizes_separators() -> None:
    cleaned, removed = sanitizer._sanitize_string(
        "No WAF, TLS is terminated by nginx; no IDS, signed JWT verification is configured"
    )

    assert cleaned == (
        "TLS is terminated by nginx, signed JWT verification is configured; "
        "deployment-time perimeter controls out of scope for source-tree review"
    )
    assert removed == ["WAF", "IDS/IPS"]
    assert not cleaned.startswith(",")
    assert sanitizer._sanitize_string("") == ("", [])


def test_sanitize_string_replaces_whole_field_with_neutral_marker() -> None:
    cleaned, removed = sanitizer._sanitize_string("No web application firewall")

    assert cleaned == "deployment-time perimeter controls out of scope for source-tree review"
    assert removed == ["WAF"]


def test_sanitize_string_preserves_positive_and_existing_neutral_text() -> None:
    positive = "Terraform configures AWS WAF rules and API Gateway authorizers."
    existing = "TLS is enforced; no firewall; deployment-time perimeter controls out of scope for source-tree review"

    assert sanitizer._sanitize_string(positive) == (positive, [])

    cleaned, removed = sanitizer._sanitize_string(existing)

    assert cleaned == "TLS is enforced; deployment-time perimeter controls out of scope for source-tree review"
    assert removed == ["network firewall"]
    assert cleaned.count("deployment-time perimeter controls out of scope") == 1


def test_sanitize_yaml_targets_only_configured_fields_and_reports_changes() -> None:
    data = {
        "trust_boundaries": [
            {
                "id": "TB-1",
                "enforcement": "JWT verification, no WAF",
                "description": "No API gateway; direct Express route exposure",
                "unrelated": "no firewall",
            },
            "ignored",
        ],
        "security_controls": [
            {
                "name": "Transport Security",
                "notes": "TLS configured; no DDoS protection",
                "implementation": "Nginx reverse proxy is configured",
                "effectiveness_rationale": "No SIEM",
            },
            {
                "id": "SC-2",
                "notes": 42,
                "implementation": "Positive WAF reference in terraform",
            },
        ],
        "threats": [{"scenario": "no WAF remains outside target collections"}],
    }

    sanitized, changes = sanitizer.sanitize_yaml(data)

    assert sanitized["trust_boundaries"][0]["enforcement"] == (
        "JWT verification; deployment-time perimeter controls out of scope for source-tree review"
    )
    assert sanitized["trust_boundaries"][0]["description"] == (
        "direct Express route exposure; deployment-time perimeter controls out of scope for source-tree review"
    )
    assert sanitized["trust_boundaries"][0]["unrelated"] == "no firewall"
    assert sanitized["security_controls"][0]["notes"] == (
        "TLS configured; deployment-time perimeter controls out of scope for source-tree review"
    )
    assert sanitized["security_controls"][0]["implementation"] == "Nginx reverse proxy is configured"
    assert sanitized["security_controls"][0]["effectiveness_rationale"] == (
        "deployment-time perimeter controls out of scope for source-tree review"
    )
    assert sanitized["threats"][0]["scenario"] == "no WAF remains outside target collections"
    assert [(c["collection"], c["id"], c["field"]) for c in changes] == [
        ("trust_boundaries", "TB-1", "enforcement"),
        ("trust_boundaries", "TB-1", "description"),
        ("security_controls", "Transport Security", "notes"),
        ("security_controls", "Transport Security", "effectiveness_rationale"),
    ]
    assert changes[0]["removed_tokens"] == ["WAF"]
    assert changes[-1]["before"] == "No SIEM"


def test_sanitize_yaml_ignores_non_list_collections_and_is_idempotent() -> None:
    data = {
        "trust_boundaries": {"enforcement": "No WAF"},
        "security_controls": [
            {
                "id": "SC-1",
                "notes": "TLS configured; no WAF",
            }
        ],
    }

    once, first_changes = sanitizer.sanitize_yaml(data)
    twice, second_changes = sanitizer.sanitize_yaml(once)

    assert len(first_changes) == 1
    assert second_changes == []
    assert twice["security_controls"][0]["notes"].count("deployment-time perimeter controls out of scope") == 1


def test_main_reports_argument_and_input_errors(tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()

    assert sanitizer.main([]) == 2
    assert "Usage:" in capsys.readouterr().err

    assert sanitizer.main([str(out)]) == 1
    assert "no yaml" in capsys.readouterr().err

    _write(out / "threat-model.yaml", ":\n")
    assert sanitizer.main([str(out)]) == 1
    assert "could not parse" in capsys.readouterr().err

    _write(out / "threat-model.yaml", "- not a mapping\n")
    assert sanitizer.main([str(out)]) == 1
    assert "did not parse to a mapping" in capsys.readouterr().err


def test_main_no_changes_leaves_yaml_unchanged(tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    yaml_path = out / "threat-model.yaml"
    original = sanitizer.yaml.safe_dump(
        {
            "trust_boundaries": [{"id": "TB-1", "enforcement": "mTLS between services"}],
            "security_controls": [{"id": "SC-1", "notes": "AWS WAF is configured in terraform"}],
        },
        sort_keys=False,
    )
    _write(yaml_path, original)

    assert sanitizer.main([str(out)]) == 0

    assert yaml_path.read_text(encoding="utf-8") == original
    assert "nothing to scrub" in capsys.readouterr().out


def test_main_scrubs_yaml_writes_summary_and_is_idempotent(tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    yaml_path = out / "threat-model.yaml"
    _write(
        yaml_path,
        sanitizer.yaml.safe_dump(
            {
                "trust_boundaries": [{"id": "TB-1", "enforcement": "No WAF, JWT validation at the app boundary"}],
                "security_controls": [
                    {
                        "id": "SC-1",
                        "notes": "TLS configured; no firewall",
                        "implementation": "No API gateway",
                    }
                ],
            },
            sort_keys=False,
        ),
    )

    assert sanitizer.main([str(out)]) == 0

    first_out = capsys.readouterr().out
    written = _load_yaml(yaml_path)
    assert written["trust_boundaries"][0]["enforcement"] == (
        "JWT validation at the app boundary; deployment-time perimeter controls out of scope for source-tree review"
    )
    assert written["security_controls"][0]["notes"] == (
        "TLS configured; deployment-time perimeter controls out of scope for source-tree review"
    )
    assert written["security_controls"][0]["implementation"] == (
        "deployment-time perimeter controls out of scope for source-tree review"
    )
    assert "scrubbed 3 field(s)" in first_out
    assert "trust_boundaries.enforcement×1" in first_out
    assert "security_controls.notes×1" in first_out
    assert "security_controls.implementation×1" in first_out
    assert "API gateway" in first_out
    assert "WAF" in first_out
    assert "network firewall" in first_out

    assert sanitizer.main([str(out)]) == 0
    assert "nothing to scrub" in capsys.readouterr().out
