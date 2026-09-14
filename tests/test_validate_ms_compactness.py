"""Unit tests for scripts/validate_ms_compactness.py."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import validate_fragment
import validate_ms_compactness as mod

# --- helpers ---------------------------------------------------------------


def test_words():
    assert mod._words("") == 0
    assert mod._words(None) == 0
    assert mod._words("one two three") == 3


def test_sentences():
    assert mod._sentences("") == 1  # max(1, 0)
    assert mod._sentences("One sentence.") == 1
    assert mod._sentences("One. Two! Three?") == 3
    # bold markers stripped, single trailing period → 1 sentence
    assert mod._sentences("**Verdict — secure by design.**") == 1


# --- _check_verdict --------------------------------------------------------


def _write_verdict(p: Path, obj) -> None:
    (p / ".fragments").mkdir(exist_ok=True)
    (p / ".fragments" / "ms-verdict.json").write_text(json.dumps(obj), encoding="utf-8")


def test_check_verdict_clean(tmp_path):
    _write_verdict(tmp_path, {"opening": "short", "closing": "ok", "bullets": []})
    v: list[str] = []
    mod._check_verdict(tmp_path / ".fragments" / "ms-verdict.json", v)
    assert v == []


def test_check_verdict_opening_over_budget(tmp_path):
    long_opening = " ".join(["word"] * (mod.VERDICT_OPENING_MAX_WORDS + 5))
    _write_verdict(tmp_path, {"opening": long_opening})
    v: list[str] = []
    mod._check_verdict(tmp_path / ".fragments" / "ms-verdict.json", v)
    assert len(v) == 1 and "opening" in v[0]


def test_check_verdict_closing_over_budget(tmp_path):
    _write_verdict(tmp_path, {"closing": "x" * (mod.VERDICT_CLOSING_MAX_CHARS + 1)})
    v: list[str] = []
    mod._check_verdict(tmp_path / ".fragments" / "ms-verdict.json", v)
    assert len(v) == 1 and "closing" in v[0]


def test_check_verdict_bullet_over_budget_and_non_dict(tmp_path):
    long_body = " ".join(["w"] * (mod.VERDICT_BULLET_BODY_MAX_WORDS + 1))
    _write_verdict(
        tmp_path,
        {"bullets": ["not-a-dict", {"body": long_body}, {"body": "fine"}]},
    )
    v: list[str] = []
    mod._check_verdict(tmp_path / ".fragments" / "ms-verdict.json", v)
    assert len(v) == 1 and "bullets[1].body" in v[0]


def test_check_verdict_rejects_technical_detail_and_multiple_sentences(tmp_path):
    _write_verdict(
        tmp_path,
        {
            "opening": "Not production-ready. The JWT implementation exposes customer accounts.",
            "closing": "Fix the SQL query before release.",
            "bullets": [
                {
                    "title": "JWT account takeover",
                    "body": "Anyone can take over an account. The middleware accepts unsigned tokens.",
                }
            ],
        },
    )
    v: list[str] = []
    mod._check_verdict(tmp_path / ".fragments" / "ms-verdict.json", v)
    assert any("opening contains technical detail 'JWT'" in issue for issue in v)
    assert any("closing contains technical detail 'SQL'" in issue for issue in v)
    assert any("title contains technical detail 'JWT'" in issue for issue in v)
    assert any("body has 2 sentences" in issue for issue in v)
    assert any("body contains technical detail 'middleware'" in issue for issue in v)


def test_check_verdict_body_may_name_the_weakness_class(tmp_path):
    bodies = [
        "Database query injection (SQL injection) in the product search lets anyone dump every customer record.",
        "Stored cross-site scripting (XSS) in product reviews lets an attacker hijack any visitor's session.",
        "XML external entity injection (XXE) in the invoice import lets any customer read server files.",
        "Missing ownership checks (IDOR) let any signed-in customer read another customer's orders.",
        "A private key published in the source tree lets anyone forge an administrator login.",
    ]
    _write_verdict(tmp_path, {"bullets": [{"title": "Customer data exposed", "body": b} for b in bodies]})
    v: list[str] = []
    mod._check_verdict(tmp_path / ".fragments" / "ms-verdict.json", v)
    assert v == []


def test_check_verdict_keeps_weakness_class_out_of_outcome_fields(tmp_path):
    _write_verdict(
        tmp_path,
        {
            "opening": "Not production-ready. SQL injection exposes every customer account.",
            "closing": "Fix the XSS before release.",
            "bullets": [{"title": "IDOR on orders", "body": "Anyone can read another customer's orders."}],
        },
    )
    v: list[str] = []
    mod._check_verdict(tmp_path / ".fragments" / "ms-verdict.json", v)
    assert any("opening contains technical detail 'SQL'" in issue for issue in v)
    assert any("closing contains technical detail 'XSS'" in issue for issue in v)
    assert any("title contains technical detail 'IDOR'" in issue for issue in v)


def test_check_verdict_body_still_rejects_technology_terms(tmp_path):
    _write_verdict(
        tmp_path,
        {
            "bullets": [
                {
                    "title": "Admin account takeover",
                    "body": "A hard-coded JWT signing key lets anyone forge an admin login.",
                },
                {"title": "Server files exposed", "body": "The XML parser lets any customer read files on the server."},
                {"title": "Customer data exposed", "body": "An open endpoint returns every customer record to anyone."},
            ]
        },
    )
    v: list[str] = []
    mod._check_verdict(tmp_path / ".fragments" / "ms-verdict.json", v)
    assert any("bullets[0].body contains technical detail 'JWT'" in issue for issue in v)
    assert any("bullets[1].body contains technical detail 'XML'" in issue for issue in v)
    assert any("bullets[2].body contains technical detail 'endpoint'" in issue for issue in v)


def test_check_verdict_bullet_word_cap_boundary(tmp_path):
    cap = mod.VERDICT_BULLET_BODY_MAX_WORDS
    _write_verdict(
        tmp_path,
        {"bullets": [{"body": " ".join(["word"] * cap)}, {"body": " ".join(["word"] * (cap + 1))}]},
    )
    v: list[str] = []
    mod._check_verdict(tmp_path / ".fragments" / "ms-verdict.json", v)
    assert v == [f"ms-verdict.json: bullets[1].body is {cap + 1} words (max {cap})"]


def test_renderer_contract_states_the_gate_word_cap():
    renderer = Path(__file__).resolve().parent.parent / "agents" / "appsec-threat-renderer.md"
    m = re.search(
        r"aim for (\d+) words and never exceed (\d+)\*\* \(the gate rejects (\d+)\+\)",
        renderer.read_text(encoding="utf-8"),
    )
    assert m, "renderer no longer states the bullet-body word budget"
    target, cap, rejected = (int(g) for g in m.groups())
    assert cap == mod.VERDICT_BULLET_BODY_MAX_WORDS
    assert rejected == cap + 1
    assert target < cap


# --- main ------------------------------------------------------------------

# Clean for this gate's prose rules and valid against the verdict schema, which
# the gate also enforces.
_CLEAN_VERDICT = {
    "severity": "red",
    "opening": "Not ready for production. Anyone on the internet can read every customer record today.",
    "bullets": [
        {
            "title": "Customer records exposed",
            "body": "Anyone can read every stored customer record without signing in.",
            "refs": ["T-001"],
        },
        {
            "title": "Orders changed by strangers",
            "body": "Any signed-in customer can change another customer's orders.",
            "refs": ["T-002"],
        },
    ],
    "closing": "Close the open record access before the next release to customers.",
}


def test_main_fragment_absent_passes(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["validate_ms_compactness.py", str(tmp_path)])
    rc = mod.main()
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_main_clean_passes(tmp_path, capsys, monkeypatch):
    _write_verdict(tmp_path, _CLEAN_VERDICT)
    monkeypatch.setattr("sys.argv", ["validate_ms_compactness.py", str(tmp_path)])
    rc = mod.main()
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_main_violation_fails(tmp_path, capsys, monkeypatch):
    long_opening = " ".join(["word"] * (mod.VERDICT_OPENING_MAX_WORDS + 5))
    _write_verdict(tmp_path, {"opening": long_opening})
    monkeypatch.setattr("sys.argv", ["validate_ms_compactness.py", str(tmp_path)])
    rc = mod.main()
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "opening" in out


def test_main_malformed_fragment_does_not_block(tmp_path, capsys, monkeypatch):
    (tmp_path / ".fragments").mkdir()
    (tmp_path / ".fragments" / "ms-verdict.json").write_text("{ broken", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["validate_ms_compactness.py", str(tmp_path)])
    rc = mod.main()
    assert rc == 0  # parse error warned, not blocked
    err = capsys.readouterr()
    assert "warn: could not read" in err.err
    assert "PASS" in err.out


# --- schema limits of the renderer's fragments ------------------------------

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas" / "fragments"


def _max_length(schema_type: str, list_key: str, field: str) -> int:
    schema = json.loads((SCHEMAS / f"{schema_type}.schema.json").read_text(encoding="utf-8"))
    return schema["properties"][list_key]["items"]["properties"][field]["maxLength"]


def _write(p: Path, name: str, obj) -> Path:
    (p / ".fragments").mkdir(exist_ok=True)
    path = p / ".fragments" / name
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    return path


def _prose(n: int) -> str:
    return ("A request reaches the data store without a server-side check. " * 20)[:n]


def _anti_patterns(description: str, components: list | None = None) -> dict:
    item = {
        "name": "Client-held session credential",
        "description": description,
        "findings": [{"ref": "T-001", "label": "Token readable by scripts"}],
    }
    if components is not None:
        item["affected_components"] = components
    return {"anti_patterns": [item]}


def _posture(description: str) -> dict:
    return {
        "schema_version": 1,
        "actors": ["internet-anon"],
        "attack_paths": [
            {
                "class": "injection",
                "actor": "internet-anon",
                "target": "data",
                "description": description,
                "impact": ["customer-data-exfiltration"],
                "findings": ["T-001"],
            }
        ],
    }


def _ai_exposure(components: list) -> dict:
    return {
        "ai_risks": [
            {
                "name": "Prompt reaches a tool call",
                "description": _prose(60),
                "findings": [{"ref": "T-002", "label": "Unfiltered prompt"}],
                "affected_components": components,
            }
        ]
    }


def _run(tmp_path: Path, monkeypatch) -> int:
    monkeypatch.setattr("sys.argv", ["validate_ms_compactness.py", str(tmp_path)])
    return mod.main()


@pytest.mark.parametrize(
    ("name", "schema_type", "list_key", "build"),
    [
        ("ms-anti-patterns.json", "anti-patterns", "anti_patterns", _anti_patterns),
        ("security-posture-attack-paths.json", "security-posture-attack-paths", "attack_paths", _posture),
    ],
)
def test_main_names_a_schema_limit_the_renderer_broke(
    tmp_path, capsys, monkeypatch, name, schema_type, list_key, build
):
    """The renderer passed this gate with an over-long description; the pre-render
    gate then needed a fragment-fixer dispatch and a second compose to repair it."""
    cap = _max_length(schema_type, list_key, "description")
    _write(tmp_path, name, build(_prose(cap + 1)))
    assert _run(tmp_path, monkeypatch) == 1
    assert f"{name}: {list_key}/0/description is {cap + 1} chars (max {cap})" in capsys.readouterr().out

    _write(tmp_path, name, build(_prose(cap)))
    assert _run(tmp_path, monkeypatch) == 0


def test_a_component_slug_compose_repairs_is_not_a_violation(tmp_path, capsys, monkeypatch):
    """Refs are judged as compose will see them, so the gate is never stricter than compose."""
    (tmp_path / "threat-model.yaml").write_text(
        "components:\n  - id: billing-api\n  - id: web-client\n", encoding="utf-8"
    )
    path = _write(tmp_path, "ms-ai-exposure.json", _ai_exposure(["web-client"]))
    before = path.read_bytes()
    assert _run(tmp_path, monkeypatch) == 0
    assert path.read_bytes() == before, "the renderer's gate must not rewrite its fragments"

    _write(tmp_path, "ms-ai-exposure.json", _ai_exposure(["no-such-component"]))
    assert _run(tmp_path, monkeypatch) == 1
    assert "ms-ai-exposure.json: ai_risks/0/affected_components/0" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("name", "content"),
    [("compound-chains.json", '{"unexpected": true}'), ("ms-anti-patterns.json", "{ broken")],
)
def test_what_the_renderer_cannot_repair_stays_with_the_pre_render_gate(tmp_path, monkeypatch, name, content):
    """Another producer's fragment and unreadable JSON are the pre-render gate's findings."""
    (tmp_path / ".fragments").mkdir()
    (tmp_path / ".fragments" / name).write_text(content, encoding="utf-8")
    assert _run(tmp_path, monkeypatch) == 0


@pytest.mark.parametrize("shape", ["over_cap", "at_cap", "repairable_slug", "unknown_slug"])
def test_the_gate_fails_exactly_the_fragments_the_pre_render_gate_fails(tmp_path, capsys, shape):
    """Both judge the same bytes; the renderer's gate only runs first."""
    cap = _max_length("anti-patterns", "anti_patterns", "description")
    (tmp_path / "threat-model.yaml").write_text("components:\n  - id: billing-api\n", encoding="utf-8")
    fragment = {
        "over_cap": _anti_patterns(_prose(cap + 1)),
        "at_cap": _anti_patterns(_prose(cap)),
        "repairable_slug": _anti_patterns(_prose(80), ["billing-api"]),
        "unknown_slug": _anti_patterns(_prose(80), ["no-such-component"]),
    }[shape]
    _write(tmp_path, "ms-anti-patterns.json", fragment)

    own = {error.split(":", 1)[0] for error in validate_fragment.ms_renderer_schema_errors(tmp_path)}
    validate_fragment.run_pre_render_gate(tmp_path, emit_json=True)
    gate = {entry["file"] for entry in json.loads(capsys.readouterr().out)["failed"]}
    assert own == gate
