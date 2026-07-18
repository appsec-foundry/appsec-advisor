"""Unit tests for scripts/validate_ms_compactness.py."""

from __future__ import annotations

import json
from pathlib import Path

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


# --- main ------------------------------------------------------------------


def test_main_fragment_absent_passes(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["validate_ms_compactness.py", str(tmp_path)])
    rc = mod.main()
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_main_clean_passes(tmp_path, capsys, monkeypatch):
    _write_verdict(tmp_path, {"opening": "fine", "closing": "ok", "bullets": []})
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
