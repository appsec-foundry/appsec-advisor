from __future__ import annotations

import json
from pathlib import Path

import apply_repair_plan as arp
import pytest


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _plan(actions: list[dict]) -> dict:
    return {"actions": actions}


def test_fix_toc_nested_link_strips_inner_links_and_is_idempotent() -> None:
    md = "\n".join(
        [
            "- [Walkthrough [§3.9](#39-f-008-xss)](#39-f-008-xss)",
            "- [Finding [T-001](#t-001) summary](#different-anchor)",
            "- [Plain link](#plain)",
        ]
    )

    fixed, count = arp._fix_toc_nested_link(md)
    fixed_again, second_count = arp._fix_toc_nested_link(fixed)

    assert fixed == "\n".join(
        [
            "- [Walkthrough §3.9](#39-f-008-xss)",
            "- [Finding T-001 summary](#different-anchor)",
            "- [Plain link](#plain)",
        ]
    )
    assert count == 2
    assert fixed_again == fixed
    assert second_count == 0


def test_read_plan_returns_json_and_invalid_plan_exits_2(tmp_path: Path) -> None:
    plan_path = tmp_path / ".qa-repair-plan.json"
    _write(plan_path, json.dumps({"actions": []}))

    assert arp._read_plan(plan_path) == {"actions": []}

    _write(plan_path, "{bad json")
    with pytest.raises(SystemExit) as exc:
        arp._read_plan(plan_path)

    assert exc.value.code == 2

    with pytest.raises(SystemExit) as exc:
        arp._read_plan(tmp_path / "missing.json")

    assert exc.value.code == 2


def test_apply_plan_applies_supported_actions_and_leaves_unsupported_for_agent(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    md_path = out / "threat-model.md"
    _write(
        md_path,
        "- [Walkthrough [§3.9](#39-f-008-xss)](#39-f-008-xss)\n- [Clean](#clean)\n",
    )

    report = arp.apply_plan(
        out,
        _plan(
            [
                {"type": "toc_nested_link"},
                {"type": "walkthrough_depth"},
                {"rationale": "missing type"},
            ]
        ),
    )

    assert md_path.read_text(encoding="utf-8") == "- [Walkthrough §3.9](#39-f-008-xss)\n- [Clean](#clean)\n"
    assert report == {
        "applied_types": ["toc_nested_link"],
        "skipped_types": ["walkthrough_depth", "<missing>"],
        "changes": {"toc_nested_link": 1},
        "md_changed": True,
    }


def test_apply_plan_reports_no_change_for_clean_supported_action(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    md_path = out / "threat-model.md"
    _write(md_path, "- [Clean](#clean)\n")

    report = arp.apply_plan(out, _plan([{"type": "toc_nested_link"}]))

    assert md_path.read_text(encoding="utf-8") == "- [Clean](#clean)\n"
    assert report["applied_types"] == ["toc_nested_link"]
    assert report["skipped_types"] == []
    assert report["changes"] == {"toc_nested_link": 0}
    assert report["md_changed"] is False


def test_apply_plan_flags_supported_type_without_dispatch_handler(monkeypatch, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "threat-model.md", "- [Clean](#clean)\n")
    monkeypatch.setattr(arp, "SUPPORTED_TYPES", frozenset({"toc_nested_link", "future_mechanical_fix"}))

    report = arp.apply_plan(out, _plan([{"type": "future_mechanical_fix"}]))

    assert report["skipped_types"] == ["future_mechanical_fix"]
    assert "declared supported but no handler dispatched" in capsys.readouterr().err


def test_apply_plan_requires_threat_model_markdown(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()

    with pytest.raises(SystemExit) as exc:
        arp.apply_plan(out, _plan([{"type": "toc_nested_link"}]))

    assert exc.value.code == 2


def test_main_handles_missing_output_plan_and_empty_plan(tmp_path: Path, capsys) -> None:
    assert arp.main([str(tmp_path / "missing")]) == 2
    assert "output_dir is not a directory" in capsys.readouterr().err

    out = tmp_path / "out"
    out.mkdir()
    assert arp.main([str(out)]) == 0
    assert "no plan" in capsys.readouterr().err

    _write(out / ".qa-repair-plan.json", json.dumps({"actions": []}))
    assert arp.main([str(out)]) == 0
    assert "plan has 0 actions" in capsys.readouterr().err


def test_main_dry_run_reports_would_change_without_writing(tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    md_path = out / "threat-model.md"
    _write(md_path, "- [Walkthrough [§3.9](#39-f-008-xss)](#39-f-008-xss)\n")
    _write(
        out / ".qa-repair-plan.json",
        json.dumps({"actions": [{"type": "toc_nested_link"}, {"type": "mermaid_syntax"}]}),
    )

    rc = arp.main([str(out), "--dry-run"])

    assert rc == 1
    assert md_path.read_text(encoding="utf-8") == "- [Walkthrough [§3.9](#39-f-008-xss)](#39-f-008-xss)\n"
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "dry_run": True,
        "would_change": {"toc_nested_link": 1},
        "skipped_types": ["mermaid_syntax"],
    }


def test_main_dry_run_requires_markdown_when_plan_has_actions(tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / ".qa-repair-plan.json", json.dumps({"actions": [{"type": "toc_nested_link"}]}))

    assert arp.main([str(out), "--dry-run"]) == 2
    assert "threat-model.md" in capsys.readouterr().err


def test_main_applies_plan_and_returns_0_when_all_actions_supported(tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    md_path = out / "threat-model.md"
    _write(md_path, "- [Walkthrough [§3.9](#39-f-008-xss)](#39-f-008-xss)\n")
    plan_path = tmp_path / "custom-plan.json"
    _write(plan_path, json.dumps({"actions": [{"type": "toc_nested_link"}]}))

    rc = arp.main([str(out), "--plan", str(plan_path)])

    assert rc == 0
    assert md_path.read_text(encoding="utf-8") == "- [Walkthrough §3.9](#39-f-008-xss)\n"
    payload = json.loads(capsys.readouterr().out)
    assert payload["applied_types"] == ["toc_nested_link"]
    assert payload["changes"] == {"toc_nested_link": 1}


def test_main_returns_1_and_logs_skipped_unsupported_actions(tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "threat-model.md", "- [Clean](#clean)\n")
    _write(
        out / ".qa-repair-plan.json",
        json.dumps({"actions": [{"type": "toc_nested_link"}, {"type": "control_subsection_coverage"}]}),
    )

    rc = arp.main([str(out)])

    assert rc == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["skipped_types"] == ["control_subsection_coverage"]
    assert "toc_nested_link: 0 substitution(s)" in captured.err
    assert "skipped (non-mechanical)" in captured.err
