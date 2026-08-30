"""
Tests for scripts/build_editorial_context.py — the bounded Stage-4 input.

Covers:
  * every emitted block is an address the applier's allow-list admits;
  * the cap and the severity floor bound the finding prose;
  * mitigations follow their findings through either link direction;
  * the verdict, the Management Summary and the §6 narrative always come along;
  * headings, tables, fences and repeated paragraphs are not offered.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import apply_editorial_plan as applier  # noqa: E402
import build_editorial_context as builder  # noqa: E402
import check_editorial_diff as guard  # noqa: E402


def _threat(index: int, severity: str) -> dict:
    return {
        "id": f"F-{index:03d}",
        "title": f"Finding {index}",
        "risk": severity,
        "effective_severity": severity,
        "scenario": f"Scenario {index}.",
        "evidence_summary": f"Evidence {index}.",
        "impact_description": f"Impact {index}.",
        "mitigation_ids": [f"M-{index:03d}"],
    }


def _mitigation(index: int) -> dict:
    return {
        "id": f"M-{index:03d}",
        "title": f"Fix {index}",
        "priority": "P1",
        "kind": "fix",
        "steps": [f"Step one for {index}.", f"Step two for {index}."],
        "verification": f"Verify {index}.",
    }


MODEL = {
    "threats": [_threat(1, "Critical"), _threat(2, "High"), _threat(3, "Medium"), _threat(4, "High")],
    "mitigations": [_mitigation(1), _mitigation(2), _mitigation(3), _mitigation(4)],
    "verdict": {
        "severity": "Critical",
        "opening": "The application is not production ready.",
        "bullets_intro": "Two findings drive the verdict.",
        "bullets": [{"title": "Injection", "body": "Unparameterised SQL.", "refs": ["F-001"]}],
        "closing": "Close F-001 first.",
    },
}

PROSE_A = (
    "The request handler builds its query by concatenating the identifier straight from the query string, "
    "so no parameterisation stands between the caller and the database."
)
PROSE_B = (
    "**Assessment:** The validation layer runs after the query is built, which leaves the injection path open "
    "for every route that reaches this handler."
)
MECHANICAL_LABEL = "**Status:** 🔴 Weak — the control is present but defeated on the path this section describes."
FROZEN_PROSE = (
    "The overview table below is generated from the control inventory and restates the verdict of every "
    "category in this chapter, which makes it pregenerator-owned."
)

FRAGMENT_MD = f"""## 6.1 Input validation

{PROSE_A}

| Control | Status |
|---|---|
| Validation | Weak |

#### 6.1.1 Query construction

{PROSE_B}

{MECHANICAL_LABEL}

```ts
const q = "SELECT " + id;
```

- A list item is not prose.

<!-- §6.2 MECHANICAL-FROZEN — DO NOT EDIT (overview table is pregenerator-owned) -->

{FROZEN_PROSE}

<!-- §6.2 MECHANICAL-FROZEN END -->
"""

MS_VERDICT = {
    "severity": "Critical",
    "opening": "Not production ready.",
    "bullets_intro": "Two drivers.",
    "bullets": [{"title": "Injection", "body": "SQL is concatenated.", "refs": ["F-001"]}],
    "closing": "Fix injection first.",
}

MS_ANTI_PATTERNS = {
    "anti_patterns": [{"name": "Shared secret", "severity": "High", "description": "One key everywhere."}]
}


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "security"
    (out / ".fragments").mkdir(parents=True)
    (out / "threat-model.yaml").write_text(yaml.safe_dump(MODEL, sort_keys=False), encoding="utf-8")
    (out / ".fragments" / "security-architecture.md").write_text(FRAGMENT_MD, encoding="utf-8")
    (out / ".fragments" / "ms-verdict.json").write_text(json.dumps(MS_VERDICT), encoding="utf-8")
    (out / ".fragments" / "ms-anti-patterns.json").write_text(json.dumps(MS_ANTI_PATTERNS), encoding="utf-8")
    return out


def _build(output_dir: Path, **kwargs) -> dict:
    argv = [str(output_dir)]
    for key, value in kwargs.items():
        argv += [f"--{key.replace('_', '-')}", str(value)]
    assert builder.main(argv) == 0
    return json.loads((output_dir / builder.CONTEXT_DIR / builder.BLOCKS_NAME).read_text(encoding="utf-8"))


# ---------- the contract that keeps the projection and the applier aligned --


def test_every_block_is_an_address_the_applier_admits(output_dir: Path) -> None:
    projection = _build(output_dir)
    document = yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))
    allowed = set(guard.yaml_editable_paths(document))

    for block in projection["blocks"]:
        if block["file"] != "threat-model.yaml":
            continue
        assert applier.parse_field_path(block["path"]) in allowed


def test_block_text_matches_the_live_value(output_dir: Path) -> None:
    projection = _build(output_dir)
    document = yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))

    for block in projection["blocks"]:
        if block["file"] != "threat-model.yaml":
            continue
        path = applier.parse_field_path(block["path"])
        node = document
        for key in path:
            node = node[key]
        assert node == block["text"]


# ---------- selection --------------------------------------------------------


def test_the_severity_floor_excludes_lighter_findings(output_dir: Path) -> None:
    projection = _build(output_dir)
    labels = " ".join(b["label"] for b in projection["blocks"])

    assert "F-003" not in labels  # Medium
    assert "F-001" in labels and "F-002" in labels and "F-004" in labels


def test_the_cap_keeps_the_worst_findings(output_dir: Path) -> None:
    projection = _build(output_dir, max_findings=1)
    labels = " ".join(b["label"] for b in projection["blocks"])

    assert "F-001" in labels
    assert "F-002" not in labels and "F-004" not in labels


def test_a_capped_out_finding_takes_its_mitigation_with_it(output_dir: Path) -> None:
    projection = _build(output_dir, max_findings=1)
    labels = " ".join(b["label"] for b in projection["blocks"])

    assert "M-001" in labels
    assert "M-002" not in labels


def test_the_reverse_link_direction_also_selects_a_mitigation(output_dir: Path, tmp_path: Path) -> None:
    model = yaml.safe_load(yaml.safe_dump(MODEL, sort_keys=False))
    model["threats"][0].pop("mitigation_ids")
    model["mitigations"][0]["threat_ids"] = ["F-001"]
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(model, sort_keys=False), encoding="utf-8")

    projection = _build(output_dir, max_findings=1)

    assert "M-001" in " ".join(b["label"] for b in projection["blocks"])


def test_the_verdict_and_management_summary_always_travel(output_dir: Path) -> None:
    projection = _build(output_dir, max_findings=0)
    files = {b["file"] for b in projection["blocks"]}
    labels = [b["label"] for b in projection["blocks"]]

    assert ".fragments/ms-verdict.json" in files
    assert ".fragments/ms-anti-patterns.json" in files
    assert any(label.startswith("verdict · ") for label in labels)


# ---------- what the §6 fragment offers -------------------------------------


def test_only_prose_paragraphs_of_the_fragment_are_offered(output_dir: Path) -> None:
    projection = _build(output_dir)
    texts = [b["text"] for b in projection["blocks"] if b["file"].endswith(".md")]

    assert PROSE_A in texts
    assert PROSE_B in texts  # a bold label the pass may still improve
    assert all(not t.lstrip().startswith(("#", "|", "```", "-")) for t in texts)


def test_a_mechanical_label_is_not_offered(output_dir: Path) -> None:
    projection = _build(output_dir)
    texts = [b["text"] for b in projection["blocks"] if b["file"].endswith(".md")]

    assert MECHANICAL_LABEL not in texts


def test_a_frozen_region_is_not_offered(output_dir: Path) -> None:
    projection = _build(output_dir)
    texts = [b["text"] for b in projection["blocks"] if b["file"].endswith(".md")]

    assert FROZEN_PROSE not in texts


def test_a_short_paragraph_is_not_worth_a_dispatch(output_dir: Path) -> None:
    assert not builder.is_prose_paragraph("No parameterisation is in place.")
    assert builder.is_prose_paragraph(PROSE_A)


def test_a_repeated_paragraph_is_skipped_rather_than_made_ambiguous(output_dir: Path) -> None:
    fragment = output_dir / ".fragments" / "security-architecture.md"
    fragment.write_text(FRAGMENT_MD + f"\n{PROSE_A}\n", encoding="utf-8")

    projection = _build(output_dir)
    texts = [b["text"] for b in projection["blocks"] if b["file"].endswith(".md")]

    assert PROSE_A not in texts


def test_markdown_blocks_carry_no_field_address(output_dir: Path) -> None:
    projection = _build(output_dir)

    assert all(b["path"] is None for b in projection["blocks"] if b["file"].endswith(".md"))


def test_the_selection_summary_reports_the_size(output_dir: Path) -> None:
    projection = _build(output_dir)
    selection = projection["selection"]

    assert selection["blocks_total"] == len(projection["blocks"])
    assert selection["chars_total"] == sum(len(b["text"]) for b in projection["blocks"])
    assert selection["severity_floor"] == "high"
