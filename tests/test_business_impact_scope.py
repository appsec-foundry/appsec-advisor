"""Tests for scripts/contexts/business_impact_scope.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import contexts.business_impact_scope as scope  # noqa: E402
from orchestrator.build_stride_dispatch_manifest import _is_cicd  # noqa: E402

NO_HARM = "No material business harm — assuming only synthetic test data and no business-critical use."
HARM = "Customers lose access to scheduled deliveries for a full day."


def _dialog(answer: str, *, bold: bool = True) -> str:
    q, a = ("**Question:**", "**Answer:**") if bold else ("Question:", "Answer:")
    return (
        "## Business purpose\n\n"
        f"{q} Is this the use case?\n\n{a} Yes, assess this use case\n\n"
        "## Impact if compromised\n\n"
        f"{q} What would be the worst plausible consequence if the application were compromised?\n\n"
        f"{a} {answer}\n"
    )


COMPONENTS = [
    {"id": "web", "name": "Web Frontend", "tier": "client"},
    {"id": "api", "name": "REST API", "tier": "application"},
    {"id": "socket", "name": "Realtime Channel", "tier": "application"},
    {"id": "db", "name": "Database", "tier": "data"},
    {"id": "ci-cd-pipeline", "name": "CI/CD Pipeline", "tier": "application"},
    {"id": "release", "name": "Release Automation", "tier": "application", "deployment_zones": ["build-pipeline"]},
]


@pytest.mark.parametrize(
    ("answer", "choice", "material", "bold"),
    [
        (NO_HARM, "no-material-harm", False, True),
        (HARM, "declared-harm", True, True),
        (NO_HARM, "no-material-harm", False, False),
    ],
)
def test_marked_answer_round_trips_with_application_scope(answer, choice, material, bold):
    marked = scope.annotate(_dialog(answer, bold=bold), choice)
    impact = scope.application_impact("<!-- header -->\n\n## Confirmed business context\n\n" + marked)
    assert impact == {
        "choice": choice,
        "scope": "application",
        "impact_if_compromised": answer,
        "impact_is_material": material,
    }


@pytest.mark.parametrize(
    ("text", "choice", "error"),
    [
        (_dialog(HARM), "no-material-harm", "does not match"),
        (_dialog(NO_HARM), "declared-harm", "does not match"),
        ("## Business purpose\n\nAnswer: training\n", "no-material-harm", "no '## Impact"),
        ("## Impact if compromised\n\nAnswers vary by tenant.\n", "declared-harm", "no 'Answer:'"),
        (_dialog("x" * (scope.MAX_IMPACT_CHARS + 1)), "declared-harm", "exceeds"),
        (_dialog(HARM), "maybe", "unknown impact choice"),
    ],
)
def test_annotate_rejects_answers_the_choice_cannot_stand_for(text, choice, error):
    with pytest.raises(ValueError, match=error):
        scope.annotate(text, choice)


@pytest.mark.parametrize(
    "text",
    [
        "",
        _dialog(NO_HARM),  # saved before markers existed: previous behavior
        "## Impact if compromised\n<!-- appsec-advisor: impact scope=application choice=no-material-harm -->\n",
        "## Impact if compromised\n<!-- appsec-advisor: impact scope=application choice=other -->\nAnswer: x\n",
        "## Notes\n<!-- appsec-advisor: impact scope=application choice=no-material-harm -->\nAnswer: x\n",
    ],
)
def test_unmarked_or_malformed_context_has_no_application_impact(text):
    assert scope.application_impact(text) is None


def test_latest_marked_answer_wins():
    older = scope.annotate(_dialog(HARM), "declared-harm")
    newer = scope.annotate(_dialog(NO_HARM), "no-material-harm")
    assert scope.application_impact(older + "\n" + newer)["choice"] == "no-material-harm"


def _schema_valid(analyst: dict) -> None:
    schema = json.loads((ROOT / "schemas/stride-analyst-context.schema.json").read_text())
    jsonschema.validate(analyst, schema)


@pytest.mark.parametrize("answer", [NO_HARM, HARM])
def test_every_runtime_component_receives_the_application_impact(answer):
    impact = scope.application_impact(
        scope.annotate(_dialog(answer), "no-material-harm" if answer == NO_HARM else "declared-harm")
    )
    analyst = {"api": {"interfaces": "REST"}, "socket": {"business_context": {"business_purpose": "Live updates."}}}
    changed = scope.propagate(analyst, COMPONENTS, impact, _is_cicd)
    runtime = {"web", "api", "socket", "db"}
    assert set(changed) == runtime
    for cid in runtime:
        context = analyst[cid]["business_context"]
        assert context["impact_if_compromised"] == answer
        assert context["impact_is_material"] is (answer == HARM)
    assert analyst["socket"]["business_context"]["business_purpose"] == "Live updates."
    assert "ci-cd-pipeline" not in analyst and "release" not in analyst
    _schema_valid(analyst)


def test_narrower_declarations_are_kept():
    narrower = {"impact_if_compromised": "Payment records of real customers leak.", "impact_is_material": True}
    analyst = {"db": {"business_context": dict(narrower)}}
    impact = scope.application_impact(scope.annotate(_dialog(NO_HARM), "no-material-harm"))
    changed = scope.propagate(analyst, COMPONENTS, impact, _is_cicd)
    assert "db" not in changed
    assert analyst["db"]["business_context"] == narrower


def test_build_component_receives_the_impact_only_when_the_answer_names_it():
    answer = "No material business harm, including for the CI/CD Pipeline: it publishes nothing."
    impact = scope.application_impact(scope.annotate(_dialog(answer), "no-material-harm"))
    analyst: dict = {}
    changed = scope.propagate(analyst, COMPONENTS, impact, _is_cicd)
    assert "ci-cd-pipeline" in changed and "release" not in changed


def test_model_without_build_components_is_fully_covered():
    runtime_only = [c for c in COMPONENTS if not _is_cicd(c)]
    impact = scope.application_impact(scope.annotate(_dialog(NO_HARM), "no-material-harm"))
    analyst: dict = {}
    assert sorted(scope.propagate(analyst, runtime_only, impact, _is_cicd)) == sorted(c["id"] for c in runtime_only)
    _schema_valid(analyst)
