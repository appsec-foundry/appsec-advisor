"""Question identity, answer provenance, reuse, and explicit feature persistence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from contexts import analyst_questions as aq  # noqa: E402

PKG = "a" * 64
JOB = "aj-" + "b" * 32
SECRET = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"


def pending() -> list[dict]:
    return aq.assign(
        [
            {
                "question_ref": "appsec/core:authz-scope",
                "asks": "Who may export?",
                "why": "Access scope.",
                "affects": "export",
                "required": True,
            }
        ],
        PKG,
    )


def answers_file(tmp_path: Path, items: list, job: str = JOB) -> Path:
    path = tmp_path / "answers.json"
    path.write_text(json.dumps({"job_id": job, "answers": items}))
    return path


def test_ids_are_job_local_and_catalog_fingerprints_survive_rewording():
    q = pending()[0]
    assert q["id"] == "q-001"
    reworded = aq.assign(
        [
            {
                "question_ref": "appsec/core:authz-scope",
                "asks": "Which roles may export which data?",
                "why": "x",
                "affects": "y",
                "required": True,
            }
        ],
        PKG,
    )[0]
    assert reworded["fingerprint"] == q["fingerprint"]
    assert aq.question_fingerprint("Who may export?", "appsec/core:authz-scope", "c" * 64) != q["fingerprint"]
    free = aq.question_fingerprint("Who may export?", None, PKG)
    assert free != q["fingerprint"] and free == aq.question_fingerprint(" Who  may export? ", None, PKG)


def test_valid_answers_are_accepted(tmp_path):
    q = pending()[0]
    path = answers_file(
        tmp_path, [{"question_id": q["id"], "fingerprint": q["fingerprint"], "answer": " Only  assigned customers. "}]
    )
    assert aq.load_answers(path, JOB, [q]) == {"q-001": "Only assigned customers."}


@pytest.mark.parametrize(
    ("items", "job", "message"),
    [
        ([{"question_id": "q-001", "fingerprint": "0" * 64, "answer": "x"}], JOB, "changed since it was asked"),
        ([{"question_id": "q-009", "fingerprint": "0" * 64, "answer": "x"}], JOB, "not a pending question"),
        ([{"question_id": "q-001", "fingerprint": None, "answer": ""}], JOB, None),
        ([{"question_id": "q-001", "fingerprint": None, "answer": SECRET}], JOB, "contains a secret"),
        (
            [{"question_id": "q-001", "fingerprint": None, "answer": "x", "accept_risk": True}],
            JOB,
            "expected question_id",
        ),
        ([], "aj-" + "c" * 32, "different job"),
    ],
    ids=["changed-question", "unknown-question", "empty", "secret", "extra-field", "other-job"],
)
def test_invalid_answers_are_rejected(tmp_path, items, job, message):
    q = pending()[0]
    for item in items:
        if item.get("fingerprint") is None:
            item["fingerprint"] = q["fingerprint"]
    with pytest.raises(aq.QuestionError, match=message):
        aq.load_answers(answers_file(tmp_path, items, job), JOB, [q])


def test_feature_save_is_explicit_merging_and_refuses_stale_overwrites(tmp_path):
    q = pending()[0]
    path = tmp_path / "feature.yaml"
    answer = {
        "question_ref": q["question_ref"],
        "asks": q["asks"],
        "answer": "Only assigned customers.",
        "question_fingerprint": q["fingerprint"],
    }
    first = aq.save(
        path, None, "customer-export", "Support exports customer data.", [answer], answered_at="2026-10-04T12:00:00Z"
    )
    doc, sha = aq.load_feature(path)
    assert sha == first and doc["revision"] == 1 and len(doc["answers"]) == 1
    with pytest.raises(aq.QuestionError, match="load it before saving"):
        aq.save(path, None, "customer-export", "x", [answer])
    with pytest.raises(aq.QuestionError, match="changed since it was read"):
        aq.save(path, "0" * 64, "customer-export", "x", [answer])
    with pytest.raises(aq.QuestionError, match="another feature"):
        aq.save(path, first, "other-feature", "x", [answer])
    second = aq.save(
        path,
        first,
        "customer-export",
        "Support exports customer data.",
        [dict(answer, answer="Assigned customers only, read-only.")],
    )
    doc, _ = aq.load_feature(path)
    assert doc["revision"] == 2 and [a["answer"] for a in doc["answers"]] == ["Assigned customers only, read-only."]
    aq.save(
        path,
        second,
        "customer-export",
        "Support exports customer data.",
        [],
        remove_fingerprints=frozenset({q["fingerprint"]}),
    )
    assert aq.load_feature(path)[0]["answers"] == []


def test_feature_save_refuses_secrets_git_dirs_and_symlinks(tmp_path):
    q = pending()[0]
    answer = {"asks": q["asks"], "answer": "ok", "question_fingerprint": q["fingerprint"]}
    with pytest.raises(aq.QuestionError, match="secret"):
        aq.save(tmp_path / "f.yaml", None, "f", SECRET, [answer])
    assert not (tmp_path / "f.yaml").exists()
    (tmp_path / ".git").mkdir()
    with pytest.raises(aq.QuestionError, match=".git"):
        aq.save(tmp_path / ".git" / "f.yaml", None, "f", "intent", [answer])
    target = tmp_path / "target.yaml"
    target.write_text("keep\n")
    (tmp_path / "link.yaml").symlink_to(target)
    with pytest.raises(aq.QuestionError):
        aq.save(tmp_path / "link.yaml", None, "f", "intent", [answer])
    assert target.read_text() == "keep\n"


def test_reuse_rechecks_saved_answers(tmp_path):
    q = pending()[0]
    path = tmp_path / "feature.yaml"
    answer = {
        "question_ref": q["question_ref"],
        "asks": q["asks"],
        "answer": "Assigned only.",
        "question_fingerprint": q["fingerprint"],
    }
    aq.save(path, None, "customer-export", "intent", [answer])
    doc, sha = aq.load_feature(path)
    assert aq.projection(doc, sha, "feature.yaml", [q])["declarations"]["answers"] == [
        {"asks": q["asks"], "answer": "Assigned only."}
    ]
    changed_package = aq.assign([dict(q, asks=q["asks"])], "d" * 64)
    assert aq.classify(doc, changed_package)["stale"]
    doc["answers"][0]["answer"] = "Everyone may export everything."
    groups = aq.classify(doc, [q])
    assert groups["edited"] and not groups["reusable"]
    assert aq.projection(doc, sha, "feature.yaml", [q])["declarations"]["edited_answers"] == 1


def test_feature_files_cannot_carry_authority(tmp_path):
    path = tmp_path / "feature.yaml"
    doc = yaml.safe_load((ROOT / "examples" / "analyst" / "customer-export-feature.yaml").read_text())
    path.write_text(yaml.safe_dump(doc))
    assert aq.load_feature(path)[0]["feature_id"] == "customer-export"
    for key, value in (("permissions", ["Bash"]), ("risk_acceptance", True), ("waive_requirements", ["X-1"])):
        path.write_text(yaml.safe_dump(dict(doc, **{key: value})))
        with pytest.raises(aq.QuestionError):
            aq.load_feature(path)
