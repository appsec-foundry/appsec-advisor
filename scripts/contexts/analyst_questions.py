#!/usr/bin/env python3
"""contexts/analyst_questions.py — questions, answers, and feature files of the analyst.

Questions get controller-owned, job-local ids (``q-001``) and a fingerprint
over their text, catalog entry, and the job's package fingerprint. An answer
is accepted only for a pending question of the same job whose fingerprint
still matches; it is a sourced declaration, never risk acceptance, and an
answer containing a detected secret is refused.

A feature file is written only on explicit save, to the path the developer
chose, and never committed. A save rejects a stale overwrite: the caller must
present the digest of the version it read, and an absent file must still be
absent. Reuse rechecks every saved answer: an answer whose question
fingerprint no longer matches a delivered question is stale, and one whose
stored answer fingerprint no longer matches its text was edited after saving.
Neither is delivered as an answer. Saved content never gains authority.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import contextlib
import hashlib
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml
from validators.secret_scan import scan_text
from validators.validate_analyst import schema_errors

MAX_FILE_BYTES = 256 * 1024
MAX_ANSWER_CHARS = 2000


class QuestionError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()


def question_fingerprint(asks: str, question_ref: str | None, package_fingerprint: str) -> str:
    """Identity of a question for answer reuse.

    A catalog question is identified by its entry and the job's packages, so
    its answer survives rewording by the model but not a package change. A
    free-form question is identified by its normalized text.
    """
    if question_ref:
        return _sha({"ref": question_ref, "packages": package_fingerprint})
    return _sha({"asks": " ".join(asks.split()), "packages": package_fingerprint})


def answer_fingerprint(question_fp: str, answer: str) -> str:
    return _sha({"question": question_fp, "answer": answer})


def assign(questions: list[dict], package_fingerprint: str) -> list[dict]:
    """Give validated model questions job-local ids and fingerprints."""
    assigned = []
    for i, q in enumerate(questions, start=1):
        entry = {k: q[k] for k in ("question_ref", "asks", "why", "affects", "suggested_answers", "required") if k in q}
        entry["id"] = f"q-{i:03d}"
        entry["fingerprint"] = question_fingerprint(q["asks"], q.get("question_ref"), package_fingerprint)
        assigned.append(entry)
    return assigned


def _read(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise QuestionError([f"{path.name}: not a regular file"])
        body = handle.read(MAX_FILE_BYTES + 1)
    if len(body) > MAX_FILE_BYTES:
        raise QuestionError([f"{path.name}: too large"])
    return body


def check_answers(items: list, pending: list[dict]) -> dict[str, str]:
    """Validate answer items ``{question_id, fingerprint, answer}``; return ``{question id: answer}``."""
    by_id = {q["id"]: q for q in pending}
    accepted, errors = {}, []
    for i, item in enumerate(items):
        if not isinstance(item, dict) or set(item) != {"question_id", "fingerprint", "answer"}:
            errors.append(f"answers/{i}: expected question_id, fingerprint, and answer")
            continue
        question = by_id.get(item["question_id"])
        answer = " ".join(item["answer"].split()) if isinstance(item["answer"], str) else ""
        if question is None:
            errors.append(f"answers/{i}: not a pending question of this job")
        elif item["fingerprint"] != question["fingerprint"]:
            errors.append(f"answers/{i}: the question changed since it was asked")
        elif item["question_id"] in accepted:
            errors.append(f"answers/{i}: answered twice")
        elif not answer or len(answer) > MAX_ANSWER_CHARS:
            errors.append(f"answers/{i}: empty or too long")
        elif scan_text(answer):
            errors.append(f"answers/{i}: contains a secret; describe the fact without the value")
        else:
            accepted[item["question_id"]] = answer
    if errors:
        raise QuestionError(errors)
    return accepted


def load_answers(path: Path, job_id: str, pending: list[dict]) -> dict[str, str]:
    """Validate a submitted answers file; return ``{question id: answer}``."""
    try:
        data = json.loads(_read(path))
    except (OSError, json.JSONDecodeError):
        raise QuestionError([f"{path.name}: unreadable or not JSON"]) from None
    if not isinstance(data, dict) or set(data) != {"job_id", "answers"} or not isinstance(data["answers"], list):
        raise QuestionError(["answers: expected an object with job_id and answers"])
    if data["job_id"] != job_id:
        raise QuestionError(["answers: written for a different job"])
    return check_answers(data["answers"], pending)


def load_feature(path: Path) -> tuple[dict, str]:
    """Read and validate a feature file; return (document, sha256)."""
    try:
        body = _read(path)
        data = yaml.safe_load(body)
    except FileNotFoundError:
        raise QuestionError([f"{path.name}: feature file not found"]) from None
    except (OSError, yaml.YAMLError):
        raise QuestionError([f"{path.name}: unreadable or invalid YAML"]) from None
    errors = schema_errors("feature", data)
    if errors:
        raise QuestionError(errors)
    return data, hashlib.sha256(body).hexdigest()


def classify(feature: dict, delivered: list[dict]) -> dict[str, list[dict]]:
    """Split saved answers into reusable, stale, and edited ones."""
    current = {q["fingerprint"] for q in delivered}
    groups: dict[str, list[dict]] = {"reusable": [], "stale": [], "edited": []}
    for answer in feature["answers"]:
        if answer_fingerprint(answer["question_fingerprint"], answer["answer"]) != answer["answer_fingerprint"]:
            groups["edited"].append(answer)
        elif answer["question_fingerprint"] not in current:
            groups["stale"].append(answer)
        else:
            groups["reusable"].append(answer)
    return groups


def projection(feature: dict, sha256: str, label: str, delivered: list[dict]) -> dict:
    """Context projection of a feature file: declarations plus reusable answers only."""
    groups = classify(feature, delivered)
    return {
        "label": label,
        "sha256": sha256,
        "declarations": {
            "intent": feature["intent"],
            "declarations": feature["declarations"],
            "answers": [{"asks": a["asks"], "answer": a["answer"]} for a in groups["reusable"]],
            "pending_verification": feature["pending_verification"],
            "stale_answers": len(groups["stale"]),
            "edited_answers": len(groups["edited"]),
        },
    }


def _write_atomic(path: Path, text: str) -> None:
    if path.is_symlink():
        raise QuestionError([f"{path.name}: is a symlink"])
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def save(
    path: Path,
    expected_sha256: str | None,
    feature_id: str,
    intent: str,
    answers: list[dict],
    declarations: list[str] | None = None,
    pending_verification: list[str] | None = None,
    remove_fingerprints: frozenset[str] = frozenset(),
    answered_at: str | None = None,
) -> str:
    """Merge validated answers into the feature file and return its new digest.

    ``answers`` items carry ``question_ref`` (optional), ``asks``, ``answer``,
    and ``question_fingerprint``. A saved answer for the same question
    fingerprint is replaced; ``remove_fingerprints`` drops saved answers.
    """
    if ".git" in path.resolve().parts:
        raise QuestionError(["feature file cannot be inside .git"])
    if path.exists() or path.is_symlink():
        if expected_sha256 is None:
            raise QuestionError([f"{path.name}: exists; load it before saving"])
        current, sha = load_feature(path)
        if sha != expected_sha256:
            raise QuestionError([f"{path.name}: changed since it was read"])
        if current["feature_id"] != feature_id:
            raise QuestionError([f"{path.name}: belongs to another feature"])
    else:
        if expected_sha256 is not None:
            raise QuestionError([f"{path.name}: was removed since it was read"])
        current = {"revision": 0, "declarations": [], "answers": [], "pending_verification": []}
    replaced = {a["question_fingerprint"] for a in answers} | set(remove_fingerprints)
    merged = [a for a in current["answers"] if a["question_fingerprint"] not in replaced]
    for a in answers:
        entry = {k: a[k] for k in ("question_ref",) if a.get(k)}
        entry.update(
            asks=a["asks"],
            answer=a["answer"],
            question_fingerprint=a["question_fingerprint"],
            answer_fingerprint=answer_fingerprint(a["question_fingerprint"], a["answer"]),
            answered_at=answered_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        merged.append(entry)
    document = {
        "schema_version": 1,
        "feature_id": feature_id,
        "revision": current["revision"] + 1,
        "intent": intent,
        "declarations": declarations if declarations is not None else current["declarations"],
        "answers": merged,
        "pending_verification": pending_verification
        if pending_verification is not None
        else current["pending_verification"],
    }
    errors = schema_errors("feature", document)
    if errors:
        raise QuestionError(errors)
    text = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    if scan_text(text):
        raise QuestionError(["feature file would contain a secret; nothing was saved"])
    _write_atomic(path, text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
