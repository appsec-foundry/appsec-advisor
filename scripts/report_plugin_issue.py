#!/usr/bin/env python3
"""Prepare reviewed support issues locally; publish only an explicitly approved digest.

The support skill owns source inspection and neutral prose. This module validates
the current diagnosis, excludes raw diagnostic data, checks common disclosure
signals, and binds publication to the exact preview. It cannot prove that prose
is anonymous or that an agent actually performed its claimed verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema
from recommend_fixes import _current_diagnoses
from secret_scan import scan_text

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "appsec-foundry/appsec-advisor"
INPUT = ".plugin-issue-input.json"
DRAFT = ".plugin-issue-draft.json"


class SupportError(ValueError):
    """A safe, actionable error containing no imported diagnostic text."""


def _read(output: Path, name: str) -> dict:
    path = output / name
    if path.is_symlink() or not path.resolve().is_relative_to(output.resolve()):
        raise SupportError("support artifacts must be local regular files")
    return json.loads(path.read_text(encoding="utf-8"))


def _validate(data: dict, kind: str) -> None:
    schema = json.loads((PLUGIN_ROOT / "schemas/plugin-issue.schema.json").read_text())
    jsonschema.Draft202012Validator({**schema, "$ref": f"#/$defs/{kind}"}).validate(data)


def _write(output: Path, name: str, data: dict, kind: str, *, exclusive: bool = False) -> None:
    _validate(data, kind)
    path = output / name
    # O_NOFOLLOW prevents replacing an unrelated file through a sidecar symlink.
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def _digest(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def offer(output: Path) -> dict:
    """Read-only support eligibility; completion has already released its lock."""
    from orchestration_controller import _headless_session
    from render_completion_summary import extract_run_issues, user_visible_issues

    data = extract_run_issues(output)
    issues = data.get("issues", []) if isinstance(data, dict) else []
    eligible = isinstance(issues, list) and bool(user_visible_issues([i for i in issues if isinstance(i, dict)]))
    result = {
        "schema_version": 1,
        "interactive": not _headless_session(),
        "busy": (output / ".appsec-lock").exists(),
        "offer": eligible and not _headless_session() and not (output / ".appsec-lock").exists(),
    }
    _validate(result, "offer")
    return result


def _diagnosis(output: Path, issue_id: str) -> tuple[dict, str]:
    from render_completion_summary import extract_run_issues

    if (output / ".appsec-lock").exists():
        raise SupportError("wait until the owning scan has finished")
    if extract_run_issues(output) is None:
        raise SupportError("current run issues are absent or stale")
    issues = _read(output, ".run-issues.json")
    # Validate before the existing consumer reads the same fixed diagnostic file.
    diagnosis = _read(output, ".run-bugs.json")
    entry = _current_diagnoses(issues, output).get(issue_id)
    if not entry or entry["verdict"] != "plugin_bug" or entry["confidence"] != "high":
        raise SupportError("a current, high-confidence plugin diagnosis is required")
    return entry, _digest({"issues": issues, "diagnosis": diagnosis})


def _location(entry: dict) -> str:
    location = entry["root_cause"]["location"]
    match = re.fullmatch(
        r"((?:(?:scripts|agents|skills|schemas|data|hooks|templates|docs)/[A-Za-z0-9_./-]+"
        r"|\.claude-plugin/(?:plugin|marketplace)\.json|config\.json|AGENTS\.md))(?::([1-9][0-9]*))?",
        location,
    )
    if not match or ".." in Path(match[1]).parts:
        raise SupportError("root cause must identify an existing plugin source file")
    path = PLUGIN_ROOT / match[1]
    if not path.resolve().is_relative_to(PLUGIN_ROOT.resolve()) or not path.is_file():
        raise SupportError("root cause must stay inside the installed plugin")
    if match[2] and int(match[2]) > len(path.read_text(encoding="utf-8").splitlines()):
        raise SupportError("root cause line does not exist")
    return location


def _privacy(text: str, repo: Path) -> None:
    # These are rejection checks, not an assertion of complete anonymisation.
    # Plugin-relative references and neutral synthetic inputs remain useful.
    signals = (
        r"https?://|www\.|[\w.+-]+@[\w.-]+",
        r"(?<![\w/])(?:/[\w.-]+|[A-Za-z]:[\\/]|~[/\\]|\\\\)",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"\b[A-Za-z0-9_+/=-]{32,}\b",
        r"[\x00-\x08\x0b-\x1f\x7f]|[\u202a-\u202e\u2066-\u2069]",
        r"<[^>]*>|!\[|\]\(",
    )
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in signals) or scan_text(text):
        raise SupportError("public text contains a potential identifier, secret, path, or link; rewrite it neutrally")
    if str(repo.resolve()).casefold() in text.casefold() or re.search(
        rf"(?<!\w){re.escape(repo.resolve().name)}(?!\w)", text, re.IGNORECASE
    ):
        raise SupportError("public text contains the scanned repository identity")


def _build(output: Path, repo: Path) -> dict:
    source = _read(output, INPUT)
    _validate(source, "input")
    if source["source_generated"] != _read(output, ".run-issues.json").get("generated"):
        raise SupportError("neutral issue input belongs to a different run; prepare it again")
    entry, snapshot = _diagnosis(output, source["issue_id"])
    location = _location(entry)
    public = [source[key] for key in ("title", "expected", "actual", "cause")]
    _privacy("\n".join([*public, source["verification"]["evidence"]]), repo)
    version = json.loads((PLUGIN_ROOT / ".claude-plugin/plugin.json").read_text())["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version):
        raise SupportError("invalid plugin version")
    verification = source["verification"]
    method = {
        "source_trace": "Source inspection; not independently reproduced",
        "reproduced": "Neutral local reproduction executed",
    }[verification["method"]]
    body = (
        f"## Environment\n\nPlugin version: {version}\n\n"
        f"## Expected behavior\n\n{source['expected']}\n\n"
        f"## Actual behavior\n\n{source['actual']}\n\n"
        f"## Plugin cause\n\nLocation: `{location}`\n\n{source['cause']}\n\n"
        f"## Verification\n\n{method}\n\n{verification['evidence']}\n\n"
        "No raw logs, source from the scanned repository, findings, or diagnostic attachments are included.\n"
    )
    draft = {
        "schema_version": 1,
        "issue_id": source["issue_id"],
        "snapshot": snapshot,
        "title": source["title"],
        "body": body,
    }
    return draft


def prepare(output: Path, repo: Path) -> dict:
    draft = _build(output, repo)
    _write(output, DRAFT, draft, "draft")
    return draft


def preview(output: Path) -> str:
    draft = _read(output, DRAFT)
    _validate(draft, "draft")
    return (
        f"Destination: https://github.com/{REPOSITORY}/issues\n"
        "Public issue; the authenticated GitHub account remains visible as author.\n"
        "Review all text for internal names and confidential details before approval.\n\n"
        f"Title: {draft['title']}\n\n{draft['body']}\n"
        f"Approval SHA-256: {_digest(draft)}"
    )


def publish(output: Path, repo: Path, approved: str) -> str:
    from orchestration_controller import _headless_session

    if _headless_session():
        raise SupportError("unattended publication is disabled")
    draft = _read(output, DRAFT)
    _validate(draft, "draft")
    digest = _digest(draft)
    if approved != digest:
        raise SupportError("approval does not match the exact draft; preview and request approval again")
    # Rebuild in memory through the same gates without replacing the approved file.
    original = draft
    regenerated = _build(output, repo)
    if regenerated != original:
        raise SupportError("diagnosis or draft inputs changed; preview and request approval again")
    gh = shutil.which("gh")
    if not gh:
        raise SupportError("GitHub CLI is unavailable; the draft remains local for manual submission")
    receipt = {"schema_version": 1, "digest": digest, "status": "pending", "url": None}
    receipt_name = f".plugin-issue-{digest}.receipt.json"
    # A pending receipt is deliberate: ambiguous network outcomes must not retry.
    try:
        _write(output, receipt_name, receipt, "receipt", exclusive=True)
    except FileExistsError:
        prior = _read(output, receipt_name)
        _validate(prior, "receipt")
        if prior["digest"] != digest:
            raise SupportError("submission receipt does not match the approved draft")
        if prior["status"] == "published":
            return prior["url"]
        raise SupportError("a prior submission may have succeeded; check GitHub before any manual retry") from None
    try:
        result = subprocess.run(
            [gh, "api", "--hostname", "github.com", f"repos/{REPOSITORY}/issues", "--method", "POST", "--input", "-"],
            input=json.dumps({"title": draft["title"], "body": draft["body"]}),
            text=True,
            capture_output=True,
            timeout=60,
            check=True,
        )
        url = json.loads(result.stdout)["html_url"]
        if not re.fullmatch(r"https://github\.com/appsec-foundry/appsec-advisor/issues/[1-9][0-9]*", url):
            raise SupportError("unexpected issue URL")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise SupportError(
            "submission outcome is uncertain; check GitHub before retrying; the local draft is retained"
        ) from None
    receipt.update(status="published", url=url)
    _write(output, receipt_name, receipt, "receipt")
    return url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("offer", "prepare", "preview", "publish"))
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--approved-sha256")
    args = parser.parse_args(argv)
    try:
        if args.command == "offer":
            print(json.dumps(offer(args.output_dir)))
        elif args.command == "preview":
            print(preview(args.output_dir))
        elif args.repo_root is None:
            raise SupportError("--repo-root is required")
        elif args.command == "prepare":
            prepare(args.output_dir, args.repo_root)
            print(preview(args.output_dir))
        elif not args.approved_sha256:
            raise SupportError("explicit --approved-sha256 is required after user review")
        else:
            print(publish(args.output_dir, args.repo_root, args.approved_sha256))
    except SupportError as exc:
        print(f"Support operation refused: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError, jsonschema.ValidationError):
        # Never echo malformed diagnostic fields or subprocess stderr into logs.
        print(
            "Support operation refused. Check local inputs, diagnosis, approval, and any submission receipt; no automatic retry.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
