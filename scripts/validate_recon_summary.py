#!/usr/bin/env python3
"""Validate the bounded Markdown contract for ``.recon-summary.md``.

The recon summary is Markdown rather than JSON, but its numbered headings are
an inter-stage API.  The recon producer runs this validator before publishing
its companion signal artifact, and the orchestration controller runs the same
validator again at the post-recon boundary.
"""

from __future__ import annotations

import argparse
import re
import sys
from functools import cache
from pathlib import Path

from _atomic_io import atomic_write_text

CONTRACT = "recon-summary-markdown-v1"
MAX_BYTES = 262_144
MAX_LINES = 1_000
_TEMPLATE_MARKER = "````markdown"
_KEY_FILES_PREFIX = "**Key files:**"
_FILE_REF_RE = re.compile(
    r"(?P<quote>`?)(?P<path>(?:[A-Za-z0-9_.@+ -]+/)*[A-Za-z0-9_.@+ -]+):"
    r"(?P<line>[1-9][0-9]*)(?P=quote)"
)


class ReconSummaryValidationError(ValueError):
    """Raised when a recon summary violates its Markdown contract."""


def _default_template_path() -> Path:
    return Path(__file__).resolve().parent.parent / "agents" / "shared" / "recon-output-template.md"


@cache
def required_headings(template_path: Path | None = None) -> tuple[str, ...]:
    """Return the ordered headings from the canonical fenced template."""
    path = (template_path or _default_template_path()).resolve()
    try:
        template = path.read_text(encoding="utf-8")
        fenced = template.split(_TEMPLATE_MARKER, 1)[1].split("````", 1)[0]
    except (OSError, UnicodeDecodeError, IndexError) as exc:
        raise ReconSummaryValidationError(f"cannot load {CONTRACT} template: {exc}") from exc
    headings = tuple(line for line in fenced.splitlines() if line.startswith("#"))
    if not headings:
        raise ReconSummaryValidationError(f"{CONTRACT} template has no headings")
    return headings


def _missing_heading_message(heading: str) -> str:
    if heading.startswith("### 7."):
        section = heading.split(maxsplit=1)[1].split(maxsplit=1)[0]
        return f"{CONTRACT} is missing or reorders security section {section} (expected {heading!r})"
    return f"{CONTRACT} is missing or reorders heading {heading!r}"


def _resolved_repo_root(repo_root: Path) -> Path:
    try:
        root = repo_root.resolve()
    except (OSError, RuntimeError) as exc:
        raise ReconSummaryValidationError(f"cannot resolve repository root {repo_root}: {exc}") from exc
    if not root.is_dir():
        raise ReconSummaryValidationError(f"repository root is not a directory: {repo_root}")
    return root


def _validate_key_file_reference(
    relative: str,
    raw_line: str,
    *,
    root: Path,
    summary_line: int,
    line_counts: dict[Path, int],
) -> None:
    relative = relative.strip()
    if "\\" in relative or "://" in relative or relative.startswith(("/", "./")) or ".." in Path(relative).parts:
        raise ReconSummaryValidationError(
            f"{CONTRACT} Key files entry at line {summary_line} has unsafe path {relative!r}"
        )
    try:
        candidate = (root / relative).resolve()
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ReconSummaryValidationError(
            f"{CONTRACT} Key files entry at line {summary_line} escapes the repository: {relative!r}"
        ) from exc
    if not candidate.is_file():
        raise ReconSummaryValidationError(
            f"{CONTRACT} Key files entry at line {summary_line} names a missing file: {relative!r}"
        )
    if candidate not in line_counts:
        try:
            with candidate.open("r", encoding="utf-8", errors="ignore") as handle:
                line_counts[candidate] = sum(1 for _ in handle)
        except OSError as exc:
            raise ReconSummaryValidationError(f"{CONTRACT} cannot read Key files entry {relative!r}: {exc}") from exc
    evidence_line = int(raw_line)
    if evidence_line > max(line_counts[candidate], 1):
        raise ReconSummaryValidationError(
            f"{CONTRACT} Key files entry {relative!r}:{evidence_line} exceeds the file's {line_counts[candidate]} lines"
        )


def _validate_key_file_references(lines: list[str], repo_root: Path) -> None:
    root = _resolved_repo_root(repo_root)

    line_counts: dict[Path, int] = {}
    for summary_line, text in enumerate(lines, start=1):
        if not text.startswith(_KEY_FILES_PREFIX):
            continue
        payload = text.removeprefix(_KEY_FILES_PREFIX).strip()
        none_value = payload.casefold().strip(" .")
        if none_value.startswith(("none", "no ", "not ", "n/a")) or none_value in {"—", "-"}:
            continue
        for entry in (part.strip() for part in re.split(r"[,;]", payload)):
            match = _FILE_REF_RE.fullmatch(entry)
            if match is None:
                raise ReconSummaryValidationError(
                    f"{CONTRACT} Key files entry at line {summary_line} must be exactly one observed "
                    "regular-file:single-line reference per comma/semicolon entry, or none"
                )
            _validate_key_file_reference(
                match.group("path"),
                match.group("line"),
                root=root,
                summary_line=summary_line,
                line_counts=line_counts,
            )


def normalize_key_file_references(path: Path, repo_root: Path) -> int:
    """Drop unsafe or unverifiable Key files entries without inventing evidence."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReconSummaryValidationError(f"cannot read {CONTRACT} artifact {path}: {exc}") from exc
    root = _resolved_repo_root(repo_root)
    line_counts: dict[Path, int] = {}
    changed = 0
    rendered_lines: list[str] = []
    for summary_line, text_line in enumerate(text.splitlines(), start=1):
        if not text_line.startswith(_KEY_FILES_PREFIX):
            rendered_lines.append(text_line)
            continue
        payload = text_line.removeprefix(_KEY_FILES_PREFIX).strip()
        none_value = payload.casefold().strip(" .")
        retained: list[str] = []
        if not (none_value.startswith(("none", "no ", "not ", "n/a")) or none_value in {"—", "-"}):
            for entry in (part.strip() for part in re.split(r"[,;]", payload)):
                match = _FILE_REF_RE.fullmatch(entry)
                if match is None:
                    continue
                try:
                    _validate_key_file_reference(
                        match.group("path"),
                        match.group("line"),
                        root=root,
                        summary_line=summary_line,
                        line_counts=line_counts,
                    )
                except ReconSummaryValidationError:
                    continue
                retained.append(f"`{match.group('path')}:{match.group('line')}`")
        replacement = f"{_KEY_FILES_PREFIX} {', '.join(retained) if retained else 'none detected'}"
        if replacement != text_line:
            changed += 1
        rendered_lines.append(replacement)
    if changed:
        atomic_write_text(path, "\n".join(rendered_lines) + ("\n" if text.endswith("\n") else ""))
    return changed


def validate_recon_summary(
    path: Path,
    *,
    template_path: Path | None = None,
    repo_root: Path | None = None,
    max_bytes: int = MAX_BYTES,
    max_lines: int = MAX_LINES,
) -> int:
    """Validate *path* and return its line count on success."""
    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReconSummaryValidationError(f"cannot read {CONTRACT} artifact {path}: {exc}") from exc
    if len(payload) > max_bytes:
        raise ReconSummaryValidationError(f"{CONTRACT} exceeds the {max_bytes}-byte cap")
    lines = text.splitlines()
    if len(lines) > max_lines:
        raise ReconSummaryValidationError(f"{CONTRACT} exceeds the {max_lines}-line cap")

    headings = [line for line in lines if line.startswith("#")]
    cursor = 0
    for required in required_headings(template_path):
        try:
            cursor = headings.index(required, cursor) + 1
        except ValueError as exc:
            raise ReconSummaryValidationError(_missing_heading_message(required)) from exc
    if repo_root is not None:
        _validate_key_file_references(lines, repo_root)
    return len(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path, help="Path to .recon-summary.md")
    parser.add_argument("--template", type=Path, help="Override the canonical template (tests only)")
    parser.add_argument("--repo-root", type=Path, help="Validate Key files references against this repository")
    parser.add_argument(
        "--normalize-key-files",
        action="store_true",
        help="Drop malformed, missing, directory, or out-of-range Key files entries before validation",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.normalize_key_files:
            if args.repo_root is None:
                raise ReconSummaryValidationError("--normalize-key-files requires --repo-root")
            changed = normalize_key_file_references(args.summary, args.repo_root)
            if changed:
                print(f"NORMALIZED: {CONTRACT} Key files lines={changed}")
        line_count = validate_recon_summary(args.summary, template_path=args.template, repo_root=args.repo_root)
    except ReconSummaryValidationError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"VALID: {CONTRACT} ({line_count} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
