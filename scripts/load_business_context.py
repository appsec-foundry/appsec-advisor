#!/usr/bin/env python3
"""Capture business context from a URL or a file into the repository's context file.

The analysis reads business context from ``docs/business-context.md`` (or, for a
run the user chose not to persist, from ``.business-context-input.md`` in the
output directory). This script is the only writer of both: it validates the
source, rejects credentials, and writes the result with a provenance header.

Captured text is untrusted data. It is stored, never executed, and the context
producer fences it before any agent reads it.

CLI
---

    load_business_context.py --repo-root R --output-dir O --source <url|path>
        (--persist | --run-only) [--replace] [--consume-source] [--json]

Exit codes
    0 — context written
    1 — rejected (URL policy, unreachable, HTML, secret found, target exists)
    2 — usage / IO error
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import secret_scan
from _atomic_io import atomic_write_text
from _url_guard import validate_target_url, validated_opener

REPO_RELATIVE = "docs/business-context.md"
RUN_ONLY_NAME = ".business-context-input.md"
MAX_BYTES = 65_536
READ_LINE_LIMIT = 200
FETCH_TIMEOUT = 15
_HTML_SNIFF = re.compile(r"^\s*(<!doctype\s+html|<html\b)", re.IGNORECASE)


class BusinessContextError(ValueError):
    """Raised when context cannot be captured safely."""


def _sanitize_provenance(value: str) -> str:
    """Keep a source label inside one Markdown comment line."""
    flat = value.replace("\r", " ").replace("\n", " ").replace("<", "&lt;").replace("-->", "--&gt;")
    return flat[:200]


def _decode(payload: bytes) -> str:
    text = payload.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    return text.strip("\n").rstrip() + "\n"


def _fetch_url(url: str) -> str:
    verdict = validate_target_url(url)
    if not verdict.ok:
        raise BusinessContextError(f"URL rejected by policy: {verdict.reason}")
    request = urllib.request.Request(url, headers={"Accept": "text/markdown, text/plain;q=0.9, */*;q=0.1"})
    opener = validated_opener()
    try:
        with opener.open(request, timeout=FETCH_TIMEOUT) as response:  # noqa: S310 - URL was policy-validated
            content_type = (response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            payload = response.read(MAX_BYTES + 1)
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise BusinessContextError(f"could not fetch {url}: {exc}") from exc
    if len(payload) > MAX_BYTES:
        raise BusinessContextError(f"context source exceeds the {MAX_BYTES}-byte cap")
    if content_type in {"text/html", "application/xhtml+xml"}:
        raise BusinessContextError(f"{url} returned {content_type}; point at a raw Markdown or plain-text export")
    text = _decode(payload)
    if _HTML_SNIFF.match(text):
        raise BusinessContextError(f"{url} returned an HTML page; point at a raw Markdown or plain-text export")
    return text


def _read_file(path: Path) -> str:
    resolved = path.expanduser()
    if not resolved.is_file():
        raise BusinessContextError(f"context source is not a file: {path}")
    payload = resolved.read_bytes()
    if len(payload) > MAX_BYTES:
        raise BusinessContextError(f"context source exceeds the {MAX_BYTES}-byte cap")
    return _decode(payload)


def load_source(source: str) -> tuple[str, str]:
    """Return (kind, text) for a URL or a file path."""
    if source.lower().startswith(("http://", "https://")):
        return "url", _fetch_url(source)
    return "file", _read_file(Path(source))


def _reject_secrets(text: str) -> None:
    hits = secret_scan.scan_text(text)
    if not hits:
        return
    where = ", ".join(f"line {hit.line} ({hit.pattern})" for hit in hits[:5])
    raise BusinessContextError(
        f"context source contains what looks like a credential — {where}. "
        "Remove it and capture the context again; business context is stored in the repository."
    )


def _persist_target(repo_root: Path) -> Path:
    if (repo_root / REPO_RELATIVE).is_symlink():
        raise BusinessContextError(f"{REPO_RELATIVE} is a symlink; refusing to write through it")
    target = (repo_root / REPO_RELATIVE).resolve()
    try:
        target.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise BusinessContextError(f"{REPO_RELATIVE} resolves outside the repository") from exc
    return target


def capture(
    *,
    repo_root: Path,
    output_dir: Path,
    source: str,
    persist: bool,
    replace: bool = False,
) -> dict[str, object]:
    kind, text = load_source(source)
    if not text.strip():
        raise BusinessContextError("context source is empty")
    _reject_secrets(text)

    if persist:
        target = _persist_target(repo_root)
        if target.exists() and not replace:
            raise BusinessContextError(f"{REPO_RELATIVE} already exists; pass --replace to overwrite it")
        target.parent.mkdir(parents=True, exist_ok=True)
    else:
        target = output_dir.resolve() / RUN_ONLY_NAME
        target.parent.mkdir(parents=True, exist_ok=True)

    captured = dt.datetime.now(tz=dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    header = f"<!-- appsec-advisor: business context captured {captured} from {_sanitize_provenance(source)} -->\n\n"
    body = header + text
    atomic_write_text(target, body)
    lines = text.count("\n")
    return {
        "status": "written",
        "target": str(target),
        "persisted": persist,
        "source_kind": kind,
        "bytes": len(body.encode("utf-8")),
        "lines": lines,
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "read_limit_exceeded": lines > READ_LINE_LIMIT,
    }


def effective_source(repo_root: Path, output_dir: Path) -> Path | None:
    """Return the file the analysis reads business context from, if any.

    A run-only capture takes precedence: it is this run's deliberate input, made
    after the repository file was written.
    """
    run_only = output_dir / RUN_ONLY_NAME
    if run_only.is_file():
        return run_only
    repo_file = repo_root / REPO_RELATIVE
    if repo_file.is_symlink() or not repo_file.is_file():
        return None
    try:
        repo_file.resolve(strict=True).relative_to(repo_root.resolve())
    except (OSError, ValueError):
        return None
    return repo_file


def context_digest(repo_root: Path, output_dir: Path) -> str | None:
    """Return the sha256 of the effective business context, or None when absent."""
    path = effective_source(repo_root, output_dir)
    if path is None:
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source", required=True, help="http(s) URL or a path to a Markdown/text file")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--persist", action="store_true", help=f"write <repo>/{REPO_RELATIVE}")
    target.add_argument("--run-only", action="store_true", help="write the transient input in the output directory")
    parser.add_argument("--replace", action="store_true", help=f"overwrite an existing {REPO_RELATIVE}")
    parser.add_argument(
        "--consume-source",
        action="store_true",
        help="delete the source file after reading (only inside the output directory)",
    )
    parser.add_argument("--json", action="store_true", help="print the receipt as JSON")
    return parser


def _consume(source: str, output_dir: Path) -> None:
    path = Path(source).expanduser()
    if not path.is_file():
        return
    try:
        path.resolve().relative_to(output_dir.resolve())
    except ValueError:
        return
    path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = capture(
            repo_root=args.repo_root,
            output_dir=args.output_dir,
            source=args.source,
            persist=args.persist,
            replace=args.replace,
        )
    except BusinessContextError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.consume_source:
        _consume(args.source, args.output_dir)
    if receipt["read_limit_exceeded"]:
        print(
            f"warning: only the first {READ_LINE_LIMIT} lines are read into the analysis context",
            file=sys.stderr,
        )
    if args.json:
        print(json.dumps(receipt, indent=2))
    else:
        print(f"business context written to {receipt['target']} ({receipt['bytes']} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
