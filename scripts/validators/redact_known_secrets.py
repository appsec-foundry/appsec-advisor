#!/usr/bin/env python3
"""Deterministic exact-value secret redaction over rendered artifacts.

The pattern-based masker (``secret_scan.mask_text``) neutralises a secret only
in the *form* it can match (e.g. ``secret = '...'``). When an LLM author copies
a raw secret VALUE into prose ("the JWT signing secret is the literal
e2e-fixture-jwt-secret-7f4c91") no pattern matches and the value ships in the
report — and it propagates through the STRIDE -> merged -> yaml/sarif/md/html
pipeline (2026-06-28 e2e leak).

This pass closes that gap. It scans the repository SOURCE for secret values —
where they appear in a matchable assignment / token form, so ``secret_scan``
yields the clean value — then replaces each exact value string everywhere it
occurs in the output artifacts, prose included.

Two bounds keep a document-wide replacement from corrupting the report, because
the pass rewrites every artifact and cannot be reviewed per occurrence:

* The source walk skips prior assessment outputs. A previous run's artifacts are
  this plugin's own prose ABOUT credentials, so harvesting them lets each run
  poison the next. ``--output-dir`` is user-selectable and copies get arbitrary
  names, so the static prefix list cannot carry this — detection is structural
  (``scan_excludes.is_assessment_artifact``).
* A value shaped like a natural-language word is replaced only where the
  artifact itself shows credential context. The blanket replace assumed the
  scanner never yields a false positive; when that premise broke, the ordinary
  word "referenced" was destroyed in three unrelated sentences (juice-shop
  2026-08-28). High-entropy values keep the unconditional replace.

Conservative by design: only values >= 8 chars that are not already masked are
redacted, and the source walk honours ``data/scan-excludes.yaml``.

The source walk only sees values in a form the pattern scanner matches. A key
passed straight into a call (``hmac('sha256', '<literal>')``) has no assignment
or token shape, yet the analysis itself cites it as a hardcoded secret, and the
report quoted it unmasked while redaction and the gate both passed (2026-10-08).
``known_secret_values`` therefore also takes the secret-shaped literals at the
evidence lines of every secret-management finding. The ``unmasked_secrets`` gate
checks the same set, so it cannot pass a value this pass does not know.

Usage:
    validators/redact_known_secrets.py --repo-root <repo> --output-dir <out> [--write-scan-json]
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import math
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analyzers.scan_excludes as scan_excludes  # noqa: E402
from analyzers.weakness_classifier import classify_threat, load_weakness_classes  # noqa: E402

from validators.secret_scan import (  # noqa: E402
    _PROSE_VOWEL_RE,
    _PROSE_WORD_RE,
    CREDENTIAL_KEYWORDS,
    PUBLISHED_ARTIFACTS,
    _value_is_masked,
    scan_file,
    scan_text,
)

# Output artifacts a copied secret can reach. Globs are resolved under the
# output dir; the data-pipeline sidecars are included because the secret enters
# there first (analyst evidence) before propagating to the published files.
_ARTIFACT_GLOBS = (
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.sarif.json",
    "threat-model.threatdragon.json",
    "threat-model.html",
    "pentest-tasks.yaml",
    ".threats-merged.json",
    ".merge-candidates.json",
    ".source-auth-findings.json",
    ".config-scan-findings.json",
    ".stride-*.json",
    ".fragments/*.md",
    ".fragments/*.json",
)

_MIN_VALUE_LEN = 8

# A word-shaped value is only recognisable as a credential where it stands in
# an ASSIGNMENT — a credential keyword, an operator, then the value. Proximity
# to a credential keyword is not usable here: a threat model discusses
# authentication on every page, so "…classified by authentication requirement.
# Each row links to the threat(s) referenced…" puts a keyword within a clause
# of ordinary prose. An assignment position cannot occur mid-sentence, so this
# test cannot fire on prose at all.
# ``[ \t]*`` rather than ``\s*`` for the same reason as the scanner's twin
# pattern: an assignment does not span a line break, and a keyword sitting at
# the end of one line would otherwise claim the next line's first token.
_CREDENTIAL_ASSIGNMENT_RE = re.compile(rf"(?i)(?:\b|_)(?:{CREDENTIAL_KEYWORDS})[\"']?[ \t]*[=:][ \t]*[\"']?$")


def _is_word_shaped(value: str) -> bool:
    """Whether ``value`` is indistinguishable from an ordinary word.

    Such a value cannot be replaced safely without looking at each occurrence:
    it carries no token shape, so every sentence that happens to use the word
    matches. Mirrors the scanner's own prose test, so the two agree on what
    "looks like a word" means.
    """
    return bool(_PROSE_WORD_RE.match(value) and _PROSE_VOWEL_RE.search(value))


def _replace_in_credential_context(text: str, value: str, mask: str) -> tuple[str, int]:
    """Replace ``value`` only where it stands as an assigned credential.

    A word-shaped value in running prose is just the word; there is no
    discriminator that separates it from a leak, so this pass does not try and
    covers the one position where the value IS identifiable instead. Bare-prose
    occurrences of such a value are therefore left to the pattern masker, which
    matches the same assignment form.
    """
    out: list[str] = []
    count = 0
    pos = 0
    while True:
        idx = text.find(value, pos)
        if idx == -1:
            break
        # Bounded lookbehind: the operator and keyword sit immediately before
        # the value, so a fixed slice is enough and keeps this linear.
        out.append(text[pos:idx])
        if _CREDENTIAL_ASSIGNMENT_RE.search(text[max(0, idx - 40) : idx]):
            out.append(mask)
            count += 1
        else:
            out.append(value)
        pos = idx + len(value)
    out.append(text[pos:])
    return "".join(out), count


def _masked(value: str) -> str:
    """First 4 chars + ``****`` — carries a masking marker (so the result can
    never be re-flagged) while breaking the reusable secret."""
    head = value[:4] if len(value) > 4 else ""
    return f"{head}**** ({len(value)} chars)"


def collect_source_secrets(repo_root: Path) -> dict[str, str]:
    """Walk the repository source and return ``{raw_value: masked_value}`` for
    every high-confidence secret value found."""
    excludes = scan_excludes.load_excludes()
    cap = scan_excludes.max_file_bytes(excludes)
    secrets: dict[str, str] = {}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root).as_posix()
        if scan_excludes.is_excluded(rel, excludes):
            continue
        # A prior run's own output is not repository source. Structural, because
        # the output directory is user-selectable and backups get any name.
        if scan_excludes.is_assessment_artifact(rel, repo_root):
            continue
        try:
            if path.stat().st_size > cap:
                continue
        except OSError:
            continue
        for hit in scan_file(path):
            value = (hit.value or "").strip()
            if len(value) < _MIN_VALUE_LEN or _value_is_masked(value):
                continue
            secrets.setdefault(value, _masked(value))
    return secrets


# The weakness cluster whose findings name a committed secret; its CWE list is
# data/weakness-classes.yaml, not a copy here.
_SECRET_CLUSTER = "secret_management"
_FINDING_SOURCES = ("threat-model.yaml", ".threats-merged.json")
_STRING_LITERAL_RE = re.compile(r"""(?<![\w])[bBrRuU]{0,2}(["'`])((?:\\.|(?!\1)[^\\\n])+)\1""")
_LITERAL_MIN_LEN = 12
_LITERAL_MIN_ENTROPY = 3.0
# Letters joined by separators read as an identifier, header or module name.
_IDENTIFIER_SHAPED_RE = re.compile(r"^[A-Za-z]+(?:[-_.][A-Za-z]+)*$")


def _shannon_entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _is_secret_shaped_literal(value: str) -> bool:
    """Whether a string literal on a cited line can be a committed secret.

    The line already carries a hardcoded-secret finding, so this only has to
    separate the value from its neighbours on that line: algorithm names,
    encodings, header names, module paths and URLs.
    """
    if len(value) < _LITERAL_MIN_LEN or any(c.isspace() for c in value):
        return False
    if _value_is_masked(value) or _is_word_shaped(value) or _IDENTIFIER_SHAPED_RE.match(value):
        return False
    if "://" in value or value.startswith(("./", "../", "/")):
        return False
    return _shannon_entropy(value) >= _LITERAL_MIN_ENTROPY


def _finding_records(output_dir: Path) -> list[dict]:
    records: list[dict] = []
    for name in _FINDING_SOURCES:
        path = output_dir / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            if name.endswith(".json"):
                data = json.loads(text)
            else:
                import yaml

                data = yaml.safe_load(text)
        except (OSError, ValueError):
            continue
        threats = data.get("threats") if isinstance(data, dict) else None
        records.extend(t for t in threats or [] if isinstance(t, dict))
    return records


def _evidence_locations(threat: dict) -> set[tuple[str, int]]:
    out: set[tuple[str, int]] = set()
    evidence = threat.get("evidence")
    entries = [evidence] if isinstance(evidence, dict) else list(evidence or [])
    entries += list(threat.get("instances") or [])
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        file, line = entry.get("file"), entry.get("line")
        if isinstance(file, str) and file.strip() and isinstance(line, int) and line > 0:
            out.add((file.strip(), line))
    return out


def _source_line(repo_root: Path, rel: str, line_no: int, excludes: dict, cap: int) -> str | None:
    """The cited line, read only from a regular file inside the repository."""
    root = repo_root.resolve()
    try:
        path = (root / rel).resolve()
        path.relative_to(root)
    except (OSError, ValueError):
        return None
    rel_posix = path.relative_to(root).as_posix()
    if scan_excludes.is_excluded(rel_posix, excludes) or scan_excludes.is_assessment_artifact(rel_posix, root):
        return None
    try:
        if not path.is_file() or path.stat().st_size > cap:
            return None
        with path.open(encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh, start=1):
                if idx == line_no:
                    return line
    except OSError:
        return None
    return None


def collect_finding_secrets(repo_root: Path, output_dir: Path) -> dict[str, str]:
    """``{raw_value: masked_value}`` for the secret-shaped string literals at the
    evidence lines of every finding in the secret-management weakness cluster."""
    vocab = load_weakness_classes()
    excludes = scan_excludes.load_excludes()
    cap = scan_excludes.max_file_bytes(excludes)
    secrets: dict[str, str] = {}
    seen: set[tuple[str, int]] = set()
    for threat in _finding_records(output_dir):
        if classify_threat(threat, vocab, warn=False) != _SECRET_CLUSTER:
            continue
        for location in _evidence_locations(threat) - seen:
            seen.add(location)
            line = _source_line(repo_root, location[0], location[1], excludes, cap)
            if line is None:
                continue
            for match in _STRING_LITERAL_RE.finditer(line):
                value = match.group(2)
                if _is_secret_shaped_literal(value):
                    secrets.setdefault(value, _masked(value))
    return secrets


def known_secret_values(repo_root: Path, output_dir: Path) -> dict[str, str]:
    """Every secret value the run knows about: source values in a scanner-matched
    form plus literals the analysis cited as hardcoded secrets. The redaction
    pass and the ``unmasked_secrets`` gate both use this one set."""
    if not repo_root.is_dir():
        return {}
    secrets = collect_source_secrets(repo_root)
    for value, mask in collect_finding_secrets(repo_root, output_dir).items():
        secrets.setdefault(value, mask)
    return secrets


def unmasked_occurrences(text: str, value: str) -> int:
    """How many occurrences of ``value`` the redaction pass would mask in ``text``."""
    if value not in text:
        return 0
    if _is_word_shaped(value):
        return _replace_in_credential_context(text, value, "")[1]
    return text.count(value)


def redact_artifacts(output_dir: Path, secrets: dict[str, str]) -> dict:
    """Replace each known secret value in every artifact. Returns a report."""
    redacted: dict[str, int] = {}
    touched_files: list[str] = []
    seen: set[Path] = set()
    targets: list[Path] = []
    for glob in _ARTIFACT_GLOBS:
        for p in sorted(output_dir.glob(glob)):
            if p.is_file() and p not in seen:
                seen.add(p)
                targets.append(p)

    for path in targets:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        new_text = text
        file_hits = 0
        for value, mask in secrets.items():
            if value not in new_text:
                continue
            if _is_word_shaped(value):
                new_text, count = _replace_in_credential_context(new_text, value, mask)
            else:
                count = new_text.count(value)
                new_text = new_text.replace(value, mask)
            if count:
                redacted[value] = redacted.get(value, 0) + count
                file_hits += count
        if file_hits and new_text != text:
            if path.name == "threat-model.yaml":
                import yaml
                from model.enrichment_pass import EnrichmentContinuation, valid_receipt

                try:
                    before = yaml.safe_load(text)
                    after = yaml.safe_load(new_text)
                    if isinstance(before, dict) and isinstance(after, dict) and valid_receipt(before):
                        EnrichmentContinuation(before).refresh(after)
                        new_text = yaml.safe_dump(after, sort_keys=False, allow_unicode=True, width=120)
                except yaml.YAMLError:
                    pass  # An undecodable artifact cannot acquire a receipt.
            path.write_text(new_text, encoding="utf-8")
            touched_files.append(path.name)

    return {
        "check": "redact_known_secrets",
        "source_secret_values": len(secrets),
        "total_redactions": sum(redacted.values()),
        "files_modified": sorted(set(touched_files)),
        "redacted": [{"value_preview": v[:4] + "…", "length": len(v), "count": n} for v, n in sorted(redacted.items())],
    }


def _residual_scan(output_dir: Path) -> list[str]:
    """Final pattern scan over the published artifacts — confirms the redaction
    left nothing the unmasked-secrets gate would still catch."""
    issues: list[str] = []
    for rel in ("threat-model.md", *PUBLISHED_ARTIFACTS):
        p = output_dir / rel
        if not p.is_file():
            continue
        try:
            for hit in scan_text(p.read_text(encoding="utf-8", errors="replace")):
                issues.append(f"{p.name}: {hit.render()}")
        except OSError:
            continue
    return issues


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Exact-value secret redaction over rendered artifacts.")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument(
        "--write-scan-json",
        action="store_true",
        help="Also write .qa-secret-scan.json with the post-redaction residual scan.",
    )
    a = ap.parse_args(argv)
    repo_root = Path(a.repo_root)
    output_dir = Path(a.output_dir)
    if not output_dir.is_dir():
        sys.stderr.write(f"redact_known_secrets: no output dir {output_dir} — skipping\n")
        return 0

    secrets = known_secret_values(repo_root, output_dir)
    report = redact_artifacts(output_dir, secrets)
    (output_dir / ".secret-redaction.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    residual = _residual_scan(output_dir)
    if a.write_scan_json:
        (output_dir / ".qa-secret-scan.json").write_text(
            json.dumps(
                {
                    "check": "unmasked_secrets",
                    "ok": 1 if not residual else 0,
                    "issue_count": len(residual),
                    "issues": residual,
                    "redaction": report,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    if report["total_redactions"]:
        sys.stderr.write(
            f"redact_known_secrets: redacted {report['total_redactions']} occurrence(s) of "
            f"{len(report['redacted'])} secret value(s) across {len(report['files_modified'])} file(s)\n"
        )
    # Fail closed only if a residual raw secret survived (should never happen
    # after exact-value redaction, but the gate must not pass a leak silently).
    return 2 if residual else 0


if __name__ == "__main__":
    sys.exit(main())
