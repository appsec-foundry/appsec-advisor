#!/usr/bin/env python3
"""Source-preserving inline-code recognition for rendered threat-model prose.

This module owns the syntax-aware part of inline-code formatting.  It does not
render Markdown and it never rewrites an existing Markdown construct.  Instead
it identifies complete code expressions in plain-text runs and returns the same
bytes with only the necessary backtick delimiters inserted.

The recognizer is intentionally evidence-led:

* balanced calls, member chains, subscripts, paths, assignments, command-line
  flags, payload literals, regexes, and globs carry structural code evidence;
* ambiguous package names are formatted only when a repository manifest or a
  validated structured artifact names them;
* existing code spans, links, HTML, and other opaque Markdown regions are left
  byte-for-byte unchanged.

Callers that operate on a full report remain responsible for block context
(fences, headings, and raw-HTML table cells).  ``apply_prose_fixes`` is the
single document-level owner and delegates every plain-text run here.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Iterator


@dataclass(frozen=True, slots=True)
class CodeCandidate:
    """One unformatted code-shaped span in a plain-text Markdown run."""

    start: int
    end: int
    text: str
    kind: str
    priority: int


@dataclass(slots=True)
class MarkdownScanState:
    """Track block constructs whose contents are not report prose."""

    fence_char: str = ""
    fence_length: int = 0
    raw_tag: str = ""
    in_comment: bool = False

    def scannable(self, line: str) -> bool:
        """Return whether ``line`` may contain prose candidates and advance state."""

        stripped = line.lstrip()
        if self.in_comment:
            if "-->" in line:
                self.in_comment = False
            return False
        if "<!--" in line and "-->" not in line.split("<!--", 1)[1]:
            self.in_comment = True
            return False
        fence = re.match(r"(`{3,}|~{3,})(.*)$", stripped)
        if self.fence_char:
            if (
                fence
                and fence.group(1)[0] == self.fence_char
                and len(fence.group(1)) >= self.fence_length
                and not fence.group(2).strip()
            ):
                self.fence_char = ""
                self.fence_length = 0
            return False
        if fence:
            self.fence_char = fence.group(1)[0]
            self.fence_length = len(fence.group(1))
            return False
        if self.raw_tag:
            if re.search(rf"</\s*{re.escape(self.raw_tag)}\s*>", line, re.IGNORECASE):
                self.raw_tag = ""
            return False
        raw_open = re.search(r"<\s*(details|pre|code)\b", line, re.IGNORECASE)
        if raw_open:
            tag = raw_open.group(1).casefold()
            if not re.search(rf"</\s*{tag}\s*>", line[raw_open.end() :], re.IGNORECASE):
                self.raw_tag = tag
            return False
        if re.match(r"^\s{0,3}#{1,6}\s", line):
            return False
        return True


_IDENT_HEAD_RE = re.compile(r"(?<![\w`])(?:[A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)*")
_CAMEL_RE = re.compile(r"(?<![\w`])(?P<token>[a-z][a-z0-9]+[A-Z][A-Za-z0-9]*)(?![\w`])")
_DOTTED_RE = re.compile(r"(?<![\w`/])(?P<token>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)(?![\w`(]|\.\w)")
_SNAKE_RE = re.compile(
    r"(?<![\w`./$-])(?P<token>__\w+__|(?:[a-z][a-z0-9]*\.)?[a-z][a-z0-9]*(?:_[a-z0-9]+)+|"
    r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)(?![\w`/(])"
)
_FILE_RE = re.compile(
    r"(?<![\w`/@-])(?P<token>\.?[A-Za-z0-9_@-][\w.@+-]*(?:[/\\][\w.@+-]+)*"
    r"\.(?:bak|bash|c|cc|conf|cpp|crt|cs|css|csv|env|go|h|hpp|html|ini|java|js|json|jsx|kdbx|key|"
    r"kt|lock|md|mjs|p12|pem|php|properties|ps1|pub|py|rb|rs|scala|scss|sh|sql|swift|toml|ts|tsx|"
    r"xml|yaml|yml)"
    r"(?::\d+(?:-\d+)?)?)(?![\w/`])",
    re.IGNORECASE,
)
_EXTENSIONLESS_FILE_RE = re.compile(
    r"(?<![\w`./-])(?P<token>(?:(?:[\w.-]+/)+)?(?:Dockerfile|Containerfile|Makefile|Jenkinsfile|"
    r"Gemfile|Procfile|Rakefile|Vagrantfile|Brewfile)(?::\d+(?:-\d+)?)?)(?![\w/`])"
)
_URL_RE = re.compile(r"(?<![\w`/])(?P<token>(?:https?|ftp|file|ws|wss)://[^\s`<>\"'()\[\]]+)")
_IPV4_PART = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IP_RE = re.compile(
    r"(?<![\w`.:/-])(?P<token>"
    + _IPV4_PART
    + r"(?:\."
    + _IPV4_PART
    + r"){3}(?::\d{1,5})?(?:/\d{1,2})?|\[[0-9A-Fa-f:]+\](?::\d{1,5})?)(?![\w`])"
)
_SCOPED_PACKAGE_RE = re.compile(
    r"(?<![\w.@-])(?P<token>@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*(?:@\d[\w.+-]*)?)(?![\w/`])"
)
_VERSIONED_PACKAGE_RE = re.compile(r"(?<![\w`/@])(?P<token>[a-z][a-z0-9._-]*@\d[\w.+-]*)(?![\w`])", re.IGNORECASE)
_CLI_FLAG_RE = re.compile(r"(?<![\w`-])(?P<token>--[a-z0-9][a-z0-9-]*(?:=[^\s`,;]+)?)(?![\w`])", re.I)
_CONFIG_RE = re.compile(
    r"(?<![\w`.-])(?P<token>(?:"
    r"[a-z][a-z0-9_.-]*=[A-Za-z0-9_.+-]+"
    r"|SameSite\s*=\s*[A-Za-z0-9_.+-]+"
    r"|(?:alg|role|noent|multi|method):(?:[A-Za-z_][A-Za-z0-9_.+-]*|\d+)"
    r"|[a-z][a-z0-9_.-]*\s*:\s*(?:true|false|null|none)"
    r"|(?:[a-z][A-Za-z0-9]*[A-Z][A-Za-z0-9]*|[a-z][a-z0-9]*(?:[_.-][a-z0-9]+)+)"
    r"\s*:\s*(?:[A-Za-z_][A-Za-z0-9_.+-]*|\d+)"
    r"))(?!://)(?![\w`])"
)
_GLOB_RE = re.compile(r"(?<![\w`])(?P<token>(?:\.?[\w.-]+/)+[\w./-]*[*?][\w*/?.-]*)(?![\w`])")
_REGEX_RE = re.compile(r"(?<![\w`])(?P<token>\^(?=[^\s`]{3,80}\$)[^\s`]+\$)(?![\w`])")
_ABSOLUTE_PATH_RE = re.compile(r"(?<![\w`/<])(?P<token>/[A-Za-z][\w%:@=+.-]{2,}(?:/[\w%:@=+.*?{}-]+)*/?)(?![\w/`>])")
_CVE_RE = re.compile(r"(?<![\w`-])(?P<token>CVE-\d{4}-\d{4,7})(?![\w`])")
_SECURITY_ALGORITHM_RE = re.compile(
    r"(?<![\w`:/-])(?P<token>MD[45]|SHA-?(?:1|224|256|384|512)|(?:HS|RS|ES|PS)(?:256|384|512))(?![\w`])"
)
_SQL_FRAGMENT_RE = re.compile(
    r"(?<![\w`])(?P<token>(?:UNION\s+)?SELECT\b.{0,100}?\b[Ff][Rr][Oo][Mm]\s+[A-Za-z_][\w.]*"
    r"|INSERT\s+INTO\s+[A-Za-z_][\w.]*|UPDATE\s+[A-Za-z_][\w.]*\s+SET\s+[A-Za-z_][\w.]*"
    r"|DELETE\s+FROM\s+[A-Za-z_][\w.]*)(?![\w`])"
)
_ANGLE_PLACEHOLDER_RE = re.compile(r"(?<![\w`<])(?P<token><[a-z][a-z0-9_-]*>)(?![\w`])")
_BACKTICK_CONTENT_RE = re.compile(r"`([^`\n]+)`")
_LINKED_TITLE_TAIL_RE = re.compile(r"\]\(#(?:f|t|m|th)-\d+\)\s*[—–-]\s[^\n|]*?(?=<br/?>|\||$)")

# Single-word protocol identifiers are otherwise indistinguishable from prose.
# This is a protocol vocabulary, not a product/application allow-list.
_PROTOCOL_IDENTIFIERS = frozenset(
    {
        "Authorization",
        "Cookie",
        "ETag",
        "Origin",
        "Referer",
        "SameSite",
        "Set-Cookie",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "Content-Type",
        "Content-Length",
        "X-Content-Type-Options",
        "X-Frame-Options",
    }
)

_TRAILING_PUNCTUATION = ".,;:!?"
_MAX_KNOWN_TOKENS = 512
_MAX_KNOWN_TOKEN_LENGTH = 160
_OPTIONAL_PLURAL_ARGUMENTS = frozenset({"s", "es", "ies"})
_DOMAIN_SUFFIXES = frozenset({"ai", "app", "co", "com", "dev", "gg", "io", "js", "net", "org", "xyz"})
_CODE_OBJECT_HEADS = frozenset({"ctx", "document", "lib", "Object", "process", "req", "res", "self", "this", "window"})
_HTML_ELEMENTS = frozenset(
    "a abbr b blockquote br code col colgroup dd details div dl dt em h1 h2 h3 h4 h5 h6 hr i img "
    "li ol p pre q s small span strong sub summary sup table tbody td tfoot th thead tr u ul".split()
)


def _consume_quoted(text: str, start: int) -> int | None:
    quote = text[start]
    escaped = False
    for index in range(start + 1, len(text)):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index + 1
    return None


def _consume_balanced(text: str, start: int) -> int | None:
    """Return the end of one balanced ``()``, ``[]``, or ``{}`` group."""

    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = text[start]
    if opener not in pairs:
        return None
    stack = [pairs[opener]]
    index = start + 1
    while index < len(text):
        char = text[index]
        if char in "'\"":
            quoted_end = _consume_quoted(text, index)
            if quoted_end is None:
                return None
            index = quoted_end
            continue
        if char in pairs:
            stack.append(pairs[char])
        elif char in ")]}":
            if not stack or char != stack[-1]:
                return None
            stack.pop()
            if not stack:
                return index + 1
        index += 1
    return None


def _consume_expression_tail(text: str, start: int) -> int:
    """Consume chained calls, subscripts, and member accesses atomically."""

    index = start
    while index < len(text):
        if text[index] in "([":
            end = _consume_balanced(text, index)
            if end is None:
                return start
            index = end
            continue
        member = re.match(r"\??\.[A-Za-z_$][\w$]*", text[index:])
        if member:
            index += member.end()
            continue
        break
    return index


def _looks_like_code_call(head: str, expression: str) -> bool:
    first_open = expression.find("(")
    if first_open < 0:
        return False
    first_end = _consume_balanced(expression, first_open)
    if first_end is None:
        return False
    inner = expression[first_open + 1 : first_end - 1].strip()
    if head in {"_", "$"}:
        return False
    if "." in head or "_" in head or "$" in head or re.search(r"[a-z][A-Z]", head):
        return True
    if inner.casefold() in _OPTIONAL_PLURAL_ARGUMENTS:
        return False
    # An identifier immediately followed by balanced parentheses is code unless
    # it is the narrow optional-plural prose shape rejected above.
    return bool(re.fullmatch(r"[A-Za-z_$][\w$]*", head))


def _expression_candidates(text: str) -> Iterator[CodeCandidate]:
    for match in _IDENT_HEAD_RE.finditer(text):
        head = match.group(0)
        end = _consume_expression_tail(text, match.end())
        if end == match.end():
            continue
        expression = text[match.start() : end]
        if "(" in expression:
            if _looks_like_code_call(head, expression):
                yield CodeCandidate(match.start(), end, expression, "expression", 100)
            continue
        if "[" in expression and ("." in head or "_" in head or re.search(r"[a-z][A-Z]", head)):
            yield CodeCandidate(match.start(), end, expression, "subscript", 95)


def _compound_literal_candidates(text: str) -> Iterator[CodeCandidate]:
    """Yield complete object and quoted payload literals before inner tokens."""

    for index, char in enumerate(text):
        if char == "{":
            end = _consume_balanced(text, index)
            if end is None:
                continue
            literal = text[index:end]
            if re.search(r"(?:['\"][\w.$-]+['\"]\s*:|\\?\$\w+\s*:)", literal):
                yield CodeCandidate(index, end, literal.replace("\\$", "$"), "object", 98)
        elif char in "'\"":
            end = _consume_quoted(text, index)
            if end is None:
                continue
            literal = text[index:end]
            inner = literal[1:-1]
            sql_keywords = {
                match.group(0).casefold()
                for match in re.finditer(
                    r"\b(?:select|insert|update|delete|union|from|where|join|into|values|set)\b",
                    inner,
                    re.IGNORECASE,
                )
            }
            if (
                re.search(r"https?://|\b(?:curl|wget|npm|git|python3?)\s", inner, re.IGNORECASE)
                or len(sql_keywords) >= 2
            ):
                yield CodeCandidate(index, end, literal, "literal", 97)


def _opaque_ranges(text: str) -> list[tuple[int, int]]:
    """Locate Markdown constructs whose bytes the formatter must not edit."""

    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        if text.startswith("<!--", index):
            end = text.find("-->", index + 4)
            end = len(text) if end < 0 else end + 3
            ranges.append((index, end))
            index = end
            continue
        if text[index] == "`":
            run = 1
            while index + run < len(text) and text[index + run] == "`":
                run += 1
            delimiter = "`" * run
            end = text.find(delimiter, index + run)
            end = len(text) if end < 0 else end + run
            ranges.append((index, end))
            index = end
            continue
        if text[index] == "<":
            placeholder = _ANGLE_PLACEHOLDER_RE.match(text, index)
            if placeholder and placeholder.group("token")[1:-1] not in _HTML_ELEMENTS:
                index += 1
                continue
            quote: str | None = None
            cursor = index + 1
            while cursor < len(text):
                char = text[cursor]
                if quote:
                    if char == quote and text[cursor - 1] != "\\":
                        quote = None
                elif char in "'\"":
                    quote = char
                elif char == ">":
                    cursor += 1
                    break
                cursor += 1
            if cursor <= len(text) and cursor > index + 1:
                opening = text[index:cursor]
                tag_match = re.match(r"<\s*(code|pre|details)\b", opening, re.IGNORECASE)
                if tag_match:
                    closing = re.search(rf"</\s*{tag_match.group(1)}\s*>", text[cursor:], re.IGNORECASE)
                    if closing:
                        cursor += closing.end()
                ranges.append((index, cursor))
                index = cursor
                continue
        label_start = index
        if text.startswith("![", index):
            label_start += 1
        if text[label_start : label_start + 1] == "[":
            label_end = text.find("](", label_start + 1)
            if label_end >= 0:
                target_end = _consume_balanced(text, label_end + 1)
                if target_end is not None:
                    ranges.append((index, target_end))
                    index = target_end
                    continue
        index += 1
    return ranges


def _overlaps(ranges: Iterable[tuple[int, int]], start: int, end: int) -> bool:
    return any(start < range_end and end > range_start for range_start, range_end in ranges)


def _regex_candidates(text: str, known_tokens: frozenset[str]) -> Iterator[CodeCandidate]:
    patterns: tuple[tuple[re.Pattern[str], str, int], ...] = (
        (_URL_RE, "url", 90),
        (_IP_RE, "ip", 88),
        (_SCOPED_PACKAGE_RE, "package", 86),
        (_VERSIONED_PACKAGE_RE, "package", 85),
        (_FILE_RE, "file", 84),
        (_EXTENSIONLESS_FILE_RE, "file", 83),
        (_ABSOLUTE_PATH_RE, "path", 82),
        (_CONFIG_RE, "config", 80),
        (_CLI_FLAG_RE, "flag", 78),
        (_REGEX_RE, "regex", 76),
        (_GLOB_RE, "glob", 75),
        (_SNAKE_RE, "identifier", 70),
        (_CAMEL_RE, "identifier", 68),
        (_CVE_RE, "identifier", 64),
        (_SECURITY_ALGORITHM_RE, "identifier", 63),
        (_SQL_FRAGMENT_RE, "expression", 96),
        (_ANGLE_PLACEHOLDER_RE, "placeholder", 62),
    )
    for pattern, kind, priority in patterns:
        for match in pattern.finditer(text):
            token = match.group("token")
            if kind == "file" and "/" not in token and "\\" not in token and ":" not in token:
                stem, _, extension = token.partition(".")
                if extension.casefold() in {"js", "jsx", "mjs", "cjs"} and re.fullmatch(r"[A-Z][A-Za-z0-9]*", stem):
                    continue
            end = match.end("token")
            while token and token[-1] in _TRAILING_PUNCTUATION:
                token = token[:-1]
                end -= 1
            if token:
                yield CodeCandidate(match.start("token"), end, token, kind, priority)

    for match in _DOTTED_RE.finditer(text):
        token = match.group("token")
        if token.endswith("._"):
            continue
        parts = token.split(".")
        if all(len(part) == 1 for part in parts):
            continue
        if parts[-1].casefold() in _DOMAIN_SUFFIXES and parts[0] not in _CODE_OBJECT_HEADS:
            continue
        yield CodeCandidate(match.start("token"), match.end("token"), token, "identifier", 89)

    evidence_tokens = sorted(
        known_tokens - _PROTOCOL_IDENTIFIERS,
        key=lambda item: (-len(item), item),
    )[: _MAX_KNOWN_TOKENS - len(_PROTOCOL_IDENTIFIERS)]
    search_tokens = tuple(sorted((*_PROTOCOL_IDENTIFIERS, *evidence_tokens), key=lambda item: (-len(item), item)))
    known_pattern = _known_token_pattern(search_tokens)
    if known_pattern is not None:
        for match in known_pattern.finditer(text):
            yield CodeCandidate(match.start(), match.end(), match.group(0), "known", 110)


@lru_cache(maxsize=16)
def _known_token_pattern(tokens: tuple[str, ...]) -> re.Pattern[str] | None:
    """Compile one bounded alternation for evidence-backed identifiers."""

    safe = tuple(
        token
        for token in tokens
        if 0 < len(token) <= _MAX_KNOWN_TOKEN_LENGTH and "`" not in token and "\n" not in token
    )
    if not safe:
        return None
    return re.compile(r"(?<![\w.@/+:-])(?:" + "|".join(re.escape(token) for token in safe) + r")(?![\w.@/+:-])")


def candidates(text: str, known_tokens: Iterable[str] = ()) -> list[CodeCandidate]:
    """Return non-overlapping code candidates outside opaque Markdown."""

    if not text:
        return []
    opaque = _opaque_ranges(text)
    title_tails = [(match.start(), match.end()) for match in _LINKED_TITLE_TAIL_RE.finditer(text)]
    known = frozenset(
        token for token in known_tokens if isinstance(token, str) and 0 < len(token) <= _MAX_KNOWN_TOKEN_LENGTH
    )
    found = [*_compound_literal_candidates(text), *_expression_candidates(text), *_regex_candidates(text, known)]
    visible: list[CodeCandidate] = []
    for item in found:
        overlaps = [(start, end) for start, end in opaque if item.start < end and item.end > start]
        if not overlaps:
            visible.append(item)
            continue
        # An authored span inside a larger balanced call is a partial-format
        # defect, not an opaque region. Claim the complete expression and drop
        # only the delimiters contained by it. Links and HTML stay opaque.
        if item.kind == "expression" and all(
            item.start <= start
            and end <= item.end
            and text[start:end].startswith("`")
            and text[start:end].endswith("`")
            for start, end in overlaps
        ):
            visible.append(CodeCandidate(item.start, item.end, item.text.replace("`", ""), item.kind, item.priority))
    found = visible
    found = [
        item
        for item in found
        if not (
            item.kind != "literal"
            and item.start > 0
            and item.end < len(text)
            and text[item.start - 1] in "'\""
            and text[item.end] == text[item.start - 1]
        )
    ]
    # Linked finding/mitigation tails are titles. Keep semantic labels such as
    # "MD5 hashing" plain, but still format concrete source locations and
    # complete call expressions embedded in the title.
    title_safe_kinds = frozenset({"expression", "subscript", "file", "path", "url", "ip"})
    found = [
        item for item in found if not _overlaps(title_tails, item.start, item.end) or item.kind in title_safe_kinds
    ]
    # At the same start offset the complete expression wins over a known inner
    # token (``SameSite=Strict`` must not become ``SameSite`=Strict``).
    found.sort(key=lambda item: (item.start, -(item.end - item.start), -item.priority))

    selected: list[CodeCandidate] = []
    for item in found:
        if selected and item.start < selected[-1].end:
            continue
        selected.append(item)
    return selected


def format_inline_code(text: str, known_tokens: Iterable[str] = ()) -> tuple[str, int]:
    """Backtick complete code candidates without changing other bytes."""

    selected = candidates(text, known_tokens)
    if not selected:
        return text, 0
    output: list[str] = []
    cursor = 0
    for item in selected:
        output.append(text[cursor : item.start])
        output.append(f"`{item.text}`")
        cursor = item.end
    output.append(text[cursor:])
    return "".join(output), len(selected)


def _dependency_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)", requirement)
    return match.group(1).split("[", 1)[0] if match else ""


def _manifest_tokens(path: Path) -> set[str]:
    tokens: set[str] = set()
    try:
        if path.stat().st_size > 1_000_000:
            return tokens
        if path.name == "package.json":
            data = json.loads(path.read_text(encoding="utf-8"))
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                value = data.get(key) if isinstance(data, dict) else None
                if isinstance(value, dict):
                    tokens.update(name for name in value if isinstance(name, str))
        elif path.name == "pyproject.toml":
            text = path.read_text(encoding="utf-8")
            # Python 3.10 is the supported floor, so avoid a runtime dependency
            # on tomllib/tomli for this advisory vocabulary.  Project arrays
            # and Poetry dependency tables have deliberately simple, bounded
            # extraction rules; malformed TOML merely contributes no token.
            for match in re.finditer(r"(?ms)^dependencies\s*=\s*\[(.*?)^\]", text):
                for quoted in re.findall(r"['\"]([^'\"]+)['\"]", match.group(1)):
                    if name := _dependency_name(quoted):
                        tokens.add(name)
            poetry = re.search(r"(?ms)^\[tool\.poetry\.dependencies\]\s*$\n(.*?)(?=^\[|\Z)", text)
            if poetry:
                for name in re.findall(r"(?m)^\s*([A-Za-z0-9_.-]+)\s*=", poetry.group(1)):
                    if name.lower() != "python":
                        tokens.add(name)
        elif path.name in {"Cargo.toml", "Pipfile"}:
            text = path.read_text(encoding="utf-8")
            section_names = r"dependencies|dev-dependencies|build-dependencies|packages|dev-packages"
            for section in re.finditer(rf"(?ms)^\[(?:{section_names})\]\s*$\n(.*?)(?=^\[|\Z)", text):
                tokens.update(re.findall(r"(?m)^\s*([A-Za-z0-9_.-]+)\s*=", section.group(1)))
        elif path.name.startswith("requirements") and path.suffix == ".txt":
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.lstrip().startswith(("#", "-")):
                    continue
                if name := _dependency_name(line):
                    tokens.add(name)
    except (OSError, UnicodeError, ValueError, TypeError):
        return set()
    return tokens


def repository_vocabulary(
    repo_root: Path,
    *,
    max_manifests: int = 100,
    max_entries: int = 20_000,
) -> frozenset[str]:
    """Read dependency manifests without following links or walking forever."""

    try:
        root = repo_root.resolve(strict=True)
    except OSError:
        return frozenset()
    names = {"package.json", "pyproject.toml", "Cargo.toml", "Pipfile"}
    manifest_paths: list[Path] = []
    entries_seen = 0
    try:
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(directory)
            remaining = max_entries - entries_seen
            if remaining <= 0:
                break
            safe_directories = sorted(name for name in dirnames if not (base / name).is_symlink())[:remaining]
            dirnames[:] = safe_directories
            entries_seen += len(safe_directories)
            for filename in sorted(filenames):
                entries_seen += 1
                if entries_seen > max_entries or len(manifest_paths) >= max_manifests:
                    break
                path = base / filename
                if path.is_symlink():
                    continue
                if path.name not in names and not (path.name.startswith("requirements") and path.suffix == ".txt"):
                    continue
                try:
                    path.resolve(strict=True).relative_to(root)
                except (OSError, ValueError):
                    continue
                manifest_paths.append(path)
            if entries_seen > max_entries or len(manifest_paths) >= max_manifests:
                break
    except OSError:
        pass
    tokens: set[str] = set()
    for path in manifest_paths:
        tokens.update(_manifest_tokens(path))
    return frozenset(sorted(tokens, key=lambda item: (-len(item), item))[:_MAX_KNOWN_TOKENS])


_STRUCTURED_CODE_KEYS = frozenset(
    {
        "code",
        "code_example",
        "excerpt",
        "file",
        "filename",
        "path",
        "review_target",
        "snippet",
        "source_file",
    }
)


def structured_vocabulary(value: Any) -> frozenset[str]:
    """Extract explicit code tokens from code-bearing structured fields."""

    tokens: set[str] = set()

    def visit(node: Any, key: str = "") -> None:
        if isinstance(node, dict):
            for child_key, child in node.items():
                visit(child, str(child_key))
            return
        if isinstance(node, list):
            for child in node:
                visit(child, key)
            return
        if not isinstance(node, str):
            return
        tokens.update(match.group(1) for match in _BACKTICK_CONTENT_RE.finditer(node))
        if key in _STRUCTURED_CODE_KEYS:
            if "\n" not in node and 0 < len(node) <= 240:
                tokens.add(node.strip())
            tokens.update(item.text for item in candidates(node))

    visit(value)
    return frozenset(token for token in tokens if token)
