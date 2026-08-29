"""Contract and property tests for the canonical inline-code recognizer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import inline_code_formatter as formatter  # noqa: E402


def _format(token: str, *, known_tokens: tuple[str, ...] = ()) -> str:
    return formatter.format_inline_code(f"The report references {token} here.", known_tokens)[0]


def test_rule_6_code_matrix_formats_complete_tokens() -> None:
    required = (
        "eval()",
        "bypassSecurityTrustHtml()",
        "vm.runInContext(safeEval())",
        "models.sequelize.query()",
        "req.body.email",
        "process.env.SECRET_KEY",
        "Object.assign",
        "lib.insecurity.signToken",
        "routes/login.ts",
        "routes/login.ts:34",
        "lib/insecurity.ts",
        "frontend/src/app/about/about.component.ts",
        "package.json",
        "sanitize-html@1.4.2",
        "noent: true",
        "SameSite=Strict",
        "Authorization",
        "Content-Security-Policy",
        r"^F-\d{3}$",
        "routes/**",
    )
    for token in required:
        assert f"`{token}`" in _format(token), token


def test_ambiguous_packages_require_repository_evidence() -> None:
    source = "Replace express-jwt and libxmljs2 here."
    plain, _ = formatter.format_inline_code(source)
    evidenced, _ = formatter.format_inline_code(source, {"express-jwt", "libxmljs2"})
    assert "`express-jwt`" not in plain
    assert "`express-jwt`" in evidenced
    assert "`libxmljs2`" in evidenced


def test_balanced_expression_never_swallows_trailing_prose() -> None:
    source = "Use vm.runInContext(safeEval()) here."
    output, changes = formatter.format_inline_code(source)
    assert output == "Use `vm.runInContext(safeEval())` here."
    assert changes == 1


def test_chained_expression_is_one_span() -> None:
    source = "Use crypto.createHash('md5').update(secret).digest('hex') here."
    output, _ = formatter.format_inline_code(source)
    assert output == "Use `crypto.createHash('md5').update(secret).digest('hex')` here."


def test_partial_authored_span_is_repaired_as_one_expression() -> None:
    source = "Use notifications.forEach((item) => { `socket.emit('ready', item)` }) here."
    output, changes = formatter.format_inline_code(source)
    assert output == "Use `notifications.forEach((item) => { socket.emit('ready', item) })` here."
    assert changes == 1


def test_existing_markdown_constructs_are_byte_preserved() -> None:
    source = "See [`routes/x.ts`](https://example.com/routes/x.ts) and <code>req.body</code>."
    output, changes = formatter.format_inline_code(source)
    assert output == source
    assert changes == 0


def test_markdown_state_skips_fences_headings_and_multiline_raw_code() -> None:
    lines = [
        "# routes/x.ts",
        "~~~python",
        "routes/x.ts",
        "~~~",
        "<details>",
        "routes/y.ts",
        "</details>",
        "routes/z.ts",
    ]
    state = formatter.MarkdownScanState()
    assert [state.scannable(line) for line in lines] == [False, False, False, False, False, False, False, True]


def test_formatter_is_idempotent() -> None:
    source = "Use vm.runInContext(safeEval()), req.body.email, and routes/x.ts:4."
    once, first = formatter.format_inline_code(source)
    twice, second = formatter.format_inline_code(once)
    assert first == 3
    assert second == 0
    assert twice == once


def test_optional_plural_is_not_a_call() -> None:
    source = "The report contains finding(s) and weakness(es)."
    output, changes = formatter.format_inline_code(source)
    assert output == source
    assert changes == 0


def test_markdown_emphasis_placeholder_is_not_a_call() -> None:
    source = "| Baseline | _(initial)_ |"
    output, changes = formatter.format_inline_code(source)
    assert output == source
    assert changes == 0


def test_repository_vocabulary_reads_manifest_dependencies(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express-jwt": "1.0.0", "@scope/pkg": "2.0.0"}}), encoding="utf-8"
    )
    assert formatter.repository_vocabulary(tmp_path) == frozenset({"express-jwt", "@scope/pkg"})


def test_repository_vocabulary_rejects_escaping_symlink(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-package.json"
    outside.write_text(json.dumps({"dependencies": {"not-admitted": "1"}}), encoding="utf-8")
    (tmp_path / "package.json").symlink_to(outside)
    assert "not-admitted" not in formatter.repository_vocabulary(tmp_path)


def test_structured_vocabulary_uses_only_code_bearing_fields() -> None:
    data = {
        "scenario": "ordinary prose mentions not-a-package",
        "evidence": {"file": "routes/x.ts:4", "snippet": "return req.body.email"},
        "verification": "Run `npm audit --omit=dev`.",
    }
    vocabulary = formatter.structured_vocabulary(data)
    assert "routes/x.ts:4" in vocabulary
    assert "req.body.email" in vocabulary
    assert "npm audit --omit=dev" in vocabulary
    assert "not-a-package" not in vocabulary
