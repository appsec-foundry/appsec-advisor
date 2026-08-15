"""Tests for scripts/load_business_context.py."""

from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import load_business_context as lbc  # noqa: E402
from _url_guard import ValidationResult  # noqa: E402


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    return repo


def _output(tmp_path: Path) -> Path:
    output = tmp_path / "output"
    output.mkdir()
    return output


def _source(tmp_path: Path, text: str = "Payments are revenue critical.\n") -> Path:
    path = tmp_path / "context-source.md"
    path.write_text(text, encoding="utf-8")
    return path


class _FakeResponse:
    def __init__(self, payload: bytes, content_type: str) -> None:
        self._payload = payload
        self.headers = {"Content-Type": content_type}

    def read(self, size: int) -> bytes:
        return self._payload[:size]


class _FakeOpener:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    @contextmanager
    def open(self, _request, timeout=None):  # noqa: A003, ARG002
        yield self._response


def _serve(monkeypatch, payload: bytes, content_type: str = "text/markdown") -> None:
    monkeypatch.setattr(lbc, "validate_target_url", lambda *_a, **_k: ValidationResult(True, "ok", "203.0.113.7"))
    monkeypatch.setattr(lbc, "validated_opener", lambda *_a, **_k: _FakeOpener(_FakeResponse(payload, content_type)))


def test_persists_captured_context_with_provenance(tmp_path):
    repo, output = _repo(tmp_path), _output(tmp_path)

    receipt = lbc.capture(repo_root=repo, output_dir=output, source=str(_source(tmp_path)), persist=True)

    target = repo / lbc.REPO_RELATIVE
    text = target.read_text(encoding="utf-8")
    assert text.startswith("<!-- appsec-advisor: business context captured ")
    assert "Payments are revenue critical." in text
    assert receipt["persisted"] is True
    assert receipt["source_kind"] == "file"


def test_refuses_to_overwrite_an_existing_context_file_without_replace(tmp_path):
    repo, output = _repo(tmp_path), _output(tmp_path)
    existing = repo / lbc.REPO_RELATIVE
    existing.write_text("Team-authored context.\n", encoding="utf-8")

    with pytest.raises(lbc.BusinessContextError, match="already exists"):
        lbc.capture(repo_root=repo, output_dir=output, source=str(_source(tmp_path)), persist=True)
    assert existing.read_text(encoding="utf-8") == "Team-authored context.\n"

    lbc.capture(repo_root=repo, output_dir=output, source=str(_source(tmp_path)), persist=True, replace=True)
    assert "Payments are revenue critical." in existing.read_text(encoding="utf-8")


def test_run_only_capture_stays_out_of_the_repository(tmp_path):
    repo, output = _repo(tmp_path), _output(tmp_path)

    receipt = lbc.capture(repo_root=repo, output_dir=output, source=str(_source(tmp_path)), persist=False)

    assert not (repo / lbc.REPO_RELATIVE).exists()
    assert (output / lbc.RUN_ONLY_NAME).is_file()
    assert receipt["persisted"] is False


def test_rejects_a_source_carrying_a_credential(tmp_path):
    repo, output = _repo(tmp_path), _output(tmp_path)
    source = _source(tmp_path, 'Deploy notes.\naws_key = "AKIAIOSFODNN7EXAMPLE"\n')

    with pytest.raises(lbc.BusinessContextError, match="credential"):
        lbc.capture(repo_root=repo, output_dir=output, source=str(source), persist=True)
    assert not (repo / lbc.REPO_RELATIVE).exists()


def test_rejects_an_empty_source(tmp_path):
    repo, output = _repo(tmp_path), _output(tmp_path)

    with pytest.raises(lbc.BusinessContextError, match="empty"):
        lbc.capture(repo_root=repo, output_dir=output, source=str(_source(tmp_path, "\n \n")), persist=True)


def test_rejects_an_oversized_source(tmp_path):
    repo, output = _repo(tmp_path), _output(tmp_path)
    source = _source(tmp_path, "x" * (lbc.MAX_BYTES + 10))

    with pytest.raises(lbc.BusinessContextError, match="byte cap"):
        lbc.capture(repo_root=repo, output_dir=output, source=str(source), persist=True)


def test_refuses_to_write_through_a_symlinked_context_file(tmp_path):
    repo, output = _repo(tmp_path), _output(tmp_path)
    outside = tmp_path / "outside.md"
    outside.write_text("untouched\n", encoding="utf-8")
    (repo / lbc.REPO_RELATIVE).symlink_to(outside)

    with pytest.raises(lbc.BusinessContextError, match="symlink"):
        lbc.capture(repo_root=repo, output_dir=output, source=str(_source(tmp_path)), persist=True)
    assert outside.read_text(encoding="utf-8") == "untouched\n"


def test_url_source_is_policy_validated(tmp_path, monkeypatch):
    repo, output = _repo(tmp_path), _output(tmp_path)
    monkeypatch.setattr(
        lbc,
        "validate_target_url",
        lambda *_a, **_k: ValidationResult(False, "host 'wiki.internal' resolves to 10.0.0.5 (private)", None),
    )

    with pytest.raises(lbc.BusinessContextError, match="rejected by policy"):
        lbc.capture(repo_root=repo, output_dir=output, source="https://wiki.internal/ctx", persist=True)


def test_url_source_is_fetched_and_persisted(tmp_path, monkeypatch):
    repo, output = _repo(tmp_path), _output(tmp_path)
    _serve(monkeypatch, b"# Context\n\nCheckout handles card data.\n")

    receipt = lbc.capture(repo_root=repo, output_dir=output, source="https://ctx.example.test/a.md", persist=True)

    assert receipt["source_kind"] == "url"
    text = (repo / lbc.REPO_RELATIVE).read_text(encoding="utf-8")
    assert "Checkout handles card data." in text
    assert "https://ctx.example.test/a.md" in text.splitlines()[0]


def test_rejects_an_html_page(tmp_path, monkeypatch):
    repo, output = _repo(tmp_path), _output(tmp_path)
    _serve(monkeypatch, b"<!doctype html><html><body>wiki</body></html>", content_type="text/html")

    with pytest.raises(lbc.BusinessContextError, match="raw Markdown"):
        lbc.capture(repo_root=repo, output_dir=output, source="https://wiki.example.test/page", persist=True)


def test_rejects_html_without_a_content_type(tmp_path, monkeypatch):
    repo, output = _repo(tmp_path), _output(tmp_path)
    _serve(monkeypatch, b"<html><body>wiki</body></html>", content_type="application/octet-stream")

    with pytest.raises(lbc.BusinessContextError, match="HTML page"):
        lbc.capture(repo_root=repo, output_dir=output, source="https://wiki.example.test/page", persist=True)


def test_provenance_cannot_break_out_of_its_comment(tmp_path, monkeypatch):
    repo, output = _repo(tmp_path), _output(tmp_path)
    _serve(monkeypatch, b"Context body.\n")

    lbc.capture(
        repo_root=repo,
        output_dir=output,
        source="https://ctx.example.test/a.md?x=--><script>alert(1)</script>",
        persist=True,
    )

    first_line = (repo / lbc.REPO_RELATIVE).read_text(encoding="utf-8").splitlines()[0]
    assert first_line.endswith("-->")
    assert "<script>" not in first_line


def test_run_only_capture_takes_precedence_over_the_repository_file(tmp_path):
    repo, output = _repo(tmp_path), _output(tmp_path)
    (repo / lbc.REPO_RELATIVE).write_text("stored context\n", encoding="utf-8")
    (output / lbc.RUN_ONLY_NAME).write_text("this run only\n", encoding="utf-8")

    assert lbc.effective_source(repo, output) == output / lbc.RUN_ONLY_NAME


def test_digest_tracks_the_effective_context(tmp_path):
    repo, output = _repo(tmp_path), _output(tmp_path)
    assert lbc.context_digest(repo, output) is None

    (repo / lbc.REPO_RELATIVE).write_text("stored context\n", encoding="utf-8")
    first = lbc.context_digest(repo, output)
    (repo / lbc.REPO_RELATIVE).write_text("stored context, revised\n", encoding="utf-8")

    assert first is not None
    assert lbc.context_digest(repo, output) != first


def test_consume_source_only_deletes_inside_the_output_directory(tmp_path):
    output = _output(tmp_path)
    inside = output / ".business-context-raw.md"
    inside.write_text("pasted\n", encoding="utf-8")
    outside = _source(tmp_path)

    lbc._consume(str(outside), output)  # noqa: SLF001
    lbc._consume(str(inside), output)  # noqa: SLF001

    assert outside.is_file()
    assert not inside.exists()


def test_cli_reports_a_rejected_source_without_writing(tmp_path, capsys):
    repo, output = _repo(tmp_path), _output(tmp_path)
    source = _source(tmp_path, 'token = "AKIAIOSFODNN7EXAMPLE"\n')

    code = lbc.main(
        ["--repo-root", str(repo), "--output-dir", str(output), "--source", str(source), "--persist"],
    )

    assert code == 1
    assert "credential" in capsys.readouterr().err
    assert not (repo / lbc.REPO_RELATIVE).exists()
