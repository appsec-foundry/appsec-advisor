import json
from pathlib import Path
from types import SimpleNamespace

import harvest_requirements as harvester
import pytest
import requests


def _args(config=None, output=None, *, dry_run=False, verbose=False, req_only=False, blueprint_only=False, token=None):
    return SimpleNamespace(
        config=str(config) if config else None,
        output=str(output) if output else None,
        token=token,
        dry_run=dry_run,
        verbose=verbose,
        req_only=req_only,
        blueprint_only=blueprint_only,
    )


def _write_config(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "harvest-config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# HTTP / config / run input paths
# ---------------------------------------------------------------------------


def test_build_session_applies_auth_headers_proxy_and_tls(monkeypatch):
    disabled = []

    monkeypatch.setattr(harvester.urllib3, "disable_warnings", lambda warning: disabled.append(warning))

    session = harvester.build_session(
        token="tok",
        extra_headers={"X-Test": "yes"},
        timeout=7,
        use_proxy=False,
        verify_ssl=False,
    )

    assert session.headers["Authorization"] == "Bearer tok"
    assert session.headers["X-Test"] == "yes"
    assert session.timeout == 7
    assert session.trust_env is False
    assert session.verify is False
    assert disabled == [harvester.urllib3.exceptions.InsecureRequestWarning]


def test_fetch_success_forces_latin1_to_utf8():
    class Resp:
        encoding = "ISO-8859-1"
        text = "ok"
        url = "https://example.test/final"

        def raise_for_status(self):
            return None

    class Session:
        def get(self, url):
            self.url = url
            return Resp()

    html, final_url = harvester.fetch(Session(), "https://example.test/start", "source")

    assert html == "ok"
    assert final_url == "https://example.test/final"


def test_fetch_warns_for_timeout_http_and_connection_errors(capsys):
    class TimeoutSession:
        def get(self, url):
            raise requests.exceptions.Timeout()

    class HttpSession:
        def get(self, url):
            response = SimpleNamespace(status_code=503)
            raise requests.exceptions.HTTPError(response=response)

    class ConnectionSession:
        def get(self, url):
            raise requests.exceptions.ConnectionError()

    for session in (TimeoutSession(), HttpSession(), ConnectionSession()):
        html, final_url = harvester.fetch(session, "https://example.test/x", "src")
        assert html is None
        assert final_url == "https://example.test/x"

    err = capsys.readouterr().err
    assert "request timed out" in err
    assert "HTTP 503" in err
    assert "connection failed" in err


def test_same_origin_links_filters_and_uses_parent_for_file_url():
    html = """
    <a href="child.html#top">child</a>
    <a href="/docs/guide/child.html">dupe</a>
    <a href="/docs/other.html">outside</a>
    <a href="https://other.test/docs/guide/x.html">other host</a>
    <a href="mailto:security@example.test">mail</a>
    <a href="#anchor">anchor</a>
    <a href="javascript:void(0)">js</a>
    """

    links = harvester.same_origin_links(html, "https://example.test/docs/guide/index.html")

    assert links == ["https://example.test/docs/guide/child.html"]


def test_crawl_index_fetch_failure_and_page_cap(monkeypatch, capsys):
    def fail_fetch(_session, url, _label):
        return None, url

    monkeypatch.setattr(harvester, "fetch", fail_fetch)
    assert harvester.crawl_index(object(), "https://example.test/base/", "src", 2) == ([], None)

    html = """
    <a href="a.html">a</a>
    <a href="b.html">b</a>
    <a href="c.html">c</a>
    """

    def fake_fetch(_session, url, _label):
        if url.endswith("/base/"):
            return html, url
        return f"<html>{url}</html>", url

    monkeypatch.setattr(harvester, "fetch", fake_fetch)

    pages, index_page = harvester.crawl_index(object(), "https://example.test/base/", "src", 2)

    assert len(pages) == 2
    assert index_page == ("https://example.test/base/", html)
    assert "Capping at 2 pages" in capsys.readouterr().err


def test_load_config_reads_json(tmp_path):
    path = _write_config(tmp_path, {"output": "requirements.yaml"})

    assert harvester.load_config(path) == {"output": "requirements.yaml"}


def test_indexing_mode_precedence_and_literal_wrapping():
    cfg = {"defaults": {"requirements_mode": "full", "blueprints_mode": "summary"}}

    assert harvester.resolve_indexing_mode(cfg, "requirement", "structured", "structured") == "structured"
    assert harvester.resolve_indexing_mode(cfg, "requirement", None, "structured") == "full"
    assert harvester.resolve_indexing_mode(cfg, "blueprint", None, "full") == "summary"
    assert harvester.resolve_indexing_mode(cfg, "other", None, "structured") == "structured"
    assert harvester.wrap_long("short", threshold=10) == "short"

    long_value = harvester.wrap_long("x" * 20, threshold=10)

    assert isinstance(long_value, harvester.LiteralStr)
    assert "text: |" in harvester.yaml.dump({"text": long_value})


def test_run_missing_config_and_empty_sources_return_1(tmp_path, capsys):
    assert harvester.run(_args(config=tmp_path / "missing.json")) == 1
    assert "Config not found" in capsys.readouterr().err

    config = _write_config(tmp_path, {"sources": []})
    assert harvester.run(_args(config=config)) == 1
    assert "No sources configured" in capsys.readouterr().err


def test_run_filters_sources_and_dry_run(monkeypatch, tmp_path, capsys):
    config = _write_config(
        tmp_path,
        {
            "sources": [
                {"id": "req", "type": "requirement", "title": "Req", "crawl_url": "https://example.test/req"},
                {"id": "bp", "type": "blueprint", "title": "BP", "crawl_url": "https://example.test/bp"},
            ]
        },
    )

    monkeypatch.setattr(harvester, "build_session", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        harvester,
        "harvest_requirements_source",
        lambda *args, **kwargs: [{"id": "SEC", "requirements": [{"id": "SEC-1", "url": "u", "text": "t", "priority": "MUST"}]}],
    )
    monkeypatch.setattr(harvester, "harvest_blueprints_source", lambda *args, **kwargs: [{"id": "BP-X"}])

    assert harvester.run(_args(config=config, dry_run=True, req_only=True)) == 0

    out = capsys.readouterr().out
    assert "Requirements: Req" in out
    assert "Blueprints: BP" not in out
    assert "Dry run" in out

    assert harvester.run(_args(config=config, dry_run=True, blueprint_only=True)) == 0

    out = capsys.readouterr().out
    assert "Requirements: Req" not in out
    assert "Blueprints: BP" in out
    assert "Dry run" in out


def test_run_legacy_sources_unknown_type_and_output_validation(monkeypatch, tmp_path, capsys):
    output = tmp_path / "out" / "requirements.yaml"
    config = _write_config(
        tmp_path,
        {
            "description": "Harvested",
            "url": "https://catalog.example.test",
            "output": "ignored.yaml",
            "crawl": {"requirements_base_url": "https://example.test/req", "blueprints_base_url": "https://example.test/bp"},
            "requirements_overrides": [{"id": "extra-req", "url": "https://example.test/extra"}],
            "blueprints_overrides": [{"id": "extra-bp", "url": "https://example.test/extra-bp"}],
            "sources": [],
        },
    )

    monkeypatch.setattr(harvester, "build_session", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        harvester,
        "harvest_requirements_source",
        lambda *args, **kwargs: [{"id": "SEC", "requirements": [{"id": "SEC-1", "url": "u", "text": "t", "priority": "MUST"}]}],
    )
    monkeypatch.setattr(
        harvester,
        "harvest_blueprints_source",
        lambda *args, **kwargs: [{"id": "BP-X", "sections": [{"content": "Follow SEC-1"}]}],
    )
    monkeypatch.setattr(harvester.rstate, "validate_catalog", lambda _body: ([], ["warning only"]))

    assert harvester.run(_args(config=config, output=output, verbose=True)) == 0

    written = harvester.yaml.safe_load(output.read_text(encoding="utf-8"))
    assert written["description"] == "Harvested"
    assert written["url"] == "https://catalog.example.test"
    assert len(written["sources_meta"]) == 4
    assert "schema warning" in capsys.readouterr().out


def test_run_skips_no_crawl_and_unknown_sources(monkeypatch, tmp_path, capsys):
    config = _write_config(
        tmp_path,
        {
            "sources": [
                {"id": "missing-url", "type": "requirement", "title": "Missing URL"},
                {"id": "mystery", "type": "other", "title": "Mystery", "crawl_url": "https://example.test/x"},
            ]
        },
    )

    monkeypatch.setattr(harvester, "build_session", lambda *args, **kwargs: object())

    assert harvester.run(_args(config=config, dry_run=True)) == 0

    captured = capsys.readouterr()
    assert "Source 'missing-url': no crawl_url configured" in captured.out
    assert "unknown type 'other'" in captured.err


def test_run_failed_requirements_source_returns_2_after_write(monkeypatch, tmp_path):
    output = tmp_path / "requirements.yaml"
    config = _write_config(
        tmp_path,
        {"sources": [{"id": "req", "type": "requirement", "title": "Req", "crawl_url": "https://example.test/req"}]},
    )

    monkeypatch.setattr(harvester, "build_session", lambda *args, **kwargs: object())
    monkeypatch.setattr(harvester, "harvest_requirements_source", lambda *args, **kwargs: [])
    monkeypatch.setattr(harvester.rstate, "validate_catalog", lambda _body: ([], []))

    assert harvester.run(_args(config=config, output=output)) == 2

    written = harvester.yaml.safe_load(output.read_text(encoding="utf-8"))
    assert written["sources_meta"][0]["items_count"] == 0
    assert written["categories"] == []


def test_run_reference_url_and_schema_errors_return_2(monkeypatch, tmp_path, capsys):
    output = tmp_path / "requirements.yaml"
    config = _write_config(
        tmp_path,
        {
            "sources": [
                {
                    "id": "req",
                    "type": "requirement",
                    "title": "Req",
                    "crawl_url": "https://example.test/req",
                    "reference_url": "https://example.test/reference",
                }
            ]
        },
    )

    monkeypatch.setattr(harvester, "build_session", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        harvester,
        "harvest_requirements_source",
        lambda *args, **kwargs: [{"id": "SEC", "requirements": [{"id": "SEC-1", "url": "u", "text": "t", "priority": "MUST"}]}],
    )
    monkeypatch.setattr(harvester.rstate, "validate_catalog", lambda _body: (["bad category"], ["warning only"]))

    assert harvester.run(_args(config=config, output=output)) == 2

    written = harvester.yaml.safe_load(output.read_text(encoding="utf-8"))
    assert written["sources_meta"][0]["reference_url"] == "https://example.test/reference"
    captured = capsys.readouterr()
    assert "schema warning: warning only" in captured.out
    assert "schema error: bad category" in captured.err


# ---------------------------------------------------------------------------
# Requirement / blueprint parser helpers
# ---------------------------------------------------------------------------


def test_text_helpers_intro_and_requirement_detection():
    assert harvester.detect_priority("Teams SHOULD rotate signing keys") == "SHOULD"
    assert harvester.detect_priority("No modal verb here") == "MUST"
    assert harvester.clean_text("[SEC-AUTH-1] MUST validate sessions.") == "MUST validate sessions"
    assert harvester.deduplicate_text("Use TLS. Use TLS. Pin certificates.") == "Use TLS. Pin certificates."
    assert harvester.deduplicate_text("Use TLS.\n\nPin certificates.") == "Use TLS. Pin certificates."
    assert harvester.page_has_requirements('<span class="badge">ACME‑AUTH</span>') is True
    assert harvester.page_has_requirements("plain documentation") is False

    html = """
    <main>
      <p>This introduction explains the authentication baseline before controls are listed.</p>
      <div>Container wrapper copy should not be duplicated.
        <p>This nested paragraph is useful introductory context.</p>
      </div>
      <p>Another useful paragraph describes expected rollout and review ownership.</p>
      <p>[SEC-AUTH-1] First requirement stops the intro collection.</p>
    </main>
    """

    intro = harvester.parse_page_intro(html)

    assert "authentication baseline" in intro
    assert "Container wrapper copy" not in intro
    assert "nested paragraph" in intro
    assert "First requirement" not in intro


def test_parse_page_intro_without_main_returns_empty():
    assert harvester.parse_page_intro("<html></html>") == ""


def test_parse_antora_requirements_and_badge_only_summary():
    html = """
    <html>
      <body>
        <h1>MUST API authentication</h1>
        <div class="sect1">
          <h2 id="session-control"><span class="must-label">MUST:</span> Session control</h2>
          <div class="sectionbody">
            <p><span class="badge">SEC_AUTH-2</span></p>
            <p>Sessions must expire after inactivity.</p>
            <details><p>Implementation detail should not be included.</p></details>
          </div>
        </div>
        <div class="sect1">
          <div class="sectionbody">
            <p><span class="badge">SEC‑TOKEN</span></p>
          </div>
        </div>
        <div class="sect1">
          <h2>Summary</h2>
          <div class="sectionbody"><p>Tokens must be stored in the approved vault.</p></div>
        </div>
      </body>
    </html>
    """

    reqs = harvester.parse_requirements_from_page(html, "https://example.test/auth")
    by_id = {r["id"]: r for r in reqs}

    assert by_id["SEC-AUTH-2"]["priority"] == "MUST"
    assert by_id["SEC-AUTH-2"]["url"].endswith("#session-control")
    assert "Implementation detail" not in by_id["SEC-AUTH-2"]["text"]
    assert by_id["SEC-TOKEN"]["text"] == "Tokens must be stored in the approved vault"


def test_parse_requirements_fallback_strategies_and_sorting():
    html = """
    <main>
      <p id="sec-auth-10">[SEC-AUTH-10] SHOULD expire remembered devices.</p>
      <p id="sec-auth-2"></p><p>MAY allow emergency access with approval.</p>
      <dl>
        <dt>[SEC-AUTH-3]</dt>
        <dd>MUST rotate session secrets.</dd>
      </dl>
      <section><p>[SEC-AUTH-4] MUST log privilege changes.</p></section>
      <table>
        <tr><th>ID</th><th>Text</th></tr>
        <tr><td>[SEC-AUTH-5]</td><td>SHOULD pin identity-provider metadata.</td></tr>
      </table>
      <p>[ORG-CUSTOM] MAY document a custom control.</p>
    </main>
    """

    reqs = harvester.parse_requirements_from_page(html, "https://example.test/auth")

    assert [r["id"] for r in reqs] == [
        "SEC-AUTH-2",
        "SEC-AUTH-3",
        "SEC-AUTH-4",
        "SEC-AUTH-5",
        "SEC-AUTH-10",
        "ORG-CUSTOM",
    ]
    by_id = {r["id"]: r for r in reqs}
    assert by_id["SEC-AUTH-2"]["text"] == "MAY allow emergency access with approval"
    assert by_id["SEC-AUTH-3"]["priority"] == "MUST"
    assert by_id["SEC-AUTH-5"]["priority"] == "SHOULD"
    assert by_id["ORG-CUSTOM"]["priority"] == "MAY"


def test_parse_requirements_tolerates_invalid_duplicate_and_empty_markup():
    html = """
    <html>
      <body>
        <h1>MUST Fallback Requirement Title</h1>
        <div class="sect1">
          <h2>Invalid</h2>
          <div class="sectionbody"><p><span class="badge">INVALID</span></p></div>
        </div>
        <div class="sect1">
          <h2 id="dup"><span class="must-label">REQUIRED:</span> Duplicate</h2>
          <div class="sectionbody"><p><span class="badge">SEC-DUP-1</span></p></div>
        </div>
        <div class="sect1">
          <h2>Duplicate again</h2>
          <div class="sectionbody"><p><span class="badge">SEC-DUP-1</span></p></div>
        </div>
        <div class="sect1">
          <h2 id="fallback">SEC-FALLBACK</h2>
          <div class="sectionbody"><p><span class="badge">SEC-FALLBACK</span></p></div>
        </div>
        <dl>
          <dt>No requirement here</dt>
          <dt>[SEC-DUP-1]</dt><dd>Duplicate definition must not replace the badge result.</dd>
        </dl>
        <table>
          <tr><td>[SEC-TABLE-1]</td></tr>
          <tr><td>[SEC-DUP-1]</td><td>Duplicate table entry must not replace the badge result.</td></tr>
        </table>
      </body>
    </html>
    """

    reqs = harvester.parse_requirements_from_page(html, "https://example.test/edge")
    by_id = {r["id"]: r for r in reqs}

    assert "INVALID" not in by_id
    assert list(by_id).count("SEC-DUP-1") == 1
    assert by_id["SEC-DUP-1"]["priority"] == "MUST"
    assert by_id["SEC-DUP-1"]["url"].endswith("#dup")
    assert by_id["SEC-FALLBACK"]["text"] == "Fallback Requirement Title"


def test_group_by_category_atomic_multi_and_full_context():
    atomic = [{"id": "SEC-AUTH", "url": "u#sec-auth", "text": "Do auth", "priority": "MUST"}]
    multi = [
        {"id": "SEC-AUTH-2", "url": "u#2", "text": "B", "priority": "MUST"},
        {"id": "SEC-AUTH-1", "url": "u#1", "text": "A", "priority": "SHOULD"},
        {"id": "ORG-CUSTOM", "url": "u#custom", "text": "C", "priority": "MAY"},
    ]

    atomic_groups = harvester.group_by_category(atomic, "https://example.test/one", "One")
    multi_groups = harvester.group_by_category(
        multi,
        "https://example.test/security-baseline",
        "Baseline",
        mode="full",
        page_intro="This is a long page introduction explaining the context for the harvested controls.",
    )

    assert atomic_groups[0]["id"] == "SEC-AUTH"
    by_cat = {cat["id"]: cat for cat in multi_groups}
    assert [r["id"] for r in by_cat["SEC-AUTH"]["requirements"]] == ["SEC-AUTH-2", "SEC-AUTH-1"]
    assert by_cat["SECURITY_BASELINE"]["requirements"][0]["id"] == "ORG-CUSTOM"
    assert "context" in by_cat["SEC-AUTH"]


def test_page_title_and_section_anchor_fallbacks():
    assert harvester.page_title("<h1>Heading</h1><title>Title</title>", "fallback") == "Heading"
    assert harvester.page_title("<title>Title</title>", "fallback") == "Title"
    assert harvester.page_title("<html></html>", "fallback") == "fallback"
    assert harvester.section_anchor("API & Auth: Rules!") == "api-auth-rules"


def test_parse_blueprint_summary_and_flat_page_modes():
    summary_html = """
    <html>
      <head><title>API Security</title><meta name="description" content="Secure APIs."></head>
      <body>
        <article>
          <p>This paragraph is long enough to become the visible summary for the blueprint page.</p>
          <h2 id="auth">Authentication</h2>
          <p>   </p>
          <p>Use central identity.</p>
          <h3>Tokens</h3>
          <p>Rotate tokens. Rotate tokens.</p>
        </article>
      </body>
    </html>
    """
    flat_html = """
    <html>
      <head><meta name="description" content="Fallback summary."></head>
      <body>
        <main>
          <p>This flat blueprint page has enough text to become a summary paragraph.</p>
          <p>This second paragraph should be captured in the Overview section.</p>
        </main>
      </body>
    </html>
    """

    summary = harvester.parse_blueprint_page(summary_html, "https://example.test/api", mode="summary")
    full = harvester.parse_blueprint_page(summary_html, "https://example.test/api", mode="full", max_section_chars=200)
    flat = harvester.parse_blueprint_page(flat_html, "https://example.test/flat", mode="full", max_section_chars=80)

    assert summary["title"] == "API Security"
    assert summary["topics"] == ["auth", "tokens"]
    assert "sections" not in summary
    assert [section["title"] for section in full["sections"]] == ["Authentication", "Tokens"]
    assert flat["title"] == "https://example.test/flat"
    assert flat["sections"][0]["title"] == "Overview"
    assert len(flat["sections"][0]["content"]) <= 80


def test_requirements_sources_without_crawl_url_warn(capsys):
    assert harvester.harvest_requirements_source(
        session=None,
        cfg={},
        source={"id": "req"},
        verbose=False,
    ) == []
    assert harvester.harvest_blueprints_source(
        session=None,
        cfg={},
        source={"id": "bp"},
        verbose=False,
    ) == []

    err = capsys.readouterr().err
    assert "Source 'req': no crawl_url" in err
    assert "Source 'bp': no crawl_url" in err


def test_requirements_source_includes_index_merges_sorts_and_reports(monkeypatch, capsys):
    index_html = """
    <html>
      <body>
        <main>
          <h1>Auth Requirements</h1>
          <p>This authentication baseline introduces the controls before listing them.</p>
          <p>[SEC-AUTH-10] SHOULD review remembered devices.</p>
          <p>[SEC-AUTH-1] MUST validate every session.</p>
        </main>
      </body>
    </html>
    """
    child_html = """
    <html>
      <body>
        <main>
          <h1>Auth Follow-up</h1>
          <p>[SEC-AUTH-3] MAY allow emergency access with approval.</p>
          <p>[SEC-AUTH-2] MUST rotate signing keys.</p>
        </main>
      </body>
    </html>
    """
    no_ids_html = "<main><p>General guidance without requirement identifiers.</p></main>"
    matched_empty_html = "<main><p>[SEC-DROP-1] This page is intentionally not extracted.</p></main>"

    def fake_crawl_index(_session, base_url, label, max_pages):
        assert label == "app-reqs"
        assert max_pages == 4
        return [
            (f"{base_url.rstrip('/')}/child", child_html),
            (f"{base_url.rstrip('/')}/no-ids", no_ids_html),
            (f"{base_url.rstrip('/')}/matched-empty", matched_empty_html),
        ], (base_url, index_html)

    real_parse = harvester.parse_requirements_from_page

    def fake_parse_requirements(html, url):
        if url.endswith("/matched-empty"):
            return []
        return real_parse(html, url)

    monkeypatch.setattr(harvester, "crawl_index", fake_crawl_index)
    monkeypatch.setattr(harvester, "parse_requirements_from_page", fake_parse_requirements)

    categories = harvester.harvest_requirements_source(
        session=None,
        cfg={"defaults": {"requirements_mode": "full", "max_pages": 2}},
        source={"id": "app-reqs", "crawl_url": "https://example.test/req", "max_pages": 4},
        verbose=True,
    )

    by_id = {cat["id"]: cat for cat in categories}

    assert [r["id"] for r in by_id["SEC-AUTH"]["requirements"]] == [
        "SEC-AUTH-1",
        "SEC-AUTH-2",
        "SEC-AUTH-3",
        "SEC-AUTH-10",
    ]
    assert by_id["SEC-AUTH"]["source_id"] == "app-reqs"
    assert "authentication baseline" in by_id["SEC-AUTH"]["context"]
    captured = capsys.readouterr()
    assert "merged 2 more requirements" in captured.out
    assert "[SKIP] No requirement-ID tokens found" in captured.out
    assert "SEC-AUTH-10 [SHOULD]" in captured.out
    assert "matched but no requirements extracted" in captured.err


def test_blueprint_source_indexes_configured_crawl_url(monkeypatch):
    index_html = """
    <html>
      <body>
        <main>
          <h1>API Blueprint</h1>
          <p>Implementation guidance for APIs.</p>
          <h2 id="auth">Authentication</h2>
          <p>Use the central identity provider for every API.</p>
        </main>
      </body>
    </html>
    """

    def fake_crawl_index(session, base_url, label, max_pages):
        return [], (base_url, index_html)

    monkeypatch.setattr(harvester, "crawl_index", fake_crawl_index)

    blueprints = harvester.harvest_blueprints_source(
        session=None,
        cfg={"defaults": {"blueprints_mode": "full", "section_max_chars": 5000}},
        source={
            "id": "api-blueprints",
            "type": "blueprint",
            "crawl_url": "https://security.example.com/blueprints/api",
        },
        verbose=False,
    )

    assert [bp["id"] for bp in blueprints] == ["BP-API"]
    assert blueprints[0]["title"] == "API Blueprint"
    assert blueprints[0]["sections"][0]["title"] == "Authentication"


def test_blueprint_source_deduplicates_index_page_from_discovered_links(monkeypatch):
    index_html = """
    <html>
      <body>
        <main>
          <h1>Blueprints</h1>
          <h2 id="overview">Overview</h2>
          <p>Blueprint catalog overview.</p>
        </main>
      </body>
    </html>
    """

    def fake_crawl_index(session, base_url, label, max_pages):
        return [(base_url + "/", index_html)], (base_url, index_html)

    monkeypatch.setattr(harvester, "crawl_index", fake_crawl_index)

    blueprints = harvester.harvest_blueprints_source(
        session=None,
        cfg={"defaults": {"blueprints_mode": "full", "section_max_chars": 5000}},
        source={
            "id": "appsec-blueprints",
            "type": "blueprint",
            "crawl_url": "https://security.example.com/blueprints",
        },
        verbose=False,
    )

    assert len(blueprints) == 1
    assert blueprints[0]["id"] == "BP-BLUEPRINTS"


def test_blueprint_source_summary_and_verbose_full_modes(monkeypatch, capsys):
    index_html = """
    <html>
      <body>
        <main>
          <h1>Runtime Blueprint</h1>
          <p>This blueprint explains runtime hardening for deployed services.</p>
          <h2 id="deploy">Deploy</h2>
          <p>Require deployment approvals and immutable release artifacts.</p>
        </main>
      </body>
    </html>
    """

    def fake_crawl_index(_session, base_url, _label, _max_pages):
        return [], (base_url, index_html)

    monkeypatch.setattr(harvester, "crawl_index", fake_crawl_index)

    summary = harvester.harvest_blueprints_source(
        session=None,
        cfg={"defaults": {"blueprints_mode": "summary"}},
        source={"id": "bp", "crawl_url": "https://example.test/blueprints/runtime"},
        verbose=True,
    )
    full = harvester.harvest_blueprints_source(
        session=None,
        cfg={"defaults": {"blueprints_mode": "full", "section_max_chars": 100}},
        source={"id": "bp", "crawl_url": "https://example.test/blueprints/runtime", "mode": "full"},
        verbose=True,
    )

    assert "sections" not in summary[0]
    assert full[0]["sections"][0]["title"] == "Deploy"
    out = capsys.readouterr().out
    assert "summary only" in out
    assert "[Deploy]" in out


# ---------------------------------------------------------------------------
# Blueprint ↔ requirement cross-reference resolution
# (resolve_references / add_references_to_blueprints) — the link that the §7b
# audit and the threat-model report rely on for "mapping bei Blueprints".
# ---------------------------------------------------------------------------


def test_resolve_references_keeps_known_skips_unknown_and_dedupes():
    req_url_map = {
        "SEC-AUTH-1": "https://req.example/sec-auth-1",
        "SSLM-WAF": "https://req.example/sslm-waf",
    }
    text = (
        "Authenticate via SEC-AUTH-1 and protect with SSLM-WAF. See SEC-AUTH-1 again. UNKNOWN-99 is not in the catalog."
    )
    refs = harvester.resolve_references(text, req_url_map)

    # Known IDs resolved (order-preserving, first-seen), duplicate collapsed,
    # unknown ID skipped.
    assert refs == [
        {"id": "SEC-AUTH-1", "url": "https://req.example/sec-auth-1"},
        {"id": "SSLM-WAF", "url": "https://req.example/sslm-waf"},
    ]


def test_resolve_references_handles_arbitrary_org_prefixes():
    # The ID grammar is generic (_ID_BODY) — no hardcoded SEC- prefix. Diverse
    # real-world org prefixes must all resolve.
    req_url_map = {
        "AC-001": "https://req/ac-001",
        "ISO27K-9": "https://req/iso27k-9",
        "SSLM-WAF": "https://req/sslm-waf",
        "OWASP-A01": "https://req/owasp-a01",
    }
    text = "Apply AC-001, ISO27K-9, SSLM-WAF and OWASP-A01 across the stack."
    refs = harvester.resolve_references(text, req_url_map)
    assert [r["id"] for r in refs] == ["AC-001", "ISO27K-9", "SSLM-WAF", "OWASP-A01"]


def test_add_references_to_blueprints_annotates_only_matching_sections():
    req_url_map = {"SEC-AUTH-1": "https://req.example/sec-auth-1"}
    blueprints = [
        {
            "id": "BP-API",
            "sections": [
                {"title": "Auth", "content": "Follow SEC-AUTH-1 for API auth."},
                {"title": "Misc", "content": "No requirement IDs here."},
            ],
        }
    ]
    total = harvester.add_references_to_blueprints(blueprints, req_url_map)

    assert total == 1
    secs = blueprints[0]["sections"]
    assert secs[0]["references"] == [{"id": "SEC-AUTH-1", "url": "https://req.example/sec-auth-1"}]
    # A section with no resolvable ID is left untouched (no empty references key).
    assert "references" not in secs[1]


def test_main_parses_cli_arguments_and_exits(monkeypatch, tmp_path):
    seen = {}

    def fake_run(args):
        seen["args"] = args
        return 7

    monkeypatch.setattr(harvester, "run", fake_run)
    monkeypatch.setattr(
        harvester.sys,
        "argv",
        [
            "harvest_requirements.py",
            "--config",
            str(tmp_path / "config.json"),
            "--output",
            str(tmp_path / "out.yaml"),
            "--token",
            "tok",
            "--dry-run",
            "--verbose",
            "--req-only",
            "--blueprint-only",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        harvester.main()

    assert exc.value.code == 7
    assert seen["args"].config == str(tmp_path / "config.json")
    assert seen["args"].output == str(tmp_path / "out.yaml")
    assert seen["args"].token == "tok"
    assert seen["args"].dry_run is True
    assert seen["args"].verbose is True
    assert seen["args"].req_only is True
    assert seen["args"].blueprint_only is True
