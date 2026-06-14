import json
from pathlib import Path
from types import SimpleNamespace

import harvest_requirements as harvester
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
