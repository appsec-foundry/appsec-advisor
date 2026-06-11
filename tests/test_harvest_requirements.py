import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "harvest_requirements.py"


def load_harvester():
    spec = importlib.util.spec_from_file_location("harvest_requirements", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_blueprint_source_indexes_configured_crawl_url(monkeypatch):
    harvester = load_harvester()
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
    harvester = load_harvester()
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
    harvester = load_harvester()
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
    harvester = load_harvester()
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
    harvester = load_harvester()
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
