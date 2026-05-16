import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "harvest-requirements.py"


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
