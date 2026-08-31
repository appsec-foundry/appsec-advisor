"""
Tests for the requirements YAML schema.

Validates that examples/appsec-requirements-example.yaml conforms to the
structure expected by the audit-security-requirements skill (SKILL.md Step 1c):
  categories[].id, .title, .url
  categories[].requirements[].id, .text, .priority, .url

Also validates the optional blueprints[] section and cross-references.

The split examples beside it (a requirements-only catalog and one file per
blueprint) must not drift from what this catalog publishes.
"""

import re
from pathlib import Path
from urllib.parse import urlparse

import pytest
import requirements_state as rstate
import yaml

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
REQUIREMENTS_FILE = EXAMPLES_DIR / "appsec-requirements-example.yaml"
REQUIREMENTS_ONLY_FILE = EXAMPLES_DIR / "appsec-requirements-example.requirements.yaml"
BLUEPRINT_FILES = {
    "BP-API-HARDENING": EXAMPLES_DIR / "blueprints" / "api-hardening.yaml",
    "BP-LLM-SECURITY": EXAMPLES_DIR / "blueprints" / "llm-security.yaml",
}

VALID_PRIORITIES = {"MUST", "SHOULD", "MAY"}

# The example models a catalog published on one organization-internal portal, the
# shape `harvest_requirements.py` produces: a requirement page per category, a
# requirement anchored on its page, a blueprint page per blueprint, a blueprint
# section anchored on its page. Every link in the file stays inside that host.
CATALOG_HOST = "https://appsec.int.example.com"
REQUIREMENT_PAGE_PREFIX = f"{CATALOG_HOST}/req/"
BLUEPRINT_PAGE_PREFIX = f"{CATALOG_HOST}/blueprints/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def data():
    """Load and parse the requirements YAML once for all tests."""
    text = REQUIREMENTS_FILE.read_text()
    return yaml.safe_load(text)


@pytest.fixture(scope="module")
def all_requirements(data):
    """Flatten all requirements from all categories."""
    reqs = []
    for cat in data.get("categories", []):
        for req in cat.get("requirements", []):
            reqs.append({**req, "_category_id": cat["id"]})
    return reqs


@pytest.fixture(scope="module")
def all_requirement_ids(all_requirements):
    """Set of all requirement IDs."""
    return {r["id"] for r in all_requirements}


# ---------------------------------------------------------------------------
# Top-level structure
# ---------------------------------------------------------------------------


class TestTopLevel:
    def test_file_exists(self):
        assert REQUIREMENTS_FILE.exists(), f"Requirements file not found: {REQUIREMENTS_FILE}"

    def test_yaml_is_parseable(self, data):
        assert isinstance(data, dict), "YAML root must be a mapping"

    def test_has_categories(self, data):
        assert "categories" in data, "Missing top-level 'categories' key"
        assert isinstance(data["categories"], list), "'categories' must be a list"
        assert len(data["categories"]) > 0, "'categories' must not be empty"

    def test_has_generated_timestamp(self, data):
        assert "generated" in data, "Missing 'generated' timestamp"

    def test_has_source(self, data):
        assert "source" in data, "Missing 'source' field"

    def test_example_is_honestly_labelled_as_curated(self, data):
        assert data["source"] == "bundled-example"
        assert "not an official OWASP standard" in data["description"]

    def test_catalog_declares_its_own_home(self, data):
        assert data["url"] == CATALOG_HOST

    def test_source_metadata_matches_catalog_items(self, data):
        metadata = {entry["id"]: entry for entry in data["sources_meta"]}
        assert set(metadata) == {"owasp-informed-requirements", "owasp-informed-blueprints"}
        assert metadata["owasp-informed-requirements"]["reference_url"] == f"{CATALOG_HOST}/req"
        assert metadata["owasp-informed-blueprints"]["reference_url"] == f"{CATALOG_HOST}/blueprints"

        requirement_counts = {
            source_id: sum(
                len(category.get("requirements", []))
                for category in data["categories"]
                if category["source_id"] == source_id
            )
            for source_id in metadata
        }
        blueprint_counts = {
            source_id: sum(1 for blueprint in data.get("blueprints", []) if blueprint["source_id"] == source_id)
            for source_id in metadata
        }

        assert (
            metadata["owasp-informed-requirements"]["items_count"] == requirement_counts["owasp-informed-requirements"]
        )
        assert metadata["owasp-informed-blueprints"]["items_count"] == blueprint_counts["owasp-informed-blueprints"]
        assert all("crawl_url" not in entry and "indexed_at" not in entry for entry in metadata.values())


# ---------------------------------------------------------------------------
# Category-level validation
# ---------------------------------------------------------------------------


def category_ids(data_dict):
    return [(c.get("id", f"<index-{i}>"), c) for i, c in enumerate(data_dict.get("categories", []))]


class TestCategories:
    def test_all_categories_have_id(self, data):
        for i, cat in enumerate(data["categories"]):
            assert "id" in cat, f"Category at index {i} missing 'id'"

    def test_all_categories_have_title(self, data):
        for cat in data["categories"]:
            assert "title" in cat and len(cat["title"].strip()) > 0, (
                f"Category {cat.get('id', '?')} missing or empty 'title'"
            )

    def test_all_categories_have_url(self, data):
        for cat in data["categories"]:
            assert "url" in cat and cat["url"].startswith("http"), (
                f"Category {cat.get('id', '?')} missing or invalid 'url'"
            )

    def test_category_ids_are_unique(self, data):
        ids = [c["id"] for c in data["categories"]]
        assert len(ids) == len(set(ids)), f"Duplicate category IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_every_category_has_requirements(self, data):
        for cat in data["categories"]:
            reqs = cat.get("requirements", [])
            assert isinstance(reqs, list) and len(reqs) > 0, f"Category {cat['id']} has no requirements"

    def test_categories_declare_scope_and_a_requirement_page(self, data):
        for category in data["categories"]:
            assert category.get("context"), f"Category {category['id']} has no applicability context"
            assert category["url"].startswith(REQUIREMENT_PAGE_PREFIX), (
                f"Category {category['id']} does not point at a requirement page on {CATALOG_HOST}"
            )


# ---------------------------------------------------------------------------
# Requirement-level validation
# ---------------------------------------------------------------------------


class TestRequirements:
    def test_all_have_id(self, all_requirements):
        for req in all_requirements:
            assert "id" in req and len(req["id"].strip()) > 0, f"Requirement in {req['_category_id']} missing 'id'"

    def test_all_have_text(self, all_requirements):
        for req in all_requirements:
            assert "text" in req and len(req["text"].strip()) > 0, (
                f"Requirement {req.get('id', '?')} missing or empty 'text'"
            )

    def test_all_have_priority(self, all_requirements):
        for req in all_requirements:
            assert "priority" in req, f"Requirement {req['id']} missing 'priority'"

    def test_priority_values_are_valid(self, all_requirements):
        for req in all_requirements:
            assert req["priority"] in VALID_PRIORITIES, (
                f"Requirement {req['id']} has invalid priority '{req['priority']}', expected one of {VALID_PRIORITIES}"
            )

    def test_all_have_url(self, all_requirements):
        for req in all_requirements:
            assert "url" in req and req["url"].startswith("http"), f"Requirement {req['id']} missing or invalid 'url'"

    def test_ids_are_globally_unique(self, all_requirements):
        ids = [r["id"] for r in all_requirements]
        assert len(ids) == len(set(ids)), f"Duplicate requirement IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_id_format(self, all_requirements):
        """IDs should follow the pattern PREFIX-NNN (e.g. WEB-001, AC-002)."""
        pattern = re.compile(r"^[A-Z]{2,6}-\d{3}$")
        for req in all_requirements:
            assert pattern.match(req["id"]), f"Requirement ID '{req['id']}' does not match expected format PREFIX-NNN"

    def test_urls_are_syntactically_valid(self, all_requirements):
        for req in all_requirements:
            parsed = urlparse(req["url"])
            assert parsed.scheme in ("http", "https") and parsed.netloc, (
                f"Requirement {req['id']} URL is not valid: {req['url']}"
            )

    def test_minimum_requirement_count(self, all_requirements):
        """The example baseline should have a meaningful number of requirements."""
        assert len(all_requirements) >= 30, f"Expected at least 30 requirements, got {len(all_requirements)}"

    def test_has_must_requirements(self, all_requirements):
        must_count = sum(1 for r in all_requirements if r["priority"] == "MUST")
        assert must_count > 0, "Expected at least one MUST requirement"

    def test_expected_modern_baseline_coverage_is_present(self, all_requirement_ids):
        assert {
            "AC-007",  # session lifecycle
            "AC-008",  # out-of-band verification
            "DP-008",  # data lifecycle
            "IV-007",  # SSRF
            "IV-008",  # path and process safety
            "SC-007",  # build provenance
            "SD-001",  # threat modeling
            "SD-002",  # business-logic abuse
            "SD-003",  # high-impact actions
        } <= all_requirement_ids

    def test_critical_guidance_does_not_regress(self, all_requirements):
        requirements = {requirement["id"]: requirement["text"] for requirement in all_requirements}

        assert "SameSite cookies provide defense in depth" in requirements["WEB-001"]
        assert "mutual authentication via" not in requirements["AC-001"]
        assert "JWT validation MUST verify" in requirements["AC-005"]
        assert "opaque tokens MUST use authoritative introspection" in requirements["AC-005"]
        assert "regardless of fix availability" in requirements["SC-001"]
        assert "prompt injection cannot be eliminated" in requirements["LLM-001"]
        assert "enforced outside the model" in requirements["LLM-007"]

    def test_every_requirement_is_anchored_on_its_category_page(self, data):
        for category in data["categories"]:
            for requirement in category["requirements"]:
                expected = f"{category['url']}#{requirement['id'].lower()}"
                assert requirement["url"] == expected, (
                    f"Requirement {requirement['id']} is not anchored on its category page: {requirement['url']}"
                )


# ---------------------------------------------------------------------------
# Blueprint validation (optional section)
# ---------------------------------------------------------------------------


class TestBlueprints:
    def test_blueprints_are_list_if_present(self, data):
        if "blueprints" not in data:
            pytest.skip("No blueprints section")
        assert isinstance(data["blueprints"], list)

    def test_blueprints_have_required_fields(self, data):
        if "blueprints" not in data:
            pytest.skip("No blueprints section")
        for bp in data["blueprints"]:
            assert "id" in bp, "Blueprint missing 'id'"
            assert "title" in bp, f"Blueprint {bp.get('id', '?')} missing 'title'"
            assert "sections" in bp, f"Blueprint {bp['id']} missing 'sections'"

    def test_blueprint_ids_are_unique(self, data):
        if "blueprints" not in data:
            pytest.skip("No blueprints section")
        ids = [bp["id"] for bp in data["blueprints"]]
        assert len(ids) == len(set(ids)), "Duplicate blueprint IDs"

    def test_blueprint_sections_have_title_and_content(self, data):
        if "blueprints" not in data:
            pytest.skip("No blueprints section")
        for bp in data["blueprints"]:
            for i, sec in enumerate(bp["sections"]):
                assert "title" in sec, f"Blueprint {bp['id']} section {i} missing 'title'"
                assert "content" in sec, f"Blueprint {bp['id']} section {i} missing 'content'"

    def test_blueprint_references_point_to_valid_requirements(self, data, all_requirement_ids):
        """Every requirement ID referenced from a blueprint section must exist in categories."""
        if "blueprints" not in data:
            pytest.skip("No blueprints section")
        for bp in data["blueprints"]:
            for sec in bp["sections"]:
                for ref in sec.get("references", []):
                    assert ref["id"] in all_requirement_ids, (
                        f"Blueprint {bp['id']} section '{sec['title']}' references unknown requirement '{ref['id']}'"
                    )

    def test_blueprint_sections_are_anchored_on_their_blueprint_page(self, data):
        """`topics` is the ordered heading-anchor list of the page, so it must cover
        every section anchor. A page without headings falls back to `#overview`."""
        for bp in data["blueprints"]:
            assert bp["url"].startswith(BLUEPRINT_PAGE_PREFIX), (
                f"Blueprint {bp['id']} does not point at a blueprint page on {CATALOG_HOST}"
            )
            topics = bp.get("topics") or []
            anchors = []
            for sec in bp["sections"]:
                prefix = f"{bp['url']}#"
                assert sec["url"].startswith(prefix), (
                    f"Blueprint {bp['id']} section '{sec['title']}' is not anchored on its own page: {sec['url']}"
                )
                anchor = sec["url"][len(prefix) :]
                assert anchor in topics or (not topics and anchor == "overview"), (
                    f"Blueprint {bp['id']} section anchor '{anchor}' is not one of the page's headings"
                )
                anchors.append(anchor)
            assert len(set(anchors)) == len(anchors), f"Blueprint {bp['id']} has duplicate section anchors: {anchors}"

    def test_blueprint_references_link_to_the_requirement_itself(self, data, all_requirements):
        requirement_urls = {requirement["id"]: requirement["url"] for requirement in all_requirements}
        for bp in data["blueprints"]:
            for sec in bp["sections"]:
                for ref in sec.get("references", []):
                    assert ref["url"] == requirement_urls[ref["id"]], (
                        f"Blueprint {bp['id']} links {ref['id']} to {ref['url']}, "
                        f"not to the requirement itself ({requirement_urls[ref['id']]})"
                    )

    def test_blueprints_use_declared_source_and_safe_examples(self, data):
        blueprints = data["blueprints"]
        assert len(blueprints) == 12
        assert {blueprint["source_id"] for blueprint in blueprints} == {"owasp-informed-blueprints"}

        rendered = yaml.safe_dump(blueprints, sort_keys=False)
        assert "session=abc123" not in rendered
        assert "SameSite=Lax cookie setting is sufficient" not in rendered
        assert "CORS is a browser policy and is not an access-control mechanism" in rendered
        assert "Assume users can infer or extract prompt content" in rendered
        assert "output constraints outside the model" in rendered


# ---------------------------------------------------------------------------
# Cross-reference consistency
# ---------------------------------------------------------------------------


class TestCrossReferences:
    def test_no_orphan_category_prefix(self, data, all_requirements):
        """Each requirement ID prefix (e.g. WEB, AC) should map to exactly one category."""
        prefix_to_cats = {}
        for req in all_requirements:
            prefix = req["id"].rsplit("-", 1)[0]
            prefix_to_cats.setdefault(prefix, set()).add(req["_category_id"])
        for prefix, cats in prefix_to_cats.items():
            assert len(cats) == 1, f"Prefix '{prefix}' appears in multiple categories: {cats}"

    def test_every_link_field_stays_on_the_catalog_host(self, data):
        """The example stands in for one organization's own catalog, so every `url`
        and `reference_url` resolves inside it. Illustrative hosts inside section
        prose (a CSP source list, an issuer) are content, not links, and are exempt."""

        def links(node, path="$"):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in ("url", "reference_url") and isinstance(value, str):
                        yield f"{path}.{key}", value
                    else:
                        yield from links(value, f"{path}.{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    yield from links(value, f"{path}[{index}]")

        strays = [(path, url) for path, url in links(data) if not url.startswith(CATALOG_HOST)]
        assert not strays, f"Link fields outside {CATALOG_HOST}: {strays}"


# ---------------------------------------------------------------------------
# Split examples
# ---------------------------------------------------------------------------


class TestSplitExamples:
    """The split files model the harvester's per-source output: a catalog that
    carries only requirements, and a catalog per blueprint with an empty
    `categories` list. Each one is passed to `--requirements` on its own, so each
    one must validate alone and must not drift from the combined catalog."""

    def test_requirements_only_example_repeats_the_catalog_requirements(self, data):
        split = yaml.safe_load(REQUIREMENTS_ONLY_FILE.read_text())
        assert split["categories"] == data["categories"]
        assert split["blueprints"] == []
        assert [meta["id"] for meta in split["sources_meta"]] == ["owasp-informed-requirements"]

    @pytest.mark.parametrize("blueprint_id", sorted(BLUEPRINT_FILES))
    def test_blueprint_example_repeats_the_catalog_blueprint(self, data, blueprint_id):
        split = yaml.safe_load(BLUEPRINT_FILES[blueprint_id].read_text())
        published = {entry["id"]: entry for entry in data["blueprints"]}
        assert split["categories"] == []
        assert split["blueprints"] == [published[blueprint_id]]

    @pytest.mark.parametrize("path", [REQUIREMENTS_ONLY_FILE, *BLUEPRINT_FILES.values()], ids=lambda p: p.name)
    def test_split_example_validates_as_a_catalog_of_its_own(self, path):
        errors, _ = rstate.validate_catalog(path.read_bytes())
        assert errors == []
