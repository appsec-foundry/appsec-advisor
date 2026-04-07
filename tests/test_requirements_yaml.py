"""
Tests for the requirements YAML schema.

Validates that examples/appsec-requirements-example.yaml conforms to the
structure expected by the check-appsec-requirements skill (SKILL.md Step 1c):
  categories[].id, .title, .url
  categories[].requirements[].id, .text, .priority, .url

Also validates the optional blueprints[] section and cross-references.
"""

import re
from pathlib import Path
from urllib.parse import urlparse

import pytest
import yaml

REQUIREMENTS_FILE = Path(__file__).parent.parent / "examples" / "appsec-requirements-example.yaml"

VALID_PRIORITIES = {"MUST", "SHOULD", "MAY"}


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
            assert isinstance(reqs, list) and len(reqs) > 0, (
                f"Category {cat['id']} has no requirements"
            )


# ---------------------------------------------------------------------------
# Requirement-level validation
# ---------------------------------------------------------------------------

class TestRequirements:
    def test_all_have_id(self, all_requirements):
        for req in all_requirements:
            assert "id" in req and len(req["id"].strip()) > 0, (
                f"Requirement in {req['_category_id']} missing 'id'"
            )

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
                f"Requirement {req['id']} has invalid priority '{req['priority']}', "
                f"expected one of {VALID_PRIORITIES}"
            )

    def test_all_have_url(self, all_requirements):
        for req in all_requirements:
            assert "url" in req and req["url"].startswith("http"), (
                f"Requirement {req['id']} missing or invalid 'url'"
            )

    def test_ids_are_globally_unique(self, all_requirements):
        ids = [r["id"] for r in all_requirements]
        assert len(ids) == len(set(ids)), (
            f"Duplicate requirement IDs: {[x for x in ids if ids.count(x) > 1]}"
        )

    def test_id_format(self, all_requirements):
        """IDs should follow the pattern PREFIX-NNN (e.g. WEB-001, AC-002)."""
        pattern = re.compile(r"^[A-Z]{2,6}-\d{3}$")
        for req in all_requirements:
            assert pattern.match(req["id"]), (
                f"Requirement ID '{req['id']}' does not match expected format PREFIX-NNN"
            )

    def test_urls_are_syntactically_valid(self, all_requirements):
        for req in all_requirements:
            parsed = urlparse(req["url"])
            assert parsed.scheme in ("http", "https") and parsed.netloc, (
                f"Requirement {req['id']} URL is not valid: {req['url']}"
            )

    def test_minimum_requirement_count(self, all_requirements):
        """The example baseline should have a meaningful number of requirements."""
        assert len(all_requirements) >= 30, (
            f"Expected at least 30 requirements, got {len(all_requirements)}"
        )

    def test_has_must_requirements(self, all_requirements):
        must_count = sum(1 for r in all_requirements if r["priority"] == "MUST")
        assert must_count > 0, "Expected at least one MUST requirement"


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
            assert "id" in bp, f"Blueprint missing 'id'"
            assert "title" in bp, f"Blueprint {bp.get('id', '?')} missing 'title'"
            assert "sections" in bp, f"Blueprint {bp['id']} missing 'sections'"

    def test_blueprint_ids_are_unique(self, data):
        if "blueprints" not in data:
            pytest.skip("No blueprints section")
        ids = [bp["id"] for bp in data["blueprints"]]
        assert len(ids) == len(set(ids)), f"Duplicate blueprint IDs"

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
                        f"Blueprint {bp['id']} section '{sec['title']}' references "
                        f"unknown requirement '{ref['id']}'"
                    )


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
            assert len(cats) == 1, (
                f"Prefix '{prefix}' appears in multiple categories: {cats}"
            )
