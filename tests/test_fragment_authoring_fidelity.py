"""Regression tests for the 2026-06-12 juice-shop run defects.

Three plugin-side root causes surfaced on that run:

  RC1 — the threat-renderer authored ``ms-anti-patterns.json`` with component
        SLUG ids (``backend-api``) where ``anti-patterns.schema.json`` requires
        the canonical ``C-NN`` form, hard-aborting compose. The composer now
        normalises slug→C-NN before validation
        (``_normalize_anti_pattern_component_refs``).

  RC2 — the renderer agent doc and ``security-posture-attack-paths.schema.json``
        had completely DESYNCED enum vocabularies (doc said ``auth_bypass`` /
        ``External Attacker`` / ``account_takeover``; schema requires
        ``auth-bypass`` / ``internet-anon`` / ``full-admin-takeover``), so the
        agent authored a fragment that failed every enum and was discarded to
        the deterministic fallback. The doc was rewritten to match the schema.

RC3 (verifier maxTurns + write-first contract) is covered by
``test_agent_definitions.py`` (maxTurns ceiling) — see that file.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"
RENDERER_DOC = REPO_ROOT / "agents" / "appsec-threat-renderer.md"
POSTURE_SCHEMA = REPO_ROOT / "schemas" / "fragments" / "security-posture-attack-paths.schema.json"


def _load_compose():
    spec = importlib.util.spec_from_file_location("compose_threat_model", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    # Register before exec so the @dataclass forward-ref resolution in
    # RenderContext can see the module in sys.modules (Python 3.10+).
    sys.modules["compose_threat_model"] = module
    spec.loader.exec_module(module)
    return module


compose = _load_compose()


# ---------------------------------------------------------------------------
# RC1 — composer normalises ms-anti-patterns affected_components slug → C-NN
# ---------------------------------------------------------------------------


def _make_ctx(tmp_path: Path, components: list[dict]):
    out_dir = tmp_path / "out"
    frag = out_dir / ".fragments"
    frag.mkdir(parents=True)
    return compose.RenderContext(
        output_dir=out_dir,
        contract={},
        yaml_data={"components": components},
        triage={},
        fragments_dir=frag,
    )


class TestAntiPatternComponentNormalization:
    COMPONENTS = [
        {"id": "frontend-spa", "name": "Angular SPA"},
        {"id": "backend-api", "name": "Express API"},
        {"id": "data-persistence", "name": "SQLite"},
    ]

    def _write_fragment(self, ctx, affected):
        path = ctx.fragments_dir / "ms-anti-patterns.json"
        path.write_text(
            json.dumps(
                {
                    "anti_patterns": [
                        {
                            "name": "Secrets hardcoded in source",
                            "description": "RSA private key committed in lib/insecurity.ts.",
                            "findings": [{"ref": "F-005", "label": "Hardcoded RSA private key"}],
                            "affected_components": affected,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_slug_refs_rewritten_to_canonical_cnn(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        path = self._write_fragment(ctx, ["backend-api"])
        compose._normalize_anti_pattern_component_refs(ctx)
        data = json.loads(path.read_text())
        assert data["anti_patterns"][0]["affected_components"] == ["C-02"]

    def test_normalized_fragment_passes_schema(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        path = self._write_fragment(ctx, ["frontend-spa", "data-persistence"])
        compose._normalize_anti_pattern_component_refs(ctx)
        data = json.loads(path.read_text())
        assert data["anti_patterns"][0]["affected_components"] == ["C-01", "C-03"]
        # The whole point: the normalized fragment now validates.
        compose._validate_fragment("architectural_anti_patterns", data, "anti-patterns.schema.json")

    def test_already_canonical_refs_untouched(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        path = self._write_fragment(ctx, ["C-02"])
        compose._normalize_anti_pattern_component_refs(ctx)
        assert json.loads(path.read_text())["anti_patterns"][0]["affected_components"] == ["C-02"]

    def test_idempotent(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        path = self._write_fragment(ctx, ["backend-api"])
        compose._normalize_anti_pattern_component_refs(ctx)
        first = path.read_text()
        compose._normalize_anti_pattern_component_refs(ctx)
        assert path.read_text() == first

    def test_missing_fragment_is_noop(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        # No fragment written — must not raise.
        compose._normalize_anti_pattern_component_refs(ctx)

    def test_dict_form_id_normalized(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        path = self._write_fragment(ctx, [{"id": "backend-api", "name": "Express API"}])
        compose._normalize_anti_pattern_component_refs(ctx)
        ref = json.loads(path.read_text())["anti_patterns"][0]["affected_components"][0]
        assert ref == {"id": "C-02", "name": "Express API"}


# ---------------------------------------------------------------------------
# RC1b — composer normalises ms-ai-exposure affected_components slug → C-NN
#        (2026-06-21 juice-shop: ai-exposure had the SAME slug bug as
#        anti-patterns but no normalizer, so compose --strict hard-aborted.)
# ---------------------------------------------------------------------------


class TestAiExposureComponentNormalization:
    COMPONENTS = [
        {"id": "frontend-spa", "name": "Angular SPA"},
        {"id": "backend-api", "name": "Express API"},
        {"id": "data-persistence", "name": "SQLite"},
        {"id": "ai-chatbot-service", "name": "AI Chatbot"},
    ]

    def _write_fragment(self, ctx, affected):
        path = ctx.fragments_dir / "ms-ai-exposure.json"
        path.write_text(
            json.dumps(
                {
                    "summary": "LLM chatbot delegates policy enforcement to instructions.",
                    "ai_risks": [
                        {
                            "owasp_llm_id": "LLM01",
                            "name": "Prompt Injection",
                            "severity": "red",
                            "description": "User chat input is concatenated into the prompt.",
                            "affected_components": affected,
                            "findings": [
                                {"ref": "T-020", "label": "Prompt injection via chat input"}
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_slug_refs_rewritten_to_canonical_cnn(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        path = self._write_fragment(ctx, ["ai-chatbot-service"])
        compose._normalize_ms_component_refs(ctx)
        data = json.loads(path.read_text())
        assert data["ai_risks"][0]["affected_components"] == ["C-04"]

    def test_normalized_fragment_passes_schema(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        path = self._write_fragment(ctx, ["ai-chatbot-service"])
        compose._normalize_ms_component_refs(ctx)
        data = json.loads(path.read_text())
        assert data["ai_risks"][0]["affected_components"] == ["C-04"]
        # The whole point: the normalized fragment now validates strictly.
        compose._validate_fragment("ai_exposure_ms", data, "ai-exposure.schema.json")

    def test_already_canonical_refs_untouched(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        path = self._write_fragment(ctx, ["C-04"])
        compose._normalize_ms_component_refs(ctx)
        assert json.loads(path.read_text())["ai_risks"][0]["affected_components"] == ["C-04"]

    def test_idempotent(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        path = self._write_fragment(ctx, ["ai-chatbot-service"])
        compose._normalize_ms_component_refs(ctx)
        first = path.read_text()
        compose._normalize_ms_component_refs(ctx)
        assert path.read_text() == first

    def test_missing_fragment_is_noop(self, tmp_path):
        ctx = _make_ctx(tmp_path, self.COMPONENTS)
        # Neither MS fragment written — must not raise.
        compose._normalize_ms_component_refs(ctx)


# ---------------------------------------------------------------------------
# RC2 — renderer doc enum vocabulary must match the posture schema
# ---------------------------------------------------------------------------


def _posture_doc_section() -> str:
    text = RENDERER_DOC.read_text(encoding="utf-8")
    marker = "### `security-posture-attack-paths.json` authoring contract"
    start = text.index(marker)
    rest = text[start + len(marker) :]
    nxt = rest.index("\n### ")
    return rest[:nxt]


def _posture_schema_enums() -> dict[str, list[str]]:
    s = json.loads(POSTURE_SCHEMA.read_text(encoding="utf-8"))
    item = s["properties"]["attack_paths"]["items"]["properties"]
    return {
        "actor": s["properties"]["actors"]["items"]["enum"],
        "class": item["class"]["enum"],
        "target": item["target"]["enum"],
        "impact": item["impact"]["items"]["enum"],
    }


class TestPostureDocSchemaSync:
    def test_doc_lists_every_schema_enum_value(self):
        section = _posture_doc_section()
        missing = []
        for field, values in _posture_schema_enums().items():
            for v in values:
                if f"`{v}`" not in section:
                    missing.append(f"{field}={v}")
        assert not missing, (
            "renderer doc posture contract is missing schema enum value(s): "
            f"{missing} — doc and schema have drifted apart again"
        )

    def test_doc_has_no_stale_pre_2026_06_vocabulary(self):
        section = _posture_doc_section()
        stale = [
            "auth_bypass",
            "session_hijack",
            "data_exfiltration",
            "account_takeover",
            "service_disruption",
            "compliance_violation",
            "financial_loss",
            "reputational_damage",
            "External Attacker",
            "Malicious Insider",
            "Supply Chain Actor",
        ]
        found = [t for t in stale if t in section]
        assert not found, f"stale posture vocabulary resurfaced in renderer doc: {found}"
