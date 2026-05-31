"""Tests for Patch P3 — Behavior Tuning (A6 + B2).

Two orthogonal regressions:

    A6 — Quick-mode STRIDE profile no longer suppresses evidence excerpts.
         The flag was demoted from True to False so the §8 Threat Register
         Finding column and the Linked Threats columns regain their
         truncated descriptions. The other flags (max_threats_per_category,
         skip_verification_greps, skip_code_examples, skip_cvss_scoring)
         keep the real token-budget reductions.

    B2 — `_build_attack_arrows` and `_build_consequence_arrows` correctly
         identify victim-targeting attack classes (XSS / CSRF) regardless
         of whether the fragment was LLM-authored (target=victim) or
         deterministic-fallback (target=client + actor=victim-required).
         For victim-targeting classes the renderer now emits TWO arrows:
           1. attacker → client tier (injection path)
           2. client tier → victim actor (consequence path)
         Pre-fix, only one arrow was emitted with reversed direction
         (SHOPUSER → BROWSER) because the data shape didn't match the
         hardcoded `target == "victim"` check.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rc = _load("resolve_config", _SCRIPTS / "resolve_config.py")
compose = _load("compose_threat_model", _SCRIPTS / "compose_threat_model.py")


# ---------------------------------------------------------------------------
# A6 — Quick-profile rebalance
# ---------------------------------------------------------------------------


class TestQuickProfileEvidenceExcerptRestored:
    """The cheap, high-impact rebalance: evidence excerpt is back at quick."""

    def test_quick_haiku_economy_keeps_evidence_excerpt(self):
        profile = rc.resolve_stride_profile("haiku-economy", "quick")
        sp = profile["stride_profile"]
        assert sp["skip_evidence_excerpt"] is False, (
            "P3 (A6) — skip_evidence_excerpt must be False at quick depth so "
            "§8 Threat Register and Linked Threats columns regain their "
            "truncated descriptions"
        )

    def test_other_quick_flags_unchanged(self):
        """The token-budget reductions must remain in place — only the
        cheap-but-impactful evidence flag and (separately, 2026-05) the
        code-example flag flipped. Both are now False because the
        ~200-400 added output tokens per mitigation are worth restoring
        actionable code hints to the §9 Mitigation Register."""
        profile = rc.resolve_stride_profile("haiku-economy", "quick")
        sp = profile["stride_profile"]
        assert sp["skip_verification_greps"] is True
        assert sp["max_threats_per_category"] == 1  # quick triage, Critical-safe (2026-05)
        assert sp["skip_code_examples"] is False  # F4.4 — verified 2026-05
        assert sp["skip_cvss_scoring"] is True
        assert sp["turn_budget_hard_cap"] == 25

    def test_non_quick_depths_get_full_profile(self):
        """The rebalance only touches the haiku-economy quick branch.
        Standard / thorough must still see the full-profile label."""
        for depth in ("standard", "thorough"):
            profile = rc.resolve_stride_profile("haiku-economy", depth)
            assert profile["stride_profile"].get("stride_profile_label") == "full", (
                f"depth={depth} must keep the full STRIDE profile"
            )


# ---------------------------------------------------------------------------
# B2 — Multi-arrow heatmap
# ---------------------------------------------------------------------------

# Minimal taxonomy + actor/tier card fixtures suitable for unit-testing
# `_build_attack_arrows` directly.


def _taxonomy():
    return {
        "glyph_sequence": ["①", "②", "③", "④", "⑤", "⑥", "⑦"],
        "classes": [
            {"id": "injection", "label": "Injection", "short_label": "Injection"},
            {"id": "auth-bypass", "label": "Auth Bypass", "short_label": "Auth Bypass"},
            {"id": "remote-code-execution", "label": "RCE", "short_label": "RCE"},
            {"id": "cross-site-scripting", "label": "XSS", "short_label": "XSS"},
            {"id": "cross-site-request-forgery", "label": "CSRF", "short_label": "CSRF"},
        ],
    }


def _actors():
    return [
        {"slug": "internet-anon", "id": "ANON", "label": "Anon"},
        {"slug": "victim-required", "id": "SHOPUSER", "label": "Shop User"},
    ]


def _tiers():
    return [
        {"key": "client", "node_id": "BROWSER", "name": "Client Tier"},
        {"key": "application", "node_id": "SERVER", "name": "Application Tier"},
    ]


class TestVictimTargetingArrowDirection:
    """Pre-P3 bug: when the fallback emitted ``target: client`` +
    ``actor: victim-required``, the renderer fell into the else branch and
    emitted ``SHOPUSER → BROWSER`` (victim as source). P3 detects victim-
    targeting classes via either ``target == "victim"`` or
    ``actor == "victim-required"`` and emits two arrows in the correct
    direction."""

    def test_target_victim_form_emits_dual_arrows(self):
        """LLM-authored fragment shape: ``target: victim``. The function
        returns ``(attack_arrows, relay_arrows)``; the injection edge is in
        attack_arrows (grouped, no text label), the delivery edge in relays."""
        attack_paths = {
            "attack_paths": [{"class": "cross-site-scripting", "actor": "victim-required", "target": "victim"}]
        }
        arrows, relays = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        # Edge 1 — injection attacker → client tier (grouped, label dropped).
        assert arrows == [{"src": "ANON", "glyph": "①", "label": "", "dst": "BROWSER"}]
        # Edge 2 — relay client tier → victim, sharing the glyph.
        assert relays == [{"src": "BROWSER", "glyph": "①", "label": "XSS", "dst": "SHOPUSER"}]

    def test_target_client_actor_victim_form_emits_dual_arrows(self):
        """Deterministic-fallback shape: ``target: client`` +
        ``actor: victim-required``. Must route attacker→client + client→victim,
        never victim→client."""
        attack_paths = {
            "attack_paths": [{"class": "cross-site-scripting", "actor": "victim-required", "target": "client"}]
        }
        arrows, relays = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert arrows[0]["src"] == "ANON" and arrows[0]["dst"] == "BROWSER"
        assert relays[0]["src"] == "BROWSER" and relays[0]["dst"] == "SHOPUSER"

    def test_csrf_also_dual_arrow(self):
        """CSRF is the second victim-targeting class; same treatment."""
        attack_paths = {
            "attack_paths": [{"class": "cross-site-request-forgery", "actor": "victim-required", "target": "client"}]
        }
        arrows, relays = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert arrows[0]["src"] == "ANON" and arrows[0]["dst"] == "BROWSER"
        assert relays[0]["src"] == "BROWSER" and relays[0]["dst"] == "SHOPUSER"


class TestDirectAttackArrowsGrouped:
    """Reference form (2026-05): direct-attack arrows are grouped per
    (actor, tier) — one arrow carrying all of that actor's glyphs against the
    tier, with no per-class text label. `_build_attack_arrows` returns
    ``(attack_arrows, relay_arrows)``."""

    def test_injection_emits_single_grouped_arrow_anon_to_application(self):
        attack_paths = {"attack_paths": [{"class": "injection", "actor": "internet-anon", "target": "application"}]}
        arrows, relays = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert arrows == [{"src": "ANON", "glyph": "①", "label": "", "dst": "SERVER"}]
        assert relays == []

    def test_rce_emits_single_grouped_arrow_anon_to_application(self):
        attack_paths = {
            "attack_paths": [{"class": "remote-code-execution", "actor": "internet-anon", "target": "application"}]
        }
        arrows, _relays = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert len(arrows) == 1
        assert arrows[0]["src"] == "ANON"
        assert arrows[0]["dst"] == "SERVER"

    def test_same_actor_same_tier_classes_collapse_to_one_arrow(self):
        """3 direct classes from the same actor against the same tier collapse
        to one grouped arrow carrying ``① ② ③``; the victim class adds a second
        grouped arrow (anon→client) plus a relay."""
        attack_paths = {
            "attack_paths": [
                {"class": "injection", "actor": "internet-anon", "target": "application"},
                {"class": "auth-bypass", "actor": "internet-anon", "target": "application"},
                {"class": "remote-code-execution", "actor": "internet-anon", "target": "application"},
                {"class": "cross-site-scripting", "actor": "victim-required", "target": "client"},
            ]
        }
        arrows, relays = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert len(arrows) == 2  # grouped app arrow + grouped client arrow
        app = next(a for a in arrows if a["dst"] == "SERVER")
        assert app["glyph"] == "① ② ③"
        assert len(relays) == 1 and relays[0]["dst"] == "SHOPUSER"


class TestGlyphSharingAcrossDualArrow:
    """A victim-targeting class shares one glyph across its injection arrow
    and its relay arrow, and the glyph index advances once per class."""

    def test_injection_and_relay_share_glyph(self):
        attack_paths = {
            "attack_paths": [{"class": "cross-site-scripting", "actor": "victim-required", "target": "victim"}]
        }
        arrows, relays = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert arrows[0]["glyph"] == "①"
        assert relays[0]["glyph"] == "①"

    def test_glyph_sequence_advances_per_class_not_per_arrow(self):
        """XSS (glyph ①, emitted as anon→client arrow + relay) then a direct
        injection must get glyph ②, not ③."""
        attack_paths = {
            "attack_paths": [
                {"class": "cross-site-scripting", "actor": "victim-required", "target": "victim"},
                {"class": "injection", "actor": "internet-anon", "target": "application"},
            ]
        }
        arrows, relays = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        xss = next(a for a in arrows if a["dst"] == "BROWSER")
        inj = next(a for a in arrows if a["dst"] == "SERVER")
        assert xss["glyph"] == "①"
        assert inj["glyph"] == "②"
        assert relays[0]["glyph"] == "①"


class TestNoAttackerActorPresent:
    """When the actor list contains ONLY the victim, no injection arrow can be
    emitted (no attacker to route from); only the client→victim relay edge is
    produced."""

    def test_only_victim_in_actor_list_emits_relay_only(self):
        actors = [{"slug": "victim-required", "id": "SHOPUSER", "label": "Shop User"}]
        attack_paths = {
            "attack_paths": [{"class": "cross-site-scripting", "actor": "victim-required", "target": "victim"}]
        }
        arrows, relays = compose._build_attack_arrows(attack_paths, _taxonomy(), actors, _tiers())
        assert arrows == []
        assert relays[0]["src"] == "BROWSER" and relays[0]["dst"] == "SHOPUSER"


class TestConsequenceArrowsVictimTargetingDetection:
    """Mirror dual-form detection in `_build_consequence_arrows` so the
    dashed tier→impact edges originate from the correct tier regardless
    of fragment shape."""

    def _impact_cards(self):
        return [
            {"id": "customer-session-hijack", "node_id": "HIJACK"},
            {"id": "full-server-compromise", "node_id": "COMPROMISE"},
        ]

    def test_target_victim_uses_client_tier(self):
        attack_paths = {
            "attack_paths": [
                {
                    "class": "cross-site-scripting",
                    "actor": "victim-required",
                    "target": "victim",
                    "impact": ["customer-session-hijack"],
                }
            ]
        }
        arrows = compose._build_consequence_arrows(attack_paths, self._impact_cards(), _tiers())
        assert arrows == [{"src": "BROWSER", "dst": "HIJACK"}]

    def test_target_client_actor_victim_also_uses_client_tier(self):
        """The fallback shape must also route consequence arrows from the
        client tier, not from the wrongly-interpreted ``client`` target."""
        attack_paths = {
            "attack_paths": [
                {
                    "class": "cross-site-scripting",
                    "actor": "victim-required",
                    "target": "client",
                    "impact": ["customer-session-hijack"],
                }
            ]
        }
        arrows = compose._build_consequence_arrows(attack_paths, self._impact_cards(), _tiers())
        assert arrows == [{"src": "BROWSER", "dst": "HIJACK"}]

    def test_direct_attack_routes_from_named_tier(self):
        attack_paths = {
            "attack_paths": [
                {
                    "class": "remote-code-execution",
                    "actor": "internet-anon",
                    "target": "application",
                    "impact": ["full-server-compromise"],
                }
            ]
        }
        arrows = compose._build_consequence_arrows(attack_paths, self._impact_cards(), _tiers())
        assert arrows == [{"src": "SERVER", "dst": "COMPROMISE"}]
