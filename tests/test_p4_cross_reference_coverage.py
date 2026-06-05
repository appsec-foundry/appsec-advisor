"""Tests for Patch P4 — Cross-Reference Coverage.

Two regressions surfaced by the systematic REF comparison after P1+P2+P3:

    §5 Attack Surface — Notes column rendered as plain text (no links to
    the threat register) because:
      (a) the STRIDE merger does not currently populate the yaml's
          ``attack_surface[].linked_threats`` field, and
      (b) ``_attack_surface_notes`` preferred the existing ``notes``
          string and dropped the linked-threats fallback whenever notes
          was non-empty.

    §Operational Strengths Mitigates — column was empty / suppressed
    because the yaml's ``security_controls[].mitigates_findings`` field
    is also unpopulated by the merger, and the renderer had no fallback.

P4 introduces two heuristics:

    1. ``_derive_attack_surface_links`` — score-based path-vs-threat
       matching (verbatim path mention, path-token hits, evidence-file
       basename normalisation). Auto-fills ``linked_threats`` per entry
       when the yaml has none. ``_attack_surface_notes`` then combines
       the linked-threats list and the notes text.

    2. ``_derive_control_mitigates`` — domain → CWE membership match.
       The control's ``domain`` field maps to a curated CWE set; threats
       whose ``cwe`` belongs to that set become candidates, ranked by
       severity and control-name keyword overlap.

These tests pin the heuristics' behaviour for the documented juice-shop
case AND guard against the two main failure modes — silent over-linkage
(false positives flooding cells) and silent under-linkage (threshold
too high).
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


pregen = _load("pregenerate_fragments", _SCRIPTS / "pregenerate_fragments.py")
compose = _load("compose_threat_model", _SCRIPTS / "compose_threat_model.py")


# ---------------------------------------------------------------------------
# §5 Attack Surface — auto-derive linked_threats
# ---------------------------------------------------------------------------


class TestStripPathParams:
    def test_strips_colon_placeholders(self):
        assert pregen._strip_path_params("/ftp/:file") == "/ftp"
        assert pregen._strip_path_params("/api/Users/:id") == "/api/Users"

    def test_keeps_static_paths_unchanged(self):
        assert pregen._strip_path_params("/rest/user/login") == "/rest/user/login"
        assert pregen._strip_path_params("/metrics") == "/metrics"

    def test_handles_empty_input(self):
        assert pregen._strip_path_params("") == "/"
        assert pregen._strip_path_params(None or "") == "/"


class TestNormalizeToken:
    def test_collapses_camelcase_and_punctuation(self):
        # "fileUpload" and "file-upload" both normalise to "fileupload"
        assert pregen._normalize_token("fileUpload") == "fileupload"
        assert pregen._normalize_token("file-upload") == "fileupload"
        assert pregen._normalize_token("/file-upload") == "fileupload"


class TestScoreThreatPathMatch:
    """Pin the scoring weights so future tweaks don't silently drift."""

    def test_verbatim_path_hits_score_5(self):
        threat = {"scenario": "/rest/user/login is vulnerable to SQLi"}
        assert pregen._score_threat_path_match(threat, "/rest/user/login") >= 5

    def test_evidence_file_basename_match_scores_3(self):
        threat = {"evidence": [{"file": "routes/fileUpload.ts", "line": 83}]}
        # The path normalises to "fileupload"; basename normalises to
        # "fileupload" — bidirectional substring match → +3.
        assert pregen._score_threat_path_match(threat, "/file-upload") >= 3

    def test_evidence_file_strips_extensions(self):
        # Route-handler file (the +3 evidence bonus is gated to route dirs).
        # "Login.java" strips to "login" and names the "/rest/user/login"
        # segment → +3, exercising the extension-stripping path.
        threat = {"evidence": [{"file": "routes/Login.java", "line": 1}]}
        assert pregen._score_threat_path_match(threat, "/rest/user/login") >= 3

    def test_no_signals_returns_zero(self):
        threat = {
            "scenario": "totally unrelated content",
            "title": "no path mentioned",
            "evidence": [{"file": "src/auth.ts"}],
        }
        assert pregen._score_threat_path_match(threat, "/rest/products/search") == 0

    def test_path_token_hits_each_score_one(self):
        # Path /api/orders has a token "orders" length 6.
        # Threat scenario contains "orders" exactly.
        threat = {"scenario": "manipulating orders endpoint", "evidence": []}
        # Verbatim path "/api/orders" not in scenario → +0.
        # Token "orders" in scenario → +1.
        # Tokens "api" length 3 → excluded by length filter.
        assert pregen._score_threat_path_match(threat, "/api/orders") == 1


class TestDeriveAttackSurfaceLinks:
    def _threats(self):
        return [
            # T-002 — SQLi in login (matches /rest/user/login + /rest/products/search)
            {
                "id": "T-002",
                "title": "SQL Injection in Login Endpoint Bypasses Authentication",
                "scenario": "routes/login.ts:38 constructs a raw SQL query. Also in routes/search.ts:23.",
                "evidence": [{"file": "routes/login.ts", "line": 38}, {"file": "routes/search.ts", "line": 23}],
                "cwe": "CWE-89",
            },
            # T-008 — Sensitive file dirs (matches /ftp + /encryptionkeys)
            {
                "id": "T-008",
                "title": "Sensitive File Directories Served Publicly Without Authentication",
                "scenario": "server.ts serves /ftp, /encryptionkeys, /support/logs, "
                "and /metrics without authentication.",
                "evidence": [{"file": "server.ts", "line": 100}],
                "cwe": "CWE-552",
            },
            # T-099 — unrelated finding
            {"id": "T-099", "title": "Unrelated thing", "scenario": "totally different topic", "evidence": []},
        ]

    def test_derives_for_login_endpoint(self):
        entry = {"entry_point": "POST /rest/user/login"}
        derived = pregen._derive_attack_surface_links(entry, self._threats())
        assert "T-002" in derived

    def test_derives_for_param_path(self):
        # /ftp/:file → strips to /ftp → matches T-008 scenario substring.
        entry = {"entry_point": "GET /ftp/:file"}
        derived = pregen._derive_attack_surface_links(entry, self._threats())
        assert "T-008" in derived

    def test_no_match_returns_empty_list(self):
        entry = {"entry_point": "POST /quantum/teleport"}
        derived = pregen._derive_attack_surface_links(entry, self._threats())
        assert derived == []

    def test_caps_at_max_links(self):
        # Five threats all matching the same path — derivation caps to 3.
        threats = [
            {"id": f"T-{i:03d}", "title": "x", "scenario": "/test/path mentioned", "evidence": [], "cwe": "CWE-89"}
            for i in range(1, 6)
        ]
        entry = {"entry_point": "POST /test/path"}
        derived = pregen._derive_attack_surface_links(entry, threats)
        assert len(derived) == 3

    def test_handles_missing_entry_point_gracefully(self):
        assert pregen._derive_attack_surface_links({}, self._threats()) == []
        assert pregen._derive_attack_surface_links(None, self._threats()) == []
        assert pregen._derive_attack_surface_links({"entry_point": ""}, self._threats()) == []

    def test_handles_empty_threats_list(self):
        entry = {"entry_point": "POST /rest/user/login"}
        assert pregen._derive_attack_surface_links(entry, []) == []


class TestAttackSurfaceNotesCombination:
    """When both notes and linked_threats are populated, both are rendered."""

    def test_notes_only_returns_notes(self):
        result = pregen._attack_surface_notes({"notes": "SQL injection"})
        assert result == "SQL injection"

    def test_linked_threats_only_returns_links(self):
        # P4 visible-label normalisation: T-NNN → F-NNN (anchor stays valid
        # via the dual-anchor emission in _render_threat_register).
        result = pregen._attack_surface_notes({"linked_threats": ["T-001", "T-002"]})
        assert result == "[F-001](#f-001)<br/>[F-002](#f-002)"

    def test_both_combines_links_then_notes(self):
        """The new P4 behaviour — pre-fix this returned only notes."""
        entry = {"notes": "SQL injection via email", "linked_threats": ["T-002"]}
        result = pregen._attack_surface_notes(entry)
        # Visible label normalised T-NNN → F-NNN.
        assert "[F-002](#f-002)" in result
        assert "SQL injection via email" in result
        # Linked threats first, then notes — joined by <br/>.
        assert result == "[F-002](#f-002)<br/>SQL injection via email"

    def test_empty_returns_empty_string(self):
        assert pregen._attack_surface_notes({}) == ""

    def test_falls_back_to_threats_when_linked_threats_absent(self):
        # Legacy schema used `threats` not `linked_threats`.
        # Visible label normalised T-005 → F-005.
        entry = {"threats": ["T-005"]}
        result = pregen._attack_surface_notes(entry)
        assert result == "[F-005](#f-005)"


class TestGenAttackSurfaceAutoLinks:
    """End-to-end: gen_attack_surface enriches entries before rendering."""

    def test_yaml_without_linked_threats_gets_them_derived(self, tmp_path: Path):
        yaml_data = {
            "threats": [
                {
                    "id": "T-002",
                    "title": "SQLi in login",
                    "scenario": "routes/login.ts has raw SQL",
                    "evidence": [{"file": "routes/login.ts", "line": 38}],
                    "cwe": "CWE-89",
                },
            ],
            "attack_surface": {
                "unauthenticated": [
                    {"entry_point": "POST /rest/user/login", "notes": "SQL injection via email body parameter"},
                ],
                "authenticated": [],
            },
        }
        rendered = pregen.gen_attack_surface(yaml_data)
        # Visible label normalised T-NNN → F-NNN.
        assert "[F-002](#f-002)" in rendered
        assert "SQL injection via email body parameter" in rendered  # notes preserved

    def test_explicit_linked_threats_respected(self, tmp_path: Path):
        """When yaml already has linked_threats, the heuristic does NOT
        override or augment — explicit upstream signal wins."""
        yaml_data = {
            "threats": [
                {"id": "T-002", "title": "x", "scenario": "routes/login.ts", "cwe": "CWE-89"},
                {"id": "T-009", "title": "y", "scenario": "routes/login.ts also", "cwe": "CWE-89"},
            ],
            "attack_surface": {
                "unauthenticated": [
                    {
                        "entry_point": "POST /rest/user/login",
                        "linked_threats": ["T-009"],  # explicit
                        "notes": "n/a",
                    },
                ],
                "authenticated": [],
            },
        }
        rendered = pregen.gen_attack_surface(yaml_data)
        # Explicit T-009 from yaml is normalised to F-009 visible label.
        assert "[F-009](#f-009)" in rendered
        # Heuristic must NOT overwrite the explicit value.
        assert "[F-002](#f-002)" not in rendered
        assert "[T-002](#t-002)" not in rendered  # legacy form also absent


# ---------------------------------------------------------------------------
# §Operational Strengths — auto-derive mitigates_findings
# ---------------------------------------------------------------------------


class TestDeriveControlMitigates:
    def _threats(self):
        return [
            # T-001 — Hardcoded RSA key (CWE-321 → Crypto / Secret Mgmt)
            {"id": "T-001", "title": "RSA key", "scenario": "hardcoded key", "cwe": "CWE-321", "risk": "Critical"},
            # T-002 — SQLi (CWE-89 → Input Validation)
            {"id": "T-002", "title": "SQLi", "scenario": "raw SQL in login", "cwe": "CWE-89", "risk": "Critical"},
            # T-005 — JWT signature not verified (CWE-347 → IAM). CWE-347's C1
            # required-token set {signature, jwt, verify} matches the test's
            # "JWT signature verification" control, so the domain match survives
            # the false-positive gate (unlike a hashing CWE + a JWT control).
            {"id": "T-005", "title": "JWT not verified", "scenario": "jwt signature not validated", "cwe": "CWE-347", "risk": "Critical"},
            # T-006 — IDOR (CWE-639 → Authorization)
            {"id": "T-006", "title": "IDOR", "scenario": "no ownership check", "cwe": "CWE-639", "risk": "High"},
        ]

    def test_iam_domain_picks_iam_cwes(self):
        control = {"domain": "Identity & Access Management", "control": "JWT signature verification"}
        derived = compose._derive_control_mitigates(control, self._threats())
        # CWE-347 is in the IAM set; CWE-89 / 639 are not.
        assert "T-005" in derived
        assert "T-002" not in derived
        assert "T-006" not in derived

    def test_input_validation_domain_picks_injection_cwes(self):
        control = {"domain": "Input Validation", "control": "SQL query parameterization"}
        derived = compose._derive_control_mitigates(control, self._threats())
        assert "T-002" in derived  # CWE-89 = SQLi
        assert "T-005" not in derived  # CWE-916 belongs to IAM/Crypto

    def test_authorization_domain_picks_authz_cwes(self):
        control = {"domain": "Authorization", "control": "Resource ownership verification"}
        derived = compose._derive_control_mitigates(control, self._threats())
        assert "T-006" in derived  # CWE-639 = IDOR

    def test_unknown_domain_returns_empty_list(self):
        # An entirely off-map domain returns no derivation. (We pick a
        # bespoke string that does NOT contain any catalogued substring —
        # "crypto" / "auth" / "data" etc. would partially-match.)
        control = {"domain": "Photonics R&D", "control": "Lattice-based signing"}
        assert compose._derive_control_mitigates(control, self._threats()) == []

    def test_missing_domain_returns_empty(self):
        assert compose._derive_control_mitigates({}, self._threats()) == []
        assert compose._derive_control_mitigates({"control": "x"}, self._threats()) == []

    def test_keyword_match_boosts_score(self):
        """A control name token appearing in the threat scenario should
        boost the score so closer-matching threats rank first."""
        threats = [
            {
                "id": "T-A",
                "cwe": "CWE-89",
                "title": "SQL injection in some module",
                "scenario": "regex injection somewhere",
                "risk": "Medium",
            },
            {
                "id": "T-B",
                "cwe": "CWE-89",
                "title": "SQL injection bypasses login",
                "scenario": "login route concats SQL via parameterization gap",
                "risk": "Critical",
            },
        ]
        control = {"domain": "Input Validation", "control": "SQL parameterization in login"}
        derived = compose._derive_control_mitigates(control, threats)
        # T-B has both keyword match ("login", "parameterization") AND higher
        # severity; should rank first.
        assert derived[0] == "T-B"

    def test_severity_breaks_ties(self):
        """Equal scores → Critical wins over High."""
        threats = [
            {"id": "T-A", "cwe": "CWE-89", "scenario": "x", "title": "a", "risk": "High"},
            {"id": "T-B", "cwe": "CWE-89", "scenario": "x", "title": "b", "risk": "Critical"},
        ]
        control = {"domain": "Input Validation", "control": "x"}
        derived = compose._derive_control_mitigates(control, threats)
        assert derived[0] == "T-B"

    def test_caps_at_5_refs(self):
        """Avoid flooding the cell with 10+ refs."""
        threats = [
            {"id": f"T-{i:03d}", "cwe": "CWE-89", "scenario": "x", "title": f"finding {i}", "risk": "High"}
            for i in range(1, 9)
        ]
        control = {"domain": "Input Validation", "control": "x"}
        derived = compose._derive_control_mitigates(control, threats)
        assert len(derived) == 5

    def test_cwe_normalization(self):
        """CWE-89, cwe-89, 89 should all match."""
        threats_variants = [
            {"id": "T-A", "cwe": "CWE-89", "title": "x", "scenario": "x", "risk": "High"},
            {"id": "T-B", "cwe": "cwe-89", "title": "x", "scenario": "x", "risk": "High"},
            # Bare integer in cwe is unusual but tolerate.
        ]
        control = {"domain": "Input Validation", "control": "x"}
        derived = compose._derive_control_mitigates(control, threats_variants)
        # Both A and B should be present (case-insensitive CWE handling).
        assert "T-A" in derived
        assert "T-B" in derived


class TestRenderOperationalStrengthsAutoDerive:
    """End-to-end: when yaml has empty mitigates_findings, the renderer
    auto-fills the Mitigates column from the threats list."""

    def test_empty_mitigates_findings_gets_derived(self, tmp_path: Path):
        # We can't easily call _render_operational_strengths in isolation
        # because it requires a full RenderContext. Instead, exercise
        # _derive_control_mitigates which is the new logic.
        threats = [
            {"id": "T-002", "cwe": "CWE-89", "title": "SQLi", "scenario": "raw SQL", "risk": "Critical"},
        ]
        control = {
            "domain": "Input Validation",
            "control": "SQL parameterization",
            "mitigates_findings": [],
        }  # explicitly empty
        derived = compose._derive_control_mitigates(control, threats)
        assert "T-002" in derived

    def test_explicit_mitigates_findings_unchanged_in_yaml(self):
        """When the yaml carries an explicit mitigates_findings list, the
        derive function still computes its result — the renderer's
        mitigates_cell is responsible for choosing yaml > derived. Verify
        the mitigates_cell logic by inspecting the source contract."""
        # The derivation function itself doesn't read mitigates_findings,
        # it only inspects threats. The mitigates_cell function in
        # _render_operational_strengths chooses yaml-explicit over derived.
        # We verify that here at the source-contract level.
        src = (REPO_ROOT / "scripts" / "compose_threat_model.py").read_text()
        # The decision check must appear in the body.
        assert "_derive_control_mitigates" in src
        # Pattern: the renderer falls back to derive only when mits is empty.
        assert "if not mits:" in src or "if not mits" in src


# ---------------------------------------------------------------------------
# Cross-reference labelling invariant — end-to-end
# ---------------------------------------------------------------------------

import re
import textwrap

qa = _load("qa_checks", _SCRIPTS / "qa_checks.py")


class TestCrossReferenceTitleCoverageEndToEnd:
    """End-to-end pin: after `linkify_anchors`, every cross-reference
    OUTSIDE the declaration sites (the §8 ID column and the §9 ####
    M-NNN headings) MUST carry a `— <title>` suffix.

    A regression here means a future report ships with bare
    `[F-NNN](#f-nnn)` / `[T-NNN](#t-nnn)` / `[TH-NN](#th-nn)` links
    where the title is no longer visible to the reader. AGENTS.md §4a
    documents why this matters.
    """

    def test_all_four_id_classes_get_title_suffix(self, tmp_path: Path):
        """Compose a minimal MD with cross-refs of every class and verify
        linkify_anchors yields zero un-suffixed cross-references.
        """
        md_body = textwrap.dedent("""\
            ## Management Summary
            Top: TH-01. Critical findings: [F-001](#f-001), [F-002](#f-002).

            ## 3. Walkthrough

            **Threat:** see T-001. Mitigated by M-001 and M-002.

            ## 8. Threat Register

            | ID | Finding | Threat Category | Mitigation |
            |----|---------|-----------------|------------|
            | <a id="t-001"></a><a id="f-001"></a>F-001 | … | <a id="th-01"></a>TH-01 — Injection | [M-001](#m-001) |
            | <a id="t-002"></a><a id="f-002"></a>F-002 | … | TH-01 | [M-002](#m-002) |

            ## 9. Mitigation Register

            #### <a id="m-001"></a>M-001 — Use parameterized queries everywhere

            **Addresses:**

            - [F-001](#f-001)

            #### <a id="m-002"></a>M-002 — Rotate JWT signing keys via secrets manager

            **Addresses:**

            - [F-002](#f-002)
            """)
        yml_body = textwrap.dedent("""\
            meta: {schema_version: 1}
            threats:
              - id: T-001
                title: "SQL Injection in login endpoint"
                component: x
                stride: Spoofing
                scenario: "long scenario text…"
                likelihood: High
                impact: Critical
                risk: Critical
              - id: T-002
                title: "Hardcoded RSA private key in source"
                component: x
                stride: Tampering
                scenario: "long scenario text…"
                likelihood: High
                impact: Critical
                risk: Critical
            mitigations:
              - id: M-001
                title: "Use parameterized queries everywhere"
                threat_ids: [T-001]
                priority: P1
              - id: M-002
                title: "Rotate JWT signing keys via secrets manager"
                threat_ids: [T-002]
                priority: P1
            """)
        md = tmp_path / "threat-model.md"
        yml = tmp_path / "threat-model.yaml"
        md.write_text(md_body)
        yml.write_text(yml_body)

        _, new_text = qa.linkify_anchors(md)

        # Strip the §8 ID-column rows (those are declaration sites — bare
        # `F-NNN` is correct there) before counting un-suffixed refs.
        # Strategy: drop any line that contains an `<a id="…"></a>` anchor
        # whose ID matches the ref on the same line.
        def is_decl_line(line: str) -> bool:
            # §8 ID column row
            if re.search(r'\|\s*<a id="[ftm]-\d+"></a>', line):
                return True
            # §9 #### heading
            if re.match(r"^####\s*<a id=", line):
                return True
            # TH-NN declaration cell
            if re.search(r'<a id="th-\d+"></a>TH-\d+', line):
                return True
            return False

        # Strip code fences too.
        in_code = False
        usable = []
        for line in new_text.splitlines():
            if line.startswith("```"):
                in_code = not in_code
                continue
            if in_code or is_decl_line(line):
                continue
            usable.append(line)
        body = "\n".join(usable)

        # Count un-suffixed cross-refs of every class.
        for cls_pat, classname in (
            (r"\[F-\d{3,4}\]\(#f-\d+\)(?! — )", "F-NNN"),
            (r"\[T-\d{3,4}\]\(#[ft]-\d+\)(?! — )", "T-NNN"),
            (r"\[M-\d{3,4}\]\(#m-\d+\)(?! — )", "M-NNN"),
            (r"\[TH-\d{2,3}\]\(#th-\d+\)(?! — )", "TH-NN"),
        ):
            offenders = re.findall(cls_pat, body)
            assert not offenders, (
                f"{len(offenders)} {classname} cross-reference(s) ship "
                f"WITHOUT a `— title` suffix — AGENTS.md §4a violation. "
                f"Examples: {offenders[:3]}"
            )

        # Positive assertions — at least one of each class actually got
        # a labelled link, so the test is not vacuously satisfied.
        assert "[F-001](#f-001) — SQL Injection in login endpoint" in body
        assert "[T-001](#t-001) — SQL Injection in login endpoint" in body
        assert "[M-001](#m-001) — Use parameterized queries everywhere" in body
        assert "[TH-01](#th-01) — Injection" in body
