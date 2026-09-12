"""Console verdict: a weakness-class tag replaces each bullet's finding-reference clause."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "render_completion_summary.py"


def _load_module():
    if "render_completion_summary" in sys.modules:
        return sys.modules["render_completion_summary"]
    spec = importlib.util.spec_from_file_location("render_completion_summary", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["render_completion_summary"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rcs = _load_module()

_TAXONOMY = {
    "cwes": {
        "CWE-1": {"title": "Improper Neutralization in a Query (Query Injection)"},
        "CWE-2": {"title": "Path Traversal"},
        "CWE-3": {"title": "Improper Output Encoding (XSS)"},
    }
}


def _plugin_root(tmp_path: Path) -> Path:
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "cwe-taxonomy.yaml").write_text(yaml.safe_dump(_TAXONOMY), encoding="utf-8")
    return tmp_path


def _bullet(body: str, refs: str) -> str:
    return f"- **Customer data exposed** — {body} *({refs} → [W-003](#w-003))* — ✓ verified attack path"


def test_labels_follow_the_cwe_short_name_rule(tmp_path):
    labels = rcs._verdict_class_labels(
        [
            {"id": "T-011", "cwe": "CWE-1"},
            {"id": "T-012", "cwe": "CWE-2"},
            {"id": "T-013", "cwe": ["CWE-3", "CWE-3"]},
            {"id": "T-014", "cwe": "CWE-999"},
            {"id": "T-015"},
            "not-a-threat",
        ],
        _plugin_root(tmp_path),
    )
    assert labels == {"F-011": ["Query Injection"], "F-012": ["Path Traversal"], "F-013": ["XSS"]}


def test_missing_taxonomy_yields_no_labels(tmp_path):
    assert rcs._verdict_class_labels([{"id": "T-011", "cwe": "CWE-1"}], tmp_path) == {}


def test_clause_becomes_a_class_tag_before_the_badge():
    line = _bullet(
        "Anyone can dump every record.", "🔴 [F-011](#f-011) — Query built from input (`src/db/search.ts:23`)"
    )
    out = rcs._strip_verdict_refs(line, {"F-011": ["Query Injection"]})
    assert out == (
        "- **Customer data exposed** — Anyone can dump every record. (Query Injection) — ✓ verified attack path"
    )


def test_tag_is_left_out_when_the_bullet_already_names_the_class():
    line = _bullet("Query injection lets anyone dump every record.", "🔴 [F-011](#f-011)")
    assert rcs._strip_verdict_refs(line, {"F-011": ["Query Injection"]}) == rcs._strip_verdict_refs(line)


def test_labels_of_several_refs_are_deduplicated_in_order():
    line = _bullet("Anyone can dump every record.", "🔴 [F-011](#f-011), 🔴 [F-012](#f-012), 🟠 [F-013](#f-013)")
    labels = {"F-011": ["Query Injection"], "F-012": ["Query Injection", "Path Traversal"], "F-013": ["XSS"]}
    assert "(Query Injection, Path Traversal, XSS)" in rcs._strip_verdict_refs(line, labels)


def test_without_labels_the_clause_is_only_dropped():
    line = _bullet("Anyone can dump every record.", "🔴 [F-011](#f-011)")
    assert rcs._strip_verdict_refs(line) == (
        "- **Customer data exposed** — Anyone can dump every record. — ✓ verified attack path"
    )


def test_summary_tags_bullets_from_the_run_yaml(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    (out / "threat-model.md").write_text(
        "# Threat Model\n\n## Management Summary\n\n### Verdict\n\n🔴 Not production-ready.\n\n"
        + _bullet("Anyone can dump every record.", "🔴 [F-011](#f-011)")
        + "\n\n### Security Posture & Top Threats\n\nNot part of the verdict.\n",
        encoding="utf-8",
    )
    threats = [{"id": "T-011", "cwe": "CWE-89", "title": "Query built from input", "risk": "Critical"}]
    model = {"meta": {"schema_version": 1}, "threats": threats, "mitigations": [], "components": []}
    (out / "threat-model.yaml").write_text(yaml.safe_dump(model), encoding="utf-8")
    expected = rcs._verdict_class_labels(threats, REPO_ROOT)["F-011"]
    r = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--output-dir", str(out), "--repo-root", str(out), "--mode", "full"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    assert f"Anyone can dump every record. ({', '.join(expected)})" in r.stdout
