"""Neutral producer, consumer, trust, and refutation regression evidence."""

import argparse
import copy
import json

import merge_threats as merger
import pytest
from weakness_signals import finding_signals, validate_document


@pytest.mark.parametrize(
    ("cwe", "body", "mechanism"),
    [
        ("CWE-915", "const account = Model.create(request.body)", "unrestricted-attribute-binding"),
        ("CWE-915", "record.update(params)", "unrestricted-attribute-binding"),
        ("CWE-94", "const output = eval(expression)", "application-data-as-code"),
        ("CWE-95", "answer = eval(request.json['formula'])", "application-data-as-code"),
        ("CWE-922", "localStorage.setItem('session', credentials)", "browser-readable-session-credentials"),
        ("CWE-922", "sessionStorage.getItem('access_token')", "browser-readable-session-credentials"),
        ("CWE-352", "const actor = sessions.get(request.cookies.sid)", "unprotected-cookie-mutations"),
        ("CWE-352", "account = request.session['account']", "unprotected-cookie-mutations"),
        # Database engines evaluating application values as JavaScript.
        ("CWE-94", "db.reviews.find({ $where: 'this.product == ' + id })", "application-data-as-code"),
        ("CWE-95", 'rows = collection.find({"$where": f"this.owner == {owner}"})', "application-data-as-code"),
        ("CWE-94", "Order.find().$where(filterSource)", "application-data-as-code"),
        ("CWE-94", "const out = await coll.mapReduce(mapper, reducer)", "application-data-as-code"),
        # Document queries taking their structure from application values.
        ("CWE-943", "orders.find({ $where: `this.id === '${id}'` })", "document-query-construction"),
        ("CWE-943", "users.findOne({ name: { $regex: pattern } })", "document-query-construction"),
        ("CWE-943", "const user = await User.findOne(req.body)", "document-query-construction"),
        ("CWE-943", "docs = db.items.find(request.query.filter)", "document-query-construction"),
        # Authorization requests without a state binding.
        (
            "CWE-352",
            "window.location.assign(`${provider}?client_id=${id}&response_type=code&redirect_uri=${cb}`)",
            "unbound-authorization-requests",
        ),
        (
            "CWE-352",
            'return redirect(f"{AUTH_URL}?response_type=code&client_id={CLIENT_ID}")',
            "unbound-authorization-requests",
        ),
    ],
)
def test_verified_mechanism_reaches_register(tmp_path, cwe, body, mechanism):
    source = tmp_path / "service" / "operation.ts"
    source.parent.mkdir()
    source.write_text(body + "\n")
    threat = {
        "t_id": "T-001",
        "source": "stride",
        "cwe": cwe,
        "risk": "High",
        "component_id": "service",
        "evidence_check": "verified",
        "evidence_tier": "confirmed-exploitable",
        "evidence": {"file": "service/operation.ts", "line": 1},
    }
    signals = finding_signals([threat], tmp_path)
    assert len(signals) == 1
    assert signals[0]["mechanism_id"] == mechanism
    assert signals[0]["practice_evidence"] == [{"file": "service/operation.ts", "line": 1, "id": "T-001"}]
    weaknesses = merger.build_weakness_register([threat], signals)
    assert len(weaknesses) == 1
    assert weaknesses[0]["kind"] == "implementation"
    assert weaknesses[0]["severity_basis"] == "confirmed"
    assert [i["id"] for i in weaknesses[0]["instances"]] == ["T-001"]
    assert weaknesses[0]["affected_components"] == ["service"]
    assert "cvss" not in weaknesses[0]
    for status in ("refuted", "ambiguous", "unchecked"):
        assert finding_signals([{**threat, "evidence_check": status}], tmp_path) == []
    # A safe control assessed by the verifier cannot be reintroduced by a CWE.
    assert merger.build_weakness_register([{**threat, "evidence_check": "refuted"}], []) == []


@pytest.mark.parametrize(
    ("cwe", "body"),
    [
        ("CWE-94", "const result = eval('1 + 2')"),
        ("CWE-922", "localStorage.setItem('theme', preference)"),
        ("CWE-94", "// eval(request.body.code)"),
        ("CWE-94", 'const documentation = "eval(request.body.code)"'),
        ("CWE-943", "users.findOne({ name: { $regex: '^fixed' } })"),
        ("CWE-943", 'const doc = "db.find({ $where: input })"'),
        ("CWE-943", "const rows = await sql.query(statement, [id])"),
        ("CWE-352", "location.assign(`${p}?client_id=${id}&response_type=code&state=${state}`)"),
        ("CWE-352", "const url = `${p}?client_id=${id}`"),
    ],
)
def test_safe_source_does_not_establish_claimed_mechanism(tmp_path, cwe, body):
    (tmp_path / "handler.ts").write_text(body + "\n")
    threat = {
        "t_id": "T-001",
        "source": "stride",
        "cwe": cwe,
        "evidence_check": "verified",
        "evidence": {"file": "handler.ts", "line": 1},
    }
    assert finding_signals([threat], tmp_path) == []


def test_refresh_rebuilds_and_drops_refuted_backing(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "operation.py").write_text("value = eval(expression)\n")
    output = tmp_path / "run"
    output.mkdir()
    (output / ".skill-config.json").write_text(json.dumps({"repo_root": str(repo)}))
    threat = {
        "t_id": "T-001",
        "source": "stride",
        "cwe": "CWE-94",
        "risk": "High",
        "component_id": "worker",
        "evidence_check": "verified",
        "evidence_tier": "confirmed-exploitable",
        "evidence": {"file": "operation.py", "line": 1},
    }
    path = output / ".threats-merged.json"
    path.write_text(json.dumps({"version": 1, "threats": [threat]}))
    args = argparse.Namespace(output_dir=str(output))
    assert merger.cmd_refresh_weaknesses(args) == 0
    first = json.loads(path.read_text())
    assert first["weaknesses"][0]["mechanism_id"] == "application-data-as-code"
    first["threats"][0]["evidence_check"] = "refuted"
    path.write_text(json.dumps(first))
    assert merger.cmd_refresh_weaknesses(args) == 0
    assert json.loads(path.read_text())["weaknesses"] == []
    assert json.loads((output / ".finding-design-signals.json").read_text())["design_signals"] == []


@pytest.mark.parametrize("file", ["../outside.ts", "tests/example.ts", "ui/example.spec.ts", "/outside.ts"])
def test_untrusted_or_nonproduction_location_is_not_backing(tmp_path, file):
    threat = {
        "t_id": "T-001",
        "source": "stride",
        "cwe": "CWE-94",
        "evidence_check": "verified",
        "evidence": {"file": file, "line": 1},
    }
    assert finding_signals([threat], tmp_path) == []


def test_escaping_source_symlink_is_not_followed(tmp_path):
    outside = tmp_path / "outside.ts"
    outside.write_text("eval(request.body.code)\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked.ts").symlink_to(outside)
    threat = {
        "t_id": "T-001",
        "source": "stride",
        "cwe": "CWE-94",
        "evidence_check": "verified",
        "evidence": {"file": "linked.ts", "line": 1},
    }
    assert finding_signals([threat], repo) == []


def test_schema_rejects_empty_or_malformed_backing():
    for signal in (
        {"weakness_class": "injection", "statement": "observed"},
        {
            "weakness_class": "injection",
            "statement": "observed",
            "practice_evidence": [{"file": "../escape", "line": 0}],
        },
    ):
        with pytest.raises(ValueError):
            validate_document({"version": 1, "design_signals": [signal]})


def test_unknown_cwe_practices_keep_separate_causes():
    threats = [
        {
            "t_id": f"T-00{i}",
            "source": "stride",
            "cwe": "CWE-400",
            "component_id": comp,
            "title": title,
            "evidence_tier": "insecure-practice",
            "evidence": {"file": file, "line": 1},
        }
        for i, comp, file, title in [
            (1, "pipeline", "ci/jobs.yml", "Unbounded build matrix"),
            (2, "browser", "ui/chat.ts", "Unbounded conversation history"),
        ]
    ]
    snapshot = copy.deepcopy(threats)
    weaknesses = merger.build_weakness_register(threats)
    assert len(weaknesses) == 2
    assert {w["title"] for w in weaknesses} == {t["title"] for t in snapshot}
    assert all("structural_recommendation" not in w and not w.get("instances") for w in weaknesses)


def test_same_cwe_elsewhere_does_not_join_observed_mechanism(tmp_path):
    (tmp_path / "browser.ts").write_text("localStorage.getItem('token')\n")
    browser = {
        "t_id": "T-001",
        "source": "stride",
        "cwe": "CWE-922",
        "evidence_check": "verified",
        "evidence_tier": "confirmed-exploitable",
        "evidence": {"file": "browser.ts", "line": 1},
    }
    unrelated = {**browser, "t_id": "T-002", "evidence": {"file": "backup.py", "line": 1}}
    signals = finding_signals([browser, unrelated], tmp_path)
    weaknesses = merger.build_weakness_register([browser, unrelated], signals)
    assert [i["id"] for i in weaknesses[0]["instances"]] == ["T-001"]


def test_bounded_source_sample_does_not_replace_architecture_scope():
    threat = {
        "t_id": "T-001",
        "source": "stride",
        "cwe": "CWE-79",
        "evidence_tier": "confirmed-exploitable",
        "evidence": {"file": "view.ts", "line": 10},
    }
    architecture = {
        "weakness_class": "output_xss_csp",
        "mechanism_id": "frontend-output-encoding",
        "cwe": "CWE-79",
        "statement": "Raw output",
        "absent_control_signal": ["Output encoding"],
    }
    observation = {
        **architecture,
        "absent_control_signal": [],
        "instance_ids": [],
        "practice_evidence": [{"file": "preview.ts", "line": 3}],
    }
    for signals in ([architecture, observation], [observation, architecture]):
        weaknesses = merger.build_weakness_register([threat], signals)
        assert [i["id"] for i in weaknesses[0]["instances"]] == ["T-001"]


def test_malformed_observation_stops_consumer(tmp_path):
    (tmp_path / ".impl-design-signals.json").write_text(
        '{"version":1,"design_signals":[{"weakness_class":"injection"}]}'
    )
    with pytest.raises(ValueError, match="weakness-signals"):
        merger._load_design_signals(tmp_path)


def test_finalize_invokes_source_producers_with_assigned_ids(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "calculate.py").write_text("value = eval(formula)\n")
    out = tmp_path / "run"
    out.mkdir()
    (out / ".skill-config.json").write_text(json.dumps({"repo_root": str(repo)}))
    threat = {
        "source": "stride",
        "cwe": "CWE-94",
        "risk": "High",
        "component_id": "compute",
        "title": "Application formula is evaluated as code",
        "evidence_check": "verified",
        "evidence_tier": "confirmed-exploitable",
        "evidence": {"file": "calculate.py", "line": 1},
    }
    (out / ".merge-candidates.json").write_text(json.dumps({"threats": [threat]}))
    assert merger.main(["finalize", "--output-dir", str(out)]) == 0
    document = json.loads((out / ".threats-merged.json").read_text())
    assert document["weaknesses"][0]["instances"][0]["id"] == document["threats"][0]["t_id"]
    assert document["weaknesses"][0]["mechanism_id"] == "application-data-as-code"


def test_repository_inventory_cannot_escalate_an_unrelated_mechanism(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "query.ts").write_text("db.query(`SELECT * FROM entries WHERE key=${value}`)")
    out = tmp_path / "run"
    out.mkdir()
    (out / ".skill-config.json").write_text(json.dumps({"repo_root": str(repo)}))
    signal = {
        "weakness_class": "injection",
        "mechanism_id": "blacklist-only-input-validation",
        "cwe": "CWE-20",
        "statement": "Input validation is inconsistent",
        "absent_control_signal": ["validation"],
        "affected_components": ["service", "worker"],
    }
    (out / ".arch-design-signals.json").write_text(json.dumps({"version": 1, "design_signals": [signal]}))
    weaknesses = merger.refresh_weaknesses(out, [])
    validation = next(w for w in weaknesses if w["mechanism_id"] == "blacklist-only-input-validation")
    assert validation["severity"] == "High"
    assert "implementation_strategy" not in validation
