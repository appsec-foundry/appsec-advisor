"""One offline single-repository controller run over a small web application (`make test-controller`).

The other controller tests assess a two-line `app.py`, so the deterministic
stages between model calls never see real structure. This fixture gives them
some: a browser client calling its own Express API through a verified bearer
guard, a public login route and a route behind an unresolvable guard. The
fake host answers every model role with contract-valid replies; route
inventory, client-to-API flows, the route fill, the architecture gate,
abuse matching, rendering and publication run for real.
"""

import json
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime.analyst_host import HostReply
from runtime.assessment_host import MARKER
from validators.validate_intermediate import validate_threat_model_output

from tests.test_multi_repo_assessment import FullHost, _assess

FILES = {
    "server.js": (
        "const express = require('express')\n"
        "const permit = require('permit-guard')\n"
        "const { authenticate } = require('./lib/auth')\n"
        "const reports = require('./lib/reports')\n"
        "\n"
        "const app = express()\n"
        "\n"
        "app.get('/api/orders/:id', authenticate, (req, res) => res.json({ id: req.params.id, owner: req.user.id }))\n"
        "app.post('/rest/login', (req, res) => res.json({ user: req.body.email }))\n"
        "app.get('/rest/reports', permit.check(), reports.list())\n"
        "\n"
        "app.listen(3000)\n"
    ),
    "lib/auth.js": (
        "const jwt = require('jsonwebtoken')\n"
        "module.exports.authenticate = (req, res, next) => {\n"
        "  const token = (req.headers.authorization || '').replace('Bearer ', '')\n"
        "  try {\n"
        "    req.user = jwt.verify(token, process.env.TOKEN_PUBLIC_KEY)\n"
        "  } catch (error) {\n"
        "    return res.status(401).end()\n"
        "  }\n"
        "  next()\n"
        "}\n"
    ),
    "lib/reports.js": "module.exports.list = () => (req, res) => res.json({ query: req.query.q })\n",
    "web/src/api.ts": (
        "export const order = (http, id) => http.get(`/api/orders/${id}`)\n"
        "export const login = (http, credentials) => http.post('/rest/login', credentials)\n"
        "export const reports = (http) => http.get('/rest/reports')\n"
    ),
}


class WebApplicationHost(FullHost):
    """FullHost with a recon answer that splits the fixture into a browser client and its API."""

    def invoke(self, role, system, prompt, schema, timeout_s, should_stop):
        if role == "abuse_case_verifier":
            reply = self.verify_abuse_case(prompt)
        else:
            reply = super().invoke(role, system, prompt, schema, timeout_s, should_stop)
        artifact = reply.payload.get("artifact")
        if role == "recon_scanner" and reply.payload.get("action") == "read":
            # A component may cite only what its task read.
            reads = reply.payload["reads"]
            listed = {row["path"] for row in reads}
            rid = reads[0]["repository_id"]
            reads += [
                dict(repository_id=rid, path=path, start_line=1, end_line=2) for path in FILES if path not in listed
            ]
        if role == "actor_discoverer" and artifact:
            # The shared fake cites every read file; an actor allows four citations.
            for row in artifact.get("proposed_additional") or []:
                row["evidence"] = row["evidence"][:4]
        if role == "recon_scanner" and artifact:
            service = artifact["components"][0]
            service["paths"] = sorted({*service["paths"], "server.js", "lib/auth.js", "lib/reports.js"})
            client = dict(
                id="web",
                name="Browser client",
                description="Single-page client calling the API.",
                tier="client",
                paths=["web/src/api.ts"],
            )
            artifact["components"] = [service, client]
            artifact["interfaces"] = []
        _assert_schema_valid(role, schema, reply.payload)
        return reply

    @staticmethod
    def verify_abuse_case(prompt):
        """Every step inconclusive: a valid verdict that needs no source read."""
        context = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])["context"]
        body = context["candidate_context"]["candidate"]
        verdicts = [
            dict(
                step=row["step"],
                verdict="inconclusive",
                state="decided",
                matched_finding_id=None,
                reason="The fixture host does not judge abuse cases.",
                evidence=None,
                controls_found=[],
            )
            for row in body.get("chain") or body.get("steps") or []
        ]
        artifact = {"abuse_case_id": body["abuse_case_id"], "step_verdicts": verdicts}
        return HostReply(dict(action="complete", reads=[], artifact=artifact), 0.01)


def _assert_schema_valid(role, schema, payload):
    """A fake reply the real CLI could not produce fails here, naming the rule it broke."""
    import jsonschema

    def leaves(errors):
        for error in errors:
            if error.context:
                yield from leaves(error.context)
            else:
                yield f"{'/'.join(map(str, error.absolute_path))}: {error.validator} {str(error.validator_value)[:80]}"

    problems = sorted(set(leaves(jsonschema.Draft202012Validator(schema).iter_errors(payload))))
    assert not problems, f"fake {role} reply breaks its schema: {problems[:5]}"


def _seed(roots):
    for path, text in FILES.items():
        target = roots[0] / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)


def test_web_application_run_publishes_a_valid_model(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    outcome, _, out = _assess(tmp_path, monkeypatch, ("shop",), ("--no-pdf",), seed=_seed, host=WebApplicationHost())
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "threat-model.yaml").read_text())
    assert validate_threat_model_output(model)[0]

    # Client-to-API flows from the routes the client requests, one per proven authentication.
    client = next(c["id"] for c in model["components"] if c.get("tier") == "client")
    api = [f for f in model["data_flows"] if f.get("from") == client and f.get("provenance") == "route-extraction"]
    schemes = sorted((f.get("authentication") or {}).get("scheme", "unknown") for f in api)
    assert schemes == ["bearer", "none", "unknown"]
    # An access group keeps only members whose authentication the route fill proved.
    grouped = [f for f in api if f.get("access_group")]
    assert sorted(f["authentication"]["scheme"] for f in grouped) == ["bearer", "none"]

    head = subprocess.run(["git", "-C", str(tmp_path / "shop"), "rev-parse", "HEAD"], capture_output=True, text=True)
    assert model["meta"]["git"]["commit_sha"] == head.stdout.strip(), "the published model names its source revision"
    assert model.get("abuse_case_analysis", {}).get("status") != "not_run"
