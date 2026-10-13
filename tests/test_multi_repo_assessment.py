"""A combined assessment runs every stage through scoped exchanges and publishes one model."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from orchestrator import orchestration_controller as controller
from runtime.analyst_host import HostReply
from runtime.assessment_host import MARKER

from tests.test_assessment_posture import Discoverer
from tests.test_multi_repo_controller import BoundaryHost, Host, checkout


class FullHost:
    """Contract-valid replies for every semantic role of a combined assessment."""

    def __init__(self):
        self.scope = None
        self.roles = []

    def factory(self, role, model, ceiling):
        self.roles.append(role)
        owner = self

        class Transport:
            def invoke(self, system, prompt, schema, timeout_s, should_stop):
                return owner.invoke(role, system, prompt, schema, timeout_s, should_stop)

        return Transport()

    def invoke(self, role, system, prompt, schema, timeout_s, should_stop):
        if role == "trust_boundary_analyst":
            return BoundaryHost().invoke(system, prompt, schema, timeout_s, should_stop)
        if role == "post_stride_synthesizer":
            artifact = {"schema_version": 1, "tier_root_causes": {"server": ["Unvalidated request input"]}}
            return HostReply(dict(action="complete", reads=[], artifact=artifact), 0.01)
        if role in ("abuse_case_deriver", "architect_reviewer"):
            context = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])["context"]
            if role == "abuse_case_deriver":
                artifact = {"cases": []}
            else:
                from tests.test_architect_review_runtime import answer

                artifact = {
                    "schema_version": 1,
                    "job_id": context["job_id"],
                    "proposals": {packet["packet_id"]: answer(packet) for packet in context["packets"]},
                }
            return HostReply(dict(action="complete", reads=[], artifact=artifact), 0.01)
        if role == "actor_discoverer":
            return Discoverer(line=2).invoke(role, prompt)
        if role in ("ms_renderer", "secarch_renderer"):
            context = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])["context"]
            return HostReply(dict(action="complete", reads=[], artifact=self.stage2(role, context)), 0.01)
        reply = Host(self.scope).invoke(role, prompt)
        artifact = reply.payload.get("artifact")
        if role == "architecture_analyst" and artifact and "assets" in artifact:
            packet = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])
            component = packet["context"]["components"][0]
            path = component["paths"][0]
            artifact["assets"].append(
                dict(
                    id="asset-records",
                    name="Record data",
                    classification="Confidential",
                    description="Records the service reads and returns.",
                    component_refs=[
                        dict(
                            component_id=component["id"],
                            relation="processed",
                            evidence=[
                                dict(
                                    repository_id=path["repository_id"],
                                    file=path["path"],
                                    line=2,
                                    sha256=path["sha256"],
                                )
                            ],
                        )
                    ],
                )
            )
        return reply

    @staticmethod
    def stage2(role, context):
        if "requirements" in context:
            rows = [
                {
                    "id": row["id"],
                    "title": str(row.get("title") or row["id"])[:120],
                    "status": "UNVERIFIABLE",
                    "evidence": "The retrieved request handlers do not show this control.",
                    "finding_ids": [],
                }
                for row in context["requirements"]
            ]
            return {"summary": "No requirement is shown as met by the retrieved code.", "rows": rows}
        if role == "secarch_renderer":
            fills = []
            for row in context["placeholders"]:
                if row["optional"]:
                    text = ""
                elif row["mermaid"]:
                    text = (
                        "The diagram shows the request path:\n```mermaid\nsequenceDiagram\n"
                        "  Edge->>Service: request records\n  Service-->>Edge: records\n```"
                    )
                elif row["inline"]:
                    text = "🟠 Partial — the handler reads request input without validation."
                else:
                    text = "The service reads request parameters directly in its handler."
                fills.append({"id": row["id"], "text": text})
            return {"fills": fills}
        digest = context["digest"] if "digest" in context else context
        refs = [row["ref"] for row in digest["findings"] + digest["other_findings"]]
        verdict = {
            "severity": digest["verdict"]["severity"],
            "opening": "The combined system accepts unvalidated request input in both of its services, "
            "which lets a caller submit malformed records.",
            "bullets": [
                {
                    "title": "Unvalidated request input",
                    "body": "Both request handlers read parameters directly without checking their type.",
                    "refs": refs[:2],
                }
            ],
            "closing": "Validate request input at each handler before the services exchange records.",
        }
        attack_paths = {
            "schema_version": 1,
            "actors": ["internet-anon"],
            "attack_paths": [
                {
                    "class": "injection",
                    "actor": "internet-anon",
                    "target": "data",
                    "scenario_title": "Malformed records reach the service",
                    "description": "Unvalidated input lets a caller submit records the service does not expect.",
                    "findings": refs[:1],
                    "impact": ["customer-data-exfiltration"],
                }
            ],
        }
        return {"verdict": verdict, "attack_paths": attack_paths, "anti_patterns": None}


def _assess(tmp_path, monkeypatch, names, extra=(), seed=None, progress=lambda text: None):
    from runtime import multi_repo_scope

    roots = [tmp_path / name for name in names]
    for root in roots:
        checkout(root)
    if seed:
        seed(roots)
    host = FullHost()
    real_admit = multi_repo_scope.admit

    def admit(selections, output, **options):
        host.scope = real_admit(selections, output, **options)
        return host.scope

    monkeypatch.setattr(multi_repo_scope, "admit", admit)
    # Concurrent plugin edits must not abort the test run; runtime binding has its own tests.
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: "a" * 64)
    outcome = controller.assess_repositories(
        [
            *[arg for root in roots for arg in ("--repo", str(root))],
            "--output",
            str(tmp_path / "out"),
            "--hard-budget",
            "5",
            "--trust-mode",
            "trusted",
            "--model",
            "haiku",
            *extra,
        ],
        host_factory=host.factory,
        progress=progress,
    )
    return outcome, host, tmp_path / "out"


def test_one_repository_takes_the_combined_path_only_when_switched_on(tmp_path, monkeypatch):
    for part in ("off", "on"):
        (tmp_path / part).mkdir()
    monkeypatch.delenv("APPSEC_SINGLE_REPO_CONTROLLER", raising=False)
    with pytest.raises(controller.CallError, match="at least two"):
        _assess(tmp_path / "off", monkeypatch, ("solo",))
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    seen = []
    monkeypatch.setattr(controller, "_assessment_architecture", lambda scope, *a, **k: seen.append(scope) or 1 / 0)
    with pytest.raises(ZeroDivisionError):
        _assess(tmp_path / "on", monkeypatch, ("solo",))
    (scope,) = seen
    assert [row["label"] for row in scope.inventory()["repositories"]] == ["solo"]
    scope.verify_unchanged()


@pytest.mark.parametrize(("names", "depth"), [(("edge", "service"), "standard"), (("west", "east"), "thorough")])
def test_combined_assessment_publishes_one_qualified_model(tmp_path, monkeypatch, names, depth):
    outcome, host, out = _assess(tmp_path, monkeypatch, names, ("--assessment-depth", depth))
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "threat-model.yaml").read_text())
    assert model["meta"]["schema_version"] == 2
    labels = {row["label"] for row in model["source_inventory"]["repositories"]}
    assert labels == set(names)
    owners = {row["repository_id"] for t in model["threats"] for row in t.get("evidence") or []}
    assert owners == {row["repository_id"] for row in model["source_inventory"]["repositories"]}
    report = (out / "threat-model.md").read_text()
    for name in names:
        assert f"{name}/app.py" in report
        assert f"[{name}]" in report
    assert report.startswith(f"# Threat Model - Combined system ({len(names)} repositories)")
    assert f"together as one system ({', '.join(sorted(names))})" in report
    assert "**Repositories:**" in report and "github.com" not in report.split("## 2.")[0]
    figure = (out / "threat-model.figure1.svg").read_text()
    assert all(f"[{name}]" in figure for name in names)
    # The published model never names a workspace or combined-root path.
    text = (out / "threat-model.yaml").read_text()
    assert ".assessment-work" not in text and "appsec-combined-" not in text
    assert not (out / ".assessment-work" / "render").exists()
    assert "trust_boundary_analyst" in host.roles and "post_stride_synthesizer" in host.roles
    assert {"actor_discoverer", "ms_renderer", "secarch_renderer"} <= set(host.roles)
    assert ({"architect_reviewer", "abuse_case_deriver"} <= set(host.roles)) == (depth == "thorough")
    assert not list(out.glob("threat-model-*"))


def test_default_console_shows_phases_counts_and_stalls_not_call_detail(monkeypatch):
    lines = []
    console = controller._AssessmentConsole(False, lines.append)
    console.step("Models: sonnet (stride_analyzer)")
    console.step("Discovering every selected repository")
    console.call("reads app/server.ts:1-200 (3 s)")
    console.step("Reviewing trust crossing: signal-external-ingress-0123abcd (1/3)")
    console.step("Analyzing all STRIDE categories: API (1/2)")
    console.call("1 min: no model activity for 95 s (waiting for the API)")
    console.step("Independently verifying evidence: API")
    console.step("Analyzing all STRIDE categories: Store (2/2)")
    monkeypatch.setattr(console, "HEARTBEAT_SECONDS", 0)
    console.call("2 min: model is thinking (~9,000 tokens)")
    console.step("Stage 2: Management Summary")
    console.close()
    assert lines[:2] == [f"   Pipeline: {console.PIPELINE}", "▶ Models: sonnet (stride_analyzer)"]
    # Phase lines carry the run's estimated share and elapsed time, as the single-repository view does.
    assert [line.split(" · ~")[0] for line in lines if line.startswith("▶ Phase")] == [
        "▶ Phase 2/11 · Reconnaissance",
        "▶ Phase 7/11 · Trust Boundaries",
        "▶ Phase 9/11 · STRIDE",
        "▶ Phase 11/11 · Finalization",
    ]
    assert "▶ Phase 9/11 · STRIDE · ~27%   [+<1m total]" in lines
    assert sum(line.startswith("    ✓ Phase") for line in lines) == 4
    # The component or section in work is named; a crossing's signal hash is not.
    for shown in (
        "    · trust crossing 1 of 3 · ~10%",
        "    · API (1/2) · ~27%",
        "    · Store (2/2) · ~54%",
        "    · report section: Management Summary",
        "    · still in Phase 9/11 STRIDE — <1m · ~54%   [+<1m total]",
    ):
        assert shown in lines
    assert "    ⚠ 1 min: no model activity for 95 s (waiting for the API)" in lines
    assert not any("reads " in line or "signal-" in line or "verifying evidence" in line for line in lines)
    # --verbose keeps every step and call line and adds no phase summary.
    verbose = []
    console = controller._AssessmentConsole(True, verbose.append)
    console.step("Discovering every selected repository")
    console.call("reads app/server.ts:1-200 (3 s)")
    console.close()
    assert verbose == ["▶ Discovering every selected repository", "  · reads app/server.ts:1-200 (3 s)"]


@pytest.mark.parametrize("names", [("edge", "service"), ("west", "east")])
def test_per_call_progress_lines_reach_the_end_of_a_combined_run(tmp_path, monkeypatch, capsys, names):
    """Calls made after the workspace exists, such as the report renderers, still label their reads."""
    outcome, host, _ = _assess(tmp_path, monkeypatch, names, ("--verbose",), progress=None)
    assert outcome["status"] == "complete" and "ms_renderer" in host.roles
    lines = [line for line in capsys.readouterr().err.splitlines() if line.startswith("  · reads ")]
    assert lines and any(f"{name}/" in line for line in lines for name in names)


@pytest.mark.parametrize(("names", "target"), [(("edge", "service"), "nowhere"), (("west", "east"), "ghost-api")])
def test_a_declaration_naming_no_component_stops_before_any_boundary_job(tmp_path, monkeypatch, names, target):
    def seed(roots):
        declared = {
            "api_version": "appsec-advisor/trust-boundaries/v1",
            "boundaries": [
                {
                    "key": "public-ingress",
                    "name": "Public ingress",
                    "kind": "network",
                    "assumption": "Every request must carry a session the receiver validates.",
                    "from": "external",
                    "to": target,
                }
            ],
        }
        (roots[1] / ".appsec").mkdir()
        (roots[1] / ".appsec" / "trust-boundaries.yaml").write_text(yaml.safe_dump(declared))
        subprocess.run(["git", "-C", str(roots[1]), "add", "-A"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(roots[1]),
                "-c",
                "user.name=T",
                "-c",
                "user.email=t@example.invalid",
                "commit",
                "-qm",
                "d",
            ],
            check=True,
        )

    host = {}
    real = FullHost.factory

    def recording(self, role, model, ceiling):
        host.setdefault("roles", []).append(role)
        return real(self, role, model, ceiling)

    monkeypatch.setattr(FullHost, "factory", recording)
    with pytest.raises(controller.CallError, match="names no component"):
        _assess(tmp_path, monkeypatch, names, seed=seed)
    assert "trust_boundary_analyst" not in host.get("roles", [])


@pytest.mark.parametrize("slug", ["team-a", "v2.release_1"])
def test_slug_adds_a_stamped_copy_of_the_combined_deliverables(tmp_path, monkeypatch, slug):
    outcome, _, out = _assess(tmp_path, monkeypatch, ("edge", "service"), ("--slug", slug))
    assert outcome["status"] == "complete"
    for name in ("threat-model.md", "threat-model.yaml", "threat-model.figure1.svg"):
        stamped = name.replace("threat-model", f"threat-model-{slug}", 1)
        assert (out / name).is_file() and (out / stamped).is_file()
        assert stamped in outcome["deliverables"]
    report = (out / f"threat-model-{slug}.md").read_text()
    assert f"threat-model-{slug}.figure1.svg" in report


def test_invalid_slug_stops_the_run_before_publication(tmp_path, monkeypatch):
    with pytest.raises((SystemExit, controller.CallError)):
        _assess(tmp_path, monkeypatch, ("edge", "service"), ("--slug", "../escape"))
    assert not (tmp_path / "out" / "threat-model.yaml").exists()


@pytest.mark.parametrize("names", [("caller", "receiver"), ("west", "east")])
def test_rebuild_redoes_every_job_an_earlier_run_accepted(tmp_path, monkeypatch, names):
    from runtime import multi_repo_scope
    from runtime.assessment_host import ExchangeError

    roots = [tmp_path / name for name in names]
    for root in roots:
        checkout(root)
    host = FullHost()
    real_admit = multi_repo_scope.admit

    def admit(selections, output, **options):
        host.scope = real_admit(selections, output, **options)
        return host.scope

    monkeypatch.setattr(multi_repo_scope, "admit", admit)
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: "a" * 64)
    argv = [
        *[arg for root in roots for arg in ("--repo", str(root))],
        *("--output", str(tmp_path / "out"), "--hard-budget", "5", "--trust-mode", "trusted", "--model", "haiku"),
    ]
    original = host.stage2
    host.stage2 = lambda role, context: {"unexpected": True}
    with pytest.raises(ExchangeError):
        controller.assess_repositories(argv, host_factory=host.factory, progress=lambda text: None)
    host.roles.clear()
    host.stage2 = original
    with pytest.raises(controller.CallError, match="--resume"):
        controller.assess_repositories([*argv, "--rebuild", "--resume"], host_factory=host.factory)
    outcome = controller.assess_repositories([*argv, "--rebuild"], host_factory=host.factory, progress=lambda t: None)
    assert outcome["status"] == "complete"
    # Accepted Stage-1 jobs reach the host again instead of being replayed.
    assert {"stride_analyzer", "trust_boundary_analyst"} <= set(host.roles)


def test_resume_reuses_accepted_jobs_after_an_interrupted_render(tmp_path, monkeypatch):
    from runtime import multi_repo_scope
    from runtime.assessment_host import ExchangeError

    roots = [tmp_path / name for name in ("caller", "receiver")]
    for root in roots:
        checkout(root)
    host = FullHost()
    real_admit = multi_repo_scope.admit

    def admit(selections, output, **options):
        host.scope = real_admit(selections, output, **options)
        return host.scope

    monkeypatch.setattr(multi_repo_scope, "admit", admit)
    # Concurrent plugin edits must not abort the test run; runtime binding has its own tests.
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: "a" * 64)
    argv = [
        *[arg for root in roots for arg in ("--repo", str(root))],
        *("--output", str(tmp_path / "out"), "--hard-budget", "5", "--trust-mode", "trusted", "--model", "haiku"),
    ]
    original = host.stage2

    def interrupted(role, context):
        # A reply with a known cost that its contract rejects; an unknown-cost
        # failure deliberately blocks resume instead.
        return {"unexpected": True}

    host.stage2 = interrupted
    with pytest.raises(ExchangeError):
        controller.assess_repositories(argv, host_factory=host.factory, progress=lambda text: None)
    assert not (tmp_path / "out" / "threat-model.yaml").exists()
    first = list(host.roles)
    host.roles.clear()
    host.stage2 = original
    outcome = controller.assess_repositories([*argv, "--resume"], host_factory=host.factory, progress=lambda text: None)
    assert outcome["status"] == "complete"
    # Every accepted Stage-1 job is replayed from its receipt; only the
    # interrupted render job reaches the host again.
    assert set(host.roles) <= {"ms_renderer", "secarch_renderer"}
    assert "stride_analyzer" in first


def test_changed_source_stops_publication(tmp_path, monkeypatch):
    from runtime import multi_repo_scope

    roots = [tmp_path / name for name in ("caller", "receiver")]
    for root in roots:
        checkout(root)
    host = FullHost()
    real_admit = multi_repo_scope.admit

    def admit(selections, output, **options):
        host.scope = real_admit(selections, output, **options)
        return host.scope

    monkeypatch.setattr(multi_repo_scope, "admit", admit)
    # Concurrent plugin edits must not abort the test run; runtime binding has its own tests.
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: "a" * 64)
    original = host.stage2

    def edit_then_answer(role, context):
        (roots[0] / "app.py").write_text("changed = True\n")
        return original(role, context)

    host.stage2 = edit_then_answer
    with pytest.raises(controller.ControllerError, match="source state changed"):
        controller.assess_repositories(
            [
                *[arg for root in roots for arg in ("--repo", str(root))],
                *("--output", str(tmp_path / "out"), "--hard-budget", "5", "--trust-mode", "trusted"),
            ],
            host_factory=host.factory,
            progress=lambda text: None,
        )
    assert not (tmp_path / "out" / "threat-model.yaml").exists()


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (("--incremental",), "--incremental is not supported"),
        (("--rerender",), "--rerender is not supported"),
        ((), "requires --soft-budget or --hard-budget"),
    ],
)
def test_unsupported_modes_stop_before_admission(tmp_path, extra, message):
    roots = [tmp_path / name for name in ("caller", "receiver")]
    for root in roots:
        checkout(root)
    budget = () if not extra else ("--hard-budget", "5")
    with pytest.raises(controller.CallError, match=message):
        controller.assess_repositories(
            [*[a for r in roots for a in ("--repo", str(r))], "--output", str(tmp_path / "out"), *budget, *extra],
            host_factory=lambda *args: pytest.fail("no model may be called"),
        )
    assert not (tmp_path / "out").exists()


def test_untrusted_preflight_rejects_repository_owned_agent_configuration(tmp_path):
    roots = [tmp_path / name for name in ("caller", "receiver")]
    for root in roots:
        checkout(root)
    (roots[1] / ".claude").mkdir()
    (roots[1] / ".claude" / "settings.json").write_text('{"hooks": {}}')
    with pytest.raises(controller.CallError, match="preflight rejected receiver"):
        controller.assess_repositories(
            [*[a for r in roots for a in ("--repo", str(r))], "--output", str(tmp_path / "out"), "--hard-budget", "5"],
            host_factory=lambda *args: pytest.fail("no model may be called"),
        )
    assert not (tmp_path / "out").exists()


def test_declared_context_and_a_run_wide_catalog_reach_the_combined_model(tmp_path, monkeypatch):
    from tests.test_assessment_context import BUSINESS, CATALOG

    catalog = tmp_path / "catalog.yaml"
    # The output contract accepts only MUST/SHOULD/MAY priorities.
    catalog.write_text(CATALOG.replace("priority: high", "priority: MUST"))

    def seed(roots):
        target = roots[0] / "docs/security/business-context.md"
        target.parent.mkdir(parents=True)
        target.write_text(BUSINESS)
        import subprocess

        subprocess.run(["git", "-C", str(roots[0]), "add", "-A"], check=True)

    outcome, host, out = _assess(tmp_path, monkeypatch, ("alpha", "beta"), ("--requirements", str(catalog)), seed=seed)
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "threat-model.yaml").read_text())
    trace = model["business_context_trace"]
    assert "alpha/docs/security/business-context.md" in trace["source"]
    assert model["meta"]["check_requirements"] is True
    report = (out / "threat-model.md").read_text()
    assert "Requirements" in report


def test_selection_order_does_not_change_the_combined_model(tmp_path, monkeypatch):
    from runtime import multi_repo_scope

    roots = [tmp_path / name for name in ("north", "south")]
    for root in roots:
        checkout(root)
    real_admit = multi_repo_scope.admit
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: "a" * 64)
    models = []
    for index, order in enumerate((roots, roots[::-1])):
        host = FullHost()

        def admit(selections, output, host=host):
            host.scope = real_admit(selections, output)
            return host.scope

        monkeypatch.setattr(multi_repo_scope, "admit", admit)
        out = tmp_path / f"out-{index}"
        controller.assess_repositories(
            [
                *[a for r in order for a in ("--repo", str(r))],
                "--output",
                str(out),
                "--hard-budget",
                "5",
                "--trust-mode",
                "trusted",
                "--model",
                "haiku",
            ],
            host_factory=host.factory,
            progress=lambda text: None,
        )
        models.append(yaml.safe_load((out / "threat-model.yaml").read_text()))
    first, second = models
    assert first["source_inventory"] == second["source_inventory"]
    assert [c["id"] for c in first["components"]] == [c["id"] for c in second["components"]]
    assert [(t["id"], t["evidence"]) for t in first["threats"]] == [(t["id"], t["evidence"]) for t in second["threats"]]
    assert first["data_flows"] == second["data_flows"]


def test_a_host_failure_ends_with_a_message_not_a_traceback(tmp_path, monkeypatch, capsys):
    from runtime.analyst_host import TransportError

    def fail(*args, **kwargs):
        raise TransportError("host returned no parseable result")

    monkeypatch.setattr(controller, "assess_repositories", fail)
    assert controller.assess_main(["--repo", "a", "--repo", "b"]) == 1
    err = capsys.readouterr().err
    assert "stopped: host returned no parseable result" in err and "Unpublished draft" not in err


def test_a_stopped_run_names_its_kept_draft_as_unpublished(tmp_path, monkeypatch, capsys):
    draft = tmp_path / "out" / ".assessment-work" / "render"
    draft.mkdir(parents=True)
    (draft / "threat-model.md").write_text("# Threat Model\n")

    def fail(*args, **kwargs):
        raise ValueError("Multi-repository model violates its versioned output schema: meta: bad")

    monkeypatch.setattr(controller, "assess_repositories", fail)
    assert controller.assess_main(["--repo", "a", "--repo", "b", "--output", str(tmp_path / "out")]) == 1
    assert f"Unpublished draft kept for diagnosis in {draft}" in capsys.readouterr().err
