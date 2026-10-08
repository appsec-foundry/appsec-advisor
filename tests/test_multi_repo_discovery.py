"""Combined discovery preserves ownership, evidence retrieval, and run limits."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime import multi_repo_discovery as discovery
from runtime.analyst_host import HostCancelled, HostReply, TransportError
from runtime.assessment_host import MARKER, ExchangeError
from runtime.multi_repo_scope import ScopeError, admit


def sources(tmp_path, names=("edge", "service"), operation="GET /records"):
    roots = []
    for name in names:
        root = tmp_path / name
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "initial",
            ],
            check=True,
        )
        (root / "service.txt").write_text(
            f"cluster=production-a endpoint=https://api.example.invalid operation={operation}\n"
        )
        (root / "notes.txt").write_text("Repository documentation.\n")
        roots.append(str(root))
    return admit(roots, str(tmp_path / "output"))


class ScriptedHost:
    def __init__(self, scope, *, mutate=None, usd=0.01):
        self.scope, self.mutate, self.usd = scope, mutate, usd
        self.contexts, self.ceilings = [], []

    def factory(self, ceiling):
        self.ceilings.append(ceiling)
        return self

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        packet = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])
        context = packet["context"]
        self.contexts.append(context)
        rid = context["repository_id"]
        if not packet["source_slices"]:
            payload = {
                "action": "read",
                "artifact": None,
                "reads": [{"repository_id": rid, "path": "service.txt", "start_line": 1, "end_line": 1}],
            }
        else:
            quote = packet["source_slices"][0]["lines"][0]
            artifact = {
                "schema_version": 1,
                "repository_id": rid,
                "components": [
                    {
                        "id": "service",
                        "name": context["label"],
                        "description": "Application component",
                        "tier": "application",
                        "paths": ["service.txt"],
                    }
                ],
                "interfaces": [
                    {
                        "id": "endpoint",
                        "component_id": "service",
                        "role": "request" if rid == self.scope.repositories[0].repository_id else "serve",
                        "protocol": "HTTPS",
                        "address": "https://api.example.invalid",
                        "deployment": "production-a",
                        "operation": quote.split("operation=")[1],
                        "evidence": [{"file": "service.txt", "line": 1, "quote": quote}],
                    }
                ],
            }
            payload = {"action": "complete", "reads": [], "artifact": artifact}
        if self.mutate:
            self.mutate(payload, context, len(self.contexts))
        return HostReply(payload, self.usd)


def budget():
    return discovery.DiscoveryBudget(max_usd=0.20, call_usd=0.05, max_calls=12, timeout_s=60)


@pytest.mark.parametrize(
    "names,operation", [(("edge", "service"), "GET /records"), (("west", "east"), "POST /entries")]
)
def test_every_root_is_freshly_discovered_with_only_its_sources(tmp_path, names, operation):
    scope = sources(tmp_path, names, operation)
    host = ScriptedHost(scope)
    limits = budget()
    result = discovery.discover(scope, host_factory=host.factory, budget=limits, should_stop=lambda: False)
    assert {d["repository_id"] for d in result.observations} == {r.repository_id for r in scope.repositories}
    assert len(result.connections["candidates"]) == 1
    assert result.connections["candidates"][0]["status"] == "requires-architecture-review"
    assert all(r["unread_paths"] == ["notes.txt"] for r in result.retrieval)
    assert len(host.contexts) == 4 and limits.calls == 4 and limits.spent_usd == pytest.approx(0.04)
    assert all(set(c) == {"repository_id", "label", "files"} for c in host.contexts)
    assert not scope.output.exists()


def test_cross_repository_read_is_denied_before_any_source_is_served(tmp_path):
    scope = sources(tmp_path)

    def mutate(payload, context, call):
        if payload["action"] == "read":
            payload["reads"][0]["repository_id"] = next(
                r.repository_id for r in scope.repositories if r.repository_id != context["repository_id"]
            )

    host = ScriptedHost(scope, mutate=mutate)
    with pytest.raises(ExchangeError, match="outside this task"):
        discovery.discover(scope, host_factory=host.factory, budget=budget(), should_stop=lambda: False)
    assert len(host.contexts) == 1


def test_real_but_unretrieved_source_cannot_support_model_observation(tmp_path):
    scope = sources(tmp_path)

    def mutate(payload, context, call):
        if payload["action"] == "complete":
            payload["artifact"]["components"][0]["paths"].append("notes.txt")

    host = ScriptedHost(scope, mutate=mutate)
    with pytest.raises(ExchangeError, match="not retrieved"):
        discovery.discover(scope, host_factory=host.factory, budget=budget(), should_stop=lambda: False)


@pytest.mark.parametrize("when", ["before", "during"])
def test_any_root_change_prevents_combined_result(tmp_path, when):
    scope = sources(tmp_path)

    def change():
        (scope.repositories[-1].root / "new.txt").write_text("new source\n")

    if when == "before":
        change()

    def mutate(payload, context, call):
        if when == "during" and call == 4:
            change()

    host = ScriptedHost(scope, mutate=mutate)
    with pytest.raises(ScopeError, match="changed"):
        discovery.discover(scope, host_factory=host.factory, budget=budget(), should_stop=lambda: False)
    assert len(host.contexts) == (0 if when == "before" else 4)


@pytest.mark.parametrize("cost", [None, float("nan"), -1, True, 0.06])
def test_missing_or_invalid_cost_closes_further_dispatch(tmp_path, cost):
    scope = sources(tmp_path)
    host = ScriptedHost(scope, usd=cost)
    limits = budget()
    with pytest.raises(TransportError, match="cost"):
        discovery.discover(scope, host_factory=host.factory, budget=limits, should_stop=lambda: False)
    assert len(host.contexts) == 1 and limits.failed
    assert limits.spent_usd == 0.05


def test_aggregate_budget_is_not_reset_for_next_repository(tmp_path):
    scope = sources(tmp_path)
    host = ScriptedHost(scope, usd=0.05)
    limits = discovery.DiscoveryBudget(max_usd=0.10, call_usd=0.05, max_calls=12, timeout_s=60)
    with pytest.raises(ExchangeError, match="cost budget"):
        discovery.discover(scope, host_factory=host.factory, budget=limits, should_stop=lambda: False)
    assert len(host.contexts) == 2 and limits.spent_usd == 0.10


def test_cancellation_between_roots_stops_dispatch(tmp_path):
    scope = sources(tmp_path)
    host = ScriptedHost(scope)
    with pytest.raises(HostCancelled):
        discovery.discover(
            scope, host_factory=host.factory, budget=budget(), should_stop=lambda: len(host.contexts) >= 2
        )
    assert len(host.contexts) == 2


def test_call_limit_is_shared_between_roots(tmp_path):
    scope = sources(tmp_path)
    host = ScriptedHost(scope)
    limits = discovery.DiscoveryBudget(max_usd=0.20, call_usd=0.05, max_calls=3, timeout_s=60)
    with pytest.raises(ExchangeError, match="call budget"):
        discovery.discover(scope, host_factory=host.factory, budget=limits, should_stop=lambda: False)
    assert len(host.contexts) == 3


def test_expired_budget_never_creates_a_host(tmp_path):
    scope = sources(tmp_path)
    host = ScriptedHost(scope)
    limits = budget()
    limits.deadline = 0
    with pytest.raises(HostCancelled, match="time limit"):
        discovery.discover(scope, host_factory=host.factory, budget=limits, should_stop=lambda: False)
    assert host.ceilings == []
