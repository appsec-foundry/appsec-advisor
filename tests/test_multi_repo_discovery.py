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
from runtime.assessment_host import MARKER, ExchangeError, ModelAnswerFailure
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
            # A model quotes the source text without its line-number prefix (MR-15).
            quote = packet["source_slices"][0]["lines"][0].split(": ", 1)[1]
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

    served = []

    class Recording(ScriptedHost):
        def invoke(self, system, prompt, *args):
            packet = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])
            served.extend((row["repository_id"], packet["context"]["repository_id"]) for row in packet["source_slices"])
            return super().invoke(system, prompt, *args)

    host = Recording(scope, mutate=mutate)
    # The read is refused back, never served; a model that keeps asking ends its own job.
    with pytest.raises(ModelAnswerFailure):
        discovery.discover(scope, host_factory=host.factory, budget=budget(), should_stop=lambda: False)
    assert served == [] and len(host.contexts) > 1


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


@pytest.mark.parametrize("cost", [None, float("nan"), -1, True])
def test_missing_or_invalid_cost_closes_further_dispatch(tmp_path, cost):
    scope = sources(tmp_path)
    host = ScriptedHost(scope, usd=cost)
    limits = budget()
    with pytest.raises(TransportError, match="cost"):
        discovery.discover(scope, host_factory=host.factory, budget=limits, should_stop=lambda: False)
    assert len(host.contexts) == 1 and limits.failed
    assert limits.spent_usd == 0.05


def test_a_reported_cost_one_turn_over_the_reservation_is_charged_as_reported():
    """The host checks its spending limit between turns, so a reply can cost slightly more."""
    limits = discovery.DiscoveryBudget(max_usd=1.0, call_usd=0.05, max_calls=12, timeout_s=60)

    class Over:
        def __init__(self, ceiling):
            pass

        def invoke(self, *args):
            return HostReply({"action": "complete"}, 0.06)

    assert limits.invoke(Over, "s", "p", {}, 30, lambda: False).usd == 0.06
    assert not limits.failed and limits.spent_usd == pytest.approx(0.06)


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


@pytest.mark.parametrize("usd", [0.0, 0.03, None, 0.06])
def test_a_refused_call_is_settled_so_the_run_can_resume(tmp_path, usd):
    class RefusingHost:
        def invoke(self, *args):
            raise TransportError("host call failed: authentication_failed", reason="authentication_failed", usd=usd)

    limits = budget()
    with pytest.raises(TransportError) as caught:
        discovery.discover(
            sources(tmp_path), host_factory=lambda ceiling: RefusingHost(), budget=limits, should_stop=lambda: False
        )
    assert caught.value.reason == "authentication_failed"
    # A reported cost replaces the reservation; without a report the
    # reservation the host enforced is the cost.
    assert not limits.failed
    assert limits.spent_usd == pytest.approx(0.05 if usd is None else usd)
    assert "--resume" in str(caught.value)


def test_a_small_repository_keeps_its_complete_file_list():
    files = {"app.py": b"print(1)\n", "lib/util.py": b"x = 1\n"}
    assert discovery.file_listing(files, None) == {
        "files": [{"path": "app.py", "bytes": 9}, {"path": "lib/util.py", "bytes": 6}]
    }


@pytest.mark.parametrize("count", [3_000, 12_000])
def test_a_large_repository_lists_cited_and_source_files_first_and_counts_the_rest(count):
    from runtime.assessment_host import _prompt

    files = {
        f"src/main/java/com/example/module{i // 50}/ServiceImplementation{i}.java": b"class A {}\n"
        for i in range(count)
    }
    files.update({f"docs/guide/page{i}.md": b"# Page\n" for i in range(200)})
    entry = "test/fixtures/deep/entry/Server.java"
    files[entry] = b"class Server {}\n"
    listing = discovery.file_listing(files, {"serving_units": {"units": [{"entry_files": [entry]}]}})
    listed = {row["path"] for row in listing["files"]}
    # The cited entry file is listed although its path looks peripheral; documentation is not.
    assert entry in listed and not any(path.startswith("docs/") for path in listed)
    assert listing["unlisted"]["files"] == len(files) - len(listed)
    assert sum(row["files"] for row in listing["unlisted"]["directories"]) == listing["unlisted"]["files"]
    # The packet the model receives fits, leaving room for source reads.
    context = {"repository_id": "repo-0123456789abcdef", "label": "large", **listing}
    prompt = _prompt({"context": context, "source_slices": [], "source_reads_remaining": 12})
    assert len(prompt.encode()) < 150_000


@pytest.mark.parametrize(
    "max_usd,call_usd,concurrent", [(5.0, 2.0, 2), (16.0, 2.0, 4)], ids=["tight-budget", "roomy-budget"]
)
def test_concurrent_calls_never_reserve_more_than_the_budget(max_usd, call_usd, concurrent):
    """MR-16: running reservations count against the budget; a call waits instead of overspending."""
    import threading
    import time

    limits = discovery.DiscoveryBudget(max_usd=max_usd, call_usd=call_usd, max_calls=12, timeout_s=60)
    release = threading.Event()
    lock = threading.Lock()
    running, peak, ceilings = [0], [0], []

    class Blocking:
        def __init__(self, ceiling):
            ceilings.append(ceiling)

        def invoke(self, system, prompt, schema, timeout_s, should_stop):
            with lock:
                running[0] += 1
                peak[0] = max(peak[0], running[0])
            release.wait(10)
            with lock:
                running[0] -= 1
            return HostReply({}, 0.5)

    threads = [
        threading.Thread(target=limits.invoke, args=(Blocking, "s", "p", {}, 30, lambda: False)) for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 5
    while len(ceilings) < concurrent and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.2)
    # Only calls whose full ceiling fits beside the running reservations have started.
    assert len(ceilings) == concurrent and limits.spent_usd <= max_usd and limits.failed
    release.set()
    for thread in threads:
        thread.join(10)
    # Settled costs free the reservations, so every waiting call ran with its full ceiling.
    assert peak[0] == concurrent and ceilings == [call_usd] * 4
    assert limits.spent_usd == pytest.approx(4 * 0.5) and not limits.failed


def test_an_unsettled_concurrent_call_stops_the_calls_waiting_for_budget():
    import threading

    limits = discovery.DiscoveryBudget(max_usd=3.0, call_usd=2.0, max_calls=12, timeout_s=60)
    started, release = threading.Event(), threading.Event()
    errors = []

    class Unknown:
        def __init__(self, ceiling):
            pass

        def invoke(self, system, prompt, schema, timeout_s, should_stop):
            started.set()
            release.wait(10)
            return HostReply({"action": "complete"}, float("nan"))

    def call():
        try:
            limits.invoke(Unknown, "s", "p", {}, 30, lambda: False)
        except Exception as exc:  # noqa: BLE001 - the test inspects every outcome
            errors.append(exc)

    first = threading.Thread(target=call)
    first.start()
    started.wait(5)
    waiting = threading.Thread(target=call)
    waiting.start()
    release.set()
    first.join(10)
    waiting.join(10)
    # An implausible cost report keeps its reservation and no waiting call starts after it.
    assert limits.unsettled and limits.calls == 1
    assert any(isinstance(e, ExchangeError) and "accounting unavailable" in str(e) for e in errors)


def test_a_call_cancelled_mid_flight_is_charged_its_reservation_and_stays_resumable():
    """assess-stop or SIGTERM kills the call's process group; the host's spending limit bounds its cost."""
    limits = discovery.DiscoveryBudget(max_usd=1.0, call_usd=0.05, max_calls=1, timeout_s=60)

    class Stopped:
        def __init__(self, ceiling):
            pass

        def invoke(self, *args):
            raise HostCancelled("Assessment cancelled")

    with pytest.raises(HostCancelled):
        limits.invoke(Stopped, "s", "p", {}, 30, lambda: False)
    assert not limits.failed and limits.spent_usd == pytest.approx(0.05)
