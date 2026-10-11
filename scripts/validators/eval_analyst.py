#!/usr/bin/env python3
"""validators/eval_analyst.py — compare threat-analyst configurations on a fixed case set.

A developer tool, never part of a test gate: ``run`` calls real models and
costs money; ``score`` is deterministic and reads only recorded results.

Each case of ``tests/fixtures/analyst-eval/cases.yaml`` becomes a small Git
repository: the project files as the first commit and, for a review case, the
changed files as a second commit. A configuration names the engine and model:

* ``analyst`` runs ``scripts/appsec-analyst-cli`` interactively (``design
  --text`` or ``review --base HEAD~1 --head HEAD``), with ``--explore`` when the
  configuration sets it. Open questions are answered once with a fixed
  neutral sentence, so every configuration gets the same information.
* ``direct`` asks the model the same question with read-only file tools in the
  repository and no plugin context, as a developer would without the analyst.

The score counts, per configuration: seeded weaknesses found (a finding or a
code-backed assumption that cites the expected file and names the weakness by
CWE or keyword), findings of medium or higher severity on benign changes,
covered design themes, cost, and wall time. Keyword matching is a coarse proxy
for quality: read the recorded results before acting on a close score.

Usage:
    eval_analyst.py run --out DIR [--configs A,C,E] [--case ID ...]
    eval_analyst.py score --out DIR
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
CASES = PLUGIN_ROOT / "tests" / "fixtures" / "analyst-eval" / "cases.yaml"
CLI = PLUGIN_ROOT / "scripts" / "appsec-analyst-cli"
CONFIGS = {
    "A": {"engine": "analyst", "model": "sonnet"},
    "B": {"engine": "analyst", "model": "opus"},
    "C": {"engine": "analyst", "model": "sonnet", "explore": True},
    "D": {"engine": "analyst", "model": "opus", "explore": True},
    "E": {"engine": "direct", "model": "opus"},
}
NEUTRAL_ANSWER = "No further information is available; assume the most common setup."
# The controller allows two question rounds; one more call ends a job that still asks.
MAX_ANSWER_ROUNDS = 3
SERIOUS = {"medium", "high", "critical"}
RUN_TIMEOUT_SECONDS = 1200
DIRECT_BUDGET_USD = "3.00"
GIT_ENV = {
    "GIT_AUTHOR_NAME": "eval",
    "GIT_AUTHOR_EMAIL": "eval@example.invalid",
    "GIT_COMMITTER_NAME": "eval",
    "GIT_COMMITTER_EMAIL": "eval@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
DIRECT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings", "scenarios", "recommendations"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["title", "explanation", "severity", "file"],
                "properties": {
                    "title": {"type": "string"},
                    "explanation": {"type": "string"},
                    "severity": {"enum": ["low", "medium", "high", "critical"]},
                    "file": {"type": "string"},
                    "cwe": {"type": "integer"},
                },
            },
        },
        "scenarios": {"type": "array", "items": {"type": "string"}},
        "recommendations": {"type": "array", "items": {"type": "string"}},
    },
}


class EvalError(Exception):
    """The case set, a configuration, or a recorded result is unusable."""


def load_cases(path: Path = CASES) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise EvalError(f"{path.name}: unsupported case set")
    for case in data["cases"]:
        if case["project"] not in data["projects"]:
            raise EvalError(f"{case['id']}: unknown project")
        if not {"weakness", "benign", "themes"} & set(case.get("expect") or {}):
            raise EvalError(f"{case['id']}: expect names no weakness, benign flag, or themes")
    return data


def parse_configs(text: str) -> list[str]:
    names = [n.strip() for n in text.split(",") if n.strip()]
    unknown = [n for n in names if n not in CONFIGS]
    if unknown or not names:
        raise EvalError(f"unknown configuration(s) {unknown}; choose from {sorted(CONFIGS)}")
    return names


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env={**os.environ, **GIT_ENV}, check=True
    )
    return proc.stdout


def materialize(project: dict, case: dict, root: Path) -> Path:
    """Build the case repository: project files committed, then the change as a second commit."""
    repo = root / case["id"]
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    for name, text in project.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    if case.get("change"):
        for name, text in case["change"].items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(text, encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "change")
    return repo


def _pending_question_ids(report: str) -> list[str]:
    """Required questions only: the job waits for exactly these, and answering others is rejected."""
    return re.findall(r"^- (q-\d{3}) \(required\):", report, re.M)


def run_analyst(repo: Path, case: dict, config: dict, out: Path) -> dict:
    report = out / "report"
    report.mkdir(parents=True, exist_ok=True)
    state = out / "state"
    common = ["--repo", str(repo), "--state-dir", str(state), "--interactive", "--model", config["model"]]
    if case.get("change"):
        argv = ["review", *common, "--base", "HEAD~1", "--head", "HEAD", "--output", str(report)]
        if case.get("question"):
            argv += ["--question", case["question"]]
    else:
        argv = ["design", *common, "--text", case["question"], "--output", str(report)]
    if config.get("explore"):
        argv.append("--explore")
    proc = subprocess.run(
        [_sys.executable, str(CLI), *argv], capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS, check=False
    )
    for _round in range(MAX_ANSWER_ROUNDS):
        job = re.search(r"^Job: (aj-[0-9a-f]{32})$", proc.stdout, re.M)
        if not job or "State: awaiting_answers" not in proc.stdout or not _pending_question_ids(proc.stdout):
            break
        argv = ["answer", "--repo", str(repo), "--state-dir", str(state), "--interactive", "--job", job.group(1)]
        for qid in _pending_question_ids(proc.stdout):
            argv += ["--answer", f"{qid}={NEUTRAL_ANSWER}"]
        proc = subprocess.run(
            [_sys.executable, str(CLI), *argv], capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS, check=False
        )
    result_path = report / "analyst-result.json"
    if not result_path.is_file():
        return {"state": "no_result", "detail": (proc.stdout + proc.stderr)[-800:]}
    return {"state": "recorded", "result": json.loads(result_path.read_text(encoding="utf-8"))}


def run_direct(repo: Path, case: dict, config: dict) -> dict:
    if case.get("change"):
        diff = _git(repo, "diff", "HEAD~1", "HEAD")
        prompt = (
            "Review the security of this change to the repository in the working directory. Read any file you need.\n"
            + (f"Answer this question first: {case['question']}\n" if case.get("question") else "")
            + f"The change:\n{diff}"
        )
    else:
        prompt = (
            "The working directory holds the repository of a web service. Read any file you need. "
            f"Give security advice for this planned feature: {case['question']}"
        )
    argv = [
        "claude", "-p", "--model", config["model"], "--safe-mode", "--restricted", "--tools", "Read,Grep,Glob",
        "--strict-mcp-config", "--no-session-persistence", "--permission-prompts", "none",
        "--output-format", "json", "--json-schema", json.dumps(DIRECT_SCHEMA), "--max-budget-usd", DIRECT_BUDGET_USD,
    ]  # fmt: skip
    proc = subprocess.run(
        argv, input=prompt, capture_output=True, text=True, cwd=repo, timeout=RUN_TIMEOUT_SECONDS, check=False
    )
    try:
        outcome = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"state": "no_result", "detail": proc.stdout[-400:]}
    if not isinstance(outcome, dict) or "structured_output" not in outcome:
        return {"state": "no_result", "detail": str(outcome)[:400]}
    return {"state": "recorded", "direct": outcome["structured_output"], "usd": outcome.get("total_cost_usd")}


def normalize(record: dict) -> dict:
    """One shape for both engines: findings with files, severity, CWE, and text; plus free advice texts."""
    if record.get("state") != "recorded":
        return {"findings": [], "texts": [], "usd": None}
    if "direct" in record:
        data = record["direct"]
        findings = [
            {
                "files": [f["file"]],
                "severity": f["severity"],
                "cwe": f.get("cwe"),
                "text": f"{f['title']} {f['explanation']}",
            }
            for f in data.get("findings", [])
        ]
        return {
            "findings": findings,
            "texts": [*data.get("scenarios", []), *data.get("recommendations", [])],
            "usd": record.get("usd"),
        }
    result = record["result"]
    findings = [
        {
            "files": [loc["path"] for loc in f["evidence"] + f.get("comparison", [])],
            "severity": f["severity"],
            "cwe": None,
            "text": f"{f['title']} {f.get('explanation', '')}",
        }
        for f in result["findings"]
    ]
    findings += [
        {
            "files": [loc["path"] for loc in a.get("evidence", [])],
            "severity": "medium",
            "cwe": None,
            "text": a["statement"],
        }
        for a in result["assumptions"]
        if a["status"] == "contradicted" and a.get("evidence")
    ]
    texts = [result.get("summary", "")]
    texts += [f"{s['title']} {s.get('description', '')}" for s in result["scenarios"]]
    texts += [f"{r['title']} {r.get('rationale', '')}" for r in result.get("recommendations", [])]
    texts += [a["statement"] for a in result["assumptions"]] + [q["asks"] for q in result["questions"]]
    return {"findings": findings, "texts": texts, "usd": (result.get("costs") or {}).get("usd")}


def score_case(case: dict, normalized: dict) -> dict:
    expect = case["expect"]
    score: dict = {}
    if "weakness" in expect:
        weakness = expect["weakness"]
        keywords = [k.lower() for k in weakness.get("keywords", [])]
        score["weakness_found"] = any(
            weakness["file"] in f["files"]
            and (f.get("cwe") in weakness.get("cwe", []) or any(k in f["text"].lower() for k in keywords))
            for f in normalized["findings"]
        )
    if expect.get("benign"):
        score["false_positives"] = sum(1 for f in normalized["findings"] if f["severity"] in SERIOUS)
    if "themes" in expect:
        corpus = " ".join(normalized["texts"] + [f["text"] for f in normalized["findings"]]).lower()
        hits = sum(1 for group in expect["themes"] if any(k.lower() in corpus for k in group))
        score["themes_covered"] = hits
        score["themes_total"] = len(expect["themes"])
    return score


def summarize(rows: list[dict]) -> dict:
    """Aggregate per configuration from ``{config, case_id, score, seconds, usd, state}`` rows."""
    out: dict = {}
    for row in rows:
        agg = out.setdefault(
            row["config"],
            {"weaknesses": [0, 0], "false_positives": 0, "themes": [0, 0], "usd": 0.0, "seconds": 0.0, "no_result": 0},
        )
        s = row["score"]
        if "weakness_found" in s:
            agg["weaknesses"][0] += int(s["weakness_found"])
            agg["weaknesses"][1] += 1
        agg["false_positives"] += s.get("false_positives", 0)
        if "themes_total" in s:
            agg["themes"][0] += s["themes_covered"]
            agg["themes"][1] += s["themes_total"]
        agg["usd"] += row.get("usd") or 0.0
        agg["seconds"] += row.get("seconds") or 0.0
        agg["no_result"] += int(row.get("state") != "recorded")
    return out


def render_table(summary: dict) -> str:
    lines = [
        "| Config | Weaknesses found | False positives (benign) | Design themes | No result | USD | Seconds |",
        "|---|---|---|---|---|---|---|",
    ]
    for name in sorted(summary):
        a = summary[name]
        lines.append(
            f"| {name} {CONFIGS.get(name, {})} | {a['weaknesses'][0]}/{a['weaknesses'][1]} | {a['false_positives']} "
            f"| {a['themes'][0]}/{a['themes'][1]} | {a['no_result']} | {a['usd']:.2f} | {a['seconds']:.0f} |"
        )
    return "\n".join(lines) + "\n"


def run(out: Path, configs: list[str], only: list[str] | None, cases_path: Path = CASES) -> None:
    data = load_cases(cases_path)
    selected = [c for c in data["cases"] if not only or c["id"] in only]
    for name in configs:
        config = CONFIGS[name]
        for case in selected:
            target = out / name / case["id"]
            if (target / "record.json").is_file():
                continue
            shutil.rmtree(out / "repos" / name / case["id"], ignore_errors=True)
            repo = materialize(data["projects"][case["project"]], case, out / "repos" / name)
            started = time.monotonic()
            record = (
                run_analyst(repo, case, config, target)
                if config["engine"] == "analyst"
                else run_direct(repo, case, config)
            )
            record["seconds"] = round(time.monotonic() - started, 1)
            target.mkdir(parents=True, exist_ok=True)
            (target / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            print(f"{name} {case['id']}: {record['state']} in {record['seconds']}s", flush=True)


def score(out: Path, cases_path: Path = CASES) -> tuple[list[dict], dict]:
    data = load_cases(cases_path)
    by_id = {c["id"]: c for c in data["cases"]}
    rows = []
    for record_path in sorted(out.glob("*/*/record.json")):
        config, case_id = record_path.parent.parent.name, record_path.parent.name
        if case_id not in by_id or config not in CONFIGS:
            continue
        record = json.loads(record_path.read_text(encoding="utf-8"))
        normalized = normalize(record)
        rows.append(
            {
                "config": config,
                "case_id": case_id,
                "state": record.get("state"),
                "score": score_case(by_id[case_id], normalized),
                "seconds": record.get("seconds"),
                "usd": normalized["usd"],
            }
        )
    return rows, summarize(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="run configurations against the case set (calls models, costs money)")
    run_p.add_argument("--out", type=Path, required=True)
    run_p.add_argument("--configs", default="A,C,E")
    run_p.add_argument("--case", action="append", default=[])
    score_p = sub.add_parser("score", help="score recorded results deterministically")
    score_p.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            run(args.out.resolve(), parse_configs(args.configs), args.case)
            return 0
        rows, summary = score(args.out.resolve())
    except EvalError as exc:
        print(f"eval_analyst: {exc}", file=_sys.stderr)
        return 2
    (args.out / "scores.json").write_text(json.dumps({"rows": rows, "summary": summary}, indent=2) + "\n")
    print(render_table(summary), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
