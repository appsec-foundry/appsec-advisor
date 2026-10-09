"""
analyzers/security_steering.py — AppSec Coach UserPromptSubmit hook.

Registered in hooks/hooks.json. Runs on every prompt and injects secure-coding
guidance as additional context when the coach is active and the prompt looks
like coding work.

Input (stdin): the hook JSON; only the ``prompt`` field is read.

Output (stdout): ``{}`` when the coach is inactive, the input is invalid or
empty, or the prompt does not meet the keyword thresholds. Otherwise
``hookSpecificOutput.additionalContext`` carries the baseline text plus the
matched topics' guidance and requirement text, and ``systemMessage`` names the
activation source. Every handled path exits 0.

Activation (first match wins): ``APPSEC_COACH`` env var (truthy forces on,
falsy forces off), an active org profile's
``security_coach.enabled_by_default``, then ``enabled`` in
hooks/steering_keywords.json. Keywords, topics, thresholds, and requirement
sources come from that file, with built-in defaults when it is unreadable.

Side effect: appends a COACH_INJECTED line to docs/security/.hook-events.log
under the working directory (best-effort).

The hook runs on every prompt, so every lookup is cheap and best-effort: an
unreadable file means "use the default", never an error shown to the user.
"""

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import hashlib
import json
import os
import re
import sys

from runtime.event_log import format_line

# ---------------------------------------------------------------------------
# Defaults (used when steering_keywords.json is missing or unreadable)
# ---------------------------------------------------------------------------

_DEFAULT_BASELINE = (
    "Security steering active. Always implement secure-by-default:\n"
    "- Treat all input as untrusted\n"
    "- Enforce authentication and least privilege\n"
    "- Never hardcode or expose secrets\n"
    "- Use secure defaults\n"
    "- Prevent common vulnerabilities\n"
    "- Do not suggest insecure shortcuts"
)

_DEFAULT_CODE = {
    "code",
    "function",
    "class",
    "module",
    "api",
    "endpoint",
    "database",
    "query",
    "http",
    "request",
    "response",
    "upload",
    "deploy",
    "docker",
    "config",
    "env",
    "dependency",
    "package",
    "import",
    "install",
    "script",
    "shell",
    "middleware",
    "route",
    "controller",
    "schema",
    "migration",
}

_DEFAULT_ACTION = {
    "write",
    "implement",
    "fix",
    "refactor",
    "add",
    "create",
    "build",
    "review",
    "file",
    "key",
}

# A prompt triggers the coach when it matches a topic, names at least `code_min` code words, or names
# `code_action_code_min` code words together with `code_action_action_min` action words.
_DEFAULT_THRESHOLDS = {
    "code_min": 2,
    "code_action_code_min": 1,
    "code_action_action_min": 1,
}

# Size limits of the injected context; it costs context budget on every matching prompt.
_DEFAULT_SEVERITY = {
    "max_injected_chars": 2500,
    "max_requirements_per_topic": 3,
}

_DEFAULT_REQ_SOURCE_PATHS = [
    ".cache/requirements.yaml",
    "data/appsec-requirements-fallback.yaml",
    # Vendor-neutral best-practices floor: when no company catalog is present the
    # steering hook still resolves BP-* requirement text (matches the L0
    # "company else best-practices" behaviour). See docs/internal/analysis/proposal-dev-security-helper.md.
    "data/appsec-bestpractices-baseline.yaml",
]


def _verbose():
    return os.environ.get("APPSEC_VERBOSE", "").strip() not in ("", "0", "false", "no")


def _log(msg):
    """Diagnostics go to stderr and only with APPSEC_VERBOSE; stdout belongs to the hook protocol."""
    if _verbose():
        print(f"[appsec] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Activation
# ---------------------------------------------------------------------------

_TRUTHY = {"1", "true", "yes", "on", "enable", "enabled"}
_FALSY = {"0", "false", "no", "off", "disable", "disabled"}


def _activation_source(cfg):
    """Decide whether the coach is active and where the signal came from.

    Precedence: environment variable wins (it can force-on OR force-off),
    then ``.org-profile-effective.json`` (if an org profile is active and
    sets ``security_coach.enabled_by_default``), then the static config
    file's ``enabled`` flag, then off.
    Returns a short source label when active, else None.
    """
    env = os.environ.get("APPSEC_COACH", "").strip().lower()
    if env in _TRUTHY:
        return "env"
    if env in _FALSY:
        return None
    if (cfg.get("_org_profile_security_coach") or {}).get("enabled_by_default"):
        return "org-profile"
    if cfg.get("enabled") is True:
        return "config"
    return None


# ---------------------------------------------------------------------------
# Plugin root and org profile lookup
# ---------------------------------------------------------------------------


def _plugin_roots():
    """Return candidate plugin root directories: ``CLAUDE_PLUGIN_ROOT`` first,
    then the root derived from this file's location, deduplicated."""
    roots = []
    env_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "").strip()
    if env_root:
        roots.append(env_root)
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    roots.append(os.path.normpath(os.path.join(script_dir, "..")))
    return [r for r in dict.fromkeys(roots) if r]


def _load_org_profile_coach():
    """Read security_coach config from an active org profile, if any.

    The lookup is best-effort: any IO or parse error returns an empty
    dict so the hook stays cheap and robust on every prompt.
    """
    coach = _coach_from_effective_profile()
    if coach is not None:
        return coach
    return _coach_from_configured_profile()


def _coach_from_effective_profile():
    """``security_coach`` of the first active ``.org-profile-effective.json``; None when there is none.

    That file is the profile a threat-model run already resolved, so it is the cheapest source. It is looked for
    in OUTPUT_DIR, then in docs/security/ under the working directory. An active profile without a coach block
    yields ``{}`` and ends the lookup: the configured profile is not consulted then.
    """
    candidates = []
    output_dir = os.environ.get("OUTPUT_DIR")
    if output_dir:
        candidates.append(os.path.join(output_dir, ".org-profile-effective.json"))
    candidates.append(os.path.join(os.getcwd(), "docs", "security", ".org-profile-effective.json"))
    for path in candidates:
        try:
            with open(path) as fh:
                eff = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        if eff.get("org_profile", {}).get("active"):
            return eff.get("security_coach") or {}
    return None


def _coach_from_configured_profile():
    """``security_coach`` of the profile YAML that ``organization_profile`` in a plugin root's config.json names."""
    try:
        import yaml
    except ImportError:
        return {}
    for root in _plugin_roots():
        try:
            with open(os.path.join(root, "config.json")) as fh:
                cfg = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        block = cfg.get("organization_profile") or {}
        if not block.get("enabled") or not block.get("path"):
            continue
        prof_path = block["path"]
        if not os.path.isabs(prof_path):
            prof_path = os.path.normpath(os.path.join(root, prof_path))
        try:
            with open(prof_path) as fh:
                profile = yaml.safe_load(fh) or {}
        except Exception:  # noqa: BLE001
            continue
        coach = profile.get("security_coach") or {}
        if coach:
            return coach
    return {}


# ---------------------------------------------------------------------------
# Configuration: defaults, then hooks/steering_keywords.json, then the org profile
# ---------------------------------------------------------------------------


def _load_config():
    """Load steering_keywords.json or fall back to defaults. Backwards-compatible
    with the old schema (top-level `strong`, `code`, `action`, `thresholds`)."""
    cfg = _default_config()
    _apply_steering_file(cfg, _read_steering_file() or {})
    # Applied even without a readable steering file: the activation order in the
    # module docstring relies on an org profile being able to switch the coach on.
    org_coach = _load_org_profile_coach()
    if org_coach:
        _apply_org_coach(cfg, org_coach)
    return cfg


def _default_config():
    return {
        "enabled": False,
        "baseline": _DEFAULT_BASELINE,
        "code_keywords": set(_DEFAULT_CODE),
        "action_keywords": set(_DEFAULT_ACTION),
        "thresholds": dict(_DEFAULT_THRESHOLDS),
        "severity": dict(_DEFAULT_SEVERITY),
        "topics": {},
        "requirements_source": {"paths": list(_DEFAULT_REQ_SOURCE_PATHS)},
    }


def _read_steering_file():
    """The parsed hooks/steering_keywords.json of the first plugin root that has a readable one, else None."""
    for path in (os.path.join(root, "hooks", "steering_keywords.json") for root in _plugin_roots()):
        try:
            with open(path) as fh:
                return json.load(fh)
        except Exception as exc:
            _log(f"config candidate {path} skipped: {exc}")
    return None


def _apply_steering_file(cfg, loaded):
    """Overlay the steering file on the defaults; a key the file omits keeps its default."""
    cfg["enabled"] = bool(loaded.get("enabled", False))
    if "baseline" in loaded and isinstance(loaded["baseline"], str):
        cfg["baseline"] = loaded["baseline"]

    # The current schema names the keyword lists code_keywords/action_keywords; the old one used code/action.
    if "code_keywords" in loaded:
        cfg["code_keywords"] = set(loaded["code_keywords"])
    elif "code" in loaded:
        cfg["code_keywords"] = set(loaded["code"])

    if "action_keywords" in loaded:
        cfg["action_keywords"] = set(loaded["action_keywords"])
    elif "action" in loaded:
        cfg["action_keywords"] = set(loaded["action"])

    if isinstance(loaded.get("thresholds"), dict):
        cfg["thresholds"].update(loaded["thresholds"])
    if isinstance(loaded.get("severity"), dict):
        cfg["severity"].update(loaded["severity"])

    if isinstance(loaded.get("topics"), dict):
        cfg["topics"] = loaded["topics"]
    elif "strong" in loaded:
        # Old schema: the `strong` trigger words become one topic; its leading _ keeps it out of messages.
        cfg["topics"] = {
            "_legacy": {
                "triggers": list(loaded.get("strong") or []),
                "guidance": "",
                "requirements": [],
            }
        }

    if isinstance(loaded.get("requirements_source"), dict):
        paths = loaded["requirements_source"].get("paths")
        if isinstance(paths, list) and paths:
            cfg["requirements_source"]["paths"] = list(paths)


def _apply_org_coach(cfg, org_coach):
    """Let an org profile switch the coach on and set its own baseline, topics and requirement limit.

    The profile is declarative data, never code: its guidance is injected as advice and capped by
    max_injected_chars like any other topic.
    """
    cfg["_org_profile_security_coach"] = org_coach
    max_per_topic = org_coach.get("max_requirements_per_topic")
    if isinstance(max_per_topic, int):
        cfg["severity"]["max_requirements_per_topic"] = max_per_topic
    if isinstance(org_coach.get("baseline"), str) and org_coach["baseline"].strip():
        cfg["baseline"] = org_coach["baseline"]
    org_topics = org_coach.get("topics")
    if isinstance(org_topics, dict):
        # inherit_default_topics=false → use only the org's topics; otherwise
        # merge, with an org topic overriding a built-in of the same id.
        if org_coach.get("inherit_default_topics") is False:
            cfg["topics"] = dict(org_topics)
        else:
            cfg["topics"] = {**cfg["topics"], **org_topics}


# ---------------------------------------------------------------------------
# Requirements catalog: the text behind the requirement ids a topic lists
# ---------------------------------------------------------------------------


def _load_requirements_index(cfg):
    """Build {id: {text, priority, url}} from the first readable requirements YAML.

    Paths are tried in configured order under each plugin root, so a company catalog wins over the
    best-practices floor. A catalog without any requirement does not count as found.
    """
    try:
        import yaml
    except ImportError:
        _log("pyyaml unavailable — requirements injection disabled")
        return {}

    rel_paths = cfg["requirements_source"].get("paths") or []
    for path in [os.path.join(root, rel) for root in _plugin_roots() for rel in rel_paths]:
        try:
            with open(path) as fh:
                data = yaml.safe_load(fh)
        except FileNotFoundError:
            continue
        except Exception as exc:
            _log(f"requirements load failed at {path}: {exc}")
            continue
        if not isinstance(data, dict):
            continue
        index = _requirements_by_id(data)
        if index:
            _log(f"loaded {len(index)} requirements from {path}")
            return index
    return {}


def _requirements_by_id(data):
    """Requirements of a catalog's categories by id; the first entry of a duplicated id wins."""
    index = {}
    for cat in data.get("categories") or []:
        if not isinstance(cat, dict):
            continue
        for req in cat.get("requirements") or []:
            if not isinstance(req, dict):
                continue
            rid = req.get("id")
            if not rid or rid in index:
                continue
            index[rid] = {
                "text": (req.get("text") or "").strip(),
                "priority": req.get("priority"),
                "url": req.get("url"),
            }
    return index


# ---------------------------------------------------------------------------
# Prompt matching and context assembly
# ---------------------------------------------------------------------------


def _count_matches(keywords, text):
    """How many distinct keywords occur in text as whole words; the caller lower-cases the text."""
    return sum(1 for kw in keywords if kw and re.search(r"\b" + re.escape(kw) + r"\b", text))


def _match_topics(topics, text):
    """Return {topic_name: match_count} for topics whose triggers appear in text."""
    hits = {}
    for name, spec in (topics or {}).items():
        if not isinstance(spec, dict):
            continue
        count = _count_matches(spec.get("triggers") or [], text)
        if count > 0:
            hits[name] = count
    return hits


def _should_trigger(cfg, prompt, matched_topics):
    """Whether the prompt looks like coding work: a topic matched, or enough code and action words."""
    if matched_topics:
        return True
    t = cfg["thresholds"]
    code = _count_matches(cfg["code_keywords"], prompt)
    action = _count_matches(cfg["action_keywords"], prompt)
    return code >= _limit(t, _DEFAULT_THRESHOLDS, "code_min") or (
        code >= _limit(t, _DEFAULT_THRESHOLDS, "code_action_code_min")
        and action >= _limit(t, _DEFAULT_THRESHOLDS, "code_action_action_min")
    )


def _limit(values, defaults, key):
    """A configured number; a missing, zero or empty value falls back to the default."""
    return int(values.get(key, defaults[key]) or defaults[key])


def _assemble_context(cfg, matched_topics, req_index):
    """Return (assembled_context, resolved_req_ids).

    resolved_req_ids is the flat list of requirement IDs that were successfully
    looked up in the YAML and rendered into the output — used for telemetry so
    the log reflects what Claude actually saw, not what the config aspired to.
    """
    parts = [cfg["baseline"]]
    resolved_req_ids = []
    max_per_topic = _limit(cfg["severity"], _DEFAULT_SEVERITY, "max_requirements_per_topic")

    # Topics with more triggers first; tiebreak alphabetically for stability
    ordered = sorted(matched_topics.items(), key=lambda kv: (-kv[1], kv[0]))

    for name, _count in ordered:
        spec = cfg["topics"].get(name, {})
        if not isinstance(spec, dict):
            continue
        guidance = (spec.get("guidance") or "").strip()
        if guidance:
            parts.append(f"\n[{name}] {guidance}")
        lines, ids = _requirement_lines(spec, req_index, max_per_topic)
        if lines:
            parts.append("Applicable requirements:")
            parts.extend(lines)
            resolved_req_ids.extend(ids)

    assembled = "\n".join(parts)
    cap = _limit(cfg["severity"], _DEFAULT_SEVERITY, "max_injected_chars")
    if len(assembled) > cap:
        assembled = assembled[: max(0, cap - 3)] + "..."
    return assembled, resolved_req_ids


def _requirement_lines(spec, req_index, max_per_topic):
    """One ``- id (priority): text`` line per requirement of a topic that the active catalog defines with text.

    Ids absent from the catalog are dropped BEFORE capping, so a topic can list both company (SEC-*) and
    best-practices (BP-*) ids and the right set survives depending on which catalog is loaded. Capping first
    would let absent ids consume the per-topic budget and inject fewer (or zero) lines.
    """
    req_ids = [rid for rid in (spec.get("requirements") or []) if isinstance(rid, str) and req_index.get(rid)]
    lines, ids = [], []
    for rid in req_ids[:max_per_topic]:
        entry = req_index[rid]
        body = (entry.get("text") or "").replace("\n", " ").strip()
        if not body:
            continue
        lines.append(f"  - {rid} ({entry.get('priority') or '—'}): {body}")
        ids.append(rid)
    return lines, ids


# ---------------------------------------------------------------------------
# Telemetry — append COACH_INJECTED to docs/security/.hook-events.log
# ---------------------------------------------------------------------------


def _log_coach_event(topics, req_ids, chars, prompt):
    """Append a COACH_INJECTED line to .hook-events.log.

    Best-effort. Never raises: a non-writable log directory (e.g. read-only
    filesystem, `--repo` pointing at an external tree) must not fail the hook.
    Format matches agent_logger._write() so both producers share one log.
    The prompt is recorded only as a short hash, never as text.
    """
    try:
        log_dir = os.path.join(os.getcwd(), "docs", "security")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, ".hook-events.log")

        topic_str = ",".join(sorted(t for t in topics if not t.startswith("_"))) or "-"
        req_str = ",".join(req_ids) if req_ids else "-"
        prompt_hash = hashlib.sha256(prompt.encode("utf-8", "replace")).hexdigest()[:8]
        detail = f"topics={topic_str} req_ids={req_str} chars={chars} prompt={prompt_hash}"
        line = format_line("COACH_INJECTED", detail)

        with open(log_file, "a") as fh:
            fh.write(line)
    except Exception as exc:
        _log(f"coach telemetry skipped: {exc}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _emit(payload):
    """Write the hook answer and end the process; every handled path exits 0 so a prompt is never blocked."""
    print(json.dumps(payload))
    sys.exit(0)


def main():
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        _log(f"steering hook received invalid JSON: {exc}")
        _emit({})

    if not isinstance(data, dict):
        _emit({})

    prompt = (data.get("prompt") or "").lower()
    if not prompt:
        _emit({})

    cfg = _load_config()
    activation = _activation_source(cfg)
    if activation is None:
        _emit({})

    matched_topics = _match_topics(cfg["topics"], prompt)
    if not _should_trigger(cfg, prompt, matched_topics):
        _emit({})

    # The catalog is read only when a matched topic can cite requirements from it.
    req_index = _load_requirements_index(cfg) if matched_topics else {}
    context, resolved_req_ids = _assemble_context(cfg, matched_topics, req_index)

    # Topics whose name starts with _ (the legacy topic) are internal and never named to the user.
    visible_topics = sorted(n for n in matched_topics if not n.startswith("_"))
    topic_suffix = f": {', '.join(visible_topics)}" if visible_topics else ""
    _log_coach_event(topics=visible_topics, req_ids=resolved_req_ids, chars=len(context), prompt=prompt)
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": context,
            },
            "systemMessage": f"AppSec Coach active (via {activation}){topic_suffix}.",
        }
    )


if __name__ == "__main__":
    main()
