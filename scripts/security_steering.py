import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

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

_DEFAULT_THRESHOLDS = {
    "code_min": 2,
    "code_action_code_min": 1,
    "code_action_action_min": 1,
}

_DEFAULT_SEVERITY = {
    "max_injected_chars": 2500,
    "max_requirements_per_topic": 3,
}

_DEFAULT_REQ_SOURCE_PATHS = [
    ".cache/requirements.yaml",
    "data/appsec-requirements-fallback.yaml",
]


def _verbose():
    return os.environ.get("APPSEC_VERBOSE", "").strip() not in ("", "0", "false", "no")


def _log(msg):
    if _verbose():
        print(f"[appsec] {msg}", file=sys.stderr)


_TRUTHY = {"1", "true", "yes", "on", "enable", "enabled"}
_FALSY = {"0", "false", "no", "off", "disable", "disabled"}


def _activation_source(cfg):
    """Decide whether the coach is active and where the signal came from.

    Precedence: environment variable wins (it can force-on OR force-off),
    then the config file's `enabled` flag, then off.
    Returns a short source label ("env" | "config") when active, else None.
    """
    env = os.environ.get("APPSEC_COACH", "").strip().lower()
    if env in _TRUTHY:
        return "env"
    if env in _FALSY:
        return None
    if cfg.get("enabled") is True:
        return "config"
    return None


def _plugin_roots():
    """Return candidate paths that resolve to the  directory."""
    roots = []
    env_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "").strip()
    if env_root:
        roots.append(env_root)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    roots.append(os.path.normpath(os.path.join(script_dir, "..")))
    # Deduplicate while preserving order
    seen, out = set(), []
    for r in roots:
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _load_config():
    """Load steering_keywords.json or fall back to defaults. Backwards-compatible
    with the old schema (top-level `strong`, `code`, `action`, `thresholds`)."""
    candidates = [os.path.join(root, "hooks", "steering_keywords.json") for root in _plugin_roots()]

    loaded = None
    for path in candidates:
        try:
            with open(path) as fh:
                loaded = json.load(fh)
            break
        except Exception as exc:
            _log(f"config candidate {path} skipped: {exc}")

    cfg = {
        "enabled": False,
        "baseline": _DEFAULT_BASELINE,
        "code_keywords": set(_DEFAULT_CODE),
        "action_keywords": set(_DEFAULT_ACTION),
        "thresholds": dict(_DEFAULT_THRESHOLDS),
        "severity": dict(_DEFAULT_SEVERITY),
        "topics": {},
        "requirements_source": {"paths": list(_DEFAULT_REQ_SOURCE_PATHS)},
    }

    if not loaded:
        return cfg

    cfg["enabled"] = bool(loaded.get("enabled", False))
    if "baseline" in loaded and isinstance(loaded["baseline"], str):
        cfg["baseline"] = loaded["baseline"]

    # New schema
    if "code_keywords" in loaded:
        cfg["code_keywords"] = set(loaded["code_keywords"])
    elif "code" in loaded:  # old schema
        cfg["code_keywords"] = set(loaded["code"])

    if "action_keywords" in loaded:
        cfg["action_keywords"] = set(loaded["action_keywords"])
    elif "action" in loaded:  # old schema
        cfg["action_keywords"] = set(loaded["action"])

    if isinstance(loaded.get("thresholds"), dict):
        cfg["thresholds"].update(loaded["thresholds"])
    if isinstance(loaded.get("severity"), dict):
        cfg["severity"].update(loaded["severity"])

    if isinstance(loaded.get("topics"), dict):
        cfg["topics"] = loaded["topics"]
    elif "strong" in loaded:
        # Old schema migration: treat `strong` as a single unnamed topic
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

    return cfg


def _load_requirements_index(cfg):
    """Build {id: {text, priority, url}} from the first readable requirements YAML."""
    try:
        import yaml
    except ImportError:
        _log("pyyaml unavailable — requirements injection disabled")
        return {}

    rel_paths = cfg["requirements_source"].get("paths") or []
    tried = []
    for root in _plugin_roots():
        for rel in rel_paths:
            tried.append(os.path.join(root, rel))

    for path in tried:
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
        if index:
            _log(f"loaded {len(index)} requirements from {path}")
            return index
    return {}


def _count_matches(keywords, text):
    hits = 0
    for kw in keywords:
        if not kw:
            continue
        if re.search(r"\b" + re.escape(kw) + r"\b", text):
            hits += 1
    return hits


def _match_topics(topics, text):
    """Return {topic_name: match_count} for topics whose triggers appear in text."""
    hits = {}
    for name, spec in (topics or {}).items():
        if not isinstance(spec, dict):
            continue
        triggers = spec.get("triggers") or []
        count = _count_matches(triggers, text)
        if count > 0:
            hits[name] = count
    return hits


def _assemble_context(cfg, matched_topics, req_index):
    """Return (assembled_context, resolved_req_ids).

    resolved_req_ids is the flat list of requirement IDs that were successfully
    looked up in the YAML and rendered into the output — used for telemetry so
    the log reflects what Claude actually saw, not what the config aspired to.
    """
    parts = [cfg["baseline"]]
    resolved_req_ids = []

    max_per_topic = int(cfg["severity"].get("max_requirements_per_topic", 3) or 3)

    # Topics with more triggers first; tiebreak alphabetically for stability
    ordered = sorted(matched_topics.items(), key=lambda kv: (-kv[1], kv[0]))

    for name, _count in ordered:
        spec = cfg["topics"].get(name, {})
        if not isinstance(spec, dict):
            continue
        guidance = (spec.get("guidance") or "").strip()
        if guidance:
            parts.append(f"\n[{name}] {guidance}")

        req_ids = [rid for rid in (spec.get("requirements") or []) if isinstance(rid, str)]
        req_ids = req_ids[:max_per_topic]
        resolved_lines = []
        for rid in req_ids:
            entry = req_index.get(rid)
            if not entry:
                continue
            body = (entry.get("text") or "").replace("\n", " ").strip()
            if not body:
                continue
            priority = entry.get("priority") or "—"
            resolved_lines.append(f"  - {rid} ({priority}): {body}")
            resolved_req_ids.append(rid)
        if resolved_lines:
            parts.append("Applicable requirements:")
            parts.extend(resolved_lines)

    assembled = "\n".join(parts)
    cap = int(cfg["severity"].get("max_injected_chars", 2500) or 2500)
    if len(assembled) > cap:
        assembled = assembled[: max(0, cap - 3)] + "..."
    return assembled, resolved_req_ids


# ---------------------------------------------------------------------------
# Telemetry — append COACH_INJECTED to docs/security/.hook-events.log
# ---------------------------------------------------------------------------


def _log_coach_event(topics, req_ids, chars, prompt):
    """Append a COACH_INJECTED line to .hook-events.log.

    Best-effort. Never raises: a non-writable log directory (e.g. read-only
    filesystem, `--repo` pointing at an external tree) must not fail the hook.
    Format matches agent_logger._write() so both producers share one log.
    """
    try:
        log_dir = os.path.join(os.getcwd(), "docs", "security")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, ".hook-events.log")

        topic_str = ",".join(sorted(t for t in topics if not t.startswith("_"))) or "-"
        req_str = ",".join(req_ids) if req_ids else "-"
        prompt_hash = hashlib.sha256(prompt.encode("utf-8", "replace")).hexdigest()[:8]
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        detail = f"topics={topic_str} req_ids={req_str} chars={chars} prompt={prompt_hash}"
        line = f"{ts}  [--------]  {'INFO':<5}  {'COACH_INJECTED':<18}  {detail}\n"

        with open(log_file, "a") as fh:
            fh.write(line)
    except Exception as exc:
        _log(f"coach telemetry skipped: {exc}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _emit(payload):
    print(json.dumps(payload))
    sys.exit(0)


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
code = _count_matches(cfg["code_keywords"], prompt)
action = _count_matches(cfg["action_keywords"], prompt)

t = cfg["thresholds"]
should_trigger = (
    bool(matched_topics)
    or code >= int(t.get("code_min", 2) or 2)
    or (code >= int(t.get("code_action_code_min", 1) or 1) and action >= int(t.get("code_action_action_min", 1) or 1))
)

if not should_trigger:
    _emit({})

req_index = _load_requirements_index(cfg) if matched_topics else {}
context, resolved_req_ids = _assemble_context(cfg, matched_topics, req_index)

visible_topics = sorted(n for n in matched_topics if not n.startswith("_"))
topic_suffix = f": {', '.join(visible_topics)}" if visible_topics else ""
system_msg = f"AppSec Coach active (via {activation}){topic_suffix}."

_log_coach_event(
    topics=visible_topics,
    req_ids=resolved_req_ids,
    chars=len(context),
    prompt=prompt,
)

_emit(
    {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        },
        "systemMessage": system_msg,
    }
)
