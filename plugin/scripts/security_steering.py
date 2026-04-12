import json
import os
import re
import sys

try:
    data = json.loads(sys.stdin.read())
except (json.JSONDecodeError, ValueError, OSError) as exc:
    if os.environ.get("APPSEC_VERBOSE", "").strip() not in ("", "0", "false", "no"):
        print(f"[appsec] warning: steering hook received invalid JSON: {exc}", file=sys.stderr)
    print(json.dumps({}))
    sys.exit(0)

prompt = data.get("prompt", "").lower()

# ---------------------------------------------------------------------------
# Load keyword lists from config file, fall back to built-in defaults
# ---------------------------------------------------------------------------
_DEFAULT_STRONG = {
    "auth", "login", "token", "password", "secret", "encrypt", "hash",
    "sql", "vulnerability", "vulnerabilities", "threat", "stride", "appsec",
    "security", "oauth", "oidc", "cors", "csrf", "xss", "injection", "tls",
    "cert", "eval", "exec", "exploit", "privilege", "permission", "scan",
}

_DEFAULT_CODE = {
    "code", "function", "class", "module", "api", "endpoint",
    "database", "query", "http", "request", "response", "upload",
    "deploy", "docker", "config", "env", "dependency", "package",
    "import", "install", "script", "shell", "middleware", "route",
    "controller", "schema", "migration",
}

_DEFAULT_ACTION = {
    "write", "implement", "fix", "refactor", "add", "create", "build",
    "review", "file", "key",
}

_DEFAULT_THRESHOLDS = {
    "strong_min": 1,
    "code_min": 2,
    "code_action_code_min": 1,
    "code_action_action_min": 1,
}


def _load_keywords():
    """Load keyword lists from steering_keywords.json if available."""
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    config_paths = []
    if plugin_root:
        config_paths.append(os.path.join(plugin_root, "hooks", "steering_keywords.json"))
    # Also check relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_paths.append(os.path.join(script_dir, "..", "hooks", "steering_keywords.json"))

    for path in config_paths:
        try:
            with open(path) as fh:
                cfg = json.load(fh)
            return (
                set(cfg.get("strong", _DEFAULT_STRONG)),
                set(cfg.get("code", _DEFAULT_CODE)),
                set(cfg.get("action", _DEFAULT_ACTION)),
                cfg.get("thresholds", _DEFAULT_THRESHOLDS),
            )
        except Exception as exc:
            if os.environ.get("APPSEC_VERBOSE", "").strip() not in ("", "0", "false", "no"):
                print(f"[appsec] warning: failed to load steering keywords from {path}: {exc}", file=sys.stderr)
            continue

    return _DEFAULT_STRONG, _DEFAULT_CODE, _DEFAULT_ACTION, _DEFAULT_THRESHOLDS


STRONG_KEYWORDS, CODE_KEYWORDS, ACTION_KEYWORDS, THRESHOLDS = _load_keywords()


def _count_matches(keywords, text):
    return sum(1 for kw in keywords if re.search(r'\b' + re.escape(kw) + r'\b', text))


strong = _count_matches(STRONG_KEYWORDS, prompt)
code = _count_matches(CODE_KEYWORDS, prompt)
action = _count_matches(ACTION_KEYWORDS, prompt)

should_trigger = (
    strong >= THRESHOLDS.get("strong_min", 1)
    or code >= THRESHOLDS.get("code_min", 2)
    or (code >= THRESHOLDS.get("code_action_code_min", 1)
        and action >= THRESHOLDS.get("code_action_action_min", 1))
)

if not should_trigger:
    print(json.dumps({}))
    sys.exit(0)

print(json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": (
            "Security steering active. Always implement secure-by-default:\n"
            "- Treat all input as untrusted\n"
            "- Enforce authentication and least privilege\n"
            "- Never hardcode or expose secrets\n"
            "- Use secure defaults\n"
            "- Prevent common vulns\n"
            "- Do not suggest insecure shortcuts"
        )
    },
    "systemMessage": "AppSec steering is active for this prompt."
}))
