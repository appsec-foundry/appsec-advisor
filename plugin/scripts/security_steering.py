import json
import re
import sys

try:
    data = json.loads(sys.stdin.read())
except Exception:
    print(json.dumps({}))
    sys.exit(0)

prompt = data.get("prompt", "").lower()

# Tiered keyword matching to reduce false positives on generic prompts
# like "create a README" or "build the frontend".
#
# STRONG: clearly security-related — a single match triggers injection.
# CODE:   code-related but ambiguous alone — 2+ matches required.
# ACTION: generic verbs — never trigger alone, only combined with a CODE keyword.

STRONG_KEYWORDS = {
    "auth", "login", "token", "password", "secret", "encrypt", "hash",
    "sql", "vulnerability", "vulnerabilities", "threat", "stride", "appsec",
    "security", "oauth", "oidc", "cors", "csrf", "xss", "injection", "tls",
    "cert", "eval", "exec", "exploit", "privilege", "permission", "scan",
}

CODE_KEYWORDS = {
    "code", "function", "class", "module", "api", "endpoint",
    "database", "query", "http", "request", "response", "upload",
    "deploy", "docker", "config", "env", "dependency", "package",
    "import", "install", "script", "shell", "middleware", "route",
    "controller", "schema", "migration",
}

ACTION_KEYWORDS = {
    "write", "implement", "fix", "refactor", "add", "create", "build",
    "review", "file", "key",
}


def _count_matches(keywords, text):
    return sum(1 for kw in keywords if re.search(r'\b' + re.escape(kw) + r'\b', text))


strong = _count_matches(STRONG_KEYWORDS, prompt)
code = _count_matches(CODE_KEYWORDS, prompt)
action = _count_matches(ACTION_KEYWORDS, prompt)

should_trigger = (
    strong >= 1           # any strong keyword is enough
    or code >= 2          # 2+ code keywords together
    or (code >= 1 and action >= 1)  # 1 code + 1 action
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
