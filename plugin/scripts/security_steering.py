import json
import re
import sys

try:
    data = json.loads(sys.stdin.read())
except Exception:
    print(json.dumps({}))
    sys.exit(0)

prompt = data.get("prompt", "").lower()

# Only inject security context when the prompt is plausibly security- or code-related.
# This avoids latency and noise for purely conversational or administrative inputs.
#
# Matching uses whole-word boundaries (\b) to prevent substring false positives
# (e.g. "api" matching inside "capital", "key" inside "monkey").
SECURITY_KEYWORDS = (
    "code", "function", "class", "module", "api", "endpoint", "auth",
    "login", "token", "password", "secret", "key", "encrypt", "hash",
    "database", "query", "sql", "http", "request", "response", "file",
    "upload", "deploy", "docker", "config", "env", "dependency", "package",
    "import", "install", "script", "shell", "exec", "eval", "security",
    "vulnerability", "threat", "model", "stride", "appsec", "review",
    "write", "implement", "fix", "refactor", "add", "create", "build",
    "oauth", "oidc", "cors", "csrf", "xss", "injection", "tls", "cert",
)

if not any(re.search(r'\b' + re.escape(kw) + r'\b', prompt) for kw in SECURITY_KEYWORDS):
    # Not code/security related — pass through silently
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
