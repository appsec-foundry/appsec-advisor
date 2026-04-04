import json
import sys

sys.stdin.read()

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