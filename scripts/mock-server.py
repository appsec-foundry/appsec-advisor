#!/usr/bin/env python3
"""
Combined mock server for appsec-advisor development.

Endpoints:
    POST /              → business context  (external_context.rest_url)
    GET  /requirements.yaml → serves examples/appsec-requirements-example.yaml
                              (requirements_yaml_url)

Usage:
    python3 scripts/mock-server.py          # default port 4444
    python3 scripts/mock-server.py 8080     # custom port

Config snippet (config.json):
    {
      "external_context": {
        "enabled": true,
        "rest_url": "http://127.0.0.1:4444/"
      }
    }

Config snippet (skills/audit-security-requirements/config.json):
    {
      "requirements_source": {
        "enabled": true,
        "requirements_yaml_url": "http://127.0.0.1:4444/requirements.yaml"
      }
    }
"""

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4444

REQUIREMENTS_FILE = Path(__file__).parent.parent / "examples" / "appsec-requirements-example.yaml"

PATTERNS = [
    (
        r"payment|checkout|billing|commerce|shop",
        "Payments platform. Compliance: PCI-DSS v4.0. Tier 1 — Mission Critical.",
    ),
    (
        r"auth|identity|sso|login|oauth|iam",
        "Identity / SSO service. Compliance: SOC 2 Type II. Tier 1 — Mission Critical.",
    ),
    (r"health|medical|patient|clinic|ehr", "Clinical data service. Compliance: HIPAA. Tier 1 — Mission Critical."),
]

DEFAULT_CONTEXT = "Internal application. Compliance: SOC 2 Type II. Tier 2."


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        repo = body.get("repo_url", "")

        context = next(
            (text for pattern, text in PATTERNS if re.search(pattern, repo, re.I)),
            DEFAULT_CONTEXT,
        )

        self._respond_json({"context": f"Repository: {repo}\n{context}"})

    def do_GET(self):
        if self.path != "/requirements.yaml":
            self.send_error(404)
            return

        if not REQUIREMENTS_FILE.exists():
            self.send_error(404, f"Not found: {REQUIREMENTS_FILE}")
            return

        payload = REQUIREMENTS_FILE.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/yaml")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _respond_json(self, data):
        payload = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"[mock-server] {fmt % args}")


print(f"[mock-server] Listening on http://127.0.0.1:{PORT}")
print("[mock-server]   POST /                  → business context")
print(f"[mock-server]   GET  /requirements.yaml → {REQUIREMENTS_FILE.name}")
print("[mock-server] Ctrl+C to stop")
HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
