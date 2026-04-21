#!/usr/bin/env python3
"""
Mock context server for appsec-advisor development.

Returns free-form context text for a repository URL.
Replace with your own endpoint or point rest_url at any service
that accepts POST {"repo_url": "..."} and returns {"context": "..."}.

Usage:
    python3 scripts/mock-context-server.py          # default port 4444
    python3 scripts/mock-context-server.py 8080     # custom port
"""

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4444

PATTERNS = [
    (r"payment|checkout|billing|commerce|shop",
     "Payments platform. Compliance: PCI-DSS v4.0. Tier 1 — Mission Critical."),
    (r"auth|identity|sso|login|oauth|iam",
     "Identity / SSO service. Compliance: SOC 2 Type II. Tier 1 — Mission Critical."),
    (r"health|medical|patient|clinic|ehr",
     "Clinical data service. Compliance: HIPAA. Tier 1 — Mission Critical."),
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

        self._respond({"context": f"Repository: {repo}\n{context}"})

    def _respond(self, data):
        payload = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"[mock-context] {fmt % args}")


print(f"[mock-context] Listening on http://127.0.0.1:{PORT}/context  (Ctrl+C to stop)")
HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
