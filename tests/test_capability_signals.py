"""Capabilities come from call sites that prove the function, never from names or comments."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from analyzers.capability_signals import capabilities  # noqa: E402


@pytest.mark.parametrize(
    ("path", "source", "capability", "line"),
    [
        (
            "lib/tokens.ts",
            "import jwt from 'jsonwebtoken'\nexport const issue = (u) => jwt.sign(u, key)\n",
            "jwt-issuer",
            2,
        ),
        ("auth/session.py", "import jwt\n\ndef issue(user):\n    return jwt.encode(user, KEY)\n", "jwt-issuer", 4),
        (
            "routes/otp.ts",
            "import { verifySync } from 'otplib'\nconst ok = verifySync({ token, secret })\n",
            "mfa-verifier",
            2,
        ),
        (
            "svc/mfa.js",
            "const otplib = require('otplib')\nif (otplib.authenticator.check(t, s)) next()\n",
            "mfa-verifier",
            2,
        ),
        (
            "chain/wallet.ts",
            "const { JsonRpcProvider } = await import('ethers')\nconst p = new JsonRpcProvider(url)\n",
            "blockchain-client",
            2,
        ),
        ("api/upload.js", "const upload = multer({ dest: 'tmp/' })\n", "file-upload", 1),
        (
            "ui/login.ts",
            "location.href = `https://idp.example.invalid/oauth2/authorize?client_id=${id}`\n",
            "oauth-client",
            1,
        ),
        (
            "rt/socket.js",
            "const io = require('socket.io')(server)\nio.on('connection', onConnect)\n",
            "websocket-endpoint",
            2,
        ),
        ("lib/feed.ts", "const doc = libxml.parseXml(body, { noent: true })\n", "xml-parsing", 1),
    ],
)
def test_a_call_site_proves_the_capability(path, source, capability, line):
    found = {row["capability"]: row["evidence"] for row in capabilities({path: source.encode()})}
    assert found[capability][0] == {"file": path, "line": line}


@pytest.mark.parametrize(
    ("path", "source"),
    [
        ("lib/tokens.ts", "// jwt.sign(user, key) was removed\n"),
        ("lib/tokens.test.ts", "jwt.sign(user, key)\n"),
        ("tests/otp_test.py", "pyotp.TOTP(secret).verify(code)\n"),
        ("lib/names.ts", "const jwtSign = 'jwt.sign is documented elsewhere'.length\nexport const verifySync = 1\n"),
        ("routes/otp.ts", "import { verifySync } from 'otplib'\n"),
        ("lib/math.ts", "import { verify } from './local-verify'\nverify(x)\n"),
    ],
    ids=["comment", "test-file", "python-test-dir", "names-only", "import-only", "local-module"],
)
def test_names_comments_tests_and_imports_prove_nothing(path, source):
    assert [row for row in capabilities({path: source.encode()}) if row["capability"] != "code-evaluation"] == []
