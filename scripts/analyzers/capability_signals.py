"""Security-relevant capabilities a component's code shows, with file/line evidence.

Figure 1 labels a component with the functions it performs
(`data/security-capabilities.yaml`). On the single-repository path the
architecture analyst assigns them; a controller assessment has no such field
in its architecture contract, so this module derives the ones a call site
proves. Each rule needs a call of a library or API whose only purpose is the
function, never a name or a comment: signing a JWT, verifying a one-time
password, accepting multipart uploads, opening a WebSocket server, calling a
blockchain RPC provider, starting an OAuth authorization request, parsing XML,
sending e-mail, serving GraphQL, evaluating code. Functions that need
semantics a call cannot show (URL fetch from input, admin functions) stay with
findings and the model. A capability is not a finding and carries no rating.

False-positive exclusions: test files, comment lines, and lines outside the
component's own files never count.
"""

from __future__ import annotations

import re

MAX_CAPABILITIES = 8
MAX_EVIDENCE = 4

# (capability, pattern). A pattern matches one source line.
_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("jwt-issuer", re.compile(r"\b(?:jwt|jsonwebtoken|jws)\s*\.\s*sign\s*\(|\bnew\s+SignJWT\s*\(|\bjwt\.encode\s*\(")),
    (
        "mfa-verifier",
        re.compile(
            r"\b(?:authenticator|totp|hotp)\s*\.\s*(?:check|verify)\w*\s*\("
            r"|\bspeakeasy\s*\.\s*totp\s*\.\s*verify\s*\(|\bpyotp\s*\.\s*TOTP\s*\([^)]*\)\s*\.\s*verify\s*\("
        ),
    ),
    ("file-upload", re.compile(r"\bmulter\s*\(|\bupload\s*\.\s*(?:single|array|fields|any)\s*\(|\brequest\.files\b")),
    (
        "websocket-endpoint",
        re.compile(
            r"\bnew\s+(?:WebSocket\.)?(?:WebSocketServer|Server)\s*\(\s*[\w$.]*(?:server|http|httpServer)\b"
            r"|\bsocketIo\s*\(|\brequire\(\s*['\"]socket\.io['\"]\s*\)\s*\(|\bio\s*\.\s*on\s*\(\s*['\"]connection['\"]"
            r"|@(?:app\.)?websocket\b|\bwebsockets\.serve\s*\("
        ),
    ),
    (
        "blockchain-client",
        re.compile(
            r"\bnew\s+ethers\s*\.\s*(?:providers\s*\.\s*)?\w*Provider\s*\(|\bnew\s+Web3\s*\("
            r"|\bnew\s+(?:Json)?RpcProvider\s*\(|\bWeb3\s*\(\s*Web3\.HTTPProvider"
        ),
    ),
    (
        "oauth-client",
        re.compile(
            r"https://[^\s'\"`]*/(?:o/)?oauth2?/(?:v\d+/)?auth(?:orize)?\b"
            r"|[?&]response_type=(?:code|token|id_token)\b"
        ),
    ),
    (
        "xml-parsing",
        re.compile(
            r"\blibxml(?:js)?\s*\.\s*parseXml\w*\s*\(|\bxml2js\s*\.\s*parseString\w*\s*\(|\bnew\s+DOMParser\s*\("
            r"|\betree\s*\.\s*(?:fromstring|parse|XML)\s*\(|\bxml\.dom\.minidom\.parse\w*\s*\("
        ),
    ),
    ("email-sending", re.compile(r"\bnodemailer\s*\.\s*createTransport\s*\(|\bsmtplib\s*\.\s*SMTP(?:_SSL)?\s*\(")),
    ("graphql-endpoint", re.compile(r"\bnew\s+ApolloServer\s*\(|\bgraphqlHTTP\s*\(|\bcreateYoga\s*\(")),
    (
        "code-evaluation",
        re.compile(r"(?<![\w$.])eval\s*\(|\bvm\s*\.\s*run\w*\s*\(|\bnew\s+Function\s*\(|\bsafeEval\s*\("),
    ),
)
# A call of a name imported from one of these packages proves the capability when
# the imported name matches (`import { verifySync } from 'otplib'`, then `verifySync(`).
_IMPORT_RULES: tuple[tuple[str, frozenset[str], re.Pattern], ...] = (
    (
        "mfa-verifier",
        frozenset({"otplib", "speakeasy", "notp", "@otplib/core", "@otplib/preset-default"}),
        re.compile(r"(?i)verify|check"),
    ),
    ("blockchain-client", frozenset({"ethers", "web3", "viem"}), re.compile(r"Provider$|^Web3$|^create\w*Client$")),
    ("jwt-issuer", frozenset({"jsonwebtoken", "jose"}), re.compile(r"^sign$|^SignJWT$")),
)
# `const { WebSocketProvider } = await import('ethers')`
_DYNAMIC_IMPORT_RE = re.compile(
    r"\b(?:const|let|var)\s+\{(?P<named>[^}]*)\}\s*=\s*(?:await\s+)?import\(\s*['\"](?P<src>[^'\"]+)['\"]\s*\)"
)
_COMMENT_RE = re.compile(r"^\s*(?://|#|\*|/\*|<!--)")
_TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|e2e|cypress|__mocks__)(?:/|$)|\.(?:spec|test|cy)\.\w+$|(?:^|/)test_[^/]*$"
)


def _imported_calls(text: str) -> list[tuple[str, re.Pattern]]:
    """(capability, call pattern) for each local name imported from a rule's package under a matching name."""
    from analyzers.handler_resolver import _JS_IMPORT_RE, _JS_REQUIRE_RE

    calls = []
    found = [*_JS_IMPORT_RE.finditer(text), *_JS_REQUIRE_RE.finditer(text), *_DYNAMIC_IMPORT_RE.finditer(text)]
    for m in found:
        package = m.group("src")
        for capability, packages, names in _IMPORT_RULES:
            if package not in packages:
                continue
            for part in (m.group("named") or "").split(","):
                exported, _, local = part.replace("type ", "").replace(":", " as ").partition(" as ")
                exported, local = exported.strip(), (local or exported).strip()
                if exported and names.search(exported):
                    calls.append((capability, re.compile(rf"(?<![\w$.])(?:new\s+)?{re.escape(local)}\s*\(")))
    return calls


def capabilities(files: dict[str, bytes]) -> list[dict]:
    """``[{capability, evidence: [{file, line}]}]`` for the given component files, in rule order."""
    found: dict[str, list[dict]] = {}
    for path in sorted(files):
        if _TEST_PATH_RE.search(path):
            continue
        text = files[path].decode("utf-8", "replace")
        rules = [*_RULES, *_imported_calls(text)]
        for number, line in enumerate(text.splitlines(), 1):
            if _COMMENT_RE.match(line):
                continue
            for capability, pattern in rules:
                rows = found.setdefault(capability, [])
                if len(rows) < MAX_EVIDENCE and pattern.search(line) and not _imports(line):
                    rows.append({"file": path, "line": number})
    ordered = [{"capability": c, "evidence": found[c]} for c, _ in _RULES if found.get(c)]
    return ordered[:MAX_CAPABILITIES]


def _imports(line: str) -> bool:
    return bool(re.match(r"\s*(?:import\b|(?:const|let|var)\s+[^=]+=\s*require\()", line))
