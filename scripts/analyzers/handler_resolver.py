"""Resolve a route's handler chain to code and classify its authentication.

A route inventory sees where a route is registered; a handler usually proves
authentication inside its own body (a session-store lookup keyed by a cookie, a
token verification, a rejecting branch). This module follows every element that
runs for a route - the registration's arguments and, for call-registered
routes, the middlewares mounted on the same application object before it - to
its definition and classifies the resolved code:

- ``verified``    a credential is read, checked against a verifier or session
                  store, and a rejecting branch follows within a few lines;
- ``decode_only`` a token is decoded without signature verification;
- ``none``        every element resolved, none reads a credential (or only as a
                  pass-through loader, below), and the application object is
                  created in the registration file, so no unseen global
                  middleware can authenticate the route;
- ``unresolved``  anything else: an element that cannot be followed (unknown
                  package, dynamic dispatch, a conditional guard, a missing
                  definition), a credential read without a check, or a router
                  whose mounting context lies in another file.

A JavaScript middleware that reads or decodes a credential but can never stop
the request is a pass-through loader (an identity cache, a challenge or audit
hook) and authenticates nothing: it calls only an argument-less ``next()``,
writes no response, throws nothing, and verifies only through a callback, so a
failed verification cannot reject. Any response call, ``throw``, ``next(arg)``
or synchronous verify keeps the element unresolved, because the request may
end there.

Resolution covers JavaScript/TypeScript call registrations (same-file
definitions, ES imports and ``require`` of repository modules, factory calls,
objects created by a package call, one level of same-file helpers) and
decorated Python handlers including FastAPI ``Depends(...)``/``Security(...)``
targets. A call of a known authentication middleware package
(``_AUTHENTICATING_PACKAGES``) counts as ``verified`` when its inline options
keep rejection on; NestJS handlers report ``verified``/``decode_only`` only, because
class and global guards stay invisible. Other stacks return no signal. Comments
never count, only a function's own body counts, and test files are never used
as definitions. ``analyzers/route_inventory.py`` records the signal and
``analyzers/authz_confirm.py`` reads handler bodies through the same resolver.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from shared._path_guard import is_safe_to_read

SIGNALS = ("verified", "decode_only", "none", "unresolved")
DECODE_ONLY_SCOPE = "token decoded without signature verification"

_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_CALL_FRAMEWORKS = {"express", "koa", "fastify", "hapi"}
_PY_FRAMEWORKS = {"fastapi", "flask"}
RESOLVED_FRAMEWORKS = frozenset(_CALL_FRAMEWORKS | _PY_FRAMEWORKS | {"nestjs"})
_MAX_FILE_BYTES = 1_000_000
_MAX_EVIDENCE = 8
_REJECT_WINDOW = 8

# Middleware packages that never read a credential: body parsing, uploads,
# compression, CORS, security headers, logging, metrics, rate limiting,
# localisation, static files, robots and error pages. Any other package that
# _AUTHENTICATING_PACKAGES does not list is unresolved, because it may authenticate.
_NON_CREDENTIAL_PACKAGES = frozenset(
    {
        "body-parser",
        "compression",
        "connect-timeout",
        "cookie-parser",
        "cors",
        "errorhandler",
        "express",
        "express-prom-bundle",
        "express-rate-limit",
        "express-robots-txt",
        "express-validator",
        "feature-policy",
        "helmet",
        "hpp",
        "i18n",
        "method-override",
        "morgan",
        "multer",
        "pino-http",
        "prom-client",
        "response-time",
        "serve-favicon",
        "serve-index",
        "serve-static",
    }
)


@dataclass(frozen=True)
class _PackageGuard:
    """A call of an authentication middleware package that rejects requests without a valid credential.

    ``evidence`` is the repository line that calls the package, set once the
    call's options are seen to keep rejection on; until then the guard only
    names the package's scheme and the option that would turn rejection off.
    """

    scheme: str
    members: frozenset[str] | None
    disabled: re.Pattern | None
    evidence: tuple[str, int] | None = None


# Middleware packages whose call rejects a request without a valid credential
# by default: (scheme, exported members that do so or None for any, option that
# turns rejection off). Session loaders such as express-session and strategy
# frameworks such as passport are absent: they do not reject on their own.
_AUTHENTICATING_PACKAGES = {
    "express-jwt": _PackageGuard("bearer", None, re.compile(r"\bcredentialsRequired\s*:\s*false\b")),
    "koa-jwt": _PackageGuard("bearer", None, re.compile(r"\bpassthrough\s*:\s*true\b")),
    "express-oauth2-jwt-bearer": _PackageGuard(
        "bearer", frozenset({"auth"}), re.compile(r"\bauthRequired\s*:\s*false\b")
    ),
    "express-basic-auth": _PackageGuard("other", None, None),
}
_JS_INLINE_OPTIONS_RE = re.compile(r"[\s(]*\{.*\}[\s)]*(?:as\s+[\w$.<>]+\s*)?", re.DOTALL)
_JS_APP_FACTORY_RE = re.compile(
    r"=\s*(?:express|fastify|restify\.createServer)\s*\(|=\s*new\s+Koa\s*\(|Hapi\.server\s*\("
)
_PY_APP_FACTORY_RE = re.compile(r"=\s*(?:FastAPI|Flask)\s*\(")
_PY_GLOBAL_HOOK_RE = re.compile(r"\bbefore_request\b|\badd_middleware\s*\(|\bmiddleware\s*\(\s*['\"]http")

_TEST_PATH_RE = re.compile(r"(?:^|/)(?:tests?|__tests__|spec)(?:/|$)|(?:^|/)test_[^/]*\.py$|\.(?:spec|test)\.[jt]sx?$")

# --- JavaScript / TypeScript signals -----------------------------------------
# `?.` (optional chaining) reads a member exactly like `.`.
_JS_CREDENTIAL_RE = re.compile(
    r"\breq(?:uest)?\s*\??\.\s*(?:signed)?[cC]ookies\s*(?:\??\.\s*|(?:\?\.)?\[\s*['\"`])"
    r"(?:token|jwt|session\w*|sid|auth\w*|access\w*|id_?token|connect\.sid)\b"
    r"|\bheaders\s*(?:\??\.\s*authorization\b|(?:\?\.)?\[\s*['\"`]authorization['\"`])"
    r"|\??\.get\(\s*['\"`]authorization['\"`]"
    r"|\b[\w$]*(?:jwt|Jwt|JWT|[tT]oken)[\w$]*\s*\(\s*req(?:uest)?\b"
    r"|\breq(?:uest)?\s*\??\.\s*(?:user|session|auth)\b"
    r"|\bisAuthenticated\s*\("
    # A token field read from the body or query (`req.body.tmpToken`,
    # `const { tmpToken } = req.body`). CSRF and captcha tokens are not credentials.
    r"|\breq(?:uest)?\s*\??\.\s*(?:body|query)\s*\??\.\s*(?![\w$]*(?i:csrf|xsrf|captcha))[\w$]*[tT]oken\b"
    r"|\{[^{}]*\b(?![\w$]*(?i:csrf|xsrf|captcha))[\w$]*[tT]oken\b[^{}]*\}\s*=\s*req(?:uest)?\s*\??\.\s*(?:body|query)\b"
)
_JS_VERIFY_RE = re.compile(
    r"(?:\.|\b)verify(?:Token|Jwt|JWT|IdToken|Signature|Session|Credentials)?\s*\("
    r"|\.get\(\s*req(?:uest)?\s*\??\.\s*(?:signed)?(?:[cC]ookies|headers)\b"
    r"|\bisAuthenticated\s*\(\s*\)"
    r"|\bgetServerSession\s*\("
    r"|\bif\s*\(\s*!\s*req(?:uest)?\s*\??\.\s*(?:user|session)\b"
)
_JS_DECODE_RE = re.compile(
    r"\b(?:jwt|jws|jose)\s*\.\s*decode\w*\s*\(|\bjwt_?[dD]ecode\s*\(|\.decode\w*\s*\(\s*[\w$.]*(?:[tT]oken|jwt|JWT)"
)
_JS_REJECT_RE = re.compile(
    r"\.status\(\s*40[13]\s*\)|\bsendStatus\(\s*40[13]\s*\)|\bnext\(\s*new\s+\w*Error\b"
    r"|\bthrow\s+new\s+\w*(?:Unauthori[sz]ed|Forbidden|Auth\w*)\w*|\bUnauthori[sz]ed\w*\s*\("
    r"|\.redirect\(\s*['\"`][^'\"`]*login"
)
# What lets a middleware end or reject the request; its absence makes a credential read pass-through.
_JS_REQUEST_END_RE = re.compile(
    r"\b(?:res|response|reply|ctx)\s*\.\s*(?:status|sendStatus|send|json|end|redirect|render|sendFile|code|body)\b"
    r"|\bthrow\b|\bnext\s*\(\s*[^)\s]"
)
_JS_BARE_NEXT_RE = re.compile(r"\bnext\s*\(\s*\)")
_JS_CALLBACK_RE = re.compile(r"=>|\bfunction\b")
_JS_IMPORT_RE = re.compile(
    r"\bimport\s+(?:type\s+)?(?:(?P<default>[\w$]+)\s*,?\s*)?"
    r"(?:\{(?P<named>[^}]*)\}|\*\s+as\s+(?P<ns>[\w$]+))?\s*from\s*['\"](?P<src>[^'\"]+)['\"]"
)
_JS_REQUIRE_RE = re.compile(
    r"\b(?:const|let|var)\s+(?:(?P<name>[\w$]+)|\{(?P<named>[^}]*)\})\s*=\s*"
    r"require\(\s*['\"](?P<src>[^'\"]+)['\"]\s*\)"
)
_JS_CALLEE_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(")
_JS_PATH_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$")
_JS_FUNCTION_START_RE = re.compile(r"^(?:async\s+)?(?:function\b|\(|[\w$]+\s*=>)")
_JS_STRING_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`(?:[^`\\]|\\.)*`")

# --- Python signals ----------------------------------------------------------
_PY_CREDENTIAL_RE = re.compile(
    r"(?i)\bauthorization\b|\bOAuth2PasswordBearer\b|\bHTTPBearer\b|\bAPIKey\w*\b|\brequest\.cookies\b"
    r"|\btoken\b|\bsession\b|\bcurrent_user\b|\brequest\.user\b"
)
_PY_VERIFY_RE = re.compile(
    r"\bjwt\.decode\s*\((?![^)]*(?:verify_signature['\"]?\s*:\s*False|verify\s*=\s*False))"
    r"|\bverify\w*\s*\(|\brequest\.user\.is_authenticated\b|\bsession(?:\.get\(|\[)\s*['\"]user"
)
_PY_DECODE_RE = re.compile(r"\bjwt\.decode\s*\(|\bget_unverified_\w+\s*\(")
_PY_REJECT_RE = re.compile(
    r"\bHTTPException\([^)]*40[13]|\bstatus\.HTTP_40[13]\w*|\babort\(\s*40[13]"
    r"|\braise\s+\w*(?:Unauthori[sz]ed|Forbidden|Authentication|Permission)\w*|\breturn\b[^\n]*\b40[13]\b"
)
_PY_DEPENDS_RE = re.compile(r"\b(?:Depends|Security)\(\s*([A-Za-z_][\w.]*)")
_PY_ROUTE_DECORATOR_RE = re.compile(
    r"^\s*@\w+(?:\.\w+)*\.(?:get|post|put|patch|delete|head|options|route|api_route)\s*\("
)
_PY_IMPORT_RE = re.compile(r"^\s*from\s+(?P<mod>[\w.]+)\s+import\s+(?P<names>[^\n#]+)", re.MULTILINE)

Body = tuple[str, int, str]


@dataclass
class HandlerSignal:
    signal: str
    scheme: str | None = None
    evidence: list[dict] = field(default_factory=list)
    bodies: list[Body] = field(default_factory=list)

    def scope(self) -> str:
        if self.signal == "verified":
            return f"the handler checks a {self.scheme} credential and rejects the request without it"
        if self.signal == "decode_only":
            return DECODE_ONLY_SCOPE
        return "no credential check in the resolved handler chain"


def _skip_string(text: str, i: int) -> int:
    quote, i = text[i], i + 1
    while i < len(text) and text[i] != quote:
        i += 2 if text[i] == "\\" else 1
    return i + 1


#: Handler factories nest a few arrows at most; the cap bounds a pathological chain.
_MAX_CURRIED_ARROWS = 4


def _is_arrow(text: str, start: int) -> bool:
    """Whether an arrow function starts at `start`."""
    rest = text[start:]
    params = start + len(re.match(r"(?:async\s+)?", rest).group(0))
    return bool(_JS_FUNCTION_START_RE.match(rest)) and "=>" in rest.split("\n", 1)[0] + (
        text[params : _matching(text, params)] if text.startswith("(", params) else ""
    )


def _strip_js_comments(text: str) -> str:
    """Blank comments while keeping offsets and line numbers."""
    out, i = list(text), 0
    while i < len(text):
        if text[i] in "'\"`":
            i = _skip_string(text, i)
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
            out[i:end] = " " * (end - i)
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = len(text) if end < 0 else end + 2
            out[i:end] = [c if c == "\n" else " " for c in text[i:end]]
            i = end
        else:
            i += 1
    return "".join(out)


def _matching(text: str, i: int) -> int:
    """Index just past the bracket that closes the one at `i`; strings do not count."""
    depth = 0
    while i < len(text):
        if text[i] in "'\"`":
            i = _skip_string(text, i)
            continue
        if text[i] in "([{":
            depth += 1
        elif text[i] in ")]}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def _split_args(text: str) -> list[str]:
    args, depth, start, i = [], 0, 0, 0
    while i < len(text):
        if text[i] in "'\"`":
            i = _skip_string(text, i)
            continue
        if text[i] in "([{":
            depth += 1
        elif text[i] in ")]}":
            depth -= 1
        elif text[i] == "," and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    return [a for a in [*args, text[start:].strip()] if a]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_offset(text: str, line: int) -> int:
    return sum(len(row) + 1 for row in text.split("\n")[: line - 1])


def _indented_block(lines: list[str], start: int) -> int:
    base = len(lines[start]) - len(lines[start].lstrip())
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) > base):
        end += 1
    return end


def _returned_package_call(code: str, imports: dict[str, tuple[str, str]]) -> str | None:
    """Callee of a factory that only returns a package call (`() => pkg(...)`); its result is that package's code."""
    arrow = code.find("=>")
    if 0 <= arrow < (code.find("{") if "{" in code else len(code)):
        m = re.match(r"\s*(?:await\s+)?([A-Za-z_$][\w$.]*)\s*\(", code[arrow + 2 :])
    else:
        m = re.match(r"\s*return\s+(?:await\s+)?([A-Za-z_$][\w$.]*)\s*\(", code[code.find("{") + 1 :])
    root = m.group(1).split(".")[0] if m else ""
    return m.group(1) if m and root in imports and not imports[root][0].startswith(".") else None


def _rejecting_call(code: str, callee: str, guard: _PackageGuard) -> bool:
    """`code` calls `callee` with inline options that keep the package's rejection on.

    Options passed by name could hold the disabling option unseen, so only an
    inline object literal counts.
    """
    m = re.search(rf"(?<![\w$]){re.escape(callee)}\s*\(", code)
    if not m:
        return False
    args = code[m.end() : _matching(code, m.end() - 1) - 1]
    return bool(_JS_INLINE_OPTIONS_RE.fullmatch(args)) and not (guard.disabled and guard.disabled.search(args))


def direct_imports(path: str, text: str, exists) -> list[str]:
    """Repository files `path` imports directly, resolved against a file set (MR-19).

    `exists(candidate)` tells whether a repository-relative file is admitted.
    JavaScript/TypeScript relative ``import``/``require`` and Python relative
    or root-anchored ``from … import`` resolve; packages and unresolved
    specifiers are dropped. The importing file never names itself.
    """
    import posixpath

    found: list[str] = []
    folder = posixpath.dirname(path)
    if path.endswith(_JS_EXTS):
        stripped = _strip_js_comments(text)
        sources = [m.group("src") for m in _JS_IMPORT_RE.finditer(stripped)]
        sources += [m.group("src") for m in _JS_REQUIRE_RE.finditer(stripped)]
        for src in sources:
            if not src.startswith("."):
                continue
            base = posixpath.normpath(posixpath.join(folder, src))
            candidates = [base, *(base + ext for ext in _JS_EXTS), *(f"{base}/index{ext}" for ext in _JS_EXTS)]
            hit = next((c for c in candidates if exists(c)), None)
            if hit and hit != path and hit not in found:
                found.append(hit)
    elif path.endswith(".py"):
        for m in _PY_IMPORT_RE.finditer(text):
            module = m.group("mod")
            dots = len(module) - len(module.lstrip("."))
            parts = [p for p in module.lstrip(".").split(".") if p]
            if dots:
                base = folder
                for _ in range(dots - 1):
                    base = posixpath.dirname(base)
                roots = [base]
            else:
                roots = ["", "src"]
            for root in roots:
                stem = posixpath.join(root, *parts) if parts else root
                hit = next(
                    (c for c in (stem + ".py", posixpath.join(stem, "__init__.py")) if parts and exists(c)), None
                )
                if hit and hit != path and hit not in found:
                    found.append(hit)
                    break
    return found


def _scheme(text: str) -> str:
    if re.search(r"(?i)cookies", text):
        return "cookie"
    if re.search(r"(?i)authorization|bearer|jwt|token|verify", text):
        return "bearer"
    return "other"


class HandlerResolver:
    """Per-repository resolver with file and import caches."""

    def __init__(self, repo_root: Path) -> None:
        self.root = Path(repo_root).resolve()
        self._texts: dict[str, str | None] = {}
        self._imports: dict[str, dict[str, tuple[str, str]]] = {}

    def _text(self, rel: str) -> str | None:
        if rel not in self._texts:
            path = self.root / rel
            text = None
            try:
                readable = path.is_file() and is_safe_to_read(path, self.root)
                if readable and path.stat().st_size <= _MAX_FILE_BYTES:
                    raw = path.read_text(encoding="utf-8", errors="replace")
                    text = _strip_js_comments(raw) if path.suffix.lower() in _JS_EXTS else raw
            except OSError:
                text = None
            self._texts[rel] = text
        return self._texts[rel]

    def _repo_file(self, candidate: Path) -> str | None:
        try:
            rel = candidate.resolve().relative_to(self.root).as_posix()
        except (OSError, ValueError):
            return None
        return rel if candidate.is_file() and not _TEST_PATH_RE.search(rel) else None

    # -- JavaScript / TypeScript --------------------------------------------
    def _module(self, from_rel: str, src: str) -> str | None:
        base = (self.root / from_rel).parent / src
        for candidate in (
            base,
            *(base.with_name(base.name + ext) for ext in _JS_EXTS),
            *(base / f"index{ext}" for ext in _JS_EXTS),
        ):
            found = self._repo_file(candidate)
            if found:
                return found
        return None

    def _js_imports(self, rel: str) -> dict[str, tuple[str, str]]:
        """Local name → (source, exported name, or '*' for a namespace or default binding)."""
        if rel not in self._imports:
            table: dict[str, tuple[str, str]] = {}
            text = self._text(rel) or ""
            for m in _JS_IMPORT_RE.finditer(text):
                for local in (m.group("default"), m.group("ns")):
                    if local:
                        table[local] = (m.group("src"), "*")
                for part in (m.group("named") or "").split(","):
                    names = part.replace("type ", "").split(" as ")
                    if names[0].strip():
                        table[names[-1].strip()] = (m.group("src"), names[0].strip())
            for m in _JS_REQUIRE_RE.finditer(text):
                if m.group("name"):
                    table[m.group("name")] = (m.group("src"), "*")
                for part in (m.group("named") or "").split(","):
                    names = part.split(":")
                    if names[0].strip():
                        table[names[-1].strip()] = (m.group("src"), names[0].strip())
            self._imports[rel] = table
        return self._imports[rel]

    def _js_definition(self, rel: str, name: str) -> tuple[int, str, str | None] | None:
        """(line, code, initializer callee) of a top-level JS definition of `name`."""
        text = self._text(rel)
        if text is None:
            return None
        anonymous = ""
        if name == "default":
            m = re.search(r"^[ \t]*export\s+default\s+(?:async\s+)?(?:function\s*\*?\s*)?([\w$]+)", text, re.MULTILINE)
            if m and m.group(1) != "function" and not _is_arrow(text, m.start(1)):
                return self._js_definition(rel, m.group(1))
            # `export default () => handler` and `export default function (req, res) {…}`
            # define the export in place; the bodies below read them like a const initializer.
            anonymous = r"|^[ \t]*export\s+default(?P<anon>)(?=\s+(?:async\s+)?(?:function\s*\*?\s*\(|\(|[\w$]+\s*=>))"
        n = re.escape(name)
        m = re.search(
            rf"^[ \t]*(?:export\s+)?(?:async\s+)?function\s*\*?\s*{n}\s*(?P<params>\()"
            rf"|^[ \t]*(?:export\s+)?(?:const|let|var)\s+{n}\s*(?::[^=\n]+)?=(?P<init>)"
            rf"|^[ \t]*(?:module\.)?exports\.{n}\s*=(?P<exp>)" + anonymous,
            text,
            re.MULTILINE,
        )
        if not m:
            return None
        line = _line_of(text, m.start())
        if m.group("params") is not None:
            brace = text.find("{", _matching(text, m.start("params")))
            return (line, text[m.start() : _matching(text, brace)], None) if brace >= 0 else None
        start = m.end()
        while start < len(text) and text[start] in " \t\n":
            start += 1
        rest = text[start:]
        if _is_arrow(text, start):
            # A factory returns the handler (`() => async (req, res) => {…}`): follow
            # each returned arrow to the block body instead of stopping at the first.
            for _ in range(_MAX_CURRIED_ARROWS):
                params = start + len(re.match(r"(?:async\s+)?", text[start:]).group(0))
                arrow = text.find("=>", _matching(text, params) if text.startswith("(", params) else params)
                body_start = arrow + 2
                while body_start < len(text) and text[body_start] in " \t\n":
                    body_start += 1
                if text.startswith("{", body_start):
                    return line, text[m.start() : _matching(text, body_start)], None
                if not _is_arrow(text, body_start):
                    break
                start = body_start
            if re.match(r"(?:async\s+)?function\b", text[body_start:]):
                brace = text.find("{", _matching(text, text.find("(", body_start)))
                return line, text[m.start() : _matching(text, brace)], None
            end = text.find("\n", body_start)
            # A factory that returns a named function (`() => loadMembers`) leads to it.
            # Only a name defined or imported here is followed; _resolve_js bounds the depth.
            returned = re.match(r"([\w$]+)\s*;?\s*$", text[body_start : len(text) if end < 0 else end])
            follow = returned and (
                returned.group(1) in self._js_imports(rel)
                or re.search(
                    rf"^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s*\*?|const|let|var)\s+{re.escape(returned.group(1))}\b",
                    text,
                    re.MULTILINE,
                )
            )
            return line, text[m.start() : len(text) if end < 0 else end], returned.group(1) if follow else None
        if re.match(r"(?:async\s+)?function\b", rest):
            params = text.find("(", start)
            brace = text.find("{", _matching(text, params))
            return line, text[m.start() : _matching(text, brace)], None
        callee = _JS_CALLEE_RE.match(rest)
        end = _matching(text, start + callee.end() - 1) if callee else text.find("\n", start)
        return (
            line,
            text[m.start() : len(text) if end < 0 else end],
            re.sub(r"\s+", "", callee.group(1)) if callee else None,
        )

    def _resolve_js(self, rel: str, dotted: str, depth: int = 0) -> list[Body] | str | _PackageGuard | None:
        """Code behind a callee path; 'external' for a non-credential package; a guard for an
        authentication package; None when unresolved."""
        if depth > 4:
            return None
        parts = [p.strip() for p in dotted.split(".")]
        imported = self._js_imports(rel).get(parts[0])
        if imported:
            src, exported = imported
            member = exported if exported != "*" else (parts[1] if len(parts) > 1 else "default")
            if not src.startswith("."):
                package = "/".join(src.split("/")[:2]) if src.startswith("@") else src.split("/")[0]
                if package in _NON_CREDENTIAL_PACKAGES:
                    return "external"
                guard = _AUTHENTICATING_PACKAGES.get(package)
                return guard if guard and (guard.members is None or member in guard.members) else None
            module = self._module(rel, src)
            if module is None:
                return None
            return self._resolve_js(module, member, depth + 1)
        definition = self._js_definition(rel, parts[0])
        if definition is None:
            return None
        line, code, initializer = definition
        if not initializer:
            initializer = _returned_package_call(code, self._js_imports(rel))
        if not initializer:
            return [(rel, line, code)]
        resolved = self._resolve_js(rel, initializer, depth + 1)
        if isinstance(resolved, _PackageGuard) and resolved.evidence is None:
            # A definition calling the package (`() => jwtGuard({...})`) is the guard's evidence.
            return replace(resolved, evidence=(rel, line)) if _rejecting_call(code, initializer, resolved) else None
        if resolved is None or isinstance(resolved, _PackageGuard):
            return resolved
        return [(rel, line, code), *([] if resolved == "external" else resolved)]

    def _js_element(self, rel: str, line: int, expr: str, depth: int = 0) -> tuple[bool, list[Body] | _PackageGuard]:
        """(resolved, code or authentication guard) of one middleware or handler expression.

        Only the outer callee counts. Its arguments are followed only when it
        resolves to repository code (a wrapper such as `asyncHandler(handler())`);
        a package middleware's arguments are configuration. A guard passed into
        a wrapper stays unresolved, since the wrapper decides whether it runs.
        """
        expr = expr.strip()
        bare = _JS_STRING_RE.sub("''", expr)
        if _JS_FUNCTION_START_RE.match(expr) and "=>" in bare or expr.startswith(("function", "async function")):
            return True, [(rel, line, expr)]
        head = bare.split("(", 1)[0]
        if depth > 2 or re.search(r"\?|\|\||&&|\[", head):
            return False, []
        outer = _JS_CALLEE_RE.match(expr)
        callee = re.sub(r"\s+", "", outer.group(1)) if outer else (expr if _JS_PATH_RE.match(expr) else None)
        if callee is None:
            return False, []
        resolved = self._resolve_js(rel, callee)
        if resolved is None:
            return False, []
        if isinstance(resolved, _PackageGuard):
            if resolved.evidence is None:
                # The registration calls the package itself.
                if not (outer and _rejecting_call(expr, callee, resolved)):
                    return False, []
                resolved = replace(resolved, evidence=(rel, line))
            return True, resolved
        if resolved == "external":
            return True, []
        code = list(resolved)
        if outer:
            open_paren = outer.end() - 1
            for arg in _split_args(expr[open_paren + 1 : _matching(expr, open_paren) - 1]):
                literal = arg.startswith(("function", "async function")) or (
                    _JS_FUNCTION_START_RE.match(arg) and "=>" in _JS_STRING_RE.sub("''", arg)
                )
                if arg in {"true", "false", "null", "undefined"}:
                    continue
                if literal or _JS_CALLEE_RE.match(arg) or _JS_PATH_RE.match(arg):
                    ok, inner = self._js_element(rel, line, arg, depth + 1)
                    if not ok or isinstance(inner, _PackageGuard):
                        return False, []
                    code.extend(inner)
        return True, code

    def _js_helpers(self, rel: str, body: str) -> list[Body]:
        """Same-file functions a body calls, one level deep."""
        out = []
        for name in sorted({m.group(1) for m in _JS_CALLEE_RE.finditer(body) if "." not in m.group(1)}):
            definition = self._js_definition(rel, name)
            if definition and definition[1] not in body:
                out.append((rel, definition[0], definition[1]))
        return out

    def _js_registration(self, route: dict) -> tuple[str, int, str, re.Match, list[str]] | None:
        """(file, line, text, registration call, its arguments) of a call-registered route."""
        rel, line = route.get("handler_file") or "", route.get("handler_line")
        text = self._text(rel)
        if text is None or not isinstance(line, int):
            return None
        call = re.compile(
            r"\b(?P<obj>[\w$]+)\s*\.\s*(?:get|post|put|patch|delete|head|options|all|any|route)\s*\(", re.IGNORECASE
        ).search(text, _line_offset(text, line))
        if not call or _line_of(text, call.start()) != line:
            return None
        args = _split_args(text[call.end() : _matching(text, call.end() - 1) - 1])
        return (rel, line, text, call, args) if len(args) >= 2 else None

    def _js_handler_module(self, rel: str, expr: str) -> str | None:
        """Module defining the handler expression, looking through repository wrappers such as `wrap(handler())`."""
        for _ in range(3):
            outer = _JS_CALLEE_RE.match(expr)
            callee = re.sub(r"\s+", "", outer.group(1)) if outer else (expr if _JS_PATH_RE.match(expr) else None)
            if callee is None:
                return None
            resolved = self._resolve_js(rel, callee)
            if not isinstance(resolved, list) or not resolved:
                return None
            open_paren = outer.end() - 1 if outer else -1
            inner = (
                [
                    a
                    for a in _split_args(expr[open_paren + 1 : _matching(expr, open_paren) - 1])
                    if _JS_CALLEE_RE.match(a) or _JS_PATH_RE.match(a)
                ]
                if outer
                else []
            )
            if not inner or not isinstance(self._resolve_js(rel, re.sub(r"\s+", "", inner[-1].split("(", 1)[0])), list):
                return resolved[0][0]
            expr = inner[-1]
        return None

    def _js_chain(
        self, route: dict
    ) -> tuple[list[tuple[bool, list[Body]]], list[tuple[bool, list[Body]]], bool] | None:
        """(mounted middlewares, registration arguments, application object created here)."""
        found = self._js_registration(route)
        if found is None:
            return None
        rel, line, text, call, args = found
        obj, path = call.group("obj"), (route.get("path") or "").rstrip("/") or "/"
        chain = []
        for use in re.finditer(rf"\b{re.escape(obj)}\s*\.\s*use\s*\(", text[: call.start()]):
            mounted = _split_args(text[use.end() : _matching(text, use.end() - 1) - 1])
            prefixes = (
                re.findall(r"['\"`](/[^'\"`]*)['\"`]", mounted[0]) if mounted and mounted[0][:1] in "'\"`[" else []
            )
            if mounted and mounted[0][:1] in "'\"`[":
                covered = any(path == p.rstrip("/*") or path.startswith(p.rstrip("/*") + "/") for p in prefixes)
                mounted = mounted[1:] if covered else []
            chain.extend(self._js_element(rel, _line_of(text, use.start()), m) for m in mounted)
        handler = [self._js_element(rel, line, arg) for arg in args[1:]]
        app = re.search(rf"\b(?:const|let|var)\s+{re.escape(obj)}\b[^=\n]*(?:{_JS_APP_FACTORY_RE.pattern})", text)
        return chain, handler, bool(app)

    # -- Python and NestJS decorated handlers -------------------------------
    def _py_modules(self, rel: str, local: str) -> list[str]:
        for m in _PY_IMPORT_RE.finditer(self._text(rel) or ""):
            names = [n.strip().strip("() ").split(" as ")[-1].strip() for n in m.group("names").split(",")]
            if local not in names:
                continue
            mod = m.group("mod")
            dots = len(mod) - len(mod.lstrip("."))
            parts = [p for p in mod.lstrip(".").split(".") if p]
            base = (self.root / rel).parent
            for _ in range(max(dots - 1, 0)):
                base = base.parent
            roots = [base] if dots else [self.root, self.root / "src", *(self.root / rel).parents]
            for root in roots:
                for candidate in (root.joinpath(*parts).with_suffix(".py"), root.joinpath(*parts, "__init__.py")):
                    found = self._repo_file(candidate) if parts else None
                    if found:
                        return [found]
        return []

    def _resolve_py(self, rel: str, dotted: str) -> list[Body] | None:
        name = dotted.split(".")[-1]
        for module in [rel, *self._py_modules(rel, dotted.split(".")[0])]:
            text = self._text(module) or ""
            m = re.search(rf"^[ \t]*(?:async\s+)?def\s+{re.escape(name)}\s*\(", text, re.MULTILINE)
            if m:
                lines = text.split("\n")
                start = _line_of(text, m.start()) - 1
                return [(module, start + 1, "\n".join(lines[start : _indented_block(lines, start)]))]
        return None

    def _decorated_chain(
        self, route: dict, python: bool
    ) -> tuple[list[tuple[bool, list[Body]]], list[tuple[bool, list[Body]]], bool] | None:
        """([], handler function and its dependencies, application object created here)."""
        rel, line = route.get("handler_file") or "", route.get("handler_line")
        text = self._text(rel)
        if text is None or not isinstance(line, int):
            return None
        lines = text.split("\n")
        extra_decorator = False
        for index in range(line, min(len(lines), line + 8)):
            row = lines[index]
            if row.strip().startswith("@"):
                if not (
                    _PY_ROUTE_DECORATOR_RE.match(row)
                    if python
                    else re.match(r"\s*@(?:Get|Post|Put|Patch|Delete|Head|Options|All|HttpCode|Header|Redirect)\b", row)
                ):
                    extra_decorator = True
                continue
            if python and re.match(r"\s*(?:async\s+)?def\s", row):
                end = _indented_block(lines, index)
                body = "\n".join(lines[index:end])
                chain = [(not extra_decorator, [(rel, index + 1, body)])]
                decorator_block = "\n".join(lines[line - 1 : index])
                for target in _PY_DEPENDS_RE.findall(decorator_block + "\n" + body):
                    resolved = self._resolve_py(rel, target)
                    chain.append((resolved is not None, resolved or []))
                app = _PY_APP_FACTORY_RE.search(text) and not _PY_GLOBAL_HOOK_RE.search(text)
                return [], chain, bool(app)
            if not python and re.match(r"\s*(?:public\s+|private\s+|protected\s+|async\s+|static\s+)*[\w$]+\s*\(", row):
                start = _line_offset(text, index + 1)
                brace = text.find("{", _matching(text, text.find("(", start)))
                if brace < 0:
                    return None
                return [], [(not extra_decorator, [(rel, index + 1, text[start : _matching(text, brace)])])], False
        return None

    # -- classification ------------------------------------------------------
    def _classify(self, bodies: list[Body], python: bool) -> HandlerSignal:
        """Authentication one chain link's code proves, judged line by line.

        JS bodies are expanded with the repository helpers they call. The first
        match wins in this order: ``verified`` (with its scheme) when a verify
        call sits in a body that reads a credential and a rejection follows
        within ``_REJECT_WINDOW`` lines, or after a later test of the verify
        result; ``decode_only`` when a token is decoded without verification;
        ``unresolved`` when a credential is read but neither is shown; else ``none``.
        A JS pass-through loader (module docstring) is ``none`` instead of
        ``decode_only`` or ``unresolved``.
        """
        credential, verify, decode, reject = (
            (_PY_CREDENTIAL_RE, _PY_VERIFY_RE, _PY_DECODE_RE, _PY_REJECT_RE)
            if python
            else (_JS_CREDENTIAL_RE, _JS_VERIFY_RE, _JS_DECODE_RE, _JS_REJECT_RE)
        )
        expanded = list(bodies)
        if not python:
            for rel, _line, body in bodies:
                expanded.extend(h for h in self._js_helpers(rel, body) if h not in expanded)
        reads = decoded = None
        for rel, line, body in expanded:
            rows = body.split("\n")
            for index, row in enumerate(rows):
                if credential.search(row):
                    reads = reads or {"file": rel, "line": line + index}
                if verify.search(row) and credential.search(body):
                    window = "\n".join(rows[index : index + _REJECT_WINDOW])
                    assigned = re.search(r"\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=[^=]", row)
                    later = "\n".join(rows[index + 1 :])
                    tested = assigned and re.search(
                        rf"\bif\s*\(?\s*(?:!|not\s+)?\s*{re.escape(assigned.group(1))}\b", later
                    )
                    if reject.search(window) or (tested and reject.search(later)):
                        return HandlerSignal("verified", _scheme(row), [{"file": rel, "line": line + index}])
                if decode.search(row) and not verify.search(row):
                    decoded = decoded or {"file": rel, "line": line + index}
        if (reads or decoded) and not python and self._passes_through(expanded):
            return HandlerSignal("none", "none")
        if decoded:
            return HandlerSignal("decode_only", "none", [decoded])
        if reads:
            return HandlerSignal("unresolved", evidence=[reads])
        return HandlerSignal("none", "none")

    @staticmethod
    def _passes_through(bodies: list[Body]) -> bool:
        """Whether a chain link always hands the request on and cannot reject it."""
        if not any(_JS_BARE_NEXT_RE.search(body) for _rel, _line, body in bodies):
            return False
        for _rel, _line, body in bodies:
            if _JS_REQUEST_END_RE.search(body):
                return False
            # A synchronous verify can throw and so reject; only a callback form cannot.
            for match in _JS_VERIFY_RE.finditer(body):
                opening = match.end() - 1
                if body[opening] != "(" or not _JS_CALLBACK_RE.search(body[opening : _matching(body, opening)]):
                    return False
        return True

    def _chain(self, route: dict):
        framework = route.get("framework")
        if framework in _CALL_FRAMEWORKS:
            return self._js_chain(route)
        if framework in _PY_FRAMEWORKS or framework == "nestjs":
            return self._decorated_chain(route, framework in _PY_FRAMEWORKS)
        return None

    def route_signal(self, route: dict) -> HandlerSignal | None:
        """Authentication the resolved chain proves, or None for a stack this module does not cover."""
        framework = route.get("framework")
        python = framework in _PY_FRAMEWORKS
        if framework not in _CALL_FRAMEWORKS and not python and framework != "nestjs":
            return None
        found = self._chain(route)
        if found is None or not found[1]:
            return HandlerSignal("unresolved")
        mounted, handler, complete = found
        chain = [*mounted, *handler]
        results = [
            HandlerSignal("unresolved")
            if not ok
            else HandlerSignal("verified", code.scheme, [{"file": code.evidence[0], "line": code.evidence[1]}])
            if isinstance(code, _PackageGuard)
            else self._classify(code, python)
            for ok, code in chain
        ]
        bodies = [body for _ok, code in [*handler, *mounted] if isinstance(code, list) for body in code]
        verified = next((r for r in results if r.signal == "verified"), None)
        if verified:
            return HandlerSignal("verified", verified.scheme, verified.evidence, bodies)
        if not complete or any(r.signal == "unresolved" for r in results):
            return HandlerSignal("unresolved", bodies=bodies)
        decoded = next((r for r in results if r.signal == "decode_only"), None)
        if decoded:
            return HandlerSignal("decode_only", "none", decoded.evidence, bodies)
        evidence = [{"file": rel, "line": line} for rel, line, _body in bodies][:_MAX_EVIDENCE]
        return HandlerSignal("none", "none", evidence, bodies)

    def handler_code(self, route: dict) -> str | None:
        """The route's own handler code (registration arguments or decorated function), or None."""
        found = self._chain(route)
        if not found or not found[1] or not all(ok for ok, _code in found[1]):
            return None
        return "\n".join(body for _ok, code in found[1] if isinstance(code, list) for _rel, _line, body in code) or None

    def handler_module(self, route: dict) -> str | None:
        """Repository file that defines the route's own handler, or None when unresolved.

        That is the last registration argument, looked at through repository
        wrappers, or the decorated function. Guards, wrappers, mounted
        middlewares and injected dependencies do not count: a flaw in code many
        routes share is no flaw of each route using it.
        """
        if route.get("framework") in _CALL_FRAMEWORKS:
            found = self._js_registration(route)
            return self._js_handler_module(found[0], found[4][-1].strip()) if found else None
        found = self._chain(route)
        if not found or not found[1] or not found[1][0][0] or not found[1][0][1]:
            return None
        return found[1][0][1][0][0]

    def middleware_definitions(self, route: dict) -> list[tuple[str, int, int]]:
        """(file, first line, last line) of each repository middleware a call-registered route runs.

        Every registration argument before the handler, then the middlewares
        mounted on a path prefix of the route, resolved to their repository
        definitions; an authentication package guard yields the line that
        configures it. Middlewares mounted without a path run on every route
        and say nothing about this one. A guard such as an identity-overwriting
        middleware decides an access claim about the handler, yet lies in
        neither the handler's nor the registration's file.
        """
        if route.get("framework") not in _CALL_FRAMEWORKS:
            return []
        found = self._js_registration(route)
        if found is None:
            return []
        rel, line, text, call, args = found
        obj, path = call.group("obj"), (route.get("path") or "").rstrip("/") or "/"
        elements = [self._js_element(rel, line, arg) for arg in args[1:-1]]
        for use in re.finditer(rf"\b{re.escape(obj)}\s*\.\s*use\s*\(", text[: call.start()]):
            mounted = _split_args(text[use.end() : _matching(text, use.end() - 1) - 1])
            if not mounted or mounted[0][:1] not in "'\"`[":
                continue
            prefixes = re.findall(r"['\"`](/[^'\"`]*)['\"`]", mounted[0])
            if any(path == p.rstrip("/*") or path.startswith(p.rstrip("/*") + "/") for p in prefixes):
                elements.extend(self._js_element(rel, _line_of(text, use.start()), m) for m in mounted[1:])
        spans = []
        for ok, code in elements:
            if not ok:
                continue
            if isinstance(code, _PackageGuard):
                if code.evidence is not None:
                    spans.append((code.evidence[0], code.evidence[1], code.evidence[1]))
            elif code:
                rel, line, body = code[0]
                spans.append((rel, line, line + body.count("\n")))
        return list(dict.fromkeys(spans))
