# Finding title contract

Canonical form for every threat's `title` field. Read this before authoring titles.

## Format

`<Weakness class> (<relative_file_path[:line]>)` — MAX 80 chars.

- **Weakness class:** short noun phrase identifying WHAT the vulnerability is. Title-case the leading word. Examples: `SQL Injection`, `Hardcoded Cryptographic Key`, `Server-Side Template Injection`, `Insecure Direct Object Reference`, `Cross-Site Scripting`.
- **Location:** source-tree path (with optional `:line`) in PARENS, never via em-dash. Path comes from `evidence[0].file`.
- **No file applies** (cross-cutting / architectural): omit parens entirely.

## Hard rules

1. No backtick code identifiers inside the title text — no inline `` `lib/...` ``; path goes inside parens unquoted.
2. No function-call expressions, payloads, library versions, exploit phrasing, or product-internal training-tier identifiers (`LEVEL_2`, `LEVEL_3 handler`).
3. When the affected parameter is meaningful, use the sibling field `affected_parameter` (`email`, `q`, `id`, `X-Forwarded-For`) — do NOT cram it into the title.

## Forbidden substrings (schema-enforced)

Eight patterns hard-fail at JSON-Schema validation via the `not.anyOf` block in `schemas/threat-model.output.schema.yaml`:

- `@\d` (any `lib@version` form — covers `@0.` … `@4.`)
- `alg:none`
- `noent:true`
- `bypassSecurityTrustHtml`
- `crypto.createHash`
- `models.sequelize.query`
- `package-lock=false`
- `(CVE-`

Three further patterns are author-discipline only (no automated check rejects them today): `eval(`, `app.use(`, `fetch(url)`.

## Examples

**Good:**
- `SQL Injection (routes/login.ts:34)`
- `Hardcoded Cryptographic Key (lib/insecurity.ts:23)`
- `Cross-Site Request Forgery (server.ts)`
- `Outdated Dependency (package.json)`
- `Insecure Token Storage (frontend/src/app/Services)`
- `JWT Algorithm Confusion (lib/insecurity.ts:54)`
- `XXE External Entity Parsing (routes/dataExport.ts:42)`
- `Path Traversal via Archive Extraction (routes/fileUpload.ts:88)`

**Bad:**
- `SQL injection — routes/login.ts:34` (em-dash separator before file — use parens)
- `SQL Injection` (no file, no location — too generic)
- `` Reflected XSS via `bypassSecurityTrustHtml(queryParam)` `` (function-call expression in title)
- `JWT alg:none bypass — express-jwt 0.1.3 (CVE-2020-15084)` (library@version + payload phrase + em-dash + CVE)
- `XXE via XML file upload — libxmljs2 noent:true` (library + payload phrase)
- `MD5 password hash — offline cracking via SQLi dump` (exploit-narrative phrase, not weakness class)
- `Path traversal via Zip Slip — unzipper@0.9.15` (library@version)
