// scripts/mermaid_validate.mjs — authoritative Mermaid syntax validator.
//
// The Python regex checks in qa_checks.py (check_mermaid_syntax) catch a
// handful of known-bad patterns (unbalanced quotes, parens in aliases,
// literal semicolons) but they are NOT a substitute for the actual Mermaid
// grammar. Real-world diagram breakages in the field came from patterns our
// regex never knew about: missing `end` on `alt` blocks, unmatched
// `subgraph`/`end`, bare `[`/`{` in node labels, invalid arrow operators.
//
// This script embeds the real Mermaid parser and exits 0 if the diagram is
// syntactically valid, exits 1 with a JSON error report on stderr otherwise.
// It reads the raw diagram body from stdin.
//
// Why Node-level validation is gated behind a Node script and not done in
// Python: Mermaid's parser is written in TypeScript/Langium and ships as
// ESM. There is no maintained Python port. Running the official parser is
// the only ground truth that stays in step with Mermaid's grammar.
//
// Runtime requirements (optional — qa_checks.py degrades gracefully if
// absent):
//   * Node 20+ (already required by @mermaid-js/mermaid-cli)
//   * `mermaid` core package — bundled inside @mermaid-js/mermaid-cli's
//     node_modules; the script auto-discovers it.
//   * `jsdom` — provides the window/document globals that Mermaid's label
//     sanitization (DOMPurify) walks during parse(). Install once via:
//
//       npm install --prefix "$CLAUDE_PLUGIN_ROOT/scripts" jsdom
//
// Output:
//   stdout: a single JSON line with the validation result, e.g.
//     {"ok":true}
//     {"ok":false,"error":"Parse error on line 2: …"}
//   exit:   0 on ok, 1 on parse error, 2 on environment error (jsdom /
//           mermaid core missing). The Python caller distinguishes the
//           latter so it can skip the check rather than flag every diagram
//           as broken.

import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { join } from "node:path";

const require = createRequire(import.meta.url);

// --- Resolve optional deps -------------------------------------------------

function resolveFrom(root, id) {
  try {
    return require.resolve(id, { paths: [root] });
  } catch {
    return null;
  }
}

const scriptsDir = new URL(".", import.meta.url).pathname;

function findJsdom() {
  // Prefer a local install next to this script, then global.
  const local = resolveFrom(scriptsDir, "jsdom");
  if (local) return local;
  const global = resolveFrom("/usr/lib/node_modules", "jsdom");
  return global;
}

function findMermaidCore() {
  // Mermaid core ships inside @mermaid-js/mermaid-cli's node_modules. Probe
  // the common global locations first; fall back to a local install under
  // scripts/.
  const candidates = [
    "/usr/lib/node_modules/@mermaid-js/mermaid-cli/node_modules/mermaid/dist/mermaid.core.mjs",
    "/usr/local/lib/node_modules/@mermaid-js/mermaid-cli/node_modules/mermaid/dist/mermaid.core.mjs",
    join(scriptsDir, "node_modules/@mermaid-js/mermaid-cli/node_modules/mermaid/dist/mermaid.core.mjs"),
    join(scriptsDir, "node_modules/mermaid/dist/mermaid.core.mjs"),
  ];
  for (const path of candidates) if (existsSync(path)) return path;
  return null;
}

const jsdomPath = findJsdom();
const mermaidPath = findMermaidCore();

if (!jsdomPath || !mermaidPath) {
  const missing = [
    !jsdomPath ? "jsdom" : null,
    !mermaidPath ? "mermaid (via @mermaid-js/mermaid-cli)" : null,
  ].filter(Boolean).join(", ");
  console.log(JSON.stringify({
    ok: false,
    skipped: true,
    error: `authoritative mermaid validator unavailable — missing: ${missing}. Install via 'npm install --prefix $CLAUDE_PLUGIN_ROOT/scripts jsdom' and ensure @mermaid-js/mermaid-cli is present.`,
  }));
  process.exit(2);
}

// --- Install DOM globals before loading mermaid ----------------------------

const { JSDOM } = await import(jsdomPath);
const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
  pretendToBeVisual: true,
});
for (const key of [
  "window", "document", "HTMLElement", "HTMLAnchorElement",
  "Node", "Element", "DocumentFragment", "NodeFilter",
]) {
  try {
    Object.defineProperty(globalThis, key, {
      value: dom.window[key],
      configurable: true,
    });
  } catch {
    // Ignore properties that Node already defines non-writable (e.g. navigator).
  }
}

const mermaid = (await import(mermaidPath)).default;

// --- Read stdin, parse, report --------------------------------------------

let src = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) src += chunk;

try {
  await mermaid.parse(src, { suppressErrors: false });
  console.log(JSON.stringify({ ok: true }));
  process.exit(0);
} catch (e) {
  const msg = e && (e.message || String(e));
  console.log(JSON.stringify({ ok: false, error: msg }));
  process.exit(1);
}
