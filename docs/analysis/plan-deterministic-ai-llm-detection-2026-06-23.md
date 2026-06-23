# Make AI/LLM detection deterministic (recon Category 13)

**Date:** 2026-06-23
**Status:** IMPLEMENTED 2026-06-23. Two refinements were made during live verification
(see §7): the weak rule requires **co-location within one file**, and Cat 13 skips
AI-assistant tooling dirs (`.claude/`, `.cursor/`, …). Sections below describe the
shipped design.
**Goal:** Move recon "Category 13" (AI/LLM integration) from the non-deterministic
LLM-grep loop into `scripts/recon_patterns.py`, so `KNOWN_LLM_PATTERNS` (and therefore
the `### AI / LLM Exposure` Management-Summary section, gated by `has_llm_surface`) is
detected reproducibly instead of by LLM judgement.

---

## 1. Problem

Today Category 13 is in the LLM-driven grep loop (`agents/appsec-recon-scanner.md:207`),
NOT in the deterministic helper (`recon_patterns.py` does 11,14,15,17,18,21,22,23,24,27,28).
Two failure modes:

1. **LLM variance** — detection depends on the recon LLM actually running the grep and
   judging; subject to turn-budget pressure, recon stalls, and the inline-shortcut modes.
2. **Too-restrictive trigger** — the current rule ANDs **all five** signal groups (LLM SDK
   *and* prompt construction *and* vector DB *and* agent/tool-use *and* model config). Only a
   full agentic RAG stack trips it; a plain OpenAI chatbot (SDK + model config, no vector
   DB, no agents) is missed.

There is **no user override** (no flag, no org-profile field), so a missed detection cannot
be forced. Fixing detection at the root is preferred over adding a `--ai-surface` band-aid.

### Key insight that lowers the cost of false positives

The recon signal is **necessary but not sufficient** for the section to appear. The chain is:
recon `KNOWN_LLM_PATTERNS != none` → STRIDE runs the OWASP-LLM-Top-10 sub-block →
`appsec-threat-renderer` authors `ms-ai-exposure.json` **only if it recorded real LLM
threats** (schema `minItems:1`) → compose renders. So a recon over-detection does **not**
force the section — the renderer's evidence-grounding is a second gate. A false positive
costs only the OWASP-LLM STRIDE sub-block (some extra turns), not a bogus report section.
This lets us bias toward **sensitivity** (catch light integrations) without much harm.

---

## 2. Design — `scan_ai_integration(repo_root)` in `recon_patterns.py`

Mirror the existing deterministic categories: module-level compiled regexes + a scan
function + registration in `run_all()` + a CLI subcommand. Per-line matching via the
existing `_walk_repo` / `_grep_file` helpers; findings carry
`{category:13, file, line, match, subcategory, strength}`.

### 2.1 Signal groups (two strengths)

Each pattern is tagged with a `subcategory` (maps 1:1 to the §7.13 output table) and a
`strength` (`strong` | `weak`). **STRONG** = tokens that essentially never appear outside
genuine LLM code. **WEAK** = generic tokens that also occur in non-LLM code (ML, sensors,
games), so they only count in combination.

**STRONG** (any single hit ⇒ AI surface):

| subcategory | patterns (case-insensitive) |
|---|---|
| `llm-sdk` | `\bopenai\b`, `\banthropic\b`, `@anthropic-ai`, `\blangchain\b`, `@langchain/`, `llama[_-]?index`, `llamaindex`, `\bautogen\b`, `\bcrewai\b`, `\blitellm\b`, `\bcohere\b`, `\bmistralai\b`, `google\.generativeai`, `@google/generative-ai`, `\bollama\b`, `@azure/openai`, `bedrock-runtime`, `ChatCompletion`, `chat\.completions`, `messages\.create`, `GenerativeModel`, `InvokeModel` |
| `vector-db` | `chromadb`, `pinecone`, `weaviate`, `qdrant`, `milvus`, `pgvector`, `\bfaiss\b` |
| `agent-framework` | `AgentExecutor`, `ReActAgent`, `create_react_agent`, `create_tool_calling_agent` |
| `prompt-framework` | `ChatPromptTemplate`, `SystemMessage`, `HumanMessage`, `\bPromptTemplate\b`, `from_messages` |
| `tokenizer` | `\btiktoken\b` |
| `model-name` | `gpt-4`, `gpt-4o`, `gpt-3\.5`, `claude-3`, `claude-2`, `claude-sonnet`, `claude-opus`, `gemini-1\.`, `text-embedding-(ada|3)`, `\bo1-(preview|mini)\b` |

**WEAK** (count only in combination — see rule):

| subcategory | patterns (case-insensitive) |
|---|---|
| `prompt-construction` | `system[ _-]?prompt`, `system[ _-]?message`, `prompt[ _-]?template`, `user[ _-]?prompt` |
| `model-config` | `\btemperature\b`, `max[_-]?tokens`, `\btop[_-]?p\b`, `model[_-]?name`, `model[_-]?id` |
| `vector-semantic` | `\bembedding`, `vector[ _-]?store`, `similarity[ _-]?search` |
| `tool-use` | `tool[ _-]?use`, `function[ _-]?call`, `tool[ _-]?choice` |

Notes on FP-hardening vs. the current regex: **dropped bare `claude`** (a person's name) —
only specific model-ids (`claude-3`, `claude-sonnet`, …) count. `temperature` / `embedding`
demoted to WEAK so a classic-ML or simulation repo never trips on them alone.

### 2.2 Decision rule (the threshold to approve)

After scanning, decide `has_ai_surface`:

```
has_ai_surface = (>=1 STRONG hit anywhere in the repo)
              OR ( some SINGLE file co-locates the "prompt-construction" weak group
                   AND >=1 other distinct weak group )
```

(Co-location was added in verification — §7. Real SDK-less integration code keeps its
prompt + model-config in the same module; scattered security *vocabulary* across separate
files, e.g. a CWE-taxonomy or threat-model artifact that merely names "prompt injection",
"embeddings", "tool use", does not.)

- The STRONG path catches the common cases the 5-AND missed: a lone `import openai`,
  a `langchain` import, a `chromadb` client, an `AgentExecutor`, or a literal `gpt-4o`.
- The WEAK path catches **SDK-less** integrations (raw `requests`/`fetch` to an LLM API):
  it requires the LLM-specific `prompt-construction` anchor **plus** one corroborating weak
  group, so `temperature` + `system prompt` fires, but `embedding` + `temperature`
  (sklearn) does **not** (no prompt anchor) — avoiding the main ML false positive.

If `has_ai_surface` is false → return `{category:13, name:…, findings:[], count:0}`
(→ `KNOWN_LLM_PATTERNS = none`, section absent). If true → return the contributing
findings (file:line:match, tagged by subcategory), capped at **20 per subcategory** to
avoid flooding output on a large LLM codebase (cap disclosed in the finding list via a
`truncated: true` marker on the category, mirroring `skipped_oversize`).

### 2.3 Output shape (unchanged contract)

```json
{
  "category": 13,
  "name": "AI / LLM Integration",
  "findings": [
    {"category":13,"subcategory":"llm-sdk","strength":"strong","file":"src/chat.ts","line":3,"match":"import OpenAI from \"openai\";"},
    {"category":13,"subcategory":"prompt-construction","strength":"weak","file":"src/chat.ts","line":18,"match":"const systemPrompt = ..."}
  ],
  "count": 2
}
```

Registered in `run_all()` as `"13": scan_ai_integration(repo_root)` and exposed as the
`ai-integration` CLI subcommand for standalone testing.

---

## 3. Wiring changes (bidirectional, per AGENTS.md §4 / Editing Guidance)

| File | Change |
|---|---|
| `scripts/recon_patterns.py` | add `_CAT13_*` compiled patterns, `scan_ai_integration()`, register `"13"` in `run_all()`, add CLI dispatch. |
| `tests/test_recon_patterns.py` | new `TestCat13AiIntegration` (matrix in §4). Same-commit rule (AGENTS.md §9). |
| `agents/appsec-recon-scanner.md` | (a) add `13` to the deterministic list at line 132; (b) **remove** the 5-AND Category-13 row from the LLM-grep table (line 207); (c) add a `categories["13"]` consume instruction in the line-148 block → routes to §7.13, tagged by `subcategory`. The recon LLM no longer greps for it — it only writes the §7.13 **impact narrative** from the deterministic findings ("reserve judgement for impact summarisation", same as cats 28/14). |
| `agents/shared/recon-output-template.md` | §7.13 structure stays; note detection is now deterministic (`.recon-patterns.json categories["13"]`), the LLM fills judgement columns only. `KNOWN_LLM_PATTERNS` table format unchanged. |
| **Unchanged** | `data/sections-contract.yaml` (`has_llm_surface` gate stays), `schemas/fragments/ai-exposure.schema.json`, `templates/fragments/ai-exposure.md.j2`, `scripts/compose_threat_model.py`. The gate's *meaning* is unchanged; only detection becomes reproducible. |
| `data/required-permissions.yaml` | **no change** — `recon_patterns.py` is already invoked; no new command/Write/Read target. |

**Drift-guard check before coding:** grep tests for any assertion that pins the
Category-13 5-AND regex string or the deterministic-category list `"11, 14, 15, 17, 18,
21, 22, 23, 24, 27, and 28"` (e.g. a recon-scanner drift test). If one exists, update it to
include `13` in the same commit.

---

## 4. Test matrix (`tests/test_recon_patterns.py`)

Mirror the existing fixture style (`repo = tmp_path`, write minimal source, call
`rp.scan_ai_integration(repo)`, assert `count`/`subcategory`).

**Positive (must detect):**
1. Plain OpenAI chatbot — `import OpenAI from "openai"` only. (STRONG `llm-sdk`; the #1 case the old 5-AND missed.)
2. LangChain RAG — `from langchain... import ChatPromptTemplate` + `chromadb`. (multiple STRONG)
3. Agent stack — `AgentExecutor(...)`. (STRONG `agent-framework`)
4. SDK-less REST — `requests.post(... json={"model":"...","temperature":0.7,"messages":[{"role":"system",...}]})` with a `system prompt` var. (WEAK path: prompt-construction + model-config)
5. Literal model id — a config with `"gpt-4o"`. (STRONG `model-name`)

**Negative (must NOT detect — false-positive guards):**
6. Classic ML — `from sklearn... ` with `embedding_dim` and simulated-annealing `temperature`. (vector-semantic + model-config, **no** prompt anchor → no fire)
7. A variable literally named `claude` (a person) and nothing else. (bare `claude` dropped)
8. A thermostat/game repo with `temperature` only. (one weak group)
9. Empty repo → `count == 0`.

---

## 5. Risks & limitations

- **Residual FPs** on the WEAK path (a text-generation toy with `PromptTemplate` +
  `temperature` but no real LLM). Bounded: the renderer's evidence gate drops the section
  anyway; cost is only the OWASP-LLM STRIDE sub-block. Tunable by tightening the weak rule.
- **Vendored/minified bundles** containing `openai` strings: handled by the existing
  `_HARD_EXCLUDE_DIRS`/`_HARD_EXCLUDE_PATTERNS` (node_modules, dist, minified) in `_walk_repo`.
- **Local/abstracted LLMs** (a thin internal wrapper named `llm_client` over a local model
  with none of the strong tokens) may still be missed — but that's strictly better than
  today, and could be covered by adding org-specific tokens later if needed.
- This is detection only; it does not change the *quality* of the §7.13 narrative or the
  STRIDE OWASP-LLM analysis — those stay LLM-authored, now reliably triggered.

---

## 6. Open decision for the user

The one judgement call is the **§2.2 decision rule** — specifically the WEAK path. Two dials:
- **As designed** (prompt-construction anchor + 1 other weak group): good precision, catches
  SDK-less integrations that name a system prompt.
- **Looser** (any 2 distinct weak groups, no anchor): catches a few more SDK-less cases but
  re-introduces the sklearn-style `embedding`+`temperature` FP.

Recommendation: ship the **anchored** rule (as designed); the STRONG path already covers the
overwhelming majority (any real SDK/framework/vector-DB/model-id), and the renderer second
gate absorbs the rest. **Shipped as recommended** (anchored + co-located; no `--ai-surface`
override).

---

## 7. Verification findings (live, 2026-06-23) — two refinements

Ran the new `ai-integration` CLI against real repos; two issues surfaced and were fixed:

1. **`.claude/` (and peer IDE-agent dirs) caused a STRONG false positive.** A
   `.claude/settings.local.json` permission entry `WebFetch(domain:api.anthropic.com)`
   matched the strong `llm-sdk` token `anthropic` — flagging *any* Claude-Code-using repo
   as an LLM app. Fix: a **Cat-13-local** skip set `_CAT13_SKIP_DIRS` (`.claude`, `.cursor`,
   `.continue`, `.codeium`, `.aider`, `.windsurf`). It is deliberately **not** a global
   `_HARD_EXCLUDE_DIRS` entry — Cat 28 (AI-assistant configs) must still catalog those dirs;
   a global exclude broke its tests. Cat 13 measures the *app's* LLM usage, not the dev's tooling.

2. **Scattered security vocabulary caused a WEAK false positive.** The tool's own committed
   threat-model/taxonomy output (CWE-taxonomy YAML, STRIDE JSON) names "prompt injection",
   "embeddings", "tool use" as security concepts. The original repo-wide weak rule tripped on
   that. Fix: the weak rule now requires **co-location in a single file** (§2.2). Real SDK-less
   integration code co-locates prompt + model-config; security docs scatter the vocabulary.

**Result on a clean target (juice-shop application source):** `has_ai_surface = False`
(the only weak match is one `// Function called …` comment — not co-located, no anchor).
The default output dir `docs/security/` is already excluded by `data/scan-excludes.yaml`,
so a normal repeated scan never re-ingests its own output; only renamed dev-experiment
output dirs in a polluted checkout (`docs/security-m1verify/`) still show matches, which is
a pre-existing all-category artifact, not Cat-13-specific.

Full suite: `tests/test_recon_patterns.py` 92 passed; broader recon/agent/dispatch sweep
290 passed; ruff clean.
