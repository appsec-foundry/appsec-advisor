# Gap Analysis: Architectural LLM / AI-Agent Coverage in the Threat Model

**Scope:** the *product's own* LLM / AI-agent usage (a feature of the repo under
assessment) — **not** coding-assistant configs (`.mcp.json`, `CLAUDE.md`, …),
which are already covered as a dev-supply-chain surface by recon **Cat 28**.

**Goal:** assess and present architectural AI/LLM risk better — an additional
architecture view + Management-Summary signalling — with **zero / minimal added
cost for repos that use no LLM**.

Date: 2026-06-06. All claims verified at `file:line` (Jun 2026 tree).

> **Implementation status (2026-06-06):** **D2 IMPLEMENTED + verified** — the
> `### AI / LLM Exposure` Management-Summary callout. Renderer
> `_render_ai_exposure` (`compose_threat_model.py`), schema
> `schemas/fragments/ai-exposure.schema.json`, template
> `templates/fragments/ai-exposure.md.j2`, contract `ai_exposure_ms`
> (`conditional: has_llm_surface`), threat-renderer authoring contract, all 5
> fragment-registry maps, QA manifest. Gated by fragment presence → **non-LLM
> repos: no fragment authored → no output, no schema load, no template (zero
> cost)**. Tests: `test_ai_exposure_absent_renders_nothing`,
> `test_ai_exposure_renders_after_anti_patterns`. Full suite green (3539 passed,
> e2e-full excluded). **D0 / D1 / D3 deferred** (see §6) — larger surface / need
> a live run. **D5 (separate LLM-analyzer subagent) analysed below — deferred.**

---

## 1. Current state (what already exists)

| Capability | Where | Status |
|---|---|---|
| LLM/AI detection | `appsec-recon-scanner.md:196` (Cat 13, 5-part AND grep) | **LLM-driven grep, conditional** — emits `KNOWN_LLM_PATTERNS` |
| OWASP LLM Top-10 STRIDE lens | `agents/shared/owasp-llm-top10.md` (LLM01–LLM10) | active, **only when `KNOWN_LLM_PATTERNS != none`** (`appsec-stride-analyzer.md:392`) |
| AI control family | `data/architectural-controls.yaml:606` (`domain: AI`) | only LLM03/04/05 mapped (training-data, output filtering) |
| LLM finding type | `data/finding-types.yaml:288` (FT-142) | training-data / supply-chain poisoning → TH-14 |
| §7 AI/LLM subsection (v1) | `pregenerate_fragments.py:2721` (`_SECARCH_SUBSECTIONS` "7.9 AI / LLM") | **drifted** — see §2 |
| CWE→§7.9 AI map | `pregenerate_fragments.py:2798` (`CWE-1039`, `CWE-1426`) | tied to drifted numbering |

**Key positive:** the "render nothing for non-LLM repos" pattern **already exists
for this exact domain.** `pregenerate_fragments.py:3756-3775` emits a
`### 7.x AI / LLM — _Not applicable …_` stub (or suppresses) when no controls and
no threats map to it. So zero-cost gating for AI/LLM is a *proven* mechanism here,
not a new invention.

---

## 2. The gaps

### G1 — §7 numbering drift dropped the dedicated AI/LLM subsection (latent bug)
Two §7 layouts disagree:
- **Active v2 contract** (`sections-contract.yaml:1236-1248`): 13 subsections,
  **no AI/LLM subsection**; `7.9 = Cryptography Secrets and Data Protection`.
- **Pregenerator** (`pregenerate_fragments.py:2712-2727`, `_SECARCH_SUBSECTIONS`):
  v1 14-subsection layout where **`7.9 = AI / LLM`**, `7.6 = Data Protection`,
  `7.12 = Dependency & Supply Chain`.

Consequence: the pregenerator still *thinks* in a numbering where 7.9 is AI/LLM
(`_SUBSECTION_DOMAIN_HINTS["7.9"]`, `CWE→7.9 = {1039,1426}`) while the rendered
report has no AI/LLM home — so in the **final document AI/LLM risk scatters**
across 7.5 (injection ⇒ prompt injection), 7.7 (output handling), 7.9 (crypto/
secrets ⇒ system-prompt leakage), 7.11 (model supply chain). There is no single
place a reader sees "this is an AI system and here is its AI-specific posture".

### G2 — No AI/LLM architecture view
`Figure 1` (`_render_top_threats_architecture`, `compose_threat_model.py:4945`)
is a deterministic tier diagram (Client/Application/Data). It has **no concept of
an LLM endpoint, model API, vector store, RAG ingestion path, or agent
tool-invocation edge**, because `component-canonical.yaml:19` has no such
component category (enum: backend-api | auth-identity | frontend |
data-persistence | file-handling | admin | messaging | ci-cd). The
AI-specific data flows that *are* the threat surface (untrusted input → prompt
assembly → external model API trust boundary → output sink; user → RAG ingest →
embeddings; agent → tool execution) are invisible architecturally.

### G3 — No Management-Summary signal
An executive reading the MS cannot tell the system embeds an LLM, nor see the
headline AI risks (prompt injection, excessive agency, model supply chain). The
proven optional-callout slot exists (`architectural_anti_patterns`,
`compose_threat_model.py:7715`) but nothing analogous for AI exposure.

### G4 — Gating signal is text-only and LLM-derived
Activation today rides on `KNOWN_LLM_PATTERNS` (free-text from an **LLM-driven**
Cat-13 grep) and control-domain string matching. There is **no deterministic
boolean** `has_llm_*` in `.recon-signals.json` (which already carries
`has_public_routes`, `has_auth_surface`, `has_open_self_registration`, …). A clean
cheap gate is the precondition for everything below.

---

## 3. Design — three deliverables on one cheap gate

Guiding constraint: **a repo with no LLM must pay essentially nothing** — one
deterministic boolean that is `false`, after which every feature short-circuits.

### D0 — The gate: deterministic `has_llm_surface` boolean *(prerequisite)*
Promote the *dependency-manifest* slice of Cat-13 into the deterministic
`recon_patterns.py` pass (which already parses `package.json` / `requirements.txt`
/ `pyproject.toml` for SCA). Match a small allowlist of AI SDKs/stores:
`openai, anthropic, @anthropic-ai/*, langchain, llama-index, autogen, crewai,
google-generativeai, cohere, mistralai, chromadb, pinecone, weaviate, qdrant,
pgvector, faiss, transformers, litellm`.

Emit one boolean into `.recon-signals.json`:
```json
"has_llm_surface": true   // any AI SDK / vector-store dep present, else false
```
- **Cost for non-LLM repo:** one set membership test over already-parsed deps → `false`. No new file walk, no LLM turn.
- **Single source of truth** consumed by D1/D2/D3. Mirrors existing deterministic signals (`default-library.yaml` signal contract).
- The richer LLM-driven Cat-13 grep (`KNOWN_LLM_PATTERNS`) stays as-is for the STRIDE lens — it already only fires when relevant; D0 just gives the deterministic on/off switch the diagram + MS + §7 need.

### D1 — Optional AI/LLM architecture sub-view (`§2.5` or `Figure 1b`)
Render **only when `has_llm_surface`**. A focused Mermaid view of the AI dataflow,
reusing Figure 1's conventions (tier subgraphs, trust-boundary edges, severity
badges):
```
[Untrusted input] ──▶ [Prompt assembly] ══▶〔Model API〕  (external trust boundary)
        │                                        │
        │                              [Output handling sink]  (LLM05)
 [RAG ingest]──▶[Vector store]──▶[Retrieval]──▶ Prompt   (LLM04/08)
 [Agent]──tool-call──▶[Tool / shell / SQL]                (LLM06 excessive agency)
```
Implementation:
- Add component categories to `component-canonical.yaml`:
  `llm-endpoint | vector-store | ai-agent | rag-pipeline` with detection_signals
  (the D0 allowlist). This also lets the **existing** deterministic Figure 1 place
  an LLM node natively.
- Add an external trust boundary for the model API (`trust_boundaries` schema
  already supports `from: external`).
- Deterministic builder (sibling of `_render_top_threats_architecture`) +
  LLM-fragment fallback (`.fragments/ai-architecture.md`), same as Figure 1.
- **Defensive-empty:** `has_llm_surface=false` → builder returns `""` → no figure,
  no heading. Non-LLM repos never see it.

### D2 — Management-Summary "AI/LLM Exposure" callout
**Clone the anti-patterns callout precedent end-to-end** (the proven optional,
zero-cost-when-absent pattern):

| Anti-patterns precedent | New AI-exposure callout |
|---|---|
| fragment `ms-anti-patterns.json` | `ms-ai-exposure.json` |
| `schemas/fragments/anti-patterns.schema.json` | `schemas/fragments/ai-exposure.schema.json` |
| `templates/fragments/anti-patterns.md.j2` | `templates/fragments/ai-exposure.md.j2` |
| `_render_architectural_anti_patterns` (`compose…:7348`) | `_render_ai_exposure` (defensive-empty: no file → `""`) |
| contract `architectural_anti_patterns` `conditional: has_anti_patterns` (`sections-contract.yaml:392`) | `ai_exposure_ms` `conditional: has_llm_surface` |
| special-case in `_render_management_summary` (`compose…:7715`) | same, added to the `sid` tuple (`compose…:7693`) |
| **NOT** in `pregenerate GENERATORS` | same — LLM-authored only, by the threat-renderer, only when `has_llm_surface` |

Content: 1–4 executive bullets naming the live AI risks with finding links, e.g.
"🔴 **Prompt injection** — chat input at `routes/chat.ts:45` reaches the system
prompt unsanitised (LLM01) ↳ [F-012]". Renders nothing when the fragment is
absent → **non-LLM repos pay nothing.**

### D3 — Restore a coherent §7 AI/LLM control subsection (fixes G1)
Reconcile the drift and give AI controls a home, reusing the **existing
auto-suppression** machinery (`pregenerate_fragments.py:3756-3775`):
- Add one optional v2 subsection to `sections-contract.yaml:1236` — e.g.
  `7.14 AI / LLM Component Controls` (append; avoids renumbering 7.1–7.13 and the
  test assertions / overlays keyed to them).
- Gate it on `has_llm_surface`: when `false`, the existing stub logic emits
  `_Not applicable — no AI / LLM usage detected_` **or** suppresses it entirely —
  identical to how 7.8/7.9 already behave today. **Zero net cost for non-LLM repos.**
- Realign `_SECARCH_SUBSECTIONS` / `_SUBSECTION_DOMAIN_HINTS` / the CWE→§7 map to
  the v2 numbering so AI/LLM points at the new 7.14, not the stale 7.9. *(This is
  also a standalone correctness fix for G1.)*

---

## 4. Cost guarantee for non-LLM repos

A repo with no AI dependency pays, in total:
1. **One deterministic set-membership test** in `recon_patterns.py` over deps it
   already parses → `has_llm_surface=false`.
2. D1 builder short-circuits → no figure. D2 fragment never authored → MS callout
   absent. D3 subsection auto-"Not applicable"/suppressed.
3. **No extra agent turns** — the OWASP-LLM STRIDE lens is *already* conditional
   on `KNOWN_LLM_PATTERNS` (`stride-analyzer.md:392`); unchanged.

Net delta for a non-LLM repo: **one boolean = false.** Everything else is dead code on that path.

---

## 5. Risks & do-nots

- **Do NOT resurrect the dead `ms-architecture-assessment` path**
  (`_render_architecture_assessment`, `compose…:6228`; unwired since 2026-05,
  `sections-contract.yaml:492`). It is *not* the slot for this; use the
  anti-patterns precedent instead.
- **Do NOT conflate with Cat 28** (coding-assistant configs / MCP). That is the
  dev-workstation supply-chain surface and is explicitly out of scope here.
- **G1 drift touches test assertions** — `_SECARCH_SUBSECTIONS` is referenced by
  e2e expectations; realign tests in the same change (test-vs-code direction per
  cluster, per the green-suite baseline).
- Appending §7.14 (not inserting) avoids breaking the overlay/QA checks keyed to
  7.1–7.13 titles (`sections-contract.yaml:1257+`).

---

## 5b. D5 — Should the LLM analysis be a separate subagent?

**Today:** the OWASP LLM Top-10 analysis is a *conditional sub-block inside the
STRIDE analyzer* (`appsec-stride-analyzer.md:392`), applied per-component as an
extra lens when `KNOWN_LLM_PATTERNS != none`, and skipped at `low` complexity
(`:142`). Findings flow into the normal T-NNN/F-NNN STRIDE output.

**Question:** extract it into a dedicated `appsec-llm-analyzer` subagent?

### Why it could be worth it
- **Cross-component fit.** The AI risk surface is inherently *cross-component*
  (input → prompt assembly → external model API → output sink; RAG ingest →
  vector store → retrieval; agent → tool graph). STRIDE is *per-component*, so an
  LLM lens bolted onto each component's pass is an awkward home for LLM06
  (excessive agency) and LLM04 (RAG poisoning), which span components. One
  analyzer that sees the whole AI subsystem at once reasons about these properly.
- **Clean data lineage.** A dedicated agent can emit a structured
  `ai-threats.json` sidecar that feeds *all three* consumers — the threat merge,
  the new `ms-ai-exposure.json` (D2), and the AI architecture diagram (D1) —
  instead of D2/D1 having to scrape LLM threats back out of mixed STRIDE output.
- **Depth.** A focused prompt with the full OWASP-LLM table as its sole job can
  trace data flows deeper than a sub-block sharing turn budget with six STRIDE
  letters.
- **Parallelism.** The pipeline already does level-0 parallel fan-out for
  STRIDE/recon/abuse-verifiers ([[project_m1_parallel_stride_verify]]); an
  LLM-analyzer would be one more level-0 role, adding ~0 wall-clock if it overlaps
  the STRIDE wave.

### Why it is not worth it yet
- **Orchestration surface.** A new agent = new dispatch path, gate, manifest
  entry, progress wiring and failure mode. STRIDE dispatch gating has been
  fragile (inline-shortcut bypass, manifest-as-evidence hole — see
  [[bug_stride_inline_shortcut]], [[bug_stride_dispatch_gate_blind_in_parallel]]).
  Adding a conditional agent adds another path to keep correct.
- **Merge cost.** Its findings must merge into the same taxonomy + triage and
  reuse the JSON-escape sanitizer path that STRIDE merge already needed
  ([[bug_stride_invalid_json_escapes]]).
- **Small surface for most repos.** Most assessed repos have no LLM; those that
  do often have 1–3 AI components — a whole agent may be overkill versus the
  existing conditional sub-block.
- **No payoff without D1/D3.** The MVP (D2) is authored by the *renderer* from
  the LLM findings STRIDE already produces — it needs no new analyzer. The
  separation only pays off once D1 (diagram) + a structured `ai-threats.json`
  exist to consume.

### Verdict — defer, with a clear trigger
Keep the conditional lens in STRIDE for now (no change; D2 consumes its output).
Introduce `appsec-llm-analyzer` **only when D1 + D3 are scheduled** — at that
point the whole-subsystem view and the shared `ai-threats.json` lineage justify
the extra orchestration. **If introduced, it MUST be deterministically gated on
`has_llm_surface` (D0) as its dispatch precondition** — spawned only when an AI
surface exists, never speculatively — which preserves the zero-cost guarantee for
non-LLM repos (the agent is simply never dispatched).

## 6. Recommended phasing

1. **D0 + D3-realign** (small, also fixes the G1 drift bug) — deterministic gate
   + coherent §7 home, both reusing existing suppression. Lowest risk, highest
   correctness payoff.
2. **D2** (MS callout) — pure clone of a proven pattern; high signal, low risk.
3. **D1** (architecture sub-view) — most new code (component types + builder);
   do last, behind the same gate.

Minimal viable first step: **D0 + D2** — a deterministic switch plus an executive
callout — delivers the "is this an AI system and what's the headline risk"
signal with the least code, fully gated.
