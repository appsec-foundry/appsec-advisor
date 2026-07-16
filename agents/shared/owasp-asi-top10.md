# OWASP Top 10 for Agentic Applications (2026, ASI) — Threat Analysis Reference

Apply the OWASP Top 10 for Agentic Applications (ASI01–ASI10) as an **agentic** lens on top of the
standard STRIDE analysis and the OWASP LLM Top-10 lens. It is conditional: only apply it when the
component has an **agentic** surface — i.e. `KNOWN_LLM_PATTERNS` contains an `agent-framework`,
`tool-use`, multi-agent SDK (`crewai`, `autogen`), or the component wires an LLM to tools, persistent
memory, retrieval, or other agents. A plain LLM call-and-return (no tools, no memory, no autonomy) is
covered by the LLM lens alone — do **not** manufacture agentic threats where no agentic surface exists.

For each applicable ASI risk below, read the source cited in `KNOWN_LLM_PATTERNS`, verify the pattern
exists, and record a threat only with evidence — do not speculate.

| OWASP ASI ID | Threat | STRIDE | What to check | LLM-lens crosswalk |
|---|---|---|---|---|
| **ASI01** | Agent Goal Hijack | Tampering / EoP | Does external content the agent ingests — tool outputs, retrieved RAG documents, web pages, prior memory — get treated as instructions? Can a hidden instruction redirect a multi-step plan (recursive / cross-context hijack), not just a single reply? | ⊇ LLM01 Prompt Injection |
| **ASI02** | Tool Misuse & Exploitation | EoP / Tampering | Are tool arguments derived from attacker-influenceable input without validation? Is there a permission/approval model for destructive tools (write/delete/exec/spend)? Can one tool's output be fed as the next tool's instruction (unsafe chaining / delegation)? | ⊇ LLM06 Excessive Agency |
| **ASI03** | Agent Identity & Privilege Abuse | Spoofing / EoP | Does the agent act with a broad/inherited/cached service credential instead of the end-user's scoped identity? Is there agent-to-agent trust with no authentication? Do delegated tokens over-grant (identity inheritance across an agent chain)? | — (no LLM analog) |
| **ASI04** | Agentic Supply Chain | Tampering | Are tools, tool **descriptors**, MCP servers, plugins, or agent **personas** loaded from untrusted/unpinned sources? Is there integrity/provenance on the tool registry and on model weights? (Cross-reference recon **Cat-28** MCP/assistant-config signals: `mcp-remote-server`, `mcp-public-registry-server`, `mcp-hardcoded-secret`.) | ⊇ LLM03 Model Supply Chain |
| **ASI05** | Unexpected Code Execution | Tampering / EoP | Does the agent generate-and-run code (code-interpreter tool, `eval`/`exec` of model output, a shell tool) without a sandbox or allow-list? Is generated SQL/shell/HTML passed to a sink unescaped? | ⊇ LLM05 Improper Output Handling |
| **ASI06** | Memory & Context Poisoning | Tampering | Is there a **persistent** memory / RAG / vector store the agent reads back across turns, sessions, or tenants? Can a user write content into it that later steers another user's/agent's run? Is stored memory validated / provenance-tagged before reuse? | ⊇ LLM04 Data & Model Poisoning · LLM08 Vector & Embedding |
| **ASI07** | Insecure Inter-Agent Communication | Spoofing / Tampering / Info Disclosure | *(Design-level — only when ≥2 agents communicate.)* Are agent-to-agent (A2A / MCP / message-bus) channels authenticated, integrity-protected, and encrypted? Does a peer agent's output get trusted without verification? | — (partial: LLM01 on the received message) |
| **ASI08** | Cascading Agent Failures | Denial of Service | *(Design-level — only for chained / looping / multi-agent flows.)* Are there loop/recursion caps, per-run tool-call budgets, and circuit breakers so one error, hallucination, or resource spike does not amplify across the chain? | ⊇ LLM10 Unbounded Consumption (single-agent subset) |
| **ASI09** | Human-Agent Trust Exploitation | Spoofing / Repudiation | Is high-impact agent action gated by an explicit human confirmation? Does the UI attribute actions/output as agent-generated (vs. authoritative human/system)? Can the agent be steered into social-engineering the user? | ⊇ LLM09 Misinformation |
| **ASI10** | Rogue Agents | EoP / Tampering | *(Design-level.)* Are the agent's standing permissions bounded to least-privilege, its actions monitored/audited, and is there a kill-switch / revocation? What is the blast radius if the agent (or its model) is compromised or misaligned? | — (no LLM analog) |

**For each ASI threat found**, apply the same quality bar as standard STRIDE (evidence, specificity,
controls confirmation) using the STRIDE category above. In the `scenario` field, reference the ASI id
explicitly, e.g. *"ASI02 — Tool Misuse: the chat agent at `routes/chat.ts:88` forwards model-chosen tool
arguments to a shell tool with no allow-list, so a hijacked goal (ASI01) escalates to command execution."*

## Crosswalk — reuse, do not duplicate

Most agentic risk on a typical repo is the **agentic framing of an LLM finding you already recorded**.
When a threat already carries an `owasp_llm_id`, tag its agentic counterpart via the crosswalk rather than
authoring a new finding:

`LLM01 → ASI01` · `LLM06 → ASI02` · `LLM03 → ASI04` · `LLM05 → ASI05` · `LLM04 → ASI06` · `LLM08 → ASI06`
· `LLM09 → ASI09` · `LLM10 → ASI08`.

`ASI03`, `ASI07`, `ASI10` have **no LLM analog** — they are genuinely agent-specific (identity/privilege,
inter-agent transport, autonomy bounds) and are only in scope when a real multi-agent / tool-wielding /
persistent-identity surface is present.

## ASI-specific fix patterns

| ASI Threat | Typical fix areas |
|-----------|------------------|
| ASI01 Agent Goal Hijack | Treat all tool/RAG/memory content as untrusted data, not instructions; separate control-plane from content-plane; constrain the plan/goal to a signed system objective |
| ASI02 Tool Misuse | Per-tool permission model; validate/allow-list tool arguments; human approval for destructive/spending tools; do not feed tool output back as instruction |
| ASI03 Identity & Privilege Abuse | Per-agent identity; propagate the end-user's scoped token (not a broad service credential); authenticate agent-to-agent calls; short-lived, least-privilege delegation |
| ASI04 Agentic Supply Chain | Pin & verify tools/MCP servers/plugins/personas; integrity-check tool descriptors and model weights; private registry; review remote MCP servers before enabling |
| ASI05 Unexpected Code Execution | Sandbox/allow-list all agent-run code; never `eval`/`exec` model output; escape generated SQL/shell/HTML at the sink |
| ASI06 Memory & Context Poisoning | Validate & provenance-tag memory before reuse; isolate memory per user/tenant; restrict who can write shared memory/RAG; TTL and audit on stored context |
| ASI07 Insecure Inter-Agent Communication | Authenticate + encrypt A2A/MCP channels; sign messages; verify peer-agent output before acting on it |
| ASI08 Cascading Agent Failures | Loop/recursion caps; per-run tool-call and token budgets; circuit breakers; isolate failure domains between agents |
| ASI09 Human-Agent Trust Exploitation | Explicit confirmation for high-impact actions; attribute agent output in the UI; guard against the agent being used to social-engineer the user |
| ASI10 Rogue Agents | Least-privilege standing permissions; monitor/audit every agent action; kill-switch / credential revocation; bound autonomy and blast radius |
