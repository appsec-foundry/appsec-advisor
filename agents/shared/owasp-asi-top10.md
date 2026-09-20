# OWASP Top 10 for Agentic Applications (2026, ASI) — Threat Analysis Reference

Apply ASI01–ASI10 alongside STRIDE and the LLM lens only for evidenced model-directed actions or delegation. `agent-framework`, `tool-use`, `crewai` and `autogen` are discovery leads; verify their executing source. RAG, persistent memory and plain model calls alone do not establish agency. Record threats only with evidence.

| OWASP ASI ID | Threat | STRIDE | What to check | LLM-lens crosswalk |
|---|---|---|---|---|
| **ASI01** | Agent Goal Hijack | Tampering / EoP | Does external content the agent ingests — tool outputs, retrieved RAG documents, web pages, prior memory — get treated as instructions? Can a hidden instruction redirect a multi-step plan (recursive / cross-context hijack), not just a single reply? | ⊇ LLM01 Prompt Injection |
| **ASI02** | Tool Misuse & Exploitation | EoP / Tampering | Are tool arguments derived from attacker-influenceable input without validation? Does executing code authorize the tool, resource, caller and tenant? Is approval bound to the executed action, target and parameters, invalidated when they change? Can one tool's output be fed as the next tool's instruction (unsafe chaining / delegation)? | ⊇ LLM06 Excessive Agency |
| **ASI03** | Agent Identity & Privilege Abuse | Spoofing / EoP | Does the agent act with a broad/inherited/cached service credential instead of the end-user's scoped identity? Is there agent-to-agent trust with no authentication? Do delegated tokens over-grant (identity inheritance across an agent chain), and is revocation rechecked before further side effects? | — (no LLM analog) |
| **ASI04** | Agentic Supply Chain | Tampering | Are tools, tool **descriptors**, MCP servers, plugins, or agent **personas** loaded from untrusted/unpinned sources? Is there integrity/provenance on the tool registry and on model weights? (Cross-reference recon **Cat-28** MCP/assistant-config signals: `mcp-remote-server`, `mcp-public-registry-server`, `mcp-hardcoded-secret`.) | ⊇ LLM03 Model Supply Chain |
| **ASI05** | Unexpected Code Execution | Tampering / EoP | Does the agent generate-and-run code (code-interpreter tool, `eval`/`exec` of model output, a shell tool) without a sandbox or allow-list? Is generated SQL/shell/HTML passed to a sink unescaped? | ⊇ LLM05 Improper Output Handling |
| **ASI06** | Memory & Context Poisoning | Tampering | Is there a **persistent** memory / RAG / vector store the agent reads back across turns, sessions, or tenants? Can a user write content into it that later steers another user's/agent's run? Are memory creation, replacement and deletion authorized outside the model? Does summarization preserve provenance and trust, and can poisoned entries and derived caches be removed? | ⊇ LLM04 Data & Model Poisoning · LLM08 Vector & Embedding |
| **ASI07** | Insecure Inter-Agent Communication | Spoofing / Tampering / Info Disclosure | *(Design-level — only when ≥2 agents communicate.)* Are agent-to-agent (A2A / MCP / message-bus) channels authenticated, integrity-protected, and encrypted? Does a peer agent's output get trusted without verification? | — (partial: LLM01 on the received message) |
| **ASI08** | Cascading Agent Failures | Denial of Service | *(Design-level — only for chained / looping / multi-agent flows.)* Are time, tool-call, cost and delegation limits enforced outside the model? Does cancellation stop subsequent effects? Are retries after an unknown action outcome reconciled or idempotent, preventing duplicate side effects? Prove amplification before assigning ASI08. | ⊇ LLM10 Unbounded Consumption (single-agent subset) |
| **ASI09** | Human-Agent Trust Exploitation | Spoofing / Repudiation | Is high-impact agent action gated by an explicit human confirmation? Does the UI attribute actions/output as agent-generated (vs. authoritative human/system)? Can the agent be steered into social-engineering the user? | ⊇ LLM09 Misinformation |
| **ASI10** | Rogue Agents | EoP / Tampering | *(Design-level.)* Are the agent's standing permissions bounded to least-privilege, its actions monitored/audited, and is there a kill-switch / revocation? What is the blast radius if the agent (or its model) is compromised or misaligned? | — (no LLM analog) |

Apply the STRIDE evidence and control-confirmation requirements. Reference the ASI ID in `scenario` and preserve explicit classification tags.

## Crosswalk — reuse, do not duplicate

Reuse one finding when its evidence proves both classifications: `LLM01 → ASI01`, `LLM06 → ASI02`, `LLM03 → ASI04`, `LLM05 → ASI05`, `LLM04/LLM08 → ASI06`, `LLM09 → ASI09`, `LLM10 → ASI08`. These are candidate mappings: ordinary consumption proves no cascade; misinformation alone proves no human trust exploitation. ASI03, ASI07 and ASI10 require their own evidenced agent identity, communication or autonomy mechanism.

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

## Evidence and exclusions

Trace attacker-controlled input to the executing operation and protected resource. A tool declaration, retrieved instruction or missing prompt disclaimer alone establishes no exploit. Existing server-side resource authorization, scoped delegation, immutable approval parameters and enforced cancellation are relevant counterevidence. Unknown deployment controls remain unverified. Use CWE-1427 for demonstrated instruction promotion, CWE-862/863 for missing/incorrect action or memory authorization, CWE-250 for excessive execution privilege, CWE-400 for unbounded work, and CWE-841 for exploitable action sequencing or duplicate effects. Apply normal impact-based severity and caps; ASI labels never raise severity. Inspect the actual control and sink before selecting the primary CWE.

For consequential actions, verification covers altered approved parameters, cross-user resources, delegated privilege escalation, revocation before the next effect and timeout followed by retry. Record inspected scope, weaknesses and unknowns in existing report fields. No finding does not establish control effectiveness. Keep one finding per mechanism.
