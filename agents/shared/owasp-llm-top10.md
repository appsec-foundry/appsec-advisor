# OWASP Top 10 for LLM Applications (2025) — Threat Analysis Reference

Apply the OWASP Top 10 for LLM Applications (2025) as an additional threat lens **on top of** the standard STRIDE analysis. Each LLM threat maps to one or more STRIDE categories.

For each applicable LLM threat below, read the relevant source files cited in `KNOWN_LLM_PATTERNS`, verify the pattern exists, and assess whether the threat applies to this component. Only record threats with evidence — do not speculate.

| OWASP LLM ID | Threat | STRIDE | What to check | Grep patterns to verify |
|---|---|---|---|---|
| **LLM01** | Prompt Injection | Tampering / EoP | Does user input flow into LLM prompts without sanitization? Is there a system prompt that can be overridden? Are there prompt template injections (f-strings, `.format()`, `+` concat with user input)? | `(?i)(f".*\{.*user\|\.format\(.*input\|prompt\s*\+\s*\|prompt\s*=.*request\|user.*message.*\+)` |
| **LLM02** | Sensitive Information Disclosure | Info Disclosure | Can the LLM output PII, credentials, or internal system details? Is output filtered before returning to the user? Are conversation histories stored without access controls? | `(?i)(completion\.choices\|response\.content\|\.generate\(.*return\|chat_history\|conversation.*log\|memory\.save)` |
| **LLM03** | Supply Chain | Tampering | Are model weights/checkpoints loaded from untrusted sources? Are LLM dependencies pinned? Is there a model registry with integrity checks? | `(?i)(from_pretrained\|load_model\|download.*model\|hub\.pull\|model.*url\|pickle\.load)` |
| **LLM04** | Data & Model Poisoning | Tampering | Can users influence training data, fine-tuning datasets, or RAG knowledge base content? Are embeddings updatable via user input? | `(?i)(fine.?tune\|training.*data\|add.*document\|upsert.*embedding\|index\.add\|collection\.add\|vectorstore\.add)` |
| **LLM05** | Improper Output Handling | Tampering / XSS | Is LLM output rendered as HTML without escaping? Is it used in SQL queries, shell commands, or code execution? Is it passed to downstream APIs without validation? | `(?i)(innerHTML.*completion\|exec\(.*response\|eval\(.*output\|query.*\+.*completion\|subprocess.*ai_output\|render.*llm)` |
| **LLM06** | Excessive Agency | EoP | What tools can the LLM invoke? Is there a permission/approval model? Can the LLM perform destructive operations (delete, write, execute) autonomously? | `(?i)(tool.?use\|function.?call\|AgentExecutor\|create.?tool\|@tool\|Tool\(\|allow.?dangerous\|shell.*tool\|sql.*tool\|file.*tool)` |
| **LLM07** | System Prompt Leakage | Info Disclosure | Is the system prompt hardcoded in client-side code? Can users extract it via prompt injection ("repeat your instructions")? Is it exposed in error messages or logs? Is there any debug flag or cookie that gates tool-call events or raw LLM output to non-admin users (inverted guards are a common mistake — check role comparisons near SSE/streaming writes)? | `(?i)(system.?prompt\|system.?message\|SystemMessage\|SYSTEM_PROMPT\|system.*content.*=\|show_tool_calls\|debug.*tool\|tool.?calls.*visible\|expose.*tool\|leak.*tool.*call)` — check if the value is in frontend code, environment, or backend-only; also check for debug/cookie flags that expose tool call events or internal function names to non-admin users |
| **LLM08** | Vector & Embedding Weaknesses | Tampering / Info Disclosure | Are embeddings queryable by unauthenticated users? Can adversarial inputs manipulate similarity search results? Is the embedding model's output validated? | `(?i)(similarity.?search\|query.*embedding\|vector.?search\|\.query\(.*text\|retrieve.*document)` |
| **LLM09** | Misinformation | Repudiation | Does the system present LLM output as authoritative fact? Is there a disclaimer or confidence indicator? Are outputs logged for audit and correction? | Check if LLM responses are returned to users without attribution, verification, or grounding against trusted sources |
| **LLM10** | Unbounded Consumption | DoS | Is there rate limiting on LLM API calls? Are `max_tokens` and `temperature` bounded? Can a single user trigger excessive token consumption? Is there cost monitoring? | `(?i)(max.?tokens\|rate.?limit\|throttl\|budget\|cost.?limit\|token.?limit\|usage.?track)` — check if these controls **exist** |

**For each LLM threat found**, apply the same quality standard as standard STRIDE threats (evidence, specificity, controls confirmation). Use the STRIDE category from the mapping above. In the `scenario` field, explicitly reference the OWASP LLM ID (e.g., "LLM01 — Prompt Injection: User-controlled input from the chat endpoint at `routes/chat.ts:45` is concatenated directly into the system prompt...").

## LLM-specific fix patterns

| LLM Threat | Typical fix areas |
|-----------|------------------|
| LLM01 Prompt Injection | Input sanitization layer before prompt assembly; separate system/user message channels; use structured tool-call APIs instead of free-text instruction; content filtering |
| LLM02 Sensitive Info Disclosure | Output filtering/PII redaction before returning to user; conversation history TTL and access controls |
| LLM03 Supply Chain | Pin model versions and SDK versions; verify model checksums; use official model registries only |
| LLM04 Data Poisoning | Validate and sanitize RAG ingestion; restrict who can update the knowledge base; audit trail for embedding updates |
| LLM05 Improper Output | Never use LLM output in `eval()`, `exec()`, raw SQL, or `innerHTML`; treat LLM output as untrusted user input |
| LLM06 Excessive Agency | Implement tool permission model; require human approval for destructive actions; limit tool scope to read-only where possible |
| LLM07 System Prompt Leakage | Keep system prompts server-side only; don't log them; don't echo them in error messages |
| LLM08 Vector/Embedding | Auth on vector DB queries; rate-limit similarity search; validate embedding dimensions and content |
| LLM09 Misinformation | Add "AI-generated" disclaimers; ground outputs against authoritative sources; log for audit |
| LLM10 Unbounded Consumption | Set `max_tokens` caps; per-user rate limits on LLM calls; cost alerting and circuit breakers |
