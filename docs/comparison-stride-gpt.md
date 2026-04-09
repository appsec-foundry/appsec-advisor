# Comparison: appsec-plugin vs. stride-gpt

| | **appsec-plugin** | **stride-gpt** |
|---|---|---|
| **Repository** | (this project) | [mrwadams/stride-gpt](https://github.com/mrwadams/stride-gpt) |
| **License** | Proprietary (Plugin) | MIT (Open Source) |
| **Version** | v0.10.0-beta | v0.15 |
| **Approach** | Code-based threat analysis (reads, greps, and analyzes actual source code) | Description-based threat generation (LLM generates threats from text descriptions) |

---

## 1. Fundamental Difference

### appsec-plugin — Code-First
The plugin operates directly on the repository. It reads source code, greps for security patterns, analyzes dependencies, and identifies entry points, trust boundaries, and security controls from the actual code. Threats are only recorded when **evidence** (file + line number) is present.

### stride-gpt — Description-First
stride-gpt works with a textual description of the application. Even in GitHub mode, only structural metadata is extracted (function signatures, imports, class names via regex) — no code content, no data flow analysis, no pattern matching for vulnerabilities.

---

## 2. Feature Comparison

### 2.1 Input & Analysis

| Feature | appsec-plugin | stride-gpt |
|---|---|---|
| **Source Code Analysis** | Deep: Grep + Read across 17 security categories (Auth, Crypto, Secrets, Dangerous Sinks, LLM Patterns, etc.) | None (only structural metadata from GitHub import) |
| **Hardcoded Secret Detection** | Yes, with masking (4 chars + `****`) | No |
| **Dependency Scanning (SCA)** | Yes (`--with-sca`): npm audit, pip-audit, govulncheck, mvn dependency-check | No |
| **Architecture Diagram Input** | No (generates diagrams as output) | Yes (upload JPG/PNG, vision LLM extracts description) |
| **Manual Description** | Not required (automatic detection) | Primary input mode |
| **GitHub Repository Import** | Full analysis of local repo | Reads README + function signatures (no deep scan) |
| **Known Threats (Team Input)** | Yes (`known-threats.yaml` with status: open/accepted/mitigated/false-positive) | No |
| **External Context** | Yes (REST endpoint for org context, ADRs, SECURITY.md) | No |

### 2.2 STRIDE Methodology

| Feature | appsec-plugin | stride-gpt |
|---|---|---|
| **STRIDE Categories** | All 6, analyzed individually per component | All 6, generated as a single pass |
| **Component Analysis** | Multi-component: 2-8 parallel STRIDE analyzers (one sub-agent per component) | Single-pass: one LLM call for the entire application |
| **Evidence Requirement** | Mandatory: file + line number, confirmed via grep | None: LLM generates plausible scenarios without code references |
| **Quality Criteria** | 5-point standard (evidence, scenario specificity, controls confirmed absent, no duplicates, realistic attack path) | No formal criteria; quality depends on LLM and description |
| **OWASP Top 10 Coverage Check** | Yes, automatic: gaps are added as gap threats | No |
| **Business Logic Threats** | Yes (workflow bypass, privilege abuse, mass enumeration, economic abuse, state manipulation) | No |
| **OWASP LLM Top 10** | Yes, conditional (when LLM integration is detected in code) | Yes (for app type "Generative AI" and "Agentic AI") |
| **OWASP Agentic AI Top 10** | No | Yes (for app type "Agentic AI", CSA MAESTRO-inspired) |
| **DREAD Scoring** | No (uses Likelihood x Impact matrix) | Yes (5-dimension scoring, 1-10 scale) |

### 2.3 Output

| Feature | appsec-plugin | stride-gpt |
|---|---|---|
| **Markdown Report** | Yes (11 sections, ~2000-5000 lines) | Yes (simple table) |
| **YAML Export** | Yes (`--yaml`) — machine-readable, structured | No |
| **SARIF Export** | Yes (`--sarif`) — SARIF v2.1.0 for CI/CD integration | No |
| **JSON Export** | Yes (intermediate files: `.stride-*.json`, `.dep-scan.json`) | No (in-session Markdown only) |
| **Architecture Diagrams** | Yes (C4 Context/Container/Component + sequence diagrams in Mermaid, auto-generated) | No (generates only attack trees as Mermaid) |
| **Attack Trees** | No | Yes (Mermaid `graph TD`) |
| **Mitigation Register** | Yes (M-NNN IDs, prioritized, with code snippets, effort, steps, framework-specific) | Yes (simple table with suggestions) |
| **Test Cases** | No | Yes (Gherkin Given/When/Then) |
| **VS Code Deep Links** | Yes (`vscode://file/<path>:<line>`) | No |
| **Severity Badges** | Yes (inline HTML badges with colors) | No |

### 2.4 Requirements & Compliance

| Feature | appsec-plugin | stride-gpt |
|---|---|---|
| **Security Requirements Verification** | Yes (`--requirements`): YAML baseline with PASS/PARTIAL/FAIL/UNVERIFIABLE per requirement | No |
| **Requirement Linking** | Yes: URLs from requirements YAML are linked in threat register, mitigation register, and compliance table | No |
| **Custom Requirements (Org-Specific)** | Yes (configurable via `requirements_yaml_url`) | No (generic OWASP references only) |
| **OWASP/CWE References** | Yes (fallback when no requirement matches) | No (no structured references) |
| **Compliance Scope** | Yes (influences impact rating, e.g. PCI-DSS elevates payment-related threats) | No |

### 2.5 Architecture & Operations

| Feature | appsec-plugin | stride-gpt |
|---|---|---|
| **Tech Stack** | Claude Code Plugin (Markdown Agents + Python Scripts) | Streamlit web app (Python) |
| **Supported LLMs** | Claude Sonnet 4.6 (all agents locked) | OpenAI, Anthropic, Google, Mistral, Groq, Ollama, LM Studio (~25 models) |
| **Multi-Agent Architecture** | Yes (6 agents: Orchestrator, Context-Resolver, Recon-Scanner, Dep-Scanner, STRIDE-Analyzer x N, QA-Reviewer) | No (individual LLM calls per feature) |
| **Parallel Execution** | Yes (STRIDE analyzers run in parallel as background agents) | No |
| **Turn Budget Management** | Yes (dynamic by complexity: 15/22/31 turns per component) | No |
| **Checkpointing / Resume** | Yes (`--resume` continues from last completed phase) | No (session lost on refresh) |
| **Incremental Analysis** | Yes (`--incremental` via git diff, only changed components) | No |
| **Dry-Run** | Yes (`--dry-run`, Phases 0-1 only) | No |
| **Quality Assurance** | Yes (QA-Reviewer agent with 10-point checklist + Mermaid validation) | No |
| **Validation** | Yes (Python script `validate_intermediate.py` validates JSON schema) | No |
| **Logging** | Yes (structured `.agent-run.log` with timestamps, steps, duration) | No |
| **CI/CD Integration** | Yes (SARIF output, CLI-based, no GUI required) | No (GUI-only, no CLI/API) |
| **Web UI** | No (CLI / IDE) | Yes (Streamlit) |
| **Concurrent Run Locking** | Yes (`.appsec-lock` file) | No |

---

## 3. Strengths and Weaknesses

### appsec-plugin

| Strengths | Weaknesses |
|---|---|
| Analyzes actual source code with evidence (file + line) | Claude models only (no multi-provider) |
| Multi-agent architecture with parallel execution | No web UI (CLI/IDE only) |
| SARIF export for CI/CD pipelines | No attack tree generation |
| Org-specific requirements with URL linking | No Gherkin test cases |
| Incremental analysis (only changed components) | No DREAD scoring |
| Automatic coverage checks (OWASP, business logic, LLM) | Beta status, not yet hardened for unattended CI/CD |
| QA review as a separate agent | Higher cost (multiple agent invocations) |
| Dependency scanning (SCA) with real audit tools | Requires Claude Code as runtime |
| Hardcoded secret detection with masking | — |
| Checkpoint/resume on interruption | — |

### stride-gpt

| Strengths | Weaknesses |
|---|---|
| Easy onboarding (web UI, no setup complexity) | No actual code analysis (descriptions only) |
| Broad model support (~25 models, 7 providers) | No evidence (no file/line references) |
| Attack tree generation (Mermaid) | No SARIF output (no CI/CD integration) |
| Gherkin test cases | No requirements verification |
| DREAD scoring | No coverage checks (OWASP/business logic) |
| Architecture diagram upload (vision) | No dependency scanning |
| Open source (MIT) | Single-pass (no multi-component analysis) |
| Free (bring your own API keys) | No persistence (session-only) |
| OWASP Agentic AI Top 10 | No quality assurance/validation |
| Local models (Ollama, LM Studio) | No incremental analysis |

---

## 4. When to Use Which Tool?

| Scenario | Recommendation |
|---|---|
| **Early design / architecture review** (no code yet) | **stride-gpt** — works with descriptions and diagrams |
| **Existing repository with code** | **appsec-plugin** — analyzes actual code with evidence |
| **CI/CD pipeline integration** | **appsec-plugin** — SARIF output, CLI-based, incremental |
| **Quick ad-hoc threat analysis** | **stride-gpt** — web UI, usable in 2 minutes |
| **Compliance evidence with requirements** | **appsec-plugin** — requirements YAML with URL linking and status tracking |
| **Team without Claude access** | **stride-gpt** — supports OpenAI, Google, Mistral, local models |
| **Agentic AI security review** | **stride-gpt** — has OWASP Agentic AI Top 10 (CSA MAESTRO) |
| **Deep component-level analysis** | **appsec-plugin** — parallel STRIDE analyzers per component with code reading |
| **Attack trees needed** | **stride-gpt** — generates Mermaid diagrams |
| **Combine both** | stride-gpt for early design, appsec-plugin for implementation phase |

---

## 5. Summary

The two tools pursue fundamentally different approaches:

**stride-gpt** is a lightweight, broadly accessible tool for description-based threat modeling. It excels in early project phases when no code exists yet, or for quick threat brainstorming sessions. Its strength lies in simplicity and flexibility in model choice.

**appsec-plugin** is a deep, evidence-based analysis framework that reads actual source code and only records threats with concrete file/line references. It is suited for existing codebases, compliance requirements, and CI/CD integration. The multi-agent architecture enables parallel analysis of multiple components with automatic quality assurance.

The tools are complementary — stride-gpt for the design phase, appsec-plugin for the implementation and operations phase.
