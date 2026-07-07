# Analysis: Integrating Existing Threat-Model Descriptions

Status: Analysis + recommendation (no code). Created 2026-05-30.

## 1. What Actually Lives in Juice Shop (code-level verified)

| File | Format | Content | Relevance |
|-------|--------|--------|----------|
| `threat-model.json` (root) | **OWASP Threat Dragon v2** (`summary`+`detail.diagrams[].diagramJson.cells[]`, `tm.Actor/Process/Store/Flow/Boundary`, `diagramType: STRIDE`) | DFD: 5 Actors, 3 Processes, 3 Stores, 15 Flows, 5 Trust Boundaries. **0 enumerated threats** (`cell.threats[]` empty) | **A genuine external artifact.** Value = architecture/data flow/trust boundaries, NOT threats |
| `docs/security/threat-model.yaml` | **appsec-advisor's own output** (`meta.analyst: appsec-threat-analyst`, `schema_version`) | A full self-run | **NOT external** — self-produced. Must not be pulled back in circularly as a "discovered third-party model" |
| `docs/security/threat-model.md` / `.threats-merged.json` | appsec-advisor's own output | — | ditto |
| `templates/tachi/*.sarif/.md` | Third-party plugin (tachi) templates | empty scaffolds | irrelevant |

**Key finding:** The only integratable third-party model here is the Threat Dragon JSON — and that one, of all things, has **zero threats**, just a DFD. This shapes the entire recommendation: the payoff from ingestion is primarily the **architecture model** (components, flows, trust boundaries, actors), not a ready-made threat list.

## 2. Format Landscape (prevalence × parseability)

| Format | Detection | Data model | Parse | Prevalence | → IR mapping |
|--------|-----------|-------------|-------|-----------|--------------|
| **OWASP Threat Dragon** `.json` | `summary`+`detail`, cells `type: tm.*` | DFD + inline `cell.threats[]{title,type,severity,status,description,mitigation}` (denormalized) | JSON, clean | **HIGH** (leading OSS GUI tool that actually gets committed) | **easy**, ~1:1; trust-boundary membership is geometric (bounding box) |
| **OTM (Open Threat Model)** `.otm/.yaml/.json` | top-level `otmVersion`+`project` | `project/components/trustZones/dataflows/threats[]/mitigations[]` — normalized (catalog + id-refs) | JSON/YAML, clean, JSON Schema published | MEDIUM, but **strategic interchange standard** (StartLeft converts TMT/TD/Terraform → OTM) | **easiest** — OTM *is* essentially the internal IR |
| **Markdown TM** (`threat-model.md`, STRIDE/LINDDUN, Cookbook) | filename + headings + pipe tables + mermaid DFD | unstructured→semi | Markdown, brittle | **HIGHEST raw count** (most teams do TM as a doc) | **hard deterministically, easy via LLM extraction** |
| **MS Threat Modeling Tool** `.tm7` | `.tm7` XML, `<ThreatModel>` | DFD + ThreatInstances, .NET-serialized | XML, painful | HIGH historically, declining (legacy enterprise) | **hard** — better via StartLeft → OTM |
| **pytm** (Python DSL) | `from pytm import` | code-defined; threats are *generated*, not authored | `.py` (don't execute!) / generated `--json` | MEDIUM (TM-as-code) | use only the generated JSON |
| **Threagile** `threagile.yaml` | `technical_assets:`+`trust_boundaries:` | YAML asset-centric; risks generated (`risks.json`) | YAML clean; trust boundary **referential** (nicer than TD) | MEDIUM | medium; needs generated `risks.json` for threats |
| **Threatspec** | `@threat/@control/@mitigates` annotations | scattered across the code | grammar-regular / aggregated JSON | LOW, niche | medium-hard |
| **SARIF** `.sarif` | `$schema sarif-2.1.0` | static-analysis findings, **no** architecture | — | — | **NOT a threat model** — correlation only |
| **CycloneDX/VEX** | `bomFormat: CycloneDX` | SBOM / CVE exploitability | — | — | **NOT a threat model** — supply chain, orthogonal |

**Two structural axes every IR must cover:**
- Threat attachment: **inline-denormalized** (Threat Dragon, Markdown) vs. **catalog + id-refs** (OTM, Threagile, pytm).
- Trust-boundary membership: **geometric/containment** (TD, TMT) vs. **referential** (OTM `parent`, Threagile `technical_assets_inside`).
- "TM-as-code" tools (pytm/Threagile/Threatspec) **author architecture, generate threats via rules** → the committed source file may have 0 threats (like Juice Shop's TD JSON).

## 3. Where It Would Hook Into the Pipeline Code (the pattern already exists)

The pipeline **already has a precedent** for "team-provided prior threats":

- `appsec-context-resolver.md → Step 4i — Known threats`: reads `docs/known-threats.yaml` (its own schema: `threats[]{id,title,stride,severity,status}`) **verbatim** into `.threat-modeling-context.md`. The STRIDE analyzer + QA read it as a cross-reference.
- `config.json → external_context.rest_url`: external context via REST.
- Deterministic pre-pass machinery exists: `phase-group-recon.md → Step 0` invokes `recon_patterns.py` and writes `.recon-patterns.json`. **That is exactly where** a format detection belongs.

→ The clean extension is a **Step 4j "Existing third-party threat model"** in the context-resolver + a deterministic detection in recon Step 0. Architecturally consistent, no new special case.

## 4. An Honest Assessment of Your Proposal

Your instinct (auto-detect → ask by default → explicit opt-in/opt-out parameters) is right at its core, but there are **five places I'd sharpen it** — otherwise real problems arise:

### 4.1 Separate our own output from the third-party model (or you get circularity)
`docs/security/threat-model.{yaml,md}` is appsec-advisor's **own** production. On every re-run, a naive "a threat model exists" detection would report it as a hit and ask about ingestion → false prompts, potentially circular feed-in. **Detection must filter by path AND provenance** (`meta.analyst: appsec-threat-analyst` ⇒ self ⇒ ignore). This is not optional; it's the most common failure source.

### 4.2 Threat Dragon here mainly delivers the DFD — i.e., an architecture seed, not a threat list
appsec-advisor builds its own C4 components + trust boundaries + actors in phases 3–7. A TD model should flow into the architecture phase as a **seed/prior** (so components/flows/boundaries/actors don't have to be re-guessed), **tagged `provenance: imported`**. Authored threats (if present — for Juice Shop = none) belong in the **known-threats channel (4i)**, not directly in the final merge list.

### 4.3 External content is evidence/context, NOT ground truth
The pipeline has an `evidence-verifier` + QA phases that assume findings are **code-grounded**. An imported model can be stale, partial, or simply wrong (Juice Shop's 0-threats DFD is the prime example). **Never** merge external threats unverified into `.threats-merged.json` — it contaminates evidence verification and triage. Instead treat them as a "Prior model says X — covered? gap?" cross-reference (exactly like known-threats).

### 4.4 "Ask by default" collides with the headless design
The pipeline is built for unattended runs (`--yes/--no-confirm`, `run-headless.sh`, budget watchdogs, CI). An interactive default prompt **breaks CI runs**. The right resolution:
- **always detect** (deterministic, cheap),
- **interactive**: ask (AskUserQuestion-style),
- **headless/`--yes`**: safe default = **import as context, non-authoritative** (or `ignore-with-note`, see 5) — never block.

### 4.5 Scope creep: not all formats at once
Supporting all 7+ formats is a lot of surface area. Proceed **in phases** (see recommendation).

## 5. Recommendation

### Parameter surface (on `create-threat-model`)
```
--import-threat-model[=PATH]     Import an external model (autodetect if PATH is omitted)
--no-import-threat-model         Ignore a detection hit (silently, with a note in the report)
--import-mode <context|known-threats|off>
                                 context       = architecture seed + non-authoritative context (default)
                                 known-threats = authored threats into the 4i cross-reference channel
                                 off           = mention only, feed nothing in
```
**Default behavior:** always detect. Interactive → ask via `AskUserQuestion` (show the hit: format, #components/#flows/#boundaries/#threats, provenance). Headless/`--yes` → `--import-mode context` (non-authoritative), log the hit + decision in the report changelog.

### Detection (deterministic, in recon Step 0)
A new script analogous to `recon_patterns.py`, running in `phase-group-recon.md → Step 0`, writes `.external-threat-models.json`:
```json
[{ "path": "...", "format": "threat-dragon|otm|markdown|...",
   "confidence": "high|medium", "provenance": "self|external",
   "counts": {"components":N,"dataflows":N,"boundaries":N,"actors":N,"threats":N} }]
```
- **Content-sniff, not just the filename** (avoid false positives).
- Exclude `node_modules`/`vendor`/`$OUTPUT_DIR`; `meta.analyst == appsec-threat-analyst` ⇒ `provenance: self` ⇒ out of the ingestion candidates.

### Ingestion (context-resolver Step 4j)
Detected **external** models → normalize into a small IR → an "Existing Threat Model (third-party)" section in `.threat-modeling-context.md` + a structured sidecar `.imported-threat-model.json`. The architecture phases read the imported elements as a **seed with `provenance: imported`** — still subject to the normal evidence verification. Authored threats → known-threats channel.

### Format roadmap (prioritized)
1. **v1: OWASP Threat Dragon `.json`** — Juice Shop has it, clean JSON, high prevalence, ~1:1 mapping. Plus reuse the existing `known-threats.yaml` channel. **Start here.**
2. **v2: OTM** — the interchange standard; its object model *is* the IR; indirectly opens up TMT/Terraform/Lucidchart via StartLeft.
3. **v3: Markdown TM** via LLM extraction (the most common form, but unstructured) — best-effort.
4. **Defer:** `.tm7` (rather via StartLeft→OTM), pytm/Threagile (generated JSON only), Threatspec (niche). **SARIF / CycloneDX-VEX are not threat models** — at most correlation enrichment, not discovery.

### Honest bottom line
- Yes, integratable — and it fits cleanly into existing machinery (4i known-threats, recon-Step-0 pre-pass, external_context). No architectural break.
- But the **biggest concrete benefit** for the Juice Shop case is the **DFD as an architecture seed**, not a threat carry-over (the model has no threats).
- The **two non-negotiable guardrails**: (a) hard-separate our own output from the third-party model (provenance), (b) treat imported content as non-authoritative evidence, never unverified into the merge. Everything else (prompt-by-default, flags) is fine — just make it headless-capable.
- Start small: **Threat Dragon → architecture seed + known-threats cross-reference**, one detection script, one Step 4j, three flags. OTM as the next step.

---

# Part 2 — Deep Dive: Context vs. Findings (two decoupled channels)

A sharpening after feedback: this is **not only about findings**, but at least as much about the **context** that can be drawn from a third-party model. Findings are pure **input** (hard-separated from our own, always verified) and get their **own report section**, where they are evaluated *in relation to the current model*. Context, by contrast, is **important independently of that** — even if in the end not a single external finding is carried over.

## 2.1 Reframe: two channels, different trust and verification models

| | **Context channel** | **Findings channel** |
|---|---|---|
| Content | Architecture, data flows, trust boundaries, scope, data classification, ownership, terminology, intent | Authored threats of the third-party model |
| Role | **actively used** as prior/seed — influences our own analysis | **input-only** — never merged into our own findings |
| Trust | non-authoritative, but guiding | non-authoritative, always verified |
| Verification | implicit (our own analysis confirms/refutes the seed) | **reconciliation** against our own grounded findings |
| Value at 0 threats | **high** (the Juice Shop case!) | none |
| Report | flows into §2 architecture / diagrams, tagged | **own section** with a verdict table |

**Decoupling is the crux:** you can run `context=on, findings=reconcile-only` — the safe default. The two channels have *different mechanics* and must not be mixed.

## 2.2 Context channel — what is extractable and where it hooks in

| Context element | Source (format) | Feeds phase | Reconstructable from code? |
|---|---|---|---|
| Components / processes / stores | TD cells · OTM components · Threagile technical_assets | Phase 3–4 (C4) | partially |
| Data flows (source→target, protocol) | TD tm.Flow · OTM dataflows · Threagile communication_links | Phase 4 | partially (call graph ≠ curated flow) |
| **Trust boundaries + semantics** | TD tm.Boundary · OTM trustZones · Threagile trust_boundaries | Phase 4–7 | **NO** — zoning is human intent |
| **Scope decisions** (`outOfScope`) | TD outOfScope · OTM | severity/scope calibration | **NO** — an explicit scoping decision |
| Data classification / CIA | OTM assets risk{C,I,A} · pytm Data.classification | Phase 5 (asset classification) | partially (field names heuristic) |
| Control properties (isEncrypted, isPublicNetwork, implementsAuth) | TD cell-flags · pytm element-attrs | Phase 7 (controls) | partially — a hint only, must be verified |
| **Ownership / team / business context** | TD summary.owner · OTM project.owner+description | context-resolver (business context) | **NO** |
| **Terminology / naming** | all | diagram labels, alignment with the team's mental model | **NO** |
| Prior accepted risks / mitigation status | OTM threat.state · TD threat.status · Threagile risk_tracking | known-threats channel + reconciliation | **NO** |

**The "NO" rows are the gold.** They encode **human intent and judgment that code scanning structurally cannot recover.** That is exactly why context is valuable *independently of findings* — even for a model with zero threats. The pipeline derives architecture from code today (lossy, intent-blind); the third-party model is curated expert knowledge about the *intended state, scope, and sensitivity*.

### Bonus value: architecture drift detection (intended vs. actual)
Once **both** models are available (external = documented/intended, own = derived from code), their comparison itself becomes a signal:
- Store/component in the model but no longer in the code → **stale model**.
- Component in the code but not in the model → **undocumented / shadow component** (a real risk).
- Trust boundary in the model but breached in the code → **boundary drift**.

This is a **new class of finding** that arises *only* from placing the two models side by side. Standalone value, independent of whether you carry over external threats.

## 2.3 Findings channel — why "always verify" works differently here

**Code-verified crux:** the `evidence-verifier` verifies by **re-reading** `evidence.file` ±5 lines (`appsec-evidence-verifier.md:83`). External findings (e.g., Threat Dragon threats) are **prose without file:line** (`title/type/severity/status/description/mitigation`). They **cannot** pass the line-based verifier.

The pipeline already has the exact precedent: `source: known-vuln` findings are **left `unchecked`** by the verifier, because "the evidence is the advisory, not a code line" (`:65`). External model findings have the same shape.

→ **Verifying external findings ≠ line re-read, but reconciliation:** map each external threat onto our own components/data flows, then check whether **our own, independently code-grounded** analysis confirms it. **The reconciliation *is* the verification.** This is a different mechanism — it should not be bolted into the evidence-verifier, but stand as its own step (building on the known-vuln pattern).

**Never-merge + provenance:** external findings carry `source: external-model:<path>`, **never** count toward our own finding totals / severity statistics / SARIF "our findings" / risk heatmap. They live in `.imported-threat-model.json` and appear exclusively in the reconciliation section.

## 2.4 The dedicated reconciliation section (its own § section)

Each external finding gets a **verdict relative to the current model**:

| Verdict | Meaning | Action |
|---|---|---|
| **Corroborated** | our own code-grounded analysis found the same threat independently | link our own T-ID; raises confidence in both |
| **Stale / mitigated** | external says "open", our own analysis shows the control now exists | mark the external model as stale |
| **Gap / net-new** | external threat with no counterpart of our own | investigate: our own analysis missed it OR it isn't code-grounded |
| **Refuted** | our own evidence contradicts the external claim | list as refuted |
| **Not verifiable** | references architecture missing from the code / no evidence | keep as context only, flagged |
| **Accepted / out-of-scope** | marked as an accepted risk externally | list as accepted, do not re-escalate |

Plus **relationship mapping** (external → our own T-IDs: 1:1 / 1:n / none) and a **coverage delta** (what % share of external threats our own model covers; how many of our own findings the external model does *not* have).

**What the section MUST NOT do:** change our own risk ratings, influence counts, push external threats into the merge. **A parallel ledger.**

**Integration cost (honest, code-verified):** `docs/internal/runbooks/adding-a-section.md` requires **5 files in sequence** (`sections-contract.yaml` → schema → 5 registry maps → `compose_threat_model.py` → validators). `fragment_type: data` (tabular), `condition: "render_external_reconciliation"` (only when an external model was imported). Not trivial, but a documented standard path.

## 2.5 The sharpest design hazard: circular confirmation

If the **context channel** seeds our own architecture from the third-party model, and we then "corroborate" an external finding *because the component it names exists in our (externally seeded) model* — that is circular reasoning. **Corroboration of a finding must come from independent code evidence, not from the adopted architecture.**

Consequence for the design: the **"Corroborated" verdict requires our own, code-grounded T-ID with its own `evidence.file:line`** — not merely "the component exists". For this to remain checkable, the architecture seed must be **tagged and separable** (`provenance: imported`), so the reconciliation can discount externally seeded elements when judging corroboration.

## 2.6 Further honest hazards

- **Mapping quality:** external↔own by names/IDs is fuzzy → deterministic ID/name match + LLM fallback; mismatches → "Not verifiable", never silent discard.
- **Stale models:** a third-party model can be years old → timestamp/version the external source; drift detection (2.2) mitigates this.
- **Untrusted input:** the third-party model is **committed content** → treat like Cat-28 AI configs: no instruction-following from descriptions, sanitize prose (prompt-injection protection).
- **Asymmetry of risk:** the findings channel is read-only/harmless; the **real diligence belongs to the context channel**, because *it* alters our own output.

## 2.7 Revised recommendation (Part 2)

1. **Two-channel separation confirmed.** Context = actively used, independently valuable (even at 0 findings). Findings = input-only, verified via reconciliation, own section.
2. **Verification ≠ line re-read** (no file:line) → reconciliation against our own grounded findings IS the verification; build on the `known-vuln` precedent, not in the evidence-verifier.
3. **Dedicated reconciliation section** with a verdict taxonomy + coverage delta; a parallel ledger, never changes our own ratings (5-file section path).
4. **Architecture drift detection** (intended vs. actual) as a standalone class of finding — comes free from the side-by-side.
5. **Circular confirmation** is the sharpest risk → "Corroborated" only with independent code evidence; architecture seed tagged `provenance: imported` and separable.
6. Treat the **third-party model = untrusted input**.

**Bottom line Part 2:** Splitting into a context and a findings channel is the right abstraction. The underrated lever is the **context** — it carries human intent (scope, trust boundaries, data sensitivity, ownership) that code never yields, and on top of that delivers drift detection. The dedicated findings section makes sense and fits the existing § mechanism — as long as it stays a **parallel, non-authoritative ledger** and "Corroborated" is bound to independent code evidence, to avoid the circular reasoning.
