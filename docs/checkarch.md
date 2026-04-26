  3 Root-Cause-Schichten

  A. Orchestrator-Phase-7/8 schreibt yaml zu schmal

  threat-model.yaml hat:
  components:        [id, name, paths, description, complexity, threat_ids]   # FEHLT: type/kind, tier, responsibilities
  trust_boundaries:  [id, name, description, trust_level]                     # FEHLT: enforcement
  security_controls: [id, domain, control, implementation, effectiveness, evidence_file, linked_threats]   # FEHLT: notes
  data_flows:        []                                                       # KOMPLETT LEER

  → Phase 8 (Security Controls Catalog) lief 20s, Phase 7 (Trust Boundary Analysis) 13s — diese kurzen Phasen produzieren nur die Pflicht-Felder, keine Detail-Felder.
  Vergleich: in example2.md waren diese Felder gefüllt.

  B. Pre-generator-Renderer hardcoded

  pregenerate_fragments.py:140-281 (gen_architecture_diagrams):
  - 2.1 hardcoded 3 Knoten (Zeilen 167-179)
  - 2.2 nur eine Verbindung pro Tier-Paar (Zeilen 217-224) — ignoriert data_flows[] komplett
  - 2.4 hardcoded TB1/TB2/TB3 mermaid (Zeilen 266-279)

  pregenerate_fragments.py:560-618 (gen_security_architecture):
  - 7.3 IAM-Flow ist ein generischer Stub (Zeilen 603-612), nutzt Client/Service/Store egal welcher Auth-Methode
  - Domain-Matching nur auf control.domain-Substring (Zeile 504), nicht auf threats/CWE → Sub-Sections 7.8/7.9/7.11/7.12 bleiben leer obwohl threats-Daten reichen
  würden

  C. Stage 2 RENDER_ONLY enrichment-Pfad fehlt

  agents/appsec-threat-analyst.md "Stage 2 mode" verlangt nur die Authoring von:
  - ms-verdict.json, ms-architecture-assessment.json (Management Summary)
  - attack-walkthroughs.md (für Critical findings)
  - attack-surface.md (Fallback bei pregen-Crash)

  → Stage 2 LLM muss architecture-diagrams.md und security-architecture.md nicht ersetzen, also bleibt die deterministische Dünn-Version stehen. Der
  pregenerate_fragments.py ist idempotent — wenn LLM sie geschrieben hätte, würde pregen sie überspringen, aber LLM schreibt sie nicht.

  Lösungsoptionen

  ┌─────────┬─────────────────────────────────────────────────────────────────────────────────────────────────┬───────────────────────────┬────────────────────────┐
  │ Schicht │                                             Option                                              │          Aufwand          │        Wirkung         │
  ├─────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┼────────────────────────┤
  │         │ Orchestrator-Prompt in phase-group-architecture.md erweitert: zwingt data_flows[] +             │ mittel —                  │ hoch — füllt yaml mit  │
  │ A       │ components[].type/responsibilities + trust_boundaries[].enforcement + security_controls[].notes │ Agent-Prompt-Edit         │ Substanz               │
  │         │  zu schreiben                                                                                   │                           │                        │
  ├─────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┼────────────────────────┤
  │ B       │ Renderer liest data_flows[] für §2.2 und nutzt threats[].cwe für §7-Domain-Zuordnung            │ niedrig (~80 LoC)         │ mittel — bessere       │
  │         │                                                                                                 │                           │ Defaults               │
  ├─────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┼────────────────────────┤
  │ C       │ Stage 2 RENDER_ONLY Mode bekommt zwei neue Pflicht-Fragmente: architecture-diagrams.md und      │ mittel — Agent-Prompt +   │ sehr hoch — LLM bringt │
  │         │ security-architecture.md mit "richer Mermaid + per-domain prose" Anforderung                    │ contract update           │  domain expertise rein │