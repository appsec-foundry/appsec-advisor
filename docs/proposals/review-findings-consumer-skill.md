# Consumer skill: review findings, prioritize, derive remediations

> **Status: implemented** as `/appsec-advisor:review-threat-model` (dev). This
> document remains as a design record — it explains why the skill is a pure
> consumer and how independence from the generation workflow was verified.
> Delivered: `skills/review-threat-model/SKILL.md`, `scripts/review_threat_model.py`,
> `tests/test_review_threat_model.py`, one additive permissions entry, user docs
> (README + `docs/threat-modeler.md`), and a next-steps hint in the completion summary.

A **user-facing skill** that runs at a **later point in time**, **completely
independent** of the `create-threat-model` workflow, against an already-generated `threat-model.yaml`.

## Guiding principle: consumer, never producer

The value lies in the layer **above** the report that the pipeline deliberately lacks,
because it needs inputs only a human can supply (business context, owner, capacity).
The discipline that keeps the skill clean and risk-free:

| Allowed (consumer) | Forbidden (would duplicate the producer) |
|---|---|
| Read `threat-model.yaml` **read-only**, rank by severity, present | Recompute severity/CVSS |
| Capture user triage: `fix` / `accept-risk` / `defer` + rationale, `owner`, `target_sprint` | Re-author mitigations |
| **Reuse** the `remediation` text from the yaml | **Write back** into `threat-model.yaml` |
| Write sidecar + action plan as **net-new** artifacts | Touch producer scripts/schemas/templates |

If the skill breaks this boundary, it becomes a second source of truth for severity/mitigations
— exactly the anti-pattern from AGENTS.md §12. That is why the boundary is the core of the design,
not a detail.

## Full independence — verified

The existing create workflow keeps running **byte-identically**. Proven at the two
only collision points:

| Point | Result |
|---|---|
| Skill registration | `.claude-plugin/plugin.json` enumerates **no** skills → auto-discovery from `skills/`. New skill = new folder, **zero edits** to shared manifests. |
| Producer (scripts/schemas/templates/agents) | **Untouched.** |
| `threat-model.yaml` | **Read-only.** |
| State namespace | `.appsec/` is pipeline-owned (`actors.yaml`, `abuse-cases/`), as is `.appsec-cache/`. The sidecar therefore lives in its **own** namespace `.appsec-triage/` → guaranteed zero overlap, survives re-scan. |
| `data/required-permissions.yaml` | The **only** shared file touched — purely **additive** (its own skill block), changes no runtime behavior of existing skills. Required anyway per AGENTS.md §7. |

## Skill sketch: `review-threat-model`

**Invocation:** `/appsec-advisor:review-threat-model [--repo <path>] [--output <path>]`

**Naming boundary:** belongs to the consumption family `<verb>-threat-model` (like
`show`/`export`/`publish`). Only a word overlap with `eval-threat-model`, no real
collision: `eval` is **dev/test** (artifact quality, adversarial-verify), `review` is
**user-facing** (prioritize findings, derive remediations). The `description:` lines
of both skills must separate them sharply (no "evaluate/quality" for `review`), so that
skill discovery does not route incorrectly.
No scan, no agents, no producer. Runs against the committed `threat-model.yaml`.

1. **Load** — merge `threat-model.yaml` + existing `.appsec-triage/triage.yaml`.
   Finding IDs (`F-NNN`/`T-NNN`) are the join axis.
2. **Reconcile** — new findings since the last triage → `untriaged`; disappeared ones →
   `stale` flag (never hard-delete). Robust against ID drift from `_assign_t_ids` renumbering
   (a known gotcha) → stale flag instead of hard-fail.
3. **Rank** — by `effective_severity` → `severity`, enriched with existing
   triage state. Quick wins (high severity × cheap `remediation`) vs. heavy lifts made visible.
4. **Triage (interactive)** — per finding/batch via AskUserQuestion: decision +
   rationale, optionally owner + target sprint. Business context is **user input**, not
   computed.
5. **Persist** — `.appsec-triage/triage.yaml`, key = finding ID. **Never** back into
   `threat-model.yaml` (see "rebuild yaml wipes enrichments").
6. **Emit** — `remediation-plan.md` (+ optional `.yaml`): grouped by decision,
   with owner/sprint, mitigations reused from the yaml.

## Open design points (to resolve before building)

- **Triage granularity**: per finding (thorough, many prompts) vs. batch by
  severity bucket (fast). Proposal: batch as default, single-finding drilldown on request.
- **`stale` policy**: keep the flag and mark it in the plan as "no longer in the model",
  or auto-archive after N rounds.
- **Relationship to `show-threat-model`**: deliberately keep them separate (read-only vs.
  action-oriented), do not merge — otherwise scope creep into a so-far passive skill.

## Effort / risk

- **Risk**: minimal. Net-new skill + sidecar namespace; one additive permissions block.
  No producer path touched, no schema/template/contract change.
- **Effort**: one skill folder (`SKILL.md` + runtime), a small deterministic
  reconciler/renderer in `scripts/` (yaml→plan, no LLM for the artifact), tests for it,
  a permissions entry.
