# Full-Scan Recommendation Prompt (auto-incremental only)

> **Lazy-loaded mode file.** Read by `SKILL-impl.md` only when `MODE=incremental` and the
> mode was auto-detected (`INCREMENTAL_IS_AUTO=true`). Kept out of `SKILL-impl.md` so this
> branch never enters the resident full-run context — same just-in-time pattern as
> `modes/rerender.md` and the lazy-loaded `agents/phases/phase-group-*.md` files. The
> control-flow position is the Full-Scan-Recommendation anchor in `SKILL-impl.md` (after
> the fast-path + Plugin Version Compatibility Gate, before the Stage 1 Handoff Banner).

After the fast-path and the Plugin Version Compatibility Gate, and **before** the Stage 1 Handoff Banner, evaluate whether the user should be offered a chance to switch to a full scan. This prompt fires **only** when all of the following are true:

1. `INCREMENTAL_IS_AUTO=true` — mode was auto-detected, not explicitly requested via `--incremental`
2. At least one recommendation trigger is present (see table below)
3. `NO_CONFIRM=false` — `--no-confirm` / `--yes` was not passed
4. `APPSEC_CI_MODE` is not `1`
5. stdin is a TTY (`[ -t 0 ]`)

| Trigger | Variable | Condition |
|---------|----------|-----------|
| Analysis-version drifted | `COMPAT_LABEL` | `older-compatible` (baseline yaml's `analysis_version` is older but compatible with the current plugin) |
| Plugin-version drifted | `PLUGIN_TIER` | `minor` \| `major` (semver bump even if `analysis_version` did not move — the runtime prompts / heuristics may still be different) |
| Broad source delta | `SEC_CHANGE_COUNT` vs `MAX_STRIDE_COMPONENTS` | security-relevant file count is large relative to the operational component ceiling: `SEC_CHANGE_COUNT / MAX_STRIDE_COMPONENTS >= 0.8` (integer: `SEC_CHANGE_COUNT * 10 / MAX_STRIDE_COMPONENTS >= 8`) — a broad delta where a full scan gives better T-ID stability |
| Critical / attack-surface change | `CRITICAL_CHANGE_COUNT` | one or more changed files are high-blast-radius: **security primitives** (auth / crypto / session / validation / CORS / CSP) **or** **trust-boundary & I/O surface** (new/changed routes, endpoints, controllers, interfaces, GraphQL/gRPC/OpenAPI, serializers, schemas) **or** **architecture / data model** (middleware, gateways, adapters, ORM/entities, model files, migrations); `security_critical_change_count > 0` from the fast-path. The incremental dirty-set maps such a file to a single component and carries every other component forward — but a new route or a shared-code change expands or shifts the attack surface in ways a delta scope never re-models. Fires **regardless of count** (a single such file is enough). |

```bash
# Only evaluate when mode was auto-detected incremental.
if [ "$MODE" = "incremental" ] && [ "$INCREMENTAL_IS_AUTO" = "true" ] \
    && [ "$NO_CONFIRM" = "false" ] \
    && [ "${APPSEC_CI_MODE:-}" != "1" ] \
    && [ -t 0 ]; then

  # Collect trigger reasons.
  PROMPT_REASONS=""
  BASELINE_PLUGIN=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("plugin_version",{}).get("baseline","?"))' 2>/dev/null || echo '?')
  CURRENT_PLUGIN=$(echo  "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("plugin_version",{}).get("current","?"))' 2>/dev/null || echo '?')
  PLUGIN_TIER=$(echo     "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("plugin_version",{}).get("tier","?"))' 2>/dev/null || echo '?')

  if [ "$COMPAT_LABEL" = "older-compatible" ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • Analysis schema drifted (baseline analysis_version is older but compatible) — full rebuild ensures new categories / CWE remappings apply to ALL findings, not just newly-scanned code\n"
  elif [ "$PLUGIN_TIER" = "major" ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • Plugin upgraded ${BASELINE_PLUGIN} → ${CURRENT_PLUGIN} (MAJOR) — STRIDE prompts / heuristics likely changed; carried-forward threats use the old reasoning\n"
  elif [ "$PLUGIN_TIER" = "minor" ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • Plugin upgraded ${BASELINE_PLUGIN} → ${CURRENT_PLUGIN} (minor) — analysis improvements ship in minors and only apply to newly-scanned code in incremental mode\n"
  fi

  SEC_CHANGE_COUNT=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("security_relevant_change_count",0))' 2>/dev/null || echo 0)
  # Integer arithmetic: count*10/max >= 8  ⟺  count/max >= 0.8
  if [ "$(( SEC_CHANGE_COUNT * 10 / MAX_STRIDE_COMPONENTS ))" -ge 8 ] && [ "$SEC_CHANGE_COUNT" -gt 0 ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • ${SEC_CHANGE_COUNT} security-relevant files changed (broad delta vs the ${MAX_STRIDE_COMPONENTS}-component operational ceiling) — full scan gives better T-ID stability at similar cost\n"
  fi

  # Critical / attack-surface change — fires on a SINGLE file. Security
  # primitives (auth/crypto/session/validation) OR trust-boundary & I/O surface
  # (new/changed routes, endpoints, interfaces, schemas) OR architecture/data
  # model (middleware, gateway, adapter, ORM, model, migration). A delta scope
  # re-examines just the one component the file's path-glob matched.
  CRITICAL_CHANGE_COUNT=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("security_critical_change_count",0))' 2>/dev/null || echo 0)
  CRITICAL_SAMPLE=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(", ".join(d.get("security_critical_changes",[])[:3]))' 2>/dev/null || echo '')
  if [ "$CRITICAL_CHANGE_COUNT" -gt 0 ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • ${CRITICAL_CHANGE_COUNT} critical / attack-surface file(s) changed (${CRITICAL_SAMPLE}) — security primitive, route/interface, or architecture/model change with system-wide blast radius; incremental only re-scans the one matching component and carries dependents forward\n"
  fi

  if [ -n "$PROMPT_REASONS" ]; then
    printf "\n⚠ Incremental run not recommended:\n"
    printf "%b" "$PROMPT_REASONS"
    printf "\n  [I] Continue incremental   [F] Switch to full scan   [A] Abort\n"
    printf "  Choice (default: F in 30s): "

    # Read with timeout; default to 'f' on timeout or empty input.
    CONFIRM_TIMEOUT="${APPSEC_CONFIRM_TIMEOUT:-30}"
    if read -r -t "$CONFIRM_TIMEOUT" CONFIRM_CHOICE 2>/dev/null; then
      CONFIRM_CHOICE=$(echo "$CONFIRM_CHOICE" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
    else
      CONFIRM_CHOICE="f"
      printf "\n  (timed out — defaulting to full scan)\n"
    fi

    case "$CONFIRM_CHOICE" in
      i|incremental)
        echo "  Continuing with incremental run."
        ;;
      a|abort)
        echo "  Aborted."
        rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
        exit 0
        ;;
      *)
        # 'f', empty, or anything else → switch to full.
        echo "  Switching to full scan."
        MODE="full"
        INCREMENTAL="false"
        MODE_UPGRADED_BY_PROMPT=true
        # Carry the trigger that justified the upgrade into the re-rendered
        # Pre-flight Reason line (§"Full scan over an existing model"). Collapse
        # the first PROMPT_REASONS bullet to a one-liner; fall back to a generic
        # phrase. The post-upgrade summary surfaces this so a full scan over an
        # existing model is never unexplained.
        MODE_UPGRADED_REASON=$(printf '%b' "$PROMPT_REASONS" | sed -n 's/^[[:space:]]*•[[:space:]]*//p' | head -1)
        [ -z "$MODE_UPGRADED_REASON" ] && MODE_UPGRADED_REASON="auto-incremental upgraded to full at user request"
        MODE_UPGRADED_REASON="existing model present; switched to full — ${MODE_UPGRADED_REASON}"
        ;;
    esac
  fi
fi

# Non-interactive backstop for the critical / attack-surface trigger. The
# prompt above is interactive-only (CI / --no-confirm / non-TTY all skip it),
# but a security-primitive, route/interface, or architecture/model change is a
# CORRECTNESS concern, not a preference — so even when we cannot prompt we
# still (a) print a visible advisory and (b) set
# RECOMMEND_FULL=true so Phase 11 renders the "consider --full" callout in the
# report and sets meta.recommend_full_rerun. We do NOT silently force a full
# scan in CI: that could 10× an automated run's cost/time on a 1-line change.
if [ "$MODE" = "incremental" ] && [ "$INCREMENTAL_IS_AUTO" = "true" ] \
    && { [ "$NO_CONFIRM" = "true" ] || [ "${APPSEC_CI_MODE:-}" = "1" ] || [ ! -t 0 ]; }; then
  CRITICAL_CHANGE_COUNT=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("security_critical_change_count",0))' 2>/dev/null || echo 0)
  if [ "$CRITICAL_CHANGE_COUNT" -gt 0 ]; then
    CRITICAL_SAMPLE=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(", ".join(d.get("security_critical_changes",[])[:3]))' 2>/dev/null || echo '')
    printf '\n⚠ %s critical / attack-surface file(s) changed (%s) — security primitive, route/interface, or architecture/model change; incremental re-scans only the matching component and carries dependents forward.\n  Consider re-running with --full. (Set meta.recommend_full_rerun in this run.)\n' "$CRITICAL_CHANGE_COUNT" "$CRITICAL_SAMPLE" >&2
    RECOMMEND_FULL=true
  fi
fi
```

**When the user chooses full:** override `MODE=full` and `INCREMENTAL=false` in shell scope, then continue with the Stage 1 Handoff Banner as normal. The orchestrator receives `INCREMENTAL=false` and runs a complete assessment.
