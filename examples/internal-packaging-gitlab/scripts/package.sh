#!/usr/bin/env bash
# package.sh — vendor upstream appsec-advisor, overlay the org profile,
# and patch plugin.json + config.json so the packaged copy is self-contained.
#
# Inputs:
#   INTERNAL_NAME   (env, default: acme-appsec)   plugin name + command namespace
#   VERSION         (env, default: dev)           value written to plugin.json
#
# Inputs on disk:
#   upstream/appsec-advisor/   vendored upstream source (cloned by the pipeline)
#   org-profile/               company overlay (this repository)
#
# Output:
#   build/${INTERNAL_NAME}/    packaged plugin tree, ready to validate + tar

set -euo pipefail

INTERNAL_NAME="${INTERNAL_NAME:-acme-appsec}"
VERSION="${VERSION:-dev}"
BUILD="build/${INTERNAL_NAME}"
export INTERNAL_NAME VERSION BUILD

echo "==> Packaging ${INTERNAL_NAME} ${VERSION}"

rm -rf "${BUILD}"
mkdir -p "${BUILD}"

# 1. Vendor upstream into the build tree.
rsync -a --delete upstream/appsec-advisor/ "${BUILD}/"

# 2. Overlay the company org profile (yaml + context + actors).
rsync -a --delete org-profile/ "${BUILD}/org-profile/"

# 3. Patch plugin.json — set the internal name + version so Claude Code
#    exposes commands under the new namespace.
python3 - <<PY
import json, os, pathlib
plugin_path = pathlib.Path("${BUILD}/.claude-plugin/plugin.json")
data = json.loads(plugin_path.read_text())
data["name"] = "${INTERNAL_NAME}"
data["version"] = "${VERSION}"
data["description"] = "Internal packaged build of appsec-advisor for ${INTERNAL_NAME}."
plugin_path.write_text(json.dumps(data, indent=2) + "\n")
PY

# 4. Patch config.json — enable the bundled org profile.
python3 - <<'PY'
import json, os, pathlib
config_path = pathlib.Path(os.environ["BUILD"] + "/config.json")
data = json.loads(config_path.read_text())
data["organization_profile"] = {
    "enabled": True,
    "path": "org-profile/org-profile.yaml",
}
config_path.write_text(json.dumps(data, indent=2) + "\n")
PY

# 5. Rewrite the upstream namespace inside docs and prompts so generated
#    commands (e.g. /acme-appsec:create-threat-model) match the new name.
#    Schema identifiers like 'appsec-advisor.org-profile/v2' must NOT be
#    rewritten — the sed pattern below only matches 'appsec-advisor:'.
find "${BUILD}" -type f \( -name "*.md" -o -name "*.txt" -o -name "SKILL.md" \) \
  -exec sed -i "s/appsec-advisor:/${INTERNAL_NAME}:/g" {} +

# Also rewrite namespaced agent IDs embedded in skill/agent YAML or JSON.
find "${BUILD}/skills" "${BUILD}/agents" -type f \( -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) \
  -exec sed -i "s/appsec-advisor:/${INTERNAL_NAME}:/g" {} + 2>/dev/null || true

echo "==> Build tree ready at ${BUILD}"
