#!/usr/bin/env bash
# Installs the Android SDK packages this project builds against.
#
# Why not `android-actions/setup-android`: that action runs `sdkmanager tools`,
# but the `tools` package was removed from the SDK repository, so the command
# exits 1 and the action aborts the whole job. The GitHub-hosted runner already
# ships a usable SDK, so we only add what is missing.
#
# The sdkmanager `--licenses` prompt is answered with `yes`; its exit status is
# tolerated because licences are usually already accepted on the runner image.
set -euo pipefail

if command -v sdkmanager >/dev/null 2>&1; then
  SDKMANAGER=sdkmanager
elif [ -n "${ANDROID_HOME:-}" ] && [ -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
  SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
else
  echo "error: sdkmanager not found (ANDROID_HOME=${ANDROID_HOME:-unset})" >&2
  exit 1
fi

echo "Using sdkmanager: $SDKMANAGER"
"$SDKMANAGER" --version || true

yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true

# compileSdk 34, and the build-tools version AGP 8.5.2 expects by default.
"$SDKMANAGER" --install "platforms;android-34" "build-tools;34.0.0" "platform-tools"

echo "Installed platforms:"
ls "$ANDROID_HOME/platforms" 2>/dev/null || true
