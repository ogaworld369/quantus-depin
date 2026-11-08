#!/usr/bin/env bash
# Plain-JVM harness + Python cross-implementation check for the
# DePIN companion app. No JUnit in the VM (same approach as the
# sibling bench app).
#
#   tests/run-tests.sh           harness only
#   tests/run-tests.sh --cross   harness + crosscheck.py
set -euo pipefail
# JDK: prefer $JAVA_HOME; otherwise derive it from the java on PATH.
if [ -z "${JAVA_HOME:-}" ]; then
  _java_bin="$(command -v java || true)"
  if [ -n "$_java_bin" ]; then
    JAVA_HOME="$(dirname "$(dirname "$_java_bin")")"
  else
    echo "error: JAVA_HOME is not set and no java was found on PATH" >&2
    exit 1
  fi
fi
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
CORE_DIR="$PROJ"
OUT="${TMPDIR:-/tmp}/depin-companion-tests-$$"
mkdir -p "$OUT"

# Device-independent classes only: the Android-bound classes
# (MainActivity / ObservationService / AndroidSeedVault) are compiled
# by the APK build against android.jar instead.
"$JAVA_HOME/bin/javac" -d "$OUT" \
  "$CORE_DIR/Hex.java" \
  "$CORE_DIR/Json.java" \
  "$CORE_DIR/Ed25519.java" \
  "$CORE_DIR/DepinCore.java" \
  "$CORE_DIR/RpcClient.java" \
  "$CORE_DIR/SeedVault.java" \
  "$CORE_DIR/JournalStore.java" \
  "$CORE_DIR/CompanionStatus.java" \
  "$CORE_DIR/PendingExport.java" \
  "$CORE_DIR/CrashLog.java" \
  "$PROJ/tests/app/quantusnode/depin/HarnessMain.java" \
  "$PROJ/tests/app/quantusnode/depin/BundleGenMain.java" \
  "$PROJ/tests/app/quantusnode/depin/BundleVerifyMain.java"

"$JAVA_HOME/bin/java" -cp "$OUT" app.quantusnode.depin.HarnessMain

if [ "${1:-}" = "--cross" ]; then
  DEPIN_COMPANION_TEST_CP="$OUT" python3 "$PROJ/tests/crosscheck.py"
fi

rm -rf "$OUT"
