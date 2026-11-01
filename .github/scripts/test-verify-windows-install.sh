#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>
#
# Tests for verify-windows-install.sh. Runs on Linux in CI on every PR
# against fake install trees, with a stub `dumpbin` standing in for the
# MSVC one. The launch half needs a real Windows install and is covered
# by the Windows CI job instead, so every case here uses --no-launch.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER_TEST="$SCRIPT_DIR/verify-windows-install.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

failures=0
checked=0

# assert_exit <label> <expected-rc> <actual-rc>
assert_exit() {
    checked=$((checked + 1))
    if [ "$2" -eq "$3" ]; then
        echo "  ok   — $1"
    else
        echo "  FAIL — $1"
        echo "         expected exit $2, got $3"
        failures=$((failures + 1))
    fi
}

# assert_contains <label> <haystack-file> <needle>
assert_contains() {
    checked=$((checked + 1))
    if grep -qF -- "$3" "$2"; then
        echo "  ok   — $1"
    else
        echo "  FAIL — $1"
        echo "         expected to find: $3"
        failures=$((failures + 1))
    fi
}

# assert_absent <label> <haystack-file> <needle>
assert_absent() {
    checked=$((checked + 1))
    if grep -qF -- "$3" "$2"; then
        echo "  FAIL — $1"
        echo "         expected NOT to find: $3"
        failures=$((failures + 1))
    else
        echo "  ok   — $1"
    fi
}

# Stub dumpbin: prints the import table recorded in
# $FAKE_DEPS_DIR/<basename>.deps, in dumpbin's own layout and with its
# CRLF line endings. A file with no .deps entry imports nothing.
STUB_BIN="$TMP/stub-bin"
mkdir -p "$STUB_BIN"
cat > "$STUB_BIN/dumpbin" <<'EOF'
#!/usr/bin/env bash
file="${!#}"
{
echo
echo "Dump of file $file"
echo
echo "File Type: DLL"
echo
deps="$FAKE_DEPS_DIR/$(basename "$file").deps"
if [ -f "$deps" ]; then
    echo "  Image has the following dependencies:"
    echo
    grep -v '^delay:' "$deps" | sed 's/^/    /'
    echo
    if grep -q '^delay:' "$deps"; then
        echo "  Image has the following delay load dependencies:"
        echo
        grep '^delay:' "$deps" | sed 's/^delay:/    /'
        echo
    fi
fi
echo "  Summary"
echo
echo "        1000 .text"
} | sed 's/$/\r/'
EOF
chmod +x "$STUB_BIN/dumpbin"

# A fake %SYSTEMROOT% whose System32 uses on-disk casing that differs
# from the import tables, as on real Windows.
SYSROOT="$TMP/Windows"
mkdir -p "$SYSROOT/System32"
touch "$SYSROOT/System32/kernel32.dll" "$SYSROOT/System32/user32.dll"

# make_good_tree <dir> — the flat layout the #445 fix produces.
make_good_tree() {
    local d="$1"
    mkdir -p "$d/plugins/platforms" "$d/qml/QtQuick/Controls"
    touch "$d/QuMesh.exe" "$d/qt.conf" \
          "$d/Qt6Core.dll" "$d/Qt6Gui.dll" "$d/Qt6Network.dll" "$d/Qt6Qml.dll" \
          "$d/Qt6Quick.dll" "$d/Qt6QuickControls2.dll" "$d/Qt6Svg.dll" \
          "$d/libcrypto-3-x64.dll" "$d/libssl-3-x64.dll" "$d/ssh.dll" \
          "$d/WinSparkle.dll" "$d/plugins/platforms/qwindows.dll"
}

# run_verify <name> [args...] — runs the script with the stub toolchain
# visible or not (STUB=1), capturing output to $TMP/<name>.out and the
# exit code to $rc.
run_verify() {
    local name="$1"
    shift
    local path="$PATH"
    if [ "${STUB:-0}" = 1 ]; then
        path="$STUB_BIN:$PATH"
    fi
    PATH="$path" SYSTEMROOT="$SYSROOT" FAKE_DEPS_DIR="$DEPS" \
        "$UNDER_TEST" "$@" > "$TMP/$name.out" 2>&1
    rc=$?
}

DEPS="$TMP/deps"
mkdir -p "$DEPS"

echo "Usage:"
run_verify no-args
assert_exit "no install dir is a usage error" 2 "$rc"
run_verify missing-dir --no-launch "$TMP/does-not-exist"
assert_exit "a missing install dir is a usage error" 2 "$rc"

echo "Flat layout (the fix):"
make_good_tree "$TMP/good"
run_verify good --no-launch "$TMP/good"
assert_exit "passes" 0 "$rc"
assert_contains "reports no bin/ subdirectory" "$TMP/good.out" "no bin/ subdirectory"
assert_contains "skips the import check without dumpbin" "$TMP/good.out" "dumpbin not on PATH"
assert_contains "skips the launch under --no-launch" "$TMP/good.out" "skip — --no-launch"

echo "v1.4.1 layout (#445 — Qt DLLs and qt.conf under bin/):"
mkdir -p "$TMP/v141/bin" "$TMP/v141/plugins/platforms" "$TMP/v141/qml/QtQuick/Controls"
touch "$TMP/v141/QuMesh.exe" \
      "$TMP/v141/libcrypto-3-x64.dll" "$TMP/v141/libssl-3-x64.dll" "$TMP/v141/ssh.dll" \
      "$TMP/v141/WinSparkle.dll" "$TMP/v141/plugins/platforms/qwindows.dll" \
      "$TMP/v141/bin/qt.conf" \
      "$TMP/v141/bin/Qt6Core.dll" "$TMP/v141/bin/Qt6Gui.dll" "$TMP/v141/bin/Qt6Network.dll" \
      "$TMP/v141/bin/Qt6Qml.dll" "$TMP/v141/bin/Qt6Quick.dll" \
      "$TMP/v141/bin/Qt6QuickControls2.dll" "$TMP/v141/bin/Qt6Svg.dll"
run_verify v141 --no-launch "$TMP/v141"
assert_exit "fails" 1 "$rc"
assert_contains "names the DLL from the bug report" "$TMP/v141.out" \
    "Qt6QuickControls2.dll missing from the install root"
assert_contains "flags qt.conf missing beside the exe" "$TMP/v141.out" \
    "qt.conf missing from the install root"
assert_contains "flags the stray bin/ directory" "$TMP/v141.out" \
    "bin/ holds runtime files the loader will never search"
assert_contains "lists the stray DLLs" "$TMP/v141.out" "bin/Qt6Core.dll"
assert_absent "doesn't flag OpenSSL, which was already at the root" "$TMP/v141.out" \
    "libcrypto-*.dll missing"

echo "Empty bin/ is fine:"
make_good_tree "$TMP/emptybin"
mkdir -p "$TMP/emptybin/bin"
run_verify emptybin --no-launch "$TMP/emptybin"
assert_exit "passes" 0 "$rc"
assert_contains "notes bin/ is harmless" "$TMP/emptybin.out" "holds no DLLs or qt.conf"

echo "Missing deploy pieces:"
make_good_tree "$TMP/noplugin"
rm "$TMP/noplugin/plugins/platforms/qwindows.dll"
rm -r "$TMP/noplugin/qml/QtQuick/Controls"
run_verify noplugin --no-launch "$TMP/noplugin"
assert_exit "fails" 1 "$rc"
assert_contains "flags the platform plugin" "$TMP/noplugin.out" "qwindows.dll missing"
assert_contains "flags the QML imports" "$TMP/noplugin.out" "qml/QtQuick/Controls missing"

echo "Imports resolve (stub dumpbin):"
make_good_tree "$TMP/imports-ok"
printf '%s\n' Qt6Core.dll Qt6QuickControls2.dll WinSparkle.dll KERNEL32.dll \
    api-ms-win-crt-runtime-l1-1-0.dll 'delay:dwmapi.dll' > "$DEPS/QuMesh.exe.deps"
printf '%s\n' Qt6Core.dll Qt6Gui.dll USER32.dll > "$DEPS/qwindows.dll.deps"
STUB=1 run_verify imports-ok --no-launch "$TMP/imports-ok"
assert_exit "passes" 0 "$rc"
assert_contains "reports every import resolved" "$TMP/imports-ok.out" "every import of"
assert_absent "doesn't chase delay-load imports" "$TMP/imports-ok.out" "dwmapi.dll"

echo "Imports that don't resolve (stub dumpbin):"
make_good_tree "$TMP/imports-bad"
rm "$TMP/imports-bad/WinSparkle.dll"
printf '%s\n' Qt6Core.dll WinSparkle.dll KERNEL32.dll > "$DEPS/QuMesh.exe.deps"
printf '%s\n' Qt6Core.dll MSVCP140_ATOMIC_WAIT.dll > "$DEPS/qwindows.dll.deps"
STUB=1 run_verify imports-bad --no-launch "$TMP/imports-bad"
assert_exit "fails" 1 "$rc"
assert_contains "names the exe's missing import" "$TMP/imports-bad.out" \
    "QuMesh.exe imports WinSparkle.dll"
assert_contains "checks plugins too, by install-relative path" "$TMP/imports-bad.out" \
    "plugins/platforms/qwindows.dll imports MSVCP140_ATOMIC_WAIT.dll"
assert_absent "resolves System32 imports case-insensitively" "$TMP/imports-bad.out" \
    "imports KERNEL32.dll"

echo "Unparseable dumpbin output (stub dumpbin, no imports for QuMesh.exe):"
make_good_tree "$TMP/imports-none"
rm -f "$DEPS"/*.deps
STUB=1 run_verify imports-none --no-launch "$TMP/imports-none"
assert_exit "fails" 1 "$rc"
assert_contains "says the output didn't parse" "$TMP/imports-none.out" \
    "dumpbin listed no imports for QuMesh.exe"
assert_absent "doesn't claim every import resolved" "$TMP/imports-none.out" \
    "every import of"

echo
echo "$checked checks, $failures failed"
[ "$failures" -eq 0 ]
