#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>
#
# Verify an installed QuMesh tree on Windows actually starts.
#
# Usage: verify-windows-install.sh [--no-launch] <install-dir>
#
# <install-dir> is what the user ends up with in %ProgramFiles%\QuMesh\:
# a `cmake --install` prefix (ci.yml) or the target of a silent NSIS
# install (release.yml).
#
# Exists because of #445: every Windows release up to v1.4.1 installed
# the Qt DLLs into `QuMesh\bin\` while QuMesh.exe sat one level up, so
# the app failed to start on every user machine. The release smoke
# launch never noticed because the runner had Qt's own bin\ on PATH and
# QT_PLUGIN_PATH / QML2_IMPORT_PATH pointed at the Qt install, so the
# loader found everything outside the bundle. The checks below look only
# at the install tree, and the launch scrubs PATH and the Qt env vars.
#
# Checks:
#   1. Layout — QuMesh.exe, qt.conf and the core Qt / OpenSSL / libssh
#      DLLs sit at the root; no DLLs or qt.conf under bin\; the Windows
#      platform plugin and the Qt Quick QML imports are deployed.
#   2. Imports — when `dumpbin` is on PATH (the MSVC dev env), every DLL
#      that QuMesh.exe or a bundled DLL/plugin imports must resolve to
#      the install root or %SYSTEMROOT%\System32. Skipped otherwise.
#   3. Launch — run QuMesh.exe with PATH cut down to the Windows system
#      directories and QUMESH_SMOKE_EXIT_MS set, and require a clean
#      exit. A missing DLL fails process creation; a missing QML import
#      makes main() exit -1. Skipped with --no-launch.
#
# Environment:
#   SYSTEMROOT              Windows directory (default C:\Windows)
#   QUMESH_SMOKE_EXIT_MS    passed through to the launch (default 3000)
#   VERIFY_LAUNCH_TIMEOUT   seconds before the launch is killed (default 60)
set -uo pipefail

launch=true
if [ "${1:-}" = "--no-launch" ]; then
    launch=false
    shift
fi
if [ $# -ne 1 ]; then
    echo "usage: $0 [--no-launch] <install-dir>" >&2
    exit 2
fi
root="${1%/}"
if [ ! -d "$root" ]; then
    echo "error: install dir '$root' does not exist" >&2
    exit 2
fi

failures=0
fail() {
    echo "  FAIL — $1"
    failures=$((failures + 1))
}
ok() {
    echo "  ok   — $1"
}

# to_posix <path> — Windows-form env values (C:\Windows) into something
# bash can stat. cygpath only exists under git-bash/MSYS; elsewhere
# (the Linux self-test) paths are already POSIX.
to_posix() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -u "$1"
    else
        printf '%s\n' "$1"
    fi
}

sysroot="$(to_posix "${SYSTEMROOT:-C:\\Windows}")"
system32="$sysroot/System32"

# has_file <dir> <name> — case-insensitive, since Windows is and DLL
# names in import tables don't match on-disk casing (KERNEL32.dll vs
# kernel32.dll). Avoids relying on the host filesystem folding case.
has_file() {
    [ -d "$1" ] || return 1
    find "$1" -maxdepth 1 -type f -iname "$2" -print -quit | grep -q .
}

echo "Verifying Windows install at $root"

# --- 1. Layout --------------------------------------------------------

echo "Layout:"
if has_file "$root" QuMesh.exe; then
    ok "QuMesh.exe at the install root"
else
    fail "QuMesh.exe missing from the install root"
fi
for name in qt.conf \
            Qt6Core.dll Qt6Gui.dll Qt6Network.dll Qt6Qml.dll \
            Qt6Quick.dll Qt6QuickControls2.dll Qt6Svg.dll \
            'libcrypto-*.dll' 'libssl-*.dll' ssh.dll; do
    if has_file "$root" "$name"; then
        ok "$name beside QuMesh.exe"
    else
        fail "$name missing from the install root (must sit beside QuMesh.exe)"
    fi
done

if [ -d "$root/bin" ]; then
    stray=$(find "$root/bin" -maxdepth 1 -type f \( -iname '*.dll' -o -iname 'qt.conf' \) | sort)
    if [ -n "$stray" ]; then
        fail "bin/ holds runtime files the loader will never search (#445):"
        while IFS= read -r f; do
            echo "         ${f#"$root"/}"
        done <<< "$stray"
    else
        ok "bin/ exists but holds no DLLs or qt.conf"
    fi
else
    ok "no bin/ subdirectory"
fi

if has_file "$root/plugins/platforms" qwindows.dll; then
    ok "plugins/platforms/qwindows.dll"
else
    fail "plugins/platforms/qwindows.dll missing — Qt can't create a window"
fi

if [ -d "$root/qml/QtQuick/Controls" ]; then
    ok "qml/QtQuick/Controls"
else
    fail "qml/QtQuick/Controls missing — Main.qml's imports won't resolve"
fi

# --- 2. Imports -------------------------------------------------------

# list_imports <file> — DLL names from the file's import table. Only the
# "has the following dependencies" block: delay-load imports are
# resolved lazily and may legitimately name DLLs absent on a given
# Windows build. dumpbin writes CRLF; strip the CR in awk rather than
# rely on the MSYS runtime's text-mode translation, or no name would
# match the `\.dll$` anchor and the walk would pass without checking.
list_imports() {
    dumpbin -nologo -dependents "$1" | awk '
        { sub(/\r$/, "") }
        /has the following dependencies/       { in_deps = 1; next }
        /has the following delay load/         { in_deps = 0 }
        /^[[:space:]]*Summary/                 { in_deps = 0 }
        in_deps && tolower($1) ~ /\.dll$/      { print $1 }
    '
}

echo "Imports:"
if command -v dumpbin >/dev/null 2>&1; then
    binaries=$(find "$root" -type f \( -iname '*.exe' -o -iname '*.dll' \) | sort)
    unresolved=0
    # Every Qt app imports at least Qt6Core.dll and KERNEL32.dll. An
    # empty list means the dumpbin output didn't parse, not that the
    # exe is self-contained — fail loudly instead of passing vacuously.
    if [ -z "$(list_imports "$root/QuMesh.exe")" ]; then
        fail "dumpbin listed no imports for QuMesh.exe — output format not recognised"
        unresolved=1
    fi
    while IFS= read -r bin; do
        [ -n "$bin" ] || continue
        rel="${bin#"$root"/}"
        while IFS= read -r dep; do
            [ -n "$dep" ] || continue
            # API sets are virtual; the loader maps them to real DLLs.
            case "$(printf '%s' "$dep" | tr '[:upper:]' '[:lower:]')" in
                api-ms-*|ext-ms-*) continue ;;
            esac
            if has_file "$root" "$dep" || has_file "$system32" "$dep"; then
                continue
            fi
            fail "$rel imports $dep, which is neither beside QuMesh.exe nor in System32"
            unresolved=$((unresolved + 1))
        done < <(list_imports "$bin")
    done <<< "$binaries"
    if [ "$unresolved" -eq 0 ]; then
        ok "every import of $(printf '%s\n' "$binaries" | grep -c .) binaries resolves"
    fi
else
    echo "  skip — dumpbin not on PATH"
fi

# --- 3. Launch --------------------------------------------------------

echo "Launch:"
if [ "$launch" = true ]; then
    exe="$root/QuMesh.exe"
    # Drop every Qt / QML path override the build env exported (e.g.
    # install-qt-action's QT_PLUGIN_PATH and QML2_IMPORT_PATH) so the
    # app has to find plugins and imports through its own qt.conf.
    unset_args=()
    while IFS= read -r var; do
        unset_args+=(-u "$var")
    done < <(compgen -e | grep -E '^(QT_|QML|Qt[0-9])')
    clean_path="$system32:$sysroot:$system32/Wbem"
    echo "  launching $exe with PATH=$clean_path"
    env "${unset_args[@]}" \
        PATH="$clean_path" \
        QT_FORCE_STDERR_LOGGING=1 \
        QUMESH_SMOKE_EXIT_MS="${QUMESH_SMOKE_EXIT_MS:-3000}" \
        "$exe" &
    app_pid=$!
    ( sleep "${VERIFY_LAUNCH_TIMEOUT:-60}" && kill -9 "$app_pid" 2>/dev/null ) &
    guard_pid=$!
    wait "$app_pid"
    rc=$?
    kill -9 "$guard_pid" 2>/dev/null
    wait "$guard_pid" 2>/dev/null
    if [ "$rc" -eq 0 ]; then
        ok "QuMesh.exe started and exited cleanly"
    else
        # The MSYS runtime reports STATUS_DLL_NOT_FOUND (0xC0000135)
        # as 127, or as its low byte (53) on older runtimes.
        fail "QuMesh.exe exited $rc (127/53 = a DLL failed to load, 255 = QML load failed, 137 = killed after ${VERIFY_LAUNCH_TIMEOUT:-60}s)"
    fi
else
    echo "  skip — --no-launch"
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
