#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>
#
# Tests for render-appcast-notes.sh. Runs in CI on every PR; the real
# caller, release.yml's publish job, only fires on `v*.*.*` tags, which
# is how a backslash in the v1.4.2 notes got as far as the publish step
# before anything noticed (#447).
#
# Every rendered fragment is wrapped in the same <rss> envelope
# release.yml assembles, checked with xmllint, and its <description>
# text compared byte-for-byte with the HTML that went in.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER_TEST="$SCRIPT_DIR/render-appcast-notes.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if ! command -v xmllint >/dev/null 2>&1; then
    echo "xmllint is required (apt install libxml2-utils)" >&2
    exit 2
fi

failures=0
checked=0

pass() {
    echo "  ok   — $1"
}
flunk() {
    echo "  FAIL — $1"
    failures=$((failures + 1))
}

# assert_eq <label> <expected> <actual>
assert_eq() {
    checked=$((checked + 1))
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        flunk "$1"
        echo "         expected: $(printf '%q' "$2")"
        echo "         actual:   $(printf '%q' "$3")"
    fi
}

# make_fragment <path> <os> — the shape release.yml's signing steps
# write, placeholder included.
make_fragment() {
    cat > "$1" <<EOF
<item>
  <title>9.9.9</title>
  <pubDate>Sun, 01 Nov 2026 00:00:00 +0000</pubDate>
  <sparkle:os>$2</sparkle:os>
  __NOTES_HTML_PLACEHOLDER__
  <enclosure url="https://example.invalid/QuMesh-9.9.9-$2"
             sparkle:version="9.9.9"
             sparkle:os="$2"
             type="application/octet-stream" />
</item>
EOF
}

# wrap <fragment> <out> — the appcast envelope from release.yml.
wrap() {
    {
        echo '<?xml version="1.0" encoding="utf-8"?>'
        echo '<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        echo '  <channel>'
        cat "$1"
        echo '  </channel>'
        echo '</rss>'
    } > "$2"
}

# check_roundtrip <label> <html-file> <fragment> — the fragment is
# well-formed inside the envelope and its description is exactly the
# HTML, framed by the newline after `<![CDATA[` and the indent before
# `]]>`.
check_roundtrip() {
    local label="$1" html="$2" fragment="$3" doc="$3.doc.xml"
    wrap "$fragment" "$doc"
    checked=$((checked + 1))
    if xmllint --noout "$doc" 2> "$doc.err"; then
        pass "$label: well-formed"
    else
        flunk "$label: well-formed"
        sed 's/^/         /' "$doc.err"
        return
    fi
    local got expected
    got=$(xmllint --xpath 'string(//item/description)' "$doc")
    expected=$'\n'"$(cat "$html")"$'\n  '
    assert_eq "$label: description round-trips byte-for-byte" "$expected" "$got"
}

echo "Usage:"
"$UNDER_TEST" > /dev/null 2>&1
assert_eq "no arguments is a usage error" 2 "$?"
"$UNDER_TEST" "$TMP/nope.html" "$TMP/frag.xml" > /dev/null 2>&1
assert_eq "a missing HTML file is a usage error" 2 "$?"

echo "Backslashes (#447 — the v1.4.2 notes):"
cat > "$TMP/backslash.html" <<'EOF'
<p>The installer put every Qt DLL in <code>QuMesh\bin\</code>, but
<code>QuMesh.exe</code> lives one level up in <code>QuMesh\</code>.</p>
<p>Escapes awk -v would rewrite: \n \t \\ \" \b \/ and C:\Program Files\QuMesh\</p>
EOF
make_fragment "$TMP/backslash.xml" windows
"$UNDER_TEST" "$TMP/backslash.html" "$TMP/backslash.xml"
assert_eq "exits 0" 0 "$?"
check_roundtrip "backslashes" "$TMP/backslash.html" "$TMP/backslash.xml"
checked=$((checked + 1))
if LC_ALL=C grep -q $'\b' "$TMP/backslash.xml"; then
    flunk "no backspace characters (the v1.4.2 failure)"
else
    pass "no backspace characters (the v1.4.2 failure)"
fi

echo "CDATA terminator in the notes:"
cat > "$TMP/cdata.html" <<'EOF'
<pre><code>if (a[b[0]]>1) return;</code></pre>
<p>Twice on one line: ]]> and ]]>, and one at the end ]]></p>
EOF
make_fragment "$TMP/cdata.xml" macos
"$UNDER_TEST" "$TMP/cdata.html" "$TMP/cdata.xml"
check_roundtrip "]]>" "$TMP/cdata.html" "$TMP/cdata.xml"

echo "Replacement-string specials:"
cat > "$TMP/specials.html" <<'EOF'
<p>R&amp;D &amp; more: 100% done, $1 and \1 and & stay literal.</p>
EOF
make_fragment "$TMP/specials.xml" macos
# A bare & isn't valid XML outside CDATA but is fine inside it.
"$UNDER_TEST" "$TMP/specials.html" "$TMP/specials.xml"
check_roundtrip "& % \$1 \\1" "$TMP/specials.html" "$TMP/specials.xml"

echo "Both fragments, one missing:"
cat > "$TMP/plain.html" <<'EOF'
<h1 id="qumesh-999">QuMesh 9.9.9</h1>
<p>Plain notes.</p>
EOF
make_fragment "$TMP/item-macos.xml" macos
make_fragment "$TMP/item-windows.xml" windows
cp "$TMP/item-macos.xml" "$TMP/macos.before"
"$UNDER_TEST" "$TMP/plain.html" "$TMP/item-macos.xml" "$TMP/item-windows.xml" "$TMP/item-absent.xml"
assert_eq "a missing fragment is skipped, not an error" 0 "$?"
check_roundtrip "macos fragment" "$TMP/plain.html" "$TMP/item-macos.xml"
check_roundtrip "windows fragment" "$TMP/plain.html" "$TMP/item-windows.xml"
checked=$((checked + 1))
if [ -e "$TMP/item-absent.xml" ]; then
    flunk "the missing fragment isn't created"
else
    pass "the missing fragment isn't created"
fi
# Every line but the placeholder survives untouched, in order.
assert_eq "lines around the placeholder are unchanged" \
    "$(grep -v __NOTES_HTML_PLACEHOLDER__ "$TMP/macos.before")" \
    "$(awk '/<description>/{skip=1} !skip{print} /<\/description>/{skip=0}' "$TMP/item-macos.xml")"

echo
echo "$checked checks, $failures failed"
[ "$failures" -eq 0 ]
