#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>
#
# Splice rendered release-notes HTML into Sparkle appcast fragments.
#
# Usage: render-appcast-notes.sh <html-file> <fragment>...
#
# Each fragment is an <item> written by a per-OS signing step in
# release.yml, with a `__NOTES_HTML_PLACEHOLDER__` line where the
# description belongs. That line is replaced, in place, with a
# <description> carrying the HTML inside CDATA. Fragments that don't
# exist are skipped: the Windows one is only produced when the
# WinSparkle key is provisioned.
#
# Lives here rather than inline in release.yml so it can be tested.
# The inline version passed the HTML through `awk -v`, which processes
# escape sequences, so the `QuMesh\bin\` in the v1.4.2 notes became
# `QuMesh<backspace>in` and the publish step refused the malformed
# feed (#447). The HTML is read from a file instead, which awk never
# escape-processes. Any `]]>` in it is split across two CDATA sections,
# since a literal one would end the section early.
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: $0 <html-file> <fragment>..." >&2
    exit 2
fi
html_file="$1"
shift
if [ ! -f "$html_file" ]; then
    echo "error: HTML file '$html_file' does not exist" >&2
    exit 2
fi

for fragment in "$@"; do
    [ -f "$fragment" ] || continue
    # The path goes in through the environment too: `-v` would
    # escape-process it just like the HTML.
    HTML_FILE="$html_file" awk '
        /__NOTES_HTML_PLACEHOLDER__/ {
            html_file = ENVIRON["HTML_FILE"]
            print "  <description><![CDATA["
            while ((getline line < html_file) > 0) {
                gsub(/\]\]>/, "]]]]><![CDATA[>", line)
                print line
            }
            close(html_file)
            print "  ]]></description>"
            next
        }
        { print }
    ' "$fragment" > "$fragment.tmp"
    mv "$fragment.tmp" "$fragment"
done
