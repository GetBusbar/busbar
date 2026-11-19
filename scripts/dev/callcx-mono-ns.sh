#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Add `mono_ns: 0` to every `CallCx { .. }` literal that does not state the field.
#
# `busbar_ports::CallCx` gained `mono_ns` (the operation's one monotonic clock reading, handed to the
# plugin with the call). 0 means "no reading was made; a plugin that needs the time asks the host once",
# so 0 is correct at every site; a site that has a reading in scope can be given it by hand afterwards.
#
# A literal is left alone when it already names `mono_ns` (as `mono_ns: x` or the shorthand `mono_ns,`)
# or takes its remaining fields from another value (`..base`). The struct's own definition, `impl`
# blocks, function signatures returning `CallCx`, patterns (`let CallCx { .. } =`, match arms) and
# comment lines are not literals and are not touched.
#
#   scripts/dev/callcx-mono-ns.sh            dry run: list every site (file:line) and the count
#   scripts/dev/callcx-mono-ns.sh --dry-run  the same
#   scripts/dev/callcx-mono-ns.sh --apply    edit the files in place, then run `cargo fmt`
#   scripts/dev/callcx-mono-ns.sh --check    exit 1 if any site is left (for CI or a merge checklist)
#
# Run it from anywhere inside the repository. It reads tracked and untracked (not ignored) `.rs` files.
# Running `--apply` twice changes nothing the second time.

set -euo pipefail

mode=dry
case "${1:-}" in
    "" | --dry-run) mode=dry ;;
    --apply) mode=apply ;;
    --check) mode=check ;;
    -h | --help)
        sed -n '5,22p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "callcx-mono-ns: unknown argument: $1 (use --dry-run, --apply or --check)" >&2
        exit 2
        ;;
esac

root=$(git rev-parse --show-toplevel)
cd "$root"

# One pass over one file. With apply=0 it prints `file:line` of every literal that lacks the field; with
# apply=1 it prints the whole file, edited, to stdout and the sites to /dev/stderr.
read -r -d '' PROGRAM <<'AWK' || true
function braces(text,    i, c, d) {
    d = 0
    for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (c == "{") d++
        else if (c == "}") d--
    }
    return d
}
function indent_of(text) {
    match(text, /^[ \t]*/)
    return substr(text, 1, RLENGTH)
}
function site(line) {
    if (apply) print FILENAME ":" line > "/dev/stderr"
    else print FILENAME ":" line
}
# A line that opens a literal: `CallCx {` that is not the definition, an impl, a signature, a pattern
# or a comment.
function opens(text,    t) {
    if (text !~ /CallCx[ \t]*\{/) return 0
    t = text
    sub(/^[ \t]+/, "", t)
    if (t ~ /^\/\//) return 0
    if (t ~ /^\*/) return 0
    if (text ~ /struct[ \t]+CallCx/) return 0
    if (text ~ /impl([ \t]|<)[^{]*CallCx[ \t]*\{/) return 0
    if (text ~ /->[ \t]*([A-Za-z_:]*::)?CallCx[ \t]*\{/) return 0
    if (text ~ /(let|if let|while let)[ \t]+([A-Za-z_:]*::)?CallCx[ \t]*\{/) return 0
    if (text ~ /CallCx[ \t]*\{[^}]*\}[ \t]*(=>|\|)/) return 0
    return 1
}
# The literal held in buf[1..n] (it started on line `first`) is complete: decide and print.
function finish(    i, has, rest, depth, last, pad, at, head, tail, body) {
    has = 0
    rest = 0
    if (n == 1) {
        # One line: `.. CallCx { a, b } ..`. Look only between the literal's own braces.
        at = match(buf[1], /CallCx[ \t]*\{/)
        head = substr(buf[1], 1, at + RLENGTH - 1)
        tail = substr(buf[1], at + RLENGTH)
        depth = 1
        body = ""
        for (i = 1; i <= length(tail); i++) {
            c = substr(tail, i, 1)
            if (c == "{") depth++
            else if (c == "}") {
                depth--
                if (depth == 0) break
            }
            body = body c
        }
        tail = substr(tail, i)
        if (body ~ /(^|[^A-Za-z0-9_])mono_ns[ \t]*(:|,|$)/) has = 1
        if (body ~ /(^|[ \t,])\.\.[^.=]/) rest = 1
        if (!has && !rest) {
            site(first)
            if (apply) {
                sub(/[ \t]+$/, "", body)
                sub(/,$/, "", body)
                if (body ~ /^[ \t]*$/) buf[1] = head " mono_ns: 0 " tail
                else buf[1] = head body ", mono_ns: 0 " tail
            }
        }
        if (apply) print buf[1]
        return
    }
    # Several lines: fields are the lines at depth 1, the closing brace starts the last line.
    depth = 0
    last = 0
    for (i = 1; i <= n; i++) {
        if (i > 1 && i < n && depth == 1) {
            if (buf[i] ~ /^[ \t]*mono_ns[ \t]*(:|,)/) has = 1
            if (buf[i] ~ /^[ \t]*\.\.[^.=]/) rest = 1
            if (buf[i] !~ /^[ \t]*$/ && buf[i] !~ /^[ \t]*\/\//) last = i
        }
        if (i == 1) {
            at = match(buf[1], /CallCx[ \t]*\{/)
            depth = 1 + braces(substr(buf[1], at + RLENGTH))
        } else {
            depth += braces(buf[i])
        }
    }
    if (!has && !rest) {
        site(first)
        if (apply) {
            if (last) {
                pad = indent_of(buf[last])
                # A field the formatter left without its comma gets one.
                if (buf[last] !~ /[,{(\[][ \t]*$/ && buf[last] !~ /^[ \t]*[\])}]/) buf[last] = buf[last] ","
            } else {
                pad = indent_of(buf[n]) "    "
            }
            for (i = 1; i < n; i++) print buf[i]
            print pad "mono_ns: 0,"
            print buf[n]
            return
        }
    }
    if (apply) for (i = 1; i <= n; i++) print buf[i]
}
{
    if (!open) {
        if (!opens($0)) {
            if (apply) print
            next
        }
        n = 1
        buf[1] = $0
        first = FNR
        at = match($0, /CallCx[ \t]*\{/)
        level = 1 + braces(substr($0, at + RLENGTH))
        if (level <= 0) finish()
        else open = 1
        next
    }
    n++
    buf[n] = $0
    level += braces($0)
    if (level <= 0) {
        open = 0
        finish()
    }
}
END {
    # A literal never closed (a file cut short): give its lines back untouched.
    if (open && apply) for (i = 1; i <= n; i++) print buf[i]
}
AWK

files=$(git ls-files --cached --others --exclude-standard -- '*.rs' | xargs grep -l 'CallCx' 2>/dev/null || true)

sites=0
changed=0
work=$(mktemp -d "${TMPDIR:-/tmp}/callcx-mono-ns.XXXXXX")
trap 'rm -rf "$work"' EXIT

for f in $files; do
    [ -f "$f" ] || continue
    if [ "$mode" = apply ]; then
        awk -v apply=1 "$PROGRAM" "$f" >"$work/out" 2>"$work/sites"
        here=$(wc -l <"$work/sites" | tr -d ' ')
        if [ "$here" -gt 0 ]; then
            cat "$work/sites"
            cat "$work/out" >"$f"
            changed=$((changed + 1))
        fi
    else
        awk -v apply=0 "$PROGRAM" "$f" >"$work/sites"
        here=$(wc -l <"$work/sites" | tr -d ' ')
        cat "$work/sites"
    fi
    sites=$((sites + here))
done

case "$mode" in
    dry)
        echo "callcx-mono-ns: $sites CallCx literal(s) lack mono_ns (dry run; --apply to edit)"
        ;;
    check)
        echo "callcx-mono-ns: $sites CallCx literal(s) lack mono_ns"
        [ "$sites" -eq 0 ] || exit 1
        ;;
    apply)
        echo "callcx-mono-ns: gave mono_ns: 0 to $sites literal(s) in $changed file(s)"
        if [ "$sites" -gt 0 ]; then
            cargo fmt --all
        fi
        ;;
esac
