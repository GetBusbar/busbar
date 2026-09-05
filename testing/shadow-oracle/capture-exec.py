#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Assemble one captured oracle cell for an EXEC cell (CLI flag, --validate, --migrate-config, boot).

  capture-exec.py <exit-code> <stdout-file> <stderr-file> [--strip-path <p>]... > captured.json

Same shape as capture.py's output so normalize.py / diff-cells.py treat it like any other cell:
  status   = the process exit code
  headers  = {} (there is no wire)
  body     = stdout, with stderr under effects.stderr — both with volatile fragments replaced:
             absolute paths the harness chose (`--strip-path`), the binary's own version string,
             durations, and ANSI colour codes; each replacement is a NAMED normalizer rule so a
             change is reviewable.
A boot cell is captured after the process exits (a refusal) or after /healthz answers (a warning),
and the recorder passes the log tail as <stderr-file>.
"""
import json
import re
import sys

ANSI = re.compile(r"\x1b\[[0-9;]*m")
VERSION = re.compile(r"\bbusbar (\d+\.\d+\.\d+)(?:-[0-9A-Za-z.]+)?\b")
VERSION_KV = re.compile(r'version="(\d+\.\d+\.\d+)(?:-[0-9A-Za-z.]+)?"')
# A bare duration token (`120000 ms`) is ambiguous: it is exactly as likely to be a CONFIG VALUE
# quoted back in a warning ("on_exhausted.queue.max_ms (120001 ms) exceeds ...") as it is to be a
# measured elapsed time. Only scrub it when it follows a word that actually reports elapsed time —
# "took"/"after"/"elapsed"/"in " — so a changed default (e.g. a mutated attempt_timeout_ms) that shows
# up quoted in a message stays visible instead of being silently normalized away.
DURATION = re.compile(
    r"(?<=\btook )\d+(?:\.\d+)?\s?(?:ms|µs|us|ns|s)\b"
    r"|(?<=\bafter )\d+(?:\.\d+)?\s?(?:ms|µs|us|ns|s)\b"
    r"|(?<=\belapsed )\d+(?:\.\d+)?\s?(?:ms|µs|us|ns|s)\b"
    r"|(?<=\bin )\d+(?:\.\d+)?\s?(?:ms|µs|us|ns|s)\b"
)
TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
TMPDIR = re.compile(r"/(?:private/)?(?:tmp|var/folders)/[^\s'\"`:]+")


def scrub(text: str, strip_paths: list[str], applied: set) -> str:
    if ANSI.search(text):
        applied.add("exec.ansi"); text = ANSI.sub("", text)
    for p in sorted(strip_paths, key=len, reverse=True):
        if p and p in text:
            applied.add("exec.paths"); text = text.replace(p, "<WORK>")
    if TMPDIR.search(text):
        applied.add("exec.paths"); text = TMPDIR.sub("<TMP>", text)
    if VERSION.search(text):
        applied.add("ver.string"); text = VERSION.sub("busbar <VERSION>", text)
    if VERSION_KV.search(text):
        applied.add("ver.string"); text = VERSION_KV.sub('version="<VERSION>"', text)
    if TIMESTAMP.search(text):
        applied.add("ts.unix"); text = TIMESTAMP.sub("<TS>", text)
    if DURATION.search(text):
        applied.add("exec.duration"); text = DURATION.sub("<DUR>", text)
    return text


def main() -> int:
    args = sys.argv[1:]
    strip = []
    while "--strip-path" in args:
        i = args.index("--strip-path"); strip.append(args[i + 1]); del args[i:i + 2]
    code, out_f, err_f = args[0], args[1], args[2]
    applied: set = set()
    out = scrub(open(out_f, encoding="utf-8", errors="replace").read(), strip, applied)
    err = scrub(open(err_f, encoding="utf-8", errors="replace").read(), strip, applied)
    cap = {
        "status": int(code) if code.lstrip("-").isdigit() else -1,
        "headers": {},
        "body": out,
        "effects": {"stderr": err, "exec_rules": sorted(applied)},
    }
    print(json.dumps(cap, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
