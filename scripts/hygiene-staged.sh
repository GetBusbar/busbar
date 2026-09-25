#!/usr/bin/env bash
# PUBLIC-HYGIENE, ON THE FILES ABOUT TO BE COMMITTED — a pre-commit check a contributor runs by hand.
#
# `scripts/public-hygiene-lint.py` is the CI gate: it scans every tracked public file, so a single
# comment that describes how the code was made instead of what it does reds the whole push.
# This wrapper runs THE SAME rules — it imports the lint and calls its own file filter and scanner,
# it has no rules of its own — over only the paths it is given, so the check is seconds and happens
# before the commit rather than after the push.
#
# Usage: scripts/hygiene-staged.sh <path>...
#        scripts/hygiene-staged.sh --cached     (the files staged in the index)
#
# A path the lint does not treat as public (docs/design/**, lockfiles, binaries …) is skipped, as the
# gate skips it. Exit 0 = no hits, 1 = hits (printed exactly as the gate prints them), 2 = usage
# error. The gate still decides; this only tells you sooner.
set -euo pipefail

usage() { sed -n '10,11p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

root="$(git rev-parse --show-toplevel)"
[ "$#" -gt 0 ] || usage

paths=()
if [ "$1" = "--cached" ]; then
  [ "$#" -eq 1 ] || usage
  while IFS= read -r -d '' p; do paths+=("$p"); done \
    < <(git -C "$root" diff --cached --name-only --diff-filter=ACMR -z)
  if [ "${#paths[@]}" -eq 0 ]; then
    echo "hygiene-staged: nothing staged" >&2
    exit 0
  fi
else
  for p in "$@"; do
    case "$p" in -*) usage ;; esac
    paths+=("$p")
  done
fi

exec python3 - "$root" "${paths[@]}" <<'PY'
import importlib.util, os, sys

root, args = sys.argv[1], sys.argv[2:]
spec = importlib.util.spec_from_file_location(
    "public_hygiene_lint", os.path.join(root, "scripts", "public-hygiene-lint.py"))
lint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)

cwd = os.getcwd()
scanned, hits, allowed, missing = [], [], [], []
for a in args:
    absp = os.path.abspath(os.path.join(cwd, a))
    rel = os.path.relpath(absp, root).replace(os.sep, "/")
    if rel.startswith("../"):
        print(f"hygiene-staged: {a} is outside {root}", file=sys.stderr)
        sys.exit(2)
    if not os.path.isfile(absp):
        missing.append(rel)
        continue
    if rel == lint.SELF or not lint.is_text_candidate(rel) or os.path.islink(absp):
        continue
    with open(absp, encoding="utf-8", errors="replace") as fh:
        h, al = lint.scan_text(rel, fh.read())
    scanned.append(rel)
    hits += h
    allowed += al

if missing:
    print("hygiene-staged: no such file: " + ", ".join(missing), file=sys.stderr)
    sys.exit(2)
lint.report(hits, allowed)
print(f"\n  hygiene-staged: {len(scanned)} public file(s) of {len(args)} given, "
      f"{len(lint.RULES)} rules — {len(hits)} hit(s), {len(allowed)} allowed")
if hits:
    print("  Rewrite each line to state the behaviour, not the process that produced it.")
    sys.exit(1)
PY
