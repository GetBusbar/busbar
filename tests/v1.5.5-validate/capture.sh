#!/usr/bin/env bash
# Re-capture the golden: run the PUBLISHED busbar 1.5.5 binary's `--validate` over each case in
# cases.txt and write what it refused with to refusals.txt.
#   usage: tests/v1.5.5-validate/capture.sh <path-to-busbar-1.5.5>
# Each case is one `export:` block (its lines joined with `\n`). The golden keeps, per case, the
# refusal's item lines (`  - …`) exactly as 1.5.5 printed them; 1.6.0 adds a `BUSBAR-NNNN:` code to
# the header line only (CHANGELOG, Improvements), so the header is not part of the golden.
set -euo pipefail
bin=$1
here=$(cd "$(dirname "$0")" && pwd)
"$bin" --version | grep -qx 'busbar 1.5.5' || { echo "not busbar 1.5.5: $bin" >&2; exit 2; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
: > "$tmp/providers.yaml"
{
  echo "# GOLDEN: the published busbar 1.5.5 binary's --validate refusals for the export instances in cases.txt."
  echo "# Captured by capture.sh; each case: \`=== <export block>\` then the refusal's item lines."
  while IFS= read -r case; do
    [ -z "$case" ] && continue
    printf 'listen: "127.0.0.1:0"\nproviders: {}\nmodels: {}\nexport:\n%b' "$case" > "$tmp/config.yaml"
    echo "=== $case"
    BUSBAR_CONFIG=$tmp/config.yaml BUSBAR_PROVIDERS=$tmp/providers.yaml "$bin" --validate 2>&1 \
      | grep '^  - ' || true
  done < "$here/cases.txt"
} > "$here/refusals.txt"
