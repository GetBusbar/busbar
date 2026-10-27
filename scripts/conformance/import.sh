#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bring a repo's conformance verdicts into conformance/verdicts/ and re-render the manifest:
#
#     scripts/conformance/import.sh <owner/repo> [<from branch, default dev>] [<head sha>]
#
# Reads the `conformance` check's output (target/conformance/verdicts/*.json, written by the
# repo's testing/conformance/run.sh) from ModernCI (`modernci call artifact`), keeps only the verdicts
# stamped with that repo and head, copies them over conformance/verdicts/<id>.json, and runs
# `python3 scripts/conformance/sync.py --write`, which refuses any verdict that breaks the schema's
# rules. MODERNCI (default ~/.local/bin/modernci) and MODERNCI_TENANT (default busbar) name the client.
set -euo pipefail
repo="${1:?usage: import.sh <owner/repo> [from] [head]}"; from="${2:-dev}"; head="${3:-}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MCI="${MODERNCI:-$HOME/.local/bin/modernci}"; tenant="${MODERNCI_TENANT:-busbar}"
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
python3 -I - "$MCI" "$tenant" "$repo" "$from" "$head" "$t" <<'PY'
import base64, json, subprocess, sys, tarfile, io, os
mci, tenant, repo, frm, head, out = sys.argv[1:]
buf, offset, got_head = b"", 0, None
while True:
    # The latest kept outputs of the move (a measurement's included: `head` finds check results
    # only), then held to the head asked for below.
    req = {"repo": repo, "from": frm, "check": "conformance", "offset": offset}
    r = subprocess.run([mci, "call", "--tenant", tenant, "artifact", json.dumps(req)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"import: modernci artifact refused: {r.stderr.strip() or r.stdout.strip()}")
    d = json.loads(r.stdout)
    got_head = d["head"]
    buf += base64.b64decode(d["data"])
    if not d.get("next"):
        break
    offset = d["next"]
if head and got_head != head:
    sys.exit(f"import: ModernCI answered head {got_head}, not {head}")
n = 0
with tarfile.open(fileobj=io.BytesIO(buf), mode="r:gz") as tf:
    for m in tf.getmembers():
        parts = m.name.split("/")
        if not (m.isfile() and len(parts) >= 2 and parts[-2] == "verdicts" and m.name.endswith(".json")):
            continue
        v = json.load(tf.extractfile(m))
        if v.get("repo") != repo or v.get("commit") != got_head:
            sys.exit(f"import: {m.name} is stamped {v.get('repo')}@{v.get('commit')}, not {repo}@{got_head}")
        with open(os.path.join(out, parts[-1]), "w") as f:
            json.dump(v, f, indent=2, sort_keys=True); f.write("\n")
        n += 1
if n == 0:
    sys.exit(f"import: {repo}@{got_head} carries no conformance verdicts")
print(f"import: {n} verdict(s) from {repo}@{got_head}")
PY
cp "$t"/*.json "$root/conformance/verdicts/"
python3 -I "$root/scripts/conformance/sync.py" --write
git -C "$root" status --short -- conformance/
