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
python3 -I - "$MCI" "$tenant" "$repo" "$from" "$head" "$t" "$root/scripts/conformance" <<'PY'
import base64, hashlib, json, subprocess, sys, os
mci, tenant, repo, frm, head, out, helpers = sys.argv[1:]
sys.path.insert(0, helpers)
from invocation import validated_verdicts, Refused
buf, offset, got_head = b"", 0, None
artifact = None
while True:
    req = {"repo": repo, "from": frm, "check": "conformance", "offset": offset}
    if head:
        req["head"] = head
    r = subprocess.run([mci, "call", "--tenant", tenant, "artifact", json.dumps(req)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"import: modernci artifact refused: {r.stderr.strip() or r.stdout.strip()}")
    d = json.loads(r.stdout)
    got_head = d["head"]
    if head and got_head != head:
        sys.exit(f"import: ModernCI answered head {got_head}, not {head}")
    identity = (d.get("repo"), got_head, d.get("state"), d["sha"])
    if identity[0] != repo:
        sys.exit("import: ModernCI answered another repository")
    if not all(identity):
        sys.exit("import: ModernCI answered without an artifact head and sha")
    if artifact is None:
        artifact = identity
    elif identity != artifact:
        sys.exit(f"import: ModernCI changed artifact from {artifact} to {identity} between pages")
    # Keep the caller's selector: adding head would switch a measurement to a judged result.
    buf += base64.b64decode(d["data"])
    if not d.get("next"):
        break
    offset = d["next"]
if hashlib.sha256(buf).hexdigest() != artifact[3]:
    sys.exit("import: artifact bytes do not match the service hash")
try:
    verdicts = validated_verdicts(buf, repo=repo, head=got_head, state=artifact[2])
except Refused as error:
    sys.exit(f"import: {error}")
for sid, verdict in verdicts.items():
    with open(os.path.join(out, sid + ".json"), "w") as stream:
        json.dump(verdict, stream, indent=2, sort_keys=True)
        stream.write("\n")
n = len(verdicts)
print(f"import: {n} verdict(s) from {repo}@{got_head}")
PY
cp "$t"/*.json "$root/conformance/verdicts/"
python3 -I "$root/scripts/conformance/sync.py" --write
git -C "$root" status --short -- conformance/
