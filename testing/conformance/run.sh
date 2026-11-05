#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RENDERED by `busbar-release plugin heal` from GetBusbar/busbar-release template/conformance/run.sh;
# a hand edit is overwritten by the next sync.
#
# THE CONFORMANCE CHECK: every official suite this repo owns, run against busbar at the pin in
# `.busbar-ref` (busbar itself, which has no pin, judges its own HEAD), each judged into one busbar.conformance.verdict/1 file that busbar's
# conformance/verdicts/ imports. ModernCI runs it as the `conformance` check of every plugin repo
# (template/modernci/conformance.yaml):
#
#     bash testing/conformance/run.sh            # every suite in testing/conformance/suites.tsv
#     bash testing/conformance/run.sh --selftest # the verdict judge bites on planted verdicts
#
# THE SUITE LIST is this repo's own `testing/conformance/suites.tsv` (not templated): one suite per
# line, `<suite-id><TAB><command>`; `#` starts a comment. The id is busbar's registry id
# (conformance/registry.toml). An optional `# tools: rust node` declaration names only the
# instruments these suites need; supported names are rust and node. Without it, provisioning
# follows the checkout's Cargo/toolchain ownership and also provides Node. The command runs
# from the repo root with:
#
#     CONFORMANCE_SUITE  the suite id
#     CONFORMANCE_OUT    an empty directory; the command MUST write $CONFORMANCE_OUT/verdict.json
#     BUSBAR_CHECKOUT    busbar at the pin (a full checkout)
#     BUSBAR_PIN         the pin's sha
#     CARGO_TARGET_DIR   this repo's target/ (the subject builds there)
#
# and Node at testing/conformance/tools.sh's pin on PATH. Rust workspaces also receive the Rust
# toolchain declared by their own rust-toolchain[.toml]. Its verdict states `suite`, `status`
# (pass|fail|not-run), `armed`, and may state `standard`, `plan`, `spec_version`, `reason`. A command
# keeps the suite's three legs: the control (a known-good third-party peer) always runs, the negative
# control (a deliberately broken peer) must grade red, and the subject is armed or red. `pass` means
# all three held. Verdicts contain small metadata, not embedded reports: raw JSON is limited to 1 MiB.
#
# THIS SCRIPT then holds each verdict to the schema (an absent, unreadable or mismatched verdict is
# `fail`, never skipped), stamps what the suite's freshness is judged by (`repo`, `commit`,
# `core_pin`, `run_id`, `evidence`: the ModernCI move, `generated_at`) and writes it to
# target/conformance/verdicts/<id>.json, the check's output. A successful nonempty run also writes
# invocation.json binding its source inputs and verdict hashes; completed failed suites also carry
# their actual exit code. Importing PASS requires the job's green result and receipt exit zero.
# Exit 0 only when every suite passed; an empty list exits 0 and says so. Each suite gets CONFORMANCE_TIMEOUT_SECONDS (default 1800,
# valid range 1..86400); expiry refuses the verdict and terminates its complete process group.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$here" || exit 2
LIST="testing/conformance/suites.tsv"
OUT="$here/target/conformance"
MCI_URL="${MODERNCI_URL:-https://eu-central.modernci.dev}"

say() { printf 'conformance: %s\n' "$*" >&2; }

# judge <raw verdict> <suite id> <command rc> <out file>: the verdict as published, or exit 1.
judge() {
  python3 -I - "$@" <<'PY'
import json, sys, os, stat, datetime, urllib.parse
raw, suite, rc, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
SCHEMA = "busbar.conformance.verdict/1"
MAX_VERDICT_BYTES = 1024 * 1024
OPTIONAL_STRINGS = {"standard", "plan", "spec_version", "reason", "cert_id", "issuer", "expires"}
KEYS = {"schema", "suite", "status", "armed", "commit", "run_id", "evidence", "generated_at",
        "repo", "core_pin"} | OPTIONAL_STRINGS
class VerdictInputError(ValueError):
    pass

def read_verdict(path):
    with open(path, "rb") as stream:
        before = os.fstat(stream.fileno())
        regular = stat.S_ISREG(before.st_mode)
        if regular and before.st_size > MAX_VERDICT_BYTES:
            raise VerdictInputError(f"verdict.json exceeds the {MAX_VERDICT_BYTES}-byte limit")
        payload = stream.read(MAX_VERDICT_BYTES + 1)
        if len(payload) > MAX_VERDICT_BYTES:
            raise VerdictInputError(f"verdict.json exceeds the {MAX_VERDICT_BYTES}-byte limit")
        if regular:
            after = os.fstat(stream.fileno())
            if len(payload) < before.st_size:
                raise VerdictInputError("verdict.json returned a short read")
            if (len(payload) != before.st_size or after.st_size != before.st_size
                    or after.st_mtime_ns != before.st_mtime_ns
                    or after.st_ctime_ns != before.st_ctime_ns):
                raise VerdictInputError("verdict.json changed while being read")
    return json.loads(payload)

def refuse(why):
    return {"suite": suite, "status": "fail", "armed": True,
            "reason": "the suite wrote no valid verdict: " + why}
def check(v):
    if not isinstance(v, dict):
        return "verdict.json is not an object"
    if v.get("suite") != suite:
        return f"verdict names suite {v.get('suite')!r}, filed under {suite!r}"
    extra = set(v) - KEYS
    if extra:
        return f"verdict carries unknown fields {sorted(extra)}"
    for field in sorted(OPTIONAL_STRINGS):
        if field in v and not isinstance(v[field], str):
            return f"{field} is not a string"
    if v.get("schema", SCHEMA) != SCHEMA:
        return f"verdict states schema {v.get('schema')!r}, not {SCHEMA!r}"
    if v.get("status") not in ("pass", "fail", "not-run"):
        return f"status {v.get('status')!r} is not pass|fail|not-run"
    if not isinstance(v.get("armed"), bool):
        return "armed is not a boolean"
    if v["armed"] is False and v["status"] != "not-run":
        return f"an unarmed verdict claims {v['status']}"
    if v["status"] == "pass" and rc != 0:
        return f"the verdict says pass but the command exited {rc}"
    return None
try:
    v = read_verdict(raw)
    why = check(v)
    if why:
        v = refuse(why)
except VerdictInputError as error:
    v = refuse(str(error))
except FileNotFoundError:
    v = refuse(f"no verdict.json (command exit {rc})")
except (OSError, ValueError, RecursionError) as e:
    v = refuse(f"verdict.json cannot be read: {type(e).__name__}")
env = os.environ
repo = env.get("MODERNCI_REPO") or env["CONF_REPO"]
head = env["CONF_HEAD"]
frm = env.get("MODERNCI_FROM") or env.get("CONF_BRANCH") or "dev"
expected = {"repo": repo, "commit": head, "core_pin": env["BUSBAR_PIN"]}
for field, value in expected.items():
    if field in v and v[field] != value:
        v = refuse(f"the suite's subject {field} is {v[field]!r}, expected {value!r}")
        break
v["schema"] = SCHEMA
v["repo"] = repo
v["commit"] = head
v["core_pin"] = env["BUSBAR_PIN"]
url = env["CONF_MCI_URL"].rstrip("/") + "/move?" + urllib.parse.urlencode({"repo": repo, "from": frm, "head": head})
v["run_id"] = "modernci:" + repo + "@" + head + ":conformance"
v["evidence"] = url
v["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
try:
    with open(out, "w") as f:
        json.dump(v, f, indent=2, sort_keys=True)
        f.write("\n")
except OSError as error:
    print(f"cannot publish conformance verdict: {type(error).__name__}", file=sys.stderr)
    sys.exit(1)
print(v["status"], v.get("reason", ""))
sys.exit(0 if v["status"] == "pass" else 1)
PY
}

# Each suite owns a process group so a timed-out judge cannot leave its subjects running.
run_suite() {
  python3 -I - "$1" "$SUITE_TIMEOUT" <<'PYTIMEOUT'
import os, signal, subprocess, sys
command, budget = sys.argv[1:3]
def interrupted(signum, frame):
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
process = subprocess.Popen(["bash", "-c", command], stdin=subprocess.DEVNULL, start_new_session=True)
try:
    try:
        result = process.wait(timeout=int(budget))
    except subprocess.TimeoutExpired:
        print("conformance: suite exceeded its time budget", file=sys.stderr)
        result = 124
    sys.exit(result)
finally:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()
PYTIMEOUT
}

# Bind a completed generation to this invocation, its exact control inputs and verdict bytes.
# The caller must separately require the job's actual successful result before importing it.
invocation_receipt() {
  python3 -I - "$1" "$W/invocation.json" "$OUT" "${2:-0}" <<'PYINVOCATION'
import datetime, hashlib, json, os, pathlib, subprocess, sys, uuid
phase, journal, output, exit_code = sys.argv[1:]
root = pathlib.Path.cwd()
def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def inputs():
    required = ("testing/conformance/run.sh", "testing/conformance/tools.sh", "testing/conformance/suites.tsv")
    optional = (".busbar-ref", "Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml")
    return {name: digest(root / name) for name in required + optional if name in required or (root / name).is_file()}
try:
    if phase == "start":
        record = {"schema": "busbar.conformance.invocation/1", "invocation_id": uuid.uuid4().hex,
                  "repo": os.environ["CONF_REPO"], "commit": os.environ["CONF_HEAD"],
                  "core_pin": os.environ["BUSBAR_PIN"], "started_at": now(), "inputs": inputs()}
        pathlib.Path(journal).write_text(json.dumps(record, sort_keys=True) + "\n")
    else:
        record = json.loads(pathlib.Path(journal).read_text())
        head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        if record["inputs"] != inputs() or record["commit"] != head:
            raise ValueError("source or conformance inputs changed during the invocation")
        verdicts = pathlib.Path(output) / "verdicts"
        record.update(exit_code=int(exit_code), finished_at=now(), verdicts={p.name: digest(p) for p in sorted(verdicts.glob("*.json"))})
        if not record["verdicts"]:
            raise ValueError("no verdicts to publish")
        temporary = pathlib.Path(output) / ".invocation.json"
        temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, pathlib.Path(output) / "invocation.json")
except (OSError, ValueError, subprocess.CalledProcessError) as error:
    print(f"conformance: invocation receipt refused: {error}", file=sys.stderr)
    sys.exit(2)
PYINVOCATION
}

selftest() (
  export MODERNCI_REPO=selftest/repo
  local t; t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
  export BUSBAR_PIN=0000000000000000000000000000000000000000 CONF_REPO=selftest/repo CONF_HEAD=1111111111111111111111111111111111111111 CONF_MCI_URL="$MCI_URL"
  local ok=0
  expect() { # expect <want rc> <name> <verdict text or -> <rc>
    local want="$1" name="$2" text="$3" rc="$4" got=0
    rm -f "$t/v.json"; [ "$text" = - ] || printf '%s' "$text" > "$t/v.json"
    judge "$t/v.json" s1 "$rc" "$t/out.json" >/dev/null || got=1
    if [ "$got" != "$want" ]; then echo "selftest FAILED: $name (exit $got, wanted $want)"; ok=1; else echo "  ok: $name"; fi
  }
  expect 0 "an armed pass is published" '{"suite":"s1","status":"pass","armed":true}' 0
  expect 0 "optional certificate metadata is preserved" '{"suite":"s1","status":"pass","armed":true,"cert_id":"cert","issuer":"body","expires":"2030-01-01"}' 0
  expect 1 "a non-string optional field is red" '{"suite":"s1","status":"pass","armed":true,"standard":null}' 0
  expect 1 "no verdict file is red" - 0
  expect 1 "a verdict that is not JSON is red" 'nope' 0
  expect 1 "a verdict filed under another suite is red" '{"suite":"s2","status":"pass","armed":true}' 0
  expect 1 "an unarmed pass is red" '{"suite":"s1","status":"pass","armed":false}' 0
  expect 1 "a pass whose command failed is red" '{"suite":"s1","status":"pass","armed":true}' 1
  expect 1 "an unknown field is red" '{"suite":"s1","status":"pass","armed":true,"x":1}' 0
  expect 1 "another schema is red" '{"schema":"busbar.conformance.verdict/2","suite":"s1","status":"pass","armed":true}' 0
  expect 1 "a fail is red" '{"suite":"s1","status":"fail","armed":true}' 1
  expect 1 "not-run is red" '{"suite":"s1","status":"not-run","armed":false}' 3
  expect 1 "an older subject cannot be stamped current" '{"suite":"s1","status":"pass","armed":true,"commit":"2222222222222222222222222222222222222222"}' 0
  expect 1 "another core cannot be stamped current" '{"suite":"s1","status":"pass","armed":true,"core_pin":"2222222222222222222222222222222222222222"}' 0
  expect 1 "another repo cannot be stamped current" '{"suite":"s1","status":"pass","armed":true,"repo":"other/repo"}' 0
  judge <(printf '%s' '{"suite":"s1","status":"pass","armed":true}') s1 0 "$t/out.json" >/dev/null
  python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["repo"]=="selftest/repo" and v["core_pin"].startswith("0000") and v["evidence"].endswith("&head=1111111111111111111111111111111111111111"), v' "$t/out.json" \
    && echo "  ok: the stamp names the repo, the commit, the core pin and the move" || { echo "selftest FAILED: the stamp"; ok=1; }
  return "$ok"
)

[ "${1:-}" = --selftest ] && { selftest; exit $?; }

# One driver owns this checkout's fixed output tree until its suites and judgments finish.
mkdir -p "$(dirname "$OUT")" || { say "the output parent could not be created"; exit 2; }
exec 7>"$OUT.lock" || { say "the output lease could not be opened"; exit 2; }
python3 -I - 7 <<'PYOUTPUT' || exit 2
import fcntl, sys
try:
    fcntl.flock(int(sys.argv[1]), fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError as error:
    print(f"conformance: output is already leased or unavailable: {error}", file=sys.stderr)
    sys.exit(1)
PYOUTPUT

if ! rm -rf "$OUT" || ! mkdir -p "$OUT/verdicts"; then
  say "the conformance output could not be cleaned and created"; exit 2
fi

SUITE_TIMEOUT="${CONFORMANCE_TIMEOUT_SECONDS-1800}"
[[ "$SUITE_TIMEOUT" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$SUITE_TIMEOUT" -le 86400 ] \
  || { say "CONFORMANCE_TIMEOUT_SECONDS must be an integer from 1 to 86400"; exit 2; }

[ -f "$LIST" ] || { say "$LIST is missing"; exit 2; }
if [ ! -s "$LIST" ] || ! grep -qvE '^[[:space:]]*(#|$)' "$LIST"; then
  say "this repo lists no suites ($LIST); nothing to judge"
  exit 0
fi

# Validate the entire list before fetching core or provisioning any tool.
awk -F '\t' '!/^[[:space:]]*(#|$)/ {
  if ($1 !~ /^[A-Za-z0-9][A-Za-z0-9_.-]*$/) {
    print "invalid suite id: " $1 > "/dev/stderr"; bad=1
  }
  if (seen[$1]++) {
    print "duplicate suite id: " $1 > "/dev/stderr"; bad=1
  }
  if ($2 !~ /[^[:space:]]/) {
    print "suite command is missing: " $1 > "/dev/stderr"; bad=1
  }
} END { exit bad }' "$LIST" || { say "$LIST is invalid"; exit 2; }

# A suite list may declare its supported provisioning tools once, before any fetch.
# Without a declaration, retain the conservative workspace/toolchain fallback.
declared_tools="$(awk '
/^[[:space:]]*#[[:space:]]*tools:/ {
  if (found++) { print "duplicate tools declaration" > "/dev/stderr"; bad=1 }
  line=$0; sub(/^[[:space:]]*#[[:space:]]*tools:[[:space:]]*/, "", line)
  sub(/[[:space:]]*$/, "", line)
  if (line == "") { print "empty tools declaration" > "/dev/stderr"; bad=1 }
  count=split(line, tools, /[[:space:]]+/)
  for (i=1; i<=count; i++) {
    if ((tools[i] != "rust" && tools[i] != "node") || seen[tools[i]]++) {
      print "unknown or duplicate tool: " tools[i] > "/dev/stderr"; bad=1
    }
  }
  print line
} END { exit bad }' "$LIST")" || { say "$LIST has invalid tool declarations"; exit 2; }
tools=(node)
if [ -f Cargo.toml ] || [ -f rust-toolchain.toml ] || [ -f rust-toolchain ]; then tools=(rust node); fi
if [ -n "$declared_tools" ]; then read -r -a tools <<< "$declared_tools"; fi

unset GIT_INDEX_FILE GIT_DIR GIT_WORK_TREE
actual_head="$(git -C "$here" rev-parse HEAD)" || { say "the checkout has no source commit"; exit 2; }
export CONF_HEAD="${MODERNCI_COMMIT:-$actual_head}"
[ "$CONF_HEAD" = "$actual_head" ] || { say "the checkout is $actual_head, expected $CONF_HEAD"; exit 2; }
# busbar itself carries no .busbar-ref: its core suites judge this checkout, so the pin is HEAD.
if [ -f .busbar-ref ]; then
  pin="$(awk '{print $1; exit}' .busbar-ref)"
  [[ "$pin" =~ ^[0-9a-f]{40}$ ]] || { say ".busbar-ref field 1 is not a full sha: '$pin'"; exit 2; }
else
  [ -f crates/busbar-contract/Cargo.toml ] || { say "no .busbar-ref, and this is not busbar"; exit 2; }
  pin="$CONF_HEAD"
fi
export BUSBAR_PIN="$pin"
# Infer only the repository path: authenticated HTTPS/SSH origins must never stamp credentials.
CONF_REPO="${MODERNCI_REPO:-}"
if [ -z "$CONF_REPO" ]; then
  origin="$(git config --get remote.origin.url)" || { say "the checkout has no origin"; exit 2; }
  CONF_REPO="$(printf '%s' "$origin" | python3 -I -c '
import sys, urllib.parse
origin = sys.stdin.read().strip()
if "://" in origin:
    repo = urllib.parse.urlsplit(origin).path
elif ":" in origin:
    repo = origin.split(":", 1)[1]
else:
    repo = origin
repo = repo.strip("/")
print(repo[:-4] if repo.endswith(".git") else repo)
')" || { say "the origin could not be parsed"; exit 2; }
fi
[ -n "$CONF_REPO" ] || { say "the repository is empty"; exit 2; }
export CONF_REPO
CONF_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
# A detached checkout names no branch (git prints `HEAD`): the judge then falls back to dev.
[ "$CONF_BRANCH" != HEAD ] || CONF_BRANCH=""
export CONF_BRANCH
export CONF_MCI_URL="$MCI_URL"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$here/target}"

# busbar at the pin, outside this checkout (its scripts and crates are what the subjects build on).
W="$(mktemp -d "${TMPDIR:-/tmp}/conformance.XXXXXX")" || { say "the invocation workspace could not be created"; exit 2; }
trap 'rm -rf "$W"' EXIT
if [ ! -f .busbar-ref ]; then
  export BUSBAR_CHECKOUT="$here"
else
  export BUSBAR_CHECKOUT="$W/busbar"
  mkdir -p "$BUSBAR_CHECKOUT" && git -C "$BUSBAR_CHECKOUT" init -q \
  && git -C "$BUSBAR_CHECKOUT" remote add origin https://github.com/GetBusbar/busbar.git \
  && git -C "$BUSBAR_CHECKOUT" fetch -q --depth 1 --no-tags origin "$pin" \
  && git -C "$BUSBAR_CHECKOUT" -c advice.detachedHead=false checkout -q FETCH_HEAD \
  || { say "busbar $pin could not be fetched"; exit 2; }
fi

invocation_receipt start || exit 2

# shellcheck source=testing/conformance/tools.sh
. testing/conformance/tools.sh "${tools[@]}" || { say "the pinned tools could not be provisioned"; exit 2; }

fail=0; n=0
while IFS=$'\t' read -r id cmd || [ -n "$id" ]; do
  # Blank and comment lines, leading whitespace included, as the emptiness and duplicate checks skip them.
  case "${id#"${id%%[![:space:]]*}"}" in ''|\#*) continue ;; esac
  [ -n "${cmd:-}" ] || { say "$LIST: suite $id names no command"; fail=1; continue; }
  n=$((n + 1))
  dir="$OUT/$id"; mkdir -p "$dir"
  say "=== $id: $cmd"
  start=$(date +%s); rc=0
  ( export CONFORMANCE_SUITE="$id" CONFORMANCE_OUT="$dir"; run_suite "$cmd" ) || rc=$?
  say "$id: command exit $rc after $(( $(date +%s) - start ))s"
  if res="$(judge "$dir/verdict.json" "$id" "$rc" "$OUT/verdicts/$id.json")"; then
    say "$id: PASS"
  else
    say "$id: NOT PASS ($res)"; fail=1
  fi
done < "$LIST"
say "$n suite(s) judged; verdicts in target/conformance/verdicts/"
python3 -I - "$OUT/verdicts" <<'PYSUMMARY'
import json, pathlib, sys
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.json")):
    if path.is_file():
        with path.open() as stream:
            print(f"{json.load(stream)['status']}  {path.stem}")
PYSUMMARY
invocation_receipt finish "$fail" || exit 2
exit "$fail"
