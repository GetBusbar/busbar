#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Prove the replayer itself: a differ that cannot see a diff is worse than none.
#   (a) golden vs a copy of itself      -> GREEN, zero divergences
#   (b) one cell's status mutated       -> RED, exactly one FAIL, class `status`
#   (c) one candidate cell deleted      -> RED, exactly one FAIL, class `missing.candidate`
#   (d) an empty candidate              -> RED, every owed id FAIL (missing.candidate), never green
#   (e) a normalizer rule on one side   -> RED, class `norm.rules`
#   (f) an effects.usage divergence     -> RED, class `effects.usage`
#   (g) a cell's own `compare` list     -> only the listed classes show, others are dropped
#   (h) an `improvement` acceptance of a `status` class -> the loader refuses it (exit != 0)
#   (i) an accepted `transform`         -> the cell reports ACCEPTED, never a silent PASS
#   (j) a baseline id the golden no longer owes, unnamed -> RED (owed-baseline regression)
#   (k) the same id named in accepted-gaps.json          -> GREEN, with a named-gap line
#   (l) golden/candidate meta.json harness_rev mismatch  -> exit 2
#   (m) --allow-harness-skew on that same mismatch       -> proceeds
#   (n) an accepted `transform` on a cell that carries content-length -> the row's class list is
#       `body` alone, with no phantom `headers` from the length the rewrite itself moved
#   (o) ONE mutation per remaining divergence class -> RED, exactly one FAIL, exactly that class:
#       headers, body, effects.metrics, effects.audit, effects.stderr, effects.egress,
#       effects.readback, effects.files, effects.usage_after_restart, effects.store_errors.
#       Together with (b)/(c)/(e)/(f) and (p) this covers all 15 of CLASS_ORDER: a class the differ
#       computes but no case exercises is a class that could stop working silently.
#   (p) the golden ledger says PASS but the golden cell file is absent -> RED [missing.golden]
#   (q) an `improvement` acceptance of each MONEY class -> the loader refuses it (exit != 0).
#       This is the guard that stops a class being quietly dropped from MONEY_CLASSES: removing
#       effects.usage (or effects.egress / effects.readback / effects.files / ...) from that set
#       makes the matching case here go green-when-it-should-be-red, i.e. RED in this selftest.
#   (w) EVERY script driver's give-up path carries effects.harness_error when it fails with a
#       non-negative status -> record.sh cannot write a PASS row over a harness failure
#   (x) no script driver steps a wall clock into effects (effects.script rates every such key
#       MONEY, so an epoch second there is a permanent divergence about nothing)
#   (y) every golden PASS id is named in owed-baseline.txt -- replay.sh only WARNS about an owed id
#       missing from the baseline, so such a cell can stop being owed later with no red row
#   (r) diff-cells.py --strict --id-filter used directly as a subset gate (land.sh's shape):
#       a filter that selects a diverging cell exits 1, and a filter that selects NOTHING also
#       exits 1 — a subset gate that compared zero cells has proven nothing
#   (w) normalize.py's `eventstream.frames` rule on REAL encoded Bedrock frames: a latencyMs-only
#       difference normalizes EQUAL, a real payload difference stays UNEQUAL, and a corrupted CRC
#       records `eventstream.undecodable` instead of decoding cleanly
# The tracked fixture recording under fixtures/selftest-recording is used read-only: every case
# below works on a `cp -R` of it, never the tracked copy itself.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
FIX="${here}/fixtures/selftest-recording"
CELLS="${FIX}/cells.json"
W="$(mktemp -d "${TMPDIR:-/tmp}/oracle-replay-selftest.XXXXXX")"
trap 'rm -rf "$W"' EXIT
fails=0
say() { printf '%s  %s\n' "$1" "$2"; [ "$1" = PASS ] || fails=$((fails+1)); }
# The fixture's meta.json predates harness_rev, so every structural case below (a-g) needs
# --allow-harness-skew just to get past the provenance check; (l)/(m) test that check itself.
# It also names no `binary_sha256` — it was made by no released binary — so the cases below say
# --no-check-golden OUT LOUD. They used to inherit the skip for free, because an absent field and a
# malformed one both read as "no binary named"; case (aa) is what that silence cost.
run_args() { local g="$1" c="$2" o="$3"; shift 3; bash "${here}/replay.sh" --golden "$g" --candidate "$c" --out "$o" --cells "$CELLS" "$@" >"$o.log" 2>&1; echo $?; }
run() { run_args "$1" "$2" "$3" --allow-harness-skew --no-check-golden --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt"; }
fails_in() { awk -F'\t' '$2=="FAIL"{n++} END{print n+0}' "$1/ledger.tsv"; }
classes_of() { awk -F'\t' -v i="$1" '$1==i{print $3}' "$2/ledger.tsv"; }

printf '{"accepted":[]}' >"$W/no-accept.json"
printf '{"accepted":[]}' >"$W/no-gaps.json"
: >"$W/no-baseline.txt"   # empty: the baseline check is a no-op unless a case opts into a real one

# (a) identical
cp -R "$FIX" "$W/same"
rc="$(run "$FIX" "$W/same" "$W/out-a")"
[ "$rc" = 0 ] && [ "$(fails_in "$W/out-a")" = 0 ] && say PASS "identical recordings -> green, 0 diffs" || say FAIL "identical recordings rc=$rc fails=$(fails_in "$W/out-a")"

# (b) mutate one status
cp -R "$FIX" "$W/mut"
f="$(ls "$W/mut/cells/" | head -1)"
python3 - "$W/mut/cells/$f" <<'EOF'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["status"]=418; json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)
EOF
id="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['cells'][0]['id'])" "$CELLS")"
rc="$(run "$FIX" "$W/mut" "$W/out-b")"
n="$(fails_in "$W/out-b")"; cls="$(grep -F "$(sed 's/__/|/g' <<<"${f%.json}")" "$W/out-b/ledger.tsv" | cut -f3)"
[ "$rc" != 0 ] && [ "$n" = 1 ] && [ "$cls" = "status" ] && say PASS "one mutated status -> exactly one FAIL [status]" || say FAIL "mutated status rc=$rc fails=$n classes=$cls"

# (c) delete one candidate cell
cp -R "$FIX" "$W/del"; rm "$W/del/cells/$f"
rc="$(run "$FIX" "$W/del" "$W/out-c")"
n="$(fails_in "$W/out-c")"; cls="$(grep -F "$(sed 's/__/|/g' <<<"${f%.json}")" "$W/out-c/ledger.tsv" | cut -f3)"
[ "$rc" != 0 ] && [ "$n" = 1 ] && [ "$cls" = "missing.candidate" ] && say PASS "one deleted cell -> exactly one FAIL [missing.candidate]" || say FAIL "deleted cell rc=$rc fails=$n classes=$cls"

# (d) empty candidate
mkdir -p "$W/empty/cells"; : >"$W/empty/ledger.tsv"
rc="$(run "$FIX" "$W/empty" "$W/out-d")"
owed="$(wc -l <"$W/out-d/owed.txt" | tr -d ' ')"; n="$(fails_in "$W/out-d")"
[ "$rc" != 0 ] && [ "$n" = "$owed" ] && [ "$owed" -gt 0 ] && say PASS "empty candidate -> every owed cell red ($n/$owed)" || say FAIL "empty candidate rc=$rc fails=$n owed=$owed"

# (e) normalizer rule drift
cp -R "$FIX" "$W/norm"
python3 - "$W/norm/cells/$f" <<'EOF'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["applied"]=sorted(set(d.get("applied",[]))|{"ts.unix"}); json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)
EOF
rc="$(run "$FIX" "$W/norm" "$W/out-e")"
cls="$(grep -F "$(sed 's/__/|/g' <<<"${f%.json}")" "$W/out-e/ledger.tsv" | cut -f3)"
[ "$rc" != 0 ] && [ "$cls" = "norm.rules" ] && say PASS "one-sided normalizer rule -> FAIL [norm.rules]" || say FAIL "norm drift rc=$rc classes=$cls"

# (f) effects.usage divergence — money must be visible even when status/body/headers agree
cp -R "$FIX" "$W/usage"
python3 - "$W/usage/cells/self__a__ok.json" <<'EOF'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["effects"]["usage"]["spend_micros"]=19; json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)
EOF
rc="$(run "$FIX" "$W/usage" "$W/out-f")"
n="$(fails_in "$W/out-f")"; cls="$(classes_of 'self|a|ok' "$W/out-f")"
[ "$rc" != 0 ] && [ "$n" = 1 ] && [ "$cls" = "effects.usage" ] && say PASS "effects.usage divergence -> exactly one FAIL [effects.usage]" || say FAIL "usage divergence rc=$rc fails=$n classes=$cls"

# (g) a cell's own `compare` list drops every OTHER class it is ALLOWED to drop — a legal narrowing
# keeps status (money) and gives up `headers`; mutate headers and status, only status is owed.
# The narrowing must also be VISIBLE: the row carries `narrowed: [...]` naming what it gave up.
mkdir -p "$W/gcells"
python3 - "$CELLS" "$W/gcells/cells.json" <<'EOF'
import json,sys
d=json.load(open(sys.argv[1]))
for c in d["cells"]:
    if c["id"] == "self|a|ok":
        # everything except `headers`: a legal narrowing gives up a class rated 1, never money
        c["compare"] = ["status", "body", "effects.stderr", "effects.usage", "effects.usage_after_restart",
                        "effects.store_errors", "effects.metrics", "effects.audit", "norm.rules",
                        "effects.egress", "effects.readback", "effects.files", "effects.script"]
        c["why"] = "selftest: the header set is not this cell's contract"
json.dump(d, open(sys.argv[2], "w"))
EOF
cp -R "$FIX" "$W/compare"
python3 - "$W/compare/cells/self__a__ok.json" <<'EOF'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["status"]=418; d.setdefault("headers",{})["x-selftest"]="1"; json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)
EOF
# run_args hard-codes --cells "$CELLS"; call replay.sh directly here so the compare-list cells.json is used.
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/compare" --out "$W/out-g" --cells "$W/gcells/cells.json" \
  --allow-harness-skew --no-check-golden --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-g.log" 2>&1
rc=$?
cls="$(classes_of 'self|a|ok' "$W/out-g")"
[ "$rc" != 0 ] && [ "$cls" = "status" ] && say PASS "cell 'compare' list -> only its named classes show (headers dropped)" || say FAIL "compare list rc=$rc classes=$cls (expected status only, headers must not appear)"
grep -q 'narrowed: \[headers\]' "$W/out-g/ledger.tsv" \
  && say PASS "a narrowed cell's row says so ('narrowed: [headers]')" \
  || say FAIL "a narrowed cell reported a bare verdict — the row does not name what it gave up: $(awk -F'\t' '$1=="self|a|ok"' "$W/out-g/ledger.tsv")"

# (h) an `improvement` acceptance of a `status` class must be REFUSED by the loader (exit != 0),
# even when golden and candidate are byte-identical — the register is checked whether or not it
# ever fires.
cat >"$W/bad-accept.json" <<'JSON'
{"accepted":[{"id":"bad status accept","kind":"improvement","by":"selftest","cells":"^self\\|a\\|ok$","classes":["status"],"rationale":"should be refused"}]}
JSON
cp -R "$FIX" "$W/hsame"
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/hsame" --out "$W/out-h" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/bad-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-h.log" 2>&1
rc=$?
grep -q "not kind=breaking" "$W/out-h.log" && msg_ok=1 || msg_ok=0
[ "$rc" != 0 ] && [ "$msg_ok" = 1 ] && say PASS "improvement accepting 'status' -> loader refuses (not kind=breaking)" || say FAIL "bad accept rc=$rc msg_ok=$msg_ok (see $W/out-h.log)"

# (i) an accepted `transform` reports ACCEPTED, never a silent PASS
cp -R "$FIX" "$W/xform"
python3 - "$W/xform/cells/self__b__stream.json" <<'EOF'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["body"]["text"]=d["body"]["text"].replace("hi", "hi TOKEN123"); json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)
EOF
cat >"$W/xform-accept.json" <<'JSON'
{"accepted":[{"id":"T-1 test token","kind":"improvement","by":"selftest","cells":"^self\\|b\\|stream$","expected_cells":1,"rationale":"selftest transform proof","transform":{"candidate":[[" TOKEN123",""]]}}]}
JSON
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/xform" --out "$W/out-i" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/xform-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-i.log" 2>&1
rc=$?
row="$(awk -F'\t' '$1=="self|b|stream"{print; exit}' "$W/out-i/ledger.tsv")"
status_col="$(cut -f2 <<<"$row")"; title_col="$(cut -f3 <<<"$row")"
[ "$rc" = 0 ] && [ "$status_col" = PASS ] && [[ "$title_col" == ACCEPTED* ]] && say PASS "accepted transform -> row is PASS/ACCEPTED, not a silent identical" || say FAIL "transform accept rc=$rc status=$status_col title=$title_col"

# (j) a baseline id the golden no longer owes, not named anywhere -> RED
cp -R "$FIX" "$W/regress-golden"
python3 - "$W/regress-golden/ledger.tsv" <<'EOF'
import sys
p = sys.argv[1]
lines = open(p, encoding="utf-8").read().splitlines()
out = []
for ln in lines:
    parts = ln.split("\t")
    if parts and parts[0] == "self|a|ok":
        parts[1] = "SKIP"
        parts = parts[:3] + ["golden re-recorded this cell as unsupported"]
    out.append("\t".join(parts))
open(p, "w", encoding="utf-8").write("\n".join(out) + "\n")
EOF
printf 'self|a|ok\nself|b|stream\n' >"$W/baseline-ab.txt"
cp -R "$FIX" "$W/regress-cand"
bash "${here}/replay.sh" --golden "$W/regress-golden" --candidate "$W/regress-cand" --out "$W/out-j" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/no-accept.json" --baseline "$W/baseline-ab.txt" --accepted-gaps "$W/no-gaps.json" >"$W/out-j.log" 2>&1
rc=$?
row="$(awk -F'\t' '$1=="self|a|ok"{print; exit}' "$W/out-j/ledger.tsv")"
status_col="$(cut -f2 <<<"$row")"; title_col="$(cut -f3 <<<"$row")"
[ "$rc" != 0 ] && [ "$status_col" = FAIL ] && [[ "$title_col" == *"owed-baseline"* ]] && say PASS "golden dropped a baselined id, unnamed -> RED [owed-baseline regression]" || say FAIL "baseline regression rc=$rc status=$status_col title=$title_col"

# (k) the same regression, named in accepted-gaps.json -> GREEN with a named-gap line
cat >"$W/gaps-ab.json" <<'JSON'
{"accepted":[{"id":"selftest gap self|a|ok","cells":"^self\\|a\\|ok$","owner":"selftest","rationale":"intentionally dropped for this test"}]}
JSON
bash "${here}/replay.sh" --golden "$W/regress-golden" --candidate "$W/regress-cand" --out "$W/out-k" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/no-accept.json" --baseline "$W/baseline-ab.txt" --accepted-gaps "$W/gaps-ab.json" >"$W/out-k.log" 2>&1
rc=$?
row="$(awk -F'\t' '$1=="self|a|ok"{print; exit}' "$W/out-k/ledger.tsv")"
status_col="$(cut -f2 <<<"$row")"; title_col="$(cut -f3 <<<"$row")"
[ "$rc" = 0 ] && [ "$status_col" = PASS ] && [[ "$title_col" == *"ACCEPTED named gap"* ]] && say PASS "same regression named in accepted-gaps.json -> GREEN, named-gap line" || say FAIL "accepted gap rc=$rc status=$status_col title=$title_col"

# (l) golden/candidate produced by different (or absent) harness revisions -> exit 2, no comparison
cp -R "$FIX" "$W/hrev-g"; cp -R "$FIX" "$W/hrev-c"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); d['harness_rev']='a'*64; json.dump(d, open(sys.argv[1],'w'))" "$W/hrev-g/meta.json"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); d['harness_rev']='b'*64; json.dump(d, open(sys.argv[1],'w'))" "$W/hrev-c/meta.json"
# --no-check-golden, so this case reaches the HARNESS guard: the fixture names no binary_sha256 and
# the provenance guard would otherwise (correctly) refuse first, for a different reason.
bash "${here}/replay.sh" --golden "$W/hrev-g" --candidate "$W/hrev-c" --out "$W/out-l" --cells "$CELLS" \
  --no-check-golden --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-l.log" 2>&1
rc=$?
grep -qi "harness" "$W/out-l.log" && msg_ok=1 || msg_ok=0
[ "$rc" = 2 ] && [ "$msg_ok" = 1 ] && say PASS "mismatched harness_rev -> exit 2, named in the message" || say FAIL "harness_rev mismatch rc=$rc msg_ok=$msg_ok"

# (m) --allow-harness-skew on that same mismatched pair -> proceeds to a normal verdict
bash "${here}/replay.sh" --golden "$W/hrev-g" --candidate "$W/hrev-c" --out "$W/out-m" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-m.log" 2>&1
rc=$?
[ "$rc" = 0 ] && [ "$(fails_in "$W/out-m")" = 0 ] && say PASS "--allow-harness-skew proceeds past the same mismatch" || say FAIL "--allow-harness-skew rc=$rc fails=$(fails_in "$W/out-m")"

# (n) an accepted transform on a cell whose headers carry content-length: the length moves BECAUSE
# the accepted rewrite moved the body, so it is the accepted change's shadow, not a second
# divergence. The row must report `body` alone — a phantom `headers` both mis-describes the row and
# would stop a correctly narrow `classes: ["body"]` entry from ever matching.
cp -R "$FIX" "$W/clen-g"; cp -R "$FIX" "$W/clen-c"
python3 - "$W/clen-g/cells/self__b__stream.json" "$W/clen-c/cells/self__b__stream.json" <<'EOF'
import json, sys
gp, cp_ = sys.argv[1], sys.argv[2]
g = json.load(open(gp))
g["headers"]["content-length"] = str(len(g["body"]["text"]))
json.dump(g, open(gp, "w"), separators=(",", ":"), sort_keys=True)
c = json.load(open(cp_))
c["body"]["text"] = c["body"]["text"].replace("hi", "hi TOKEN123")
c["headers"]["content-length"] = str(len(c["body"]["text"]))
json.dump(c, open(cp_, "w"), separators=(",", ":"), sort_keys=True)
EOF
bash "${here}/replay.sh" --golden "$W/clen-g" --candidate "$W/clen-c" --out "$W/out-n" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/xform-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-n.log" 2>&1
rc=$?
row="$(awk -F'\t' '$1=="self|b|stream"{print; exit}' "$W/out-n/ledger.tsv")"
status_col="$(cut -f2 <<<"$row")"; title_col="$(cut -f3 <<<"$row")"
[ "$rc" = 0 ] && [ "$status_col" = PASS ] && [[ "$title_col" == *"ACCEPTED"* ]] && [[ "$title_col" == *": body" ]] \
  && say PASS "accepted transform + content-length -> class list is 'body' alone (no phantom headers)" \
  || say FAIL "transform content-length rc=$rc status=$status_col title=$title_col (expected the class list to end ': body')"

# (o) one mutation per remaining class. Each fragment edits ONLY the candidate's self|a|ok cell, so
# the expected outcome is always: exactly one FAIL, whose class column is exactly the named class.
# A class that shows up alongside another (or not at all) is a differ that cannot name what moved.
one_class_case() {  # <tag> <expected-class> <python fragment over the candidate cell dict `d`>
  local tag="$1" want="$2" frag="$3" rc n cls
  cp -R "$FIX" "$W/m-${tag}"
  python3 -c 'import json,sys
p=sys.argv[1]; d=json.load(open(p))
exec(sys.argv[2])
json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)' "$W/m-${tag}/cells/self__a__ok.json" "$frag" || {
    say FAIL "${want}: could not apply the mutation"; return; }
  rc="$(run "$FIX" "$W/m-${tag}" "$W/out-${tag}")"
  n="$(fails_in "$W/out-${tag}")"; cls="$(classes_of 'self|a|ok' "$W/out-${tag}")"
  [ "$rc" != 0 ] && [ "$n" = 1 ] && [ "$cls" = "$want" ] \
    && say PASS "${want} divergence -> exactly one FAIL [${want}]" \
    || say FAIL "${want} divergence rc=$rc fails=$n classes=$cls (expected 1 FAIL [${want}])"
}

one_class_case hdr    headers        'd["headers"]["content-type"]="text/plain"'
one_class_case body   body           'd["body"]["json"]["usage"]["out"]=8'
one_class_case met    effects.metrics 'd["effects"]["metrics"]["busbar_requests_total{outcome=\"ok\"}"]=2'
one_class_case aud    effects.audit  'd["effects"]["audit"]={"added":1,"items":[{"actor":"admin","action":"keys.create","resource":"vk_<KEY>","outcome":"ok","chain_ok":True}]}'
one_class_case err    effects.stderr 'd["effects"]["stderr"]="[error] store error: disk full"'
one_class_case egr    effects.egress 'd["effects"]["egress"]=[{"path":"/v1/messages","method":"POST","headers":{},"body":{}}]'
one_class_case rbk    effects.readback 'd["effects"]["readback"]=[{"path":"/api/v1/admin/hooks/h","status":200,"body":{"json":{"name":"h"}}}]'
one_class_case fls    effects.files  'd["effects"]["files"]=["busbar.wal"]'
one_class_case uar    effects.usage_after_restart 'd["effects"]["usage_after_restart"]={"spend_micros":18,"requests":1}'
one_class_case ste    effects.store_errors 'd["effects"]["store_errors"]=2'
# A SCRIPT CELL'S EVIDENCE IS NOT IN THE NAMED CLASSES, AND IT USED TO BE COMPARED BY NOBODY. The
# script driver writes whatever keys its cell is about straight into `effects` — `survived`,
# `key_after_restart`, `validate_exit`, `hazard_lines`, `usage_before`/`usage_after` — and the differ
# only ever looked at nine hard-coded ones. 14 golden cells carry such a key that no other class
# mirrors (plugins.store-persist|store-sqlite's `survived`/`key_after_restart`, hazard|no-data-dir's
# `hazard_lines`, teller|admit-refusal's `usage_before`/`usage_after`), so a build that lost the
# store across a restart, or leaked a hazard line, diverged on nothing the differ computed and the
# row printed `PASS ... identical`. Every effects key is compared now; this case is red without that.
one_class_case scr    effects.script 'd["effects"]["survived"]="no"'

# (u) A LEDGER ID THAT APPEARS TWICE RESOLVES TO ITS LAST ROW, exactly as verdict.sh resolves one.
# `record` APPENDS, so an id can legitimately carry more than one row — a driver that retried, a
# later step that revised its own verdict. The differ read the FIRST row per id while verdict.sh
# (which adjudicates the very same file) reads the LAST, so the two halves of one gate disagreed
# about what the golden said. The dangerous direction is a golden whose first row is SKIP and whose
# corrected row is PASS: the cell then falls out of the OWED set entirely, is never compared, never
# appears in diverging.txt, and a divergence on it can never be seen at all. Here the corrected row
# says PASS for a cell whose candidate is mutated, so a first-row read leaves 0 FAILs (green) and a
# last-row read leaves exactly the one.
cp -R "$FIX" "$W/dup-golden"
printf 'self|a|ok\tSKIP\tUNSUPPORTED: a stale first attempt\tsuperseded below\n' >"$W/dup-golden/ledger.tsv.new"
cat "$FIX/ledger.tsv" >>"$W/dup-golden/ledger.tsv.new"
mv "$W/dup-golden/ledger.tsv.new" "$W/dup-golden/ledger.tsv"
cp -R "$FIX" "$W/dup-cand"
python3 -c 'import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["status"]=418
json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)' "$W/dup-cand/cells/self__a__ok.json"
rc="$(run "$W/dup-golden" "$W/dup-cand" "$W/out-u")"
n="$(fails_in "$W/out-u")"; cls="$(classes_of 'self|a|ok' "$W/out-u")"
[ "$rc" != 0 ] && [ "$n" = 1 ] && [ "$cls" = "status" ] \
  && say PASS "a golden id with a superseded first row -> the LAST row decides (owed, and red)" \
  || say FAIL "duplicate golden ledger row rc=$rc fails=$n classes=$cls (a first-row read makes this cell unowed and invisible)"

# (p) missing.golden: the golden's OWN ledger says PASS but its cell file is not there. That is a
# recorder bug, and it must be red rather than quietly dropping the cell out of the comparison.
cp -R "$FIX" "$W/mg-golden"; cp -R "$FIX" "$W/mg-cand"
rm "$W/mg-golden/cells/self__a__ok.json"
rc="$(run "$W/mg-golden" "$W/mg-cand" "$W/out-p")"
n="$(fails_in "$W/out-p")"; cls="$(classes_of 'self|a|ok' "$W/out-p")"
[ "$rc" != 0 ] && [ "$n" = 1 ] && [ "$cls" = "missing.golden" ] \
  && say PASS "golden ledger PASS with no golden cell file -> exactly one FAIL [missing.golden]" \
  || say FAIL "missing.golden rc=$rc fails=$n classes=$cls"

# (q) the MONEY guard, per class. An `improvement` entry naming a money class must be refused by the
# LOADER, whether or not it ever fires — so this runs against byte-identical recordings. If a class
# is ever dropped from diff-cells.py's MONEY_CLASSES, its case here stops refusing and goes red.
cp -R "$FIX" "$W/money-same"
for mc in status effects.usage effects.usage_after_restart effects.store_errors missing.candidate \
          effects.egress effects.readback effects.files effects.script; do
  python3 -c 'import json,sys
json.dump({"accepted":[{"id":"bad money accept","kind":"improvement","by":"selftest",
  "cells":"^self\\|a\\|ok$","classes":[sys.argv[2]],"rationale":"should be refused"}]},
  open(sys.argv[1],"w"))' "$W/money-accept.json" "$mc"
  bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/money-same" --out "$W/out-q" --cells "$CELLS" \
    --allow-harness-skew --no-check-golden --accepted "$W/money-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-q.log" 2>&1
  rc=$?
  grep -q "not kind=breaking" "$W/out-q.log" && msg_ok=1 || msg_ok=0
  [ "$rc" != 0 ] && [ "$msg_ok" = 1 ] \
    && say PASS "improvement accepting '${mc}' -> loader refuses (money class)" \
    || say FAIL "improvement accepting '${mc}' was NOT refused (rc=$rc msg_ok=$msg_ok) — is ${mc} still in MONEY_CLASSES?"
done

# (s) THE MONEY GUARD MUST TEST WHAT AN ENTRY *DOES*, NOT WHAT IT SAYS. An entry that omits
# `classes` forgives a whole default set, and for kind=breaking that default used to be every class
# there is — while the loader's guard looked only at the (empty) `classes` literal and so found no
# money class to refuse and demanded no changelog line. Four lines of JSON with `cells: "."` then
# forgave a 200 -> 418 and a changed bill on every cell and the oracle reported GREEN.
cp -R "$FIX" "$W/blanket"
python3 -c 'import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["status"]=418; d["effects"]["usage"]["spend_micros"]=999999
json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)' "$W/blanket/cells/self__a__ok.json"
cat >"$W/blanket-accept.json" <<'JSON'
{"accepted":[{"id":"classless breaking","kind":"breaking","by":"selftest","cells":"^self\\|a\\|ok$","rationale":"no classes, no changelog"}]}
JSON
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/blanket" --out "$W/out-s" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/blanket-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-s.log" 2>&1
rc=$?
grep -q "not kind=breaking with a changelog" "$W/out-s.log" && msg_ok=1 || msg_ok=0
[ "$rc" != 0 ] && [ "$msg_ok" = 1 ] \
  && say PASS "classless 'breaking' entry -> loader refuses (it would forgive every money class)" \
  || say FAIL "classless 'breaking' entry was NOT refused (rc=$rc msg_ok=$msg_ok) — it forgives status/effects.usage with no changelog line (see $W/out-s.log)"

# (t) `missing.golden` — the golden's ledger saying PASS for a cell it never wrote — is a RECORDER
# bug, and CLASS_WEIGHT's own assertion calls it never acceptable at all. Naming it in the register
# must be refused by the loader rather than waiving a golden that recorded nothing.
cat >"$W/mg-accept.json" <<'JSON'
{"accepted":[{"id":"waive a recorder bug","kind":"improvement","by":"selftest","cells":".","classes":["missing.golden"],"rationale":"should be refused"}]}
JSON
bash "${here}/replay.sh" --golden "$W/mg-golden" --candidate "$W/mg-cand" --out "$W/out-t" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/mg-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-t.log" 2>&1
rc=$?
grep -q "recorder bug" "$W/out-t.log" && msg_ok=1 || msg_ok=0
[ "$rc" != 0 ] && [ "$msg_ok" = 1 ] \
  && say PASS "an entry naming 'missing.golden' -> loader refuses (recorder bug, never acceptable)" \
  || say FAIL "'missing.golden' acceptance was NOT refused (rc=$rc msg_ok=$msg_ok) — a golden that recorded nothing can be waived (see $W/out-t.log)"

# (u) --strict on a filtered subset: the differ is a gate on its own when a caller (land.sh) uses it
# that way. A filter that selects the mutated cell must exit 1 …
DC="python3 ${here}/diff-cells.py"
$DC --golden "$FIX" --candidate "$W/mut" --out "$W/out-u" --cells "$CELLS" --accepted "$W/no-accept.json" \
  --allow-harness-skew --strict --id-filter '^self\|a\|ok$' >"$W/out-u.log" 2>&1
rc=$?
owed_u="$(wc -l <"$W/out-u/owed.txt" | tr -d ' ')"
[ "$rc" = 1 ] && [ "$owed_u" = 1 ] && grep -q "unaccepted divergence" "$W/out-u.log" && say PASS "--strict with a filter selecting the mutated cell -> exit 1" || say FAIL "strict filtered rc=$rc owed=$owed_u (see $W/out-u.log)"

# (v) … and a filter that selects NOTHING is red too: a subset gate that compared zero cells proved
# nothing, and must never be mistaken for a clean run.
$DC --golden "$FIX" --candidate "$W/mut" --out "$W/out-v" --cells "$CELLS" --accepted "$W/no-accept.json" \
  --allow-harness-skew --strict --id-filter 'no-such-cell-anywhere' >"$W/out-v.log" 2>&1
rc=$?
grep -q "no owed cells matched" "$W/out-v.log" && msg_ok=1 || msg_ok=0
[ "$rc" = 1 ] && [ "$msg_ok" = 1 ] && say PASS "--strict with a filter matching nothing -> exit 1 (nothing was compared)" || say FAIL "strict empty filter rc=$rc msg_ok=$msg_ok (see $W/out-v.log)"

# (w) AN ENTRY MAY NOT MATCH MORE CELLS THAN IT SAYS IT DOES. The money guard asks WHICH classes an
# entry forgives and never over HOW MANY cells, so a live entry could be widened by gluing one more
# alternation onto its `cells` regex — the reviewable prose (id, rationale, changelog line) stays
# word-for-word what it was and the scope quietly doubles. That is exactly what M-3 did: an entry
# about Cohere `billed_units` carried effects.usage over every `billing|*` cell in the corpus.
# `expected_cells` is the count the author saw; matching more is refused.
cp -R "$FIX" "$W/width"
python3 -c 'import json,sys
json.dump({"accepted":[{"id":"widened waiver","kind":"improvement","by":"selftest",
  "cells":"^self\\|a\\|ok$|^self\\|b\\|","classes":["body"],"expected_cells":1,
  "rationale":"declares one cell, the regex takes two"}]}, open(sys.argv[1],"w"))' "$W/width-accept.json"
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/width" --out "$W/out-w" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/width-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-w.log" 2>&1
rc=$?
grep -q "matches 2 cells" "$W/out-w.log" && msg_ok=1 || msg_ok=0
[ "$rc" != 0 ] && [ "$msg_ok" = 1 ] \
  && say PASS "an entry matching more cells than expected_cells -> loader refuses (silent widening)" \
  || say FAIL "widened entry was NOT refused (rc=$rc msg_ok=$msg_ok) — a waiver can grow without its prose changing (see $W/out-w.log)"

# …and the same entry, declaring the truth, loads and runs. Without this arm the guard could be a
# blanket refusal and case (w) would still pass.
python3 -c 'import json,sys
json.dump({"accepted":[{"id":"honest waiver","kind":"improvement","by":"selftest",
  "cells":"^self\\|a\\|ok$|^self\\|b\\|","classes":["body"],"expected_cells":2,
  "rationale":"declares what it takes"}]}, open(sys.argv[1],"w"))' "$W/width-ok.json"
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/width" --out "$W/out-w2" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/width-ok.json" --baseline "$W/no-baseline.txt" >"$W/out-w2.log" 2>&1
rc=$?
[ "$rc" = 0 ] && [ "$(fails_in "$W/out-w2")" = 0 ] \
  && say PASS "an entry declaring its true width loads (the guard refuses widening, not entries)" \
  || say FAIL "an honest expected_cells was refused (rc=$rc fails=$(fails_in "$W/out-w2")) (see $W/out-w2.log)"

# …and an entry that declares NO width at all is refused: an optional field is one nobody fills in.
python3 -c 'import json,sys
json.dump({"accepted":[{"id":"undeclared width","kind":"improvement","by":"selftest",
  "cells":"^self\\|a\\|ok$","classes":["body"],"rationale":"no expected_cells"}]}, open(sys.argv[1],"w"))' "$W/width-none.json"
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/width" --out "$W/out-w3" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/width-none.json" --baseline "$W/no-baseline.txt" >"$W/out-w3.log" 2>&1
rc=$?
grep -q "declares no \`expected_cells\`" "$W/out-w3.log" && msg_ok=1 || msg_ok=0
[ "$rc" != 0 ] && [ "$msg_ok" = 1 ] \
  && say PASS "an entry with no expected_cells -> loader refuses (the width must be declared)" \
  || say FAIL "an entry with no expected_cells was accepted (rc=$rc msg_ok=$msg_ok) (see $W/out-w3.log)"

# …and the SHIPPED register is loaded against the SHIPPED corpus, so the guard is proven against the
# real file rather than only against fixtures: a widened live entry fails HERE, not in CI.
if python3 "${here}/diff-cells.py" --golden "$FIX" --candidate "$W/width" --out "$W/out-w4" \
     --cells "${here}/cells.json" --accepted "${here}/accepted-differences.json" \
     --allow-harness-skew >"$W/out-w4.log" 2>&1; then
  say PASS "the shipped accepted-differences.json loads against the shipped cells.json"
else
  say FAIL "the shipped accepted-differences.json was REFUSED against the shipped cells.json: $(tail -3 "$W/out-w4.log")"
fi

# (w) EVERY script driver's give-up path must be distinguishable from a recorded outcome. record.sh
# reads a script cell's `status` alone: -1 is a named gap (SKIP), and EVERY other status is recorded
# PASS unless the capture carries `effects.harness_error` (record.sh:835). So a driver whose fail()
# writes a NON-NEGATIVE status without that marker freezes its own infrastructure failure into the
# golden — "this cell is exit 1" with a PASS row behind it — and the candidate, failing the same way
# for the same reason, matches it exactly. hazard-no-data-dir.sh was the one driver in scripts/ that
# did this (`fail 1 "busbar did not come up"`, `fail 2 "could not mint a key"`). This is a STATIC
# guard, not a mutation case, because it has to hold for the next driver somebody writes too.
sd="${here}/scripts"
missing_he=""
for f in "$sd"/*.sh; do
  # does this driver ever call fail with a status other than -1? (`fail -1 …` is the named-gap shape)
  grep -Eq '(^|[^-[:alnum:]_])fail[[:space:]]+[0-9]' "$f" || continue
  grep -q 'harness_error' "$f" || missing_he="${missing_he} $(basename "$f")"
done
[ -z "$missing_he" ] \
  && say PASS "every script driver that fails with a non-negative status marks it harness_error" \
  || say FAIL "script driver(s) fail with a non-negative status and NO harness_error, so record.sh writes a PASS row over a harness failure:${missing_he}"

# (x) A DRIVER MUST NOT PUT A WALL CLOCK IN `effects`. Since diff-cells.py grew `effects.script`,
# EVERY effects key a driver writes is compared, and rated MONEY. A raw `date +%s` (or a store column
# holding one) stepped into effects therefore differs on every single replay by construction — the
# golden was recorded at one instant and the candidate runs at another — and normalize.py cannot save
# it: its TS_KEYS rewrite is an EXACT key-name match on an int/float, and `step` writes strings under
# names of the driver's own choosing (`now_at_edit`, `expires_at_after_edit`). The result is a
# permanent, unforgivable-except-as-`breaking` divergence on a cell about nothing.
clock_in_eff=""
for f in "$sd"/*.sh; do
  grep -Eq '^[[:space:]]*step[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+"\$\((date|python3 -c .import time)' "$f" \
    && clock_in_eff="${clock_in_eff} $(basename "$f")"
done
[ -z "$clock_in_eff" ] \
  && say PASS "no script driver steps a wall clock straight into effects (money-rated by effects.script)" \
  || say FAIL "script driver(s) step a raw wall clock into effects, which effects.script now compares as MONEY on every replay:${clock_in_eff}"

# (y) THE OWED RATCHET MUST COVER EVERY GOLDEN PASS. replay.sh only prints "new coverage" to stderr
# for an owed id missing from owed-baseline.txt — it is not a red row. So a golden PASS absent from
# the baseline is a cell that can silently stop being owed later with nothing to catch it: exactly
# the regression owed-baseline.txt exists to make impossible. (`http.crosscut|413|gemini-path` was
# such a cell.) Only checked when the real golden is present in the tree.
GOLD="${here}/golden/1.5.5"
if [ -s "${GOLD}/ledger.tsv" ] && [ -s "${here}/owed-baseline.txt" ]; then
  awk -F'\t' '$2=="PASS"{print $1}' "${GOLD}/ledger.tsv" | LC_ALL=C sort -u >"$W/gold-pass.txt"
  grep -v '^[[:space:]]*$' "${here}/owed-baseline.txt" | LC_ALL=C sort -u >"$W/base.txt"
  unowed="$(comm -23 "$W/gold-pass.txt" "$W/base.txt" | tr '\n' ' ')"
  [ -z "$(printf '%s' "$unowed" | tr -d ' ')" ] \
    && say PASS "every golden PASS id is named in owed-baseline.txt (the ratchet covers all of them)" \
    || say FAIL "golden PASS id(s) missing from owed-baseline.txt, so they can stop being owed with no red row: ${unowed}"
fi

# (z) `compare` IS POLICED LIKE THE REGISTER IS. It is a whitelist with no owner, no kind and no
# changelog line, so it is the widest waiver in the tree and the cheapest to write; the one shipped
# use (`cli|--generate-signing-key`, `compare: ["status"]`) discarded effects.files on the one verb
# that mints a secret — a build writing that key to disk would have been invisible. `compare` may
# now only drop classes outside MONEY_CLASSES, never effects.files/effects.script, and must say why.
mkdir -p "$W/xcells"
compare_case() {  # <name> <json-fragment-for-the-cell> <expected-message> <label>
  python3 - "$CELLS" "$W/xcells/$1.json" "$2" <<'EOF'
import json,sys
d=json.load(open(sys.argv[1]))
patch=json.loads(sys.argv[3])
for c in d["cells"]:
    if c["id"] == "self|a|ok":
        c.pop("why", None); c.update(patch)
json.dump(d, open(sys.argv[2], "w"))
EOF
  bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/same" --out "$W/out-x-$1" --cells "$W/xcells/$1.json" \
    --allow-harness-skew --no-check-golden --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-x-$1.log" 2>&1
  local rc=$?
  grep -q "$3" "$W/out-x-$1.log" && local msg_ok=1 || local msg_ok=0
  [ "$rc" != 0 ] && [ "$msg_ok" = 1 ] \
    && say PASS "$4" \
    || say FAIL "$4 — NOT refused (rc=$rc msg_ok=$msg_ok, see $W/out-x-$1.log)"
}
compare_case money '{"compare":["body"],"why":"selftest"}' 'DROPS' \
  "a 'compare' dropping a money class -> loader refuses"
compare_case files '{"compare":["status","body","headers","effects.stderr","effects.usage","effects.usage_after_restart","effects.store_errors","effects.metrics","effects.audit","norm.rules","effects.egress","effects.readback","effects.script"],"why":"selftest"}' 'effects.files' \
  "a 'compare' dropping effects.files -> loader refuses (a written keyset is invisible elsewhere)"
compare_case nowhy '{"compare":["status","body","effects.stderr","effects.usage","effects.usage_after_restart","effects.store_errors","effects.metrics","effects.audit","norm.rules","effects.egress","effects.readback","effects.files","effects.script"]}' 'carries no .why.' \
  "a 'compare' with no 'why' -> loader refuses"
compare_case typo '{"compare":["stauts"],"why":"selftest"}' 'unknown compare class' \
  "a 'compare' naming a misspelt class -> loader refuses (the typo would drop what it meant to keep)"

# …and the SHIPPED corpus obeys the policy, so a future `compare: [status]` on a real cell is red
# here rather than green forever.
if python3 "${here}/diff-cells.py" --golden "$FIX" --candidate "$W/same" --out "$W/out-x-ship" \
     --cells "${here}/cells.json" --accepted "${here}/accepted-differences.json" \
     --allow-harness-skew >"$W/out-x-ship.log" 2>&1; then
  say PASS "every 'compare' in the shipped cells.json obeys the policy"
else
  say FAIL "a shipped cell's 'compare' was refused: $(tail -3 "$W/out-x-ship.log")"
fi

# (aa) THE `norm.rules` EXEMPTION IS THE ONLY WAY A NORMALIZER RULE ESCAPES BEING COMPARED, so it is
# held to normalize.py rather than trusted to have been copied correctly. diff-cells.ORDER_RULES
# drops a rule name out of the one-sided-firing check; the ONLY rules that may be in it are pure
# RE-SORTS, which change no content. Two ways it can be wrong, and this case catches both:
#   * a re-sort rule normalize.py emits is MISSING from the set -> that rule counts as one-sided and
#     the differ reports a divergence about nothing (this had already happened: normalize.py grew a
#     third sort_runs call, `boot.exhaustion-order`, and the set was never told);
#   * a rule that DROPS or BLANKS content is ADDED to the set -> its one-sided firing goes
#     invisible, which is how content leaves a cell with no class saying so. diff-cells.py asserts
#     that direction at import (ORDER_RULES vs CONTENT_RULES); this case proves the assert bites.
# normalize.py's re-sort rules are read out of the source: the three `sort_runs(...)` calls plus the
# two in-place sorts (`boot.pair-order`, `keys.order`), so a fourth one added tomorrow is red here
# the day it lands rather than the day someone remembers this set exists.
n_sort="$(grep -oE 'sort_runs\([^,]+, [^,]+, "[^"]+"' "${here}/normalize.py" | sed 's/.*"\(.*\)"/\1/' | LC_ALL=C sort -u)"
n_inplace="$(grep -oE 'applied\.add\("(boot\.pair-order|keys\.order)"\)' "${here}/normalize.py" | sed 's/.*"\(.*\)".*/\1/' | LC_ALL=C sort -u)"
printf '%s\n%s\n' "$n_sort" "$n_inplace" | grep -v '^$' | LC_ALL=C sort -u >"$W/resort-rules.txt"
python3 - "$W/order-rules.txt" <<PY
import sys
sys.path.insert(0, "${here}")
import importlib.util
spec = importlib.util.spec_from_file_location("dc", "${here}/diff-cells.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
open(sys.argv[1], "w").write("\n".join(sorted(m.ORDER_RULES)) + "\n")
PY
if diff -u "$W/resort-rules.txt" "$W/order-rules.txt" >"$W/order-rules.diff" 2>&1; then
  say PASS "diff-cells' norm.rules exemption is exactly normalize.py's re-sort rules ($(wc -l <"$W/resort-rules.txt" | tr -d ' ') of them)"
else
  say FAIL "diff-cells.ORDER_RULES has drifted from normalize.py's re-sort rules (- normalize.py, + diff-cells): $(tail -n +4 "$W/order-rules.diff" | tr '\n' ' ')"
fi
# …and a CONTENT rule may never be smuggled into the exemption: the assert must fire.
if python3 - <<PY >"$W/order-assert.log" 2>&1
import importlib.util, sys
spec = importlib.util.spec_from_file_location("dc", "${here}/diff-cells.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
# the guard is the disjointness the module asserts at import; prove it is not vacuous
assert m.CONTENT_RULES, "CONTENT_RULES is empty, so the disjointness assert forbids nothing"
bad = m.ORDER_RULES | {"metrics.timing"}
if bad & m.CONTENT_RULES:
    sys.exit(0)
sys.exit("metrics.timing is not in CONTENT_RULES, so adding it to the exemption would be allowed")
PY
then
  say PASS "a content-dropping rule cannot be exempted from norm.rules (the disjointness guard is not vacuous)"
else
  say FAIL "the ORDER_RULES/CONTENT_RULES guard does not forbid exempting a content-dropping rule: $(tail -2 "$W/order-assert.log")"
fi

# (ab) THE HARNESS REVISION MUST COVER EVERY FILE THAT DECIDES A VERDICT, not only every file that
# decides a RECORDING. harness-rev.sh's own header says the set is "the files that decide what gets
# recorded AND HOW IT IS COMPARED", and it is on that ground that accepted-differences.json and
# owed-baseline.txt are in it — neither is executed while recording; both change the verdict on
# identical bytes. By exactly that argument four more belong and were absent:
#
#   replay.sh          the comparison DRIVER. It holds the owed-baseline regression check, the
#                      golden-binary provenance gate and the --allow-harness-skew plumbing; edit it
#                      and the same two recordings get a different verdict.
#   fleet-fixtures/verdict.sh
#                      its own header: "This is the ONLY place the gate decides anything." lib.sh is
#                      already in the set for writing the ledger ROW; the file that turns those rows
#                      into red or green was not.
#   accepted-gaps.json the register that forgives an owed-baseline regression, with an owner and a
#                      rationale — the exact shape of accepted-differences.json, which is in the set.
#   harness-rev.sh     the definition of the set. Removing a file from the list moves the hash only
#                      because that file's bytes leave it; changing how the list is HASHED does not.
#
# A file outside the set can change while the rev sits still, and diff-cells' skew guard — whose
# whole job is to refuse a pair of recordings made under different harnesses — then compares two
# equal stamps and says nothing. Checked by NAME against `harness-rev.sh --files`, so this is red the
# day one is dropped rather than the day a verdict is doubted.
#
# rigs-baseline.json is deliberately NOT required here: it is the sign-off floor of the SEPARATE
# plane-rigs gate (rigs-ledger.sh), which has its own verdict and never touches an LLM-plane
# recording or this replay.
hr_files="$(bash "${here}/harness-rev.sh" --files)"
hr_missing=""
for want in testing/shadow-oracle/replay.sh testing/shadow-oracle/harness-rev.sh \
            testing/shadow-oracle/accepted-gaps.json testing/fleet-fixtures/verdict.sh; do
  printf '%s\n' "$hr_files" | grep -Fqx "$want" || hr_missing="${hr_missing} ${want}"
done
[ -z "$hr_missing" ] \
  && say PASS "the harness revision covers the comparison driver, the verdict, the gap register and its own definition" \
  || say FAIL "file(s) that decide a verdict are OUTSIDE the harness revision, so they can change while the rev sits still and the skew guard stays quiet:${hr_missing}"
# …and the rev genuinely MOVES when one of them does — a name in the list that is never hashed
# would pass the check above and prove nothing.
hr_before="$(bash "${here}/harness-rev.sh" | awk '{print $2}')"
cp "${here}/replay.sh" "$W/replay.sh.bak"
printf '\n# harness-rev selftest probe\n' >>"${here}/replay.sh"
hr_after="$(bash "${here}/harness-rev.sh" | awk '{print $2}')"
cp "$W/replay.sh.bak" "${here}/replay.sh"
hr_restored="$(bash "${here}/harness-rev.sh" | awk '{print $2}')"
if [ "$hr_before" != "$hr_after" ] && [ "$hr_before" = "$hr_restored" ]; then
  say PASS "editing the comparison driver MOVES the harness revision (and restoring it moves it back)"
else
  say FAIL "editing replay.sh did not move the harness revision (before=${hr_before:0:12} after=${hr_after:0:12} restored=${hr_restored:0:12})"
fi

# (ac) renormalize.sh IS FAITHFUL TO THE RECORDER'S CALL SITE, OR IT REFUSES. It rewrites a
# recording's normalized cells IN PLACE — over the tracked golden — and its own header claims the
# cell's `keep`/`body_lines` spec is "passed exactly as record.sh passes it". record.sh has FOUR
# normalize.py invocations, not one, and they differ: an http cell gets --key-id and both keep
# flags, an exec cell gets the keep flags and no --key-id, a concurrent cell gets --key-id alone,
# and a script cell gets nothing at all. Passing all three uniformly means a `keep` on a script cell
# is applied here and never was by the recorder — the golden silently becomes a cell no recording
# ever produced, and the harness_rev re-stamp makes the rewrite look like an honest re-derivation.
# No script or concurrent cell declares a spec TODAY, so that was faithful by luck; this case is the
# rule. It drives the REAL renormalize.sh against a fixture corpus that gives a script cell a
# `keep`, and requires a refusal that names the cell.
rn="$W/renorm"; mkdir -p "$rn/raw/self__s__script" "$rn/cells"
printf '{"status":0,"headers":{},"body":"{\\"ok\\":true}","effects":{"survived":"yes"}}' \
  >"$rn/raw/self__s__script/captured.json"
printf '{"status":0}' >"$rn/cells/self__s__script.json"
printf '{"harness_rev":"x","version":"busbar 1.5.5"}' >"$rn/meta.json"
cat >"$W/renorm-cells.json" <<'JSON'
{"cells":[{"id":"self|s|script","driver":"script","keep":{"headers":["date"]}}]}
JSON
cp -R "$rn" "$rn-before"
if bash "${here}/renormalize.sh" --cells "$W/renorm-cells.json" "$rn" >"$W/renorm.log" 2>&1; then
  say FAIL "renormalize.sh applied a script cell's keep spec that record.sh never passes, and exited 0"
else
  if grep -q 'self|s|script' "$W/renorm.log" && grep -q 'record.sh:825' "$W/renorm.log" \
     && cmp -s "$rn-before/cells/self__s__script.json" "$rn/cells/self__s__script.json"; then
    say PASS "renormalize.sh refuses a cell whose spec record.sh's own call site would not have passed, and leaves the cell untouched"
  else
    say FAIL "renormalize.sh refused but did not name the cell/call site, or rewrote the cell anyway: $(tail -2 "$W/renorm.log")"
  fi
fi
# …and the faithful case still re-normalizes: the refusal must not be a blanket.
rn2="$W/renorm-ok"; mkdir -p "$rn2/raw/self__h__http" "$rn2/cells"
printf '{"status":200,"headers":{"Date":"x"},"body":"{\\"ok\\":true}","effects":{}}' \
  >"$rn2/raw/self__h__http/captured.json"
printf '{"status":200}' >"$rn2/cells/self__h__http.json"
printf '{"harness_rev":"x","version":"busbar 1.5.5"}' >"$rn2/meta.json"
printf '{"cells":[{"id":"self|h|http","driver":"http"}]}' >"$W/renorm-cells-ok.json"
if bash "${here}/renormalize.sh" --cells "$W/renorm-cells-ok.json" "$rn2" >"$W/renorm-ok.log" 2>&1 \
   && grep -q '"status":200' "$rn2/cells/self__h__http.json"; then
  say PASS "renormalize.sh still re-normalizes a cell whose driver matches its spec (the refusal is not a blanket)"
else
  say FAIL "renormalize.sh refused a faithful http cell: $(tail -2 "$W/renorm-ok.log")"
fi

# (y) THE HARNESS REVISION MUST COVER EVERY FILE THAT DECIDES A RECORDING OR A VERDICT. harness_rev
# is the ONE fact that lets diff-cells refuse a golden and a candidate made under different rules,
# and four files that decide exactly that were outside it: testing/fleet-fixtures/lib.sh (record.sh
# and all 20 drivers source it — it supplies `record`, the writer of the ledger rows the differ reads
# to decide what is OWED), renormalize.sh (rewrites an existing recording's cells in place),
# accepted-differences.json and owed-baseline.txt (the register and the floor the replay is judged
# against). Each could change while every recording on disk went on claiming the same revision.
# Proven by MUTATION, over a copy of the real tree: change the file, the rev must move.
hrtree="$W/hrtree/testing"
mkdir -p "$hrtree"
cp -R "${here}" "$hrtree/shadow-oracle"
rm -rf "$hrtree/shadow-oracle/golden"
mkdir -p "$hrtree/fleet-fixtures"
cp "${here}/../fleet-fixtures/lib.sh" "$hrtree/fleet-fixtures/lib.sh"
hr_of() { bash "$hrtree/shadow-oracle/harness-rev.sh" | awk '{print $2}'; }
hr0="$(hr_of)"
[ -n "$hr0" ] || say FAIL "harness-rev.sh printed no revision over the copied tree"
for hf in shadow-oracle/renormalize.sh shadow-oracle/accepted-differences.json \
          shadow-oracle/owed-baseline.txt fleet-fixtures/lib.sh; do
  printf '\n# harness-rev selftest mutation\n' >>"$hrtree/$hf"
  hrN="$(hr_of)"
  if [ -n "$hrN" ] && [ "$hrN" != "$hr0" ]; then
    say PASS "harness_rev moves when ${hf} changes"
  else
    say FAIL "harness_rev did NOT move when ${hf} changed — a recording made under a different ${hf} claims the same revision, and the skew guard has nothing to see"
  fi
  # put it back, so each file is proven on its own and the loop compares against the same hr0
  cp "${here}/../${hf#shadow-oracle/}" "$hrtree/$hf" 2>/dev/null \
    || cp "${here}/${hf#shadow-oracle/}" "$hrtree/$hf"
  [ "$(hr_of)" = "$hr0" ] || say FAIL "restoring ${hf} did not restore the revision (the selftest's own fixture drifted)"
done

# (z) A RE-NORMALIZED RECORDING SAYS SO. renormalize.sh rewrites the normalized cells of a recording
# that is already on disk, and it is itself in the harness-rev set — so after it runs, the recording
# holds cells THIS harness wrote while meta.json still named the harness that recorded them. The skew
# guard then compares two stale stamps, finds them equal, and permits a comparison across a
# normalizer change. The rewrite has to move the stamp.
rn="$W/renorm"; mkdir -p "$rn/cells" "$rn/raw/cli__--version"
printf '%s\n' '{"status":0,"headers":{},"body":"busbar 1.5.5\\n","effects":{"stderr":""}}' >"$rn/raw/cli__--version/captured.json"
printf '%s\n' '{"binary":"fixture","version":"busbar fixture","recorded":1,"harness_rev":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}' >"$rn/meta.json"
if bash "${here}/renormalize.sh" "$rn" >"$W/renorm.log" 2>&1; then
  now="$(bash "${here}/harness-rev.sh" | awk '{print $2}')"
  got="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("harness_rev",""))' "$rn/meta.json")"
  hist="$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1])).get("harness_rev_history",[])))' "$rn/meta.json")"
  if [ "$got" = "$now" ]; then
    say PASS "renormalize.sh re-stamps harness_rev after rewriting a recording's cells"
  else
    say FAIL "renormalize.sh rewrote cells but left harness_rev at '${got:0:12}' (this harness is ${now:0:12}) — the recording claims a harness that did not write its cells"
  fi
  case "$hist" in *deadbeefdeadbeef*) say PASS "the superseded harness_rev is kept in harness_rev_history" ;;
    *) say FAIL "renormalize.sh dropped the superseded harness_rev instead of recording it (history: ${hist:-<empty>})" ;;
  esac
else
  say FAIL "renormalize.sh failed on a minimal recording: $(tail -3 "$W/renorm.log")"
fi

# (aa) A GOLDEN THAT DOES NOT SAY WHICH BINARY MADE IT IS NOT COMPARED. The binary-provenance check
# extracted `binary_sha256` with `python3 -c … 2>/dev/null || true` and then ran only `if [ -n
# "$gbin" ]`, so EVERY failure of the field — absent, null, a number, a truncated digest, a
# meta.json that did not parse at all — collapsed to the empty string and took the same branch as
# the one legitimate case (a fixture recording that names no binary). The check that proves the
# golden came from the pinned 1.5.5 release was skipped by anything that broke it. Each shape is
# driven separately, because they failed for different reasons and must now each be named.
prov_case() {  # <name> <meta.json bytes> <expected-message-fragment> <label>
  local pg="$W/prov-$1"
  rm -rf "$pg"; cp -R "$FIX" "$pg"
  printf '%s' "$2" >"$pg/meta.json"
  bash "${here}/replay.sh" --golden "$pg" --candidate "$W/same" --out "$W/out-prov-$1" --cells "$CELLS" \
    --allow-harness-skew --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-prov-$1.log" 2>&1
  local rc=$?
  grep -q "$3" "$W/out-prov-$1.log" && local msg_ok=1 || local msg_ok=0
  [ "$rc" = 2 ] && [ "$msg_ok" = 1 ] \
    && say PASS "$4" \
    || say FAIL "$4 — NOT refused (rc=$rc msg_ok=$msg_ok, see $W/out-prov-$1.log)"
}
prov_case absent   '{"binary":"fixture","version":"busbar 1.5.5"}' 'carries no .binary_sha256.' \
  "a golden meta.json with no binary_sha256 -> refuses to compare"
prov_case null     '{"binary":"fixture","version":"busbar 1.5.5","binary_sha256":null}' 'carries no .binary_sha256.' \
  "a golden meta.json with a null binary_sha256 -> refuses to compare"
prov_case short    '{"binary":"fixture","version":"busbar 1.5.5","binary_sha256":"48e2800c"}' 'malformed .binary_sha256.' \
  "a golden meta.json with a truncated binary_sha256 -> refuses to compare"
prov_case notjson  '{"binary": "fixture", "version":' 'not readable JSON' \
  "a golden meta.json that does not parse -> refuses to compare (it used to be swallowed)"
prov_case noversion '{"binary":"fixture","binary_sha256":"48e2800cc1fbf229104d73c23039ba4d4a703c0a8db9e7872e22fec33f9b1e48"}' 'carries no .version.' \
  "a golden meta.json with no version -> refuses to compare (nothing to check the digest against)"

# …and --no-check-golden is still the way to say "I know this pair has no released binary": the
# refusal must be escapable DELIBERATELY, or every fixture-based case above would be unreachable.
rm -rf "$W/prov-esc"; cp -R "$FIX" "$W/prov-esc"
printf '%s' '{"binary":"fixture","version":"busbar 1.5.5"}' >"$W/prov-esc/meta.json"
bash "${here}/replay.sh" --golden "$W/prov-esc" --candidate "$W/same" --out "$W/out-prov-esc" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-prov-esc.log" 2>&1
rc=$?
[ "$rc" = 0 ] && say PASS "--no-check-golden still skips the provenance check, explicitly" \
  || say FAIL "--no-check-golden did not skip the provenance check (rc=$rc, see $W/out-prov-esc.log)"

# (bb) A TRANSFORM MUST HAVE A SCOPE, AND FIRING IS NOT ACCEPTING. `cells` defaulted to "." for every
# entry, and the two shipped transforms (D-1, D-2) carried none — so their rewrites ran over all 2299
# cells. That was called harmless because a transform is line-precise, but the match is not the
# acceptance: once ANY of a cell's text was rewritten, the branch below handed the cell's WHOLE raw
# class list to the accepted column without ever testing it against the entry's `allowed` set. A cell
# where D-1's `[error] BUSBAR-NNNN: ` rewrite fired and whose STATUS had also moved reported
# `PASS ACCEPTED improvement (D-1 …): status` — a money class, forgiven by an `improvement`.
cp -R "$FIX" "$W/tscope"
python3 - "$W/tscope/cells/self__b__stream.json" <<'EOF'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
d["body"]["text"]=d["body"]["text"].replace("hi", "hi TOKEN123")
json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)
EOF
# T-2 fires (its rewrite erases the body divergence) but claims only `headers`. `body` is outside
# its allowed set, so the cell stays RED — the rewrite is not a licence over the cell.
cat >"$W/tscope-accept.json" <<'JSON'
{"accepted":[{"id":"T-2 fires and overreaches","kind":"improvement","by":"selftest","cells":"^self\\|b\\|stream$","expected_cells":1,"classes":["headers"],"rationale":"fires on the body, but only claims headers","transform":{"candidate":[[" TOKEN123",""]]}}]}
JSON
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/tscope" --out "$W/out-bb" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/tscope-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-bb.log" 2>&1
rc=$?
row="$(awk -F'\t' '$1=="self|b|stream"{print; exit}' "$W/out-bb/ledger.tsv")"
[ "$rc" != 0 ] && [ "$(cut -f2 <<<"$row")" = FAIL ] \
  && say PASS "a fired transform does not forgive a class outside its 'allowed' set" \
  || say FAIL "a transform that merely FIRED carried a class it does not claim into the accepted column (rc=$rc row=$row)"

# …and a transform that DOES claim the class it erased still accepts, or the guard above would just
# be a blanket refusal of every transform.
cat >"$W/tscope-ok.json" <<'JSON'
{"accepted":[{"id":"T-2b claims what it erases","kind":"improvement","by":"selftest","cells":"^self\\|b\\|stream$","expected_cells":1,"classes":["body"],"rationale":"claims the class its rewrite erases","transform":{"candidate":[[" TOKEN123",""]]}}]}
JSON
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/tscope" --out "$W/out-bb1b" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/tscope-ok.json" --baseline "$W/no-baseline.txt" >"$W/out-bb1b.log" 2>&1
rc=$?
row="$(awk -F'\t' '$1=="self|b|stream"{print; exit}' "$W/out-bb1b/ledger.tsv")"
[ "$rc" = 0 ] && [[ "$(cut -f3 <<<"$row")" == ACCEPTED* ]] \
  && say PASS "a transform that claims the class it erases still reports ACCEPTED" \
  || say FAIL "a correctly-scoped transform was refused (rc=$rc row=$row)"

# …and a transform with no `cells` at all is refused: an unscoped rewrite is the whole corpus.
cat >"$W/tnoscope.json" <<'JSON'
{"accepted":[{"id":"T-3 unscoped","kind":"improvement","by":"selftest","rationale":"no cells","transform":{"candidate":[[" TOKEN123",""]]}}]}
JSON
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/tscope" --out "$W/out-bb2" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/tnoscope.json" --baseline "$W/no-baseline.txt" >"$W/out-bb2.log" 2>&1
rc=$?
grep -q "declares no \`cells\`" "$W/out-bb2.log" && msg_ok=1 || msg_ok=0
[ "$rc" != 0 ] && [ "$msg_ok" = 1 ] \
  && say PASS "a transform entry with no 'cells' -> loader refuses (an unscoped rewrite is the whole corpus)" \
  || say FAIL "an unscoped transform was accepted (rc=$rc msg_ok=$msg_ok, see $W/out-bb2.log)"

# …and a transform's `cells` is held to its declared width, exactly like every other entry's.
cat >"$W/twide.json" <<'JSON'
{"accepted":[{"id":"T-4 widened","kind":"improvement","by":"selftest","cells":"^self\\|","expected_cells":1,"rationale":"declares one, takes three","transform":{"candidate":[[" TOKEN123",""]]}}]}
JSON
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/tscope" --out "$W/out-bb3" --cells "$CELLS" \
  --allow-harness-skew --no-check-golden --accepted "$W/twide.json" --baseline "$W/no-baseline.txt" >"$W/out-bb3.log" 2>&1
rc=$?
grep -q "expected_cells=1" "$W/out-bb3.log" && msg_ok=1 || msg_ok=0
[ "$rc" != 0 ] && [ "$msg_ok" = 1 ] \
  && say PASS "a transform entry is held to its expected_cells too" \
  || say FAIL "a widened transform was accepted (rc=$rc msg_ok=$msg_ok, see $W/out-bb3.log)"
# (cc) normalize.py's `eventstream.frames` rule, on REAL `application/vnd.amazon.eventstream` bytes.
# The frames below are built by a real encoder — big-endian prelude, a header block in AWS's own
# name/type/length encoding, and both CRC32s computed over the actual bytes — so this exercises the
# decoder against the wire format, not against a mock of itself. Three things are proved:
#   1. a per-run MEASUREMENT inside a frame is normalized away: two streams identical but for the
#      metadata frame's `metrics.latencyMs` (0 vs 2) are BYTE-DIFFERENT before and EQUAL after.
#      Before this rule the body was `.decode("utf-8","replace")`d, so the literal latency sat in
#      the golden and the cell diverged on how fast the machine was — the reason S-1 existed.
#   2. a real CONTENT difference inside a frame is still caught: changing the contentBlockDelta's
#      text is UNEQUAL after. A rule that made (1) pass by flattening the body would fail here.
#   3. a corrupted stream does not decode into a clean-looking list: flipping one bit of the last
#      message CRC yields `eventstream.undecodable`, never `eventstream.frames`. Because the applied
#      set is the `norm.rules` diff class, that swap is red on its own.
esgen="$W/es-frames.py"
cat >"$esgen" <<'PYES'
import base64, json, struct, sys, zlib
def frame(event_type, payload):
    hb = b""
    for n, v in ((":event-type", event_type), (":content-type", "application/json"), (":message-type", "event")):
        nb, vb = n.encode(), v.encode()
        hb += bytes([len(nb)]) + nb + b"\x07" + struct.pack(">H", len(vb)) + vb   # 0x07 = STRING
    pb = json.dumps(payload, separators=(",", ":")).encode()
    pre = struct.pack(">II", 16 + len(hb) + len(pb), len(hb))
    pre += struct.pack(">I", zlib.crc32(pre) & 0xFFFFFFFF)          # prelude CRC32
    msg = pre + hb + pb
    return msg + struct.pack(">I", zlib.crc32(msg) & 0xFFFFFFFF)    # message CRC32
def stream(latency_ms, text):
    return (frame("messageStart", {"role": "assistant"})
            + frame("contentBlockStart", {"contentBlockIndex": 0, "start": {}})
            + frame("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"text": text}})
            + frame("contentBlockStop", {"contentBlockIndex": 0})
            + frame("messageStop", {"stopReason": "end_turn"})
            + frame("metadata", {"metrics": {"latencyMs": latency_ms},
                                 "usage": {"inputTokens": 11, "outputTokens": 7, "totalTokens": 18}}))
which = sys.argv[1]
body = stream(0, "oracle-marker") if which in ("lat0", "corrupt") else \
       stream(2, "oracle-marker") if which == "lat2" else stream(0, "DIFFERENT-TEXT")
if which == "corrupt":
    b = bytearray(body); b[-1] ^= 0xFF; body = bytes(b)
print(json.dumps({"status": 200,
                  "headers": {"content-type": "application/vnd.amazon.eventstream",
                              "content-length": str(len(body))},
                  "body": "base64:" + base64.b64encode(body).decode(),
                  "effects": {}}))
PYES
es_ok=1
for w in lat0 lat2 difftext corrupt; do
  python3 "$esgen" "$w" >"$W/es-$w.cap.json" 2>"$W/es-$w.err" || { es_ok=0; break; }
  python3 "${here}/normalize.py" "$W/es-$w.cap.json" >"$W/es-$w.norm.json" 2>>"$W/es-$w.err" || { es_ok=0; break; }
done
if [ "$es_ok" != 1 ]; then
  say FAIL "eventstream.frames: the fixture or the normalizer errored (see $W/es-*.err)"
else
  raw_differ=0; cmp -s "$W/es-lat0.cap.json" "$W/es-lat2.cap.json" || raw_differ=1
  norm_equal=0; cmp -s "$W/es-lat0.norm.json" "$W/es-lat2.norm.json" && norm_equal=1
  norm_differ=0; cmp -s "$W/es-lat0.norm.json" "$W/es-difftext.norm.json" || norm_differ=1
  rules="$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))["applied"]))' "$W/es-lat0.norm.json")"
  bad_rules="$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))["applied"]))' "$W/es-corrupt.norm.json")"
  [ "$raw_differ" = 1 ] && [ "$norm_equal" = 1 ] \
    && say PASS "eventstream.frames: latencyMs 0 vs 2 differ on the wire, equal after normalization" \
    || say FAIL "eventstream.frames: latencyMs 0 vs 2 raw_differ=$raw_differ norm_equal=$norm_equal"
  [ "$norm_differ" = 1 ] \
    && say PASS "eventstream.frames: a real payload difference inside a frame is still UNEQUAL after" \
    || say FAIL "eventstream.frames: a changed contentBlockDelta normalized to the same bytes — the rule is hiding content"
  case ",$rules," in *,eventstream.frames,*) f1=1 ;; *) f1=0 ;; esac
  case ",$rules," in *,metrics.timing,*) f2=1 ;; *) f2=0 ;; esac
  [ "$f1" = 1 ] && [ "$f2" = 1 ] \
    && say PASS "eventstream.frames: the rule and metrics.timing both fire (the payload went through the JSON path)" \
    || say FAIL "eventstream.frames: applied=$rules (wanted eventstream.frames AND metrics.timing)"
  case ",$bad_rules," in *,eventstream.undecodable,*) c1=1 ;; *) c1=0 ;; esac
  case ",$bad_rules," in *,eventstream.frames,*) c2=1 ;; *) c2=0 ;; esac
  [ "$c1" = 1 ] && [ "$c2" = 0 ] \
    && say PASS "eventstream.frames: a flipped message CRC -> eventstream.undecodable, never a clean decode" \
    || say FAIL "eventstream.frames: corrupt stream applied=$bad_rules (wanted undecodable, not frames)"
fi

echo
[ "$fails" -eq 0 ] && echo "replay selftest: GREEN" || { echo "replay selftest: RED ($fails)"; exit 1; }
