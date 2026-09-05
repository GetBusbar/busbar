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
run_args() { local g="$1" c="$2" o="$3"; shift 3; bash "${here}/replay.sh" --golden "$g" --candidate "$c" --out "$o" --cells "$CELLS" "$@" >"$o.log" 2>&1; echo $?; }
run() { run_args "$1" "$2" "$3" --allow-harness-skew --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt"; }
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

# (g) a cell's own `compare` list drops every OTHER class — mutate status AND usage, only usage owed
mkdir -p "$W/gcells"
python3 - "$CELLS" "$W/gcells/cells.json" <<'EOF'
import json,sys
d=json.load(open(sys.argv[1]))
for c in d["cells"]:
    if c["id"] == "self|a|ok":
        c["compare"] = ["effects.usage"]
json.dump(d, open(sys.argv[2], "w"))
EOF
cp -R "$FIX" "$W/compare"
python3 - "$W/compare/cells/self__a__ok.json" <<'EOF'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["status"]=418; d["effects"]["usage"]["spend_micros"]=19; json.dump(d,open(p,"w"),separators=(",",":"),sort_keys=True)
EOF
# run_args hard-codes --cells "$CELLS"; call replay.sh directly here so the compare-list cells.json is used.
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/compare" --out "$W/out-g" --cells "$W/gcells/cells.json" \
  --allow-harness-skew --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-g.log" 2>&1
rc=$?
cls="$(classes_of 'self|a|ok' "$W/out-g")"
[ "$rc" != 0 ] && [ "$cls" = "effects.usage" ] && say PASS "cell 'compare' list -> only its named class shows (status dropped)" || say FAIL "compare list rc=$rc classes=$cls (expected effects.usage only, status must not appear)"

# (h) an `improvement` acceptance of a `status` class must be REFUSED by the loader (exit != 0),
# even when golden and candidate are byte-identical — the register is checked whether or not it
# ever fires.
cat >"$W/bad-accept.json" <<'JSON'
{"accepted":[{"id":"bad status accept","kind":"improvement","by":"selftest","cells":"^self\\|a\\|ok$","classes":["status"],"rationale":"should be refused"}]}
JSON
cp -R "$FIX" "$W/hsame"
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/hsame" --out "$W/out-h" --cells "$CELLS" \
  --allow-harness-skew --accepted "$W/bad-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-h.log" 2>&1
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
{"accepted":[{"id":"T-1 test token","kind":"improvement","by":"selftest","cells":"^self\\|b\\|stream$","rationale":"selftest transform proof","transform":{"candidate":[[" TOKEN123",""]]}}]}
JSON
bash "${here}/replay.sh" --golden "$FIX" --candidate "$W/xform" --out "$W/out-i" --cells "$CELLS" \
  --allow-harness-skew --accepted "$W/xform-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-i.log" 2>&1
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
  --allow-harness-skew --accepted "$W/no-accept.json" --baseline "$W/baseline-ab.txt" --accepted-gaps "$W/no-gaps.json" >"$W/out-j.log" 2>&1
rc=$?
row="$(awk -F'\t' '$1=="self|a|ok"{print; exit}' "$W/out-j/ledger.tsv")"
status_col="$(cut -f2 <<<"$row")"; title_col="$(cut -f3 <<<"$row")"
[ "$rc" != 0 ] && [ "$status_col" = FAIL ] && [[ "$title_col" == *"owed-baseline"* ]] && say PASS "golden dropped a baselined id, unnamed -> RED [owed-baseline regression]" || say FAIL "baseline regression rc=$rc status=$status_col title=$title_col"

# (k) the same regression, named in accepted-gaps.json -> GREEN with a named-gap line
cat >"$W/gaps-ab.json" <<'JSON'
{"accepted":[{"id":"selftest gap self|a|ok","cells":"^self\\|a\\|ok$","owner":"selftest","rationale":"intentionally dropped for this test"}]}
JSON
bash "${here}/replay.sh" --golden "$W/regress-golden" --candidate "$W/regress-cand" --out "$W/out-k" --cells "$CELLS" \
  --allow-harness-skew --accepted "$W/no-accept.json" --baseline "$W/baseline-ab.txt" --accepted-gaps "$W/gaps-ab.json" >"$W/out-k.log" 2>&1
rc=$?
row="$(awk -F'\t' '$1=="self|a|ok"{print; exit}' "$W/out-k/ledger.tsv")"
status_col="$(cut -f2 <<<"$row")"; title_col="$(cut -f3 <<<"$row")"
[ "$rc" = 0 ] && [ "$status_col" = PASS ] && [[ "$title_col" == *"ACCEPTED named gap"* ]] && say PASS "same regression named in accepted-gaps.json -> GREEN, named-gap line" || say FAIL "accepted gap rc=$rc status=$status_col title=$title_col"

# (l) golden/candidate produced by different (or absent) harness revisions -> exit 2, no comparison
cp -R "$FIX" "$W/hrev-g"; cp -R "$FIX" "$W/hrev-c"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); d['harness_rev']='a'*64; json.dump(d, open(sys.argv[1],'w'))" "$W/hrev-g/meta.json"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); d['harness_rev']='b'*64; json.dump(d, open(sys.argv[1],'w'))" "$W/hrev-c/meta.json"
bash "${here}/replay.sh" --golden "$W/hrev-g" --candidate "$W/hrev-c" --out "$W/out-l" --cells "$CELLS" \
  --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-l.log" 2>&1
rc=$?
grep -qi "harness" "$W/out-l.log" && msg_ok=1 || msg_ok=0
[ "$rc" = 2 ] && [ "$msg_ok" = 1 ] && say PASS "mismatched harness_rev -> exit 2, named in the message" || say FAIL "harness_rev mismatch rc=$rc msg_ok=$msg_ok"

# (m) --allow-harness-skew on that same mismatched pair -> proceeds to a normal verdict
bash "${here}/replay.sh" --golden "$W/hrev-g" --candidate "$W/hrev-c" --out "$W/out-m" --cells "$CELLS" \
  --allow-harness-skew --accepted "$W/no-accept.json" --baseline "$W/no-baseline.txt" >"$W/out-m.log" 2>&1
rc=$?
[ "$rc" = 0 ] && [ "$(fails_in "$W/out-m")" = 0 ] && say PASS "--allow-harness-skew proceeds past the same mismatch" || say FAIL "--allow-harness-skew rc=$rc fails=$(fails_in "$W/out-m")"

echo
[ "$fails" -eq 0 ] && echo "replay selftest: GREEN" || { echo "replay selftest: RED ($fails)"; exit 1; }
