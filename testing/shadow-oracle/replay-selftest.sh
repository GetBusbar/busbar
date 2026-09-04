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
# Uses the tiny tracked fixture recording under fixtures/selftest-recording.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
FIX="${here}/fixtures/selftest-recording"
CELLS="${FIX}/cells.json"
W="$(mktemp -d "${TMPDIR:-/tmp}/oracle-replay-selftest.XXXXXX")"
trap 'rm -rf "$W"' EXIT
fails=0
say() { printf '%s  %s\n' "$1" "$2"; [ "$1" = PASS ] || fails=$((fails+1)); }
run() { bash "${here}/replay.sh" --golden "$1" --candidate "$2" --out "$3" --cells "$CELLS" >"$3.log" 2>&1; echo $?; }
fails_in() { awk -F'\t' '$2=="FAIL"{n++} END{print n+0}' "$1/ledger.tsv"; }
classes_of() { awk -F'\t' -v i="$1" '$1==i{print $3}' "$2/ledger.tsv"; }

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

echo
[ "$fails" -eq 0 ] && echo "replay selftest: GREEN" || { echo "replay selftest: RED ($fails)"; exit 1; }
