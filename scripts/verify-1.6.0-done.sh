#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): why the voice harness does not build, why the h2
# busbars do not boot, and why a2a-sdk does not install. Compact output at the end of the log.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
( . testing/voice-conformance/lib/conform-bin.sh; voice_conform_bin ) >"$D/vcb.out" 2>"$D/vcb.err"; vrc=$?
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
MCP_SUBJECT_BUSBAR_BIN="$R/target/release/busbar" H2_WORK="$D/mh2" bash scripts/mcp-subject/h2-meter-row.sh >"$D/mh2.out" 2>"$D/mh2.err"
A2A_SUBJECT_BUSBAR_BIN="$R/target/release/busbar" H2_WORK="$D/ah2" bash scripts/a2a-subject/h2-meter-row.sh >"$D/ah2.out" 2>"$D/ah2.err"
python3 -m pip download --no-deps -d "$D/pipdl" a2a-sdk==1.1.2 >"$D/pip.out" 2>&1; prc=$?
echo "######## SUMMARY ########"
echo "VCB rc=$vrc out=$(cat "$D/vcb.out") env: $(env | grep -E '^CARGO_(TARGET|BUILD)' | tr '\n' ' ')"
grep -vE '^\s*$' "$D/vcb.err" | grep -vE '^\s+(Compiling|Finished|Blocking|Downloaded|Updating|Locking)' | head -n 8 | cut -c1-220
ls -la target/debug/voice_conform target/debug/libbusbar_plane_streaming_plugin.so 2>&1 | cut -c1-160
echo "BUILD rc=$brc"
echo "MCP-H2: $(head -c 200 "$D/mh2.out")"
f="$(find "$D/mh2" -name busbar.log 2>/dev/null | head -1)"; [ -n "$f" ] && grep -vE '^\s*$' "$f" | head -n 6 | cut -c1-260
grep -vE '^\s*$' "$D/mh2.err" | head -n 3 | cut -c1-200
echo "A2A-H2: $(head -c 200 "$D/ah2.out")"
f="$(find "$D/ah2" -name busbar.log 2>/dev/null | head -1)"; [ -n "$f" ] && grep -vE '^\s*$' "$f" | head -n 6 | cut -c1-260
echo "PY: $(python3 --version 2>&1) pip rc=$prc"
grep -vE '^\s*$' "$D/pip.out" | tail -n 3 | cut -c1-220
exit 1
