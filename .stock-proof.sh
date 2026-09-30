set -o pipefail
cargo build -q -p xtask 2>&1 | tail -3
echo "=== HEAD gates"; cargo xtask gate --all > /tmp/g_head.txt 2>&1; echo "rc=$?"
echo "=== selftest"; cargo xtask full-gate --selftest > /tmp/st.txt 2>&1; echo "selftest rc=$?"; tail -5 /tmp/st.txt
git checkout -q dac216977 -- docs testing/shadow-oracle
echo "=== BASE gates"; cargo xtask gate --all > /tmp/g_base.txt 2>&1; echo "rc=$?"
git checkout -q HEAD -- docs testing/shadow-oracle
grep -E '^(PASS|FAIL|RED|GREEN|ok|FAILED)|: (PASS|FAIL|RED|GREEN)' /tmp/g_head.txt | sort > /tmp/h.s
grep -E '^(PASS|FAIL|RED|GREEN|ok|FAILED)|: (PASS|FAIL|RED|GREEN)' /tmp/g_base.txt | sort > /tmp/b.s
echo "=== DIFF base->head (lines only in head = new, only in base = gone)"; diff /tmp/b.s /tmp/h.s | head -80
echo "=== head tail"; tail -40 /tmp/g_head.txt
