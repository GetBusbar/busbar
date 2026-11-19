#!/bin/sh
# classify2.sh <root-dir> : one row per .rs file under root: path total test doc comment blank code
# ONE METHOD for every tree:
#  test    = whole file when under tests/ or benches/ or named *_tests.rs, *_test.rs, tests.rs, test_*.rs;
#            otherwise the lines of each inline `#[cfg(test)] mod x { ... }` block (to the closing brace in column 0)
#  doc     = lines starting /// or //!   comment = other lines starting //   blank = empty
#  code    = everything else
cd "$1" || exit 1
find . -name '*.rs' -not -path '*/target/*' -not -path '*/vendor/*' -not -path '*/.git/*' | sed 's|^\./||' | while read -r f; do
  awk -v path="$f" '
  BEGIN { whole = (path ~ /(^|\/)tests\// || path ~ /(^|\/)benches\// || path ~ /_tests?\.rs$/ || path ~ /(^|\/)tests\.rs$/ || path ~ /(^|\/)test_[a-z_0-9]*\.rs$/) }
  {
    total++
    if (whole) { test++; next }
    if (intest) { test++; if ($0 ~ /^}/) intest=0; next }
    if ($0 ~ /^#\[cfg\(test\)\]/) { pend=NR; held=1; next }
    if (pend && NR-pend<=3 && $0 ~ /^(pub(\([a-z]+\))? )?mod [a-z_0-9]+ *\{/) { test+=held+1; intest=1; pend=0; held=0; next }
    if (pend && NR-pend<=3 && $0 ~ /^#\[/) { held++; next }
    if (pend) { code+=held; pend=0; held=0 }
    s=$0; sub(/^[ \t]+/, "", s)
    if (s=="") blank++
    else if (s ~ /^\/\/[\/!]/) doc++
    else if (s ~ /^\/\//) comment++
    else code++
  }
  END { printf "%s %d %d %d %d %d %d\n", path, total, test, doc, comment, blank, code+held }' "$f"
done
