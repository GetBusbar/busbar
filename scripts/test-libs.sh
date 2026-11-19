#!/usr/bin/env bash
# The product libraries the root and dist/default tests read by variable, built from the admitted
# product vector (scripts/ci-product-pins.json): one place, called by the CI jobs that run those
# tests (root-tests, mr-red-proof, the root red evidence job) and by a build machine.
#
#   . scripts/test-libs.sh && test_libs            # every library below
#   . scripts/test-libs.sh && test_libs sqlite     # only the named ones
#
# Each library is the product's own plugin crate at its pinned commit, lock checked against the pin
# and SDK checked against the cohort, built `--features dropped-in` in the debug profile. A miss is
# a failure of the job's set-up (return 1), never a skipped test.
#
# Reads: TEST_LIBS_GIT (the forge's GetBusbar group URL; default $CI_SERVER_URL/GetBusbar),
#   TEST_LIBS_SRC (where the pinned sources are fetched; default $CI_PROJECT_DIR/target/test-libs/src;
#   a source already there at the pinned commit is used as it is, so an offline machine works once
#   fetched), TEST_LIBS_OUT (target directories; default $CI_PROJECT_DIR/target/test-libs).
# Writes: one exported variable per library and ci-reports/house/<name>.sha256 and a row of source.jsonl.

# name  variable                              repository
# Only the two the tests still read once the old plugin interface is deleted. The tests that read
# BUSBAR_TEST_TCP_CDYLIB, _HTTP_, _RANKING_, _WEBREQUEST_ and BUSBAR_GOVERNANCE_TEST_PLANE_PLUGIN, and
# those that want a statement from the OIDC product, load through the old door and go with it: they
# get no row here.
TEST_LIBS_TABLE='
sqlite      BUSBAR_TEST_SQLITE_CDYLIB            busbar-store-sqlite
mysql       BUSBAR_TEST_MYSQL_CDYLIB             busbar-store-mysql
'

test_lib() { # test_lib <name> <variable> <repository>
  local name=$1 variable=$2 repo=$3 root pins pin revision lock sdk package image source out built
  root=${CI_PROJECT_DIR:-$(git rev-parse --show-toplevel)} || return 1
  pins=$root/scripts/ci-product-pins.json
  pin=$(jq -ce --arg repo "$repo" '[.products[] | select(.repo == $repo)] | select(length == 1) | .[0]' "$pins") || { echo "test-libs: $repo is not exactly one row of the product vector"; return 1; }
  revision=$(jq -er '.commit | select(test("^[0-9a-f]{40}$"))' <<<"$pin") || return 1
  lock=$(jq -er '.lock_sha256 | select(test("^[0-9a-f]{64}$"))' <<<"$pin") || return 1
  package=$(jq -er '.package' <<<"$pin") || return 1
  image=$(jq -er '.image' <<<"$pin") || return 1
  sdk=$(jq -er '.sdk | select(test("^[0-9a-f]{40}$"))' "$pins") || return 1
  source=${TEST_LIBS_SRC:-$root/target/test-libs/src}/$repo
  out=${TEST_LIBS_OUT:-$root/target/test-libs}/$name
  if [ "$(git -C "$source" rev-parse -q --verify HEAD 2>/dev/null)" != "$revision" ]; then
    rm -rf "$source" && mkdir -p "$source" && git init -q "$source" || return 1
    git -C "$source" fetch -q --depth 1 "${TEST_LIBS_GIT:-${CI_SERVER_URL%/}/GetBusbar}/$repo.git" "$revision" && git -C "$source" checkout -q FETCH_HEAD || { echo "test-libs: $repo at $revision could not be fetched"; return 1; }
  fi
  test "$(git -C "$source" rev-parse HEAD)" = "$revision" || return 1
  test -z "$(git -C "$source" status --porcelain --untracked-files=no)" || { echo "test-libs: $source is not the pinned source"; return 1; }
  printf '%s  %s\n' "$lock" "$source/Cargo.lock" | sha256sum -c --quiet || { echo "test-libs: $repo lock differs from its pin"; return 1; }
  test "$(cut -d' ' -f1 "$source/.busbar-ref")" = "$sdk" || { echo "test-libs: $repo source SDK differs from the declared product cohort"; return 1; }
  cargo build --locked --manifest-path "$source/Cargo.toml" -p "$package" --lib --features dropped-in --target-dir "$out" || return 1
  built=$out/debug/$image
  test -f "$built" || { echo "test-libs: $package built no $image"; return 1; }
  export "$variable=$built"
  mkdir -p "$root/ci-reports/house"
  sha256sum "$built" > "$root/ci-reports/house/$name.sha256"
  jq -n --arg name "$name" --arg variable "$variable" --arg repo "$repo" --arg commit "$revision" --arg sdk "$sdk" \
    '{name:$name,variable:$variable,repo:$repo,commit:$commit,sdk:$sdk,profile:"debug",features:["dropped-in"],trust:"actual test fixture; not signed shipping evidence"}' \
    >> "$root/ci-reports/house/source.jsonl"
  echo "test-libs: $variable=$built ($repo@$revision)"
}

test_libs() { # test_libs [name...]: the named libraries, or every row of the table
  local want=" $* " name variable repo failed=0
  while read -r name variable repo; do
    [ -n "$name" ] || continue
    if [ "$want" != "  " ] && [ "${want#* "$name" }" = "$want" ]; then continue; fi
    test_lib "$name" "$variable" "$repo" || { echo "test-libs: $name ($variable) NOT provisioned"; failed=1; }
  done <<<"$TEST_LIBS_TABLE"
  return "$failed"
}

# The name CI's jobs call today (`k house_sqlite`): the SQLite row of the table.
house_sqlite() { test_lib sqlite BUSBAR_TEST_SQLITE_CDYLIB busbar-store-sqlite; }
