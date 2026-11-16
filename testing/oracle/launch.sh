#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE ORACLE'S PRODUCT (busbar-release planning/design/ORACLE-FIRST.md): core's own `busbar` with the bundled
# plugins loaded from packages, where dist/default compiled them in. common::boot::exe() runs whatever
# BUSBAR_TEST_PRODUCT_BIN names; ci/qa.yml points it at a copy of this file and writes launch.env beside it
# (ORACLE_CORE: the core binary; ORACLE_PLUGINS: the bundled packs; ORACLE_FETCH: their `plugins.fetch` pins, one
# `    - { url, sha256 }` line per pack; ORACLE_FIRST_PARTY_KEY: the key they are signed with), so a child whose
# environment a test cleared still finds them.
#
# Mechanics only. Before it execs core, for the config the test points BUSBAR_CONFIG at (the test's own file):
#   * no top-level `plugins:` -> append `plugins: {enabled: true, dir: <bundled packs>, fetch: <pins>}`, so core
#     loads the bundled set the linked product served without one;
#   * a `plugins:` block of the test's own (block style) -> copy the bundled packs into `<config dir>/plugins`,
#     beside what the test installed there, and add the pins as its `fetch:` unless it has one.
# The pins: core opens a store bootstrap dependency (the store, the secret sources its settings and the
# operator credentials read) only from an archive pinned by SHA-256 in the base config's plugins.fetch
# (busbar-kernel appbuild validate_bootstrap_artifacts); a linked row needed none. Each pin names a file
# already in the directory, so core takes it as cached and never fetches (the URL is never contacted).
# The packs verify first-party through the harness key (core built with test-harness), as linked rows were.
set -u
: "${PATH:=/usr/local/bin:/usr/bin:/bin}"
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 70
. "$here/launch.env" || exit 70
c=${BUSBAR_CONFIG:-}
if [ -n "$c" ] && [ -f "$c" ]; then
  if grep -q '^plugins:' "$c"; then
    d=$(dirname -- "$c")/plugins
    mkdir -p "$d" || exit 70
    for p in "$ORACLE_PLUGINS"/*.tar.gz; do
      [ -e "$p" ] || continue
      [ -e "$d/${p##*/}" ] || cp "$p" "$d/" || exit 70
    done
    if ! grep -q '^  fetch:' "$c"; then
      t=$(awk -v f="$ORACLE_FETCH" '{ print } /^plugins:[[:space:]]*$/ { print "  fetch:"; while ((getline l < f) > 0) print l }' "$c") || exit 70
      printf '%s\n' "$t" > "$c" || exit 70
    fi
  else
    [ -z "$(tail -c 1 "$c")" ] || printf '\n' >> "$c"
    printf 'plugins:\n  enabled: true\n  dir: "%s"\n  fetch:\n' "$ORACLE_PLUGINS" >> "$c" || exit 70
    cat "$ORACLE_FETCH" >> "$c" || exit 70
  fi
fi
BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY=${BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY:-$ORACLE_FIRST_PARTY_KEY}
export BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY
exec "$ORACLE_CORE" "$@"
