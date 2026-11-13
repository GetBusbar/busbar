#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build sources come only from the forge (GitHub is a read-only replica). Source this
# file in a CI job: every git (and `cargo` with CARGO_NET_GIT_FETCH_WITH_CLI) URL under
# https://github.com/GetBusbar/ and each reviewed upstream fork is rewritten to the
# forge, and every other https://github.com/ URL to an unroutable host, so a stray
# fetch fails loudly instead of reading the replica (native_sources.py l.22-50).
# Git applies the longest matching insteadOf, so the exact mappings win.
#
# Outside CI (no CI_SERVER_URL / CI_JOB_TOKEN) it does nothing.

forge_setup() {
  if [ -z "${CI_SERVER_URL:-}" ] || [ -z "${CI_JOB_TOKEN:-}" ]; then
    return 0
  fi
  local server="${CI_SERVER_URL%/}" index=0 auth
  auth="$(printf 'gitlab-ci-token:%s' "$CI_JOB_TOKEN" | base64 | tr -d '\n')"
  forge_set() {
    export "GIT_CONFIG_KEY_${index}=$1" "GIT_CONFIG_VALUE_${index}=$2"
    index=$((index + 1))
  }
  forge_set "http.${server}/.extraheader" "Authorization: Basic ${auth}"
  forge_set "url.${server}/GetBusbar/.insteadOf" "https://github.com/GetBusbar/"
  local fork
  for fork in \
    MattJackson/aws-lc-sys:aws-lc-sys \
    MattJackson/jobserver-rs:jobserver-rs \
    MattJackson/rust-stringprep:rust-stringprep \
    MattJackson/dunce:dunce \
    MattJackson/fs_extra:fs_extra \
    MattJackson/h2:h2 \
    MattJackson/tungstenite-rs:tungstenite-rs \
    headroomlabs-ai/headroom:headroom; do
    forge_set "url.${server}/GetBusbar/upstream-forks/${fork#*:}.insteadOf" "https://github.com/${fork%%:*}"
  done
  forge_set "url.https://public-replica-refused.invalid/.insteadOf" "https://github.com/"
  export GIT_CONFIG_COUNT="$index" GIT_TERMINAL_PROMPT=0 CARGO_NET_GIT_FETCH_WITH_CLI=true
  unset -f forge_set
}
