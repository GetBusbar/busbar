#!/usr/bin/env bash
# conformance-serve.sh - launch this crate's HTTP conformance host for a black-box harness.
#
# Contract (see the harness that calls this): serve on OAUTH_AS_ADDR, honor
# OAUTH_AS_CONFORMANCE_SEED=1, and block until killed. `cargo run` execs the built example on
# Unix, so this process's PID stays the server's PID and a plain `kill` stops it.
set -euo pipefail
cd "$(dirname "$0")"
exec cargo run --locked -p oauth-as --example conformance_server
