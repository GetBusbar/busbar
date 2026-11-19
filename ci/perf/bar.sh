#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DONE statement 5, the measurement: a launcher. The runner is Rust (`perf-bar run`, in
# tools/perf-bar/src/main.rs: the method, the counts and the server directory layout are stated
# there). Runs on the measurement machine only, never on a laptop.
#
#   bar.sh <out.tsv> <reps> <server-dir> [<server-dir> ...]     (SMOKE=1 for a rehearsal)
set -eu
out=$1
shift
here=$(cd "$(dirname "$0")" && pwd)
exec "${PERF_BAR:-$here/../../tools/perf-bar/target/release/perf-bar}" run "$@" > "$out"
