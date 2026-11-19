#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DONE statement 5, the verdict: a launcher. The judgment is Rust (`perf-bar compare`, in
# tools/perf-bar/src/main.rs): the candidate's middle repetition beside the baseline's middle and
# worst; PASS, PASS*, FAIL, NOT MEASURED; exit 0 only when nothing failed and nothing is unmeasured.
#
#   bar-compare.sh <rows.tsv> <baseline label> <candidate label>
set -eu
here=$(cd "$(dirname "$0")" && pwd)
exec "${PERF_BAR:-$here/../../tools/perf-bar/target/release/perf-bar}" compare "$@"
