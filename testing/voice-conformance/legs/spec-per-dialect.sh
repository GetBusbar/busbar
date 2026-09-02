# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# LEG: spec-per-dialect — the voice conformance spec, run once PER DIALECT.
#
# The matrix is the two dialects busbar's voice plane will speak: openai and gemini. Each slice runs
# the full spec battery against that dialect's peer and holds it to the dialect's own required
# scenario set (set equality, never a floor — see the sibling MCP `assert_covered`).
#
# STATUS: pending. The voice runtime does not exist yet, and neither do the fixtures this leg will
# consume (another agent authors `testing/voice-conformance/fixtures/{openai,gemini}/`). This file
# is the DROP-IN point: when the runtime lands, flip LEG_STATUS to `ready` and implement
# `leg_execute` so it prints one `RESULT <slice> <PASS|FAIL> <detail>` line per asserted scenario.
# The runner will then hold a ready-but-empty run to RED automatically (the vacuous-ready trap).

LEG_KIND=conformance
LEG_STATUS=pending
LEG_SLICES=(openai gemini)

leg_execute() {
  local dialect="$1"
  # DROP-IN: boot the pinned dialect peer, drive the spec battery against
  # testing/voice-conformance/fixtures/$dialect/, and emit one RESULT line per required scenario:
  #   echo "RESULT $dialect PASS <scenario-id>"
  #   echo "RESULT $dialect FAIL <scenario-id> — <why>"
  die "spec-per-dialect[$dialect]: not implemented — the voice runtime does not exist yet (scaffold)"
}
