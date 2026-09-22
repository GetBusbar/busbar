#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-card-epoch` -- H2 (ARCHITECTURE.md #2.2 step 6, METER) for the MCP
# plane: the DATED-CARD question (#79). It is the mcp twin of the oracle cell
# `billing|rate-card|history-mid-window` (testing/shadow-oracle/scripts/rate-card-history.sh), which
# asks the same thing of the llm plane and can never ask it of this one -- the golden is 1.5.5, 1.5.5
# had no mcp plane, and every one of the corpus's 912 mcp rows reads SKIP.
#
# THE RULE, in the decision's own words: "'Price against the latest rate card' means the latest card
# whose `effective_from` had arrived at the posting's instant -- NOT the latest card ever authored
# ... Publishing a new card never reprices the window before its `effective_from`." The resolution
# key is the posting's own arrival instant (`arrived_ms`), not a version stamped into the posting.
#
# THE DIMENSION THIS LEG MOVES IS THE FLAT FEE, and that is decision-backed rather than convenient.
# #44: "A flat/static fee is ONE plane-agnostic pricing dimension on the rate card (applied
# per-request or per-session), identical for every plane, and NEVER rounded." It is also the ONLY
# dimension of this card an mcp deployment can move at all: the card's other dimensions are the four
# LLM token tiers keyed by `models:` name, and this plane's declared classes (`tool_calls`, `bytes`)
# are neither -- which h2-class-price.sh asks directly. Never rounded is what makes the arithmetic
# below exact rather than approximate.
#
# THE SHAPE. Two dated cards, one call under each:
#
#   boot                    card 0: per_request_fee 1   (effective_from 0 -- `HistorySeq::OPENING`,
#                                                        because `RootHistory::apply` dates a node's
#                                                        FIRST card from zero, kernel.rs:264)
#   call A                  arrives inside card 0's window
#   PUT /config/settings    card 1: per_request_fee 7   (effective_from = the apply's instant, and
#                                                        it CLOSES NOTHING -- card 0 goes on
#                                                        answering for every instant before it)
#   re-approve              the live apply rebuilds the App and the registry returns unapproved
#   call B                  arrives inside card 1's window
#   GET keys/<kid>/usage
#
# THE THREE HYPOTHESES SEPARATE ARITHMETICALLY, which is why there are two calls and not one -- one
# call could not tell a correct resolution from one that always returns the opening entry:
#
#   #79, the card in force at each call's own arrived_ms   ->  1 + 7 =  8   EXPECTED
#   reprice off the NEWEST card ever authored              ->  7 + 7 = 14
#   resolve everything to HistorySeq::OPENING, forever     ->  1 + 1 =  2
#
# THE READ IS THE BUDGET CELL (`GET /api/v1/admin/keys/<kid>/usage`), not the metering series:
# `derived_bucket_usage` (governance/state.rs:1581) reads a cell that survives the live config swap,
# while the write-behind metering buffer does not -- a leg that spans an apply and read
# `GET /admin/usage` would be measuring the swap as well as the card.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/mcp-card-epoch.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

failures=0
detail=""

read -r kid tok <<<"$(h2_mint h2-oracle)"
[ -n "$tok" ] || { h2_verdict FAIL "mint failed"; exit 1; }
bound="$(h2_bind "$tok")"

# ── CALL A, under card 0 (fee 1) ──────────────────────────────────────────────────────────────────
read -r a_status _ <<<"$(h2_call "$bound" "under-card-0")"
[ "$a_status" = "200" ] || { failures=$((failures+1)); detail="${detail}call_A_status=${a_status}(want 200); "; }
spend_a="$(h2_usage_field "$kid" spend_cents)"
[ "$spend_a" -eq 1 ] || { failures=$((failures+1)); detail="${detail}spend after call A = ${spend_a}(want 1, card 0's fee -- the rest of this leg is meaningless if the opening card does not price its own window); "; }

# ── CARD 1 ────────────────────────────────────────────────────────────────────────────────────────
apply="$(h2_put_fee 7)"
case "$apply" in
  *'"applied":true'*) ;;
  *) failures=$((failures+1)); detail="${detail}the second card did not apply: ${apply}; " ;;
esac

# THE SAME ONE CALL, READ AGAIN. Nothing has been served since, so any movement here is a reprice of
# a window that closed before card 1 was even authored -- the exact act #79 forbids.
spend_reread="$(h2_usage_field "$kid" spend_cents)"
[ "$spend_reread" -eq 1 ] || { failures=$((failures+1)); detail="${detail}publishing card 1 moved call A's price from 1 to ${spend_reread} with nothing served in between (#79: publishing a new card never reprices the window before its effective_from); "; }

# ── CALL B, under card 1 (fee 7) ──────────────────────────────────────────────────────────────────
h2_approve_server || { failures=$((failures+1)); detail="${detail}re-approval after the live apply failed; "; }
read -r b_status _ <<<"$(h2_call "$bound" "under-card-1")"
[ "$b_status" = "200" ] || { failures=$((failures+1)); detail="${detail}call_B_status=${b_status}(want 200); "; }

total="$(h2_usage_field "$kid" spend_cents)"
if [ "$total" -ne 8 ]; then
  failures=$((failures+1))
  case "$total" in
    14) why="every posting priced at the NEWEST card ever authored" ;;
    2)  why="every posting priced at HistorySeq::OPENING, forever" ;;
    *)  why="neither of the two named wrong answers (14 = newest-card reprice, 2 = opening-forever)" ;;
  esac
  detail="${detail}two calls either side of a dated card total ${total}(want 8 = 1 + 7, each call at the card in force at its own arrived_ms): ${why}; "
fi

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "two calls either side of a dated card totalled 8 = 1 + 7: each priced at the card in force at its own arrived_ms, not the newest and not the opening entry"
else
  h2_verdict FAIL "$detail"
fi
