//! **THE FEE IS DECIDED ONCE, AND THE KERNEL DECIDES IT.**
//!
//! The flat per-request fee had two deciders on the llm plane and one everywhere else. The kernel's
//! is `busbar_kernel::teller::fee_count` over a `FeeEvidence` the composition root builds — the same
//! function `units_mcp`, `units_a2a` and `units_voice` already price their records through, under a
//! comment that states the rule out loud: *"The record does not decide the fee a second time. It
//! reads the same evidence the exit path settles from, through the same function, so a row that says
//! one fee and a posting that says none cannot both be true of one unit."*
//!
//! The llm plane decided it a second time. `busbar-llm/src/unit/meter.rs` answered
//! `u32::from(delivered && ctx.upstream_leg)` — two booleans — and carried that count out on the
//! late report, which is the number that reached `Posting::from_usage` and therefore the number that
//! BILLED. The kernel's answer was computed on the same request and discarded.
//!
//! This cell is the byte-identity proof that retiring the second decider does not move money.
//!
//! # What is asserted, and in which direction
//!
//! **Arm 1 — the recorded corpus (`recorded_cells_agree`).** Every recorded llm cell of the three
//! families where a status frame and a plane finish can disagree — 36 `upstream_down`, 30
//! `ok_stream` — carried below as the facts the two deciders read, transcribed from
//! `testing/shadow-oracle/golden/1.5.5`. Both deciders are driven over every one and must answer the
//! same count, and that count must be the count the golden billed. This arm is the money guarantee:
//! while it is green, the MOVE is byte-identical on everything the node has ever recorded.
//!
//! **Arm 2 — the fact cube (`the_two_rules_are_not_the_same_rule`).** The two rules are NOT the same
//! expression, and arm 1 passing is not evidence that they are — it is evidence that the corpus
//! never reaches the combinations where they part. This arm drives the full boolean cube of the
//! facts and names those combinations. It is the honest statement of what arm 1 does not cover.
//!
//! # The gap this cell cannot close
//!
//! The six `llm|…|stream_upstream_error` cells are the family where a 200 head and a mid-stream
//! error finish genuinely disagree — the one case the kernel's dispute arm exists for. They are
//! **SKIP** on the golden: *"named gap: the fixture this cell needs is not in the tree yet"*. There
//! is no recorded evidence of the disagreeing case, so no arm below drives it.
//!
//! It does not block the MOVE, and the reason is structural rather than statistical: the root leg
//! builds its `FeeEvidence` with `status_at: None` — this transport reports no status leg of its
//! own, the response IS the status — so `by_status` is always `None` and the dispute arm is
//! **unreachable on this plane** whatever the fixtures say. See `dispute_arm_is_unreachable`.

use busbar_contract::FinishClass;
use busbar_kernel::teller::{fee_count, FeeEvidence};

/// One recorded cell, reduced to the facts the two deciders read.
///
/// `name` is the golden's cell id with its leading family segment implied: every cell below is an
/// `llm|…` cell, the family is stated once in the module header, and spelling it 66 more times
/// would be this test file teaching the composition root a plane's name 66 times over. Prefix it
/// back to look one up in `ledger.tsv`.
///
/// Transcribed from `golden/1.5.5/cells/llm__*__{upstream_down,ok_stream}.json`:
/// `status` is the cell's client-facing `status`; `upstream_leg` is whether the recording shows a
/// dial (a non-empty `effects.egress`, or a `busbar_upstream_attempts_total` metric);
/// `upstream_candidate` is whether a destination resolved (a `pool=` label on any metric);
/// `billed` is the flat fee the golden charged, read off `effects.usage.spend_cents`.
///
/// `effects.usage.requests` is NOT the fee: it is the request SLOT, drawn at the door and never
/// released, which is why every `upstream_down` cell records `requests: 1` against a fee of zero.
struct Cell {
    name: &'static str,
    status: u16,
    upstream_leg: bool,
    upstream_candidate: bool,
    client_origin: bool,
    billed: u32,
}

/// THE KERNEL'S DECIDER, reached over the evidence the root leg actually builds for this plane
/// (`units_llm.rs`'s `evidence()`): no status leg, and a finish read off the client-facing status.
fn kernel_fee(c: &Cell) -> u32 {
    let status = Some(c.status);
    fee_count(&FeeEvidence {
        client_open_or_one_shot: c.client_origin,
        selected_upstream: c.upstream_candidate,
        relayed_first_response_frame: status.is_some(),
        status_at: None,
        status: None,
        finish: status.map(|s| {
            if (200..300).contains(&s) {
                FinishClass::Complete
            } else {
                FinishClass::Error
            }
        }),
    })
    .0
}

/// THE PLANE'S SECOND DECIDER, verbatim as `busbar-llm/src/unit/meter.rs` answered it:
/// `u32::from(delivered && ctx.upstream_leg)`, where `delivered` is `matches!(status, 200..=299)`.
///
/// Kept here after the MOVE deletes it from the plane, because a byte-identity cell whose second
/// side has been removed proves nothing. This is the retired rule, held as a reference so the
/// identity stays checkable.
fn retired_plane_fee(c: &Cell) -> u32 {
    let delivered = matches!(c.status, 200..=299);
    u32::from(delivered && c.upstream_leg)
}

/// The recorded facts of the three families. See [`Cell`] for provenance.
///
/// The 6 `llm|…|stream_upstream_error` cells of the third family are absent because they are absent
/// from the golden — SKIP, a named gap. See the module header.
const RECORDED: &[Cell] = &[
    Cell {
        name: "anthropic|anthropic|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "anthropic|anthropic|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "anthropic|bedrock|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "anthropic|bedrock|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "anthropic|cohere|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "anthropic|cohere|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "anthropic|gemini|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "anthropic|openai|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "anthropic|openai|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "anthropic|responses|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "anthropic|responses|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "bedrock|anthropic|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "bedrock|anthropic|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "bedrock|bedrock|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "bedrock|bedrock|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "bedrock|cohere|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "bedrock|cohere|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "bedrock|gemini|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "bedrock|openai|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "bedrock|openai|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "bedrock|responses|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "bedrock|responses|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "cohere|anthropic|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "cohere|anthropic|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "cohere|bedrock|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "cohere|bedrock|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "cohere|cohere|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "cohere|cohere|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "cohere|gemini|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "cohere|openai|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "cohere|openai|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "cohere|responses|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "cohere|responses|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "gemini|anthropic|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "gemini|anthropic|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "gemini|bedrock|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "gemini|bedrock|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "gemini|cohere|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "gemini|cohere|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "gemini|gemini|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "gemini|openai|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "gemini|openai|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "gemini|responses|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "gemini|responses|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "openai|anthropic|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "openai|anthropic|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "openai|bedrock|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "openai|bedrock|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "openai|cohere|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "openai|cohere|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "openai|gemini|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "openai|openai|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "openai|openai|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "openai|responses|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "openai|responses|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "responses|anthropic|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "responses|anthropic|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "responses|bedrock|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "responses|bedrock|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "responses|cohere|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "responses|cohere|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "responses|gemini|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "responses|openai|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "responses|openai|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
    Cell {
        name: "responses|responses|request|ok_stream",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "responses|responses|request|upstream_down",
        status: 503,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 0,
    },
];

/// **ARM 1 — THE MONEY GUARANTEE.** Both deciders, over every recorded cell, against the golden.
///
/// A divergence here is a money finding and stops the MOVE: it would mean retiring the plane's
/// decider changes a count the node has actually billed.
#[test]
fn recorded_cells_agree_with_each_other_and_with_the_golden() {
    let mut diverged = Vec::new();
    for cell in RECORDED {
        let kernel = kernel_fee(cell);
        let plane = retired_plane_fee(cell);
        if kernel != plane || kernel != cell.billed {
            diverged.push(format!(
                "  {:<48} status={:<3} kernel={} plane={} golden={}",
                cell.name, cell.status, kernel, plane, cell.billed
            ));
        }
    }
    assert!(
        diverged.is_empty(),
        "the two fee deciders disagree on {} recorded cell(s), or disagree with what the golden \
         billed — this is a money finding and the MOVE stops here:\n{}",
        diverged.len(),
        diverged.join("\n")
    );
    // The corpus has to actually contain both answers, or the assertion above is vacuous.
    assert_eq!(RECORDED.len(), 66, "the recorded corpus changed size");
    assert_eq!(
        RECORDED.iter().filter(|c| c.billed == 1).count(),
        30,
        "the 30 ok_stream cells are the ones that bill"
    );
}

/// **ARM 2 — WHAT ARM 1 DOES NOT COVER.** The two rules are different expressions.
///
/// The kernel asks four things — the origin is a client's, a destination resolved, a first response
/// frame was relayed, and the finish was not an error. The retired plane rule asked two — the client
/// saw a 2xx, and a dial happened. They part in two directions:
///
/// * `origin != Client`: the plane rule bills, the kernel does not. The plane had no origin to read,
///   so it could not ask; the root leg's `evidence()` reads `ctx.origin` and does.
/// * a 2xx with a resolved destination but no dial: the kernel bills, the plane did not.
///
/// This test PINS that difference rather than asserting it away. If it ever comes back empty, the
/// two rules have converged and arm 1's guarantee has become an identity — which would be a better
/// world, and a deliberate change, not something to discover by accident.
#[test]
fn the_two_rules_are_not_the_same_rule() {
    let mut parted = Vec::new();
    for &status in &[200u16, 503] {
        for &upstream_leg in &[false, true] {
            for &upstream_candidate in &[false, true] {
                for &client_origin in &[false, true] {
                    let cell = Cell {
                        name: "cube",
                        status,
                        upstream_leg,
                        upstream_candidate,
                        client_origin,
                        billed: 0,
                    };
                    if kernel_fee(&cell) != retired_plane_fee(&cell) {
                        parted.push((status, upstream_leg, upstream_candidate, client_origin));
                    }
                }
            }
        }
    }
    assert!(
        !parted.is_empty(),
        "the two rules answer alike on the whole cube; they are one expression and this pin is stale"
    );
    // Every parting is a 2xx — below a 2xx both rules answer zero, whatever else is true.
    assert!(
        parted.iter().all(|p| p.0 == 200),
        "the rules part only on a delivered response: {parted:?}"
    );
    // And no recorded cell reaches any of them, which is exactly why arm 1 is green.
    for cell in RECORDED {
        assert!(
            !parted.contains(&(
                cell.status,
                cell.upstream_leg,
                cell.upstream_candidate,
                cell.client_origin
            )),
            "{} reaches a fact combination the two rules disagree on",
            cell.name
        );
    }
}

/// **THE DISPUTE ARM IS UNREACHABLE ON THIS PLANE**, and that is what makes the missing
/// `stream_upstream_error` fixtures not a blocker.
///
/// `fee_count` raises `METER_DISPUTED` only where a transport contributes a status leg — either by
/// reporting a `StatusClass` that contradicts the plane's `FinishClass`, or by declaring a
/// `status_at` and then losing the frame that carries it. The llm root leg builds neither: the
/// response IS the status, so `status_at` and `status` are both `None` on every unit this plane
/// runs. Whatever the unrecorded mid-stream failure would have looked like, it could not have
/// reached the dispute arm.
#[test]
fn dispute_arm_is_unreachable_for_the_llm_plane() {
    for &finish in &[
        FinishClass::Complete,
        FinishClass::TurnComplete,
        FinishClass::Error,
    ] {
        for &client in &[false, true] {
            for &upstream in &[false, true] {
                for &relayed in &[false, true] {
                    let (_, flags) = fee_count(&FeeEvidence {
                        client_open_or_one_shot: client,
                        selected_upstream: upstream,
                        relayed_first_response_frame: relayed,
                        // The two fields the root leg pins to `None` for this transport.
                        status_at: None,
                        status: None,
                        finish: Some(finish),
                    });
                    assert!(
                        !flags.contains(busbar_caps::PostingFlags::METER_DISPUTED),
                        "a unit this plane can build raised METER_DISPUTED: \
                         finish={finish:?} client={client} upstream={upstream} relayed={relayed}"
                    );
                }
            }
        }
    }
}
