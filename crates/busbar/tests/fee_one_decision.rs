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
//! **Arm 3 — the mid-stream family (`recorded_stream_faults_agree`).** The twelve
//! `llm.stream|<dialect>|{cut,stream-error}` cells: the upstream fails AFTER the door has written
//! 200 and the first frames have gone out. This is the case where the two readings of one unit
//! genuinely disagree, and it was a named gap on the golden when the fee's landing went through.
//! It is recorded now, and it is driven here.
//!
//! # WHAT THE GOLDEN CAN AND CANNOT SAY ABOUT A FEE
//!
//! Stated plainly because the `billed` column below reads like a recording and is not one. The
//! oracle's own configuration — `oracle-config.sh`, quoted in the harness: *"prices every model at
//! input 100000 / output 200000 micro-units per token and sets no per-request fee"* — means the
//! flat fee is ZERO CENTS on every `llm` and `llm.stream` cell. So `effects.usage.spend_cents` on
//! those cells is token cost and only token cost, and no recording in that family discriminates a
//! fee COUNT of one from a fee count of zero. There is no fee-only cell anywhere in the golden to
//! calibrate against either.
//!
//! What `billed` therefore is: **1.5.5's own rule evaluated over the recorded facts** — the rule
//! `retired_plane_fee` holds verbatim, which is what the published binary ran. Its agreement with
//! the presence of `spend_cents` across all 78 cells is a CROSS-CHECK on the transcription, not the
//! source of the column. The money statement this cell supports is exactly: the kernel's decider
//! answers what the shipped 1.5.5 decider answered, on every fact combination the node has
//! recorded. It is not, and cannot be, a claim that the golden recorded a fee.

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

/// THE KERNEL'S DECIDER, reached over the evidence the root leg actually builds for this plane —
/// the status leg the plane DECLARES, the class the transport reads at that frame, and the finish
/// the plane gives.
///
/// The finish is an argument because this plane has two moments and they do not have the same
/// answer. At the exit the frame the client saw is the only reading that exists, and the leg
/// derives the finish from it; after the body has drained the tap knows how the stream really
/// ended, and the leg carries that instead. Arm 1's cells are driven at the first; arm 3's at the
/// second.
fn kernel_fee(c: &Cell, finish: FinishClass) -> (u32, busbar_caps::PostingFlags) {
    fee_count(&FeeEvidence {
        client_open_or_one_shot: c.client_origin,
        selected_upstream: c.upstream_candidate,
        relayed_first_response_frame: true,
        status_at: <busbar_plane_llm::LlmPlane as busbar_contract::plane::PlaneMeta>::STATUS_LEG,
        status: Some(busbar_transport_http::status_class(c.status)),
        finish: Some(finish),
    })
}

/// The finish the EXIT arm derives, when the frame the client saw is all there is to read.
fn finish_at_the_exit(c: &Cell) -> FinishClass {
    if (200..300).contains(&c.status) {
        FinishClass::Complete
    } else {
        FinishClass::Error
    }
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

/// **THE MID-STREAM FAMILY**, `llm.stream|<dialect>|{cut,stream-error}`: the door writes 200, the
/// first frames go out, and the upstream then fails — announced in the dialect's own error shape
/// (`stream-error`) or not announced at all (`cut`).
///
/// Transcribed from `golden/1.5.5/cells/llm.stream__*.json`. Every one of the twelve records
/// `status: 200`, a single `busbar_upstream_attempts_total` metric (the dial happened, the lane
/// answered), `effects.usage.requests: 1` — the slot, drawn and never released — and NO
/// `spend_cents` key at all, because the tokens seen before the failure bill nothing and the flat
/// fee is configured to zero in this harness. See the module header on what that last fact does and
/// does not license: `billed` here is 1.5.5's own rule over the recorded facts, which is 1, and the
/// recording neither confirms nor contradicts it.
///
/// The PLANE's finish on all twelve is an error — the tap saw a cut or a terminal error, which is
/// the same fact `billing_failed` carries — while the frame the client saw said 200. That is the
/// contradiction, and this is the family the kernel's dispute arm exists for.
const RECORDED_STREAM_FAULTS: &[Cell] = &[
    Cell {
        name: "anthropic|cut",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "anthropic|stream-error",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "bedrock|cut",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "bedrock|stream-error",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "cohere|cut",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "cohere|stream-error",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "gemini|cut",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "gemini|stream-error",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "openai|cut",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "openai|stream-error",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "responses|cut",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
    },
    Cell {
        name: "responses|stream-error",
        status: 200,
        upstream_leg: true,
        upstream_candidate: true,
        client_origin: true,
        billed: 1,
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
        let (kernel, _) = kernel_fee(cell, finish_at_the_exit(cell));
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
                    if kernel_fee(&cell, finish_at_the_exit(&cell)).0 != retired_plane_fee(&cell) {
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

/// **ARM 3 — THE MID-STREAM FAMILY, WHERE THE TWO READINGS REALLY DO DISAGREE.**
///
/// Driven at the LATE moment, which is the only moment this case exists at: the body has drained,
/// the tap has said how the stream ended, and the leg carries that finish instead of the one it
/// derived from the head. So the kernel is handed a 200 and an error about the same unit, which is
/// exactly the input the dispute arm is for and exactly the input no other arm in this file
/// produces.
///
/// Three things are asserted about each of the twelve, and the order matters.
///
/// 1. **The count does not move.** 1.5.5 keeps a mid-stream failure in its billable count and
///    refunds nothing — `retired_plane_fee` is that rule, verbatim — and so does the kernel under
///    the shipped policy. The structure changed; the money did not.
/// 2. **The default policy is what decides it.** Checked against `DisputePolicy::default()`'s own
///    answer rather than against the literal 1, so that the day somebody changes the shipped
///    default this cell reports a POLICY change and not an arithmetic mystery.
/// 3. **The posting is marked.** The count alone would say nothing was wrong. It was.
#[test]
fn recorded_stream_faults_are_disputed_and_bill_what_1_5_5_billed() {
    assert_eq!(
        RECORDED_STREAM_FAULTS.len(),
        12,
        "six dialects, two fault shapes; the golden's own count"
    );
    let mut diverged = Vec::new();
    for cell in RECORDED_STREAM_FAULTS {
        // The plane's own verdict after the body drained: the stream did not finish.
        let (kernel, flags) = kernel_fee(cell, FinishClass::Error);
        let plane = retired_plane_fee(cell);
        let policy = busbar_kernel::teller::DisputePolicy::default().decide(true, false);
        if (kernel, flags) != policy || kernel != plane || kernel != cell.billed {
            diverged.push(format!(
                "  {:<28} kernel={kernel} flags={flags:?} plane={plane} billed={} policy={policy:?}",
                cell.name, cell.billed
            ));
        }
    }
    assert!(
        diverged.is_empty(),
        "a mid-stream failure after a good head does not bill what 1.5.5 billed, or is not \
         decided by the shipped dispute policy — either way it is a money finding and stops \
         here:\n{}",
        diverged.join("\n")
    );
    // And the mark is the point: without it the disagreement settles as though it never happened.
    for cell in RECORDED_STREAM_FAULTS {
        assert!(
            kernel_fee(cell, FinishClass::Error)
                .1
                .contains(busbar_caps::PostingFlags::METER_DISPUTED),
            "{} settles without saying its two readings disagreed",
            cell.name
        );
    }
}
