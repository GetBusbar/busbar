//! THE PLANE PRICING-BLINDNESS GATE, DRIVEN THROUGH THE DISPATCHER.
//!
//! DECISION #43 owes a RED-provable gate for "planes always ledger; the money acts
//! are kernel-side" (PRICING-BLIND, #71's one-fact-per-unit). The gate is registered and is RED ON HEAD BY
//! DESIGN — the #83 roster's own SPLIT row already says of `busbar-{llm,mcp,a2a,voice}` that
//! `unit/{admit,approve,meter,route}` and `runtime/metering.rs` "decide admission and price — that
//! is defs 5/6, not a plane". This file drives it through the dispatcher under
//! `cargo test --workspace --locked`, beside the pipeline's turnstile, which runs it by name on
//! every hop.
//!
//! WHAT THIS PINS, AND WHAT IT DELIBERATELY DOES NOT. It pins the SELFTEST at exit 0 — the proof
//! that the scanner can still be driven RED by a planted violation of each banned act, and still
//! stays GREEN over prose, over string literals, over a clock spelled in nanos, over a declared
//! meter class and over a rendered kernel refusal. It does NOT pin the gate's own verdict: that
//! verdict is a burndown that moves every time a money act is relocated kernel-side, and a test
//! that pinned it would have to be edited by every agent doing the relocating — which is how a
//! ratchet turns into a thing people delete.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

/// The gate proves it can still go RED — the property `cargo xtask selftest` refuses a gate for
/// lacking, and the only thing that makes its standing red mean anything.
#[test]
fn the_plane_pricing_blindness_gate_proves_red_in_its_selftest() {
    assert_eq!(run(&["gate", "plane-pricing-blindness", "--selftest"]), 0);
}
