// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REHEARSAL OF THE FLIP — one request driven through every step file in the design's order,
//! against the legacy plane on the same fixture.
//!
//! Each of the nine step files beside this one is identity-tested ALONE: its own harness builds the
//! one input it needs, calls the live site it was lifted from, and compares. That proves each step
//! is faithful. It does not prove they COMPOSE, because nothing has ever handed step N+1 what step N
//! actually returned. This file is that missing proof, and it is deliberately a test and nothing
//! else: the composition root that will really drive these steps is the kernel's, and a driver that
//! shipped in the plane would be a second one.
//!
//! # What it does
//!
//! For each fixture it runs two legs against two SEPARATE deployments — own registry, own scripted
//! upstream, own governance store — and compares what a client and an operator can see:
//!
//! - LEGACY: `native_ingress::operation_ingress_inner`, the shipped entry point, which is arrival,
//!   decode, the gauntlet's verify, `NativePlane::drive`'s door, the one engine and the finish tail.
//! - CHAINED: the step files, called one after another, each fed only from the previous one's
//!   output and from the tokens the kernel would have minted.
//!
//! # What it deliberately does not do
//!
//! Where a step's input cannot be produced from the step before it, this file does NOT invent the
//! missing value inside the chain and carry on. It stops, and the gap is written down as its own
//! test at the bottom of this file, named for the two sides that do not fit. That list is the flip's
//! work order: every one of them is a seam that has to exist before the kernel can drive this plane,
//! and a green chain over an invented value would hide exactly the work the flip has to do.
//!
//! # The tokens
//!
//! Minted the way the loop mints them — one seal for the length of one unit, one `UnitToken<S>` per
//! step, dropped when the call it was lent to returns. The seal is the caps crate's own kernel-only
//! symbol, used here exactly as the nine per-step harnesses beside this file use it: inside a test
//! module, standing in for the kernel that will lend these tokens in production.

#![cfg(test)]

// THE WHOLE REHEARSAL IS TEST CODE, and it says so with the attribute the tooling reads.
//
// The file-level `#![cfg(test)]` above already keeps every line here out of a shipped binary, but
// it is an INNER attribute on a module file, and the tree's scanners — the plane-purity lint and the
// construction gate — classify test code by `*/tests/*` paths, `*_tests.rs` names and
// `#[cfg(test)] mod … { … }` blocks. A file-level inner attribute is none of those, so this
// rehearsal was being measured as production: its kernel seal, its minted tokens, its `drive` and
// the fixture it builds out of the engine's own test app all counted against rules that exist to
// keep the PRODUCTION plane honest. They are the same constructs the nine per-step harnesses beside
// this file use, and those sit inside `#[cfg(test)] mod tests` and are read for what they are. This
// module puts the rehearsal on the same footing — one nesting level, no behaviour, and every one of
// those measurements now reads the same tree the same way.
#[cfg(test)]
#[path = "tests/chain.rs"]
mod rehearsal;
