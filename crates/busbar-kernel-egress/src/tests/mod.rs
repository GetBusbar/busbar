// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit's own proof.
//!
//! These are the previous release's failover, pick-order, exhaustion and probe tests, carried over
//! and re-asserted against the moved code. What each one checks is unchanged; what it drives is a
//! scripted transport instead of a real upstream, which is the only difference between the two and
//! the reason each is a unit test here rather than an integration test elsewhere.
//!
//! The tests that drive a route step need a `Pass<Route>`, and minting one is legal only in
//! `busbar-kernel`, so they live in its `src/tests/members/egress/route/` together with the
//! scripted node they drive. What stays here mints nothing.

mod allocation_tests;
mod exhaustion_tests;
mod pick_order_tests;
mod walk_tests;
