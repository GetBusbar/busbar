// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit's own proof.
//!
//! What stays here mints nothing: the rotation's allocation shape, the request context's deadline
//! arithmetic.
//!
//! The tests that drive the walk need a `Pass<Route>`, and minting one is legal only in
//! `busbar-kernel`, so they live in its `src/tests/members/egress/route/` together with the
//! scripted node they drive.

mod allocation_tests;
mod pick_order_tests;
mod upstream_headers_tests;
