// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The frozen request encoders and answer decoders, one file per kind (IF §8.8). W0-ABI stub: frozen
//! signatures, `todo!()` bodies; A5-A11 fill them.

pub mod auth;
pub mod export;
pub mod hook;
pub mod plane;
pub mod secret;
/// Every kind (`encode/settled.rs`, owner A5; round 31, was `encode/migrate.rs`): the optional CONFIG +
/// CORE_CFG* after INSTANCE in an `open` answer. Fragments borrow the answer. `None` = no CONFIG. Round 33: it
/// stops before a last `export::tag::CUSTODY` record of an export `open` (the export decoder reads it); any other
/// kind-range record there is RecErr (FAULT UnknownTag), as before.
pub mod settled;
pub mod store;
pub mod transport;
