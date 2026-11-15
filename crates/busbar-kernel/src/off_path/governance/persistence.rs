// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance::persistence` off-path code (see `crate::off_path::governance`): the staged
//! core-owned governance records. Every operation here is boot recovery, persistence load and
//! replay, the background budget and metering flush, rate-card publication or an operator-issued
//! control-plane write, never inline with a request; runtime attachment is a separate cutover.
//! The public paths stay `crate::governance::persistence::*` (re-exported there).
pub mod identity;
pub mod ledger;
pub mod prices;
pub mod recovery;
mod shape;
