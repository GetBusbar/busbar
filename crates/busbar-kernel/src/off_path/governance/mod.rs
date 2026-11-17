// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance` off-path code, one section per governance area: what runs once per boot,
//! recovery, configuration or operator-issued control-plane operation, never per request.

pub(crate) mod ledger;
pub(crate) mod persistence;
pub(crate) mod principal_transition;
pub(crate) mod runtime;
pub(crate) mod state;
pub mod unit_checkpoint_store;
