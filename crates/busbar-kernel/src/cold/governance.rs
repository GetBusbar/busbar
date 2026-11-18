// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance` cold code, one section per governance area. Every fn is `#[cold]` or
//! `#[inline(never)]`; none holds a while/loop or sweeps a parameter (BP17).

pub(crate) mod ledger;
pub(crate) mod persistence;
pub(crate) mod principal_transition;
pub(crate) mod runtime;
pub(crate) mod selected_policy;
pub(crate) mod state;
