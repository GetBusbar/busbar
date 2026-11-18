// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dispatch::conn_services`' bind-time tables: an instance's needs are declared once, when it is
//! bound (`Instance::bind`), and the connector slots only read them.

use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::HostCtx;

use crate::dispatch::conn_services::{ConnState, ResponseKeep};

impl ConnState {
    /// Fix the instance's ticket context and its per-need tables (reply timeouts, kept and denied
    /// response fields, interned), once, at bind.
    pub(crate) fn declare_needs(&self, ctx: HostCtx, needs: &[ReadNeed]) {
        let _ = self.context.set(ctx);
        let timeouts: Box<[u64]> = needs.iter().map(|n| n.timeout_ms).collect();
        let keeps: Box<[ResponseKeep]> = needs
            .iter()
            .map(|n| ResponseKeep {
                mode: n.keep_mode,
                kept: n
                    .keep_response_headers
                    .iter()
                    .map(|h| crate::intern_name(h))
                    .collect(),
                denied: n
                    .deny_response_headers
                    .iter()
                    .map(|h| crate::intern_name(h))
                    .collect(),
            })
            .collect();
        let _ = self.need_timeouts.set(timeouts);
        let _ = self.response_keeps.set(keeps);
    }
}
