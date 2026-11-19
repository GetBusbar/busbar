// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Secret: `resolve` (async, one blob).

use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::PooledOut;

use super::Chained;
use crate::call::{self, Mono};

pub const RESOLVE: u8 = 0;

super::proxy!(Secret);

impl Proxy {
    /// `blobs[0]` = `reference`.
    pub fn resolve<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        reference: PooledOut,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, RESOLVE, at, (), reference, true)
    }
}
