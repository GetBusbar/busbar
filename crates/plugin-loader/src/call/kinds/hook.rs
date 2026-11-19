// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Hook: `on` (plain) and `on_io` (async); head `point`, `blobs[0]` = the view.

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::PooledOut;
use zerocopy::{Immutable, IntoBytes};

use super::Chained;
use crate::call::{self, Frame, Mono};

pub const ON: u8 = 0;
pub const ON_IO: u8 = 1;

/// The head of `on` and `on_io`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct PointHead {
    pub point: u32,
}

super::proxy!(Hook);

impl Proxy {
    pub fn on<'o>(
        &self,
        buf: &'o mut PooledOut,
        at: Mono,
        point: u32,
        view: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        call::plain(
            &self.to,
            ON,
            at,
            &Frame::new(PointHead { point }, [], [view]),
            &[],
            buf,
        )
    }

    /// `blobs[0]` = `view`.
    pub fn on_io<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        view: PooledOut,
        point: u32,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, ON_IO, at, PointHead { point }, view, true)
    }
}
