// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Export: `deliver` (async), `render` (plain), `confirm` (async, no bytes).

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::PooledOut;
use zerocopy::{Immutable, IntoBytes};

use super::Chained;
use crate::call::{self, Frame, Mono};

pub const DELIVER: u8 = 0;
pub const RENDER: u8 = 1;
pub const CONFIRM: u8 = 2;

/// The head of `deliver`: `stream:u32, delivery:u64, attempt:u32, lines:u32`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct DeliverHead {
    pub stream: u32,
    pub _gap: u32,
    pub delivery: u64,
    pub attempt: u32,
    pub lines: u32,
}

/// The head of `render`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct ScopeHead {
    pub scope: u32,
}

/// The head of `confirm`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct ConfirmHead {
    pub delivery: u64,
}

super::proxy!(Export);

impl Proxy {
    /// `blobs[0]` = `batch`; `lines` is the count of lines in it.
    #[allow(clippy::too_many_arguments)]
    pub fn deliver<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        batch: PooledOut,
        stream: u32,
        delivery: u64,
        attempt: u32,
        lines: u32,
    ) -> impl Chained<'a> {
        let head = DeliverHead {
            stream,
            _gap: 0,
            delivery,
            attempt,
            lines,
        };
        call::chain(&self.to, drv, DELIVER, at, head, batch, true)
    }

    pub fn render<'o>(
        &self,
        buf: &'o mut PooledOut,
        at: Mono,
        scope: u32,
        snapshot: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        call::plain(
            &self.to,
            RENDER,
            at,
            &Frame::new(ScopeHead { scope }, [], [snapshot]),
            &[],
            buf,
        )
    }

    /// No bytes: `work` is only the chain's working block.
    pub fn confirm<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        work: PooledOut,
        delivery: u64,
    ) -> impl Chained<'a> {
        call::chain(
            &self.to,
            drv,
            CONFIRM,
            at,
            ConfirmHead { delivery },
            work,
            false,
        )
    }
}
