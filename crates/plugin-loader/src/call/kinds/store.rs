// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store: `read`, `scan`, `commit`, `clock` (async, one blob each) and `info` (plain, no arguments).

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::PooledOut;

use super::Chained;
use crate::call::{self, Frame, Mono};

pub const READ: u8 = 0;
pub const SCAN: u8 = 1;
pub const COMMIT: u8 = 2;
pub const CLOCK: u8 = 3;
pub const INFO: u8 = 4;

super::proxy!(Store);

impl Proxy {
    /// `blobs[0]` = `req`.
    pub fn read<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        req: PooledOut,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, READ, at, (), req, true)
    }

    /// `blobs[0]` = `req`.
    pub fn scan<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        req: PooledOut,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, SCAN, at, (), req, true)
    }

    /// `blobs[0]` = `cand`.
    pub fn commit<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        cand: PooledOut,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, COMMIT, at, (), cand, true)
    }

    /// `blobs[0]` = `dataset`.
    pub fn clock<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        dataset: PooledOut,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, CLOCK, at, (), dataset, true)
    }

    /// No arguments.
    pub fn info<'o>(&self, buf: &'o mut PooledOut) -> Result<Answer<'o>, CallError> {
        call::plain(
            &self.to,
            INFO,
            Mono::NONE,
            &Frame::new((), [], []),
            &[],
            buf,
        )
    }
}
