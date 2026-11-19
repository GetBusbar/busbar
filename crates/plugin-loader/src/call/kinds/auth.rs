// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Auth: `verify` (plain, the request view by position), and five async methods.

use busbar_plugin_abi::auth::AuthReq;
use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::PooledOut;
use zerocopy::{Immutable, IntoBytes};

use super::Chained;
use crate::call::frame::pairs;
use crate::call::{self, Frame, Mono};

pub const VERIFY: u8 = 0;
pub const VERIFY_IO: u8 = 1;
pub const LOGIN: u8 = 2;
pub const OUTBOUND: u8 = 3;
pub const REFRESH: u8 = 4;
pub const SERVE: u8 = 5;

/// The head of `verify`: `flags:u32, _r:u32, now_s:u64`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct VerifyHead {
    pub flags: u32,
    pub _r: u32,
    pub now_s: u64,
}

/// The head of `login`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct LoginHead {
    pub step: u32,
}

super::proxy!(Auth);

impl Proxy {
    /// texts: method, path, query, authority, peer. blobs: headers (a pair list), tls_peer_cert, body,
    /// issued. Every field is lent from where the request already lies.
    pub fn verify<'o>(
        &self,
        buf: &'o mut PooledOut,
        at: Mono,
        req: &AuthReq<'_>,
    ) -> Result<Answer<'o>, CallError> {
        let headers = req.headers.get();
        let frame = Frame::raw(
            VerifyHead {
                flags: req.flags,
                _r: 0,
                now_s: req.now_s,
            },
            [req.method, req.path, req.query, req.authority, req.peer],
            [pairs(headers), req.tls_peer_cert, req.body, req.issued],
        );
        call::plain(&self.to, VERIFY, at, &frame, headers, buf)
    }

    /// `blobs[0]` = `req`.
    pub fn verify_io<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        req: PooledOut,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, VERIFY_IO, at, (), req, true)
    }

    /// `blobs[0]` = `input`.
    pub fn login<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        input: PooledOut,
        step: u32,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, LOGIN, at, LoginHead { step }, input, true)
    }

    /// `blobs[0]` = `req`.
    pub fn outbound<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        req: PooledOut,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, OUTBOUND, at, (), req, true)
    }

    /// No bytes: `work` is only the chain's working block.
    pub fn refresh<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        work: PooledOut,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, REFRESH, at, (), work, false)
    }

    /// `blobs[0]` = `req`.
    pub fn serve<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        req: PooledOut,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, SERVE, at, (), req, true)
    }
}
