// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plane: eleven methods. `request` and `probe` open a session; `upstream`, `piece`, `rewrite` and
//! `channel` run on one; `end` ends it; `render`, `demux` and `select_resources` are plain; `admin` is
//! async.

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::PooledOut;
use busbar_plugin_abi::plane::{PlaneReq, Target};
use busbar_plugin_abi::types::{Bytes, Str};
use zerocopy::{Immutable, IntoBytes};

use super::Chained;
use crate::call::frame::pairs;
use crate::call::{self, Frame, Mono, Sess};

pub const REQUEST: u8 = 0;
pub const UPSTREAM: u8 = 1;
pub const PIECE: u8 = 2;
pub const END: u8 = 3;
pub const REWRITE: u8 = 4;
pub const RENDER: u8 = 5;
pub const ADMIN: u8 = 6;
pub const PROBE: u8 = 7;
pub const DEMUX: u8 = 8;
pub const SELECT_RESOURCES: u8 = 9;
pub const CHANNEL: u8 = 10;

/// The head of `request`: `route, flags, auth, _r: u32; request_id, carrier: u64`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct RequestHead {
    pub route: u32,
    pub flags: u32,
    pub auth: u32,
    pub _r: u32,
    pub request_id: u64,
    pub carrier: u64,
}

/// The head of `render`: the request head, then `what: u32`. 36 bytes are sent; `_gap` is not.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct RenderHead {
    pub req: RequestHead,
    pub what: u32,
    pub _gap: u32,
}
/// The bytes of `RenderHead` the method table states.
pub const RENDER_HEAD_LEN: usize = 36;

/// The head of `select_resources`: `mode: u32`, then the request head's numbers at their natural
/// alignment (`request_id` at 24, `carrier` at 32).
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct SelectHead {
    pub mode: u32,
    pub route: u32,
    pub flags: u32,
    pub auth: u32,
    pub _r: u32,
    pub _gap: u32,
    pub request_id: u64,
    pub carrier: u64,
}

/// The head of `upstream`, `probe` and `channel`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct TargetHead {
    pub attempt: u32,
    pub flags: u32,
}

/// The head of `piece`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct PieceHead {
    pub from: u32,
    pub exchange: u32,
    pub flags: u32,
}

/// The head of `admin`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct AdminHead {
    pub op: u32,
}

fn request_head(req: &PlaneReq<'_>) -> RequestHead {
    RequestHead {
        route: req.route,
        flags: req.flags,
        auth: req.auth,
        _r: 0,
        request_id: req.request_id,
        carrier: req.carrier,
    }
}

/// texts: method, path, query, work.
fn request_texts<'a>(req: &PlaneReq<'a>) -> [Str<'a>; 4] {
    [req.method, req.path, req.query, req.work]
}

/// blobs: headers (a pair list), identity, ticket_record, then the method's own bytes.
fn request_blobs<'a>(req: &PlaneReq<'a>, last: &'a [u8]) -> [Bytes<'a>; 4] {
    [
        pairs(req.headers.get()),
        req.identity,
        req.ticket_record,
        Bytes::new(last),
    ]
}

/// The frame of a target (`upstream`, `probe`, `channel`). texts: dialect, model, base_path, upstream,
/// provider. blobs: params (a pair list), admission.
pub(crate) fn target_frame<'a>(target: &Target<'a>) -> Frame<'a, TargetHead, 5, 2> {
    Frame::raw(
        TargetHead {
            attempt: target.attempt,
            flags: target.flags,
        },
        [
            target.dialect,
            target.model,
            target.base_path,
            target.upstream,
            target.provider,
        ],
        [pairs(target.params.get()), target.admission],
    )
}

/// `request`'s call. `blobs[3]` = `body`.
pub(crate) fn request_frame<'a>(
    req: &PlaneReq<'a>,
    body: &'a [u8],
) -> Frame<'a, RequestHead, 4, 4> {
    Frame::raw(
        request_head(req),
        request_texts(req),
        request_blobs(req, body),
    )
}

/// `render`'s call. `blobs[3]` = `arg`. The head is sent to the table's 36 bytes.
pub(crate) fn render_frame<'a>(
    req: &PlaneReq<'a>,
    what: u32,
    arg: &'a [u8],
) -> Frame<'a, RenderHead, 4, 4> {
    Frame::raw(
        RenderHead {
            req: request_head(req),
            what,
            _gap: 0,
        },
        request_texts(req),
        request_blobs(req, arg),
    )
    .known(RENDER_HEAD_LEN, 4, 4)
}

/// `select_resources`'s call. `blobs[3]` = `body`.
pub(crate) fn select_frame<'a>(
    mode: u32,
    req: &PlaneReq<'a>,
    body: &'a [u8],
) -> Frame<'a, SelectHead, 4, 4> {
    Frame::raw(
        SelectHead {
            mode,
            route: req.route,
            flags: req.flags,
            auth: req.auth,
            _r: 0,
            _gap: 0,
            request_id: req.request_id,
            carrier: req.carrier,
        },
        request_texts(req),
        request_blobs(req, body),
    )
}

super::proxy!(Plane);

/// One live plane session (a request or a probe).
pub type SessionHandle = Sess<busbar_ffi::kind::Plane>;

impl Proxy {
    /// Opens the request's session. `blobs[3]` = `body`.
    pub fn request<'o>(
        &self,
        buf: &'o mut PooledOut,
        at: Mono,
        req: &PlaneReq<'_>,
        body: &[u8],
    ) -> Result<(Option<SessionHandle>, Answer<'o>), CallError> {
        let frame = request_frame(req, body);
        let (s, answer) = call::opens(&self.to, REQUEST, at, &frame, req.headers.get(), buf)?;
        Ok((s, answer))
    }

    /// `blobs[3]` = `arg`.
    pub fn render<'o>(
        &self,
        buf: &'o mut PooledOut,
        at: Mono,
        req: &PlaneReq<'_>,
        what: u32,
        arg: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        let frame = render_frame(req, what, arg);
        call::plain(&self.to, RENDER, at, &frame, req.headers.get(), buf)
    }

    /// `blobs[0]` = `arg`.
    pub fn admin<'a, N: Needs>(
        &'a self,
        drv: &'a mut Driver<'a, N>,
        at: Mono,
        arg: PooledOut,
        op: u32,
    ) -> impl Chained<'a> {
        call::chain(&self.to, drv, ADMIN, at, AdminHead { op }, arg, true)
    }

    /// Opens a probe's session.
    pub fn probe<'o>(
        &self,
        buf: &'o mut PooledOut,
        at: Mono,
        target: &Target<'_>,
    ) -> Result<(Option<SessionHandle>, Answer<'o>), CallError> {
        let frame = target_frame(target);
        let (s, answer) = call::opens(&self.to, PROBE, at, &frame, target.params.get(), buf)?;
        Ok((s, answer))
    }

    /// `blobs[3]` = `body`.
    pub fn select_resources<'o>(
        &self,
        buf: &'o mut PooledOut,
        at: Mono,
        mode: u32,
        req: &PlaneReq<'_>,
        body: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        let frame = select_frame(mode, req, body);
        call::plain(
            &self.to,
            SELECT_RESOURCES,
            at,
            &frame,
            req.headers.get(),
            buf,
        )
    }

    /// texts: key. blobs: message.
    pub fn demux<'o>(
        &self,
        buf: &'o mut PooledOut,
        at: Mono,
        key: &str,
        message: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        call::plain(
            &self.to,
            DEMUX,
            at,
            &Frame::new((), [key], [message]),
            &[],
            buf,
        )
    }
}

/// The calls on a live plane session. A trait so the session type can live wherever the ports name it.
pub trait OnSession: Sized {
    fn upstream<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        target: &Target<'_>,
    ) -> Result<Answer<'o>, CallError>;
    fn channel<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        target: &Target<'_>,
    ) -> Result<Answer<'o>, CallError>;
    fn piece<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
    ) -> Result<Answer<'o>, CallError>;
    fn piece_fixed<'o>(
        &mut self,
        buf: &'o mut [u8],
        at: Mono,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
    ) -> Result<(Answer<'o>, usize), CallError>;
    fn end<'o>(self, buf: &'o mut PooledOut, at: Mono) -> Result<Answer<'o>, CallError>;
    fn rewrite<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        conversation: &[u8],
    ) -> Result<Answer<'o>, CallError>;
}

impl OnSession for SessionHandle {
    fn upstream<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        target: &Target<'_>,
    ) -> Result<Answer<'o>, CallError> {
        let frame = target_frame(target);
        call::on(self, UPSTREAM, at, &frame, target.params.get(), buf)
    }

    fn channel<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        target: &Target<'_>,
    ) -> Result<Answer<'o>, CallError> {
        let frame = target_frame(target);
        call::on(self, CHANNEL, at, &frame, target.params.get(), buf)
    }

    /// `blobs[0]` = `bytes`.
    fn piece<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        let frame = Frame::new(
            PieceHead {
                from,
                exchange,
                flags,
            },
            [],
            [bytes],
        );
        call::on(self, PIECE, at, &frame, &[], buf)
    }

    /// `piece` on caller-owned fixed storage: one call, no pool, no growth.
    fn piece_fixed<'o>(
        &mut self,
        buf: &'o mut [u8],
        at: Mono,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
    ) -> Result<(Answer<'o>, usize), CallError> {
        let frame = Frame::new(
            PieceHead {
                from,
                exchange,
                flags,
            },
            [],
            [bytes],
        );
        call::on_fixed(self, PIECE, at, &frame, &[], buf)
    }

    /// Ends the session. The handle is spent whatever the answer.
    fn end<'o>(self, buf: &'o mut PooledOut, at: Mono) -> Result<Answer<'o>, CallError> {
        call::ends(self, END, at, &Frame::new((), [], []), buf)
    }

    /// `blobs[0]` = `conversation`.
    fn rewrite<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        conversation: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        call::on(
            self,
            REWRITE,
            at,
            &Frame::new((), [], [conversation]),
            &[],
            buf,
        )
    }
}
