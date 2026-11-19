// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Transport 2.0: `begin` opens a session; `ingest`, `emit`, `timer`, `datagram` and `event` run on it;
//! `offer` is plain.
//!
//! `emit` is the one output call: a set of pieces in the fixed order HEAD, BODY, TRAILERS, END with one
//! blob per piece that carries bytes, so a small answer is one crossing; `CONSUMED` (credit) and `CLOSE`
//! carry no blob.

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::pool::PooledOut;
use busbar_plugin_abi::transport::ConnInfo;
use zerocopy::{Immutable, IntoBytes};

use crate::call::{self, Frame, Mono, Sess};

pub const BEGIN: u8 = 0;
pub const INGEST: u8 = 1;
pub const EMIT: u8 = 2;
pub const TIMER: u8 = 3;
pub const DATAGRAM: u8 = 4;
pub const EVENT: u8 = 5;
pub const OFFER: u8 = 6;

/// The head of `begin`: `role, flags: u32; mono_ns: u64`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct BeginHead {
    pub role: u32,
    pub flags: u32,
    pub mono_ns: u64,
}

/// The head of `emit`: `stream: u64; pieces, arg: u32; credit: u64`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct EmitHead {
    pub stream: u64,
    pub pieces: u32,
    pub arg: u32,
    pub credit: u64,
}

/// The head of `datagram`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct DatagramHead {
    pub path: u32,
    pub flags: u32,
}

/// The head of `event`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct EventHead {
    pub ev: u32,
}

/// The head of `offer`.
#[repr(C)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
pub struct OfferHead {
    pub role: u32,
}

/// The byte-carrying pieces of one `emit`, in the contract's fixed order. `None`: the piece is not in
/// this call. `end` is `Some(&[])` when END is in the set (END's entry is empty).
#[derive(Clone, Copy, Default)]
pub struct Pieces<'a> {
    pub head: Option<&'a [u8]>,
    pub body: Option<&'a [u8]>,
    pub trailers: Option<&'a [u8]>,
    pub end: Option<&'a [u8]>,
}

impl<'a> Pieces<'a> {
    /// The present pieces packed to the front, and how many there are.
    fn packed(self) -> ([&'a [u8]; 4], usize) {
        let mut out: [&'a [u8]; 4] = [&[]; 4];
        let mut n = 0;
        for piece in [self.head, self.body, self.trailers, self.end]
            .into_iter()
            .flatten()
        {
            out[n] = piece;
            n += 1;
        }
        (out, n)
    }
}

/// `begin`'s call. texts: alpn, sni, peer, local, local_fingerprint. blobs: tls_peer_cert, leftover,
/// head.
pub(crate) fn begin_frame<'a>(conn: &ConnInfo<'a>) -> Frame<'a, BeginHead, 5, 3> {
    Frame::raw(
        BeginHead {
            role: conn.role,
            flags: conn.flags,
            mono_ns: conn.mono_ns,
        },
        [
            conn.alpn,
            conn.sni,
            conn.peer,
            conn.local,
            conn.local_fingerprint,
        ],
        [conn.tls_peer_cert, conn.leftover, conn.head],
    )
}

/// `emit`'s call: one blob per byte-carrying piece present, packed to the front in the contract's
/// order.
pub(crate) fn emit_frame<'a>(
    stream: u64,
    pieces: u32,
    arg: u32,
    credit: u64,
    parts: Pieces<'a>,
) -> Frame<'a, EmitHead, 0, 4> {
    let (blobs, n) = parts.packed();
    let head = EmitHead {
        stream,
        pieces,
        arg,
        credit,
    };
    Frame::new(head, [], blobs).known(size_of::<EmitHead>(), 0, n)
}

super::proxy!(Transport);

/// One live transport session (a connection) and its output state.
pub struct SessionHandle {
    pub s: Sess<busbar_ffi::kind::Transport>,
    /// The session's one validator of the output model: what the engine asked of each stream and
    /// what the session has written for it (rules L1 to L7 and L9).
    pub wire: busbar_plugin_abi::wire::Wire,
}

impl SessionHandle {
    pub fn instance(&self) -> &std::sync::Arc<busbar_plugin_abi::host_side::driver::Instance> {
        self.s.instance()
    }
}

impl Proxy {
    /// Opens the connection's session. texts: alpn, sni, peer, local, local_fingerprint. blobs:
    /// tls_peer_cert, leftover, head.
    pub fn begin<'o>(
        &self,
        buf: &'o mut PooledOut,
        conn: &ConnInfo<'_>,
    ) -> Result<(Option<SessionHandle>, Answer<'o>), CallError> {
        let frame = begin_frame(conn);
        let (s, answer) = call::opens(&self.to, BEGIN, Mono(conn.mono_ns), &frame, &[], buf)?;
        Ok((
            s.map(|s| SessionHandle {
                s,
                wire: busbar_plugin_abi::wire::Wire::new(),
            }),
            answer,
        ))
    }

    pub fn offer<'o>(
        &self,
        buf: &'o mut PooledOut,
        at: Mono,
        role: u32,
    ) -> Result<Answer<'o>, CallError> {
        call::plain(
            &self.to,
            OFFER,
            at,
            &Frame::new(OfferHead { role }, [], []),
            &[],
            buf,
        )
    }
}

/// The calls on a live transport session. A trait so the session type can live wherever the ports name it.
pub trait OnSession: Sized {
    fn ingest<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        bytes: &[u8],
    ) -> Result<Answer<'o>, CallError>;
    #[allow(clippy::too_many_arguments)]
    fn emit<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        stream: u64,
        pieces: u32,
        arg: u32,
        credit: u64,
        parts: Pieces<'_>,
    ) -> Result<Answer<'o>, CallError>;
    #[allow(clippy::too_many_arguments)]
    fn emit_fixed<'o>(
        &mut self,
        buf: &'o mut [u8],
        at: Mono,
        stream: u64,
        pieces: u32,
        arg: u32,
        credit: u64,
        parts: Pieces<'_>,
    ) -> Result<(Answer<'o>, usize), CallError>;
    fn timer<'o>(&mut self, buf: &'o mut PooledOut, at: Mono) -> Result<Answer<'o>, CallError>;
    fn datagram<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        path: u32,
        flags: u32,
        bytes: &[u8],
    ) -> Result<Answer<'o>, CallError>;
    fn event<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        ev: u32,
        arg: &[u8],
    ) -> Result<Answer<'o>, CallError>;
}

impl OnSession for SessionHandle {
    fn ingest<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        bytes: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        call::on(
            &mut self.s,
            INGEST,
            at,
            &Frame::new((), [], [bytes]),
            &[],
            buf,
        )
    }

    /// One output call. `pieces` is the contract's piece set (its bits name which of `parts` are
    /// present, and CONSUMED or CLOSE); `credit` is the bytes of credit given with CONSUMED, else 0.
    #[allow(clippy::too_many_arguments)]
    fn emit<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        stream: u64,
        pieces: u32,
        arg: u32,
        credit: u64,
        parts: Pieces<'_>,
    ) -> Result<Answer<'o>, CallError> {
        let frame = emit_frame(stream, pieces, arg, credit, parts);
        call::on(&mut self.s, EMIT, at, &frame, &[], buf)
    }

    /// `emit` on caller-owned fixed storage: one call, no pool, no growth.
    #[allow(clippy::too_many_arguments)]
    fn emit_fixed<'o>(
        &mut self,
        buf: &'o mut [u8],
        at: Mono,
        stream: u64,
        pieces: u32,
        arg: u32,
        credit: u64,
        parts: Pieces<'_>,
    ) -> Result<(Answer<'o>, usize), CallError> {
        let frame = emit_frame(stream, pieces, arg, credit, parts);
        call::on_fixed(&mut self.s, EMIT, at, &frame, &[], buf)
    }

    fn timer<'o>(&mut self, buf: &'o mut PooledOut, at: Mono) -> Result<Answer<'o>, CallError> {
        call::on(&mut self.s, TIMER, at, &Frame::new((), [], []), &[], buf)
    }

    /// `blobs[0]` = `bytes`.
    fn datagram<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        path: u32,
        flags: u32,
        bytes: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        call::on(
            &mut self.s,
            DATAGRAM,
            at,
            &Frame::new(DatagramHead { path, flags }, [], [bytes]),
            &[],
            buf,
        )
    }

    /// `blobs[0]` = `arg`.
    fn event<'o>(
        &mut self,
        buf: &'o mut PooledOut,
        at: Mono,
        ev: u32,
        arg: &[u8],
    ) -> Result<Answer<'o>, CallError> {
        call::on(
            &mut self.s,
            EVENT,
            at,
            &Frame::new(EventHead { ev }, [], [arg]),
            &[],
            buf,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pieces_pack_to_the_front_in_the_fixed_order() {
        let parts = Pieces {
            head: Some(b"h"),
            body: None,
            trailers: Some(b"t"),
            end: Some(b""),
        };
        let (blobs, n) = parts.packed();
        assert_eq!(n, 3);
        assert_eq!(blobs[0], b"h");
        assert_eq!(blobs[1], b"t");
        assert!(blobs[2].is_empty());
    }

    #[test]
    fn a_credit_only_emit_carries_no_blob() {
        assert_eq!(Pieces::default().packed().1, 0);
    }

    #[test]
    fn the_heads_are_the_sizes_the_method_table_states() {
        assert_eq!(size_of::<BeginHead>(), 16);
        assert_eq!(size_of::<EmitHead>(), 24);
        assert_eq!(size_of::<DatagramHead>(), 8);
        assert_eq!(size_of::<EventHead>(), 4);
        assert_eq!(size_of::<OfferHead>(), 4);
    }
}
