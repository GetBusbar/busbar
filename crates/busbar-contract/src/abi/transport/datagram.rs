// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATAGRAM LANE: how a framer whose tail states [`super::FRAMING_DATAGRAM`] reads and answers
//! the host's datagram port, and the KEYING-MATERIAL ITEM through which it receives what the host's
//! secure layer exported (`BUSBAR-1.6.0.md` THE DESIGN, the connections section: "One secure layer,
//! sibling engines" and "Datagram media").
//!
//! THE PORT AND THE SECURE LAYER ARE THE HOST'S. One host port carries every association on it; the
//! host demultiplexes each datagram by its first byte, keeps the secure layer's records to itself,
//! and hands the framer only two kinds of bytes, each named by its [`DatagramLane::lane`]:
//!
//! * [`LANE_CLEAR`] — a datagram exactly as it arrived (a connectivity check, or protected media
//!   the framer itself unprotects with the exported keying material);
//! * [`LANE_SECURED`] — plaintext the secure layer opened.
//!
//! A third lane, [`LANE_RENDEZVOUS`], carries the far end's session description (the offer on the
//! accepting side, the answer on the dialling side), which reaches the framer through the
//! signalling unit, never through the port. The framer answers a rendezvous with its own
//! description as a frame piece and the [`RendezvousTerms`] the host's secure layer runs under.
//!
//! PATHS ARE HOST NUMBERS. Every far-end address the port heard from is a nonzero `u32` path the
//! host assigned; the framer names paths only by those numbers. A framer asks the host to bind a
//! path, or to move the association from the bound path to another ([`DatagramYield::request`]);
//! the host applies the request only once it has proven the path by its own round trip, and says
//! which path is bound on every later call ([`DatagramLane::bound`]). The framer never chooses
//! where the host sends: a [`LANE_CLEAR`] route to a path the host may not answer is dropped, and a
//! [`LANE_SECURED`] route always goes to the bound path, sealed by the host.
//!
//! THE KEYING MATERIAL is the one secret this lane carries (the who-sees-what table's framer row):
//! the exporter output of the host's secure layer, presented once, in host memory valid for the
//! call. The framer copies it into storage it zeroes on drop and never answers it back. No key of
//! the secure layer itself, no certificate key and no handshake state ever crosses.
//!
//! VERIFIED FIRST. [`DatagramLane::verified`] is `1` once the secure layer has matched the far end's
//! certificate to the fingerprint its description carried. Until then the framer yields no
//! application data to the layer above, whatever arrives.
//!
//! TAIL ADDITIONS (v1, pre-tag, R9 as clarified 2026-09-28): the lane is a pointer appended to the
//! `in` of `begin`, `ingest`, `emit`, `finish` and `timer`/`detach`, NULL for a stream framer;
//! [`DatagramYield`] is appended to [`super::FramerOut`]. A framer built before them reads and
//! writes neither, and the host reads a zeroed yield from it.

use super::FrameSpan;
use crate::abi::mechanism::call::AbiStr;

/// [`DatagramLane::lane`] / [`DatagramRoute::lane`]: a datagram as the port carried it.
pub const LANE_CLEAR: u32 = 1;
/// [`DatagramLane::lane`] / [`DatagramRoute::lane`]: plaintext of the host's secure layer.
pub const LANE_SECURED: u32 = 2;
/// [`DatagramLane::lane`]: the far end's session description, from the signalling unit. Never a
/// route's lane.
pub const LANE_RENDEZVOUS: u32 = 3;

/// [`DatagramYield::request`]: no path request.
pub const PATH_REQUEST_NONE: u32 = 0;
/// [`DatagramYield::request`]: bind `request_to` (nothing is bound yet).
pub const PATH_REQUEST_BIND: u32 = 1;
/// [`DatagramYield::request`]: move the association from the bound `request_from` to
/// `request_to`.
pub const PATH_REQUEST_REBIND: u32 = 2;

/// [`RendezvousTerms::role`]: this answer carries no terms.
pub const HANDSHAKE_NONE: u32 = 0;
/// [`RendezvousTerms::role`]: the host's secure layer opens the handshake.
pub const HANDSHAKE_INITIATES: u32 = 1;
/// [`RendezvousTerms::role`]: the host's secure layer answers the far end's handshake.
pub const HANDSHAKE_ANSWERS: u32 = 2;

/// The most datagram routes one framer answer may produce.
pub const MAX_ROUTES: u64 = 4096;
/// The most keying-material bytes the host presents (two keys and two salts of the widest
/// protection profile fit with room).
pub const MAX_KEYING_BYTES: u64 = 256;
/// The length of [`RendezvousTerms::peer_fingerprint`]: a SHA-256 digest.
pub const FINGERPRINT_BYTES: u64 = 32;

/// THE KEYING-MATERIAL ITEM: what the host's secure layer exported for the framer, host memory
/// valid for the call. Presented once, on the call after the export; the framer copies and zeroes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KeyingMaterial {
    /// `size_of::<KeyingMaterial>()` at construction.
    pub size: u32,
    /// The protection profile the handshake negotiated, as its registry code (nonzero).
    pub profile: u32,
    /// The material: the local and far keys, then the local and far salts, as the exporter laid
    /// them out.
    pub bytes: *const u8,
    /// How many (`1..=`[`MAX_KEYING_BYTES`]).
    pub len: usize,
}

/// One datagram a framer answered: its bytes in the sink's `wire`, where it goes, and its lane.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DatagramRoute {
    /// Offset into the sink's `wire`.
    pub offset: u64,
    /// How many bytes (nonzero: one datagram).
    pub len: u64,
    /// The path it goes to (nonzero). A [`LANE_SECURED`] route names the bound path.
    pub path: u32,
    /// [`LANE_CLEAR`] (sent as written) or [`LANE_SECURED`] (sealed by the host first).
    pub lane: u32,
}

/// One path the host knows: its number and its far-end address. On the dialling side these are the
/// far end's advertised candidates the host's destination judge allowed; on the accepting side,
/// the addresses verified checks came from.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DatagramPath {
    /// The path (nonzero).
    pub path: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// Its far-end address as text (`ip:port`).
    pub addr: AbiStr,
}

/// THE LANE A DATAGRAM FRAMER'S CALL CARRIES, host-written: what arrived, from where, the host's
/// path and secure-layer state, and the host buffer the framer's datagram routes go into.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DatagramLane {
    /// `size_of::<DatagramLane>()` at construction.
    pub size: u32,
    /// The ingested bytes' lane (`LANE_*`); `0` on a call that ingests nothing.
    pub lane: u32,
    /// The path a [`LANE_CLEAR`] or [`LANE_SECURED`] datagram came from; `0` = none.
    pub path: u32,
    /// The path the host has bound, proven; `0` = none yet.
    pub bound: u32,
    /// `path`'s far-end address as text (`ip:port`); absent with `path == 0`.
    pub path_addr: AbiStr,
    /// The host port's own address as text, the one candidate the framer advertises.
    pub local_addr: AbiStr,
    /// `1` = the secure layer verified the far end against its description's fingerprint.
    pub verified: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The keying-material item, on the one call that presents it; NULL otherwise.
    pub keying: *const KeyingMaterial,
    /// HOST buffer for the answer's routes.
    pub routes: *mut DatagramRoute,
    /// Its capacity, in routes.
    pub routes_cap: usize,
    /// The paths the host knows that this framing has not been told of yet (the framer keeps
    /// them); lent for the call.
    pub paths: *const DatagramPath,
    /// How many.
    pub paths_len: usize,
}

/// What the host's secure layer runs under, as the rendezvous settled it. The four credentials and
/// the fingerprint are spans of the sink's `frame`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RendezvousTerms {
    /// `HANDSHAKE_*`; [`HANDSHAKE_NONE`] = no terms in this answer (every span empty).
    pub role: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The user name the far end's checks must carry first.
    pub local_user: FrameSpan,
    /// The secret the far end's checks are keyed with.
    pub local_secret: FrameSpan,
    /// The far end's user name, carried by the host's own checks.
    pub remote_user: FrameSpan,
    /// The far end's secret, keying the host's own checks.
    pub remote_secret: FrameSpan,
    /// The far end's certificate fingerprint, [`FINGERPRINT_BYTES`] raw bytes.
    pub peer_fingerprint: FrameSpan,
    /// The datagram addresses the far end advertised, as text, one `ip:port` per line (LF); empty
    /// when it advertised none. The host judges each before any byte goes there; the accepting
    /// side's host learns paths from verified checks instead.
    pub candidates: FrameSpan,
}

/// What a datagram framer's answer adds to [`super::FramerYield`]: its routes, at most one path
/// request, and the rendezvous terms. All zero from a stream framer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DatagramYield {
    /// Routes written to the lane's `routes`.
    pub routes_len: u32,
    /// `PATH_REQUEST_*`.
    pub request: u32,
    /// [`PATH_REQUEST_REBIND`]: the bound path it moves from; `0` otherwise.
    pub request_from: u32,
    /// [`PATH_REQUEST_BIND`]/[`PATH_REQUEST_REBIND`]: the path asked for; `0` otherwise.
    pub request_to: u32,
    /// The rendezvous terms, on the answer to a rendezvous.
    pub terms: RendezvousTerms,
}

#[cfg(test)]
#[path = "../tests/transport_datagram_tests.rs"]
mod tests;
