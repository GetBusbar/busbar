// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dialect kind (D36): the wire-codec half of a plane. A plane says what bytes MEAN and holds
//! the policy — the claims, the credential locator, the routing and metering seats. A dialect holds
//! only the TRANSLATION: it turns arriving bytes into the plane's semantic IR and renders the plane's
//! IR back to bytes in one on-the-wire shape. One plane may speak several dialects; each is its own
//! plugin, sealed into policy at registration exactly as a plane is.
//!
//! A dialect names a transport only as a claim, returns facts and encoded bytes only, and holds no
//! connection, no unit, no amount, no decision, no credential and no price. It carries none of the
//! plane's policy seats — those name the plane's own verb and decision vocabulary and stay there.
//! Pure over its inputs; no default bodies (see `docs/design/contract-notes.md`).

use crate::bounded::ArenaBytes;
use crate::dest::{EgressBody, VerifiedDestination};
use crate::grammar::Claim;
use crate::plane::{PlaneSessionState, Response, UnitDraft};
use crate::plugin::{AbiVersion, Plugin};
use crate::unit::{Ctx, Refusal, Unit, UnitEnd};
use crate::wire::{Decode, Encode, Frame, FrameCursor};

/// The interface generation a dialect plugin is built against. Bumped when this trait's shape or the
/// meta below changes in a way a built dialect would have to be recompiled to satisfy.
pub const DIALECT_ABI: AbiVersion = AbiVersion(1);

/// Everything a dialect declares about itself.
///
/// All of it is a constant, read at registration and sealed into policy: a dialect cannot vary its
/// own declarations at run time. None of it names a policy verb or a decision — those are the
/// plane's, not the dialect's.
pub trait DialectMeta {
    /// The dialect's registry key — the open-vocabulary name the kernel dispatches on.
    const KEY: &'static str;
    /// The registry key of the plane this dialect speaks. A dialect is always a dialect OF one plane.
    const PLANE: &'static str;
    /// The claims this dialect makes over arriving bytes (transport key + selector + scheme).
    const CLAIMS: &'static [Claim];
    /// The wire scheme this dialect's ingress arrives under, where it names one distinctly.
    const SCHEME_ALT: Option<&'static str>;
    /// The wire scheme this dialect's egress is written under, where it names one distinctly.
    const EGRESS_SCHEME: Option<&'static str>;
    /// The content type this dialect's streaming responses carry, where it names one.
    const STREAMING_CONTENT_TYPE: Option<&'static str>;
    /// The envelope header keys this dialect reads off an arriving frame.
    const HEAD_KEYS: &'static [&'static str];
    /// The route locations this dialect's egress reaches.
    const LOCATIONS: &'static [&'static str];
}

/// The wire-codec seats. A dialect implements exactly the byte↔IR translation of a plane; the
/// plane keeps the policy seats. Every method is pure over its inputs and the borrowed codec state.
pub trait Dialect: Plugin + Send + Sync + 'static {
    /// Read inbound bytes into the plane's ingress IR.
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<crate::plane::Ingress<'u>, Decode>;

    /// Write the outbound request for one verified destination.
    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode>;

    /// Write one inbound frame of an open unit onward to its destination. Nothing out means the
    /// frame is consumed and nothing goes onward for it.
    fn encode_ingress_frame<'u>(
        &self,
        u: &Unit<'u>,
        f: &Frame,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode>;

    /// Read bytes coming back from an upstream.
    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<crate::plane::Progress<'u>, Decode>;

    /// Write one response frame back to the client.
    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode>;

    /// Write a refusal in this dialect's shape. The codec state is borrowed immutably: a refusal
    /// must not advance codec state, or a sequence-numbered protocol would desynchronise.
    fn encode_refusal<'u>(
        &self,
        refusal: &Refusal,
        draft: Option<&UnitDraft<'u>>,
        st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode>;

    /// Write the end of a unit, where the dialect has one to write.
    fn encode_end<'u>(
        &self,
        u: &Unit<'u>,
        end: &UnitEnd,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode>;
}
