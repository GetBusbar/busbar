// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S OUTBOUND VOCABULARY, shared by every protocol plane.
//!
//! The kernel dials nothing (BUSBAR-1.6.0.md THE DESIGN §5: "The kernel knows nothing about
//! transport"; status row 130): every outbound connection is the connector's
//! (`busbar-core-connector`), which alone holds TLS, the per-worker pools, ALPN, the CONNECT proxy
//! and busbar's mTLS identity (THE DESIGN §8). What stays here is the protocol-blind return
//! vocabulary of one buffered/streamed hop (`Response`, `StreamHead`, `ChunkFlow`). A destinations
//! commit reaches the connector's one guard through the root's rules
//! (`appbuild::RootRules::destinations_applied`).

// THE DESTINATIONS SEAM: a config commit raised to the deployment's one destination guard (the
// connector's), installed by the composition root.

/// One buffered outbound round trip, reduced to what a caller reads back.
///
/// `Default` is the empty response — status `0`, no location, no body, no observed identity — used
/// by a fixture that answers without a socket.
///
/// Gated to the `relay` feature: the buffered fetch/relay path is its consumer today. A dispatch path
/// keeps its own response projection, and the plugin egress vtable projects onto the ABI
/// PODs — so a build without that consumer carries no unused return vocabulary.
#[cfg(feature = "relay")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status the peer answered with.
    pub status: u16,
    /// The `Location` header, verbatim, for a 3xx. NEVER followed by the backend itself — a redirect
    /// is a fresh, unguarded URL handed back for the caller's own guard to judge.
    pub location: Option<String>,
    /// The response body, read to the caller's ceiling.
    pub body: Vec<u8>,
    /// THE TRANSPORT-LAYER IDENTITY OF THE PEER: the `sha256/…` pin of the leaf certificate's
    /// SubjectPublicKeyInfo, where this hop ran over TLS.
    ///
    /// `None` on a plaintext hop, and `None` where the certificate could not be walked. It is a fact
    /// about the connection THIS response arrived over, so it travels on the response rather than
    /// being fetched separately: a second look at "the certificate that host serves" would be a
    /// second connection a rebinding attacker gets to answer differently. A caller that requires a
    /// pin refuses on `None` — "we could not look" and "it matched" are the two answers a pin exists
    /// to keep apart.
    pub peer_spki: Option<String>,
    /// BUSBAR'S OWN END OF THE HANDSHAKE: whether this hop carried a client certificate into the
    /// handshake, so it was presented if the peer asked for one.
    ///
    /// The OTHER direction from [`Response::peer_spki`], and it travels on the response for the same
    /// reason: it is a fact about the connection this reply arrived over. `false` means there was
    /// nothing to present at all — it cannot mean "the peer did not ask", because TLS gives a client
    /// no way to tell, after the fact, a handshake in which the peer sent no `CertificateRequest`
    /// from one in which it did.
    pub client_identity_offered: bool,
}

/// The head of a streaming reply: what the backend answered before any body byte arrived.
///
/// The status is knowable before the first chunk because a caller that has already written bytes to
/// its own consumer cannot then change its mind and answer an error — so the decision "is this a
/// stream at all" is made on the head. Gated to the `relay` feature, its consumer (see [`Response`]).
#[cfg(feature = "relay")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamHead {
    /// The HTTP status the peer answered with.
    pub status: u16,
    /// The backend's `content-type`, lower-cased, or empty. A backend that answers a stream request
    /// with `application/json` has answered a NON-stream, and relaying that as event-stream framing
    /// would be busbar inventing a framing the backend never used.
    pub content_type: String,
    /// The body, for a reply the backend did NOT stream. Empty on a real stream: those bytes were
    /// handed to the chunk sink instead.
    pub body: Vec<u8>,
}

/// What a chunk sink says about continuing. A sink whose consumer has gone away asks the hop to
/// STOP rather than being written to forever: a caller that disconnected mid-stream must not leave
/// busbar holding a thread against an upstream that is happy to keep talking. Gated to the `relay`
/// feature, its consumer (see [`Response`]).
#[cfg(feature = "relay")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkFlow {
    Continue,
    Stop,
}
