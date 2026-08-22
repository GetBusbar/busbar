// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST-OWNED OUTBOUND SURFACE, shared by every protocol plane.
//!
//! One outbound hop looks the same whatever framing sits on top of it: a request goes to an address
//! the SSRF guard already judged and pinned, and a reply comes back with a status, a body, and — on
//! a TLS hop — the peer's observed public-key identity. This module owns the neutral RETURN types of
//! that hop so no single plane owns them. A plane composes protocol bytes; it never holds a client,
//! a socket, a resolver, or the vocabulary of the wire round trip.
//!
//! The types here are deliberately protocol-blind. There is nowhere in [`Response`] to record which
//! plane made the hop, and that absence is the point: the same buffered round trip serves an A2A
//! card fetch, an A2A task relay and an MCP dispatch, and a field that named one of them would be a
//! field the other two had to leave meaningless.

/// One buffered outbound round trip, reduced to what a caller reads back.
///
/// `Default` is the empty response — status `0`, no location, no body, no observed identity — used
/// by a fixture that answers without a socket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Response {
    /// The HTTP status the peer answered with.
    pub(crate) status: u16,
    /// The `Location` header, verbatim, for a 3xx. NEVER followed by the backend itself — a redirect
    /// is a fresh, unguarded URL handed back for the caller's own guard to judge.
    pub(crate) location: Option<String>,
    /// The response body, read to the caller's ceiling.
    pub(crate) body: Vec<u8>,
    /// THE TRANSPORT-LAYER IDENTITY OF THE PEER: the `sha256/…` pin of the leaf certificate's
    /// SubjectPublicKeyInfo, where this hop ran over TLS.
    ///
    /// `None` on a plaintext hop, and `None` where the certificate could not be walked. It is a fact
    /// about the connection THIS response arrived over, so it travels on the response rather than
    /// being fetched separately: a second look at "the certificate that host serves" would be a
    /// second connection a rebinding attacker gets to answer differently. A caller that requires a
    /// pin refuses on `None` — "we could not look" and "it matched" are the two answers a pin exists
    /// to keep apart.
    pub(crate) peer_spki: Option<String>,
    /// BUSBAR'S OWN END OF THE HANDSHAKE: whether this hop carried a client certificate into the
    /// handshake, so it was presented if the peer asked for one.
    ///
    /// The OTHER direction from [`Response::peer_spki`], and it travels on the response for the same
    /// reason: it is a fact about the connection this reply arrived over. `false` means there was
    /// nothing to present at all — it cannot mean "the peer did not ask", because TLS gives a client
    /// no way to tell, after the fact, a handshake in which the peer sent no `CertificateRequest`
    /// from one in which it did.
    pub(crate) client_identity_offered: bool,
}

/// The head of a streaming reply: what the backend answered before any body byte arrived.
///
/// The status is knowable before the first chunk because a caller that has already written bytes to
/// its own consumer cannot then change its mind and answer an error — so the decision "is this a
/// stream at all" is made on the head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StreamHead {
    /// The HTTP status the peer answered with.
    pub(crate) status: u16,
    /// The backend's `content-type`, lower-cased, or empty. A backend that answers a stream request
    /// with `application/json` has answered a NON-stream, and relaying that as event-stream framing
    /// would be busbar inventing a framing the backend never used.
    pub(crate) content_type: String,
    /// The body, for a reply the backend did NOT stream. Empty on a real stream: those bytes were
    /// handed to the chunk sink instead.
    pub(crate) body: Vec<u8>,
}

/// What a chunk sink says about continuing. A sink whose consumer has gone away asks the hop to
/// STOP rather than being written to forever: a caller that disconnected mid-stream must not leave
/// busbar holding a thread against an upstream that is happy to keep talking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChunkFlow {
    Continue,
    Stop,
}
