// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Guarded, bounded fetches made by core's plane maintenance services (IF §12.9/§12.14).
//! The root supplies the connector implementation. A plane never receives this authority.

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::records::Records;

use crate::retry::PortError;

/// One fetch, borrowed for its entire lifetime. The caller supplies the deadline and instance limits.
/// Neither this value nor its credential-bearing headers/body has a content-printing Debug implementation.
pub struct PlaneFetchRequest<'a> {
    /// An HTTP method already selected by the maintenance operation.
    pub method: &'a str,
    /// The destination judged by the connector on this attempt.
    pub url: &'a str,
    /// Generic PAIR records. Core's connector owns Host and framing headers.
    pub headers: Records<'a>,
    /// Request payload, never included in diagnostics.
    pub body: &'a [u8],
    /// Response body cap, also bounded by the connector's own configured cap.
    pub max_body: u64,
    /// The stated egress class; the connector remains the policy authority.
    pub egress: u32,
}

/// One bounded response. Custody applies to response headers as well as its body.
pub struct PlaneFetchReply {
    pub status: u16,
    pub headers: Vec<(Box<str>, SecureVec)>,
    pub body: SecureVec,
}

/// Root-owned bridge to the existing guarded connector fetch. It must validate the live caller and its
/// registration authority, enforce its deadline and limits, judge every new connection, and follow no
/// redirects. A sighting decides each permitted same-origin hop itself; push never follows redirects.
/// No implementation may manufacture a caller, bypass the guard, or expose a raw connector to a plugin.
pub trait PlaneFetch: Send + Sync + 'static {
    fn fetch<'a>(
        &'a self,
        who: &'a Caller<'_>,
        request: PlaneFetchRequest<'a>,
    ) -> BoxFut<'a, Result<PlaneFetchReply, PortError>>;
}
