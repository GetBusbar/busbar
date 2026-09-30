// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` THE DESIGN §6,
//! §11.4, §11.6, §11.11 R3): the [`AuthCalls`] trait the plugin loader implements over one loaded
//! auth instance, and the [`AuthAxis`] the composition root hands the kernel to open them. The
//! kernel's identity chain calls every auth plugin's `verify` through these, so a compiled-in and a
//! dropped-in auth plugin are reached through the same table. The kernel names this, the loader
//! names this, and neither names the other. Nothing here crosses the plugin boundary: the auth
//! kind's ABI is `abi::auth`.
//!
//! ONE CALL PER REQUEST PER CHAIN POSITION, and no verdict cache in the kernel: each auth plugin
//! caches inside itself (R3), and drops that cache on `refresh` ([`AuthCalls::refresh`]).

use std::future::Future;

use crate::redacted::Redacted;
use std::sync::Arc;

/// One inbound request's facts, as the kernel hands them to `verify`. Owned: the answer is
/// awaited, so nothing here borrows the request.
#[derive(Default)]
pub struct VerifyRequest {
    /// The method.
    pub method: String,
    /// The authority (host\[:port\]).
    pub authority: String,
    /// The path, raw as received.
    pub path: String,
    /// The query without `?`, raw as received; `None` = none.
    pub query: Option<String>,
    /// Wall-clock seconds since the Unix epoch, read once for this call.
    pub timestamp: u64,
    /// SHA-256 of the body, when the plugin's tail states it reads it.
    pub body_hash: Option<[u8; 32]>,
}

impl std::fmt::Debug for VerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyRequest")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

/// WHO a `verify` identified, copied out of the host's identity buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The stable subject.
    pub subject: String,
    /// The governance virtual-key id, if any.
    pub key_id: Option<String>,
    /// The governance virtual-key display name, if any.
    pub key_name: Option<String>,
    /// The end-user identifier, if any.
    pub user: Option<String>,
    /// The asserting provider, if any.
    pub provider: Option<String>,
    /// The display name, if any.
    pub name: Option<String>,
    /// The asserted groups (roles), in the plugin's order.
    pub groups: Vec<String>,
    /// The suggested cache TTL, seconds.
    pub ttl_secs: Option<u64>,
}

/// One `verify`'s answer, as the kernel's chain reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// Identified.
    Identity(VerifiedIdentity),
    /// A credential was presented and is invalid: the chain stops, denied.
    Reject,
    /// Not this plugin's credential: the chain tries the next.
    Pass,
    /// The call did not answer a verdict (FAILED, FAULT, REFUSED, a timeout or a second short
    /// answer): the chain's error path, fail-closed as 1.5.5's module failure.
    Failed,
    /// The instance's `max_inflight` is full: the call was not queued. The host answers the
    /// request 503 (THE DESIGN §11.11 R8, an accepted difference from 1.5.5).
    Overloaded,
}

/// One `verify` in flight. Dropping it before it answered is a client drop.
pub trait Verifying: Future<Output = Verified> + Send + Unpin {
    /// The answer, if it has arrived; never waits. A SYNC caller polls this once and fails closed
    /// on `None` rather than block a thread.
    fn settled(&mut self) -> Option<Verified>;
}

/// ONE AUTH INSTANCE'S CALLS, as the kernel's identity chain makes them.
pub trait AuthCalls: Send + Sync {
    /// The name the plugin's Statement states.
    fn name(&self) -> &str;

    /// The tail's facts (`abi::auth::FACT_*`).
    fn facts(&self) -> u32;

    /// `verify` ON THE SPOT: one ticket-less crossing on the caller's thread, bounded by the
    /// dispatcher's watchdog (THE DESIGN §12: a crossing that cannot wait needs no ticket). A
    /// plugin whose `verify` must wait on I/O answers REFUSED there (`abi::auth`), and this answers
    /// `None`: the caller then [`AuthCalls::verify`]s, awaiting it. A short answer is re-called once.
    fn verify_now(&self, request: &VerifyRequest) -> Option<Verified>;

    /// Submit `verify`; it crosses on a dispatcher worker and its answer is a future, so no thread
    /// is parked. A short answer is re-called once with the buffers it named; a second is
    /// [`Verified::Failed`].
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying>;

    /// `refresh` with a NEW generation and unchanged settings: the admin cache flush. The plugin
    /// drops its inbound cache. Answers how many entries it dropped, as the plugin reported them
    /// under [`crate::abi::auth::METRIC_CACHE_FLUSHED`] (`0` when it reported none).
    ///
    /// # Errors
    /// The refresh did not answer READY.
    fn refresh(&self) -> Result<u64, String>;
}

/// THE AUTH AXIS, as the composition root hands it to the kernel (the shape of the export kind's
/// `ExportAxis`): which auth modules a door answers, and opening one on the process's one
/// dispatcher. Installed once through the root's rows (`busbar_kernel::preflight::RootRows`).
pub trait AuthAxis: Send + Sync {
    /// The config keys of the auth rows this build LINKS, in registration order.
    fn linked_names(&self) -> Vec<String>;

    /// Whether a `kind: auth` row answers the module key `module` (linked or dropped in).
    fn answers(&self, module: &str) -> bool;

    /// Whether `module` names a row this build LINKS.
    fn linked(&self, module: &str) -> bool;

    /// OPEN one instance of `module` over `settings` (the provider's settings, one JSON document,
    /// its secret-refs already resolved), under the host's instance `label` (unique per opened
    /// instance: the name every host service keys its caller by).
    ///
    /// # Errors
    /// Why it will not open, naming the module: no door answers it, the door refused the load, or
    /// `open` did not answer READY.
    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String>;
}

// THE OUTBOUND HALF (open_outbound/fields) ─────────────────────────────────────────────────────
//
// THE DESIGN, §6 and §11.6: for every attempt the kernel makes ONE uniform call to the provider's
// auth plugin, "give me the auth fields for this request", by the handle `open_outbound` answered
// when the generation was sealed. The plugin caches inside itself; the kernel keeps only the handle
// and no auth cache, and never branches per plugin or per style.

/// One attempt's fixed facts, as the kernel hands them to `fields`. Owned: the answer may be
/// awaited, so nothing here borrows the request.
#[derive(Default)]
pub struct FieldsRequest {
    /// The method.
    pub method: Vec<u8>,
    /// The authority (host\[:port\]).
    pub authority: String,
    /// The path exactly as the framer will send it.
    pub path: Vec<u8>,
    /// The query without `?`, as it will be sent; `None` = none.
    pub query: Option<Vec<u8>>,
    /// Wall-clock seconds since the Unix epoch, read once by the kernel for this call.
    pub timestamp: u64,
    /// SHA-256 of the body, when the style declares `abi::auth::STYLE_NEEDS_BODY_HASH`.
    pub body_hash: Option<[u8; 32]>,
    /// The exact head envelope the framer will send, in order, when the style declares
    /// `abi::auth::STYLE_NEEDS_HEADERS`; empty otherwise.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// The caller's verified credential, for a passthrough binding (`abi::auth::MODE_PASSTHROUGH`).
    /// Secret: zeroised when it drops (every copy is its own [`Redacted`]).
    pub caller_credential: Option<Redacted<Vec<u8>>>,
}

impl std::fmt::Debug for FieldsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the caller's credential: it is secret material.
        f.debug_struct("FieldsRequest")
            .field("method", &String::from_utf8_lossy(&self.method))
            .field("authority", &self.authority)
            .field(
                "caller_credential",
                &self.caller_credential.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

/// One auth field that joins the head before the framer encodes it.
#[derive(Clone)]
pub struct AuthField {
    /// The field name.
    pub name: Vec<u8>,
    /// The value: credential material, zeroised when it drops, whichever copy it is.
    pub value: Redacted<Vec<u8>>,
    /// `abi::auth::FIELD_SENSITIVE`: never logged, zeroised once the head is encoded.
    pub sensitive: bool,
}

impl std::fmt::Debug for AuthField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = if self.sensitive {
            "<redacted>".to_string()
        } else {
            String::from_utf8_lossy(self.value.expose_secret()).into_owned()
        };
        f.debug_struct("AuthField")
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("value", &value)
            .finish()
    }
}

impl PartialEq for AuthField {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.value.expose_secret() == other.value.expose_secret()
            && self.sensitive == other.sensitive
    }
}

impl Eq for AuthField {}

/// One `fields`' answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fields {
    /// The fields, in order; none = no auth field (the upstream answers 401, as 1.5.5 did before
    /// the first mint).
    Ready(Vec<AuthField>),
    /// The handle refused the request (a passthrough on a style that does not pass the caller's
    /// credential, or a handle this generation does not hold).
    Refused,
    /// The call did not answer (FAILED, FAULT, a timeout or a second short answer): the attempt
    /// fails.
    Failed,
}

/// One `fields` in flight: PENDING while the plugin's cached token refreshes, bounded by the
/// attempt's deadline. Dropping it before it answered is a client drop.
pub trait Fielding: Future<Output = Fields> + Send + Unpin {
    /// The answer, if it has arrived; never waits.
    fn settled(&mut self) -> Option<Fields>;
}

/// ONE AUTH INSTANCE'S OUTBOUND CALLS, as the kernel's egress walk makes them.
pub trait OutboundAuth: Send + Sync {
    /// Bind `style` to its resolved `credential` (secret; empty for a passthrough-only binding)
    /// and the provider's auth `settings` (one JSON document); the handle the plugin answered.
    /// OFF-PATH: at generation seal.
    ///
    /// # Errors
    ///
    /// `open_outbound` did not answer READY.
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String>;

    /// `fields` ON THE SPOT: one ticket-less crossing on the caller's thread. `Some` only for a
    /// READY answer (a cached header: bearer, api-key, a fresh minted token, a SigV4 signature);
    /// `None` when the plugin cannot answer in place, and the caller then [`OutboundAuth::fields`]s.
    fn fields_now(&self, handle: u64, request: &FieldsRequest) -> Option<Fields>;

    /// Submit `fields` on a dispatcher worker; its answer is a future, so no thread is parked.
    /// `deadline_ns` (the dispatcher's clock; `0` = the op's own class) bounds a PENDING answer.
    fn fields(&self, handle: u64, request: FieldsRequest, deadline_ns: u64) -> Box<dyn Fielding>;
}
