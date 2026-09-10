// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One provisioned listener per configured address: the transport-key unit resolves the material,
//! journals what it read, registers the config in a slot, and hands back a handle that carries no
//! bytes.
//!
//! ## Who is allowed to know what
//!
//! A transport may not read a secret. That is not a policy about tidiness — a transport is the one
//! axis that touches raw bytes from an unauthenticated peer, and giving it the key material would
//! put the deployment's private key in the same object as the parser that meets an attacker first.
//! So something else has to resolve the material and put it somewhere the transport can find it,
//! and that something is the transport-key unit.
//!
//! The unit has had the exact shape for this since it landed. What it did not have was a caller:
//! the only thing in the tree that ever registered a listener's TLS config was the transport's own
//! tests, which meant a production listener had no key. This module is that caller.
//!
//! ## The four things a provisioning needs, and where each comes from
//!
//! - the **secret source** is the deployment's own resolver, the one seam every key resolves
//!   through;
//! - the **journal** takes an access entry per secret actually read, which is what makes "the
//!   secret plugin is read here and nowhere else" checkable after the fact;
//! - the **sink** is the TLS transport registered at boot — the same object, not a copy, or the
//!   config lands in a slot nothing will look in;
//! - the **token** is minted from the kernel. It is the one token minted outside the loop, because
//!   listen, dial and upgrade are not steps of any unit.
//!
//! ## Slots
//!
//! One per listener, allocated here, because the root is the only thing that knows how many
//! listeners there are. The data listener takes slot 0 and the administrative listener slot 1, and
//! any further configured listener takes the next index in configuration order — stable across
//! boots, so a journal entry naming a slot means the same thing tomorrow.
//!
//! What leaves the unit is `{ slot, fingerprint }` and nothing else; its debug output says so
//! rather than printing anything derived from the material.
//!
//! **A hazard this allocation exposes, named here because this is what exposes it.** The TLS
//! transport's `listen`, `dial` and `adopt` all read the slot off the handle they were given, which
//! is correct. Its `accept` does not: it reads slot 0 directly. So an administrative listener
//! provisioned at slot 1 passes `listen` and then mis-serves every accepted connection — either
//! refusing for want of a key or presenting the data listener's certificate. Nothing here works
//! around it: the workaround would be to put every listener in slot 0, which would make the slot
//! meaningless and hide the defect behind the composition that was supposed to reveal it. The fix
//! belongs in the transport, and until it lands a deployment with two TLS listeners is exposed.

use busbar_contract::{ConfigView, Listener, Transport, TransportConfigView, TransportError};
#[cfg(feature = "plane-voice")]
use busbar_transport_ws::MESSAGE_MAX_BYTES_KEY;

use std::sync::Arc;

use busbar_caps::{TransportKeyHandle, TransportKeyToken};
use busbar_unit_transport_key::{
    provision_client, provision_server, AccessJournal, SecretSource, Slot, TlsConfigSink,
    TlsLocations,
};

/// Which listener a slot belongs to.
///
/// The two named roles are fixed because they are the two every deployment has, and pinning them
/// means a journal entry that names slot 1 is the administrative listener on every node rather than
/// whichever listener happened to be configured second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ListenerRole {
    /// The data listener. Slot 0.
    Data,
    /// The administrative listener. Slot 1.
    Admin,
    /// Any further configured listener, in configuration order.
    Additional(u64),
}

impl ListenerRole {
    /// The slot index this role is provisioned at.
    #[must_use]
    pub fn slot_index(self) -> u64 {
        match self {
            ListenerRole::Data => 0,
            ListenerRole::Admin => 1,
            ListenerRole::Additional(n) => 2 + n,
        }
    }
}

/// One configured listener, as the root reads it out of configuration.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// Which listener this is, and therefore which slot it takes.
    pub role: ListenerRole,
    /// The address to bind.
    pub bind: String,
    /// Where the TLS material is resolved from, where the listener carries TLS at all.
    ///
    /// `None` is plain transport, which is the default and is not a lesser configuration: a
    /// listener behind a terminating proxy has no material of its own to resolve.
    pub tls: Option<TlsMaterialRefs>,
    /// What the journal's access entry records for this listener's material.
    pub fingerprint: &'static str,
}

/// Where one listener's material is resolved from, as the secret source spells it.
///
/// Opaque strings throughout. The grammar of a location belongs to the deployment and its own
/// secret source; nothing here interprets one, which is what lets a file path, a vault reference
/// and a cloud secret name all be the same kind of thing to this module.
#[derive(Debug, Clone)]
pub struct TlsMaterialRefs {
    /// The certificate chain, leaf first.
    pub cert: String,
    /// The private key.
    pub key: String,
    /// The CA bundle a presented client certificate is verified against, where mutual TLS is
    /// configured. Absent is server-only TLS.
    pub client_ca: Option<String>,
}

/// A listener that has been provisioned: which role it serves, and the handle the transport
/// presents at listen, accept and every adoption over it.
#[derive(Debug)]
pub struct ProvisionedListener {
    /// Which listener this is.
    pub role: ListenerRole,
    /// The address to bind.
    pub bind: String,
    /// The handle. A slot number and a fingerprint; never material.
    pub handle: TransportKeyHandle,
}

/// Provision every configured listener's server-side material, in slot order.
///
/// One access entry is journaled per secret actually read, by the unit and not by this function,
/// which is what keeps the journal a record of reads rather than a record of intentions.
///
/// # Errors
///
/// A listener's material could not be resolved through the secret source, or did not parse into a
/// usable certificate and key. The message names the secret's SOURCE and never its bytes.
pub fn provision_servers(
    listeners: &[ListenerConfig],
    source: &dyn SecretSource,
    journal: &dyn AccessJournal,
    sink: &dyn TlsConfigSink,
    token: &TransportKeyToken,
) -> Result<Vec<ProvisionedListener>, String> {
    let mut provisioned = Vec::with_capacity(listeners.len());
    for listener in listeners {
        let Some(refs) = listener.tls.as_ref() else {
            // A listener with no material is not provisioned and takes no slot's config. It still
            // gets a handle, so every listener is bound the same way and the transport never has
            // two code paths for "has a key" and "does not".
            provisioned.push(ProvisionedListener {
                role: listener.role,
                bind: listener.bind.clone(),
                handle: busbar_unit_transport_key::issue_handle(
                    token,
                    listener.role.slot_index(),
                    listener.fingerprint,
                ),
            });
            continue;
        };

        let at = TlsLocations {
            cert: &refs.cert,
            key: &refs.key,
            client_ca: refs.client_ca.as_deref(),
        };
        let slot = Slot {
            index: listener.role.slot_index(),
            fingerprint: listener.fingerprint,
        };
        let handle = provision_server(
            source,
            journal,
            sink,
            token,
            slot,
            &at,
            busbar_unit_transport_key::DEFAULT_ALPN,
        )?;
        provisioned.push(ProvisionedListener {
            role: listener.role,
            bind: listener.bind.clone(),
            handle,
        });
    }
    Ok(provisioned)
}

/// One listener's configuration, as the transport reads it.
///
/// A transport is handed a view rather than the deployment's configuration object, because the one
/// thing it needs to know is where to bind and the one thing it must not be able to do is read
/// anything else. Every other key it asks for answers `None`, which is the honest answer: this
/// listener declares an address and nothing more.
///
/// The one exception is the message ceiling, named by [`MESSAGE_MAX_BYTES_KEY`]. That key is the
/// transport crate's own constant rather than a second spelling of the same string here, because
/// the two sides of a key are exactly where a literal drifts: the crate that asks and the root that
/// answers.
#[derive(Debug)]
pub struct ListenerView {
    bind: String,
    /// The deployment's request-body cap, as resolved configuration carries it.
    request_body_max_bytes: usize,
}

impl ListenerView {
    /// A view over one bind address and the message ceiling the deployment resolved.
    #[must_use]
    pub fn new(bind: impl Into<String>, request_body_max_bytes: usize) -> Self {
        ListenerView {
            bind: bind.into(),
            request_body_max_bytes,
        }
    }
}

impl ConfigView for ListenerView {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }

    fn get_int(&self, key: &str) -> Option<i64> {
        // The one key answered, and it is answered because a transport that assembles a message
        // before anything above it sees a byte has no other place to learn the ceiling. Every other
        // key is still `None`: this is a limit the node states, not an opening onto configuration.
        #[cfg(feature = "plane-voice")]
        {
            (key == MESSAGE_MAX_BYTES_KEY)
                .then(|| i64::try_from(self.request_body_max_bytes).unwrap_or(i64::MAX))
        }
        // Without the voice plane there is no transport assembling messages, so no key is answered.
        #[cfg(not(feature = "plane-voice"))]
        {
            let _ = key;
            None
        }
    }

    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

impl TransportConfigView for ListenerView {
    fn bind(&self) -> Option<&str> {
        Some(&self.bind)
    }
}

/// Bind every provisioned listener on one transport.
///
/// The handle goes in with the address, which is the whole shape of the seam: the transport learns
/// which slot to look its config up in and never learns anything about what is in it.
///
/// # Errors
///
/// A listener could not be bound — the address is in use, or the slot holds no usable config.
pub async fn listen_all(
    transport: &dyn Transport,
    provisioned: &[ProvisionedListener],
    request_body_max_bytes: usize,
) -> Result<Vec<Listener>, TransportError> {
    let mut listeners = Vec::with_capacity(provisioned.len());
    for p in provisioned {
        let view = ListenerView::new(&p.bind, request_body_max_bytes);
        listeners.push(transport.listen(&view, &p.handle).await?);
    }
    Ok(listeners)
}

/// Provision the dial-side config a transport presents when it reaches an upstream.
///
/// The trust roots are the deployment's, because which authorities a node will accept upstream is
/// a deployment's statement rather than a unit's. Nothing is read through the secret source here —
/// a public root store is not a secret — so nothing is journaled either.
pub fn provision_dial(
    sink: &dyn TlsConfigSink,
    token: &TransportKeyToken,
    role: ListenerRole,
    fingerprint: &'static str,
    cfg: Arc<rustls::ClientConfig>,
) -> TransportKeyHandle {
    let slot = Slot {
        index: role.slot_index(),
        fingerprint,
    };
    provision_client(sink, token, slot, cfg)
}

// ── the seam a mounted leg reaches its own surface through ──────────────────────────────────────

/// WHAT ONE OPERATION ANSWERED: a status, its headers, and its body.
///
/// The three together, because a caller reads all three and this root may not re-derive any of them.
/// It is the plane's own answer travelling back OUT of the loop, and it is a record of BYTES rather
/// than of anything this file could reconstruct.
///
/// **One type, for every plane with a mount.** It was the A2A plane's `A2aAnswer` while A2A was the
/// only leg that had a dispatch seam. A second plane's leg wanting the same three fields is not a
/// reason for a second struct with the same three fields: two copies are two things that can drift,
/// and the whole content of this value is "the bytes are the surface's" — which is a statement about
/// the SEAM and not about any protocol. So the A2A leg's own type moved here and became this one,
/// rather than the MCP leg gaining a twin of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlaneAnswer {
    /// The status the surface answered with.
    pub status: u16,
    /// The headers it emitted, in emission order.
    pub headers: Vec<(String, String)>,
    /// The body it wrote. For a streamed operation this is the run of events, exactly as framed.
    pub body: Vec<u8>,
}

/// THE ONE SEAM between a plane's units and the surface that already answers its operations.
///
/// ## Why it is named for the MOUNT and not for the plane
///
/// It was written as `PlaneDispatch`, because the first thing it did was let a plane's leg reach its
/// own surface. That name says whose seam it is; it does not say WHAT it is, and what it is turns out
/// to be narrower and more particular: it is the MOUNT's channel — the one door a synchronous loop
/// running on a blocking worker has into the asynchronous runtime the mounted router lives on.
///
/// The distinction stopped being cosmetic the moment a second thing in this file also wanted to be
/// called a plane's dispatch. The generic driver has a seam of its own between a plane's units and
/// the leg they are walked against; it carries a leg through a walk and hands it back, it has no
/// runtime on either side of it, and it is `PlaneDispatch` because that is exactly what it is. Two
/// traits under one name in one module is not an ambiguity a reader resolves — it is a build that
/// does not compile, and before that it is two authors each certain the name meant their thing.
///
/// So the name follows the channel. Everything below is unchanged: the same one seam, the same
/// argument, the same rule about what may cross it.
///
/// ## Why there is exactly one, and why it takes no request
///
/// The units are the GATE and the surface is the ANSWER. Everything the loop decides — who is
/// calling, where the unit may go, whether the caller may ask, whether it is paid for — happens
/// before this seam is touched, and a unit refused at any of those steps never reaches it. What is on
/// the far side is the operation's own body, which this root does not hold and may not reimplement:
/// the whole value of the seam is that the answer a caller reads is the one the surface wrote.
///
/// It takes no request because the seam is BOUND to one. A unit of a mounted plane is assembled per
/// arrival, so the thing that carries the arrival across is per-arrival too, and a request passed
/// through the call would be the same request travelling twice. The administrative plane's seam is
/// long-lived and takes its request as an argument because ITS units are long-lived; the shape
/// follows the lifetime rather than the other way round.
///
/// The operation class IS passed, because it is the one thing the seam's far side may legitimately
/// branch on and the one thing the leg has already decided: the plane read the bytes and named the
/// class, and handing it over is what makes "the loop chose the path" checkable from the seam.
///
/// **One trait, for every plane with a mount**, and this is where the kinds stay siblings. The
/// argument is an `OpClassId`, which every plane declares, and the answer is bytes, which every
/// surface writes — so there is nothing protocol-shaped left in the signature and nothing for a
/// second copy of it to specialise. A per-plane dispatch trait would have been one trait per plane
/// carrying one identical method, and the first thing to differ between two of them would have been
/// a difference nobody meant.
pub trait MountDispatch: Send + Sync {
    /// Hand one operation to the surface it is mounted on, and take back its whole RESPONSE.
    ///
    /// The response is the plane's own, exactly as its surface wrote it — status, headers and a body
    /// that has not been read. A caller that wants bytes asks for them; a caller that does not gets
    /// a body it can hand onward as it stands.
    fn execute(&self, op: busbar_contract::ids::OpClassId) -> MountedReply;

    /// Read one body to its end, THROUGH THE SAME DOOR [`MountDispatch::execute`] used.
    ///
    /// A body is read on the runtime that owns it, and the caller of this trait is a synchronous
    /// loop that is not on that runtime. So buffering is an errand like execution is an errand,
    /// posted on the one channel this seam has, rather than a second mechanism a plane would have to
    /// find its own way onto.
    ///
    /// `None` where the body did not finish. It is not an empty body: an empty body says the
    /// operation answered with nothing, and a read that did not complete says the node could not
    /// produce the answer at all. Collapsing the two would report a truncated stream as a successful
    /// empty one to every client and every dashboard.
    fn collect(&self, body: axum::body::Body) -> Option<Vec<u8>>;
}

/// ONE REPLY, AS THE PLANE'S OWN RESPONSE, carried rather than rebuilt.
///
/// The seam used to hand back [`PlaneAnswer`] — a status, headers and `Vec<u8>` — which meant every
/// answer of every mounted plane was read to its end inside the mount before one byte of it reached
/// the wire. That is a buffer no plane asked for: a streamed answer stopped being streamed at the
/// seam, a chunk boundary the surface chose was lost, and an extension the surface attached to its
/// response was dropped on the floor because a three-field struct has nowhere to put one.
///
/// It is an alias and not a new type on purpose. The whole content of the change is "the response
/// is the plane's", and a wrapper would be this root holding the plane's answer in a container of
/// its own design — which is the thing the alias exists to stop.
pub type MountedReply = axum::http::Response<axum::body::Body>;

/// ONE OPERATION, EXECUTED AND THEN BUFFERED, for a plane whose exit path carries bytes.
///
/// ## Why this is here rather than in either plane
///
/// Two of the planes mounted today report the size of their answer at Route and carry the bytes out
/// on their exit frame, so they need the whole body before the unit ends. That is a property of
/// THOSE PLANES' exit paths and not of the mount, which is why the mount stopped doing it — but it
/// is also identical between them, and two copies of "execute, then read the body, then put the
/// three fields in a struct" are two things that can drift. The first thing to drift would have been
/// the figure one of them reports as its encoded size.
///
/// So the buffering is written ONCE, generically, over the seam's own two methods, and a plane opts
/// into it by calling this instead of [`MountDispatch::execute`]. Nothing here names a protocol: the
/// argument is an operation class, the answer is the three fields every surface writes, and a plane
/// that does not want a buffer simply does not call it.
///
/// **The bytes are unchanged.** The status, the headers in emission order and the body are the same
/// three values the seam handed back when it did this internally, which is what keeps the figure a
/// plane records as `encoded` — and therefore its exit frame — byte-identical across the change.
#[must_use]
pub fn collected(dispatch: &dyn MountDispatch, op: busbar_contract::ids::OpClassId) -> PlaneAnswer {
    let (parts, body) = dispatch.execute(op).into_parts();
    // The surface answered and its body did not come back. Serving the status with an EMPTY body
    // would read, to every client and every dashboard, as an operation that succeeded and returned
    // nothing. The node could not produce the answer, and that is what it says.
    let Some(body) = dispatch.collect(body) else {
        return unavailable_answer();
    };
    PlaneAnswer {
        status: parts.status.as_u16(),
        headers: header_pairs(&parts.headers),
        body,
    }
}

/// What the seam answers when there is no surface left to ask.
///
/// No document, because there is no plane answer to render: nothing decided anything, so anything in
/// the body would be this file's prose about a unit it did not judge.
#[must_use]
pub fn unavailable_answer() -> PlaneAnswer {
    PlaneAnswer {
        status: 503,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

/// Header names and values as owned pairs, in emission order.
///
/// A header value is bytes rather than text, and this is the one place that matters: these protocols'
/// answers carry a content type and a streamed one carries a cache directive, and every byte of them
/// has to reach the wire unchanged. Everything emitted here is ASCII, so the conversion is exact —
/// and it is written as a conversion rather than an assumption so that a value which was not would be
/// visible rather than silent.
///
/// Here rather than in the mount because [`collected`] needs it and the mount is compiled only where
/// some plane HAS a mount. One copy either way: the mount re-exports this one.
#[must_use]
pub fn header_pairs(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

// ── the leg a driver walks an arrival against ───────────────────────────────────────────────────

/// WHAT ONE ARRIVAL IS WALKED AGAINST: a plane's units, for that arrival.
///
/// ## Why this is a seam and not a field of the driver
///
/// The driver held `&ProductionUnits` for as long as there was one shape of leg. There are two, and
/// the difference between them is not cosmetic:
///
/// - A leg whose units are the SAME for every arrival — the node's own `ProductionUnits`, assembled
///   once at boot and shared by every connection. Nothing about the arrival changes what it is, so
///   the walk is `run_unit` against the value the driver already holds. Every `Units` gets this for
///   free through the blanket implementation below, which is what makes the change a widening
///   rather than a swap: the shape that worked before still works, unaltered, and the call site
///   that passed a `&ProductionUnits` still passes one.
/// - A leg whose units are ASSEMBLED PER ARRIVAL, because the bindings they run over carry facts the
///   arrival decided — what the plane made of the bytes, when they landed, which pool the agent
///   they name is reached on. Such a leg cannot exist before the arrival does, so it cannot be a
///   field of anything built at boot; what IS a field at boot is the thing that knows how to build
///   one, which is exactly what an implementor of this trait is.
///
/// ## What the driver learns from it: an ending, and nothing else
///
/// One method, one return value. The driver hands over the arrival and the four things the loop is
/// run under, and receives the `Ended` the loop reached. It learns no plane name, no operation, no
/// principal and no money — a leg that wanted to tell the driver any of those would have to widen
/// this signature, and the widening is the review.
///
/// The arrival is passed BY REFERENCE and the leg may read it; the driver still does not. Reading
/// the body is the plane's job on both sides of this seam, and a leg that reads it does so by
/// asking its own plane, in its own file, where the plane is named.
#[cfg(feature = "root-admin")]
pub trait PlaneLeg: Send + Sync {
    /// Walk one arrival through the kernel's ten steps and its one exit, and hand back the ending.
    ///
    /// The kernel, the hold cell, the leases, the gauge, the canary and the meter are the DRIVER'S:
    /// there is one of each per node and one of the first per unit, and a leg that made its own
    /// would be balancing its own books beside the node's. What the leg supplies is the `Units`.
    fn walk(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        kernel: &busbar_kernel::teller::Kernel,
        ctx: &busbar_kernel::teller::UnitCtx,
        run: busbar_kernel::teller::Run<'_>,
    ) -> busbar_kernel::teller::Ended;
}

/// A leg whose units do not depend on the arrival is the units themselves.
///
/// The blanket implementation is what makes [`PlaneLeg`] a widening of the driver rather than a
/// replacement for it: every `Units` the root already had is already a leg, so no existing
/// composition changed and no existing byte moved. The arrival goes unread here on purpose — that
/// is the whole content of "these units do not depend on it".
#[cfg(feature = "root-admin")]
impl<U: busbar_kernel::teller::Units + Send + Sync> PlaneLeg for U {
    fn walk(
        &self,
        _arrival: &busbar_contract::transport::Arrival<'_>,
        kernel: &busbar_kernel::teller::Kernel,
        ctx: &busbar_kernel::teller::UnitCtx,
        run: busbar_kernel::teller::Run<'_>,
    ) -> busbar_kernel::teller::Ended {
        busbar_kernel::teller::run_unit(kernel, self, ctx, run)
    }
}

// ── the driver a listener is handed ─────────────────────────────────────────────────────────────

/// WHAT RUNS A UNIT, on the root's side of the transport seam.
///
/// A transport that serves a plane's declared surface has to get what arrived to something that
/// will run it, and the tree's rule decides which direction that goes: core drives plugins, and a
/// plugin never names core. So the transport hands the arrival OVER, through
/// `busbar_contract::transport::UnitDriver`, and this is the root's implementation of it — handed to
/// a transport at listen, in the same breath and for the same reason as the transport key handle.
///
/// Everything the transport is not allowed to hold is held here: the kernel seal, the units the ten
/// steps run against, the in-flight table, the gauge and the canary. The transport learns none of
/// them. What it gets back is the plane's bytes, the media type the declaration named, and one word
/// from a closed list of eight.
///
/// ## The three things it does, in order
///
/// 1. **Reads with the plane.** One arrival is one inbound frame, and the plane says what it is —
///    over the root's own per-unit context, whose arena is `crate::root::arena::UnitArena` and
///    whose transport facts are the ones the mount published. The driver does not read the body.
/// 2. **Runs the loop.** The ten steps, against the node's own units, under the node's gauge and
///    canary. Not an approximation of the loop and not a subset of it.
/// 3. **Writes with the plane.** The bytes that leave are the plane's — its refusal document for an
///    ending that refused, which is what carries the caller's own request identifier back to it.
///
/// WHICH PLANE, it does not choose: it is handed one at composition, the same way it is handed the
/// kernel. There is no plane name in this file, which is the property that lets one driver serve a
/// second protocol without a line here changing.
///
/// ## What this driver does NOT do yet, said plainly
///
/// **A completed unit's answer document — CLOSED.** The loop's `Encode` step answers with a
/// `Frame`, and the ending now carries it, so a unit that completes answers with the bytes its own
/// plane wrote rather than with the outcome and nothing. What is still true is the rule that kept
/// this open: the driver does not encode anything itself, because a driver inventing an answer no
/// plane wrote is the one thing the whole seam exists to prevent. It passes the frame along unread.
/// A completed unit whose Encode step declined to write still leaves with no body.
///
/// **A plane's own steps.** A leg whose units answer every step with a refusal is a leg the root has
/// not composed yet, and that is the shape `ProductionUnits` has for every plane but the administrative one — so a
/// unit driven over it ends at its first step whatever the bytes were, and what the caller reads is
/// the plane's rendering of that refusal. A leg that DOES compose its plane's steps ends wherever
/// those steps end, and this file cannot tell the two apart, which is the property that lets a
/// second plane land without a line here changing.
#[cfg(feature = "root-admin")]
pub struct LoopDriver<'n> {
    kernel: &'n busbar_kernel::teller::Kernel,
    leg: &'n dyn PlaneLeg,
    gauge: &'n busbar_kernel::slice::ConcurrencyGauge,
    canary: &'n busbar_caps::Canary,
    /// What the bytes mean. One plane, handed in, never named here.
    plane: &'n dyn busbar_contract::Plane,
    /// When this process started, for the monotonic half of a unit's clock reading.
    ///
    /// The context carries two clocks and they are two different measurements: the wall reading
    /// dates a unit and the monotonic reading orders it. Filling both from the wall clock would give
    /// a unit one clock written twice — it would still date correctly and would order nothing at all,
    /// which is exactly the property the second field exists to provide.
    started: std::time::Instant,
    next_key: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "root-admin")]
impl std::fmt::Debug for LoopDriver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoopDriver")
    }
}

#[cfg(feature = "root-admin")]
impl<'n> LoopDriver<'n> {
    /// Bind the driver to the node's own kernel, leg, gauge and canary, and to the plane whose
    /// declared surface the listener it is handed to serves.
    ///
    /// By reference and not by value: one driver serves every connection every listener accepts, and
    /// the counts the canary balances are node-wide. A driver that owned a copy of them would be
    /// balancing its own books beside the node's.
    ///
    /// The leg arrives as `&dyn PlaneLeg`, which the node's own `ProductionUnits` coerces to through
    /// the blanket implementation — so a caller that passed the units still passes the units.
    #[must_use]
    pub fn new(
        kernel: &'n busbar_kernel::teller::Kernel,
        leg: &'n dyn PlaneLeg,
        gauge: &'n busbar_kernel::slice::ConcurrencyGauge,
        canary: &'n busbar_caps::Canary,
        plane: &'n dyn busbar_contract::Plane,
    ) -> Self {
        Self {
            kernel,
            leg,
            gauge,
            canary,
            plane,
            started: std::time::Instant::now(),
            next_key: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// The node's clock, read ONCE for one arrival.
    ///
    /// Pinned per unit rather than per step, which is what makes a plane pure over its inputs: two
    /// steps of one unit that each read the clock would see two different times, and a plane whose
    /// answer depended on which was a plane whose answer depended on how long the node took.
    ///
    /// A wall clock before the epoch is read as the epoch rather than refused. A unit is not the
    /// place to discover that the host's clock is set wrongly, and a saturating read dates the unit
    /// at the earliest time it could have happened instead of ending it.
    fn clock(&self) -> busbar_contract::unit::Clock {
        busbar_contract::unit::Clock {
            unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            monotonic_nanos: self.started.elapsed().as_nanos(),
        }
    }

    /// The key of the next unit this driver will walk.
    fn next_unit(&self) -> busbar_caps::UnitKey {
        busbar_caps::UnitKey::new(
            self.next_key
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }
}

/// How the loop's ending reads in the eight words a transport can render.
///
/// THE ONE MAPPING, here and nowhere else. The loop's ending carries a step, a reason code and a
/// posting; no wire has a field for any of the three, so the narrowing has to happen somewhere and
/// it happens on this side of the seam — where the ending's full detail is still available to the
/// audit record that keeps it.
///
/// The two credential doors stay apart, and that is the substance of this function rather than a
/// detail of it: a caller refused at Authenticate is told its credential was not accepted, and one
/// refused at Approve or Verify is told the credential was accepted and does not cover this.
/// Collapsing them sends a caller with a bad token away to fix its permissions.
#[cfg(feature = "root-admin")]
#[must_use]
pub fn outcome_of(ended: &busbar_kernel::teller::Ended) -> busbar_contract::transport::Outcome {
    use busbar_caps::{Outcome as Ends, ReasonCode as R, StepName as S};
    use busbar_contract::transport::Outcome as Out;
    match ended {
        busbar_kernel::teller::Ended::Settled { end, .. } => match end.outcome() {
            Ends::Completed => Out::Completed,
            Ends::Refused(S::Authenticate, _) => Out::Unauthenticated,
            Ends::Refused(S::Approve | S::Verify, _) => Out::Forbidden,
            // The money and rate refusals, which a caller can act on by slowing down or by paying,
            // and which every wire below spells with a code of its own.
            Ends::Refused(
                _,
                R::RateLimited | R::OverBudget | R::OverdraftCeiling | R::GroupFrozen,
            ) => Out::Throttled,
            Ends::Refused(_, R::NoDestination) => Out::NotFound,
            Ends::Refused(..) => Out::Unavailable,
            // A step BROKE, which is the node's fault and never the caller's, whatever step it was.
            Ends::Failed(..) => Out::Unavailable,
            Ends::Aborted(_) => Out::Cancelled,
            Ends::TimedOut(_) => Out::TimedOut,
        },
        // The node's own sweep took the hold first, so this unit will not produce an answer at all.
        busbar_kernel::teller::Ended::AlreadySettled => Out::Unavailable,
    }
}

/// The step the loop stopped at, in the contract's own spelling of the ten.
///
/// The kernel decides in `StepName` and a plane is handed a `Step` to render, and without a
/// written-down join the two drift. `busbar_caps` already carries the same join for the reason
/// vocabulary; this is its other half, and it is here rather than there for the same reason
/// [`outcome_of`] is — this is where an ending is narrowed for something outside the kernel to read.
///
/// Total, with no fallback arm. An eleventh step would not compile, which is the whole value of
/// writing the mapping down once.
#[cfg(feature = "root-admin")]
#[must_use]
pub fn step_of(step: busbar_caps::StepName) -> busbar_contract::unit::Step {
    use busbar_caps::StepName as S;
    use busbar_contract::unit::Step as T;
    match step {
        S::Arrival => T::Arrival,
        S::Decode => T::Decode,
        S::Authenticate => T::Authenticate,
        S::Verify => T::Verify,
        S::Approve => T::Approve,
        S::Admit => T::Admit,
        S::Route => T::Route,
        S::Meter => T::Meter,
        S::Audit => T::Audit,
        S::Encode => T::Encode,
    }
}

/// The refusal a plane is asked to render, where the ending is one it can.
///
/// THREE of the five endings become a refusal document and two do not, and the split is about what
/// the ending CARRIES rather than about how bad it was. A refusal and a failure both name a step and
/// a reason, which is exactly what a plane's refusal encoder takes. An abort and a timeout name no
/// reason at all — there is no word in the vocabulary for "the caller went away" — so a document
/// rendered for one of them would have to have a reason invented for it here, by the driver, about a
/// unit it did not decide. The transport still frames the answer from the outcome; what is missing
/// is a body, and a missing body is the truthful answer to "what did the plane say about this".
///
/// `AlreadySettled` is the same call: the node's own sweep took the hold, so this unit produced no
/// ending of its own and there is nothing of the plane's to render.
#[cfg(feature = "root-admin")]
#[must_use]
pub fn refusal_of(
    ended: &busbar_kernel::teller::Ended,
) -> Option<busbar_contract::unit::Refusal<'static>> {
    let busbar_kernel::teller::Ended::Settled { end, .. } = ended else {
        return None;
    };
    let (step, reason) = match end.outcome() {
        busbar_caps::Outcome::Refused(step, reason)
        | busbar_caps::Outcome::Failed(step, reason) => (step, reason),
        busbar_caps::Outcome::Completed
        | busbar_caps::Outcome::Aborted(_)
        | busbar_caps::Outcome::TimedOut(_) => return None,
    };
    Some(busbar_contract::unit::Refusal {
        step: step_of(step),
        reason: reason.into(),
        // The wait a caller should observe is a rate unit's answer and this driver has none of its
        // readings, so it says nothing rather than guessing a number a client would sleep for.
        retry_after_secs: None,
        // A mounted document surface carries one exchange and no stream identity, and the
        // correlation an answer must carry is read by the plane off the draft it decoded — which is
        // handed to the encoder beside this refusal rather than copied into it.
        stream: None,
        correlates: None,
    })
}

/// What the plane WROTE for an ending that completed, if it wrote anything.
///
/// The counterpart to [`refusal_of`], and deliberately not symmetrical with it. A refusal is
/// RECONSTRUCTED here, out of the step and reason the ending carries, because a refusal is a fact
/// about the loop that any renderer can be told. A completed unit's answer is not reconstructible
/// from anything: it exists exactly once, as the frame the plane's own `Encode` step wrote, and the
/// only honest thing this driver can do with it is pass it along unread.
///
/// `None` on every other ending — a refusal renders through `refusal_of`, and `AlreadySettled`
/// produced no ending of its own. `None` for a completed unit whose Encode step declined to write
/// means exactly that: no body, rather than a body this file invented.
#[cfg(feature = "root-admin")]
#[must_use]
pub fn completed_bytes(ended: &busbar_kernel::teller::Ended) -> Option<Vec<u8>> {
    let busbar_kernel::teller::Ended::Settled { end, frame, .. } = ended else {
        return None;
    };
    match end.outcome() {
        busbar_caps::Outcome::Completed => {}
        busbar_caps::Outcome::Refused(_, _)
        | busbar_caps::Outcome::Failed(_, _)
        | busbar_caps::Outcome::Aborted(_)
        | busbar_caps::Outcome::TimedOut(_) => return None,
    }
    frame.as_ref().map(|f| f.bytes.as_slice().to_vec())
}

#[cfg(feature = "root-admin")]
impl busbar_contract::transport::UnitDriver for LoopDriver<'_> {
    fn drive(
        &self,
        arrival: busbar_contract::transport::Arrival<'_>,
        _surface: &busbar_contract::transport::WireSurface,
    ) -> busbar_contract::transport::Answer {
        // WHAT THE DECLARATION SAYS THE ANSWER LOOKS LIKE, read before anything runs. Empty where
        // the arrival addressed a mount rather than a route: no declaration named a media type for
        // it, so the frame carries none rather than a guessed one.
        //
        // Whether one was ADDRESSED, never which one it is. Two fields are read off whatever the
        // declaration matched and neither is compared against a name — a driver that branched on
        // which operation this was would be the axis-agnostic side of the seam asking the operation
        // axis its identity, which is the thing the whole file is arranged not to do.
        let (media, answering) = arrival.operation.map_or_else(
            || (String::new(), busbar_contract::transport::Answering::Unary),
            |op| (op.response_media.to_string(), op.answering),
        );
        let clock = self.clock();
        let (outcome, body) =
            crate::root::plane_ctx::with_frames(&arrival, clock, |ctx, frames| {
                // THE PLANE READS. What it makes of the bytes is carried forward as the draft the
                // refusal encoder is handed, which is what puts the caller's own request identifier
                // on the answer it gets back. A body this plane cannot read yields no draft, and the
                // encoder is told so rather than handed an empty one.
                let read = self.plane.decode_ingress(frames, None, ctx);
                let draft = match &read {
                    Ok(busbar_contract::Ingress::OneShot(d))
                    | Ok(busbar_contract::Ingress::Open(d))
                    | Ok(busbar_contract::Ingress::Handshake(d)) => Some(&**d),
                    _ => None,
                };
                let ended = self.run(&arrival);
                let outcome = outcome_of(&ended);
                // THE PLANE WRITES. Never this driver's prose and never the transport's: an ending
                // the plane has no rendering for leaves with no body at all, which says less than a
                // sentence this file made up and is the only thing that is true.
                //
                // A COMPLETED unit answers with what its own Encode step wrote, carried out of the
                // loop on the ending. A REFUSED one is rendered by the plane from the ending's step
                // and reason. Neither branch is this driver's prose, and an ending that yields
                // neither leaves with no body at all — which says less than a sentence this file
                // made up, and is the only thing that is true.
                let body = completed_bytes(&ended)
                    .or_else(|| {
                        refusal_of(&ended)
                            .and_then(|refusal| {
                                self.plane.encode_refusal(&refusal, draft, None, ctx).ok()
                            })
                            .map(|bytes| bytes.as_slice().to_vec())
                    })
                    .unwrap_or_default();
                (outcome, body)
            });
        busbar_contract::transport::Answer {
            body,
            media,
            answering,
            outcome,
        }
    }
}

#[cfg(feature = "root-admin")]
impl LoopDriver<'_> {
    /// The ten steps, against this node's own units.
    ///
    /// Split out of `drive` so the loop is not nested inside the context the plane is called in:
    /// the arena's borrows live for the length of that context and the loop takes none of them, and
    /// a reader can see that here rather than having to work it out from the indentation.
    ///
    /// THE ARRIVAL IS NOT READ HERE, and that is the seam rather than a gap. Three of the fields the
    /// loop's own context carries are facts about how the bytes got here — the origin, the session,
    /// and whether the listener that accepted them is the administrative one — and every one of them
    /// is answered below with the value a client request on a data listener has. That is the truth
    /// for the mount this driver serves today and it is not a derivation: a node that mounted a
    /// surface on its administrative listener would be running those units as ordinary client units, which is
    /// the wrong answer arrived at silently.
    ///
    /// The arrival is HANDED ON, to the leg, which is the one thing here entitled to read it: a leg
    /// whose units are assembled per arrival assembles them from it, and a leg whose units are not
    /// ignores it. Either way the reading happens where a plane is named, and this file names none.
    fn run(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
    ) -> busbar_kernel::teller::Ended {
        let key = self.next_unit();
        let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
            &self.kernel.admit_token(),
            busbar_caps::PrincipalId::new(""),
            0,
        ));
        let leases = busbar_kernel::slice::LeaseCell::new();
        let meter = busbar_kernel::teller::AccrualMeter::new();
        let ctx = busbar_kernel::teller::UnitCtx {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        // THE LOOP ITSELF, not an approximation of it. Whatever this driver cannot yet do above the
        // loop, the ten steps below it are the node's own. WHICH units they run against is the leg's
        // and never this file's — the leg is handed the arrival and the four node-wide values, and
        // what comes back is the ending.
        self.leg.walk(
            arrival,
            self.kernel,
            &ctx,
            busbar_kernel::teller::Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: self.gauge,
                canary: self.canary,
                meter: &meter,
            },
        )
    }
}

// ── the loop's dispatch seam ─────────────────────────────────────────────────────────────────────

/// THE ONE SEAM A UNIT'S ROUTE STEP REACHES THE SURFACE THAT ALREADY ANSWERS IT THROUGH.
///
/// Named here, beside the driver and the outcome mapping, because nothing in it is about any one
/// plane. The argument is an [`OpClassId`](busbar_contract::ids::OpClassId), which every plane
/// declares; the answer is the loop's own [`RouteLeg`](busbar_kernel::teller::RouteLeg), which every
/// plane's Route step already hands back. A seam named after a plane would have been a second one
/// beside it the moment a second plane wanted the same thing, and the first thing to differ between
/// the two would have been a difference nobody meant.
///
/// **THE DRIVE IS THE PLANE'S AND IS HANDED IN.** This seam does not know how to execute an
/// operation and must not learn: what a request does is the plane's, and the surface that already
/// answers it is the surface that already answers it. What the seam owns is the fact that the drive
/// happened *here*, once, and nowhere else.
///
/// **THAT IS WHY THE ANSWER IS THE WORK AND NOT THE BYTES.** A status, headers and a byte vector
/// would be the honest answer for a plane whose operations are documents. It is the WRONG answer for
/// a plane whose operations are streams: taking the bytes here means draining the body here, and on
/// the billing planes the instant a body finishes draining is the instant the money is read. A seam
/// that buffered would be deciding when a stream ended, which is a decision that moves money. So the
/// leg is passed through and the bytes never come near this file.
///
/// **THE COUNT IS THE INSTRUMENT, NOT THE STATUS.** What this seam is for is answering "did the
/// engine run for this unit", and a status cannot answer it — a refusal rendered by the loop and an
/// upstream's own 403 read the same on the wire. A unit refused at Authenticate, Verify, Approve or
/// Admit never reaches Route, so it never reaches here, and the count says so.
pub trait PlaneDispatch: Send + Sync {
    /// Drive ONE operation of one unit, and count that it was driven.
    ///
    /// `drive` is the plane's own leg, already built and not yet polled. An implementation returns a
    /// leg that produces the same [`Decision`](busbar_caps::Decision) the one it was handed would
    /// have: this seam chooses WHERE the work happens, never WHAT it answers.
    fn execute<'a>(
        &'a self,
        op: busbar_contract::ids::OpClassId,
        drive: busbar_kernel::teller::RouteLeg<'a>,
    ) -> busbar_kernel::teller::RouteLeg<'a>;

    /// How many units have driven this seam, where the seam keeps count.
    ///
    /// On the trait rather than reached for by downcast, because counting is what this seam is FOR:
    /// a composition that cannot be asked "did anything run" has not got the instrument, and the
    /// honest way to say so is `None` rather than a zero indistinguishable from a node that took no
    /// traffic.
    fn driven(&self) -> Option<u64> {
        None
    }
}

/// The seam's production half: the surface the plane already routes through, counted.
///
/// Deliberately the thinnest thing in the file. It awaits the leg it was handed and returns that
/// leg's own value — no decision is computed here, no byte is touched, and nothing is added to or
/// taken from the answer. **That is what makes byte identity a property of the construction rather
/// than of a measurement**: the future this returns awaits the future it was given.
///
/// The count is taken when the leg is FIRST POLLED and not when it is built, because those are two
/// different facts. A leg built and dropped — a unit whose client hung up between Admit and the
/// first poll — did not drive the engine, and a count taken at construction would say it did.
#[derive(Debug, Default)]
pub struct DrivenOnce {
    /// How many of this node's units have driven the seam, since the node was built.
    driven: std::sync::atomic::AtomicU64,
}

impl DrivenOnce {
    /// A seam that has driven nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many units have driven the surface through this seam.
    #[must_use]
    pub fn driven(&self) -> u64 {
        self.driven.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl PlaneDispatch for DrivenOnce {
    fn execute<'a>(
        &'a self,
        _op: busbar_contract::ids::OpClassId,
        drive: busbar_kernel::teller::RouteLeg<'a>,
    ) -> busbar_kernel::teller::RouteLeg<'a> {
        Box::pin(async move {
            self.driven
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            drive.await
        })
    }

    fn driven(&self) -> Option<u64> {
        Some(DrivenOnce::driven(self))
    }
}

#[cfg(test)]
#[path = "tests/transports.rs"]
mod tests;
