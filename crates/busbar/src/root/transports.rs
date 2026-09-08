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

/// THE JOIN between the transport-key unit and the TLS transport, and the only place it is made.
///
/// The unit resolves material and needs somewhere to put the built config; the transport offers a
/// slot-keyed registry to put it in. Both halves have existed since the unit landed. What must NOT
/// exist is either crate naming the other: a `busbar-unit-*` in a transport's shipping
/// `[dependencies]` is a plugin of one kind compiled against a kernel-internal unit, which is the
/// inverse of the handle-passing rule `ARCHITECTURE.md` section 3.4 states — the unit hands the
/// transport an opaque [`TransportKeyHandle`], and nothing travels the other way.
///
/// So the adapter lives HERE. The composition root is the one thing in the tree entitled to know
/// both ends, and a two-method newtype is the whole cost of keeping the two crates ignorant of each
/// other. It forwards to the transport's own inherent registration methods and adds nothing:
/// no ordering, no caching, no policy. A caller that hands `TlsSink(&tls)` to [`provision_servers`]
/// or [`provision_dial`] gets exactly the behaviour the direct impl gave, byte for byte.
pub struct TlsSink<'a>(pub &'a busbar_transport_tls::TlsTransport);

impl TlsConfigSink for TlsSink<'_> {
    fn register_server_config(&self, slot: u64, cfg: Arc<rustls::ServerConfig>) {
        self.0.register_server_config(slot, cfg);
    }

    fn register_client_config(&self, slot: u64, cfg: Arc<rustls::ClientConfig>) {
        self.0.register_client_config(slot, cfg);
    }
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
/// ## What this driver does NOT do yet, said plainly
///
/// It runs the loop and maps the ending. It does NOT yet call the plane, so the answers it returns
/// carry no body. Two things upstream of it are missing, and neither is this file's to fix:
///
/// 1. **There is no per-unit arena that ships.** `busbar_contract::Arena` is `Send + Sync` and its
///    allocators take `&self` and hand back a slice borrowed from it; those two together have no
///    safe implementation, and every implementor in this tree is a test double that leaks. A plane
///    call needs one, so there is nothing to build a `Ctx` around.
/// 2. **`ProductionUnits` answers every non-admin step with a refusal.** That is deliberate — the
///    bodies arrive one plane at a time and admin is the one that has landed — so a unit driven
///    here today ends at Arrival whatever the bytes were.
///
/// Wiring it half-built and calling it served would be the failure this whole seam exists to
/// prevent, so it answers honestly instead: the loop really runs, the ending really is the loop's,
/// and the body is empty because no plane was asked.
#[cfg(feature = "root-admin")]
pub struct LoopDriver<'n> {
    kernel: &'n busbar_kernel::teller::Kernel,
    units: &'n crate::root::kernel::ProductionUnits,
    gauge: &'n busbar_kernel::slice::ConcurrencyGauge,
    canary: &'n busbar_caps::Canary,
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
    /// Bind the driver to the node's own kernel, units, gauge and canary.
    ///
    /// By reference and not by value: one driver serves every connection every listener accepts, and
    /// the counts the canary balances are node-wide. A driver that owned a copy of them would be
    /// balancing its own books beside the node's.
    #[must_use]
    pub fn new(
        kernel: &'n busbar_kernel::teller::Kernel,
        units: &'n crate::root::kernel::ProductionUnits,
        gauge: &'n busbar_kernel::slice::ConcurrencyGauge,
        canary: &'n busbar_caps::Canary,
    ) -> Self {
        Self {
            kernel,
            units,
            gauge,
            canary,
            next_key: std::sync::atomic::AtomicU64::new(1),
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

#[cfg(feature = "root-admin")]
impl busbar_contract::transport::UnitDriver for LoopDriver<'_> {
    fn drive(
        &self,
        _arrival: busbar_contract::transport::Arrival<'_>,
        _surface: &busbar_contract::transport::WireSurface,
    ) -> busbar_contract::transport::Answer {
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
        // loop, the ten steps below it are the node's own.
        let ended = busbar_kernel::teller::run_unit(
            self.kernel,
            self.units,
            &ctx,
            busbar_kernel::teller::Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: self.gauge,
                canary: self.canary,
                meter: &meter,
            },
        );
        busbar_contract::transport::Answer::empty(outcome_of(&ended))
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
