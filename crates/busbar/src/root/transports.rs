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
//! **Every slot is served by its own listener.** The TLS transport's `listen`, `dial`, `adopt` and
//! `accept` all read the slot off the handle the listener was provisioned with — `accept` keeps the
//! slot `listen` recorded for the bound address and resolves that slot's config, never a fixed slot
//! of its own. So a deployment with the data listener and the administrative listener both on TLS
//! serves each one the certificate provisioned for it, and nothing here has to crowd every listener
//! into slot 0 to get there. The transport crate pins that in
//! `accept_serves_the_slot_the_listener_was_provisioned_with`; this module's own tests pin it again
//! through this module's provisioning, because this is the allocation that puts a listener in slot 1.

use busbar_api::{SecretRef, SecretResolve};
use busbar_contract::caps::{DurableWrite, Grant, KeyHandle, StepName, TransportKeyHandle};
use busbar_kernel_wal::{BodyWriter, Entry, RecordClass};
use busbar_unit_transport_key::{
    provision_server, AccessJournal, SecretSource, Slot, TlsConfigSink, TlsLocations,
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
    token: &Grant<KeyHandle>,
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

/// The deployment's own secret references, at the width the transport-key unit asks for.
///
/// The unit resolves a LOCATION, which is an opaque string it never interprets — that is the whole
/// point of the seam, and it is why a file path, a vault reference and a cloud secret name are all
/// the same kind of thing to it. What a deployment actually holds is a typed `SecretRef` with its
/// own grammar, so something has to sit between the two, and the root is the only thing that has
/// both.
///
/// The locations are the CONFIG PATHS the references were written at (`tls.cert`, `admin_tls.key`)
/// rather than any rendering of the references themselves. That is deliberate on both sides: the
/// unit gets a stable opaque token, and the journal entry the unit writes names where an operator
/// declared the secret rather than anything derived from what the secret is.
pub struct ConfiguredSecrets<'a> {
    resolver: &'a dyn SecretResolve,
    refs: std::collections::BTreeMap<String, SecretRef>,
}

impl<'a> ConfiguredSecrets<'a> {
    /// Bind a resolver and the references this boot may resolve through it.
    ///
    /// The map is the whole permission: a location that is not in it resolves to nothing, so the
    /// transport-key unit cannot reach a secret the root did not put in front of it.
    #[must_use]
    pub fn new(
        resolver: &'a dyn SecretResolve,
        refs: std::collections::BTreeMap<String, SecretRef>,
    ) -> Self {
        ConfiguredSecrets { resolver, refs }
    }
}

impl SecretSource for ConfiguredSecrets<'_> {
    fn resolve(&self, location: &str) -> Result<Vec<u8>, String> {
        let reference = self
            .refs
            .get(location)
            .ok_or_else(|| format!("no secret is declared at {location}"))?;
        self.resolver.resolve(reference)
    }
}

/// The `Access` entries the transport-key unit writes, on the node's own journal.
///
/// One entry per secret ACTUALLY READ, written by the unit and not by the provisioning function,
/// which is what keeps the journal a record of reads rather than a record of intentions. It goes on
/// the node's one chain for the same reason every other record does: a read of the deployment's
/// private key has a POSITION relative to the postings around it, and an auditor asking when the key
/// was last read should not have to correlate two clocks to find out.
///
/// A journal that will not take the entry is not a boot refusal. The read has already happened by
/// then — refusing after the fact would not un-read it — and a node that would not boot because it
/// could not record a boot-time read is a node that stops serving for a reason unrelated to serving.
pub struct BookAccessJournal<'a> {
    book: &'a std::sync::Mutex<crate::root::durability::Durability>,
    token: &'a Grant<DurableWrite>,
}

impl<'a> BookAccessJournal<'a> {
    /// Write this boot's access entries onto `book`.
    #[must_use]
    pub fn new(
        book: &'a std::sync::Mutex<crate::root::durability::Durability>,
        token: &'a Grant<DurableWrite>,
    ) -> Self {
        BookAccessJournal { book, token }
    }
}

impl AccessJournal for BookAccessJournal<'_> {
    fn record_access(&self, location: &str, purpose: busbar_unit_transport_key::AccessPurpose) {
        let mut body = BodyWriter::new();
        body.text(location);
        body.text(purpose.as_str());
        let entry = Entry::new(RecordClass::Access, body.finish());
        let mut durability = self.book.lock().unwrap_or_else(|p| p.into_inner());
        let _ = durability
            .journal
            .append(self.token, StepName::Arrival, &[entry]);
    }
}

// ── the loop's dispatch seam ─────────────────────────────────────────────────────────────────────

/// THE ONE SEAM A UNIT'S ROUTE STEP REACHES THE SURFACE THAT ALREADY ANSWERS IT THROUGH.
///
/// Named here because nothing in it is about any one plane. The argument is an
/// [`OpClassId`](busbar_contract::ids::OpClassId), which every plane declares; the answer is the
/// loop's own [`RouteLeg`](busbar_kernel::teller::RouteLeg), which every plane's Route step already
/// hands back. A seam named after a plane would have been a second one
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
    /// leg that produces the same [`Decision`](busbar_contract::caps::Decision) the one it was handed would
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

/// PROVISION EVERY CONFIGURED LISTENER'S TLS MATERIAL THROUGH THE TRANSPORT-KEY UNIT.
///
/// The unit resolves the material, journals the access, and registers the config in the slot the
/// root allocated — data at 0, admin at 1 — and hands back a handle carrying a slot number, a
/// fingerprint, and no bytes at all. Before this had a caller, the only thing in the tree that ever
/// registered a listener's TLS config was the transport's own tests, so whatever bound a listener
/// bypassed the unit entirely and the deployment's private key was resolved somewhere the journal
/// never saw.
///
/// WHY NOTHING IS BOUND HERE, AND WHERE THAT ENDS. This boot binds no listener through the
/// transport, and it is not an oversight: `main.rs`'s `serve_listener` binds the data and admin addresses over its own
/// `busbar_core_connsec::prepare` path, so a second bind here would refuse the address and take
/// the node down. What this function does is everything up to the bind — resolve, journal, register
/// — so the commit that moves serving onto the root's transports is a change of who accepts, not a
/// change of where the key comes from. Until then, this is a second resolution of the same
/// references `serve_listener` resolves for itself: the bytes the transport-key unit reads are not
/// the bytes rustls loads, but they are read from the same configured location, and this is the one
/// place that read is journaled.
///
/// A PROVISIONING FAILURE IS NOT A BOOT REFUSAL, for the same reason nothing is bound here: nothing
/// serves through these slots yet, and the path that does serve resolves the same references for
/// itself and fails on its own terms if they are unusable. Refusing here would take down a
/// deployment for a slot nobody is reading.
pub(crate) fn provision_root_listeners(
    sealed: &crate::root::registry::BootRegistry,
    resolver: &dyn busbar_api::SecretResolve,
    book: &std::sync::Mutex<crate::root::durability::Durability>,
    data: (&str, Option<&busbar_kernel::config::TlsCfg>),
    admin: (&str, Option<&busbar_kernel::config::TlsCfg>),
) {
    // The location strings are CONFIG PATHS, not renderings of the references: the unit journals
    // whatever it was handed, and what an auditor wants out of that entry is where the operator
    // declared the secret.
    let mut refs = std::collections::BTreeMap::new();
    let mut listeners = Vec::new();
    for (role, at, bind, tls, fingerprint) in [
        (
            ListenerRole::Data,
            "tls",
            data.0,
            data.1,
            "data-listener" as &'static str,
        ),
        (
            ListenerRole::Admin,
            "admin_tls",
            admin.0,
            admin.1,
            "admin-listener",
        ),
    ] {
        let material = tls.map(|cfg| {
            refs.insert(format!("{at}.cert"), cfg.cert.clone());
            refs.insert(format!("{at}.key"), cfg.key.clone());
            if let Some(ca) = cfg.client_ca.as_ref() {
                refs.insert(format!("{at}.client_ca"), ca.clone());
            }
            TlsMaterialRefs {
                cert: format!("{at}.cert"),
                key: format!("{at}.key"),
                client_ca: cfg.client_ca.as_ref().map(|_| format!("{at}.client_ca")),
            }
        });
        listeners.push(ListenerConfig {
            role,
            bind: bind.to_string(),
            tls: material,
            fingerprint,
        });
    }

    let token = crate::root::kernel::new_kernel().transport_key_token();
    let durability_token = crate::root::kernel::new_kernel().durability_token();
    let secrets = ConfiguredSecrets::new(resolver, refs);
    let journal = BookAccessJournal::new(book, &durability_token);
    if let Err(e) = provision_servers(
        &listeners,
        &secrets,
        &journal,
        &*sealed.transports.tls,
        &token,
    ) {
        // NOT a boot refusal — see the function doc.
        tracing::warn!(target: "busbar", "the root's listener slots were not provisioned: {e}");
    }
}

#[cfg(test)]
#[path = "tests/transports.rs"]
mod tests;
