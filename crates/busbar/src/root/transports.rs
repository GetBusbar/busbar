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
        let handle = provision_server(source, journal, sink, token, slot, &at)?;
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
#[derive(Debug)]
pub struct ListenerView {
    bind: String,
}

impl ListenerView {
    /// A view over one bind address.
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        ListenerView { bind: bind.into() }
    }
}

impl ConfigView for ListenerView {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }

    fn get_int(&self, _key: &str) -> Option<i64> {
        None
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
) -> Result<Vec<Listener>, TransportError> {
    let mut listeners = Vec::with_capacity(provisioned.len());
    for p in provisioned {
        let view = ListenerView::new(&p.bind);
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

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_unit_transport_key::AccessPurpose;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A secret source over an in-memory map. The deployment's real resolver is the secret plugin;
    /// what matters for these tests is that it is A source and the unit reads through it.
    struct MapSource(HashMap<String, Vec<u8>>);

    impl SecretSource for MapSource {
        fn resolve(&self, location: &str) -> Result<Vec<u8>, String> {
            self.0
                .get(location)
                .cloned()
                .ok_or_else(|| format!("no such secret: {location}"))
        }
    }

    /// A journal that keeps what it was told, so a test can assert what was read and why.
    #[derive(Default)]
    struct RecordingJournal(Mutex<Vec<(String, AccessPurpose)>>);

    impl AccessJournal for RecordingJournal {
        fn record_access(&self, location: &str, purpose: AccessPurpose) {
            self.0
                .lock()
                .expect("journal lock")
                .push((location.to_string(), purpose));
        }
    }

    /// A sink that records which slot each config landed in, standing in for the TLS transport.
    #[derive(Default)]
    struct RecordingSink {
        server: Mutex<Vec<u64>>,
        client: Mutex<Vec<u64>>,
    }

    impl TlsConfigSink for RecordingSink {
        fn register_server_config(&self, slot: u64, _cfg: Arc<rustls::ServerConfig>) {
            self.server.lock().expect("sink lock").push(slot);
        }

        fn register_client_config(&self, slot: u64, _cfg: Arc<rustls::ClientConfig>) {
            self.client.lock().expect("sink lock").push(slot);
        }
    }

    /// A fresh self-signed keypair, as PEM, plus the client trust store that trusts exactly it.
    fn self_signed() -> (Vec<u8>, Vec<u8>, Arc<rustls::ClientConfig>) {
        busbar_unit_transport_key::install_crypto_provider();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("a self-signed pair");
        let cert_pem = cert.pem().into_bytes();
        let key_pem = signing_key.serialize_pem().into_bytes();

        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        for der in rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem) {
            roots.add(der.expect("a certificate")).expect("a root");
        }
        let client = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        (cert_pem, key_pem, client)
    }

    fn two_listeners(cert: &str, key: &str) -> Vec<ListenerConfig> {
        vec![
            ListenerConfig {
                role: ListenerRole::Data,
                bind: "127.0.0.1:0".into(),
                tls: Some(TlsMaterialRefs {
                    cert: cert.into(),
                    key: key.into(),
                    client_ca: None,
                }),
                fingerprint: "data-listener",
            },
            ListenerConfig {
                role: ListenerRole::Admin,
                bind: "127.0.0.1:0".into(),
                tls: Some(TlsMaterialRefs {
                    cert: cert.into(),
                    key: key.into(),
                    client_ca: None,
                }),
                fingerprint: "admin-listener",
            },
        ]
    }

    /// Slots are stable and named. The administrative listener is slot 1 on every node, so a
    /// journal entry naming a slot means the same thing on the next boot and on the next node.
    #[test]
    fn the_slot_allocation_is_fixed_and_stable() {
        assert_eq!(ListenerRole::Data.slot_index(), 0);
        assert_eq!(ListenerRole::Admin.slot_index(), 1);
        assert_eq!(ListenerRole::Additional(0).slot_index(), 2);
        assert_eq!(ListenerRole::Additional(3).slot_index(), 5);
    }

    /// The whole path, on a real self-signed pair: two listeners provisioned, two configs landing
    /// in their own slots, and the handles carrying those slots back.
    #[test]
    fn two_listeners_provision_into_their_own_slots() {
        let (cert_pem, key_pem, _) = self_signed();
        let source = MapSource(HashMap::from([
            ("cert-ref".to_string(), cert_pem),
            ("key-ref".to_string(), key_pem),
        ]));
        let journal = RecordingJournal::default();
        let sink = RecordingSink::default();
        let token = crate::root::kernel::new_kernel().transport_key_token();

        let listeners = two_listeners("cert-ref", "key-ref");
        let provisioned = provision_servers(&listeners, &source, &journal, &sink, &token)
            .expect("a self-signed pair resolves and parses");

        assert_eq!(provisioned.len(), 2);
        assert_eq!(provisioned[0].handle.slot(), 0);
        assert_eq!(provisioned[1].handle.slot(), 1);
        assert_eq!(*sink.server.lock().expect("sink lock"), vec![0, 1]);
    }

    /// Every secret actually read gets an access entry, naming WHY it was read. That is what makes
    /// "the secret plugin is read here and nowhere else" a thing anybody can check afterwards.
    #[test]
    fn every_secret_read_is_journaled_with_its_purpose() {
        let (cert_pem, key_pem, _) = self_signed();
        let source = MapSource(HashMap::from([
            ("cert-ref".to_string(), cert_pem),
            ("key-ref".to_string(), key_pem),
        ]));
        let journal = RecordingJournal::default();
        let sink = RecordingSink::default();
        let token = crate::root::kernel::new_kernel().transport_key_token();

        provision_servers(
            &two_listeners("cert-ref", "key-ref"),
            &source,
            &journal,
            &sink,
            &token,
        )
        .expect("a self-signed pair resolves and parses");

        let entries = journal.0.lock().expect("journal lock").clone();
        // Two listeners, each reading a certificate and a key, and neither reading a client CA
        // because neither declared mutual TLS.
        assert_eq!(entries.len(), 4);
        assert_eq!(
            entries
                .iter()
                .filter(|(_, p)| *p == AccessPurpose::Cert)
                .count(),
            2
        );
        assert_eq!(
            entries
                .iter()
                .filter(|(_, p)| *p == AccessPurpose::Key)
                .count(),
            2
        );
        assert!(entries
            .iter()
            .all(|(loc, _)| loc == "cert-ref" || loc == "key-ref"));
    }

    /// A listener with no configured material is not a failure and reads no secret: a listener
    /// behind a terminating proxy has nothing of its own to resolve. It still gets a handle, so the
    /// transport is bound the same way either side of that choice.
    #[test]
    fn a_plain_listener_reads_no_secret_and_still_gets_a_handle() {
        let source = MapSource(HashMap::new());
        let journal = RecordingJournal::default();
        let sink = RecordingSink::default();
        let token = crate::root::kernel::new_kernel().transport_key_token();

        let listeners = vec![ListenerConfig {
            role: ListenerRole::Data,
            bind: "127.0.0.1:0".into(),
            tls: None,
            fingerprint: "plain-listener",
        }];
        let provisioned = provision_servers(&listeners, &source, &journal, &sink, &token)
            .expect("a plain listener needs nothing resolved");

        assert_eq!(provisioned.len(), 1);
        assert_eq!(provisioned[0].handle.slot(), 0);
        assert!(journal.0.lock().expect("journal lock").is_empty());
        assert!(sink.server.lock().expect("sink lock").is_empty());
    }

    /// A material reference the source cannot resolve is an error the operator sees, and the
    /// message names the SOURCE rather than anything about the bytes it failed to produce.
    #[test]
    fn an_unresolvable_reference_names_the_source_and_not_the_bytes() {
        let source = MapSource(HashMap::new());
        let journal = RecordingJournal::default();
        let sink = RecordingSink::default();
        let token = crate::root::kernel::new_kernel().transport_key_token();

        let err = provision_servers(
            &two_listeners("missing-cert", "missing-key"),
            &source,
            &journal,
            &sink,
            &token,
        )
        .expect_err("nothing resolves");
        assert!(err.contains("missing-cert"), "the message names the source");
    }

    /// The dial side: a client config lands in its slot, and nothing is journaled, because a public
    /// root store is not a secret.
    #[test]
    fn the_dial_side_registers_a_config_and_journals_nothing() {
        let (_, _, client_cfg) = self_signed();
        let sink = RecordingSink::default();
        let token = crate::root::kernel::new_kernel().transport_key_token();

        let handle = provision_dial(
            &sink,
            &token,
            ListenerRole::Data,
            "upstream-roots",
            client_cfg,
        );

        assert_eq!(handle.slot(), 0);
        assert_eq!(*sink.client.lock().expect("sink lock"), vec![0]);
    }

    /// The whole seam, against the real TLS transport rather than a recording double: the material
    /// is resolved through the secret source, lands in the transport's own slot, and the listener
    /// binds against the handle. Before this existed the only thing that ever registered a config
    /// was the transport's own tests, so a production listener had no key at all.
    #[test]
    fn a_listener_binds_through_the_transport_it_was_provisioned_into() {
        let (cert_pem, key_pem, _) = self_signed();
        let source = MapSource(HashMap::from([
            ("cert-ref".to_string(), cert_pem),
            ("key-ref".to_string(), key_pem),
        ]));
        let journal = RecordingJournal::default();
        let tls = busbar_transport_tls::TlsTransport::new();
        let token = crate::root::kernel::new_kernel().transport_key_token();

        let listeners = vec![ListenerConfig {
            role: ListenerRole::Data,
            bind: "127.0.0.1:0".into(),
            tls: Some(TlsMaterialRefs {
                cert: "cert-ref".into(),
                key: "key-ref".into(),
                client_ca: None,
            }),
            fingerprint: "data-listener",
        }];
        let provisioned = provision_servers(&listeners, &source, &journal, &tls, &token)
            .expect("a self-signed pair resolves and parses");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let bound = runtime
            .block_on(listen_all(&tls, &provisioned))
            .expect("the listener binds against its own slot");
        assert_eq!(bound.len(), 1);
    }

    /// The view a transport is handed answers the one question it may ask and refuses the rest. A
    /// transport that could read arbitrary configuration keys would be a transport that could learn
    /// what a plane or a unit is for.
    #[test]
    fn the_listener_view_offers_the_address_and_nothing_else() {
        let view = ListenerView::new("127.0.0.1:8080");
        assert_eq!(view.bind(), Some("127.0.0.1:8080"));
        assert_eq!(view.get_str("cert"), None);
        assert_eq!(view.get_int("port"), None);
        assert_eq!(view.get_bool("tls"), None);
    }

    /// The handle carries a slot and a fingerprint, and its debug output says as much rather than
    /// printing anything derived from what was resolved.
    #[test]
    fn the_handle_carries_no_material() {
        let token = crate::root::kernel::new_kernel().transport_key_token();
        let handle = busbar_unit_transport_key::issue_handle(&token, 1, "admin-listener");
        let rendered = format!("{handle:?}");
        assert!(
            rendered.contains("no material"),
            "the handle's debug output should say it carries none: {rendered}"
        );
    }
}
