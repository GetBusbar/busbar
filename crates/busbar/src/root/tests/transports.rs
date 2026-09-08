//! Tests for `transports.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

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
    let provisioned = provision_servers(&listeners, &source, &journal, &TlsSink(&tls), &token)
        .expect("a self-signed pair resolves and parses");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let bound = runtime
        .block_on(listen_all(&tls, &provisioned, 1024))
        .expect("the listener binds against its own slot");
    assert_eq!(bound.len(), 1);
}

/// The view a transport is handed answers the one question it may ask and refuses the rest. A
/// transport that could read arbitrary configuration keys would be a transport that could learn
/// what a plane or a unit is for.
#[test]
fn the_listener_view_offers_the_address_and_nothing_else() {
    let view = ListenerView::new("127.0.0.1:8080", 1024);
    assert_eq!(view.bind(), Some("127.0.0.1:8080"));
    assert_eq!(view.get_str("cert"), None);
    assert_eq!(view.get_int("port"), None);
    assert_eq!(view.get_bool("tls"), None);
}

/// And the one key it DOES answer is the message ceiling, because a transport that assembles a
/// message before anything above it can see a byte has no other place to learn the number.
///
/// The `ws` transport reads this at `listen`. A view that answered `None` for it would leave
/// the ceiling at the WebSocket library's own default — 64 MiB, a number this project never
/// chose — while the operator's configuration said something four orders of magnitude smaller,
/// and every other listener on the node honoured it. That is not a refusal to disclose: it is a
/// limit the node states everywhere else silently not applying here.
#[cfg(feature = "plane-voice")]
#[test]
fn the_listener_view_answers_the_operators_message_ceiling() {
    const CAP: usize = 1024;
    let view = ListenerView::new("127.0.0.1:8080", CAP);
    assert_eq!(
        view.get_int(MESSAGE_MAX_BYTES_KEY),
        Some(CAP as i64),
        "a transport that asks for the operator's cap must be told it, not left on a default"
    );
    // Still nothing else. The ceiling is one answer, not an opening.
    assert_eq!(view.get_int("limits.request_body_max_bytes.other"), None);
    assert_eq!(view.get_int("port"), None);
    assert_eq!(view.bind(), Some("127.0.0.1:8080"));
}

/// THE DIRECTION OF THE SEAM, read off the manifest that decides it.
///
/// `ARCHITECTURE.md` section 3.4 states the flow one way only: the transport-key unit resolves the
/// material and hands the transport an opaque [`TransportKeyHandle`]. A transport that NAMES the
/// unit in its shipping `[dependencies]` has the edge pointing the other way — a plugin of one kind
/// compiled against a kernel-internal unit, with nothing between them — and no amount of care
/// inside the two crates makes that edge point the right way again.
///
/// The join belongs HERE, in the composition root, which is the one place allowed to know both
/// ends. `[dev-dependencies]` is deliberately not checked: the TLS battery builds real key material
/// through the unit and never ships in the plugin binary this rule protects, which is the same
/// narrowing `manifest-allowlist` states for every other plugin kind.
#[test]
fn the_tls_transport_names_no_unit_in_what_it_ships() {
    let manifest = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../busbar-transport-tls/Cargo.toml"
    ))
    .expect("the tls transport's manifest is in the tree");

    let mut in_deps = false;
    let mut named = Vec::new();
    for line in manifest.lines() {
        let s = line.trim();
        if s.starts_with('[') && s.ends_with(']') {
            in_deps = s == "[dependencies]" || s.starts_with("[dependencies.");
            if s.starts_with("[dependencies.") {
                named.push(s["[dependencies.".len()..s.len() - 1].to_string());
            }
            continue;
        }
        if !in_deps || s.is_empty() || s.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = s.split_once('=') {
            named.push(name.trim().to_string());
        }
    }

    let units: Vec<&String> = named
        .iter()
        .filter(|n| n.starts_with("busbar-unit-"))
        .collect();
    assert!(
        units.is_empty(),
        "a transport must receive key material as a handle, never by naming the unit that \
         resolves it; busbar-transport-tls ships: {units:?}"
    );
}

/// The root is what joins the unit to the transport, and it does it without either crate naming
/// the other: [`TlsSink`] is the adapter, and a config provisioned through it lands in the slot the
/// handle resolves to.
#[test]
fn the_root_adapter_lands_a_config_in_the_transports_own_slot() {
    let (_, _, client) = self_signed();
    let tls = busbar_transport_tls::TlsTransport::new();
    let token = crate::root::kernel::new_kernel().transport_key_token();

    let handle = provision_dial(
        &TlsSink(&tls),
        &token,
        ListenerRole::Admin,
        "dial-side",
        client,
    );
    assert_eq!(handle.slot(), ListenerRole::Admin.slot_index());
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
