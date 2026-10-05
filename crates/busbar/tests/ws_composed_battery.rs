// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The upgrade wire's cross-transport battery: the six cells that drive a real instance of the
//! framer an upgrade arrives on, and the wire entered by ADOPT after that framer's `detach`.
//!
//! ## The shape (ARCHITECT Q128 U7 / Q8)
//!
//! The wire composes over NOTHING: no transport names another, the carrier under a dial is the
//! connector's choice from the target's scheme, and an inbound upgrade reaches the wire by `adopt` of
//! the stream the upgraded framer's `detach` hands up (its claim row states the upgrade). These cells
//! were the composition battery while the wire composed over `http`/`tcp`; they keep their observable
//! bytes on the detach -> adopt path.
//!
//! ## Why this lives here and not in the wire's own crate
//!
//! A transport crate is a plugin-kind crate: its own `Cargo.toml` is not allowed to name a sibling
//! transport even in `[dev-dependencies]`, because a dev-dependency's SHIPPED closure is linked into
//! that crate's `cargo test` binary whole (`kind-isolation:closure`'s `closure-test-reach`
//! finding). The hand-up across two framers is real and shipped (an adoption through a contract
//! trait), but PROVING it with a real upgraded framer needs both linked, and the one crate that links
//! them all is the composition root.
//!
//! ## How this file reaches the wires
//!
//! Through the linked transport table, exactly as the boot seal does: build.rs hands this test each
//! linked row's `KEY`, `COMPOSES_OVER` and `build` (`$OUT_DIR/linked_transports.rs`) and the same
//! bottom-up fold `root::registry::compose` runs. The wire under test and the framer it is upgraded
//! from are named once, as data (`tests/fixtures/composed_battery_wire.txt`); the wire's own layer is
//! held to the shipped fold (`src/root/tests/fixtures/transport_fold.txt`: it is built over
//! nothing), so a declaration that re-layers the wire turns this battery red. The file names no
//! transport crate and spells no transport key.
//!
//! The file needs every linked wire (`linked_every_transport`, emitted by build.rs): a build that
//! leaves one unlinked is a different composition, not a smaller one.
//!
//! The remaining battery cells that do not construct another transport (the byte-exact round trip,
//! half-close, cancel-mid-frame, backpressure, K-writers, frame meta, and the crate's own
//! private-helper unit tests) live in the wire's own crate.

#![cfg(linked_every_transport)]

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;

use busbar_contract::transport::wire::TransportError;
use busbar_contract::transport::TransportSettings;
use busbar_contract::{ScratchBytes, StreamId, Transport};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The wire this battery drives and the secure target scheme it refuses over a cleartext layer.
const BATTERY_WIRE: &str = include_str!("fixtures/composed_battery_wire.txt");
/// The shipped fold: `<wire key> <layer it was composed over, or ->`, in build order.
const TRANSPORT_FOLD: &str = include_str!("../src/root/tests/fixtures/transport_fold.txt");
/// The operator's body cap, by the configuration key the deployment names it under: the key a
/// listener's configuration view answers the message ceiling through.
const BODY_CAP_KEY: &str = "limits.request_body_max_bytes";

fn rows(text: &'static str) -> impl Iterator<Item = (&'static str, &'static str)> {
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_once(' ').expect("a `<key> <value>` row"))
}

/// The wire under test, the framer it is upgraded from, and its targets — every key read off the
/// linked table.
struct Stack {
    /// The wire's linked row.
    wire: &'static LinkedWire,
    /// The framer an inbound upgrade arrives on, as the fold built it.
    upper: Arc<dyn Transport>,
    /// The scheme of a target the wire must refuse over a cleartext carrier.
    secure: &'static str,
}

impl Stack {
    /// A fresh fold of every linked wire at the default settings.
    fn fold() -> Self {
        let (key, rest) = rows(BATTERY_WIRE)
            .next()
            .expect("the battery names its wire");
        let (secure, from) = rest
            .split_once(' ')
            .expect("`<wire> <secure scheme> <upgraded from>`");
        let built = fold_linked_transports(&TransportSettings::default());
        let find = |key: &str| {
            built
                .iter()
                .find(|(row, _)| row.key == key)
                .map(|(row, t)| (*row, Arc::clone(t)))
                .unwrap_or_else(|| panic!("`{key}` is not a linked wire"))
        };
        let (wire, folded) = find(key);
        let (_, shipped) = rows(TRANSPORT_FOLD)
            .find(|(k, _)| *k == key)
            .unwrap_or_else(|| panic!("the shipped fold has no `{key}` row"));
        assert_eq!(
            (folded.composed_over(), shipped),
            (None, "-"),
            "the fold built `{key}` over nothing, as the shipped fold says"
        );
        let (_, upper) = find(from);
        Self {
            wire,
            upper,
            secure,
        }
    }

    /// A fresh instance of the wire over `lower` (or over nothing), at `settings`.
    fn build(
        &self,
        lower: Option<Arc<dyn Transport>>,
        settings: &TransportSettings,
    ) -> Arc<dyn Transport> {
        (self.wire.build)(lower, settings)
    }

    /// A fresh instance of the wire, at the default settings: it dials over the carrier the
    /// connector picks from the target's scheme.
    fn dialler(&self) -> Arc<dyn Transport> {
        self.build(None, &TransportSettings::default())
    }

    /// A cleartext target on `addr`, whose scheme is the wire's key.
    fn target(&self, addr: impl std::fmt::Display, path: &str) -> &'static str {
        Box::leak(format!("{}://{addr}{path}", self.wire.key).into_boxed_str())
    }

    /// THE UPGRADED PAIR: the upgraded-from framer listens and accepts the dialler's upgrade, the
    /// wire built at `server` ADOPTS the stream that framer hands up, and `client` dials the wire's
    /// target at `path`. Answers (the client wire, its connection, the adopting wire, its
    /// connection).
    async fn upgraded(
        &self,
        server: &TransportSettings,
        client: Arc<dyn Transport>,
        path: &str,
    ) -> (
        Arc<dyn Transport>,
        busbar_contract::transport::wire::Conn,
        Arc<dyn Transport>,
        busbar_contract::transport::wire::Conn,
    ) {
        let upper = Arc::clone(&self.upper);
        let adopter = self.build(None, server);
        let keys = test_key_handle();
        let listener = upper
            .listen(&ListenerCfg("127.0.0.1:0".to_string(), None), &keys)
            .await
            .unwrap();
        let addr = listener.local_addr();
        let upgrade_task = {
            let (upper, adopter) = (upper.clone(), adopter.clone());
            tokio::spawn(async move {
                let keys = test_key_handle();
                let upper_conn = upper.accept(&listener).await.unwrap();
                adopter.adopt(&*upper, upper_conn, &keys).await.unwrap()
            })
        };
        let client_conn = client
            .dial(
                &verified_upstream(self.wire.key, self.target(addr, path)),
                &keys,
            )
            .await
            .unwrap();
        let server_conn = upgrade_task.await.unwrap();
        (client, client_conn, adopter, server_conn)
    }
}

/// A minimal listener config view, built only from `busbar_contract`'s public
/// `ConfigView`/`TransportConfigView` traits: a bind address and, optionally, the body cap.
struct ListenerCfg(String, Option<i64>);
impl busbar_contract::ConfigView for ListenerCfg {
    fn get_str(&self, _k: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, k: &str) -> Option<i64> {
        self.1.filter(|_| k == BODY_CAP_KEY)
    }
    fn get_bool(&self, _k: &str) -> Option<bool> {
        None
    }
}
impl busbar_contract::TransportConfigView for ListenerCfg {
    fn bind(&self) -> Option<&str> {
        Some(&self.0)
    }
}

fn test_key_handle() -> busbar_contract::TransportKeyHandle {
    use busbar_contract::plugin::TestKernelSeal as Seal;
    busbar_contract::TransportKeyHandle::issue(&Seal, 0, "test")
}

fn verified_upstream(
    transport: &'static str,
    host: &'static str,
) -> busbar_contract::VerifiedDestination {
    use busbar_contract::plugin::TestKernelSeal as Seal;
    busbar_contract::VerifiedDestination::seal(
        &Seal,
        busbar_contract::DestinationFacts::Upstream {
            transport,
            address: busbar_contract::transport::dest::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test-lane"),
        },
        transport,
        None,
    )
}

/// The in-band upgrade, driven through the seam the design names: the upgraded-from framer accepts
/// the connection, the wire adopts the stream it gives up (its `detach`), and the handshake runs on
/// the wire that speaks it. The facts of the pre-upgrade framer do not survive it — that framer no
/// longer knows the connection — and the chain the adopted connection reports is the real one, not
/// a name for itself.
#[tokio::test]
async fn an_in_band_upgrade_over_the_layer_below_with_cleared_facts() {
    let stack = Stack::fold();
    let upper = Arc::clone(&stack.upper);
    let adopter = stack.build(None, &TransportSettings::default());
    let keys = test_key_handle();
    let listener = upper
        .listen(&ListenerCfg("127.0.0.1:0".to_string(), None), &keys)
        .await
        .unwrap();
    let addr = listener.local_addr();

    let upgrade_task = {
        let (upper, adopter, keys) = (upper.clone(), adopter.clone(), test_key_handle());
        tokio::spawn(async move {
            let upper_conn = upper.accept(&listener).await.unwrap();
            let before = upper.arrival(&upper_conn).transport_chain;
            let upgraded = adopter
                .adopt(&*upper, upper_conn.clone(), &keys)
                .await
                .unwrap();
            (before, upper.arrival(&upper_conn), upgraded)
        })
    };

    let client_t = stack.dialler();
    let url = stack.target(addr, "/duplex");
    let client_conn = client_t
        .dial(&verified_upstream(stack.wire.key, url), &keys)
        .await
        .unwrap();
    let (before, after_source, upgraded) = upgrade_task.await.unwrap();

    assert_eq!(
        before,
        vec![upper.key()],
        "the upgraded-from framer named itself"
    );
    assert_eq!(
        adopter.arrival(&upgraded).transport_chain,
        vec![upper.key(), stack.wire.key],
        "the real chain, not a name for itself"
    );
    assert_eq!(
        after_source.port, 0,
        "the source gave the stream up and knows nothing about it"
    );

    // And the adopted connection carries frames, which is what makes the upgrade real rather than
    // a shape that only type-checks.
    adopter
        .write(
            &upgraded,
            StreamId(0),
            ScratchBytes::new(b"after the upgrade"),
        )
        .await
        .unwrap();
    let mut frames = client_t.frames(client_conn);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"after the upgrade");
}

/// The genuine network path: the upgraded-from framer binds and accepts, the wire dials over the
/// carrier its target's scheme picks, and the wire does the one thing it owns — the handshake — on
/// both ends, the accepting end on the stream the upgraded-from framer gave up.
#[tokio::test]
async fn a_composed_round_trip_over_the_layers_below() {
    let stack = Stack::fold();
    let (client_t, client_conn, server_t, server_conn) = stack
        .upgraded(&TransportSettings::default(), stack.dialler(), "/")
        .await;

    // Both ends report the stack they actually stand on, not a name for themselves.
    assert_eq!(
        server_t.arrival(&server_conn).transport_chain,
        vec![stack.upper.key(), stack.wire.key]
    );
    assert_eq!(
        client_t.arrival(&client_conn).transport_chain,
        vec![stack.wire.key]
    );

    client_t
        .write(
            &client_conn,
            StreamId(0),
            ScratchBytes::new(b"hello over the layers below"),
        )
        .await
        .unwrap();
    let mut frames = server_t.frames(server_conn);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"hello over the layers below");
}

/// The layer this instance reports is the one it declares: NONE. An upgrade wire composes over
/// nothing, so it is built over nothing whatever the fold hands it, and reports no layer — which is
/// what the registry's boot check compares. RED: a wire that still declared a layer would be built
/// over it and report it.
#[tokio::test]
async fn the_layer_reported_is_one_the_transport_declares() {
    let stack = Stack::fold();
    let settings = TransportSettings::default();
    assert!(
        stack.wire.composes_over.is_empty(),
        "the upgrade wire declares no layer: {:?}",
        stack.wire.composes_over
    );
    assert_eq!(stack.build(None, &settings).composed_over(), None);
    assert_eq!(
        stack
            .build(Some(Arc::clone(&stack.upper)), &settings)
            .composed_over(),
        None,
        "handed a layer it does not declare, it is still built over nothing"
    );
    assert!(stack.wire.session, "the upgrade wire carries sessions");
}

/// The size of message this connection will accept is the operator's number, not the WebSocket
/// library's. Left to the default, a deployment declaring a 1 KiB body cap would still buffer 64 MiB
/// per connection before saying no — the deployment's own limit silently widened by four orders of
/// magnitude, at the one layer where an oversized message is cheapest to refuse. The accepting wire
/// is built with the deployment's cap, as the composition root builds it, and adopts the upgrade.
#[tokio::test]
async fn the_message_cap_is_the_operator_s_and_not_the_library_s() {
    const CAP: usize = 1024;
    let stack = Stack::fold();
    let capped = TransportSettings {
        request_body_max_bytes: CAP,
        ..TransportSettings::default()
    };
    // The peer is not capped at the operator's number, because the cap this test is about is the
    // RECEIVER's: a limit that only holds when the far side agrees to it is not a limit.
    let (peer, a, t, b) = stack.upgraded(&capped, stack.dialler(), "/").await;

    let oversized = vec![b'w'; 2 * CAP];
    peer.write(&a, StreamId(0), ScratchBytes::new(&oversized))
        .await
        .expect("the uncapped peer puts the oversized message on the wire");

    let mut frames = t.frames(b);
    let outcome = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("the cap must be enforced rather than waited on")
        .expect("an over-cap message is an error, not a clean end of session");
    assert_eq!(
        outcome.unwrap_err(),
        TransportError::Framing,
        "a message past the operator's cap is a framing refusal"
    );
}

/// And the other lifecycle: an instance that only ever DIALS holds the same ceiling — the settings
/// the linked row is built with, since nothing binds a dial-side instance or hands it a config view.
#[tokio::test]
async fn a_dial_only_instance_holds_the_ceiling_its_root_named() {
    const CAP: usize = 1024;
    let stack = Stack::fold();
    let capped = TransportSettings {
        request_body_max_bytes: CAP,
        ..TransportSettings::default()
    };
    let t = stack.build(None, &capped);
    // The upstream is not capped at this number: it is the dialler's ceiling under test.
    let (t, mine, upstream, theirs) = stack.upgraded(&TransportSettings::default(), t, "/").await;

    // At the ceiling the message is a message, so this is a ceiling and not a smaller default.
    let at_cap = vec![b'k'; CAP];
    upstream
        .write(&theirs, StreamId(0), ScratchBytes::new(&at_cap))
        .await
        .unwrap();
    let mut frames = t.frames(mine);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.len(), CAP);

    let oversized = vec![b'w'; 2 * CAP];
    upstream
        .write(&theirs, StreamId(0), ScratchBytes::new(&oversized))
        .await
        .expect("the uncapped upstream puts the oversized message on the wire");
    let outcome = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("the cap must be enforced rather than waited on")
        .expect("an over-cap message is an error, not a clean end of session");
    assert_eq!(
        outcome.unwrap_err(),
        TransportError::Framing,
        "a dial-side connection is bounded by the same number a served one is"
    );
}

/// A secure target is a statement that the bytes are encrypted before they leave, and this wire
/// encrypts nothing: it frames whatever stream its carrier gives it. Over a cleartext carrier the
/// handshake would therefore go out as a plain HTTP GET, with no certificate ever
/// validated, while the destination said it was secure. The dial is refused instead, and nothing
/// reaches the wire.
#[tokio::test]
async fn a_secure_target_over_a_cleartext_lower_layer_is_refused_before_any_byte_is_written() {
    let stack = Stack::fold();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = tokio::spawn(async move {
        // A refused dial connects to nothing, so the accept is bounded: no connection at all is
        // the passing shape, and waiting on one forever would hang rather than report.
        let Ok(Ok((mut sock, _))) =
            tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
        else {
            return Vec::new();
        };
        let mut buf = vec![0u8; 1024];
        match tokio::time::timeout(
            Duration::from_millis(500),
            tokio::io::AsyncReadExt::read(&mut sock, &mut buf),
        )
        .await
        {
            Ok(Ok(n)) => buf[..n].to_vec(),
            _ => Vec::new(),
        }
    });

    let client_t = stack.dialler();
    let url: &'static str = Box::leak(format!("{}://{addr}/duplex", stack.secure).into_boxed_str());
    let err = client_t
        .dial(&verified_upstream(stack.wire.key, url), &test_key_handle())
        .await
        .expect_err("a secure target dialled over a cleartext lower layer must be refused");
    assert_eq!(err, TransportError::AddressRefused);

    let first_bytes = seen.await.unwrap();
    assert!(
        !first_bytes.starts_with(b"GET "),
        "a secure dial must never put a cleartext HTTP upgrade on the wire: {:?}",
        String::from_utf8_lossy(&first_bytes)
    );
}
