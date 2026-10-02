// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The upgrade wire's cross-transport composition battery: the six cells that drive a real instance
//! of the layers it composes over underneath it.
//!
//! ## Why this lives here and not in the wire's own crate
//!
//! A transport crate is a plugin-kind crate: its own `Cargo.toml` is not allowed to name a sibling
//! transport even in `[dev-dependencies]`, because a dev-dependency's SHIPPED closure is linked into
//! that crate's `cargo test` binary whole (`kind-isolation:closure`'s `closure-test-reach`
//! finding). Composing OVER another wire is real and shipped (an adoption through a contract trait),
//! but PROVING it with a real lower layer needs every layer linked, and the one crate that links
//! them all is the composition root.
//!
//! ## How this file reaches the wires
//!
//! Through the linked transport table, exactly as the boot seal does: build.rs hands this test each
//! linked row's `KEY`, `COMPOSES_OVER` and `build` (`$OUT_DIR/linked_transports.rs`) and the same
//! bottom-up fold `root::registry::compose` runs. The wire under test is named once, as data
//! (`tests/fixtures/composed_battery_wire.txt`); the layer it is built over, and the layer under
//! that, are read off the fold — and the layer it is built over is held to the shipped fold
//! (`src/root/tests/fixtures/transport_fold.txt`), so a declaration that re-layers the wire turns
//! this battery red. The file names no transport crate and spells no transport key.
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

/// The wire under test, its layers and its targets — every key read off the linked table.
struct Stack {
    /// The wire's linked row.
    wire: &'static LinkedWire,
    /// The wire as the fold built it, over `upper`.
    composed: Arc<dyn Transport>,
    /// The layer the fold built the wire over (the one an inbound upgrade arrives on).
    upper: Arc<dyn Transport>,
    /// The first linked layer `upper` declares (the one an outbound dial goes through).
    bottom: Arc<dyn Transport>,
    /// The scheme of a target the wire must refuse over a cleartext layer.
    secure: &'static str,
}

impl Stack {
    /// A fresh fold of every linked wire at the default settings.
    fn fold() -> Self {
        Self::fold_with(&TransportSettings::default())
    }

    fn fold_with(settings: &TransportSettings) -> Self {
        let (key, secure) = rows(BATTERY_WIRE)
            .next()
            .expect("the battery names its wire");
        let built = fold_linked_transports(settings);
        let find = |key: &str| {
            built
                .iter()
                .find(|(row, _)| row.key == key)
                .map(|(row, t)| (*row, Arc::clone(t)))
                .unwrap_or_else(|| panic!("`{key}` is not a linked wire"))
        };
        let (wire, composed) = find(key);
        let upper_key = composed
            .composed_over()
            .unwrap_or_else(|| panic!("the fold built `{key}` over nothing"));
        let (_, shipped) = rows(TRANSPORT_FOLD)
            .find(|(k, _)| *k == key)
            .unwrap_or_else(|| panic!("the shipped fold has no `{key}` row"));
        assert_eq!(
            upper_key, shipped,
            "the fold built `{key}` over a layer the shipped fold does not name"
        );
        let (upper_row, upper) = find(upper_key);
        let bottom_key = upper_row
            .composes_over
            .iter()
            .find(|l| LINKED_TRANSPORTS.iter().any(|r| r.key == **l))
            .unwrap_or_else(|| panic!("`{upper_key}` declares no linked layer"));
        let (_, bottom) = find(bottom_key);
        Self {
            wire,
            composed,
            upper,
            bottom,
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

    /// A fresh instance of the wire over the dial layer, at the default settings.
    fn dialler(&self) -> Arc<dyn Transport> {
        self.build(
            Some(Arc::clone(&self.bottom)),
            &TransportSettings::default(),
        )
    }

    /// A cleartext target on `addr`, whose scheme is the wire's key.
    fn target(&self, addr: impl std::fmt::Display, path: &str) -> &'static str {
        Box::leak(format!("{}://{addr}{path}", self.wire.key).into_boxed_str())
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

/// The in-band upgrade, driven through the seam the design names: the layer below accepts the
/// connection, the wire adopts the stream it gives up, and the handshake runs on the layer that
/// speaks it. The facts of the pre-upgrade layer do not survive it — that layer no longer knows the
/// connection — and the composed chain the adopted connection reports is the real one, not a name
/// for itself.
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
        vec![stack.bottom.key(), upper.key()],
        "the layer below named itself"
    );
    assert_eq!(
        adopter.arrival(&upgraded).transport_chain,
        vec![stack.bottom.key(), upper.key(), stack.wire.key],
        "the composed chain, not a name for itself"
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

/// The genuine network path, over the layers this wire composes over rather than over sockets of
/// its own: the upper layer binds and accepts, the bottom layer dials, and this one does the one
/// thing it owns — the handshake — on the streams they give up.
#[tokio::test]
async fn a_composed_round_trip_over_the_layers_below() {
    let stack = Stack::fold();
    let server_t = Arc::clone(&stack.composed);
    let client_t = stack.dialler();
    let keys = test_key_handle();
    let listener = server_t
        .listen(&ListenerCfg("127.0.0.1:0".to_string(), None), &keys)
        .await
        .unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };

    let dest = verified_upstream(stack.wire.key, stack.target(addr, "/"));
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    // Both ends report the stack they actually stand on, not a name for themselves.
    assert_eq!(
        server_t.arrival(&server_conn).transport_chain,
        vec![stack.bottom.key(), stack.upper.key(), stack.wire.key]
    );
    assert_eq!(
        client_t.arrival(&client_conn).transport_chain,
        vec![stack.bottom.key(), stack.wire.key]
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

/// The layer this instance reports is the one it was built over, and it is one the wire declares —
/// which is what the registry's boot check compares. A composition nobody declared refuses the boot
/// rather than running as a stack the declarations do not describe.
#[tokio::test]
async fn the_layer_reported_is_one_the_transport_declares() {
    let stack = Stack::fold();
    let settings = TransportSettings::default();
    let built = fold_linked_transports(&settings);
    let mut over = Vec::new();
    for layer in stack.wire.composes_over {
        let Some((_, lower)) = built.iter().find(|(row, _)| row.key == *layer) else {
            continue;
        };
        let t = stack.build(Some(Arc::clone(lower)), &settings);
        let used = t.composed_over().expect("built over a layer, it names one");
        assert_eq!(
            used, *layer,
            "the layer reported is the one it was built over"
        );
        assert!(
            stack.wire.composes_over.contains(&used),
            "`{used}` is a layer this wire declares it composes over"
        );
        over.push(used);
    }
    // Both halves of the stack the other cells stand on were built over and answered.
    assert!(
        over.contains(&stack.upper.key()),
        "built over the upper layer"
    );
    assert!(
        over.contains(&stack.bottom.key()),
        "built over the dial layer"
    );
    assert_eq!(stack.build(None, &settings).composed_over(), None);
}

/// The size of message this connection will accept is the operator's number, not the WebSocket
/// library's. Left to the default, a listener declaring a 1 KiB body cap would still buffer 64 MiB
/// per connection before saying no — the deployment's own limit silently widened by four orders of
/// magnitude, at the one layer where an oversized message is cheapest to refuse.
#[tokio::test]
async fn the_message_cap_is_the_operator_s_and_not_the_library_s() {
    const CAP: usize = 1024;
    let stack = Stack::fold();
    let t = Arc::clone(&stack.composed);
    // The listener is where the operator's configuration reaches this transport at all.
    let keys = test_key_handle();
    let listener = t
        .listen(
            &ListenerCfg("127.0.0.1:0".to_string(), Some(CAP as i64)),
            &keys,
        )
        .await
        .unwrap();
    let addr = listener.local_addr();
    let accept_task = {
        let t = t.clone();
        tokio::spawn(async move { t.accept(&listener).await })
    };

    // The peer is not capped at the operator's number, because the cap this test is about is the
    // RECEIVER's: a limit that only holds when the far side agrees to it is not a limit.
    let peer = stack.dialler();
    let a = peer
        .dial(
            &verified_upstream(stack.wire.key, stack.target(addr, "/")),
            &keys,
        )
        .await
        .unwrap();
    let b = accept_task.await.unwrap().unwrap();

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

/// And the other lifecycle: an instance that only ever DIALS holds the same ceiling.
///
/// The cell above reaches the transport through `listen`, which is the seam a served instance
/// learns the deployment's configuration through. A dial-side instance never reaches it — nothing
/// binds it, so nothing hands it a config view — and an upstream that streams audio is exactly the
/// connection an unbounded message ceiling costs the most on. The composition root holds the number
/// in both cases, so it names it at the wire's build here — the settings the linked row is built
/// with — and the same field answers.
#[tokio::test]
async fn a_dial_only_instance_holds_the_ceiling_its_root_named() {
    const CAP: usize = 1024;
    let stack = Stack::fold();
    // No `listen` on this instance: the ceiling arrives only through the build's settings.
    let capped = TransportSettings {
        request_body_max_bytes: CAP,
        ..TransportSettings::default()
    };
    let t = stack.build(Some(Arc::clone(&stack.bottom)), &capped);

    // The upstream is not capped at this number: it is the dialler's ceiling under test.
    let upstream = Arc::clone(&stack.composed);
    let keys = test_key_handle();
    let listener = upstream
        .listen(&ListenerCfg("127.0.0.1:0".to_string(), None), &keys)
        .await
        .unwrap();
    let addr = listener.local_addr();
    let accept_task = {
        let upstream = upstream.clone();
        tokio::spawn(async move { upstream.accept(&listener).await })
    };
    let mine = t
        .dial(
            &verified_upstream(stack.wire.key, stack.target(addr, "/")),
            &keys,
        )
        .await
        .unwrap();
    let theirs = accept_task.await.unwrap().unwrap();

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
/// encrypts nothing: it upgrades whatever stream the layer below gives it. Over a cleartext lower
/// layer the handshake would therefore go out as a plain HTTP GET, with no certificate ever
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
