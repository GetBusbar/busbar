// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};
use std::sync::Mutex;

struct Observed {
    inner: Arc<crate::support::PendingDoor>,
    emits: Mutex<Vec<(u64, bool, Vec<u8>)>>,
    break_resumed: bool,
}

impl Observed {
    fn note(&self, resume: bool, call: &Call<'_>) {
        if let Call::Emit(input, _) = call {
            let extension = input.head.extensions;
            let bytes = if extension.len == 0 {
                Vec::new()
            } else {
                // SAFETY: the connector lends the complete extension for this crossing.
                unsafe { std::slice::from_raw_parts(extension.ptr, extension.len) }.to_vec()
            };
            self.emits
                .lock()
                .unwrap()
                .push((input.stream, resume, bytes));
        }
    }
}

impl FramerDoor for Observed {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn seals_values(&self) -> bool {
        self.inner.seals_values()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.note(false, &call);
        self.inner.cross(call)
    }
    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        self.inner.framing_side()
    }
    fn cross_on(&self, side: &dyn crate::carrier::Side, resume: bool, call: Call<'_>) -> Crossed {
        self.note(resume, &call);
        match call {
            Call::Emit(input, output) if resume && self.break_resumed => {
                let crossed = self.inner.cross_on(side, resume, Call::Emit(input, output));
                if crossed.outcome == busbar_contract::abi::mechanism::call::Outcome::Ready {
                    let len = output.yielded.wire_len as usize;
                    assert!(len <= input.sink.wire_cap);
                    // SAFETY: this READY output initializes the checked prefix of the host sink.
                    unsafe {
                        std::ptr::write_bytes(input.sink.wire, b'!', len);
                    }
                }
                crossed
            }
            other => self.inner.cross_on(side, resume, other),
        }
    }
}

fn named(fields: &[u8], name: &str) -> bool {
    let Some(value) = busbar_contract::abi::mechanism::extensions::get(fields, "fields.sensitive")
    else {
        return false;
    };
    let mut expected = 1_u32.to_le_bytes().to_vec();
    expected.extend_from_slice(&1_u32.to_le_bytes());
    expected.extend_from_slice(&(name.len() as u32).to_le_bytes());
    expected.extend_from_slice(name.as_bytes());
    value == expected
}

#[test]
fn trusted_names_survive_unsealed_encoding_early_writes_and_a_pending_opening_emit() {
    worker().block_on(async {
        let far = echo().await;
        let inner = Arc::new(crate::support::PendingDoor::new(
            TestDoor::new(
                "bytes",
                &["bytes"],
                &[],
                Knobs {
                    render_fields: true,
                    ..Knobs::default()
                },
            ),
            EXCHANGE_STREAM,
        ));
        let door = Arc::new(Observed {
            inner: inner.clone(),
            emits: Mutex::new(Vec::new()),
            break_resumed: false,
        });
        let mut d = dial(&far);
        d.opening = Some((
            vec![
                ("x-api-key".into(), b"dummy-first".to_vec()),
                (
                    busbar_contract::conn::SEALED_FIELDS_FIELD.into(),
                    b"X-Api-Key".to_vec(),
                ),
            ],
            b"first".to_vec().into(),
        ));
        let mut c = Connection::dial(door.clone(), &crate::support::via(), d).unwrap();
        c.open_exchange(
            3,
            Some((
                vec![
                    ("x-second".into(), b"dummy-second".to_vec()),
                    (
                        busbar_contract::conn::SEALED_FIELDS_FIELD.into(),
                        b"x-second".to_vec(),
                    ),
                ],
                b"second".to_vec().into(),
            )),
            HeadWords::default(),
            &mut std::task::Context::from_waker(std::task::Waker::noop()),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), next(&mut c))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        {
            let emits = door.emits.lock().unwrap();
            assert!(emits.iter().any(|(stream, resume, fields)| *stream == 1
                && !resume
                && named(fields, "x-api-key")));
            assert!(emits
                .iter()
                .any(|(stream, _, fields)| *stream == 3 && named(fields, "x-second")));
            assert!(!emits
                .iter()
                .any(|(stream, _, fields)| *stream == 3 && named(fields, "x-api-key")));
        }
        inner.host.complete(1);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if door
                    .emits
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(stream, resume, fields)| {
                        *stream == 1 && *resume && named(fields, "x-api-key")
                    })
                {
                    break;
                }
                next(&mut c).await.unwrap().unwrap();
            }
        })
        .await
        .unwrap();
    });
}

#[test]
fn query_target_classification_stays_with_initial_and_pooled_pending_openings() {
    worker().block_on(async {
        let far = echo().await;
        let inner = Arc::new(crate::support::PendingDoor::new(
            TestDoor::new(
                "bytes",
                &["bytes"],
                &[],
                Knobs {
                    render_fields: true,
                    render_target: true,
                    ..Knobs::default()
                },
            ),
            EXCHANGE_STREAM,
        ));
        let door = Arc::new(Observed {
            inner: inner.clone(),
            emits: Mutex::new(Vec::new()),
            break_resumed: false,
        });
        let opening = |value: &[u8]| {
            Some((
                vec![("busbar-sealed-query".into(), value.to_vec())],
                b"body".to_vec().into(),
            ))
        };
        let mut d = dial(&far);
        d.opening = opening(b"key=first");
        d.head_words = (b"POST".to_vec(), b"/first?".to_vec());
        let mut c = Connection::dial(door.clone(), &crate::support::via(), d).unwrap();
        c.open_exchange(
            3,
            opening(b"key=second"),
            (b"POST".to_vec(), b"/second?old=1".to_vec()),
            &mut Context::from_waker(std::task::Waker::noop()),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), next(&mut c))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        {
            let emits = door.emits.lock().unwrap();
            for stream in [1, 3] {
                assert!(emits
                    .iter()
                    .any(|(s, _, fields)| *s == stream && named(fields, ":path")));
            }
        }
        inner.host.complete(1);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if door
                    .emits
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(stream, resume, fields)| {
                        *stream == 1 && *resume && named(fields, ":path")
                    })
                {
                    break;
                }
                next(&mut c).await.unwrap().unwrap();
            }
        })
        .await
        .unwrap();
        let handed = inner.inner.handed.lock().unwrap();
        assert!(!handed
            .windows(b"busbar-sealed-query".len())
            .any(|w| w == b"busbar-sealed-query"));
        for target in [b"/first?key=first".as_slice(), b"/second?old=1&key=second"] {
            assert!(handed.windows(target.len()).any(|w| w == target));
        }
    });
}

#[test]
fn sealed_query_pending_and_completed_streams_keep_independent_credentials() {
    crate::tls::install_crypto_provider();
    for pending in [1, 3] {
        for broken in [false, true] {
            let (ca, leaf, key) = localhost_cert();
            worker().block_on(async move {
                let mut server = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![leaf.into()],
                        rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
                    )
                    .unwrap();
                server.alpn_protocols = vec![b"http/1.1".to_vec()];
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let far = listener.local_addr().unwrap().to_string();
                let read = tokio::spawn(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let mut got = Vec::new();
                    let _ =
                        tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut got))
                            .await;
                    got
                });
                let inner = Arc::new(crate::support::PendingDoor::new(
                    TestDoor::new(
                        "sec",
                        &["sec"],
                        &[],
                        Knobs {
                            secure_name: Some("localhost"),
                            seals: true,
                            render_fields: true,
                            render_target: true,
                            ..Knobs::default()
                        },
                    ),
                    pending,
                ));
                let door = Arc::new(Observed {
                    inner: inner.clone(),
                    emits: Mutex::new(Vec::new()),
                    break_resumed: broken,
                });
                let trust = busbar_contract::transport::trust::EgressTrust {
                    extra_anchors: vec![ca],
                    ..Default::default()
                };
                let opening = |value: &[u8]| {
                    Some((
                        vec![("busbar-sealed-query".into(), value.to_vec())],
                        b"BODY".to_vec().into(),
                    ))
                };
                let mut d = dial(&far);
                d.tls = Some(Arc::new(
                    crate::tls::client::build_client_config(&trust).unwrap(),
                ));
                d.head_words = (b"GET".to_vec(), b"/initial".to_vec());
                d.opening = opening(if pending == 1 {
                    b"key=pending-secret"
                } else {
                    b"key=initial-secret"
                });
                let mut c = Connection::dial(door, &crate::support::via(), d).unwrap();
                tokio::time::timeout(
                    Duration::from_secs(5),
                    futures::future::poll_fn(|cx| {
                        if let Poll::Ready(Err(error)) = c.poll_piece(cx) {
                            return Poll::Ready(Err(error));
                        }
                        if c.is_open() {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Pending
                        }
                    }),
                )
                .await
                .unwrap()
                .expect("a sealed pending initial emit does not fail the connection");
                if pending == 3 {
                    c.open_exchange(
                        3,
                        opening(b"key=pending-secret"),
                        (b"GET".to_vec(), b"/pooled".to_vec()),
                        &mut Context::from_waker(std::task::Waker::noop()),
                    )
                    .expect("a pooled emit may pend");
                }
                let completed = if pending == 1 { 3 } else { 5 };
                c.open_exchange(
                    completed,
                    opening(b"key=ready-secret"),
                    (b"GET".to_vec(), b"/ready".to_vec()),
                    &mut Context::from_waker(std::task::Waker::noop()),
                )
                .expect("another stream can complete while this one holds its seal");
                assert!(c.framing.as_ref().unwrap().holds(pending));
                inner.host.complete(1);
                let resumed = tokio::time::timeout(
                    Duration::from_secs(5),
                    futures::future::poll_fn(|cx| {
                        if let Poll::Ready(Err(error)) = c.poll_piece(cx) {
                            return Poll::Ready(Err(error));
                        }
                        if !c.framing.as_ref().unwrap().holds(pending) {
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Pending
                    }),
                )
                .await
                .unwrap();
                assert_eq!(
                    resumed.is_err(),
                    broken,
                    "missing filler is checked only after its own emit settles"
                );
                c.close();
                let got = read.await.unwrap();
                let contains = |needle: &[u8]| got.windows(needle.len()).any(|w| w == needle);
                assert!(
                    contains(b"ready-secret"),
                    "completed stream reached the peer"
                );
                assert_eq!(contains(b"pending-secret"), !broken);
                let handed = inner.inner.handed.lock().unwrap();
                assert!(
                    !handed.windows(b"secret".len()).any(|w| w == b"secret"),
                    "only filler reaches the framer"
                );
            });
        }
    }
}
