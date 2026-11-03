// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIVERSAL-NEEDS WITNESS (THE DESIGN: connections — "any plugin of any kind reaches the

use std::sync::OnceLock;

use busbar_contract::conn::{ConnError, PieceKind};

#[allow(unused_imports)]
use busbar_core_connector::{carrier, compose, framer, hostio};

#[allow(dead_code, unsafe_code, unused_imports)]
#[path = "../src/tests/support.rs"]
mod support;

/// The libraries beside this test binary: uplifted, under `deps/`, or an example `cdylib`.
fn libraries_beside_the_test() -> Vec<std::path::PathBuf> {
    let Some(profile) = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.parent()?.to_path_buf()))
    else {
        return Vec::new();
    };
    [
        profile.clone(),
        profile.join("deps"),
        profile.join("examples"),
    ]
    .iter()
    .flat_map(|dir| {
        busbar_plugin_loader::list_plugin_files(dir)
            .into_iter()
            .map(move |f| dir.join(f))
    })
    .collect()
}

/// THE SOCKET FRAMER these tests drive alone: the neutral frame door (the plugin loader's
fn socket_framer_door() -> Option<std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor>> {
    let file = busbar_plugin_loader::plugin_library_filename("neutral_frame_door");
    libraries_beside_the_test()
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n == file.as_str()))
        .find_map(|p| open_door(&p))
}

/// `path` admitted and opened through the one dispatcher as a transport door; `None` when it is
fn open_door(
    path: &std::path::Path,
) -> Option<std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor>> {
    open_stated(path).map(|(door, _)| door)
}

/// [`open_door`], with what the door states (its claims' sessions and upgrades among it).
fn open_stated(
    path: &std::path::Path,
) -> Option<(
    std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor>,
    busbar_plugin_loader::dispatch::kinds::transport::TransportFacts,
)> {
    use busbar_plugin_loader::dispatch::kinds::transport::{Transport, TransportFacts};
    use busbar_plugin_loader::dispatch::{
        load_dropped, rendering_of_library, Bind, DispatchConfig, Dispatcher, NoSink,
    };
    static ONE: OnceLock<std::sync::Arc<Dispatcher>> = OnceLock::new();

    let rendering = rendering_of_library(path).ok()??;
    let on = ONE.get_or_init(|| std::sync::Arc::new(Dispatcher::new(DispatchConfig::default())));
    let bind = Bind {
        instance: std::sync::Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: std::sync::Arc::new(NoSink),
        dispatcher: on.adopter(),

        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    };
    let plugin = load_dropped::<Transport>(path, &rendering, bind).ok()?;
    let stated = plugin.context::<TransportFacts>().cloned()?;
    let door = busbar_core_connector::doors::Dispatched::open_on(
        plugin,
        &busbar_contract::transport::TransportSettings::default(),
        std::sync::Arc::clone(on),
    )
    .expect("the dropped transport opens");
    Some((std::sync::Arc::new(door), stated))
}

/// THE CONNECTOR DRIVES THE DROPPED-IN HTTP DOOR AGAINST A REAL SERVER: the connector dials the
#[test]
fn the_connector_drives_the_dropped_in_http_door_against_a_real_server() {
    use busbar_core_connector::compose::{Connection, Dial};

    let door = composing_door();
    let scheme = door.facts().claims[0];
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (far, seen_rx) = serve_once(respond(
            scheme,
            "{V} 200 OK\r\ncontent-length: 5\r\n\r\nhello",
        ))
        .await;
        let mut c = Connection::dial(
            door,
            &support::via(),
            Dial {
                target: format!("{scheme}://{far}/v1/probe"),
                tls: None,
                alpn: Vec::new(),
                open_timeout: std::time::Duration::from_secs(5),
                opening: Some((
                    vec![
                        ("method".to_owned(), b"GET".to_vec()),
                        ("path".to_owned(), b"/v1/probe".to_vec()),
                    ],
                    Default::default(),
                )),
                head_words: Default::default(),
                anchors: None,
            },
        )
        .expect("the connector dials through the http door");
        let mut pieces = Vec::new();
        loop {
            let p = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                futures::future::poll_fn(|cx| c.poll_piece(cx)),
            )
            .await
            .expect("the server answers")
            .expect("no failure");
            let Some(p) = p else { break };

            let last = !p.fields && p.end_of_frame && p.bytes.is_empty();
            pieces.push(p);
            if last {
                break;
            }
        }
        let seen = seen_rx.await.unwrap();
        assert!(seen.starts_with("GET /v1/probe "), "{seen}");
        let head = pieces.first().expect("a head piece");
        assert_eq!(head.status_code, Some(200));
        let body: Vec<u8> = pieces[1..].iter().flat_map(|p| p.bytes.clone()).collect();
        assert_eq!(body, b"hello");
        assert!(pieces
            .last()
            .is_some_and(|p| p.end_of_frame && p.bytes.is_empty()));
        c.close();
    });
}

/// A BODIED REQUEST GOES OUT THROUGH THE DROPPED-IN HTTP DOOR, its length stated once: whichever
#[test]
fn a_bodied_request_goes_out_through_the_dropped_in_http_door_with_its_length() {
    use busbar_core_connector::compose::{Connection, Dial};

    let door = composing_door();
    let scheme = door.facts().claims[0];
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (far, seen_rx) =
            serve_once(respond(scheme, "{V} 200 OK\r\ncontent-length: 2\r\n\r\nok")).await;
        let mut c = Connection::dial(
            door,
            &support::via(),
            Dial {
                target: format!("{scheme}://{far}/v1/probe"),
                tls: None,
                alpn: Vec::new(),
                open_timeout: std::time::Duration::from_secs(5),
                opening: Some((
                    vec![
                        ("method".to_owned(), b"POST".to_vec()),
                        ("path".to_owned(), b"/v1/probe".to_vec()),
                        ("content-type".to_owned(), b"application/json".to_vec()),
                    ],
                    b"{\"a\":1}".to_vec().into(),
                )),
                head_words: Default::default(),
                anchors: None,
            },
        )
        .expect("the connector dials through the http door");
        let first = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            futures::future::poll_fn(|cx| c.poll_piece(cx)),
        )
        .await
        .expect("the server answers")
        .expect("the request is sent, never refused")
        .expect("a head piece");
        assert_eq!(first.status_code, Some(200));
        let seen = seen_rx.await.unwrap();
        assert!(seen.starts_with("POST /v1/probe "), "{seen}");
        let lengths: Vec<&str> = seen
            .split("\r\n")
            .filter(|l| {
                l.split_once(':')
                    .is_some_and(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            })
            .collect();
        assert_eq!(lengths.len(), 1, "{seen}");
        assert_eq!(
            lengths[0].split_once(':').map(|(_, v)| v.trim()),
            Some("7"),
            "{seen}"
        );
        c.close();
    });
}

/// THE CONNECTOR DRIVES A DROPPED-IN DOOR THAT FRAMES THE HOST'S SOCKET against a real far end: the
#[test]
fn the_connector_drives_a_dropped_in_socket_framer_against_a_real_far_end() {
    use busbar_core_connector::compose::{Connection, Dial};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let door = socket_framer_door().expect("a socket-framing door is built beside the test");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0_u8; 4096];
            while let Ok(n) = s.read(&mut buf).await {
                if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        let mut c = Connection::dial(
            door,
            &support::via(),
            Dial {
                target: far,
                tls: None,
                alpn: Vec::new(),
                open_timeout: std::time::Duration::from_secs(5),
                opening: Some((Vec::new(), b"opening;".to_vec().into())),
                head_words: Default::default(),
                anchors: None,
            },
        )
        .expect("the connector dials through the door");
        let payload: Vec<u8> = (0..=255_u8).cycle().take(40_000).collect();
        c.write(
            &payload,
            true,
            false,
            &mut std::task::Context::from_waker(std::task::Waker::noop()),
        )
        .expect("the write is taken");
        let mut got = Vec::new();
        while got.len() < 8 + payload.len() {
            let p = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                futures::future::poll_fn(|cx| c.poll_piece(cx)),
            )
            .await
            .expect("the far end answers")
            .expect("no failure")
            .expect("not ended");
            got.extend(p.bytes);
        }
        assert_eq!(&got[..8], b"opening;");
        assert_eq!(&got[8..], &payload[..]);
        c.close();
    });
}

/// Every piece one need's exchange answers through the connection table, from a server that
fn pieces_through_the_table(response: &'static str) -> Vec<(PieceKind, Option<u32>, Vec<u8>)> {
    head_through_the_table(response).0
}

type Pieces = Vec<(PieceKind, Option<u32>, Vec<u8>)>;

/// [`pieces_through_the_table`], and the head's reason phrase as the table handed it.
fn head_through_the_table(response: &'static str) -> (Pieces, Option<Vec<u8>>) {
    use busbar_contract::conn::{Conns, InstanceId, NeedId, OpenDesc};
    use busbar_core_connector::registry::{Entry, Transports};
    use busbar_core_connector::{Connector, Judged};

    let door = composing_door();
    let scheme = door.facts().claims[0];

    let layer: std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> =
        std::sync::Arc::new(support::TestDoor::identity("test-carrier"));
    let response = respond(scheme, response);

    let judge = |dest: &str, _: u32, _: Judged| {
        Some(dest.parse::<std::net::SocketAddr>().map_err(|_| 1_u64))
    };
    let c = Connector::serving(
        Transports::new(vec![
            Entry {
                door,
                alpn: Vec::new(),
            },
            Entry {
                door: layer,
                alpn: Vec::new(),
            },
        ])
        .unwrap(),
        std::sync::Arc::new(judge),
        None,
        std::sync::Arc::new(|_, _| {}),
    );
    let owner = InstanceId(1);
    c.declare_over(owner, NeedId(0), scheme)
        .expect("a served scheme declares");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (far, _) = serve_once(response).await;
        let target = format!("{scheme}://{far}/v1/probe");
        let fields: [(&str, &[u8]); 2] = [("method", b"GET"), ("path", b"/v1/probe")];
        let desc = OpenDesc {
            target: &target,
            fields: &fields,
            ..OpenDesc::default()
        };
        let id = c.open(owner, NeedId(0), &desc).expect("opens");
        let mut got = Vec::new();
        let mut reason = None;
        let mut buf = [0_u8; 4096];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            assert!(std::time::Instant::now() < deadline, "the server answers");
            match c.read(owner, id, 7, &mut buf) {
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                Err(e) => panic!("the exchange failed: {e}"),
                Ok(p) => {
                    let done = p.kind == PieceKind::Completion
                        || (p.kind == PieceKind::Body && p.end && p.len == 0);
                    if let Some(r) = p.reason.clone() {
                        reason = Some(buf[r].to_vec());
                    }
                    got.push((p.kind, p.status_code, buf[..p.len].to_vec()));
                    if done {
                        break;
                    }
                }
            }
        }
        c.close(owner, id).unwrap();
        (got, reason)
    })
}

/// RED: THE CONNECTOR YIELDS THE FAR END'S HEAD. A response with head fields reads, through the
#[test]
fn a_response_with_head_fields_yields_fields_then_body() {
    let got = pieces_through_the_table(
        "{V} 200 OK\r\nX-B: 1\r\nConnection: keep-alive, x-hop\r\nX-Session-Id: s1\r\n\
          Keep-Alive: timeout=5\r\nx-b: 2\r\nX-Hop: secret\r\ncontent-length: 5\r\n\r\nhello",
    );
    let (kind, status, head) = &got[0];
    assert_eq!((*kind, *status), (PieceKind::Fields, Some(200)), "{got:?}");
    assert_eq!(
        String::from_utf8_lossy(head),
        "x-b: 1\r\nx-b: 2\r\nx-session-id: s1\r\n"
    );

    let (last, between) = got[1..].split_last().expect("pieces after the head");
    assert_eq!(last.0, PieceKind::Completion, "{got:?}");
    let body: Vec<u8> = between
        .iter()
        .inspect(|(k, _, _)| assert_eq!(*k, PieceKind::Body, "{got:?}"))
        .flat_map(|(_, _, b)| b.clone())
        .collect();
    assert_eq!(body, b"hello");
}

/// RED: AN EMPTY HEAD STILL COMES FIRST. A head with no field left after the hop-by-hop drop reads
#[test]
fn an_empty_head_yields_one_empty_fields_piece() {
    let got = pieces_through_the_table("{V} 204 No Content\r\nConnection: close\r\n\r\n");
    assert_eq!(
        got[0],
        (PieceKind::Fields, Some(204), Vec::new()),
        "{got:?}"
    );
    assert_eq!(
        got.iter()
            .filter(|(k, _, _)| *k == PieceKind::Fields)
            .count(),
        1,
        "{got:?}"
    );
}

/// RED: the reply's head crosses whole: its fields as the field block and its reason phrase exactly
#[test]
fn the_reply_head_carries_its_reason_phrase_exactly_as_sent() {
    let (got, reason) =
        head_through_the_table("{V} 200 Fine By Me\r\nx-a: 1\r\ncontent-length: 2\r\n\r\nok");
    assert_eq!(
        got[0],
        (PieceKind::Fields, Some(200), b"x-a: 1\r\n".to_vec())
    );
    assert_eq!(reason.as_deref(), Some(&b"Fine By Me"[..]));
    let (_, reason) = head_through_the_table("{V} 204 No Content\r\n\r\n");
    assert_eq!(reason.as_deref(), Some(&b"No Content"[..]));
}

/// RED: a request's head words reach the framer byte for byte and ARE its request line; a framer
#[test]
fn the_head_words_reach_the_framer_byte_for_byte() {
    use busbar_core_connector::framer::{encode, encode_head};
    let door = composing_door();
    let wire = encode_head(
        door.as_ref(),
        b"PATCH",
        b"/v1/x?y=%20z",
        &[("x-a", b"1")],
        b"",
    )
    .expect("renders");
    let text = String::from_utf8_lossy(&wire).into_owned();
    assert!(text.starts_with("PATCH /v1/x?y=%20z "), "{text}");
    assert!(
        text.split("\r\n")
            .next()
            .is_some_and(|line| line.split(' ').count() == 3),
        "{text}"
    );
    let plain = socket_framer_door().expect("a socket-framing door is built beside the test");
    assert_eq!(
        encode_head(plain.as_ref(), b"PATCH", b"/x", &[], b"body").ok(),
        encode(plain.as_ref(), &[], b"body").ok()
    );
}

/// The actual dropped request framer's sealed opening crosses host wire ownership and TLS with
#[test]
fn a_dropped_framers_sealed_opening_keeps_its_exact_wire_bytes_through_tls() {
    use busbar_contract::conn::SEALED_FIELDS_FIELD;
    use busbar_core_connector::compose::{Dial, Planned};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SECRET: &[u8] = b"Bearer exact-sealed-opening-credential";
    const BODY: &[u8] = b"application-body-unchanged";
    const METHOD: &[u8] = b"POST";
    const TARGET: &[u8] = b"/v1/wire-custody";
    const PROTOCOL: &[u8] = b"http/1.1";
    let door = composing_door();
    let scheme = door
        .facts()
        .claims
        .iter()
        .copied()
        .find(|claim| {
            framer::locate(door.as_ref(), &format!("{claim}://127.0.0.1:443/"))
                .is_ok_and(|located| located.secure)
        })
        .expect("the request framer states its secured claim");
    busbar_core_connector::tls::install_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .unwrap();
    let trust = busbar_contract::transport::trust::EgressTrust {
        extra_anchors: vec![cert.der().to_vec()],
        ..Default::default()
    };
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap(),
        )
        .unwrap();

    let protocol = framer::accept_offer(door.as_ref())
        .unwrap()
        .into_iter()
        .find(|protocol| protocol.as_slice() == PROTOCOL)
        .expect("the framer offers the HTTP/1.1 wire this witness compares");
    server.alpn_protocols = vec![protocol];
    support::worker().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = listener.local_addr().unwrap();
        let response = respond(
            door.facts().claims[0],
            "{V} 200 OK\r\ncontent-length: 0\r\n\r\n",
        );
        let read = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_rustls::TlsAcceptor::from(Arc::new(server))
                .accept(socket)
                .await
                .unwrap();
            assert_eq!(socket.get_ref().1.alpn_protocol(), Some(PROTOCOL));
            let mut got = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !got.ends_with(BODY) {
                let read = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(read > 0, "the sealed opening arrives whole");
                got.extend_from_slice(&buffer[..read]);
            }
            socket.write_all(&response).await.unwrap();
            socket.shutdown().await.unwrap();
            got
        });
        let planned = Planned::locate(
            door.clone(),
            support::via(),
            Dial {
                target: format!("{scheme}://{far}/v1/wire-custody"),
                tls: Some(Arc::new(
                    busbar_core_connector::tls::client::build_client_config(&trust).unwrap(),
                )),
                alpn: Vec::new(),
                open_timeout: Duration::from_secs(5),
                opening: Some((
                    vec![
                        ("authorization".to_owned(), SECRET.to_vec()),
                        (SEALED_FIELDS_FIELD.to_owned(), b"authorization".to_vec()),
                    ],
                    BODY.to_vec().into(),
                )),
                head_words: (METHOD.to_vec(), TARGET.to_vec()),
                anchors: None,
            },
        )
        .unwrap();
        let (fields, body) = planned.dial().opening.as_ref().unwrap();
        let fields: Vec<(&str, &[u8])> = fields
            .iter()
            .filter(|(name, _)| name != SEALED_FIELDS_FIELD)
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let expected = framer::encode_head(door.as_ref(), METHOD, TARGET, &fields, body).unwrap();
        let mut connection = planned.dial_at(far).unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            futures::future::poll_fn(|context| connection.poll_piece(context)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            connection.established().agreed_protocol.as_deref(),
            Some(PROTOCOL)
        );
        assert_eq!(
            connection.established().scheme,
            busbar_contract::abi::host::service::SCHEME_SECURE
        );
        let got = read.await.unwrap();
        assert_eq!(
            got, expected,
            "TLS carries exactly the framer's original credential and body bytes"
        );
        assert!(got.ends_with(BODY));
        assert!(got.windows(SECRET.len()).any(|part| part == SECRET));
        assert!(!got
            .windows(SEALED_FIELDS_FIELD.len())
            .any(|part| part == SEALED_FIELDS_FIELD.as_bytes()));
        connection.close();
    });
}

/// THE REQUEST/RESPONSE FRAMER the head tests drive: of the libraries beside this test binary, the
fn composing_door() -> std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> {
    use busbar_contract::abi::transport::ROLE_FRAMER;
    if let Some(path) = std::env::var_os("BUSBAR_TEST_HTTP_CDYLIB") {
        let (door, stated) = open_stated(std::path::Path::new(&path))
            .expect("BUSBAR_TEST_HTTP_CDYLIB opens the qualified HTTP transport");
        assert_eq!(door.facts().role, ROLE_FRAMER);
        assert!(!stated.sessions.contains(&door.facts().claims[0]));
        return door;
    }
    libraries_beside_the_test()
        .into_iter()
        .filter_map(|p| open_stated(&p))
        .find(|(d, s)| d.facts().role == ROLE_FRAMER && !s.sessions.contains(&d.facts().claims[0]))
        .map(|(d, _)| d)
        .expect("a request/response framer door is built beside the test binary")
}

/// A response template with its version written as the door's own scheme, upper-cased (`{V}`), so
fn respond(scheme: &str, template: &str) -> Vec<u8> {
    template
        .replace("{V}", &format!("{}/1.1", scheme.to_ascii_uppercase()))
        .into_bytes()
}

/// A loopback far end that reads one request head and answers `response`: its address, and the
async fn serve_once(
    response: Vec<u8>,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut req = Vec::new();
        let mut buf = [0_u8; 1024];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0, "the request head arrives");
            req.extend_from_slice(&buf[..n]);
        }
        let _ = seen_tx.send(String::from_utf8_lossy(&req).into_owned());
        s.write_all(&response).await.unwrap();
    });
    (far, seen_rx)
}

/// RED: A FRAMED REQUEST'S HEAD WORDS GO OUT THROUGH THE CONNECTION TABLE. An open whose
#[test]
fn an_opening_messages_head_words_reach_the_far_end_through_the_table() {
    use busbar_contract::conn::{Conns, DeclaredConns, InstanceId, NeedId, OpenDesc};
    use busbar_core_connector::registry::{Entry, Transports};
    use busbar_core_connector::{Connector, Judged};

    let door = composing_door();
    let scheme = door.facts().claims[0];

    let layer: std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> =
        std::sync::Arc::new(support::TestDoor::identity("test-carrier"));
    let raw = layer.facts().claims[0];
    let judge = |dest: &str, _: u32, _: Judged| {
        Some(dest.parse::<std::net::SocketAddr>().map_err(|_| 1_u64))
    };
    let c = Connector::serving(
        Transports::new(vec![
            Entry {
                door,
                alpn: Vec::new(),
            },
            Entry {
                door: layer,
                alpn: Vec::new(),
            },
        ])
        .unwrap(),
        std::sync::Arc::new(judge),
        None,
        std::sync::Arc::new(|_, _| {}),
    );
    let owner = InstanceId(1);
    c.declare_over(owner, NeedId(1), raw)
        .expect("a served scheme declares");
    assert!(!c.framed(owner, NeedId(1)), "the carrier is a raw stream");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (far, mut seen) =
            serve_once(respond(scheme, "{V} 200 OK\r\ncontent-length: 0\r\n\r\n")).await;
        let declared = format!("{scheme}://{far}");
        c.declare_need_to(owner, NeedId(0), scheme, 0, &declared)
            .expect("a served scheme declares");
        assert!(c.framed(owner, NeedId(0)), "the framer is framed");
        let fields: [(&str, &[u8]); 1] = [("x-a", b"1")];
        let desc = OpenDesc {
            fields: &fields,
            method: b"PATCH",
            head_target: b"/v1/x?y=1",
            ..OpenDesc::default()
        };
        let id = c
            .open(owner, NeedId(0), &desc)
            .expect("opens at the declared target");
        let mut buf = [0_u8; 1024];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let request = loop {
            assert!(
                std::time::Instant::now() < deadline,
                "the far end reads the request"
            );

            match c.read(owner, id, 7, &mut buf) {
                Err(ConnError::Pending) | Ok(_) => {}
                Err(e) => panic!("the exchange failed: {e}"),
            }
            if let Ok(request) = seen.try_recv() {
                break request;
            }
            tokio::task::yield_now().await;
        };
        assert!(request.starts_with("PATCH /v1/x?y=1 "), "{request}");
        assert!(
            request.to_ascii_lowercase().contains("\r\nx-a: 1\r\n"),
            "{request}"
        );
        c.close(owner, id).unwrap();
    });
}

/// The download's table over a connector serving the composing door beside the test carrier, every
fn fetch_table() -> (&'static str, busbar_core_connector::fetch::Table) {
    use busbar_core_connector::Judged;
    let judge = |dest: &str, _: u32, _: Judged| {
        Some(dest.parse::<std::net::SocketAddr>().map_err(|_| 1_u64))
    };
    fetch_table_judged(std::sync::Arc::new(judge))
}

/// The download's table over a connector serving the composing door beside the test carrier, its
fn fetch_table_judged(
    judge: std::sync::Arc<dyn busbar_core_connector::DialJudge>,
) -> (&'static str, busbar_core_connector::fetch::Table) {
    use busbar_contract::conn::{DeclaredConns, InstanceId, NeedId, PollConns};
    use busbar_core_connector::registry::{Entry, Transports};
    use busbar_core_connector::Connector;

    let door = composing_door();
    let scheme = door.facts().claims[0];
    let layer: std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> =
        std::sync::Arc::new(support::TestDoor::identity("test-carrier"));
    let c = std::sync::Arc::new(Connector::serving(
        Transports::new(vec![
            Entry {
                door,
                alpn: Vec::new(),
            },
            Entry {
                door: layer,
                alpn: Vec::new(),
            },
        ])
        .unwrap(),
        judge,
        None,
        std::sync::Arc::new(|_, _| {}),
    ));
    let table = busbar_core_connector::fetch::Table {
        owner: InstanceId(9),
        secured_need: NeedId(1),
        plain_need: NeedId(2),
        declared: std::sync::Arc::clone(&c) as std::sync::Arc<dyn DeclaredConns>,
        conns: c as std::sync::Arc<dyn PollConns>,
    };
    (scheme, table)
}

/// One download of `path` from a far end answering `response` (a [`respond`] template), off the
fn fetch_once(path: &str, response: &str, cap: usize) -> (Result<Vec<u8>, String>, String) {
    fetch_once_over(fetch_table(), path, response, cap)
}

/// [`fetch_once`] over `table` (its door's scheme and the table).
fn fetch_once_over(
    (scheme, table): (&'static str, busbar_core_connector::fetch::Table),
    path: &str,
    response: &str,
    cap: usize,
) -> (Result<Vec<u8>, String>, String) {
    let response = respond(scheme, response);
    let path = path.to_owned();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let (far, seen) = serve_once(response).await;
        let url = format!("{scheme}://{far}{path}");
        let got = tokio::task::spawn_blocking(move || {
            busbar_core_connector::fetch::download(&table, &url, &[], cap)
        })
        .await
        .unwrap();
        let head = tokio::time::timeout(std::time::Duration::from_secs(10), seen)
            .await
            .map(|h| h.unwrap_or_default())
            .unwrap_or_default();
        (got, head)
    })
}

/// THE DOWNLOAD'S WIRE IS 1.5.5's: `GET <path>` with the client defaults the transport owns,
#[test]
fn the_plugins_fetch_download_sends_1_5_5s_request_through_the_table() {
    let (got, head) = fetch_once(
        "/releases/busbar-oracle-fetch-1.0.0.tar.gz",
        "{V} 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nartifact",
        4096,
    );
    assert_eq!(got.as_deref(), Ok(&b"artifact"[..]));
    let scheme = composing_door().facts().claims[0];
    let version = format!("{}/1.1", scheme.to_ascii_uppercase());
    let host = head
        .split("\r\n")
        .find_map(|l| l.strip_prefix("host: "))
        .unwrap_or_default()
        .to_owned();
    assert_eq!(
        head,
        format!(
            "GET /releases/busbar-oracle-fetch-1.0.0.tar.gz {version}\r\naccept: */*\r\n\
             host: {host}\r\n\r\n"
        ),
        "the request on the wire is 1.5.5's"
    );
    assert!(host.starts_with("127.0.0.1:"), "{head}");
}

/// An oversized body is refused under the cap, from an honest `Content-Length` (before a body
#[test]
fn the_plugins_fetch_download_refuses_an_oversized_body_and_keeps_a_small_one() {
    let big = "x".repeat(256);
    let (got, _) = fetch_once(
        "/big",
        &format!("{{V}} 200 OK\r\ncontent-length: 256\r\n\r\n{big}"),
        64,
    );
    let err = got.expect_err("an over-cap download is a clear error");
    assert!(
        err.contains("declared Content-Length 256 exceeds the 64-byte"),
        "{err}"
    );

    let chunks = "8\r\nxxxxxxxx\r\n".repeat(32);
    let (got, _) = fetch_once(
        "/big-streamed",
        &format!("{{V}} 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{chunks}0\r\n\r\n"),
        64,
    );
    let err = got.expect_err("an over-cap download with no Content-Length is still refused");
    assert!(
        err.contains("response exceeded the 64-byte plugins.fetch download cap"),
        "{err}"
    );

    let small = "y".repeat(32);
    let (got, _) = fetch_once(
        "/small",
        &format!("{{V}} 200 OK\r\ncontent-length: 32\r\nconnection: close\r\n\r\n{small}"),
        64,
    );
    assert_eq!(
        got,
        Ok(small.into_bytes()),
        "a within-cap download is the body exactly"
    );
}

/// A redirect is refused and never followed, in 1.5.5's words.
#[test]
fn the_plugins_fetch_download_refuses_to_follow_a_redirect() {
    let (got, _) = fetch_once(
        "/artifact",
        "{V} 302 Found\r\nlocation: /metadata\r\ncontent-length: 0\r\n\r\n",
        4096,
    );
    let err = got.expect_err("a redirect is refused, not followed");
    assert!(
        err.contains(
            "302 Found — refusing to follow a plugins.fetch redirect (redirect-SSRF guard)"
        ),
        "{err}"
    );
}

/// The deployment's own dial judge: the one destination guard over `destinations`, the owner's
fn guarded(blocked: &[&str]) -> std::sync::Arc<dyn busbar_core_connector::DialJudge> {
    let destinations = busbar_kernel::config::Destinations {
        block_private_addresses: true,
        blocked: blocked.iter().map(|b| (*b).to_owned()).collect(),
        ..busbar_kernel::config::Destinations::default()
    };
    busbar_core_connector::process::judge(
        busbar_core_connector::process::dest_judge(&destinations).expect("a valid guard"),
        &[],
    )
}

/// A plaintext private registry downloads under the default guard.
#[test]
fn a_plaintext_private_registry_downloads_under_the_default_guard() {
    let (got, _) = fetch_once_over(
        fetch_table_judged(guarded(&[])),
        "/releases/busbar-oracle-fetch-1.0.0.tar.gz",
        "{V} 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nartifact",
        4096,
    );
    assert_eq!(got.as_deref(), Ok(&b"artifact"[..]));
}

/// GREEN twin: the download is still judged by the one guard: an address the operator's extra
#[test]
fn a_download_the_guard_refuses_never_reaches_the_registry() {
    let (got, head) = fetch_once_over(
        fetch_table_judged(guarded(&["127.0.0.1"])),
        "/releases/busbar-oracle-fetch-1.0.0.tar.gz",
        "{V} 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nartifact",
        4096,
    );
    let err = got.expect_err("an address the guard refuses is never downloaded from");
    assert!(err.contains("error sending request"), "{err}");
    assert!(head.is_empty(), "no request reached the far end: {head}");
}
