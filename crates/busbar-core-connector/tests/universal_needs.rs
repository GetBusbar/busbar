// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIVERSAL-NEEDS WITNESS (THE DESIGN: connections — "any plugin of any kind reaches the
//! network only through a need"): the connector drives a dropped-in transport framer door through the
//! one dispatcher's crossing, every byte through the connection table.
//!
//! The JSON-lane secret fixture this file also drove (`examples/need_dialler.rs`, loaded through the
//! secret kind's JSON lane) went with that lane (THE DESIGN §11.1, the P2 switch-over): a secret
//! plugin reaches the network through its door's needs, on the connector its host hands the
//! instance at open.

use std::sync::OnceLock;

use busbar_contract::conn::{ConnError, PieceKind};

// ── the connector drives a dropped-in framer door ───────────────────────────────────────────────

/// A dropped-in transport door, as the connector reaches it: the one dispatcher's crossing, the
/// host's `in`/`out` copied in and the answer copied back.
struct DroppedDoor {
    plugin: busbar_plugin_loader::dispatch::Plugin<
        busbar_plugin_loader::dispatch::kinds::transport::Transport,
    >,
    facts: busbar_core_connector::framer::DoorFacts,
}

fn cross<I, O>(
    p: &busbar_plugin_loader::dispatch::Plugin<
        busbar_plugin_loader::dispatch::kinds::transport::Transport,
    >,
    s: u32,
    i: &mut I,
    o: &mut O,
) -> busbar_core_connector::framer::Crossed
where
    I: busbar_plugin_loader::dispatch::InFrame,
    O: busbar_plugin_loader::dispatch::OutFrame,
{
    let mut f = busbar_plugin_loader::dispatch::Frame::new(*i, *o);
    let c = p.call(s, &mut f);
    *i = f.input;
    *o = f.out;
    busbar_core_connector::framer::Crossed {
        outcome: c.outcome,
        error: c.error,
    }
}

impl busbar_core_connector::framer::FramerDoor for DroppedDoor {
    fn facts(&self) -> &busbar_core_connector::framer::DoorFacts {
        &self.facts
    }

    fn cross(
        &self,
        call: busbar_core_connector::framer::Call<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        use busbar_contract::abi::transport::slot;
        use busbar_core_connector::framer::Call;
        let p = &self.plugin;
        match call {
            Call::Locate(i, o) => cross(p, slot::LOCATE, i, o),
            Call::Begin(i, o) => cross(p, slot::BEGIN, i, o),
            Call::Ingest(i, o) => cross(p, slot::INGEST, i, o),
            Call::Emit(i, o) => cross(p, slot::EMIT, i, o),
            Call::Encode(i, o) => cross(p, slot::ENCODE, i, o),
            Call::Refuse(i, o) => cross(p, slot::REFUSE, i, o),
            Call::Finish(i, o) => cross(p, slot::FINISH, i, o),
            Call::Detach(i, o) => cross(p, slot::DETACH, i, o),
            Call::Adopt(i, o) => cross(p, slot::ADOPT, i, o),
            Call::Timer(i, o) => cross(p, slot::TIMER, i, o),
        }
    }
}

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
/// `neutral_frame_door` example, an identity framer under a neutral claim that names no transport),
/// beside this test binary.
fn socket_framer_door() -> Option<std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor>> {
    let file = busbar_plugin_loader::plugin_library_filename("neutral_frame_door");
    libraries_beside_the_test()
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n == file.as_str()))
        .find_map(|p| open_door(&p))
}

/// `path` admitted and opened through the one dispatcher as a transport door; `None` when it is
/// not one.
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
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::door::{blank_in, blank_out};
    use busbar_plugin_loader::dispatch::kinds::transport::{Transport, TransportFacts};
    use busbar_plugin_loader::dispatch::{
        load_dropped, rendering_of_library, Bind, DispatchConfig, Dispatcher, Frame, NoSink,
    };
    static ONE: OnceLock<Dispatcher> = OnceLock::new();
    // The library's own Statement rendering, as its signed manifest would state it.
    let rendering = rendering_of_library(path).ok()??;
    let bind = Bind {
        instance: std::sync::Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: std::sync::Arc::new(NoSink),
        dispatcher: ONE
            .get_or_init(|| Dispatcher::new(DispatchConfig::default()))
            .adopter(),
        // A transport door is a framer the connector drives: it declares no need.
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    };
    let plugin = load_dropped::<Transport>(path, &rendering, bind).ok()?;
    let stated = plugin.context::<TransportFacts>().cloned()?;
    let mut f = Frame::new(blank_in::<OpenIn>(), blank_out::<OpenOut>());
    assert_eq!(
        plugin.call(life::OPEN, &mut f).outcome,
        busbar_contract::abi::mechanism::call::Outcome::Ready
    );
    let facts = stated.clone();
    Some((
        std::sync::Arc::new(DroppedDoor {
            facts: busbar_core_connector::framer::DoorFacts {
                name: plugin.name().to_owned(),
                claims: stated.claims,
                role: stated.role,
                composes_over: stated.composes_over,
                status_rows: stated.status_rows,
                streams: stated
                    .upgrades
                    .iter()
                    .chain(&stated.sessions)
                    .copied()
                    .collect(),
            },
            plugin,
        }),
        facts,
    ))
}

/// THE CONNECTOR DRIVES THE DROPPED-IN HTTP DOOR AGAINST A REAL SERVER: the connector dials the
/// host socket on the worker's reactor, the door encodes the request and frames the server's
/// HTTP/1.1 response into a head piece (with its status), body pieces and the empty piece that ends
/// the stream. DOOR-TRANSPORT's own conformance proves the http door's linked and dropped doors
/// answer alike through one table; the linked arm here arrives at KERNEL<>PLUGINS step 20, when
/// http becomes a root door row.
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
                    Vec::new(),
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
            // The stream's end: its empty closing piece (an empty head is a fields piece).
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

/// THE CONNECTOR DRIVES A DROPPED-IN DOOR THAT FRAMES THE HOST'S SOCKET against a real far end: the
/// opening message and a write go out through the door, the echo comes back as its frames, byte for
/// byte. The door is the neutral frame door, which names no transport.
#[test]
fn the_connector_drives_a_dropped_in_socket_framer_against_a_real_far_end() {
    use busbar_core_connector::compose::{Connection, Dial};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some(door) = socket_framer_door() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "the neutral frame door is built beside the test binary under CI"
        );
        return;
    };
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
            Dial {
                target: far,
                tls: None,
                alpn: Vec::new(),
                open_timeout: std::time::Duration::from_secs(5),
                opening: Some((Vec::new(), b"opening;".to_vec())),
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
/// writes `response`, up to the empty piece that ends the stream: `(kind, status, bytes)`.
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
    // The connector serves a CARRIER beside the framer (no transport names another; the carrier is
    // the connector's choice): the neutral frame door, which names no transport.
    let layer = socket_framer_door().expect("a carrier door is built beside the test");
    let response = respond(scheme, response);
    // An IP literal is its own address: the judge the test needs, and no more.
    let judge = |dest: &str, _: u32, _: Judged| {
        Some(dest.parse::<std::net::SocketAddr>().map_err(|_| 1_u64))
    };
    let c = Connector::serving(
        // The door composes over its layer's door, so the view serves both.
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
        std::sync::Arc::new(|_| {}),
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
                    // The stream's end: its empty closing piece (an empty head is a Fields piece).
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
/// connection table, as ONE Fields piece carrying the status — the field block, lower-case names in
/// the far end's order, a repeated field on its own lines, hop-by-hop fields (and what `connection`
/// names) and `content-length` dropped — and then the Body.
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
    // The answer whole is the exchange's completion (the stream's empty closing piece), and every
    // piece between the head and it is Body.
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
/// as ONE EMPTY Fields piece, carrying the status, before anything else: the head is always the
/// answer's first piece, and the only Fields piece (a trailer section is dropped, as 1.5.5's
/// client dropped it).
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
/// as sent, as a range of the caller's buffer right after the block.
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
/// whose wire has no head words renders exactly what it did without them.
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

/// THE REQUEST/RESPONSE FRAMER the head tests drive: of the libraries beside this test binary, the
/// FRAMER (its stated role, ARCHITECT ruling Q128 U7) whose own claim carries no session (one request,
/// one response), found by what it states and never by a name. It is a pinned plugin repo's cdylib,
/// which is in no graph of this workspace: the hop's `build:dlopen-cdylibs` builds it from the pinned
/// checkout busbar's root resolves, into this target dir (spec P5). A missing door is a failure,
/// never a skip.
fn composing_door() -> std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> {
    use busbar_contract::abi::transport::ROLE_FRAMER;
    libraries_beside_the_test()
        .into_iter()
        .filter_map(|p| open_stated(&p))
        .find(|(d, s)| d.facts().role == ROLE_FRAMER && !s.sessions.contains(&d.facts().claims[0]))
        .map(|(d, _)| d)
        .expect("a request/response framer door is built beside the test binary")
}

/// A response template with its version written as the door's own scheme, upper-cased (`{V}`), so
/// the test names no wire.
fn respond(scheme: &str, template: &str) -> Vec<u8> {
    template
        .replace("{V}", &format!("{}/1.1", scheme.to_ascii_uppercase()))
        .into_bytes()
}

/// A loopback far end that reads one request head and answers `response`: its address, and the
/// request head it read.
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
/// descriptor states head words sends them as the opening message's own request line, byte for
/// byte; an open that names no target dials the need's declared one. The table reports the
/// composing door's need framed and the socket framer's raw.
#[test]
fn an_opening_messages_head_words_reach_the_far_end_through_the_table() {
    use busbar_contract::conn::{Conns, DeclaredConns, InstanceId, NeedId, OpenDesc};
    use busbar_core_connector::registry::{Entry, Transports};
    use busbar_core_connector::{Connector, Judged};

    let door = composing_door();
    let scheme = door.facts().claims[0];
    let plain = socket_framer_door().expect("a carrier door is built beside the test");
    let raw = plain.facts().claims[0];
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
                door: plain,
                alpn: Vec::new(),
            },
        ])
        .unwrap(),
        std::sync::Arc::new(judge),
        None,
        std::sync::Arc::new(|_| {}),
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
            // Reading drives the connection: its opening message goes out.
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
