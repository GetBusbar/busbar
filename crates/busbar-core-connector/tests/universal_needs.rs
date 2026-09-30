// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIVERSAL-NEEDS WITNESS (THE DESIGN: connections — "any plugin of any kind reaches the
//! network only through a need"). A SECRET-kind fixture (`examples/need_dialler.rs`) that declares
//! one outbound need is loaded DROPPED IN through the real admission, scan and open, and asked for its
//! secret: it dials through the connection table, writes `ping` and returns what came back.
//!
//! TODAY'S TRUTH, asserted explicitly: the secret kind's open hands an instance no connection table
//! yet, so the instance holds none and the dial answers [`TODAY`] — the named refusal for an
//! instance handed no table, decided per instance. The fixture
//! has no other way to the network: its closure is held to that by the `dep-wall` gate.
//!
//! FLIPS TO GREEN (dial succeeds, bytes round-trip over a loopback echo) once the open/refresh
//! host tables hand the instance its table: the dial reaches the connector, `TODAY` becomes
//! success, the test starts a loopback echo as the target, and the assertion below becomes "the
//! secret is the echoed `ping`".

use std::sync::OnceLock;

use busbar_contract::conn::ConnError;
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};

/// What the dial answers today. The one edit that flips this witness once instances are handed their table.
const TODAY: ConnError = ConnError::Unarmed;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where the fixture dials: a loopback address nothing answers on, until the witness starts an echo.
const TARGET: &str = "127.0.0.1:1";

fn release() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
}

/// The fixture's cdylib, as `cargo test` built it (under `examples/`). A missing artifact is a
/// failure, never a skip: this test IS the witness.
fn fixture() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("need_dialler");
    let found = [
        profile.join("examples").join(&file),
        profile.join("examples").join("deps").join(&file),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| panic!("the need_dialler fixture ({file}) is not built"));
    std::fs::read(found).expect("read the fixture")
}

/// The fixture, loaded dropped in: signed first-party into a fresh `plugins/` directory, scanned
/// under a policy holding the release key, and opened as a secret module by name.
fn dropped_in() -> &'static dyn busbar_contract::secret::SecretModule {
    static MODULE: OnceLock<Box<dyn busbar_contract::secret::SecretModule>> = OnceLock::new();
    MODULE
        .get_or_init(|| {
            let lib = fixture();
            let dir = std::env::temp_dir().join(format!("universal-needs-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create the plugins dir");
            let manifest = Manifest {
                name: "need-dialler".into(),
                alias: "need-dialler".into(),
                kind: "secret".into(),
                version: VERSION.into(),
                publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
                abi_version: busbar_contract::abi::cold::SECRET_ABI_VERSION,
                sha256: String::new(),
                signature: String::new(),
                description: String::new(),
                homepage: String::new(),
                license: String::new(),
                needs: Default::default(),
                settings_schema: None,
                schema_derived: false,
                host: None,
                declares: Default::default(),
                statement: None,
            };
            let signed = sign(&release(), manifest, &lib);
            let tarball = busbar_plugin_loader::tarball::package(&signed, "libneed.so", &lib)
                .expect("package");
            std::fs::write(dir.join("need-dialler.tar.gz"), tarball).expect("write the tarball");
            let policy = TrustPolicy {
                first_party_key: Some(release().verifying_key()),
                binary_version: VERSION.into(),
                first_party_floors: Default::default(),
                first_party_high_water: Default::default(),
                publishers: Default::default(),
                allow_unsigned: false,
                allow_third_party: false,
                min_versions: Default::default(),
            };
            let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy)
                .unwrap_or_else(|e| panic!("the signed fixture scans: {e:?}"));
            let module = registry
                .open_secret("need-dialler", "{}")
                .expect("the dropped-in door opens the fixture");
            let _ = std::fs::remove_dir_all(&dir);
            module
        })
        .as_ref()
}

/// THE WITNESS: a plugin of a kind that is not a transport reaches the network only through the
/// connection table — and today, handed none, its dial is refused by name and reaches nothing.
#[test]
fn a_secret_plugin_reaches_the_network_only_through_a_need() {
    let mut settings = serde_json::Map::new();
    settings.insert("target".into(), serde_json::Value::String(TARGET.into()));
    let err = match dropped_in().resolve(&settings) {
        Ok(bytes) => panic!("the dial succeeded ({bytes:?}) — flip TODAY"),
        Err(e) => e,
    };
    assert_eq!(err.message, TODAY.to_string(), "the host's named refusal");
}

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

/// The transport door example `name` beside this test binary, admitted and opened through the one
/// dispatcher. A missing artifact is a failure, never a skip.
fn dropped_door(name: &str) -> std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let examples = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>")
        .join("examples");
    let file = busbar_plugin_loader::plugin_library_filename(name);
    let path = [examples.join(&file), examples.join("deps").join(&file)]
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| panic!("the {name} door ({file}) is not built beside the test binary"));
    open_door(&path).expect("the door is admitted")
}

/// A door that frames the host's socket (an empty `composes_over`), found by KIND among the
/// libraries beside this test binary (uplifted, under `deps/`, or an example `cdylib` such as the
/// tcp crate's `tcp_door`): the first the one dispatcher admits as such a transport.
fn socket_framer_door() -> Option<std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor>> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?.to_path_buf();
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
    .filter_map(|p| open_door(&p))
    .find(|d| d.facts().composes_over.is_empty())
}

/// `path` admitted and opened through the one dispatcher as a transport door; `None` when it is
/// not one.
fn open_door(
    path: &std::path::Path,
) -> Option<std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor>> {
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
        conns: None,
    };
    let plugin = load_dropped::<Transport>(path, &rendering, bind).ok()?;
    let stated = plugin.context::<TransportFacts>().cloned()?;
    let mut f = Frame::new(blank_in::<OpenIn>(), blank_out::<OpenOut>());
    assert_eq!(
        plugin.call(life::OPEN, &mut f).outcome,
        busbar_contract::abi::mechanism::call::Outcome::Ready
    );
    Some(std::sync::Arc::new(DroppedDoor {
        facts: busbar_core_connector::framer::DoorFacts {
            name: plugin.name().to_owned(),
            claims: stated.claims,
            composes_over: stated.composes_over,
        },
        plugin,
    }))
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let door = dropped_door("http_door");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
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
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
                .await
                .unwrap();
        });
        let mut c = Connection::dial(
            door,
            Dial {
                target: format!("http://127.0.0.1:{port}/v1/probe"),
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
        assert!(seen.starts_with("GET /v1/probe HTTP/1.1\r\n"), "{seen}");
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
/// byte. The door is found by kind, never named. Its linked arm is the root's door row, which every
/// default build serves through the same connector.
#[test]
fn the_connector_drives_a_dropped_in_socket_framer_against_a_real_far_end() {
    use busbar_core_connector::compose::{Connection, Dial};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some(door) = socket_framer_door() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "a socket-framing transport door is built beside the test binary under CI"
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
            },
        )
        .expect("the connector dials through the door");
        let payload: Vec<u8> = (0..=255_u8).cycle().take(40_000).collect();
        c.write(
            &payload,
            true,
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
fn pieces_through_the_table(
    response: &'static [u8],
) -> Vec<(busbar_contract::conn::PieceKind, Option<u32>, Vec<u8>)> {
    use busbar_contract::conn::{Conns, InstanceId, NeedId, OpenDesc, PieceKind};
    use busbar_core_connector::registry::{Entry, Transports};
    use busbar_core_connector::{Connector, Judged};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let door = dropped_door("http_door");
    let scheme = door.facts().claims[0];
    // An IP literal is its own address: the judge the test needs, and no more.
    let judge = |dest: &str, _: u32, _: Judged| {
        Some(dest.parse::<std::net::SocketAddr>().map_err(|_| 1_u64))
    };
    let c = Connector::serving(
        // The door composes over the socket-framing door, so the view serves both.
        Transports::new(vec![
            Entry {
                door,
                alpn: Vec::new(),
            },
            Entry {
                door: socket_framer_door().expect("a socket-framing door is built beside the test"),
                alpn: Vec::new(),
            },
        ])
        .unwrap(),
        std::sync::Arc::new(judge),
        None,
        std::sync::Arc::new(|_| {}),
    );
    let owner = InstanceId(1);
    c.declare_over(owner, NeedId(0), scheme);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("{scheme}://{}/v1/probe", l.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut req = Vec::new();
            let mut buf = [0_u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).await.unwrap();
                assert!(n > 0, "the request head arrives");
                req.extend_from_slice(&buf[..n]);
            }
            s.write_all(response).await.unwrap();
        });
        let fields: [(&str, &[u8]); 2] = [("method", b"GET"), ("path", b"/v1/probe")];
        let desc = OpenDesc {
            target: &target,
            fields: &fields,
            ..OpenDesc::default()
        };
        let id = c.open(owner, NeedId(0), &desc).expect("opens");
        let mut got = Vec::new();
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
                    got.push((p.kind, p.status_code, buf[..p.len].to_vec()));
                    if done {
                        break;
                    }
                }
            }
        }
        c.close(owner, id).unwrap();
        got
    })
}

/// RED: THE CONNECTOR YIELDS THE FAR END'S HEAD. A response with head fields reads, through the
/// connection table, as ONE Fields piece carrying the status — the field block, lower-case names in
/// the far end's order, a repeated field on its own lines, hop-by-hop fields (and what `connection`
/// names) and `content-length` dropped — and then the Body.
#[test]
fn a_response_with_head_fields_yields_fields_then_body() {
    use busbar_contract::conn::PieceKind;
    let got = pieces_through_the_table(
        b"HTTP/1.1 200 OK\r\nX-B: 1\r\nConnection: keep-alive, x-hop\r\nX-Session-Id: s1\r\n\
          Keep-Alive: timeout=5\r\nx-b: 2\r\nX-Hop: secret\r\ncontent-length: 5\r\n\r\nhello",
    );
    let (kind, status, head) = &got[0];
    assert_eq!((*kind, *status), (PieceKind::Fields, Some(200)), "{got:?}");
    assert_eq!(
        String::from_utf8_lossy(head),
        "x-b: 1\r\nx-b: 2\r\nx-session-id: s1\r\n"
    );
    let body: Vec<u8> = got[1..]
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
    use busbar_contract::conn::PieceKind;
    let got = pieces_through_the_table(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
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
