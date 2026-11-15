// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIVERSAL-NEEDS WITNESS (THE DESIGN: connections — "any plugin of any kind reaches the
//!
//! Core keeps the arm a core double drives: the in-tree neutral frame door over the host's socket.
//! The request/response arms (head words and pieces through the table, the plugin-fetch download
//! and its guard refusals) drove the actual HTTP framer, which core no longer builds; they moved
//! to busbar-transport-http's against-core tests (owner ruling: "core is built and tested solo").

use std::sync::OnceLock;

use busbar_core_connector::{carrier, compose, framer, hostio};

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
    let on = ONE.get_or_init(|| {
        std::sync::Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ))
    });
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
            let (mut socket, _) = l.accept().await.unwrap();
            let mut buf = [0_u8; 4096];
            while let Ok(n) = socket.read(&mut buf).await {
                if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
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
