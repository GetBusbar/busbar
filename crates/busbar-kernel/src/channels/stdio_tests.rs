// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §12.19 (PLANE-CARRIER): the production wires. A CARRIER_STDIO generation is a real child process (POSIX
//! `env` and `cat`); a CARRIER_HTTP one is a held request sent through the connector's seam.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::secret_ref::SecretRef;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{CARRIER_HTTP, CARRIER_STDIO, CH_FRAME_NDJSON, CH_FRAME_SSE};
use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::carrier::{Wire, Wires};
use super::stdio::{HeldHttp, HeldRequest, ProcessWires, SpawnSecrets};
use super::ChannelReq;
use crate::plugin_records::RecordsDenied;
use crate::upstreams::{ProgramPin, StdioCommand, UpstreamDef, UpstreamTls};

const WAIT: Duration = Duration::from_secs(5);

struct Fixed(Option<&'static str>);

impl SpawnSecrets for Fixed {
    fn resolve<'a>(&'a self, _: &'a SecretRef) -> BoxFut<'a, Option<String>> {
        Box::pin(core::future::ready(self.0.map(str::to_owned)))
    }
}

fn upstream(
    argv: &[&str],
    env: Vec<(Box<str>, SecretRef)>,
    cwd: Option<&str>,
    pin: ProgramPin,
) -> UpstreamDef {
    UpstreamDef {
        allow_private: false,
        name: "member".into(),
        url: None,
        command: Some(StdioCommand {
            argv: argv.iter().map(|a| Box::<str>::from(*a)).collect(),
            env,
            cwd: cwd.map(Box::from),
            pin,
            idle_s: 300,
        }),
        tls: UpstreamTls {
            pin_spki: Vec::new(),
            client_identity: None,
            trust: None,
        },
        auth: None,
    }
}

fn req(carrier: u32, framing: u32, head: &[u8]) -> ChannelReq<'_> {
    static UNIT: std::sync::LazyLock<super::budget::UnitBudget> =
        std::sync::LazyLock::new(|| super::budget::ChannelBudget::new().instance().unit());
    ChannelReq {
        budget: &UNIT,
        exchange: 1,
        carrier,
        flags: 0,
        framing,
        key: "k",
        subject: None,
        head: Records::new(head),
    }
}

async fn open(
    wires: &ProcessWires,
    up: &UpstreamDef,
    req: ChannelReq<'_>,
) -> Result<Wire, RecordsDenied> {
    wires.open(up, &req).await
}

fn local() -> ProcessWires {
    ProcessWires::new(Arc::new(Fixed(Some("secret"))), None)
}

#[tokio::test]
async fn a_child_starts_with_exactly_its_argv_and_its_resolved_env_and_nothing_inherited() {
    let up = upstream(
        &["/usr/bin/env"],
        vec![("BUSBAR_X".into(), SecretRef::None)],
        Some("/"),
        ProgramPin::Unpinned,
    );
    let mut wire = open(&local(), &up, req(CARRIER_STDIO, CH_FRAME_NDJSON, &[]))
        .await
        .unwrap();
    let mut out = String::new();
    timeout(WAIT, wire.read.read_to_string(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        out, "BUSBAR_X=secret\n",
        "no other variable reached the child"
    );
}

#[tokio::test]
async fn what_core_writes_reaches_the_childs_stdin_and_its_stdout_comes_back() {
    let up = upstream(&["/bin/cat"], Vec::new(), None, ProgramPin::Unpinned);
    let mut wire = open(&local(), &up, req(CARRIER_STDIO, CH_FRAME_NDJSON, &[]))
        .await
        .unwrap();
    let write = wire.write.as_mut().expect("a child takes writes");
    write.write_all(b"ping\n").await.unwrap();
    write.flush().await.unwrap();
    let mut got = [0u8; 5];
    timeout(WAIT, wire.read.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"ping\n");
}

#[tokio::test]
async fn an_env_reference_that_does_not_resolve_spawns_nothing() {
    let up = upstream(
        &["/bin/cat"],
        vec![("K".into(), SecretRef::None)],
        None,
        ProgramPin::Unpinned,
    );
    let wires = ProcessWires::new(Arc::new(Fixed(None)), None);
    assert!(matches!(
        open(&wires, &up, req(CARRIER_STDIO, CH_FRAME_NDJSON, &[])).await,
        Err(RecordsDenied::Unavailable)
    ));
}

#[tokio::test]
async fn a_program_that_cannot_start_and_an_upstream_with_no_command_are_refused() {
    let missing = upstream(
        &["/nonexistent/program"],
        Vec::new(),
        None,
        ProgramPin::Unpinned,
    );
    assert!(matches!(
        open(&local(), &missing, req(CARRIER_STDIO, CH_FRAME_NDJSON, &[])).await,
        Err(RecordsDenied::Unavailable)
    ));
    let mut none = upstream(&["/bin/cat"], Vec::new(), None, ProgramPin::Unpinned);
    none.command = None;
    assert!(matches!(
        open(&local(), &none, req(CARRIER_STDIO, CH_FRAME_NDJSON, &[])).await,
        Err(RecordsDenied::Invalid)
    ));
    let empty = upstream(&[], Vec::new(), None, ProgramPin::Unpinned);
    assert!(matches!(
        open(&local(), &empty, req(CARRIER_STDIO, CH_FRAME_NDJSON, &[])).await,
        Err(RecordsDenied::Invalid)
    ));
}

#[tokio::test]
async fn a_local_program_pin_is_checked_against_the_spawned_path_before_the_child_exists() {
    let wrong = upstream(
        &["/bin/cat"],
        Vec::new(),
        Some("/"),
        ProgramPin::LocalProgram {
            key: "/usr/bin/env".into(),
        },
    );
    assert!(matches!(
        open(&local(), &wrong, req(CARRIER_STDIO, CH_FRAME_NDJSON, &[])).await,
        Err(RecordsDenied::Invalid)
    ));
    let right = upstream(
        &["/bin/cat"],
        Vec::new(),
        Some("/"),
        ProgramPin::LocalProgram {
            key: "/bin/cat".into(),
        },
    );
    assert!(
        open(&local(), &right, req(CARRIER_STDIO, CH_FRAME_NDJSON, &[]))
            .await
            .is_ok()
    );
}

/// One recorded request: method, path, headers, upstream name.
type SeenRequest = (String, String, Vec<(String, Vec<u8>)>, String);

#[derive(Default)]
struct Seen {
    requests: Mutex<Vec<SeenRequest>>,
}

impl HeldHttp for Seen {
    fn open<'a>(
        &'a self,
        upstream: &'a UpstreamDef,
        request: HeldRequest<'a>,
    ) -> BoxFut<'a, Result<Box<dyn AsyncRead + Send + Unpin>, RecordsDenied>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push((
                request.method.to_owned(),
                request.path.to_owned(),
                request
                    .headers
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), value.to_vec()))
                    .collect(),
                upstream.name.to_string(),
            ));
            Ok(Box::new(tokio::io::empty()) as Box<dyn AsyncRead + Send + Unpin>)
        })
    }
}

fn head(method: &str, path: &str) -> Vec<u8> {
    let mut reply = Reply::new();
    reply.put_text(tag::H_METHOD, method).unwrap();
    reply.put_text(tag::H_PATH, path).unwrap();
    reply
        .put_pair(tag::PAIR, "accept", b"text/event-stream")
        .unwrap();
    reply.as_bytes().to_vec()
}

#[tokio::test]
async fn a_held_request_is_sent_through_the_connectors_seam_with_the_head_the_plane_stated() {
    let seen = Arc::new(Seen::default());
    let wires = ProcessWires::new(
        Arc::new(Fixed(None)),
        Some(Arc::clone(&seen) as Arc<dyn HeldHttp>),
    );
    let up = upstream(&["/bin/cat"], Vec::new(), None, ProgramPin::Unpinned);
    let bytes = head("GET", "/sse?x=1");
    let wire = open(&wires, &up, req(CARRIER_HTTP, CH_FRAME_SSE, &bytes))
        .await
        .unwrap();
    assert!(wire.write.is_none(), "a held GET takes no writes");
    assert_eq!(
        seen.requests.lock().unwrap().clone(),
        [(
            "GET".to_owned(),
            "/sse?x=1".to_owned(),
            vec![("accept".to_owned(), b"text/event-stream".to_vec())],
            "member".to_owned()
        )]
    );
}

#[tokio::test]
async fn a_held_request_needs_its_method_and_path_and_a_connector_to_send_it() {
    let seen = Arc::new(Seen::default());
    let with = ProcessWires::new(
        Arc::new(Fixed(None)),
        Some(Arc::clone(&seen) as Arc<dyn HeldHttp>),
    );
    let up = upstream(&["/bin/cat"], Vec::new(), None, ProgramPin::Unpinned);
    assert!(matches!(
        open(&with, &up, req(CARRIER_HTTP, CH_FRAME_SSE, &[])).await,
        Err(RecordsDenied::Invalid)
    ));
    let bytes = head("GET", "/s");
    assert!(matches!(
        open(&local(), &up, req(CARRIER_HTTP, CH_FRAME_SSE, &bytes)).await,
        Err(RecordsDenied::Unavailable)
    ));
    assert!(seen.requests.lock().unwrap().is_empty());
}
