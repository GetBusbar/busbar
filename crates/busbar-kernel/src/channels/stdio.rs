// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The production [`Wires`] (IF §12.19): a CARRIER_STDIO generation is a child process core spawns itself, a
//! CARRIER_HTTP one is a held request sent through [`HeldHttp`].
//!
//! The child starts in `StdioCommand.cwd` with exactly `argv` and the resolved `env` (nothing inherited), stdin and
//! stdout piped to the carrier, and is killed when its generation ends (the [`Child`] is the wire's `hold`). A
//! `LocalProgram` pin is checked against the path that will be spawned before the child exists, so not one byte is
//! written to a program the operator did not approve. The kernel opens no socket: the held HTTP request is the
//! connector's ([`HeldHttp`] is its seam, judged by the same guard as every dial).

use std::process::Stdio;
use std::sync::Arc;

use busbar_contract::secret_ref::SecretRef;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{CARRIER_HTTP, CARRIER_STDIO};
use busbar_plugin_abi::records::tag;
use tokio::io::AsyncRead;
use tokio::process::{Child, Command};

use super::carrier::{Wire, Wires};
use super::ChannelReq;
use crate::plugin_records::RecordsDenied;
use crate::upstreams::{ProgramPin, StdioCommand, UpstreamDef};

/// How a child's `env` references turn into values (custody, at spawn). `None` = a reference that does not resolve:
/// the child is not spawned.
pub trait SpawnSecrets: Send + Sync + 'static {
    fn resolve(&self, secret: &SecretRef) -> Option<String>;
}

/// One held request: the head a CARRIER_HTTP CHANNEL stated, and what the far end streams back.
pub struct HeldRequest<'a> {
    pub method: &'a str,
    /// Path and query as the plane wrote them.
    pub path: &'a str,
    pub headers: Vec<(&'a str, &'a [u8])>,
}

/// Sends a held request to a configured upstream and streams its response body. The connector judges the dial
/// (egress class, plaintext only when the instance accepts it) and adds the upstream's credential; a refused dial or
/// a non-2xx answer is `Unavailable`.
pub trait HeldHttp: Send + Sync + 'static {
    fn open<'a>(
        &'a self,
        upstream: &'a UpstreamDef,
        request: HeldRequest<'a>,
    ) -> BoxFut<'a, Result<Box<dyn AsyncRead + Send + Unpin>, RecordsDenied>>;
}

/// [`Wires`] over child processes and [`HeldHttp`].
pub struct ProcessWires {
    secrets: Arc<dyn SpawnSecrets>,
    http: Option<Arc<dyn HeldHttp>>,
}

impl ProcessWires {
    /// `http` = `None`: no CARRIER_HTTP channel can open.
    #[must_use]
    pub fn new(secrets: Arc<dyn SpawnSecrets>, http: Option<Arc<dyn HeldHttp>>) -> Self {
        Self { secrets, http }
    }

    async fn child(&self, upstream: &UpstreamDef) -> Result<Wire, RecordsDenied> {
        let command = upstream.command.as_ref().ok_or(RecordsDenied::Invalid)?;
        let (program, args) = command.argv.split_first().ok_or(RecordsDenied::Invalid)?;
        pinned(command, program).await?;
        let mut spawn = Command::new(&**program);
        spawn.args(args.iter().map(|arg| &**arg)).env_clear();
        for (name, secret) in &command.env {
            let value = self
                .secrets
                .resolve(secret)
                .ok_or(RecordsDenied::Unavailable)?;
            spawn.env(&**name, value);
        }
        if let Some(cwd) = &command.cwd {
            spawn.current_dir(&**cwd);
        }
        spawn
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child: Child = spawn.spawn().map_err(|_| RecordsDenied::Unavailable)?;
        let stdin = child.stdin.take().ok_or(RecordsDenied::Unavailable)?;
        let stdout = child.stdout.take().ok_or(RecordsDenied::Unavailable)?;
        Ok(Wire {
            read: Box::new(stdout),
            write: Some(Box::new(stdin)),
            hold: Box::new(child),
        })
    }

    async fn held(
        &self,
        upstream: &UpstreamDef,
        req: &ChannelReq<'_>,
    ) -> Result<Wire, RecordsDenied> {
        let http = self.http.as_ref().ok_or(RecordsDenied::Unavailable)?;
        let (mut method, mut path) = (None, None);
        let mut headers = Vec::new();
        for rec in req.head {
            let rec = rec.map_err(|_| RecordsDenied::Invalid)?;
            match rec.tag {
                tag::H_METHOD => method = Some(rec.text().map_err(|_| RecordsDenied::Invalid)?),
                tag::H_PATH => path = Some(rec.text().map_err(|_| RecordsDenied::Invalid)?),
                tag::PAIR => headers.push(rec.pair().map_err(|_| RecordsDenied::Invalid)?),
                _ => return Err(RecordsDenied::Invalid),
            }
        }
        let (Some(method), Some(path)) = (method, path) else {
            return Err(RecordsDenied::Invalid);
        };
        let read = http
            .open(
                upstream,
                HeldRequest {
                    method,
                    path,
                    headers,
                },
            )
            .await?;
        Ok(Wire {
            read,
            write: None,
            hold: Box::new(()),
        })
    }
}

/// A `LocalProgram` pin: the spawned path is the approved one (absolute, and the same file once links resolve).
async fn pinned(command: &StdioCommand, program: &str) -> Result<(), RecordsDenied> {
    let ProgramPin::LocalProgram { key } = &command.pin else {
        return Ok(());
    };
    let (program, key) = (program.to_owned(), key.to_string());
    let same = tokio::task::spawn_blocking(move || {
        let (spawned, approved) = (std::fs::canonicalize(&program), std::fs::canonicalize(&key));
        program == key
            && matches!((spawned, approved), (Ok(spawned), Ok(approved)) if spawned == approved)
    })
    .await
    .unwrap_or(false);
    if same {
        Ok(())
    } else {
        Err(RecordsDenied::Invalid)
    }
}

impl Wires for ProcessWires {
    fn open<'a>(
        &'a self,
        upstream: &'a UpstreamDef,
        req: &'a ChannelReq<'a>,
    ) -> BoxFut<'a, Result<Wire, RecordsDenied>> {
        Box::pin(async move {
            match req.carrier {
                CARRIER_STDIO => self.child(upstream).await,
                CARRIER_HTTP => self.held(upstream, req).await,
                _ => Err(RecordsDenied::Invalid),
            }
        })
    }
}
