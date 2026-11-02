// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD (BUSBAR-1.6.0.md THE DESIGN §3 boot stage 3c,

use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_DEFAULT};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnId, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, PollConns,
};

/// The connection table a download rides: whose needs, the need a secured URL rides and the one a
/// plaintext URL (a loopback or private registry) rides, where they are declared, where they are
/// opened and read.
#[derive(Clone)]
pub struct Table {
    /// The identity the download's needs are declared and opened under.
    pub owner: InstanceId,
    /// The need a secured URL rides.
    pub secured_need: NeedId,
    /// The need a plaintext URL rides.
    pub plain_need: NeedId,
    /// Where the needs are declared.
    pub declared: Arc<dyn DeclaredConns>,
    /// Where the connection is opened and read.
    pub conns: Arc<dyn PollConns>,
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

/// Download the `plugins.fetch` artifact at `url` over `table`, under the operator's extra

pub fn download(
    table: &Table,
    url: &str,
    blocked: &[String],
    cap: usize,
) -> Result<Vec<u8>, String> {
    let secured = busbar_kernel::preflight::plugin_fetch_admits(url, blocked)?;
    std::thread::scope(|s| {
        s.spawn(|| -> Result<Vec<u8>, String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("fetch runtime: {e}"))?;
            rt.block_on(get(table, url, secured, cap))
        })
        .join()
        .map_err(|_| "plugins.fetch download thread panicked".to_string())?
    })
}

/// The download's need for the URL's own scheme (`scheme`, lower-cased, as the URL spells it): the

fn need(scheme: &str) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_DEFAULT,
        transport: scheme.to_owned(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
        keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

/// Closes the download's connection however the fetch ends.
struct Held<'a> {
    table: &'a Table,
    conn: ConnId,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let _ = self.table.conns.close(self.table.owner, self.conn);
    }
}

/// One GET of `url` over `table`, read whole under `cap`.
async fn get(table: &Table, url: &str, secured: bool, cap: usize) -> Result<Vec<u8>, String> {
    let sending = || format!("GET {url}: error sending request for url ({url})");
    let (need_id, scheme) = match url.split_once("://") {
        Some((scheme, _)) if secured => (table.secured_need, scheme.to_ascii_lowercase()),
        Some((scheme, _)) => (table.plain_need, scheme.to_ascii_lowercase()),
        None => return Err(sending()),
    };

    table
        .declared
        .declare(table.owner, need_id, &need(&scheme), Some(url), None)
        .map_err(|_| sending())?;
    let path = busbar_contract::net::parse_url(url)
        .map_err(|_| sending())?
        .path;

    let fields: [(&str, &[u8]); 1] = [("accept", b"*/*")];
    let conn = table
        .conns
        .open(
            table.owner,
            need_id,
            &OpenDesc {
                target: url,
                method: b"GET",
                head_target: path.as_bytes(),
                fields: &fields,
                ..OpenDesc::default()
            },
        )
        .map_err(|_| sending())?;
    let held = Held { table, conn };
    read_whole(&held, url, cap)
        .await
        .map_err(|e| e.unwrap_or_else(sending))
}

/// The answer, read to its completion: the status judged on the head (a redirect refused, never

async fn read_whole(held: &Held<'_>, url: &str, cap: usize) -> Result<Vec<u8>, Option<String>> {
    let (table, conn) = (held.table, held.conn);
    let mut buf = vec![0_u8; 16 * 1024];
    let mut status: Option<u32> = None;
    let mut body: Vec<u8> = Vec::new();
    loop {
        let piece =
            std::future::poll_fn(|cx| table.conns.poll_read(table.owner, conn, cx, &mut buf)).await;
        let piece = match piece {
            Ok(p) => p,
            Err(_) if status.is_none() => return Err(None),
            Err(_) => {
                return Err(Some(format!(
                    "read body {url}: connection failed mid-download"
                )))
            }
        };
        match piece.kind {
            PieceKind::Completion => break,
            PieceKind::Fields | PieceKind::HookReply => {
                let Some(code) = piece.status_code.filter(|_| status.is_none()) else {
                    continue;
                };
                if let Some(refused) =
                    busbar_kernel::preflight::plugin_fetch_status_refusal(url, code)
                {
                    return Err(Some(refused));
                }

                if let Some(len) = piece.declared_len {
                    let over = match usize::try_from(len) {
                        Ok(l) => l > cap,
                        Err(_) => true,
                    };
                    if over {
                        return Err(Some(format!(
                            "GET {url}: declared Content-Length {len} exceeds the {cap}-byte \
                             plugins.fetch download cap"
                        )));
                    }
                }
                status = Some(code);
            }
            PieceKind::Body => {
                if status.is_none() {
                    return Err(None);
                }
                if body.len() + piece.len > cap {
                    return Err(Some(format!(
                        "GET {url}: response exceeded the {cap}-byte plugins.fetch download cap; \
                         refusing to buffer a truncated download"
                    )));
                }
                body.extend_from_slice(&buf[..piece.len]);
            }
        }
    }
    if status.is_none() {
        return Err(None);
    }
    Ok(body)
}
