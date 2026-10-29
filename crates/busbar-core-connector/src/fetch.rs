// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD (BUSBAR-1.6.0.md THE DESIGN §3 boot stage 3c,
//! "fetch plugins through the connector", and §5: the kernel dials nothing). Every `plugins.fetch`
//! artifact is one GET over a need the composition root declares on the process's one connector
//! under its own identity ([`Table`]), so the one destination guard judges, pins and dials the
//! address, the proxy environment applies ([`crate::proxy`]), and the transport serving the URL's
//! scheme writes the request: the download states 1.5.5's client default `accept: */*` as its own
//! field and the transport adds `host` after it, the bytes 1.5.5's `Client::new().get()` sent
//! (oracle cell `egress.fetch|plugins|url`).
//!
//! THE URL IS THE OPERATOR'S OWN DESTINATION: every download declares its need pinned to the URL it
//! fetches, in the egress default class, so the one guard judges its address as operator
//! infrastructure (`crate::guard::judged_class`; THE DESIGN §5 egress-class table): a loopback or
//! private registry, plaintext included, is reached as 1.5.5's downloader reached it, cloud
//! metadata and the operator's extra refusals are refused, and the dial is held to the URL's host.
//! The provider class's refuse-unless-allowlisted default is a provider's and an IdP's, never the
//! download's.
//!
//! The download's own rules are the kernel's deleted `preflight::plugin_fetch_downloader`'s,
//! verbatim: the pre-check before any dial and the verdict on the answer's status are the kernel's
//! pure rules (`busbar_kernel::preflight::plugin_fetch_admits` and `plugin_fetch_status_refusal`:
//! the scheme rule, the cloud-metadata denylist the operator's `security.blocked_metadata_hosts`
//! extends, no redirect ever followed); here, a declared `Content-Length` over the cap refused
//! before a body byte and the body counted against the cap as it arrives, every refusal in 1.5.5's
//! words. The GET runs on a dedicated thread with its own current-thread runtime, so it is safe
//! whether the caller sits on a runtime worker (boot) or a blocking thread (reload).

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
/// metadata denylist `blocked`, capped at `cap` bytes.
///
/// # Errors
///
/// The pre-check's refusal, a send that got no answer, a refused status, a body over the cap, or a
/// connection that failed mid-body: each in 1.5.5's words.
pub fn download(
    table: &Table,
    url: &str,
    blocked: &[String],
    cap: usize,
) -> Result<Vec<u8>, String> {
    // The scheme rule and the cloud-metadata denylist, before any dial.
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
/// egress default class, declared pinned to the URL, so its address is judged as the operator's own
/// (module docs).
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
    // 1.5.5-faithful wording for a request that never got an answer: the older client rendered
    // every send failure as `error sending request for url (URL)`.
    let sending = || format!("GET {url}: error sending request for url ({url})");
    let (need_id, scheme) = match url.split_once("://") {
        Some((scheme, _)) if secured => (table.secured_need, scheme.to_ascii_lowercase()),
        Some((scheme, _)) => (table.plain_need, scheme.to_ascii_lowercase()),
        None => return Err(sending()),
    };
    // Pinned to this URL, every download: the need dials this URL's host and no other.
    table
        .declared
        .declare(table.owner, need_id, &need(&scheme), Some(url), None)
        .map_err(|_| sending())?;
    let path = busbar_contract::net::parse_url(url)
        .map_err(|_| sending())?
        .path;
    // 1.5.5's client default `accept: */*` is a field of the REQUEST, and the transport writes no
    // field its caller did not (SEAM-4i): the download states it, and the transport adds `host`
    // after it, the order 1.5.5's `Client::new().get()` put on the wire.
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
/// followed; any other non-success refused), a declared `Content-Length` over `cap` refused before
/// a body byte, the body counted against `cap` as it arrives. `Err(None)` = no answer at all (the
/// send failed).
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
                // A declared Content-Length over the cap is rejected BEFORE reading a single body
                // byte; a dishonest or absent header falls through to the counted cap below. The
                // length is the head piece's `declared_len`, as the framer stated it: the
                // field block never carries the wire's `content-length` (`abi::transport::fields`).
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
