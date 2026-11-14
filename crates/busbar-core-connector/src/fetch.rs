// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD (BUSBAR-1.6.0.md THE DESIGN §3 boot stage 3c,

use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::{
    CAUSE_CONNECT, CAUSE_DEADLINE, CAUSE_EXCHANGE, CAUSE_FRAMER, CAUSE_SECURITY,
    DIRECTION_OUTBOUND, EGRESS_DEFAULT,
};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnCause, ConnError, ConnId, DeclaredConns, InstanceId, NeedId, NeedRefusal, OpenDesc,
    PieceKind, PollConns,
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
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: the plugins.fetch download runs once, at boot stage 3c"
        )]
        let joined = s
            .spawn(|| -> Result<Vec<u8>, String> {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "boot: the plugins.fetch download runs once, at boot stage 3c"
                )]
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("fetch runtime: {e}"))?;
                rt.block_on(get(table, url, secured, cap))
            })
            .join()
            .map_err(|_| "plugins.fetch download thread panicked".to_owned());
        joined?
    })
}

/// The download's need for the URL's own scheme (`scheme`, lower-cased, as the URL spells it): the
fn need(scheme: &str) -> ReadNeed {
    #[expect(
        clippy::disallowed_methods,
        reason = "boot: the plugins.fetch download runs once, at boot stage 3c"
    )]
    let transport = scheme.to_owned();
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_DEFAULT,
        transport,
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
    #[expect(
        clippy::disallowed_methods,
        reason = "boot: the plugins.fetch download runs once, at boot stage 3c"
    )]
    let sending = || format!("GET {url}: error sending request for url ({url})");
    #[expect(
        clippy::disallowed_methods,
        reason = "boot: the plugins.fetch download runs once, at boot stage 3c"
    )]
    let (need_id, scheme) = match url.split_once("://") {
        Some((scheme, _)) if secured => (table.secured_need, scheme.to_ascii_lowercase()),
        Some((scheme, _)) => (table.plain_need, scheme.to_ascii_lowercase()),
        None => return Err(sending("the URL names no scheme")),
    };

    table
        .declared
        .declare(table.owner, need_id, &need(&scheme), Some(url), None)
        .map_err(|_| {
            sending(
                &refused(table.declared.refusal(table.owner, need_id))
                    .unwrap_or_else(|| CONNECTOR_REFUSED.to_owned()),
            )
        })?;
    let path = busbar_contract::net::parse_url(url)
        .map_err(|e| sending(&format!("the URL is not one busbar can request: {e}")))?
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
        .map_err(|e| {
            sending(
                &refused(table.declared.refusal(table.owner, need_id)).unwrap_or_else(|| match e {
                    ConnError::Refused => CONNECTOR_REFUSED.to_owned(),
                    other => format!("the connection could not be opened: {}", other.text()),
                }),
            )
        })?;
    let held = Held { table, conn };
    read_whole(&held, url, cap).await.map_err(|e| match e {
        Early::Said(said) => said,
        Early::Conn(e) => sending(
            &refused(table.declared.conn_refusal(table.owner, conn))
                .or_else(|| caused(table.declared.cause(table.owner, conn), url))
                .unwrap_or_else(|| {
                    format!(
                        "the connection failed before the response head: {}",
                        e.text()
                    )
                }),
        ),
        Early::BodyFirst => sending("the registry sent body bytes before a response head"),
        Early::NoHead => sending("the connection ended before the registry sent a response head"),
    })
}

/// What the connector's own checks answer when no reason was recorded.
const CONNECTOR_REFUSED: &str = "the connector's own checks refused the target";

/// The line's own failure, in words naming the stage at the registry (`None` = none recorded).
fn caused(cause: Option<ConnCause>, url: &str) -> Option<String> {
    let cause = cause?;
    let text = scrub(&cause.text, url);
    Some(match cause.stage {
        CAUSE_CONNECT => format!("could not connect to the registry: {text}"),
        CAUSE_SECURITY => format!("the TLS handshake with the registry failed: {text}"),
        CAUSE_EXCHANGE => format!("the request to the registry failed: {text}"),
        CAUSE_FRAMER => format!("the registry's response could not be read as HTTP: {text}"),
        CAUSE_DEADLINE => "the download's deadline passed before the registry answered".to_owned(),
        _ => return None,
    })
}

/// THE SCRUB of dynamic cause text (an OS, TLS or framer error, or a far end's own bytes): the
/// URL's userinfo, a non-empty query or fragment, and every control character are hidden, and the
/// result is capped at [`SCRUB_CAP`] bytes on a character boundary.
fn scrub(text: &str, url: &str) -> String {
    const REDACTED: &str = "<redacted>";
    let mut out = text.to_owned();
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if let Some((userinfo, _)) = authority.rsplit_once('@') {
        if !userinfo.is_empty() {
            out = out.replace(userinfo, REDACTED);
        }
    }
    for mark in ['?', '#'] {
        if let Some((_, tail)) = url.split_once(mark) {
            let part = if mark == '?' {
                tail.split('#').next().unwrap_or_default()
            } else {
                tail
            };
            if !part.is_empty() {
                out = out.replace(part, REDACTED);
            }
        }
    }
    let mut out: String = out
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if out.len() > SCRUB_CAP {
        let mut at = SCRUB_CAP;
        while !out.is_char_boundary(at) {
            at -= 1;
        }
        out.truncate(at);
    }
    out
}

/// The most bytes of scrubbed cause text a download error carries.
const SCRUB_CAP: usize = 300;

/// How a read ended before the answer was whole.
enum Early {
    /// Already said in full (a status, a cap, a mid-body failure).
    Said(String),
    /// The connection failed before the response head.
    Conn(ConnError),
    /// Body bytes came before any response head.
    BodyFirst,
    /// The connection completed with no response head.
    NoHead,
}

/// The answer, read to its completion: the status judged on the head (a redirect refused, never
async fn read_whole(held: &Held<'_>, url: &str, cap: usize) -> Result<Vec<u8>, Early> {
    let (table, conn) = (held.table, held.conn);
    let mut buf = vec![0_u8; 16 * 1024];
    let mut status: Option<u32> = None;
    // busbar:expect(bp::fresh_buffer, reason = "boot: the plugins.fetch download runs once, at boot stage 3c")
    let mut body: Vec<u8> = Vec::new();
    loop {
        let piece =
            std::future::poll_fn(|cx| table.conns.poll_read(table.owner, conn, cx, &mut buf)).await;
        let piece = match piece {
            Ok(p) => p,
            Err(e) if status.is_none() => return Err(Early::Conn(e)),
            Err(_) => {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "boot: the plugins.fetch download runs once, at boot stage 3c"
                )]
                return Err(Some(format!(
                    "read body {url}: connection failed mid-download"
                )));
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
                    return Err(Early::Said(refused));
                }

                if let Some(len) = piece.declared_len {
                    let over = match usize::try_from(len) {
                        Ok(l) => l > cap,
                        Err(_) => true,
                    };
                    if over {
                        #[expect(
                            clippy::disallowed_methods,
                            reason = "boot: the plugins.fetch download runs once, at boot stage 3c"
                        )]
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
                    return Err(Early::BodyFirst);
                }
                if body.len() + piece.len > cap {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "boot: the plugins.fetch download runs once, at boot stage 3c"
                    )]
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
        return Err(Early::NoHead);
    }
    Ok(body)
}
