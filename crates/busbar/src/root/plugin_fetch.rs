// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD, THROUGH THE ONE CONNECTOR (status row 130 E6; BUSBAR-1.6.0.md THE
//! DESIGN §3 boot stage 3c, "fetch plugins through the connector", and §5: the kernel dials
//! nothing). Every `plugins.fetch` artifact is one GET over a need the root declares on the
//! process's one connector under its own identity, so the connector's one destination guard judges,
//! pins and dials the address, the proxy environment applies as it did in 1.5.5, and the http
//! transport writes the request (its client defaults included: `accept: */*` before `host`, the
//! bytes 1.5.5's `Client::new().get()` sent, oracle cell `egress.fetch|plugins|url`).
//!
//! What stays the download's own is moved verbatim from the kernel's deleted
//! `preflight::plugin_fetch_downloader`: https for a public host and plaintext only for a
//! loopback or private one (a local dev registry), the cloud-metadata denylist (the operator's
//! `security.blocked_metadata_hosts` extending it), no redirect ever followed, a declared
//! `Content-Length` over the cap refused before a body byte and the body counted against the cap as
//! it arrives, and every refusal in 1.5.5's words. The GET runs on a dedicated thread with its own
//! current-thread runtime, so it is safe whether the caller sits on a runtime worker (boot) or a
//! blocking thread (reload).

use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_PROVIDER};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnId, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, PollConns,
};
use busbar_kernel::config_validate;

/// The need a download over a secured scheme rides, under the root's own identity
/// ([`crate::root::connector::ROOT_OWNER`]; `NeedId(0)` there is the authorization server's).
const SECURE_NEED: NeedId = NeedId(1);
/// The need a plaintext download (a loopback or private registry) rides.
const PLAIN_NEED: NeedId = NeedId(2);

/// The connection table a download rides: whose needs, where they are declared, where they are
/// opened and read.
#[derive(Clone)]
pub struct Table {
    /// The identity the download's needs are declared and opened under.
    pub owner: InstanceId,
    /// Where the needs are declared.
    pub declared: Arc<dyn DeclaredConns>,
    /// Where the connection is opened and read.
    pub conns: Arc<dyn PollConns>,
}

/// The process's one connector, under the root's own identity.
fn the_table() -> Table {
    let one = crate::root::connector::the();
    Table {
        owner: crate::root::connector::ROOT_OWNER,
        declared: Arc::clone(one) as Arc<dyn DeclaredConns>,
        conns: Arc::clone(one) as Arc<dyn PollConns>,
    }
}

/// The `plugins.fetch` download the root's fetch hands the loader: through the process's one
/// connector, under the operator's extra metadata denylist `blocked`, capped at
/// `config::DEFAULT_PLUGIN_FETCH_MAX_BYTES`.
pub fn downloader(blocked: &[String]) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    downloader_over(
        blocked,
        busbar_kernel::config::DEFAULT_PLUGIN_FETCH_MAX_BYTES,
        the_table,
    )
}

/// [`downloader`] over the table `table` answers, capped at `cap`: split out so a test drives it
/// over a connector of its own and a small cap.
pub fn downloader_over(
    blocked: &[String],
    cap: usize,
    table: impl Fn() -> Table,
) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    let blocked: Vec<String> = blocked.to_vec();
    move |url: &str| -> Result<Vec<u8>, String> {
        // Scheme: https required for a public host; plaintext http only for loopback/private (a local
        // dev registry). Mirrors the provider base_url rule.
        let https = config_validate::scheme_is(url, "https");
        if !https {
            let host_local = config_validate::extract_normalized_host(url)
                .as_deref()
                .map(config_validate::host_is_private_or_loopback)
                .unwrap_or(false);
            if !(config_validate::scheme_is(url, "http") && host_local) {
                return Err(format!(
                    "plugins.fetch url must use https for a public host (got '{url}')"
                ));
            }
        }
        // SSRF: never fetch from a cloud-metadata host (no per-provider carve-outs; the operator
        // denylist still extends the built-in list).
        if let Some(bad) = config_validate::ssrf_blocked_host(url, &[], false, &blocked) {
            return Err(format!(
                "plugins.fetch url '{url}' targets a blocked cloud-metadata host '{bad}'"
            ));
        }
        let table = table();
        std::thread::scope(|s| {
            s.spawn(|| -> Result<Vec<u8>, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("fetch runtime: {e}"))?;
                rt.block_on(get(&table, url, https, cap))
            })
            .join()
            .map_err(|_| "plugins.fetch download thread panicked".to_string())?
        })
    }
}

/// The download's need for the URL's own scheme (`scheme`, lower-cased, as the URL spells it): the
/// provider class, as the kernel engine judged the download.
fn need(scheme: &str) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_PROVIDER,
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

/// The response status as 1.5.5's client rendered it (`404 Not Found`).
fn status_text(code: u32) -> String {
    u16::try_from(code)
        .ok()
        .and_then(|c| http::StatusCode::from_u16(c).ok())
        .map_or_else(|| code.to_string(), |s| s.to_string())
}

/// One GET of `url` over `table`, read whole under `cap`.
async fn get(table: &Table, url: &str, https: bool, cap: usize) -> Result<Vec<u8>, String> {
    // 1.5.5-faithful wording for a request that never got an answer: the older client rendered
    // every send failure as `error sending request for url (URL)`.
    let sending = || format!("GET {url}: error sending request for url ({url})");
    let (need_id, scheme) = match url.split_once("://") {
        Some((scheme, _)) if https => (SECURE_NEED, scheme.to_ascii_lowercase()),
        Some((scheme, _)) => (PLAIN_NEED, scheme.to_ascii_lowercase()),
        None => return Err(sending()),
    };
    if table.declared.declared(table.owner, need_id) != Some(Ok(())) {
        table
            .declared
            .declare(table.owner, need_id, &need(&scheme), None, None)
            .map_err(|_| sending())?;
    }
    let path = busbar_contract::net::parse_url(url)
        .map_err(|_| sending())?
        .path;
    let conn = table
        .conns
        .open(
            table.owner,
            need_id,
            &OpenDesc {
                target: url,
                method: b"GET",
                head_target: path.as_bytes(),
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
                if !(200..300).contains(&code) {
                    let shown = status_text(code);
                    if (300..400).contains(&code) {
                        return Err(Some(format!(
                            "GET {url}: HTTP {shown} — refusing to follow a plugins.fetch \
                             redirect (redirect-SSRF guard)"
                        )));
                    }
                    return Err(Some(format!("GET {url}: HTTP {shown}")));
                }
                // A declared Content-Length over the cap is rejected BEFORE reading a single body
                // byte; a dishonest or absent header falls through to the counted cap below.
                let declared = busbar_contract::abi::transport::fields::lines(&buf[..piece.len])
                    .find(|(name, _)| name.eq_ignore_ascii_case(b"content-length"))
                    .and_then(|(_, v)| std::str::from_utf8(v).ok()?.trim().parse::<u64>().ok());
                if let Some(len) = declared {
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

#[cfg(test)]
#[path = "tests/plugin_fetch.rs"]
mod tests;
