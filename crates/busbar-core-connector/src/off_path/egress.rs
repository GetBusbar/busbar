// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS MODULES' OFF-PATH CODE: what `proxy`, `proxy_route`, `fetch`, `guard` and `doors`
//! build once per process, configuration commit or door binding (the proxy environment parsed, the
//! `plugins.fetch` boot download, the destination lists read, a transport door bound, opened and
//! refreshed), never per request. The request path only reads what these build.

/// The proxy environment, parsed once at boot into the hops every dial reads.
pub(crate) mod proxy {
    use std::{borrow::Cow, sync::Arc};

    use crate::proxy::{ProxyChoice, ProxyEnvValues, ProxyHop};

    // The proxy environment is read once, at boot (callers: `from_env` here, the boot proxy
    // posture note in `off_path::lines`).
    impl ProxyEnvValues {
        /// Uppercase read before lowercase, empty values treated as unset — hyper-util
        pub(crate) fn from_process_env() -> Result<Self, String> {
            Self::from_lookup(|key| std::env::var_os(key))
        }

        pub(crate) fn from_lookup(
            mut lookup: impl FnMut(&str) -> Option<std::ffi::OsString>,
        ) -> Result<Self, String> {
            let mut first = |keys: [&str; 2]| -> Result<Option<String>, String> {
                for key in keys {
                    let Some(value) = lookup(key) else {
                        continue;
                    };
                    if value.is_empty() {
                        continue;
                    }
                    return value.into_string().map(Some).map_err(|_| not_unicode(key));
                }
                Ok(None)
            };
            Ok(ProxyEnvValues {
                https: first(crate::proxy::HTTPS_PROXY_KEYS)?,

                http: first(crate::proxy::HTTP_PROXY_KEYS)?,
                all: first(crate::proxy::ALL_PROXY_KEYS)?,
                no: first(crate::proxy::NO_PROXY_KEYS)?,
            })
        }
    }

    /// The proxy env value as a REFUSAL may render it: userinfo replaced by `***`, everything
    fn redact_userinfo(v: &str) -> String {
        let parts = busbar_contract::net::url_authority(v);
        let (host_port, tail) = (parts.host_port, parts.tail);
        let shown = if parts.userinfo.is_some() {
            format!("***@{host_port}{tail}")
        } else if tail.contains('@') {
            "***".to_owned()
        } else {
            format!("{host_port}{tail}")
        };
        let schemed = parts.scheme.map(|s| format!("{s}://{shown}"));
        schemed.unwrap_or(shown)
    }

    /// Parse a proxy env value (`http://[user:pass@]host[:port]`; a bare `host:port` is accepted
    pub fn parse_proxy(v: &str) -> Result<ProxyHop, String> {
        let shown = redact_userinfo(v);
        let url: Cow<'_, str> = if v.contains("://") {
            Cow::Borrowed(v)
        } else {
            Cow::Owned(format!("http://{v}"))
        };
        let parsed = url::Url::parse(&url)
            .map_err(|e| format!("proxy env value {shown:?} is not a valid URL: {e}"))?;
        if parsed.scheme() != busbar_contract::http::uri::Scheme::HTTP.as_str() {
            return Err(format!(
                "proxy env value {shown:?} uses scheme {:?}: only plain http:// CONNECT proxies \
                 are supported (an https:// proxy would need TLS-to-proxy, which this tunnel does \
                 not speak)",
                parsed.scheme()
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("proxy env value {shown:?} has no host"))?
            .to_owned();
        let port = parsed.port().unwrap_or(80);
        let auth = (!parsed.username().is_empty()).then(|| {
            use base64::Engine;

            let creds = [
                busbar_contract::net::percent_decoded_bytes(parsed.username()),
                b":".to_vec(),
                busbar_contract::net::percent_decoded_bytes(parsed.password().unwrap_or_default()),
            ]
            .concat();
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(creds)
            )
        });
        Ok(ProxyHop::new(host, port, auth))
    }

    /// A hop's spellings, made once with the hop: its own `host:port` (a v6 host bracketed) and
    /// what a CONNECT request carries after its `Host` line.
    pub(crate) fn hop_spellings(host: &str, port: u16, auth: Option<&str>) -> (String, String) {
        let endpoint = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let connect_tail = match auth {
            Some(auth) => format!("Proxy-Authorization: {auth}\r\n\r\n"),
            None => "\r\n".to_owned(),
        };
        (endpoint, connect_tail)
    }

    /// The refusal of proxy environment variable `key`, set to a value that is not valid Unicode.
    pub(crate) fn not_unicode(key: &str) -> String {
        format!("proxy environment variable {key} is not valid Unicode")
    }

    /// Resolve the value bag into the per-scheme slots, reqwest's precedence: scheme-specific
    pub fn resolve_config(env: &ProxyEnvValues) -> Result<Option<Arc<ProxyChoice>>, String> {
        let all = env
            .all
            .as_deref()
            .map(parse_proxy)
            .transpose()?
            .map(Arc::new);
        let scheme_slot = |v: &Option<String>| -> Result<Option<Arc<ProxyHop>>, String> {
            Ok(match v.as_deref() {
                Some(v) => Some(Arc::new(parse_proxy(v)?)),
                None => all.clone(),
            })
        };
        let https = scheme_slot(&env.https)?;
        let http = scheme_slot(&env.http)?;
        if https.is_none() && http.is_none() {
            return Ok(None);
        }
        Ok(Some(Arc::new(ProxyChoice::new(
            https,
            http,
            env.no.as_deref().unwrap_or(""),
        ))))
    }

    /// THE PROCESS'S PROXY CHOICE, read once from its environment: `None` when no proxy variable is
    pub fn from_env() -> Result<Option<Arc<ProxyChoice>>, String> {
        resolve_config(&ProxyEnvValues::from_process_env()?)
    }
}

/// THE `plugins.fetch` DOWNLOAD, run once at boot stage 3c.
pub(crate) mod fetch {
    use busbar_contract::conn::codes::{
        CAUSE_CONNECT, CAUSE_DEADLINE, CAUSE_EXCHANGE, CAUSE_FRAMER, CAUSE_SECURITY,
        DIRECTION_OUTBOUND, EGRESS_DEFAULT,
    };
    use busbar_contract::conn::{ConnCause, ConnError, ConnId, NeedRefusal, OpenDesc, PieceKind};
    use busbar_contract::rendering::{ReadBlob, ReadNeed};

    use crate::fetch::Table;

    /// Download the `plugins.fetch` artifact at `url` over `table`, under the operator's extra
    pub fn download(
        table: &Table,
        url: &str,
        blocked: &[String],
        cap: usize,
    ) -> Result<Vec<u8>, String> {
        busbar_kernel::preflight::plugin_fetch_admits(url, blocked)?;
        std::thread::scope(|s| {
            let joined = s
                .spawn(|| -> Result<Vec<u8>, String> {
                    let rt = busbar_kernel::rt::current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| format!("fetch runtime: {e}"))?;
                    rt.block_on(get(table, url, cap))
                })
                .join()
                .map_err(|_| "plugins.fetch download thread panicked".to_owned());
            joined?
        })
    }

    /// The download's need for the URL's own scheme (`scheme`, lower-cased, as the URL spells it): the
    fn need(scheme: &str) -> ReadNeed {
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
            keep_mode: busbar_contract::conn::codes::KEEP_NAMED,
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
    async fn get(table: &Table, url: &str, cap: usize) -> Result<Vec<u8>, String> {
        let sending =
            |cause: &str| format!("GET {url}: error sending request for url ({url}): {cause}");
        let refused = |why: Option<NeedRefusal>| why.map(|w| w.render(|t| scrub(t, url)));
        let (need_id, scheme) = match url.split_once("://") {
            Some((scheme, _)) => (table.secured_need, scheme.to_ascii_lowercase()),
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
                    &refused(table.declared.refusal(table.owner, need_id)).unwrap_or_else(
                        || match e {
                            ConnError::Refused => CONNECTOR_REFUSED.to_owned(),
                            other => {
                                format!("the connection could not be opened: {}", other.text())
                            }
                        },
                    ),
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
            Early::NoHead => {
                sending("the connection ended before the registry sent a response head")
            }
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
            CAUSE_DEADLINE => {
                "the download's deadline passed before the registry answered".to_owned()
            }
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
        let mut body: Vec<u8> = Vec::new();
        loop {
            let piece =
                std::future::poll_fn(|cx| table.conns.poll_read(table.owner, conn, cx, &mut buf))
                    .await;
            let piece = match piece {
                Ok(p) => p,
                Err(e) if status.is_none() => return Err(Early::Conn(e)),
                Err(_) => {
                    return Err(Early::Said(format!(
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
                            return Err(Early::Said(format!(
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
                        return Err(Early::Said(format!(
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
}

/// The destination guard's lists, read once per configuration commit.
pub(crate) mod guard {
    use std::net::IpAddr;
    use std::sync::{Arc, PoisonError, RwLock};

    use busbar_contract::net::{host_ip, IpNet};
    use busbar_kernel::config::Destinations;

    use crate::guard::{canonical, norm, Entry, Metadata};

    /// The node's own front door as the guard keeps it: the listen ports and the canonical
    /// addresses the listeners are bound to, built once per configuration commit.
    pub fn own_node(ports: &[u16], bound: &[IpAddr]) -> crate::guard::OwnNode {
        let mut node = crate::guard::OwnNode::default();
        node.ports.extend_from_slice(ports);
        node.ips.extend(bound.iter().copied().map(canonical));
        node
    }

    /// A 1.5.5 list entry (`allow_metadata_hosts`, `blocked_metadata_hosts`), read as 1.5.5 read it:
    fn legacy(entry: &str) -> Option<Entry> {
        let e = norm(entry.trim())?;
        if e.is_empty() {
            return None;
        }
        Some(match host_ip(&e) {
            Some(ip) => Entry::Net(IpNet::host(ip)),
            None => Entry::Host(e),
        })
    }

    // A guard is built once at boot and its lists re-published once per config commit: off the
    // request path (callers: the root's boot and config commit, the store kit's run).
    impl crate::guard::Guard {
        /// The guard a deployment states, the engine's own listen addresses (`d.listens`) in its
        /// own-node set from the start, so no guard frozen from it ever judges without them.
        ///
        /// # Errors
        /// None today; the `Result` is the boot's.
        pub fn from_config(d: &Destinations) -> Result<crate::guard::Guard, String> {
            let guard = crate::guard::Guard {
                block_private: d.block_private_addresses,
                metadata: Arc::new(RwLock::new(Arc::new(Metadata::from_config(d)))),
                node: Arc::default(),
            };
            let listens: Vec<&str> = d.listens.iter().map(String::as_str).collect();
            let bound: Vec<IpAddr> = d
                .listens
                .iter()
                .filter_map(|l| l.parse::<std::net::SocketAddr>().ok())
                .map(|at| at.ip())
                .collect();
            guard.publish_own(&crate::off_path::lines::own_ports(&listens), &bound);
            Ok(guard)
        }

        /// A config commit: the metadata lists `d` states (the carve-outs and the extra refusals)
        /// replace the ones in force, whole.
        pub fn publish(&self, d: &Destinations) {
            let lists = Arc::new(Metadata::from_config(d));
            *self
                .metadata
                .write()
                .unwrap_or_else(PoisonError::into_inner) = lists;
        }
    }

    impl Metadata {
        /// The 1.5.5 metadata lists `d` states.
        pub(crate) fn from_config(d: &Destinations) -> Metadata {
            Metadata {
                blocked: d.blocked.iter().filter_map(|e| legacy(e)).collect(),
            }
        }
    }
}
