// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATOR'S PROXY ON THE DIAL: the tunnel under a dialled connection, and the proxy reached
//! over TLS.
//!
//! Order on a dial that the proxy choice selects (a kept connection was tunnelled when it was
//! dialled; nothing about the proxy is done again for it):
//!
//! 1. The target is judged first. A target the guard refuses is never shown to the proxy.
//! 2. The proxy's own host is judged in the operator-infrastructure class; its addresses are what
//!    the socket connects to.
//! 3. [`Dialling::connected`]: where the proxy address is `https://`, the engine's TLS session to
//!    the proxy ([`Outer`]), verified against the trust store's selection for the proxy's host.
//! 4. `CONNECT target HTTP/1.1` ([`connect_request`]): the proxy's password appears here and only
//!    here, in a block that is wiped as it is written.
//! 5. The proxy's answer ([`Answer`]): 2xx goes on, anything else fails. Nothing of the answer is
//!    held: the reader keeps a status and four bytes of state, so there is no cap to choose; the
//!    open deadline is the bound.
//! 6. TLS to the target, inside the tunnel, names the target (SNI and certificate), never the
//!    proxy.
//!
//! One deadline, the open deadline, covers connect, the proxy's TLS, the tunnel and the target's
//! handshake.
//!
//! The engine resolves the target's name, for every install: the CONNECT names the judged
//! address. `outbound.proxy_resolution: proxy` is an operator's deliberate, documented choice
//! (never written by an upgrade): the CONNECT then names the target by name.
//!
//! A proxy failure is the proxy's: stage [`CAUSE_PROXY`], no provider's breaker is charged
//! ([`super::redial::Ended::Proxy`]), and the refusal is audited with verdict `proxy`.

use std::fmt::Write as _;
use std::io::{self, Read as _, Write as _};
use std::net::SocketAddr;
use std::sync::Arc;

use busbar_contract::secure::SecureVec;

use crate::proxy_route::{ProxyChoice, ProxyHop};

/// The cause stage of a failure at the operator's proxy, in the connection table's own numbering
/// (after `CAUSE_FRAMER = 5`). Not part of the plugin interface.
pub(crate) const CAUSE_PROXY: u64 = 6;

/// The audit verdict of a dial the proxy refused or failed.
pub(crate) const VERDICT_PROXY: &str = "proxy";

/// The protocol the engine offers the proxy on its own TLS session: the CONNECT is HTTP/1.1.
const PROXY_ALPN: &[u8] = b"http/1.1";

/// One read of decrypted bytes off the proxy's TLS session. A stack buffer, wiped after use.
const PLAIN_CHUNK: usize = 4 * 1024;

/// A failure at the proxy. The text never carries the proxy's password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProxyFailure(pub(crate) String);

impl std::fmt::Display for ProxyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProxyFailure {}

fn failed(text: impl Into<String>) -> ProxyFailure {
    ProxyFailure(text.into())
}

/// Who resolves the target's name behind the proxy (`outbound.proxy_resolution`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// The engine: every address judged, the CONNECT names the judged address. The standard.
    Engine,
    /// The proxy: the CONNECT names the target by name. An operator's deliberate choice.
    Proxy,
}

/// What the CONNECT names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// The address the guard judged.
    Addr(SocketAddr),
    /// The target's own `host:port`.
    Name(String),
}

/// A `SocketAddr` as text, on the stack (the longest is a bracketed IPv6 address with a zone and a
/// port).
struct AddrText {
    bytes: [u8; 96],
    len: usize,
}

impl std::fmt::Write for AddrText {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(std::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl Target {
    /// The target of a tunnel. `judged` = the address the guard admitted for `authority`, when the
    /// name resolved here. `pinned` = the open pins the addresses it may reach.
    ///
    /// # Errors
    /// The refusal, in words: a name that does not resolve here under the engine's own
    /// resolution, or a pinned open handed to the proxy by name.
    pub(crate) fn of(
        resolution: Resolution,
        authority: &str,
        judged: Option<SocketAddr>,
        pinned: bool,
    ) -> Result<Self, &'static str> {
        match (resolution, judged) {
            (Resolution::Engine, Some(addr)) => Ok(Self::Addr(addr)),
            (Resolution::Engine, None) => Err(
                "the destination's name does not resolve on this host: the engine resolves and \
                 checks every address before it asks the proxy to connect",
            ),
            (Resolution::Proxy, _) if pinned => Err(
                "this open pins the addresses it may reach, and the proxy resolves the name: the \
                 address cannot be checked here",
            ),
            (Resolution::Proxy, _) => Ok(Self::Name(authority.to_owned())),
        }
    }

    /// `ConnIn.peer` of a tunnelled dial: the target's judged address, empty when the proxy
    /// resolves the name. Never the proxy's address.
    pub(crate) fn peer(&self) -> Option<SocketAddr> {
        match self {
            Self::Addr(addr) => Some(*addr),
            Self::Name(_) => None,
        }
    }

    /// The address the plaintext rule and an open's pinned set are applied to.
    pub(crate) fn judged(&self) -> Option<SocketAddr> {
        self.peer()
    }
}

/// The proxy a dial of `authority` goes through, if any: the choice's slot for the target's
/// security, unless the exemption list names the host.
pub(crate) fn hop_for(
    choice: Option<&ProxyChoice>,
    secured_target: bool,
    authority: &str,
) -> Option<Arc<ProxyHop>> {
    choice?.select(secured_target, crate::proxy::host_of(authority))
}

/// `CONNECT target HTTP/1.1`, its `Host` line, the hop's `Proxy-Authorization` line where set and
/// the blank line, appended to `out`. `out` is the connection's own output block (wiped as the
/// socket takes it), or the block handed to the proxy's TLS session and dropped at once.
///
/// # Errors
/// The buffer's refusal.
pub(crate) fn connect_request(
    out: &mut SecureVec,
    target: &Target,
    hop: &ProxyHop,
) -> Result<(), ProxyFailure> {
    let mut text = AddrText {
        bytes: [0; 96],
        len: 0,
    };
    let named: &[u8] = match target {
        Target::Name(name) => name.as_bytes(),
        Target::Addr(addr) => {
            write!(text, "{addr}").map_err(|_| failed("the tunnel's target is not an address"))?;
            &text.bytes[..text.len]
        }
    };
    let pieces: [&[u8]; 6] = [
        b"CONNECT ",
        named,
        b" HTTP/1.1\r\nHost: ",
        named,
        b"\r\n",
        hop.connect_tail().as_bytes(),
    ];
    for piece in pieces {
        out.extend(piece)
            .map_err(|_| failed("the tunnel request did not fit the write buffer"))?;
    }
    Ok(())
}

/// What the proxy's answer says so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Answered {
    /// The head has not ended.
    More,
    /// 2xx and the head ended: the tunnel is open. Bytes from this offset of the chunk just fed
    /// belong to the tunnel.
    Open(usize),
    /// The proxy answered this status: no tunnel.
    Refused(u16),
    /// Not an HTTP/1 answer.
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reading {
    /// `HTTP/1.x `, by position.
    Version(u8),
    /// The three digits, by count.
    Code(u8),
    /// The byte after the code.
    AfterCode,
    /// The rest of the head; how much of `\r\n\r\n` is matched.
    Rest(u8),
    /// Over: every later byte is the tunnel's.
    Done,
}

/// THE READER OF THE PROXY'S ANSWER TO A CONNECT. It holds nothing of the answer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Answer {
    reading: Reading,
    code: u16,
}

impl Default for Answer {
    fn default() -> Self {
        Self::new()
    }
}

impl Answer {
    /// Before the first byte.
    pub(crate) const fn new() -> Self {
        Self {
            reading: Reading::Version(0),
            code: 0,
        }
    }

    /// The next bytes the proxy sent.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Answered {
        const VERSION: &[u8] = b"HTTP/1.";
        for (at, &b) in bytes.iter().enumerate() {
            self.reading = match self.reading {
                Reading::Version(n) if (n as usize) < VERSION.len() => {
                    if b != VERSION[n as usize] {
                        return Answered::Malformed;
                    }
                    Reading::Version(n + 1)
                }
                Reading::Version(7) => {
                    if !b.is_ascii_digit() {
                        return Answered::Malformed;
                    }
                    Reading::Version(8)
                }
                Reading::Version(_) => {
                    if b != b' ' {
                        return Answered::Malformed;
                    }
                    Reading::Code(0)
                }
                Reading::Code(n) => {
                    if !b.is_ascii_digit() {
                        return Answered::Malformed;
                    }
                    self.code = self.code * 10 + u16::from(b - b'0');
                    if n == 2 {
                        Reading::AfterCode
                    } else {
                        Reading::Code(n + 1)
                    }
                }
                Reading::AfterCode => {
                    if !(200..300).contains(&self.code) {
                        return Answered::Refused(self.code);
                    }
                    match b {
                        b' ' => Reading::Rest(0),
                        b'\r' => Reading::Rest(1),
                        _ => return Answered::Malformed,
                    }
                }
                Reading::Rest(matched) => match (matched, b) {
                    (3, b'\n') => {
                        self.reading = Reading::Done;
                        return Answered::Open(at + 1);
                    }
                    (0 | 2, b'\r') => Reading::Rest(matched + 1),
                    (1, b'\n') => Reading::Rest(2),
                    (_, b'\r') => Reading::Rest(1),
                    _ => Reading::Rest(0),
                },
                Reading::Done => return Answered::Open(at),
            };
        }
        if self.reading == Reading::Done {
            Answered::Open(0)
        } else {
            Answered::More
        }
    }
}

/// THE ENGINE'S TLS SESSION TO THE PROXY ITSELF (a proxy whose address is `https://`). The tunnel,
/// and the target's own TLS inside it, ride this session.
pub(crate) struct Outer {
    tls: rustls::ClientConnection,
}

impl std::fmt::Debug for Outer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outer").finish_non_exhaustive()
    }
}

impl Outer {
    /// A session to `hop`, verified by `trust` (the trust store's selection for the proxy's host)
    /// against the proxy's own name.
    ///
    /// # Errors
    /// The proxy's host is not a server name, or the session cannot be made.
    pub(crate) fn new(
        trust: &Arc<rustls::ClientConfig>,
        hop: &ProxyHop,
    ) -> Result<Self, ProxyFailure> {
        let mut config = (**trust).clone();
        config.alpn_protocols = vec![PROXY_ALPN.to_vec()];
        let host = hop.host().trim_start_matches('[').trim_end_matches(']');
        let name = rustls::pki_types::ServerName::try_from(host)
            .map(|name| name.to_owned())
            .map_err(|error| failed(format!("the proxy's host is not a server name: {error}")))?;
        let tls = rustls::ClientConnection::new(Arc::new(config), name)
            .map_err(|error| failed(format!("the proxy's connection security: {error}")))?;
        Ok(Self { tls })
    }

    /// The handshake with the proxy has not ended.
    pub(crate) fn handshaking(&self) -> bool {
        self.tls.is_handshaking()
    }

    /// The session's queued records, appended to `out`.
    ///
    /// # Errors
    /// The buffer's refusal.
    pub(crate) fn drain(&mut self, out: &mut SecureVec) -> Result<(), ProxyFailure> {
        while self.tls.wants_write() {
            self.tls
                .write_tls(out)
                .map_err(|error| failed(format!("the proxy's connection security: {error}")))?;
        }
        Ok(())
    }

    /// Bytes for the proxy (the CONNECT, or the tunnel's bytes): encrypted, the records appended
    /// to `out`.
    ///
    /// # Errors
    /// The session's refusal.
    pub(crate) fn seal(&mut self, plain: &[u8], out: &mut SecureVec) -> Result<(), ProxyFailure> {
        self.tls
            .writer()
            .write_all(plain)
            .map_err(|error| failed(format!("the proxy's connection security: {error}")))?;
        self.drain(out)
    }

    /// Bytes the socket read: decrypted, appended to `plain`; whatever the session must answer is
    /// appended to `out`.
    ///
    /// # Errors
    /// The session's refusal (a bad certificate, a broken record).
    pub(crate) fn open(
        &mut self,
        wire: &[u8],
        plain: &mut SecureVec,
        out: &mut SecureVec,
    ) -> Result<(), ProxyFailure> {
        let security = |error: &dyn std::fmt::Display| {
            failed(format!("the proxy's connection security: {error}"))
        };
        let mut rest = wire;
        while !rest.is_empty() {
            if self.tls.read_tls(&mut rest).map_err(|e| security(&e))? == 0 {
                break;
            }
            self.tls.process_new_packets().map_err(|e| security(&e))?;
            let mut chunk = [0_u8; PLAIN_CHUNK];
            loop {
                match self.tls.reader().read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let kept = plain.extend(&chunk[..n]);
                        chunk[..n].fill(0);
                        kept.map_err(|_| failed("the tunnel's read buffer"))?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(security(&error)),
                }
            }
        }
        self.drain(out)
    }

    /// The engine is done with the connection: the session's close, queued.
    pub(crate) fn close(&mut self, out: &mut SecureVec) {
        self.tls.send_close_notify();
        let _ = self.drain(out);
    }
}

/// Where a dial is, below the transport's session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The socket is connecting (to the target, or to the proxy).
    Connecting,
    /// The engine's TLS handshake with the proxy.
    ProxyHandshake,
    /// The CONNECT is written; the proxy's answer is being read.
    Tunnelling,
    /// The target's TLS handshake (inside the tunnel when there is one).
    Handshaking,
    /// Open for the transport's session.
    Open,
}

/// THE DIAL'S STEPS BELOW THE SESSION, and the layer every later byte of a tunnelled connection
/// crosses.
pub(crate) struct Dialling {
    step: Step,
    tunnel: Option<(Arc<ProxyHop>, Target)>,
    outer: Option<Outer>,
    answer: Answer,
    secure_target: bool,
    /// Bytes between the two layers of a tunnel through a TLS proxy, emptied on every call.
    between: SecureVec,
}

impl std::fmt::Debug for Dialling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dialling")
            .field("step", &self.step)
            .field("tunnelled", &self.tunnel.is_some())
            .field("proxy_tls", &self.outer.is_some())
            .finish()
    }
}

impl Dialling {
    /// A dial straight to the target.
    pub(crate) fn direct(secure_target: bool) -> Self {
        Self {
            step: Step::Connecting,
            tunnel: None,
            outer: None,
            answer: Answer::new(),
            secure_target,
            between: SecureVec::new(),
        }
    }

    /// A dial through `hop` to `target`. `proxy_trust` = the client TLS settings for the proxy's
    /// own host; it is read only when the hop is reached over TLS.
    ///
    /// # Errors
    /// A hop reached over TLS with no settings to verify it by, or [`Outer::new`]'s refusal.
    pub(crate) fn through(
        hop: Arc<ProxyHop>,
        target: Target,
        secure_target: bool,
        proxy_trust: Option<&Arc<rustls::ClientConfig>>,
    ) -> Result<Self, ProxyFailure> {
        let outer = if hop.secure() {
            let trust = proxy_trust.ok_or_else(|| {
                failed("the proxy is reached over TLS and no trust is set to verify it by")
            })?;
            Some(Outer::new(trust, &hop)?)
        } else {
            None
        };
        Ok(Self {
            step: Step::Connecting,
            tunnel: Some((hop, target)),
            outer,
            answer: Answer::new(),
            secure_target,
            between: SecureVec::new(),
        })
    }

    /// Where the dial is.
    pub(crate) const fn step(&self) -> Step {
        self.step
    }

    /// The dial goes through a proxy.
    pub(crate) const fn tunnelled(&self) -> bool {
        self.tunnel.is_some()
    }

    /// `ConnIn.peer` where the dial is tunnelled: `Some(None)` = tunnelled by name (empty);
    /// `None` = not tunnelled (the socket's own peer).
    pub(crate) fn tunnel_peer(&self) -> Option<Option<SocketAddr>> {
        self.tunnel.as_ref().map(|(_, target)| target.peer())
    }

    fn after_tunnel(&self) -> Step {
        if self.secure_target {
            Step::Handshaking
        } else {
            Step::Open
        }
    }

    fn write_connect(&mut self, out: &mut SecureVec) -> Result<(), ProxyFailure> {
        let Some((hop, target)) = self.tunnel.as_ref() else {
            return Ok(());
        };
        match self.outer.as_mut() {
            None => connect_request(out, target, hop),
            Some(outer) => {
                // The block that held the password is wiped when this returns.
                let mut request = SecureVec::new();
                connect_request(&mut request, target, hop)?;
                outer.seal(request.as_slice(), out)
            }
        }
    }

    /// The socket connected. What must be written first is appended to `out`.
    ///
    /// # Errors
    /// The proxy session's refusal.
    pub(crate) fn connected(&mut self, out: &mut SecureVec) -> Result<Step, ProxyFailure> {
        if self.step != Step::Connecting {
            return Ok(self.step);
        }
        self.step = match (self.tunnel.is_some(), self.outer.as_mut()) {
            (false, _) => self.after_tunnel(),
            (true, Some(outer)) => {
                outer.drain(out)?;
                Step::ProxyHandshake
            }
            (true, None) => {
                self.write_connect(out)?;
                Step::Tunnelling
            }
        };
        Ok(self.step)
    }

    /// Bytes the socket read while the dial is at [`Step::ProxyHandshake`] or
    /// [`Step::Tunnelling`]. What must be written is appended to `out`; bytes the proxy sent past
    /// its answer's head belong to the tunnel and are appended to `inner`.
    ///
    /// # Errors
    /// The proxy refused the tunnel, answered something that is not HTTP, sent bytes before it was
    /// asked, or its TLS session failed.
    pub(crate) fn feed(
        &mut self,
        wire: &[u8],
        out: &mut SecureVec,
        inner: &mut SecureVec,
    ) -> Result<Step, ProxyFailure> {
        self.between.clear();
        let plain: &[u8] = match self.outer.as_mut() {
            None => wire,
            Some(outer) => {
                outer.open(wire, &mut self.between, out)?;
                self.between.as_slice()
            }
        };
        match self.step {
            Step::ProxyHandshake => {
                if !plain.is_empty() {
                    return Err(failed(
                        "the proxy sent bytes before the tunnel was asked for",
                    ));
                }
                if self
                    .outer
                    .as_ref()
                    .is_some_and(|outer| !outer.handshaking())
                {
                    self.between.clear();
                    self.write_connect(out)?;
                    self.step = Step::Tunnelling;
                }
            }
            Step::Tunnelling => match self.answer.feed(plain) {
                Answered::More => {}
                Answered::Open(at) => {
                    let rest = inner.extend(&plain[at..]);
                    self.between.clear();
                    rest.map_err(|_| failed("the tunnel's read buffer"))?;
                    self.step = self.after_tunnel();
                }
                Answered::Refused(status) => {
                    return Err(failed(format!(
                        "the proxy refused the tunnel (status {status})"
                    )))
                }
                Answered::Malformed => {
                    return Err(failed("the proxy's answer to CONNECT is not HTTP/1"))
                }
            },
            Step::Connecting | Step::Handshaking | Step::Open => {
                let rest = inner.extend(plain);
                self.between.clear();
                rest.map_err(|_| failed("the tunnel's read buffer"))?;
            }
        }
        self.between.clear();
        Ok(self.step)
    }

    /// Socket bytes of an established connection, as the layer above reads them (the target's TLS,
    /// or the transport): appended to `inner`. Without a TLS proxy the caller reads `wire` itself
    /// and never calls this.
    ///
    /// # Errors
    /// The proxy session's refusal.
    pub(crate) fn from_socket(
        &mut self,
        wire: &[u8],
        out: &mut SecureVec,
        inner: &mut SecureVec,
    ) -> Result<(), ProxyFailure> {
        match self.outer.as_mut() {
            None => inner
                .extend(wire)
                .map_err(|_| failed("the tunnel's read buffer")),
            Some(outer) => outer.open(wire, inner, out),
        }
    }

    /// The dial is reached through a TLS proxy: every byte for the socket crosses [`Self::run`].
    pub(crate) const fn wraps(&self) -> bool {
        self.outer.is_some()
    }

    /// Queue one run for the socket through every layer: the target's TLS where `target_tls` is
    /// set (one vectored write, [`super::seal::queue_run`]), then the proxy's TLS where the proxy
    /// is reached over it.
    ///
    /// # Errors
    /// A layer's refusal; the caller fails the connection, which clears `out`.
    pub(crate) fn run(
        &mut self,
        target_tls: Option<&mut rustls::ClientConnection>,
        out: &mut SecureVec,
        run: &[&[u8]],
    ) -> io::Result<()> {
        let Some(outer) = self.outer.as_mut() else {
            return super::seal::queue_run(target_tls, out, run);
        };
        self.between.clear();
        let queued = super::seal::queue_run(target_tls, &mut self.between, run);
        let sealed = queued.and_then(|()| {
            outer
                .seal(self.between.as_slice(), out)
                .map_err(|failure| io::Error::other(failure.0))
        });
        self.between.clear();
        sealed
    }

    /// The target's TLS has records to send that no run carries (its handshake, its close): they
    /// cross the proxy's layer where there is one.
    ///
    /// # Errors
    /// A layer's refusal.
    pub(crate) fn drain_target(
        &mut self,
        target_tls: &mut rustls::ClientConnection,
        out: &mut SecureVec,
    ) -> io::Result<()> {
        self.run(Some(target_tls), out, &[])
    }

    /// The engine is done with the connection: the proxy session's close, queued after the
    /// target's own.
    pub(crate) fn close(&mut self, out: &mut SecureVec) {
        if let Some(outer) = self.outer.as_mut() {
            outer.close(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(auth: Option<&str>) -> ProxyHop {
        ProxyHop::new("proxy.internal".to_owned(), 3128, auth.map(str::to_owned))
    }

    fn addr() -> SocketAddr {
        "203.0.113.7:443".parse().unwrap()
    }

    #[test]
    fn the_engine_resolves_and_the_connect_names_the_judged_address() {
        let target = Target::of(
            Resolution::Engine,
            "api.example.com:443",
            Some(addr()),
            false,
        );
        assert_eq!(target, Ok(Target::Addr(addr())));
        let mut out = SecureVec::new();
        connect_request(&mut out, &target.unwrap(), &hop(None)).unwrap();
        assert_eq!(
            out.as_slice(),
            b"CONNECT 203.0.113.7:443 HTTP/1.1\r\nHost: 203.0.113.7:443\r\n\r\n"
        );
    }

    #[test]
    fn a_name_that_does_not_resolve_here_is_refused_not_handed_to_the_proxy() {
        assert!(Target::of(Resolution::Engine, "api.example.com:443", None, false).is_err());
    }

    #[test]
    fn the_operators_own_choice_names_the_target_by_name() {
        let target = Target::of(
            Resolution::Proxy,
            "api.example.com:443",
            Some(addr()),
            false,
        );
        assert_eq!(target, Ok(Target::Name("api.example.com:443".to_owned())));
        assert_eq!(target.unwrap().peer(), None, "ConnIn.peer is empty by name");
        assert!(
            Target::of(Resolution::Proxy, "api.example.com:443", None, true).is_err(),
            "a pinned open cannot be checked when the proxy resolves"
        );
    }

    #[test]
    fn an_ipv6_target_is_bracketed() {
        let v6: SocketAddr = "[2001:db8::1]:8443".parse().unwrap();
        let mut out = SecureVec::new();
        connect_request(&mut out, &Target::Addr(v6), &hop(None)).unwrap();
        assert!(out
            .as_slice()
            .starts_with(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n"));
    }

    #[test]
    fn the_password_is_in_the_connect_and_nowhere_in_a_failure() {
        let mut out = SecureVec::new();
        connect_request(&mut out, &Target::Addr(addr()), &hop(Some("Basic dTpw"))).unwrap();
        let text = String::from_utf8_lossy(out.as_slice()).into_owned();
        assert!(text.ends_with("Proxy-Authorization: Basic dTpw\r\n\r\n"));
        let mut dial = Dialling::through(
            Arc::new(hop(Some("Basic dTpw"))),
            Target::Addr(addr()),
            true,
            None,
        )
        .unwrap();
        let (mut out, mut inner) = (SecureVec::new(), SecureVec::new());
        dial.connected(&mut out).unwrap();
        let refused = dial
            .feed(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
                &mut out,
                &mut inner,
            )
            .unwrap_err();
        assert!(!refused.0.contains("dTpw"));
        assert!(refused.0.contains("407"));
    }

    #[test]
    fn a_2xx_answer_opens_the_tunnel_and_hands_on_what_follows_it() {
        let mut answer = Answer::new();
        let bytes = b"HTTP/1.1 200 Connection established\r\nVia: x\r\n\r\n\x16\x03\x01";
        assert_eq!(answer.feed(bytes), Answered::Open(bytes.len() - 3));
    }

    #[test]
    fn an_answer_split_at_every_byte_reads_the_same() {
        let bytes = b"HTTP/1.0 200 OK\r\nA: b\r\n\r\n";
        for cut in 1..bytes.len() {
            let mut answer = Answer::new();
            assert_eq!(answer.feed(&bytes[..cut]), Answered::More, "cut {cut}");
            assert_eq!(
                answer.feed(&bytes[cut..]),
                Answered::Open(bytes.len() - cut),
                "cut {cut}"
            );
        }
    }

    #[test]
    fn a_status_line_with_no_reason_and_no_fields_opens() {
        let mut answer = Answer::new();
        assert_eq!(answer.feed(b"HTTP/1.1 200\r\n\r\n"), Answered::Open(16));
    }

    #[test]
    fn any_other_status_refuses_as_soon_as_it_is_read() {
        for (bytes, status) in [
            (&b"HTTP/1.1 403 Forbidden\r\n"[..], 403),
            (b"HTTP/1.1 502 Bad Gateway\r\n\r\n", 502),
            (b"HTTP/1.1 100 Continue\r\n\r\n", 100),
            (b"HTTP/1.1 302 Found\r\n", 302),
        ] {
            assert_eq!(Answer::new().feed(bytes), Answered::Refused(status));
        }
    }

    #[test]
    fn what_is_not_http_is_malformed() {
        for bytes in [
            &b"SSH-2.0-x\r\n"[..],
            b"HTTP/2 200\r\n",
            b"HTTP/1.1 2x0 \r\n",
            b"HTTP/1.1 200x",
        ] {
            assert_eq!(Answer::new().feed(bytes), Answered::Malformed);
        }
    }

    #[test]
    fn a_long_answer_head_is_held_nowhere() {
        let mut answer = Answer::new();
        assert_eq!(answer.feed(b"HTTP/1.1 200 OK\r\n"), Answered::More);
        let line = [b'x'; 4096];
        for _ in 0..64 {
            assert_eq!(answer.feed(&line), Answered::More);
        }
        assert_eq!(answer.feed(b"\r\n\r\n"), Answered::Open(4));
        assert_eq!(std::mem::size_of::<Answer>(), 4);
    }

    #[test]
    fn a_direct_dial_has_no_tunnel_step() {
        let mut out = SecureVec::new();
        let mut secure = Dialling::direct(true);
        assert_eq!(secure.connected(&mut out), Ok(Step::Handshaking));
        let mut plain = Dialling::direct(false);
        assert_eq!(plain.connected(&mut out), Ok(Step::Open));
        assert!(out.is_empty() && !secure.tunnelled() && !secure.wraps());
        assert_eq!(secure.tunnel_peer(), None);
    }

    #[test]
    fn a_plain_proxy_carries_a_secured_target() {
        let mut dial =
            Dialling::through(Arc::new(hop(None)), Target::Addr(addr()), true, None).unwrap();
        let (mut out, mut inner) = (SecureVec::new(), SecureVec::new());
        assert_eq!(dial.connected(&mut out), Ok(Step::Tunnelling));
        assert!(out.as_slice().starts_with(b"CONNECT 203.0.113.7:443 "));
        assert_eq!(
            dial.feed(b"HTTP/1.1 200 OK\r\n", &mut out, &mut inner),
            Ok(Step::Tunnelling)
        );
        assert_eq!(
            dial.feed(b"\r\n", &mut out, &mut inner),
            Ok(Step::Handshaking),
            "the target's handshake runs inside the tunnel"
        );
        assert!(inner.is_empty());
        assert_eq!(dial.tunnel_peer(), Some(Some(addr())));
    }

    #[test]
    fn a_plain_target_through_the_proxy_opens_after_the_tunnel() {
        let mut dial =
            Dialling::through(Arc::new(hop(None)), Target::Addr(addr()), false, None).unwrap();
        let (mut out, mut inner) = (SecureVec::new(), SecureVec::new());
        dial.connected(&mut out).unwrap();
        assert_eq!(
            dial.feed(b"HTTP/1.1 200 OK\r\n\r\nearly", &mut out, &mut inner),
            Ok(Step::Open)
        );
        assert_eq!(inner.as_slice(), b"early");
    }

    #[test]
    fn a_second_connected_writes_no_second_connect() {
        let mut dial =
            Dialling::through(Arc::new(hop(None)), Target::Addr(addr()), true, None).unwrap();
        let mut out = SecureVec::new();
        dial.connected(&mut out).unwrap();
        let once = out.len();
        dial.connected(&mut out).unwrap();
        assert_eq!(out.len(), once);
    }

    #[test]
    fn a_tls_proxy_with_no_trust_is_refused_before_any_socket() {
        let secure = Arc::new(hop(None).over_tls());
        let refused = Dialling::through(secure, Target::Addr(addr()), true, None).unwrap_err();
        assert!(refused.0.contains("no trust"));
    }

    #[test]
    fn the_hop_is_chosen_by_the_targets_security_and_the_exemption_list() {
        let (secured, plain) = (Arc::new(hop(None)), Arc::new(hop(Some("Basic eA=="))));
        let choice = ProxyChoice::new(
            Some(Arc::clone(&secured)),
            Some(Arc::clone(&plain)),
            "internal.example",
        );
        assert_eq!(
            hop_for(Some(&choice), true, "api.example.com:443"),
            Some(secured)
        );
        assert_eq!(
            hop_for(Some(&choice), false, "api.example.com:80"),
            Some(plain)
        );
        assert_eq!(hop_for(Some(&choice), true, "internal.example:443"), None);
        assert_eq!(hop_for(None, true, "api.example.com:443"), None);
    }
}
