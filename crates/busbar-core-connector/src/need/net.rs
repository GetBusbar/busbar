// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PRODUCTION `NeedIo` (IF 13): [`ConnectorIo`] carries OPEN, STARTTLS, WRITE, READ and FETCH
//! over the connector's own sockets (`socket`, registered on the process reactor through `io`),
//! rustls on the aws-lc provider (`tls::client`, `need::tlsconf`) and hyper's client connections
//! (`need::http`).
//!
//! Nothing is decided here. By the time one of these methods runs, the handler has applied the
//! transport gate, the pool and the judge: the addresses in a [`Dial`] are the ones the judge
//! admitted, and every FETCH connection is judged by the [`Admission`] it is handed. No method
//! retries, follows a redirect or adds a credential of its own.

use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use busbar_plugin_abi::host_side::needs::{NeedErr, NeedOut};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsConnector;

use super::exchange;
use super::tlsconf::Configs;
use super::{Admission, Dial, Dialled, FetchReq, NeedIo, TlsPlan};
use crate::io::{register_on, timeout_on, Direction, Registered};
use crate::socket::{self, Sock};

/// A dialled socket on the reactor, as a tokio byte stream.
#[derive(Debug)]
pub struct Net {
    sock: Registered<Sock>,
    logical_dest: Box<str>,
    epoch: u64,
    prefix: busbar_contract::secure::SecureVec,
}

impl Net {
    fn peer_ip(&self) -> Option<IpAddr> {
        socket::peer_ip(&self.sock.socket())
    }
}

impl AsyncRead for Net {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let count = buf.remaining().min(this.prefix.len());
            buf.put_slice(&this.prefix.as_slice()[..count]);
            this.prefix.consume(count);
            return Poll::Ready(Ok(()));
        }
        let dst = buf.initialize_unfilled();
        if dst.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let want = dst.len();
        let n = std::task::ready!(this
            .sock
            .poll_io_sized(Direction::Read, want, cx, |mut s| s.read(&mut *dst)))?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Net {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.sock
            .poll_io_sized(Direction::Write, buf.len(), cx, |mut s| s.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.sock.socket().shutdown(Shutdown::Write) {
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            other => Poll::Ready(other),
        }
    }
}

/// A conn a Need holds: the plaintext socket, or TLS over it.
#[derive(Debug)]
pub enum Stream {
    /// Plaintext (and TLS_INBAND's plaintext phase).
    Plain(Net),
    /// TLS over the socket.
    Tls(Box<tokio_rustls::client::TlsStream<Net>>),
}

impl Stream {
    fn net(&self) -> &Net {
        match self {
            Stream::Plain(n) => n,
            Stream::Tls(t) => &t.get_ref().0,
        }
    }

    /// Still good to hand out again: open, with nothing waiting to be read and no error.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.net().prefix.is_empty() && socket::idle_and_open(&self.net().sock.socket())
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(n) => Pin::new(n).poll_read(cx, buf),
            Stream::Tls(t) => Pin::new(&mut **t).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(n) => Pin::new(n).poll_write(cx, buf),
            Stream::Tls(t) => Pin::new(&mut **t).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(n) => Pin::new(n).poll_flush(cx),
            Stream::Tls(t) => Pin::new(&mut **t).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(n) => Pin::new(n).poll_shutdown(cx),
            Stream::Tls(t) => Pin::new(&mut **t).poll_shutdown(cx),
        }
    }
}

/// How a failed read or write reaches the plugin: a fixed status, no text (I2).
fn io_err(e: &io::Error) -> NeedErr {
    if e.get_ref().is_some_and(|inner| inner.is::<rustls::Error>()) {
        return NeedErr::Tls;
    }
    match e.kind() {
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::NotConnected => NeedErr::Closed,
        io::ErrorKind::TimedOut => NeedErr::Timeout,
        _ => NeedErr::Unavailable,
    }
}

/// One connect, begun and settled on the reactor.
async fn connect_one(
    runtime: &tokio::runtime::Handle,
    dest: &str,
    epoch: u64,
    sock: io::Result<Sock>,
) -> io::Result<Net> {
    let sock = register_on(runtime, sock?)?;
    poll_fn(|cx| socket::poll_connected(&sock, cx)).await?;
    Ok(Net {
        sock,
        logical_dest: dest.into(),
        epoch,
        prefix: Default::default(),
    })
}

/// Connect to the unix socket at `path`, or to the first of `addrs` that answers, within `timeout`
/// in all. Each address gets an equal share of what is left, so one that never answers cannot eat
/// the budget of the ones behind it. Trying the next address of the judged answer is not a retry
/// of anything the plugin sent.
pub(super) async fn connect(
    runtime: &tokio::runtime::Handle,
    dest: &str,
    epoch: u64,
    addrs: &[SocketAddr],
    unix: Option<&str>,
    timeout: Duration,
) -> Result<Net, NeedErr> {
    if let Some(path) = unix {
        #[cfg(unix)]
        return match timeout_on(
            runtime,
            timeout,
            connect_one(
                runtime,
                dest,
                epoch,
                socket::connect_unix(path).map(Sock::Unix),
            ),
        )
        .await
        {
            Ok(Ok(net)) => Ok(net),
            Ok(Err(_)) => Err(NeedErr::Unavailable),
            Err(_) => Err(NeedErr::Timeout),
        };
        #[cfg(not(unix))]
        {
            let _ = (path, timeout);
            return Err(NeedErr::Unavailable);
        }
    }
    if addrs.is_empty() {
        return Err(NeedErr::Invalid);
    }
    let end = Instant::now() + timeout;
    let mut failed = NeedErr::Unavailable;
    for (i, addr) in addrs.iter().enumerate() {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(NeedErr::Timeout);
        }
        let share = left / u32::try_from(addrs.len() - i).unwrap_or(1).max(1);
        match timeout_on(
            runtime,
            share,
            connect_one(runtime, dest, epoch, socket::connect(*addr).map(Sock::Tcp)),
        )
        .await
        {
            Ok(Ok(net)) => return Ok(net),
            Ok(Err(_)) => failed = NeedErr::Unavailable,
            Err(_) => failed = NeedErr::Timeout,
        }
    }
    Err(failed)
}

/// The name a handshake checks: the SNI when there is one, else the peer's address.
fn server_name(sni: &str, peer: Option<IpAddr>) -> Result<ServerName<'static>, NeedErr> {
    if !sni.is_empty() {
        return ServerName::try_from(sni.to_owned()).map_err(|_| NeedErr::Invalid);
    }
    peer.map(|ip| ServerName::IpAddress(ip.into()))
        .ok_or(NeedErr::Invalid)
}

/// The TLS handshake over `net`, and what it negotiated.
pub(super) async fn handshake(
    net: Net,
    config: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
) -> Result<Dialled<Stream>, NeedErr> {
    let tls = TlsConnector::from(config)
        .connect(name, net)
        .await
        .map_err(|_| NeedErr::Tls)?;
    let (_, conn) = tls.get_ref();
    let alpn: Box<str> = conn
        .alpn_protocol()
        .and_then(|a| std::str::from_utf8(a).ok())
        .unwrap_or("")
        .into();
    let resumed = matches!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed));
    Ok(Dialled {
        conn: Stream::Tls(Box::new(tls)),
        alpn,
        resumed,
    })
}

/// The production I/O, retaining one complete immutable network owner.
#[derive(Clone)]
pub struct ConnectorIo {
    state: Arc<super::network::State>,
}

impl ConnectorIo {
    pub(super) fn from_state(state: Arc<super::network::State>) -> Self {
        Self { state }
    }

    pub(super) fn configs(&self) -> &Configs {
        &self.state.configs
    }

    pub(super) fn runtime(&self) -> &tokio::runtime::Handle {
        &self.state.runtime
    }

    /// Connect one previously admitted route. OPEN and FETCH share this exact path.
    pub(super) async fn connect_route(
        &self,
        dest: &str,
        route: &super::judge::Route,
        unix: Option<&str>,
        timeout: Duration,
    ) -> Result<Net, NeedErr> {
        let epoch = self.state.configs.epoch();
        let operation = async {
            let mut net = connect(self.runtime(), dest, epoch, &route.addrs, unix, timeout).await?;
            if let Some(tunnel) = &route.tunnel {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let request = busbar_contract::secure::SecureVec::from(
                    crate::proxy::connect_request(&tunnel.target, &tunnel.hop),
                );
                net.write_all(request.as_slice())
                    .await
                    .map_err(|error| io_err(&error))?;
                net.flush().await.map_err(|error| io_err(&error))?;
                let mut head = busbar_contract::secure::SecureVec::default();
                loop {
                    let mut bytes = [0; 1024];
                    let n = net.read(&mut bytes).await.map_err(|error| io_err(&error))?;
                    if n == 0 {
                        return Err(NeedErr::Closed);
                    }
                    head.extend_from_slice(&bytes[..n]);
                    if let Some(end) = crate::proxy::connect_answer(head.as_slice(), &tunnel.target)
                        .map_err(|_| NeedErr::Denied)?
                    {
                        if end > crate::proxy::CONNECT_HEAD_CAP {
                            return Err(NeedErr::Limit);
                        }
                        head.consume(end);
                        net.prefix = head;
                        break;
                    }
                }
            }
            Ok(net)
        };
        timeout_on(self.runtime(), timeout, operation)
            .await
            .map_err(|_| NeedErr::Timeout)?
    }

    pub(super) async fn secure(
        &self,
        net: Net,
        plan: &TlsPlan<'_>,
        offered: &[Vec<u8>],
        timeout: Duration,
    ) -> Result<Dialled<Stream>, NeedErr> {
        let name = server_name(plan.sni, net.peer_ip())?;
        let host = net.logical_dest.clone();
        let result = async {
            let config = self.configs().get(&host, plan, offered)?;
            handshake(net, config, name).await
        };
        let result = timeout_on(self.runtime(), timeout, result)
            .await
            .map_err(|_| NeedErr::Timeout)?;
        if matches!(result, Err(NeedErr::Tls)) {
            self.state
                .observations
                .record(&host, None, None, super::observations::Outcome::Tls);
        }
        result
    }
}

impl NeedIo for ConnectorIo {
    type Conn = Stream;

    async fn timeout<F: std::future::Future + Send>(
        &self,
        duration: Duration,
        future: F,
    ) -> Result<F::Output, NeedErr> {
        timeout_on(self.runtime(), duration, future)
            .await
            .map_err(|_| NeedErr::Timeout)
    }

    async fn dial(&self, d: Dial<'_>) -> Result<Dialled<Stream>, NeedErr> {
        let end = Instant::now() + d.timeout;
        let net = self
            .connect_route(d.dest, &d.route, d.unix, d.timeout)
            .await?;
        let Some(plan) = d.tls else {
            return Ok(Dialled {
                conn: Stream::Plain(net),
                alpn: "".into(),
                resumed: false,
            });
        };
        let alpn = if plan.alpn.is_empty() {
            Vec::new()
        } else {
            vec![plan.alpn.as_bytes().to_vec()]
        };
        self.secure(
            net,
            &plan,
            &alpn,
            end.saturating_duration_since(Instant::now()),
        )
        .await
    }

    async fn upgrade(
        &self,
        conn: Stream,
        tls: TlsPlan<'_>,
        timeout: Duration,
    ) -> Result<Dialled<Stream>, NeedErr> {
        let Stream::Plain(net) = conn else {
            return Err(NeedErr::Invalid);
        };
        let alpn = if tls.alpn.is_empty() {
            Vec::new()
        } else {
            vec![tls.alpn.as_bytes().to_vec()]
        };
        self.secure(net, &tls, &alpn, timeout).await
    }

    async fn write(
        &self,
        conn: &mut Stream,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<usize, NeedErr> {
        let sent = async {
            let n = poll_fn(|cx| Pin::new(&mut *conn).poll_write(cx, bytes))
                .await
                .map_err(|e| io_err(&e))?;
            poll_fn(|cx| Pin::new(&mut *conn).poll_flush(cx))
                .await
                .map_err(|e| io_err(&e))?;
            Ok::<usize, NeedErr>(n)
        };
        timeout_on(self.runtime(), timeout, sent)
            .await
            .map_err(|_| NeedErr::Timeout)?
    }

    async fn read(
        &self,
        conn: &mut Stream,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, NeedErr> {
        let got = poll_fn(|cx| {
            let mut dst = ReadBuf::new(&mut *buf);
            match Pin::new(&mut *conn).poll_read(cx, &mut dst) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(dst.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        });
        timeout_on(self.runtime(), timeout, got)
            .await
            .map_err(|_| NeedErr::Timeout)?
            .map_err(|e| io_err(&e))
    }

    fn healthy(&self, conn: &Stream) -> bool {
        conn.net().epoch == self.configs().epoch() && conn.healthy()
    }

    async fn fetch(
        &self,
        req: FetchReq<'_>,
        admission: &dyn Admission,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        exchange::fetch(self, req, admission, res).await
    }
}

#[cfg(test)]
pub(crate) fn test_io() -> ConnectorIo {
    let trust = Arc::new(
        crate::tls::store::TrustStore::build(
            &Default::default(),
            std::time::SystemTime::now(),
            &|_| None,
        )
        .expect("test trust"),
    );
    super::network::BootstrapConnector::new(super::network::NetworkInputs {
        runtime: tokio::runtime::Handle::current(),
        guard: crate::guard::Guard::default().freeze(),
        resolver: Arc::new(crate::guard::SystemResolver),
        trust,
        proxy: None,
        resolution: busbar_kernel::config::tls::ProxyResolution::Local,
        observations: Arc::default(),
    })
    .io()
}

#[cfg(test)]
#[path = "../tests/need_net_tests.rs"]
mod tests;
