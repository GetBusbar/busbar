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
use crate::io::{register, Direction, Registered};
use crate::socket::{self, Sock};

/// A dialled socket on the reactor, as a tokio byte stream.
#[derive(Debug)]
pub struct Net {
    sock: Registered<Sock>,
}

impl Net {
    fn peer_ip(&self) -> Option<IpAddr> {
        self.sock.get_ref().peer_ip()
    }
}

impl AsyncRead for Net {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let dst = buf.initialize_unfilled();
        if dst.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let want = dst.len();
        let n = std::task::ready!(self.sock.poll_io_sized(Direction::Read, want, cx, |s| {
            let mut r: &Sock = s;
            r.read(&mut *dst)
        }))?;
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
            .poll_io_sized(Direction::Write, buf.len(), cx, |s| {
                let mut w: &Sock = s;
                w.write(buf)
            })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.sock.get_ref().shutdown(Shutdown::Write) {
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
    fn sock(&self) -> &Sock {
        match self {
            Stream::Plain(n) => n.sock.get_ref(),
            Stream::Tls(t) => t.get_ref().0.sock.get_ref(),
        }
    }

    /// Still good to hand out again: open, with nothing waiting to be read and no error.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.sock().idle_and_open()
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
async fn connect_one(sock: io::Result<Sock>) -> io::Result<Net> {
    let sock = register(sock?)?;
    poll_fn(|cx| socket::poll_connected(&sock, cx)).await?;
    Ok(Net { sock })
}

/// Connect to the unix socket at `path`, or to the first of `addrs` that answers, within `timeout`
/// in all. Each address gets an equal share of what is left, so one that never answers cannot eat
/// the budget of the ones behind it. Trying the next address of the judged answer is not a retry
/// of anything the plugin sent.
pub(super) async fn connect(
    addrs: &[SocketAddr],
    unix: Option<&str>,
    timeout: Duration,
) -> Result<Net, NeedErr> {
    if let Some(path) = unix {
        #[cfg(unix)]
        return match tokio::time::timeout(
            timeout,
            connect_one(socket::connect_unix(path).map(Sock::Unix)),
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
        match tokio::time::timeout(share, connect_one(socket::connect(*addr).map(Sock::Tcp))).await
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

/// The production I/O: sockets, TLS and HTTP, over what the connector already has.
#[derive(Debug, Default)]
pub struct ConnectorIo {
    configs: Configs,
}

impl ConnectorIo {
    /// The I/O seam over the process's reactor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn configs(&self) -> &Configs {
        &self.configs
    }

    async fn secure(
        &self,
        net: Net,
        plan: &TlsPlan<'_>,
        timeout: Duration,
    ) -> Result<Dialled<Stream>, NeedErr> {
        let name = server_name(plan.sni, net.peer_ip())?;
        let alpn = if plan.alpn.is_empty() {
            Vec::new()
        } else {
            vec![plan.alpn.as_bytes().to_vec()]
        };
        let config = self.configs.get(plan, &alpn)?;
        tokio::time::timeout(timeout, handshake(net, config, name))
            .await
            .map_err(|_| NeedErr::Timeout)?
    }
}

impl NeedIo for ConnectorIo {
    type Conn = Stream;

    async fn dial(&self, d: Dial<'_>) -> Result<Dialled<Stream>, NeedErr> {
        let end = Instant::now() + d.timeout;
        let net = connect(d.addrs, d.unix, d.timeout).await?;
        let Some(plan) = d.tls else {
            return Ok(Dialled {
                conn: Stream::Plain(net),
                alpn: "".into(),
                resumed: false,
            });
        };
        self.secure(net, &plan, end.saturating_duration_since(Instant::now()))
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
        self.secure(net, &tls, timeout).await
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
        tokio::time::timeout(timeout, sent)
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
        tokio::time::timeout(timeout, got)
            .await
            .map_err(|_| NeedErr::Timeout)?
            .map_err(|e| io_err(&e))
    }

    fn healthy(&self, conn: &Stream) -> bool {
        conn.healthy()
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
#[path = "../tests/need_net_tests.rs"]
mod tests;
