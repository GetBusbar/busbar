// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER (SDK-SAFE-TEST-HOST §10.2, §12.2): declared only, so the red tests compile. The fix
//! commit builds it on hyper and hyper-util.
#![forbid(unsafe_code)]

use std::net::SocketAddr;

use hyper::body::{Body as HttpBody, Bytes};
use hyper::client::conn::{http1, http2};
use hyper::{Method, Version};

use super::{Binding, Caller, Listening, Refused, Subject};

/// The largest request head the carrier takes.
pub const HEAD_MAX: usize = 64 * 1024;

/// A route's handler.
pub trait Route: Send + Sync + 'static {
    /// Answers `req`.
    fn answer(&self, req: Request) -> Reply;
}

impl<F: Fn(Request) -> Reply + Send + Sync + 'static> Route for F {
    fn answer(&self, req: Request) -> Reply {
        self(req)
    }
}

/// One request, as a route sees it.
pub struct Request;

impl Request {
    /// The image whose listener took it.
    #[must_use]
    pub fn image(&self) -> &'static str {
        todo!("T1a")
    }

    /// The method.
    #[must_use]
    pub fn verb(&self) -> &Method {
        todo!("T1a")
    }

    /// The path.
    #[must_use]
    pub fn path(&self) -> &str {
        todo!("T1a")
    }

    /// The HTTP version.
    #[must_use]
    pub fn version(&self) -> Version {
        todo!("T1a")
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        todo!("T1a")
    }

    /// The driver's caller, if any.
    #[must_use]
    pub fn caller(&self) -> Option<&Caller> {
        todo!("T1a")
    }
}

/// A route's answer.
pub struct Reply;

impl Reply {
    /// `200` with `body`.
    #[must_use]
    pub fn ok(_body: impl Into<Bytes>) -> Self {
        todo!("T1a")
    }

    /// `code` with `body`.
    #[must_use]
    pub fn status(_code: u16, _body: impl Into<Bytes>) -> Self {
        todo!("T1a")
    }

    /// `code` with a streamed body.
    #[must_use]
    pub fn stream(_code: u16) -> (Self, Pieces) {
        todo!("T1a")
    }

    /// Not served by the host target.
    #[must_use]
    pub fn unserved(_what: &str) -> Self {
        todo!("T1a")
    }

    /// Adds a header.
    #[must_use]
    pub fn header(self, _name: &str, _value: &str) -> Self {
        todo!("T1a")
    }
}

/// The sending end of a streamed answer.
pub struct Pieces;

/// The client has gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gone;

impl Pieces {
    /// Sends one piece.
    ///
    /// # Errors
    /// Never yet.
    pub fn send(&self, _piece: impl Into<Bytes>) -> Result<(), Gone> {
        todo!("T1a")
    }
}

/// The route table.
#[derive(Default)]
pub struct Routes;

impl Routes {
    /// No routes yet.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Mounts `f` for `verb` on `path`.
    #[must_use]
    pub fn route(self, _verb: &str, _path: &str, _f: impl Route) -> Self {
        self
    }
}

impl Subject for Routes {
    fn bind(&mut self, _image: &'static str, _at: &Binding<'_>) -> Result<Listening, Refused> {
        todo!("T1a")
    }
}

/// Why a dial was refused or failed.
#[derive(Debug)]
pub enum Dial {
    /// Not loopback.
    NotLoopback(SocketAddr),
}

/// Dials `addr` over HTTP/1.1.
///
/// # Errors
/// Never yet.
pub async fn dial_h1<B>(_addr: SocketAddr) -> Result<http1::SendRequest<B>, Dial>
where
    B: HttpBody + Send + 'static,
{
    todo!("T1a")
}

/// Dials `addr` with h2c prior knowledge.
///
/// # Errors
/// Never yet.
pub async fn dial_h2<B>(_addr: SocketAddr) -> Result<http2::SendRequest<B>, Dial>
where
    B: HttpBody + Send + Unpin + 'static,
{
    todo!("T1a")
}
