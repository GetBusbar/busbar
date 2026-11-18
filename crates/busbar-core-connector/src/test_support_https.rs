// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A small HTTP(S) test client: hyper's HTTP/1.1 client connection over a TCP socket, wrapped with
//! tokio-rustls when the URL is `https` and the client was given a TLS config.
//!
//! The TLS config comes from the crypto seam (`busbar_contract::crypto::tls::client_config`, or
//! this crate's `tls::client::build_client_config`). So a suite that speaks TLS needs no TLS
//! feature on reqwest. reqwest's built-in TLS brings its own provider (ring), a second crypto
//! backend (ARC-6; DES dist-test-tls-without-ring, after f75d30b031).
//!
//! The surface is the part of reqwest's that the suites use, under the same names:
//! - `get`/`post`/`request`, then `header`, `query`, `form`, `json`, `bearer_auth`, `send`;
//! - the response's `status`, `headers`, `text`, `bytes`, and the TLS peer's leaf certificate.
//!
//! What it does on purpose:
//! - one connection per request; no pool, no cookies, no proxy;
//! - **no redirect is followed** (a 3xx is the answer, as with reqwest's `Policy::none()`);
//! - the response body is read whole before `send` returns;
//! - default headers are `Host` and `Accept: */*`, as reqwest sends.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};

/// A failed exchange: a bad URL or header, a refused connection, a failed TLS handshake (an unknown
/// CA, a wrong pin, a missing client certificate), a broken HTTP exchange, or the timeout.
#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn error(what: &str, cause: impl fmt::Display) -> Error {
    Error(format!("{what}: {cause}"))
}

/// The client: an optional TLS config for `https` URLs and an optional whole-exchange timeout.
/// Cloning is cheap.
#[derive(Clone)]
pub struct Client {
    tls: Option<tokio_rustls::TlsConnector>,
    timeout: Option<Duration>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("tls", &self.tls.is_some())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Client {
    /// A client that speaks `https` with `config` (built through the crypto seam) and `http` in
    /// the clear.
    #[must_use]
    pub fn new(config: rustls::ClientConfig) -> Self {
        Self {
            tls: Some(tokio_rustls::TlsConnector::from(Arc::new(config))),
            timeout: None,
        }
    }

    /// A client for `http` URLs only; an `https` URL is an error.
    #[must_use]
    pub fn plain() -> Self {
        Self {
            tls: None,
            timeout: None,
        }
    }

    /// Bound each whole exchange (connect, handshake, request, body) by `timeout`.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// A `GET` of `url`.
    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    /// A `POST` to `url`.
    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    /// A `method` request to `url`.
    pub fn request(&self, method: Method, url: impl AsRef<str>) -> RequestBuilder {
        let (url, failed) = match url::Url::parse(url.as_ref()) {
            Ok(url) => (Some(url), None),
            Err(e) => (None, Some(error("invalid URL", e))),
        };
        RequestBuilder {
            client: self.clone(),
            method,
            url,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            failed,
        }
    }
}

/// One request being built; [`RequestBuilder::send`] runs it.
#[derive(Debug)]
pub struct RequestBuilder {
    client: Client,
    method: Method,
    url: Option<url::Url>,
    headers: HeaderMap,
    body: Bytes,
    failed: Option<Error>,
}

impl RequestBuilder {
    /// Add a header (appended: a repeated name is sent repeated).
    #[must_use]
    pub fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        K::Error: fmt::Display,
        V: TryInto<HeaderValue>,
        V::Error: fmt::Display,
    {
        if self.failed.is_none() {
            match (name.try_into(), value.try_into()) {
                (Ok(name), Ok(value)) => {
                    self.headers.append(name, value);
                }
                (Err(e), _) => self.failed = Some(error("invalid header name", e)),
                (_, Err(e)) => self.failed = Some(error("invalid header value", e)),
            }
        }
        self
    }

    /// `Authorization: Bearer <token>`.
    #[must_use]
    pub fn bearer_auth(self, token: impl fmt::Display) -> Self {
        self.header(header::AUTHORIZATION, format!("Bearer {token}"))
    }

    /// Append `pairs` to the URL's query, form-encoded.
    #[must_use]
    pub fn query<K: AsRef<str>, V: AsRef<str>>(mut self, pairs: &[(K, V)]) -> Self {
        if let Some(url) = self.url.as_mut() {
            let mut query = url.query_pairs_mut();
            for (k, v) in pairs {
                query.append_pair(k.as_ref(), v.as_ref());
            }
        }
        self
    }

    /// An `application/x-www-form-urlencoded` body of `pairs`.
    #[must_use]
    pub fn form<K: AsRef<str>, V: AsRef<str>>(self, pairs: &[(K, V)]) -> Self {
        let mut body = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            body.append_pair(k.as_ref(), v.as_ref());
        }
        let mut this = self.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        this.body = Bytes::from(body.finish());
        this
    }

    /// An `application/json` body: `document` as its JSON text (any JSON value type whose
    /// `Display` is its JSON, such as the facade's `json::Value`).
    #[must_use]
    pub fn json<T: fmt::Display + ?Sized>(self, document: &T) -> Self {
        let mut this = self.header(header::CONTENT_TYPE, "application/json");
        this.body = Bytes::from(document.to_string());
        this
    }

    /// Run the exchange and read the whole response.
    ///
    /// # Errors
    /// Any [`Error`]: the request could not be built, sent or answered, or the timeout passed.
    pub async fn send(self) -> Result<Response, Error> {
        match self.client.timeout {
            Some(limit) => tokio::time::timeout(limit, self.exchange())
                .await
                .map_err(|_| Error(format!("no answer within {limit:?}")))?,
            None => self.exchange().await,
        }
    }

    async fn exchange(self) -> Result<Response, Error> {
        if let Some(failed) = self.failed {
            return Err(failed);
        }
        let url = self.url.ok_or_else(|| Error("no URL".into()))?;
        let host = url
            .host_str()
            .ok_or_else(|| Error(format!("{url} names no host")))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error(format!("{url} names no port")))?;
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let target = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        let mut request = http::Request::builder()
            .method(self.method)
            .uri(target)
            .body(Full::new(self.body))
            .map_err(|e| error("invalid request", e))?;
        let headers = request.headers_mut();
        if !self.headers.contains_key(header::HOST) {
            headers.insert(
                header::HOST,
                HeaderValue::from_str(&authority).map_err(|e| error("invalid host", e))?,
            );
        }
        if !self.headers.contains_key(header::ACCEPT) {
            headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        }
        for (name, value) in &self.headers {
            headers.append(name.clone(), value.clone());
        }

        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let tcp = tokio::net::TcpStream::connect((bare, port))
            .await
            .map_err(|e| error("connect", e))?;
        match url.scheme() {
            "http" => exchange(tcp, request, None).await,
            "https" => {
                let tls = self
                    .client
                    .tls
                    .as_ref()
                    .ok_or_else(|| Error("an https URL needs Client::new(config)".into()))?;
                let name = ServerName::try_from(bare.to_owned())
                    .map_err(|e| error("invalid server name", e))?;
                let stream = tls
                    .connect(name, tcp)
                    .await
                    .map_err(|e| error("TLS handshake", e))?;
                let leaf = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .map(|leaf| leaf.as_ref().to_vec());
                exchange(stream, request, leaf).await
            }
            other => Err(Error(format!("unsupported scheme {other}"))),
        }
    }
}

/// One HTTP/1.1 exchange on `io`, the connection driven beside it until the body is read.
async fn exchange<S>(
    io: S,
    request: http::Request<Full<Bytes>>,
    peer_certificate: Option<Vec<u8>>,
) -> Result<Response, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| error("HTTP handshake", e))?;
    let driver = tokio::spawn(conn);
    let answered = async {
        let (head, body) = sender
            .send_request(request)
            .await
            .map_err(|e| error("HTTP exchange", e))?
            .into_parts();
        let body = body
            .collect()
            .await
            .map_err(|e| error("response body", e))?
            .to_bytes();
        Ok::<_, Error>((head, body))
    };
    let answered = answered.await;
    driver.abort();
    let (head, body) = answered?;
    Ok(Response {
        status: head.status,
        headers: head.headers,
        body,
        peer_certificate,
    })
}

/// A whole response.
#[derive(Debug)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    peer_certificate: Option<Vec<u8>>,
}

impl Response {
    /// The status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The TLS peer's leaf certificate (DER), on an `https` exchange.
    #[must_use]
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_deref()
    }

    /// The body as UTF-8 text.
    ///
    /// # Errors
    /// The body is not UTF-8.
    pub async fn text(self) -> Result<String, Error> {
        String::from_utf8(Vec::from(self.body)).map_err(|e| error("response body is not UTF-8", e))
    }

    /// The body.
    ///
    /// # Errors
    /// None today; the `Result` keeps reqwest's shape.
    pub async fn bytes(self) -> Result<Bytes, Error> {
        Ok(self.body)
    }
}
