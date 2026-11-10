// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared request-signing and credential-presentation descriptors.

/// Per-request signing context. Most protocols' `auth_headers` ignore this; protocols that
#[derive()]
pub struct SigningContext<'a> {
    /// Upstream host (no scheme), e.g. `runtime.region-1.example.com`. Borrowed from the lane's
    pub host: &'a str,
    /// URI-encoded request path (no query), e.g. `/model/vendor.model%3A0/invoke`. Borrowed (like
    pub canonical_uri: &'a str,
    /// The exact request body bytes that will be sent.
    pub body: &'a [u8],
    /// Unix epoch seconds at signing time.
    pub timestamp_epoch: u64,
    /// The UPSTREAM-credential mode for this request. Lets a writer resolve a credential whose scheme
    pub upstream_creds: crate::config::UpstreamCreds,
}

/// A protocol's declared egress credential-header builder: the resolved per-request credential
pub type EgressAuthHeaders = fn(&str, &SigningContext) -> Vec<(String, Vec<u8>)>;

/// HOW ONE CREDENTIAL IS PRESENTED on an egress request — which header carries it and in what
/// form. Declared data: the kernel's egress-auth unit reads it and writes the header itself, so the
/// credential never has to pass through the plane that declared it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredentialHeader {
    /// `authorization: Bearer <credential>`.
    Bearer,
    /// A custom header (`header`, lowercase) carrying the credential verbatim, or with its leading
    /// whitespace trimmed when `trim_start` is set (a configured key whose family was recognized on
    /// its trimmed text is sent as that text).
    Raw {
        /// The lowercase header name.
        header: &'static str,
        /// Whether leading whitespace is trimmed before the credential is sent.
        trim_start: bool,
    },
}

/// ONE ROW OF A CREDENTIAL-FAMILY TABLE: a credential whose text, leading whitespace trimmed, starts
/// with `prefix` belongs to this family and is presented as `presented_as`. The table is how a
/// dialect that accepts two credential families (a static key in one header, an access token as a
/// bearer) states which is which as data rather than as code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CredentialFamily {
    /// The family's credential prefix.
    pub prefix: &'static str,
    /// How a credential of this family is presented.
    pub presented_as: CredentialHeader,
}

/// A PROTOCOL'S DECLARED EGRESS SCHEME — how busbar presents a lane's credential to this protocol's
/// upstream, as data the kernel's egress-auth unit reads. The plane declares WHICH scheme; the
/// kernel holds the credential and writes (or signs) the headers, so no plane receives a secret.
/// Non-credential static headers a dialect always sends (a version header) are not auth: they are
/// declared separately by the credential owner.
#[derive(Clone, Copy, Debug)]
pub enum EgressScheme {
    /// A static credential, presented by a credential-family table: the first row whose prefix the
    /// credential starts with decides; a credential matching no row is presented by the lane's
    /// credential MODE — `own` for a configured lane key, `passthrough` for a forwarded caller token.
    /// A static scheme is lane-constant: the same credential and mode always present the same bytes.
    Static {
        /// The credential-family table, in precedence order (may be empty).
        families: &'static [CredentialFamily],
        /// How a configured lane key that matches no family is presented.
        own: CredentialHeader,
        /// How a forwarded caller token that matches no family is presented.
        passthrough: CredentialHeader,
    },
    /// A per-request SigV4 signature over the request, the lane credential being
    /// `ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]`. Never lane-constant: it signs the body, the time and
    /// the path.
    SigV4 {
        /// The service name the signature is scoped to.
        service: &'static str,
        /// THE REGION, as a declared pure function of the upstream host (the endpoint names its
        /// region); `None` when the host names none.
        region_of_host: fn(&str) -> Option<&str>,
        /// The region signed for when `region_of_host` finds none.
        default_region: &'static str,
        /// The request content type, which the signature covers beside the host.
        content_type: &'static str,
    },
}

impl EgressScheme {
    /// `authorization: Bearer <credential>` whatever the credential or mode.
    pub const fn bearer() -> Self {
        Self::Static {
            families: &[],
            own: CredentialHeader::Bearer,
            passthrough: CredentialHeader::Bearer,
        }
    }

    /// The credential verbatim in the custom header `header` whatever the credential or mode.
    pub const fn header(header: &'static str) -> Self {
        let raw = CredentialHeader::Raw {
            header,
            trim_start: false,
        };
        Self::Static {
            families: &[],
            own: raw,
            passthrough: raw,
        }
    }
}

impl<'a> std::fmt::Debug for SigningContext<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningContext")
            .field("host", &self.host)
            .field("canonical_uri", &"<redacted>")
            .field("body", &self.body)
            .field("timestamp_epoch", &self.timestamp_epoch)
            .field("upstream_creds", &self.upstream_creds)
            .finish()
    }
}
