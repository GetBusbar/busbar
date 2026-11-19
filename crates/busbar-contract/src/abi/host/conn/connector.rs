// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST CONNECTOR, mechanism-shaped (`BUSBAR-1.6.0.md` THE DESIGN, the connections section):

pub use crate::abi::host::service::{ServiceFn, ServiceHead, ServiceOut};
use crate::abi::mechanism::call::{AbiStr, Blob};

/// [`Need::direction`]: the plugin is reached (it listens).
pub const DIRECTION_INBOUND: u32 = 1;
/// [`Need::direction`]: the plugin reaches out (it dials).
pub const DIRECTION_OUTBOUND: u32 = 2;

/// [`Need::egress_class`]: the connector's default class.
pub const EGRESS_DEFAULT: u32 = 0;
/// [`Need::egress_class`] `provider`: upstreams a plane reaches — the allow-list, and cloud
pub const EGRESS_PROVIDER: u32 = 1;
/// [`Need::egress_class`] `operator-infrastructure`: databases, secret services, directories —
///
/// The class is a property of a CONFIG-DECLARED target, never a plugin's choice: `dest.judge`
/// refuses it (BUSBAR-6014), and a need over a FRAMED transport (`http`, `grpc`) in this class must
/// name its target from config (`target_from`) or it is refused at declaration (BUSBAR-6017). A
/// CARRIER need (`tcp`, `unix`) in this class without `target_from` is DEPRECATED: honoured in
/// 1.6.x, refused from 1.7.0.
pub const EGRESS_OPERATOR_INFRASTRUCTURE: u32 = 2;
/// [`Need::egress_class`] `open-web`: public destinations over a secure connection only.
pub const EGRESS_OPEN_WEB: u32 = 3;
/// [`Need::egress_class`] `loopback-allowed`: a secure connection, or plaintext to loopback; the
pub const EGRESS_LOOPBACK_ALLOWED: u32 = 4;

/// ONE NEED, declared once per direction: which transport claim carries it and which auth style
/// guards it. Opaque bytes to the kernel: the claiming transport validates `details`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Need {
    /// [`DIRECTION_INBOUND`] | [`DIRECTION_OUTBOUND`].
    pub direction: u32,
    /// The egress class the need's destinations are governed under (`EGRESS_*`); `0` = the
    /// connector's default.
    pub egress_class: u32,
    /// The transport claim (a scheme some transport entry claims).
    pub transport: AbiStr,
    /// The auth style (an open string resolved against the styles auth plugins declare); absent =
    /// none.
    pub auth: AbiStr,
    /// Where the target comes from (a config path the host reads); absent = the plugin names it.
    /// A plane's inbound `ingress` need uses its optional `ingress` settings block. When absent,
    /// the host's data listener is inherited; when present, `ingress.listen` selects its socket
    /// and the host validates the full listener block. A malformed block never inherits.
    pub target_from: AbiStr,
    /// Where the trust anchors come from; absent = the host's default. On a member-target need
    /// (`target_from` = `settings.*.<key>`), a member path (`settings.*.<key>`) names, per
    /// registration, the object holding busbar's client identity for it (`{cert, key}`, secret
    /// references); the host seals it, with the registration's far-end key pin (its plane's pin
    /// key, under a mechanism flagged `abi::plane::MECHANISM_PEER_KEY`), into the member's route,
    /// and the connector enforces both on every connection to the member.
    ///
    /// A settings-path `trust_from` holding a CA PEM is DEPRECATED (refused from 1.7.0): the core
    /// trust store replaces it. The client-identity shape `{cert, key}` (the key a sealed secret
    /// reference) and a far-end key pin are RESERVED for every outbound need.
    pub trust_from: AbiStr,
    /// The need's details, validated only by the claiming transport.
    pub details: Blob,
    /// Under [`KEEP_NAMED`]: the far end's RESPONSE head fields the plugin reads (lower-case
    /// names), for an outbound need: the kernel copies ONLY these into the answer's head it hands
    /// the plugin; no other response header ever crosses. Validated at boot: at most
    /// [`KEEP_RESPONSE_HEADERS_MAX`] names, each a lower-case token, none hop-by-hop or
    /// credential-bearing ([`NEVER_KEPT`]). Empty under [`KEEP_ALL_EXCEPT_DENIED`].
    pub keep_response_headers: *const AbiStr,
    /// How many.
    pub keep_response_headers_len: usize,
    /// How long establishing a stream, and each wait for a reply on it, may take, milliseconds;
    /// `0` = the host's default. The host clamps a larger value to the deadline class.
    pub timeout_ms: u64,
    /// How the far end's response head reaches the plugin: [`KEEP_NAMED`] (`0`, the named list
    /// above) or [`KEEP_ALL_EXCEPT_DENIED`] (every field but the kernel's [`ALWAYS_DENIED`] and
    /// the plugin's own [`Need::deny_response_headers`]).
    pub keep_mode: u32,
    /// Alignment padding; `0`.
    pub _reserved: u32,
    /// Under [`KEEP_ALL_EXCEPT_DENIED`]: the response head fields the plugin never reads beyond
    /// [`ALWAYS_DENIED`] (lower-case names, e.g. a far end's echo of the operator's tenant):
    /// at most [`KEEP_RESPONSE_HEADERS_MAX`]. Empty under [`KEEP_NAMED`].
    pub deny_response_headers: *const AbiStr,
    /// How many.
    pub deny_response_headers_len: usize,
}

impl Need {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    pub const ZERO: Self = Self {
        direction: 0,
        egress_class: 0,
        transport: AbiStr::ZERO,
        auth: AbiStr::ZERO,
        target_from: AbiStr::ZERO,
        trust_from: AbiStr::ZERO,
        details: Blob::ZERO,
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: 0,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    };
}

/// HOW THE NEED ROW IS MADE: from [`Need::EMPTY`], its plain fields set directly
impl Need {
    /// Nothing stated: every string absent, every list empty, every number zero.
    pub const EMPTY: Need = Need {
        direction: 0,
        egress_class: 0,
        transport: AbiStr::ABSENT,
        auth: AbiStr::ABSENT,
        target_from: AbiStr::ABSENT,
        trust_from: AbiStr::ABSENT,
        details: Blob::ABSENT,
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: 0,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    };

    abi_lists! {
        keep_response_headers, keep_response_headers_len: AbiStr
            => keep_response_headers_ptr, with_keep_response_headers, with_raw_keep_response_headers;
        deny_response_headers, deny_response_headers_len: AbiStr
            => deny_response_headers_ptr, with_deny_response_headers, with_raw_deny_response_headers;
    }
}

/// [`Need::keep_mode`]: only the fields [`Need::keep_response_headers`] names cross.
pub const KEEP_NAMED: u32 = 0;

/// [`Need::keep_mode`]: every response head field crosses but the kernel's [`ALWAYS_DENIED`] and
pub const KEEP_ALL_EXCEPT_DENIED: u32 = 1;

/// What [`KEEP_ALL_EXCEPT_DENIED`] always strips, the kernel's list: every hop-by-hop field
pub const ALWAYS_DENIED: &[&str] = &["content-length", "content-encoding"];

/// [`keeps_response_field`] over the lists as the caller holds them (`String`s or `&str`s).
#[must_use]
pub fn keeps_response_field_of<'a>(
    mode: u32,
    kept: &[impl AsRef<str>],
    denied: &[impl AsRef<str>],
    name: &str,
    nominated: impl IntoIterator<Item = &'a [u8]>,
) -> bool {
    match mode {
        KEEP_NAMED => kept.iter().any(|k| k.as_ref() == name) && !NEVER_KEPT.contains(&name),
        KEEP_ALL_EXCEPT_DENIED => {
            !(crate::abi::transport::fields::hop_by_hop(name, nominated)
                || ALWAYS_DENIED.contains(&name)
                || denied.iter().any(|d| d.as_ref() == name))
        }
        _ => false,
    }
}

/// The most response head fields one need may keep.
pub const KEEP_RESPONSE_HEADERS_MAX: usize = 32;

/// The response head fields no `KEEP_NAMED` keep list may name: hop-by-hop fields (the connection's, not the
/// message's) and the like. The caller-side request strip uses this set unconditionally;
/// `KEEP_ALL_EXCEPT_DENIED` strips hop-by-hop fields, `ALWAYS_DENIED` and the plugin's deny list instead.
pub const NEVER_KEPT: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "authorization",
    "proxy-authorization",
    "proxy-authenticate",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-amz-security-token",
];

/// The index of each connector service in [`ConnectorSlots`], in table order.
pub mod service {
    /// Establish a stream for a need on the connector lane.
    pub const ESTABLISH: u32 = 0;
    /// Reject the endpoint a stream landed on; the connector tries the next.
    pub const REJECT_ENDPOINT: u32 = 1;
    /// A second stream to the endpoint a stream landed on.
    pub const SIDE_STREAM: u32 = 2;
    /// Read.
    pub const READ: u32 = 3;
    /// Write.
    pub const WRITE: u32 = 4;
    /// Upgrade the stream to connection security, mid-stream.
    pub const UPGRADE_SECURE: u32 = 5;
    /// The stream's facts.
    pub const FACTS: u32 = 6;
    /// Check a pooled stream out for one op.
    pub const CHECKOUT: u32 = 7;
    /// Check it back in.
    pub const CHECKIN: u32 = 8;
    /// Close a stream.
    pub const CLOSE: u32 = 9;
    /// RETIRED: random bytes come from the one random service, the host service `random.fill`
    pub const RANDOM: u32 = 10;
    /// The process identity.
    pub const IDENTITY: u32 = 11;
    /// Read the next piece of the far end's reply to what the plugin sent, with its descriptor.
    pub const READ_REPLY: u32 = 12;
    /// Write one piece of a request on a FRAMED stream, with its descriptor: the framer builds its
    pub const WRITE_REQUEST: u32 = 13;
}

/// How many services [`ConnectorSlots`] holds.
pub const SERVICES: u32 = 14;

/// The separator between the addresses of [`EstablishIn::within`].
pub const WITHIN_SEPARATOR: &str = ",";

/// THE REQUEST FIELD BY WHICH A PLUGIN PINS A REQUEST'S DIAL (SEC-8F1), the request-path twin of
pub const WITHIN_REQUEST_FIELD: &str = "busbar-dial-within";

/// Whether the request field `name` is [`WITHIN_REQUEST_FIELD`] (a field name compares
#[must_use]
pub fn is_within_field(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(WITHIN_REQUEST_FIELD.as_bytes())
}

/// The address set a [`WITHIN_REQUEST_FIELD`] value states: `None` when an entry is not an IP
/// literal (an empty entry included); an empty value is `Some` of an empty set (no pin).
#[must_use]
pub fn within_of(value: &[u8]) -> Option<Vec<std::net::IpAddr>> {
    let text = std::str::from_utf8(value).ok()?;
    if text.trim().is_empty() {
        return Some(Vec::new());
    }
    text.split(WITHIN_SEPARATOR)
        .map(str::trim)
        .map(|a| a.parse().ok())
        .collect()
}

/// `ServiceOut::value` on a failure: the socket's open failed; `error` is the socket's error.
pub const CAUSE_CONNECT: u64 = 1;
/// `ServiceOut::value` on a failure: connection security failed; `error` is its own error.
pub const CAUSE_SECURITY: u64 = 2;
/// `ServiceOut::value` on a failure: the open connection failed; `error` is the socket's error.
pub const CAUSE_EXCHANGE: u64 = 3;
/// `ServiceOut::value` on a failure: a deadline the host keeps passed.
pub const CAUSE_DEADLINE: u64 = 4;
/// `ServiceOut::value` on a failure: the open connection's framer failed it; `error` is its own.
pub const CAUSE_FRAMER: u64 = 5;

/// THE CONNECTOR TABLE: one [`ServiceFn`] per [`service`], in index order. A NULL slot is a
/// service this host does not offer, and a plugin that needs it refuses to open.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnectorSlots {
    /// `size_of::<ConnectorSlots>()`.
    pub size: u32,
    /// [`SERVICES`].
    pub slots: u32,
    /// [`service::ESTABLISH`], in [`EstablishIn`].
    pub establish: Option<ServiceFn>,
    /// [`service::REJECT_ENDPOINT`], in [`StreamIn`].
    pub reject_endpoint: Option<ServiceFn>,
    /// [`service::SIDE_STREAM`], in [`StreamIn`].
    pub side_stream: Option<ServiceFn>,
    /// [`service::READ`], in [`IoIn`].
    pub read: Option<ServiceFn>,
    /// [`service::WRITE`], in [`IoIn`].
    pub write: Option<ServiceFn>,
    /// [`service::UPGRADE_SECURE`], in [`UpgradeIn`].
    pub upgrade_secure: Option<ServiceFn>,
    /// [`service::FACTS`], in [`FactsIn`].
    pub facts: Option<ServiceFn>,
    /// [`service::CHECKOUT`], in [`CheckoutIn`].
    pub checkout: Option<ServiceFn>,
    /// [`service::CHECKIN`], in [`CheckinIn`].
    pub checkin: Option<ServiceFn>,
    /// [`service::CLOSE`], in [`StreamIn`].
    pub close: Option<ServiceFn>,
    /// [`service::RANDOM`], in [`RandomIn`]: RETIRED, always NULL (`random.fill` is the one random
    /// service).
    pub random: Option<ServiceFn>,
    /// [`service::IDENTITY`], in [`IdentityIn`].
    pub identity: Option<ServiceFn>,
    /// [`service::READ_REPLY`], in [`ReplyIn`].
    pub read_reply: Option<ServiceFn>,
    /// [`service::WRITE_REQUEST`], in [`RequestIn`].
    pub write_request: Option<ServiceFn>,
}
