// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S ABI (v4; design B.3, plus the provisioning `serve` slot): its version, its table, its Statement tail, its cancel

use super::mechanism::call::{AbiStr, Op};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

mod check;
mod inbound;
mod outbound;
mod points;
mod serve;

pub use check::{check_points, check_target};

pub use inbound::{IdentifyOut, IdentityBuf, IdentityOut, LoginField};
pub use outbound::{TargetIn, TargetOut};
pub use points::{AuthPoint, AuthPoints, POINT_FRAME, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
pub use serve::{ServeIn, ServeOut};

/// The auth kind's ABI version: v1.5.5 shipped `2` (`AUTH_ABI_VERSION`), so 1.6.0 ships `3`.
pub const ABI_VERSION: u32 = super::versions::AUTH.raw();

/// [`InHead::op`](super::mechanism::call::InHead) of each auth op: kind op `k` is at slot
/// [`LIFECYCLE_SLOTS`]` + k`, contiguous, in [`Ops`] field order.
///
/// ```
/// use busbar_contract::abi::auth::{slot, Ops, KIND_SLOTS, SLOTS};
/// use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
/// use std::mem::{offset_of, size_of};
/// let order = [
///     (slot::VERIFY, offset_of!(Ops, verify)),
///     (slot::BEGIN_LOGIN, offset_of!(Ops, begin_login)),
///     (slot::COMPLETE_LOGIN, offset_of!(Ops, complete_login)),
///     (slot::OPEN_OUTBOUND, offset_of!(Ops, open_outbound)),
///     (slot::OUTBOUND_READY, offset_of!(Ops, outbound_ready)),
///     (slot::FIELDS, offset_of!(Ops, fields)),
///     (slot::TARGET, offset_of!(Ops, target)),
///     (slot::SERVE, offset_of!(Ops, serve)),
/// ];
/// assert_eq!(order.len() as u32, KIND_SLOTS);
/// for (k, (idx, off)) in order.into_iter().enumerate() {
///     assert_eq!(idx, LIFECYCLE_SLOTS + k as u32);
///     // OpsHead's `size` + `slots` (8 bytes), then one 8-byte slot per index.
///     assert_eq!(off, 8 + 8 * idx as usize);
/// }
/// assert_eq!(SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
/// assert_eq!(size_of::<Ops>(), 8 + 8 * SLOTS as usize);
/// ```
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// `verify`.
    pub const VERIFY: u32 = LIFECYCLE_SLOTS;
    /// `begin_login`.
    pub const BEGIN_LOGIN: u32 = LIFECYCLE_SLOTS + 1;
    /// `complete_login`.
    pub const COMPLETE_LOGIN: u32 = LIFECYCLE_SLOTS + 2;
    /// `open_outbound`.
    pub const OPEN_OUTBOUND: u32 = LIFECYCLE_SLOTS + 3;
    /// `outbound_ready`.
    pub const OUTBOUND_READY: u32 = LIFECYCLE_SLOTS + 4;
    /// `fields`.
    pub const FIELDS: u32 = LIFECYCLE_SLOTS + 5;
    /// `target`.
    pub const TARGET: u32 = LIFECYCLE_SLOTS + 6;
    /// `serve` (auth v4).
    pub const SERVE: u32 = LIFECYCLE_SLOTS + 7;
}

/// How many kind ops follow the lifecycle.
pub const KIND_SLOTS: u32 = 8;
/// [`OpsHead::slots`] for auth v4.
pub const SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// The auth kind's ops table: the shared [`OpsHead`], then the kind's slots, contiguous.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle. `refresh` also drops the plugin's inbound cache (the admin flush).
    pub head: OpsHead,
    /// Judge an inbound request at one AUTH POINT ([`VerifyIn::point`]; THE DESIGN, "Auth
    /// points and guest lists": the inbound point call reuses this slot). REQUEST-PATH; may pend
    /// (a key-set fetch or a directory read over the plugin's need);
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass). In [`VerifyIn`] (fixed
    /// 320 B, plus the line, peer and body bytes), out [`IdentifyOut`] (fixed 232 B; results in
    /// the host's [`IdentityBuf`], [`IDENTITY_BUF_BYTES`] and [`IDENTITY_GROUPS`] to start, and its
    /// strip array, [`FIELDS_MAX`] to start). The verdict is [`VERDICT_IDENTITY`],
    /// [`VERDICT_REJECT`] or [`VERDICT_PASS`]; the decision is [`DECISION_CONTINUE`] or
    /// [`DECISION_STOP`]; the credential lines to strip are named whatever the verdict. The
    /// transport receives only the decision and the strips; the verdict, the identity and the
    /// credential go to the kernel. OVERLOAD: when the instance's `max_inflight` is full, the host does not
    /// queue the call and answers the request 503 (an accepted difference from 1.5.5). The plugin
    /// never signals overload itself.
    pub verify: Option<Op>,
    /// Start a login. OFF-PATH; may pend through the plugin's own need; `Call`. In
    /// [`BeginLoginIn`] (fixed 168 B), out [`BeginLoginOut`] (fixed 136 B; URL and form held under
    /// `OutHead.lease`).
    pub begin_login: Option<Op>,
    /// Finish a login: the token exchange runs over the plugin's own need to its need-declared
    /// targets. OFF-PATH; may pend; `Call`. In [`CompleteLoginIn`] (fixed 232 B), out
    /// [`IdentifyOut`] (fixed 232 B; host [`IdentityBuf`]). The verdict is [`LOGIN_IDENTITY`],
    /// [`LOGIN_BAD_CREDENTIAL`], [`LOGIN_OUTAGE`] or [`LOGIN_SECURITY_CHECK_FAILED`].
    pub complete_login: Option<Op>,
    /// Bind one outbound style to its credential and answer a handle. OFF-PATH, at generation
    /// seal; never pends (the first mint runs in the background on `tick`); `Call`. In
    /// [`OpenOutboundIn`] (fixed 152 B), out [`OpenOutboundOut`] (fixed 104 B). A handle is
    /// GENERATION DATA: the kernel re-opens every handle at each generation, and a handle is valid
    /// until `retire` of the generation it was opened at. There is no close slot. The token cache
    /// behind a handle is keyed by (style, credential, settings) and outlives it.
    pub open_outbound: Option<Op>,
    /// The handle's `ready` fact, read by the health prober. OFF-PATH; never pends; `Call`. In
    /// [`OutboundReadyIn`] (fixed 96 B), out [`OutboundReadyOut`] (fixed 104 B).
    pub outbound_ready: Option<Op>,
    /// The per-attempt call the kernel makes before encode: the auth fields for this request.
    /// REQUEST-PATH; may pend only when the cached token has expired and its refresh failed
    /// (the design's expired-token rule, Q-EXPIRED), bounded by the attempt's deadline; `Call`.
    /// Called at the style's AUTH POINTS ([`FieldsIn::point`]; THE DESIGN, "Auth points and
    /// guest lists", step 5): the host REPLACES the plane's lines of the same name with the fields
    /// answered and adds nothing to the head after them; REFUSED or FAILED stops the request.
    /// In [`FieldsIn`] (fixed 288 B), out [`FieldsOut`] (fixed 112 B; fields in the host's
    /// buffer, [`FIELDS_BUF_BYTES`] and [`FIELDS_MAX`] to start; one re-call when short). READY
    /// with zero fields = no auth header, so the upstream answers 401: 1.5.5's answer before the
    /// first mint and for an un-encodable key.
    pub fields: Option<Op>,
    /// The destination one outbound style's credential sends to, for the kernel to judge (the
    /// need's target is the kernel's to judge, THE DESIGN's needs section): PURE (no I/O, never dials, reads
    /// only the credential and settings it is handed), called with NO instance (the `instance`
    /// argument is NULL) at config time and at the generation seal, never pends; `Call`. In
    /// [`TargetIn`] (fixed 168 B), out [`TargetOut`] (fixed 104 B). READY with a present
    /// [`TargetOut::target`]: the URL, in the host's buffer. READY with it absent: the style sends
    /// to no destination of its own. FAILED: why, one line in `head.error` (in the host's buffer),
    /// rendered verbatim. REFUSED: the plugin does not serve `target` (the SDK's answer for a door
    /// that wires none): the style names no destination.
    pub target: Option<Op>,
    /// THE PROVISIONING MOUNT (auth v4): one HTTP request under `/provision/<instance>/*`, from a
    /// client the kernel ALREADY authenticated with this instance's own `verify` and found in the
    /// instance's `provisioning.clients` allow-list. OFF-PATH; may pend (on `directory.*`);
    /// `Call`. In [`ServeIn`] (the hook kind's `ServeIn`, byte for byte, plus the appended
    /// [`ServeIn::client`]), out [`ServeOut`] (the hook kind's; headers and body under
    /// `head.lease`, memory class iv). The kernel never forwards `Authorization` or any of the
    /// instance's carrier fields, and calls `serve` only on an instance stating
    /// [`CAP_PROVISION`]. NULL: the plugin serves no routes (every plugin without
    /// [`CAP_PROVISION`]).
    pub serve: Option<Op>,
}

/// [`StyleDecl::flags`]: `fields` needs [`FieldsIn::headers`], the exact envelope, for this style.
pub const STYLE_NEEDS_HEADERS: u32 = 2;
/// [`StyleDecl::flags`]: the style sends the credential to the provider entry's token endpoint.
pub const STYLE_ENDPOINT_TOKEN_URL: u32 = 32;
/// [`StyleDecl::flags`]: the style takes its token endpoint from the credential itself.
pub const STYLE_ENDPOINT_FROM_CREDENTIAL: u32 = 64;
/// [`StyleDecl::flags`]: the lowest bit of the style's LIST RANK ([`STYLE_RANK_MASK`]).
pub const STYLE_RANK_SHIFT: u32 = 16;

/// The [`StyleDecl::flags`] bits stating list rank `rank` ([`STYLE_RANK_MASK`]).
#[must_use]
pub const fn ranked(rank: u8) -> u32 {
    (rank as u32) << STYLE_RANK_SHIFT
}

/// One outbound style a plugin serves: an open string the provider's `auth:` resolves against.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StyleDecl {
    /// The style name.
    pub name: AbiStr,
    /// [`STYLE_NEEDS_HEADERS`] | [`STYLE_CALLER_CREDENTIAL`] | [`STYLE_ENDPOINT_TOKEN_URL`] |
    /// [`STYLE_ENDPOINT_FROM_CREDENTIAL`], and a list rank ([`STYLE_RANK_MASK`]).
    pub flags: u32,
    /// The [`AuthPoints`] the style needs: a valid, non-empty set ([`check_style_decl`]). A style
    /// that signs the body needs [`POINT_HEAD_BODY`] and reads [`FieldsIn::body`]; a style over
    /// the head alone needs [`POINT_HEAD`].
    pub points: u32,
}

impl StyleDecl {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    pub const ZERO: Self = Self {
        name: AbiStr::ZERO,
        flags: 0,
        points: 0,
    };
}

/// THE AUTH STATEMENT TAIL: `Statement.kind_tail` of an auth plugin. Plain `'static` data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuthTail {
    /// The tail head (`size` = `size_of::<AuthTail>()`).
    pub head: KindTailHead,
    /// [`CAP_INBOUND`] | [`CAP_LOGIN`] | [`CAP_OUTBOUND`].
    pub caps: u32,
    /// [`FACT_CACHEABLE`] | [`FACT_INBOUND_NEEDS_BODY_HASH`] | [`FACT_INBOUND_ALL_HEADERS`] |
    /// [`FACT_OPERATOR`] | [`FACT_READS_CREDENTIALS`] | [`FACT_DEFAULT_INBOUND_STYLE`].
    pub facts: u32,
    /// [`LOGIN_KIND_NONE`] | [`LOGIN_KIND_REDIRECT`] | [`LOGIN_KIND_CREDENTIAL`]: the
    /// classification the login chooser reads without calling `begin_login`. It is `NONE` exactly
    /// when [`CAP_LOGIN`] is absent; a tail where the two disagree refuses the load.
    pub login_kind: u32,
    /// The [`AuthPoints`] `verify` needs inbound: with [`CAP_INBOUND`] a valid, non-empty set;
    /// without it `0` ([`check_inbound_points`]; the loader refuses any other tail). A mechanism
    /// that checks a signature over the body needs [`POINT_HEAD_BODY`] and reads
    /// [`VerifyIn::body`].
    pub inbound_points: u32,
    /// The outbound styles served ([`CAP_OUTBOUND`]).
    pub styles: *const StyleDecl,
    /// How many.
    pub styles_len: usize,
    /// With [`FACT_OPERATOR`]: the principal id the operator credential identifies; empty
    /// otherwise. APPENDED after the tail froze at [`TAIL_FROZEN`] bytes: a tail of that size
    /// reads it empty.
    pub operator_principal: AbiStr,
    /// With [`FACT_READS_CREDENTIALS`]: the credential kinds `verify` reads through
    /// `records.secret`; none otherwise. APPENDED after [`AuthTail::operator_principal`]: an older
    /// tail reads none.
    pub credential_kinds: *const AbiStr,
    /// How many.
    pub credential_kinds_len: usize,
}

impl AuthTail {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    pub const ZERO: Self = Self {
        head: KindTailHead::ZERO,
        caps: 0,
        facts: 0,
        login_kind: 0,
        inbound_points: 0,
        styles: std::ptr::null(),
        styles_len: 0,
        operator_principal: AbiStr::ZERO,
        credential_kinds: std::ptr::null(),
        credential_kinds_len: 0,
    };
}

/// HOW THE AUTH KIND TAIL IS MADE: from [`AuthTail::EMPTY`], its plain fields set
impl AuthTail {
    /// Nothing stated: every string absent, every list empty, every number zero; the head
    pub const EMPTY: AuthTail = AuthTail {
        head: KindTailHead {
            size: core::mem::size_of::<AuthTail>() as u32,
            _reserved: 0,
        },
        caps: 0,
        facts: 0,
        login_kind: 0,
        inbound_points: 0,
        styles: std::ptr::null(),
        styles_len: 0,
        operator_principal: AbiStr::ABSENT,
        credential_kinds: std::ptr::null(),
        credential_kinds_len: 0,
    };

    abi_lists! {
        styles, styles_len: StyleDecl => styles_ptr, with_styles, with_raw_styles;
        credential_kinds, credential_kinds_len: AbiStr
            => credential_kinds_ptr, with_credential_kinds, with_raw_credential_kinds;
    }
}

/// `fields`' EXTENSIONS KEY ([`crate::abi::mechanism::extensions`], carried in
pub const EXT_SCOPE: &str = "scope";

/// `complete_login`'s REPLY EXTENSIONS KEY: on a [`LOGIN_OUTAGE`], the IdP's `Retry-After`.
pub const EXT_RETRY_AFTER: &str = "retry_after";

/// The delay an IdP's `Retry-After` header value asks for, in whole seconds from `now_unix` (Unix
#[must_use]
pub fn retry_after_secs(header_value: &[u8], now_unix: u64) -> Option<u64> {
    let v = header_value.trim_ascii();
    if v.is_empty() {
        return None;
    }
    if v.iter().all(u8::is_ascii_digit) {
        return Some(v.iter().fold(0u64, |n, d| {
            n.saturating_mul(10).saturating_add(u64::from(d - b'0'))
        }));
    }
    let at = http_date_unix(std::str::from_utf8(v).ok()?, now_unix)?;
    u64::try_from((at - i128::from(now_unix)).max(0)).ok()
}

/// An HTTP-date (IMF-fixdate, RFC 850 or asctime; RFC 9110 §5.6.7) as signed Unix seconds.
/// `now_unix` resolves RFC 850's two-digit year using its fifty-year rule. Keeping the absolute
/// instant lets a caller collect the header now and calculate its remaining delay later.
/// Dates before the epoch remain negative; callers that cannot represent them may reject them.
#[must_use]
pub fn http_date_unix(v: &str, now_unix: u64) -> Option<i128> {
    const SECONDS_PER_DAY: u64 = 86_400;
    const YEARS_PER_CENTURY: i128 = 100;
    const YEARS_PER_ERA: i128 = 400;
    const DAYS_PER_ERA: i128 = 146_097;
    const CIVIL_UNIX_EPOCH_DAYS: i128 = 719_468;
    const RFC850_FUTURE_YEARS: i128 = 50;
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const LONG_DAYS: [&str; 7] = [
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let digits = |s: &str, n: usize| -> Option<u32> {
        if s.len() == n && s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse().ok()
        } else {
            None
        }
    };
    let month = |s: &str| {
        MONTHS
            .iter()
            .position(|m| *m == s)
            .and_then(|i| u32::try_from(i + 1).ok())
    };
    let time = |s: &str| -> Option<(u32, u32, u32)> {
        let mut p = s.split(':');
        let t = (
            digits(p.next()?, 2)?,
            digits(p.next()?, 2)?,
            digits(p.next()?, 2)?,
        );
        p.next().is_none().then_some(t)
    };
    let tokens: Vec<&str> = v.split_ascii_whitespace().collect();
    let (year, mon, day, (h, m, s)) = match *tokens.as_slice() {
        [wd, d, mo, y, t, "GMT"] if DAYS.iter().any(|n| wd.strip_suffix(',') == Some(*n)) => (
            i128::from(digits(y, 4)?),
            month(mo)?,
            digits(d, 2)?,
            time(t)?,
        ),

        [wd, date, t, "GMT"] if LONG_DAYS.iter().any(|n| wd.strip_suffix(',') == Some(*n)) => {
            let mut p = date.split('-');
            let (d, mo, y) = (p.next()?, p.next()?, p.next()?);
            if p.next().is_some() {
                return None;
            }
            let y = i128::from(digits(y, 2)?);
            let (mon, day, (h, m, s)) = (month(mo)?, digits(d, 2)?, time(t)?);

            let z = i128::from(now_unix / SECONDS_PER_DAY) + CIVIL_UNIX_EPOCH_DAYS;
            let era = z / DAYS_PER_ERA;
            let doe = z - era * DAYS_PER_ERA;
            let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let now_day = doy - (153 * mp + 2) / 5 + 1;
            let now_mon = if mp < 10 { mp + 3 } else { mp - 9 };
            let now_year = yoe + era * YEARS_PER_ERA + i128::from(now_mon <= 2);
            let last_future_year = now_year + RFC850_FUTURE_YEARS;
            let mut year = last_future_year - (last_future_year - y).rem_euclid(YEARS_PER_CENTURY);
            let seconds = u64::from(h) * 3600 + u64::from(m) * 60 + u64::from(s);

            if (year, i128::from(mon), i128::from(day), seconds)
                > (
                    last_future_year,
                    now_mon,
                    now_day,
                    now_unix % SECONDS_PER_DAY,
                )
            {
                year -= YEARS_PER_CENTURY;
            }
            (year, mon, day, (h, m, s))
        }

        [wd, mo, d, t, y] if DAYS.contains(&wd) => (
            i128::from(digits(y, 4)?),
            month(mo)?,
            digits(d, 1).or_else(|| digits(d, 2))?,
            time(t)?,
        ),
        _ => return None,
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = match mon {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=month_days).contains(&day) || h > 23 || m > 59 || s > 60 {
        return None;
    }

    let y = if mon <= 2 { year - 1 } else { year };
    let era = y.div_euclid(YEARS_PER_ERA);
    let yoe = y - era * YEARS_PER_ERA;
    let mp = i128::from((mon + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i128::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * DAYS_PER_ERA + doe - CIVIL_UNIX_EPOCH_DAYS;
    Some(
        days * i128::from(SECONDS_PER_DAY)
            + i128::from(h) * 3600
            + i128::from(m) * 60
            + i128::from(s),
    )
}

/// The delay reply `extensions` state under [`EXT_RETRY_AFTER`]: plain ASCII digits that fit a
#[must_use]
pub fn retry_after_of(extensions: &[u8]) -> Option<u64> {
    let v = crate::abi::mechanism::extensions::get(extensions, EXT_RETRY_AFTER)?;
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

/// THE REQUEST FIELD BY WHICH A PLUGIN STATES ITS PER-CALL SCOPE to the host: a field of this name
pub const SCOPE_REQUEST_FIELD: &str = "busbar-auth-scope";

/// Whether the request field `name` is [`SCOPE_REQUEST_FIELD`] (a field name compares
#[must_use]
pub fn is_scope_field(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(SCOPE_REQUEST_FIELD.as_bytes())
}

/// THE REQUEST FIELD BY WHICH A PLUGIN WAIVES ITS MEMBER'S BINDING FOR ONE REQUEST: a field of this
pub const NO_MEMBER_AUTH_FIELD: &str = "busbar-no-member-auth";

/// Whether the request field `name` is [`NO_MEMBER_AUTH_FIELD`] (a field name compares
#[must_use]
pub fn is_no_member_auth_field(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(NO_MEMBER_AUTH_FIELD.as_bytes())
}

/// The extensions blob a request's stated `scope` is lent to its auth call in: one [`EXT_SCOPE`]
#[must_use]
pub fn scope_extensions(scope: Option<&[u8]>) -> Vec<u8> {
    scope.map_or_else(Vec::new, |s| {
        crate::abi::mechanism::extensions::encode(&[(EXT_SCOPE, s)])
    })
}

pub use super::mechanism::check::SPAN_ABSENT;

/// [`IdentityOut::flags`]: [`IdentityOut::ttl_secs`] is set.
pub const IDENTITY_HAS_TTL: u32 = 1;
