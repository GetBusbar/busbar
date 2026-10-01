// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND: `abi/auth/`. Four kind ops are checked by their own validators:
//!
//! * `verify` by `check_identify`, over the host's `IdentityBuf` from `VerifyIn::out_buf` and its
//!   strip array from `VerifyIn::strip`;
//! * `complete_login` by `check_complete_login`, over the host's `IdentityBuf` from
//!   `CompleteLoginIn::out_buf`;
//! * `fields` by `check_fields`, over the host's field buffer and array from `FieldsIn`;
//! * `begin_login` by `check_begin_login` (its URL and form are plugin memory under the lease, so
//!   no host capacity is involved).
//!
//! `open_outbound` and `outbound_ready` state no rule beyond the mechanism's and answer `Ok`, as
//! does every lifecycle slot.
//!
//! The group spans (`verify`, `complete_login`) and the field spans (`fields`) the plugin reports
//! are built through `check::reported` with the capacity the host passed in the op's `in`, so a
//! count above it is FAULT before any slice exists (the HOST DUTY `abi/auth/check.rs` states).
//! They are built only when the validator reads them: a READY identity verdict, or a READY
//! `fields` answer. Every other answer's count is not part of the answer and is never read.
//!
//! `verify`, `complete_login` and `fields` have a short-buffer path: FAILED with a non-zero
//! `needed_*` (`IdentifyOut`, `FieldsOut`).
//!
//! The timeout outcome is FAILED: `abi/auth/mod.rs` states that deadlines are host-owned and the
//! host calls `cancel` at expiry, and names no other outcome for an expired op.

use busbar_contract::abi::auth::{
    self, check_begin_login, check_complete_login, check_fields, check_identify,
    check_inbound_points, check_style_decl, slot, AuthPoints, BeginLoginIn, BeginLoginOut,
    CompleteLoginIn, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, IdentityBuf, OpenOutboundIn,
    OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, StripName, VerifyIn, LOGIN_IDENTITY,
    VERDICT_IDENTITY,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, Span};
use busbar_contract::abi::mechanism::check::{fault, reported, Fault, Rule};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::KindCode;

use crate::dispatch::{lifecycle_name, Answer, Context, InFrame, Kind, OutFrame};

/// The auth kind.
#[derive(Debug, Clone, Copy)]
pub struct Auth;

/// The most carrier names an auth tail may state.
const MAX_CARRIERS: usize = 64;
/// The most outbound styles an auth tail may state.
const MAX_STYLES: usize = 64;

/// What an auth instance's Statement states, copied out once at bind and read back through
/// [`crate::dispatch::Plugin::context`]: its capabilities, its facts, the inbound carrier fields
/// `verify` reads (lower-case, in the tail's order), and the index of its
/// [`METRIC_CACHE_FLUSHED`](busbar_contract::abi::auth::METRIC_CACHE_FLUSHED) counter family, when
/// it declares one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthFacts {
    /// `abi::auth::CAP_*`.
    pub caps: u32,
    /// `abi::auth::FACT_*`.
    pub facts: u32,
    /// The carrier field names, lower-case.
    pub carriers: Vec<String>,
    /// The Statement family index of the cache-flush counter.
    pub cache_family: Option<u32>,
    /// The settings keys the Statement names as secret-refs (service credentials), in order: the
    /// host hands their resolved values to `open`/`refresh` as `secrets`, not in the settings.
    pub secret_refs: Vec<String>,
    /// `abi::auth::LOGIN_KIND_*`: how the plugin's login starts; `LOGIN_KIND_NONE` exactly when it
    /// states no `CAP_LOGIN`.
    pub login_kind: u32,
    /// The auth points `verify` is called at (THE DESIGN, "Auth points and guest lists"):
    /// non-empty exactly when it states `CAP_INBOUND`.
    pub inbound_points: AuthPoints,
}

/// A `'static` Statement string, copied; `None` when malformed.
fn owned(s: AbiStr) -> Option<String> {
    crate::dispatch::plugin::str_bytes(s).map(|b| String::from_utf8_lossy(b).into_owned())
}

/// Read the auth tail and the cache-flush family out of `st`.
fn facts(st: &Statement) -> Result<AuthFacts, String> {
    let p = st.kind_tail;
    if p.is_null() {
        return Err("an auth plugin states no kind tail".into());
    }
    // SAFETY: a non-NULL kind tail is `'static` plugin data leading with a `KindTailHead`; the
    // whole tail is read only once its size covers this host's `AuthTail`.
    let size = unsafe { (*p).size };
    if (size as usize) < std::mem::size_of::<auth::AuthTail>() {
        return Err(format!(
            "the auth tail is {size} bytes, smaller than this host's"
        ));
    }
    // SAFETY: as above.
    let t = unsafe { p.cast::<auth::AuthTail>().read_unaligned() };
    if t.carriers_len > MAX_CARRIERS || (t.carriers.is_null() && t.carriers_len != 0) {
        return Err(format!("the auth tail states {} carriers", t.carriers_len));
    }
    let carriers = (0..t.carriers_len)
        // SAFETY: `carriers` holds `carriers_len` `'static` strings (checked non-NULL above).
        .map(|i| {
            owned(unsafe { t.carriers.add(i).read_unaligned() }).map(|c| c.to_ascii_lowercase())
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("an auth carrier name is over-long")?;
    // The login classification agrees with the login capability, and is one the host knows.
    let logs_in = t.caps & auth::CAP_LOGIN != 0;
    let kind_known = matches!(
        t.login_kind,
        auth::LOGIN_KIND_NONE | auth::LOGIN_KIND_REDIRECT | auth::LOGIN_KIND_CREDENTIAL
    );
    if !kind_known || logs_in != (t.login_kind != auth::LOGIN_KIND_NONE) {
        return Err(format!(
            "the auth tail's login kind {} disagrees with its login capability",
            t.login_kind
        ));
    }
    // The inbound point set agrees with the inbound capability (THE DESIGN, "Auth points and
    // guest lists"): a plugin that serves `verify` states the points it needs, and no other does.
    let inbound_points = check_inbound_points(t.caps, t.inbound_points).map_err(|f| {
        format!(
            "the auth tail's inbound points {:#x} are refused: {f:?}",
            t.inbound_points
        )
    })?;
    // Every style states known flags and the points it needs; a stray bit refuses the load.
    if t.styles_len > MAX_STYLES || (t.styles.is_null() && t.styles_len != 0) {
        return Err(format!("the auth tail states {} styles", t.styles_len));
    }
    for i in 0..t.styles_len {
        // SAFETY: `styles` holds `styles_len` `'static` declarations (checked non-NULL above).
        let d = unsafe { t.styles.add(i).read_unaligned() };
        check_style_decl(d.flags, d.points).map_err(|f| {
            format!(
                "auth style {} is refused: flags {:#x}, points {:#x}: {f:?}",
                owned(d.name).unwrap_or_default(),
                d.flags,
                d.points
            )
        })?;
    }
    let mut cache_family = None;
    for i in 0..st.families_len {
        // SAFETY: the loader's Statement check: `families` holds `families_len` `'static` entries.
        let f = unsafe { st.families.add(i).read_unaligned() };
        if owned(f.name).as_deref() == Some(auth::METRIC_CACHE_FLUSHED) {
            cache_family = u32::try_from(i).ok();
        }
    }
    let secret_refs = (0..st.secret_refs_len)
        // SAFETY: the loader's Statement check refused a NULL `secret_refs` with a count; it holds
        // `secret_refs_len` `'static` strings.
        .map(|i| owned(unsafe { st.secret_refs.add(i).read_unaligned() }))
        .collect::<Option<Vec<_>>>()
        .ok_or("an auth secret-ref key is over-long")?;
    Ok(AuthFacts {
        caps: t.caps,
        facts: t.facts,
        carriers,
        cache_family,
        secret_refs,
        login_kind: t.login_kind,
        inbound_points,
    })
}

// SAFETY: `#[repr(C)]` in `abi/auth/`, each leading with its head, plain data whose pointers are
// host buffers or plugin memory held under the lease; host buffers only.
unsafe impl InFrame for VerifyIn {}
unsafe impl InFrame for BeginLoginIn {}
unsafe impl InFrame for CompleteLoginIn {}
unsafe impl InFrame for OpenOutboundIn {}
unsafe impl InFrame for OutboundReadyIn {}
unsafe impl InFrame for FieldsIn {}
unsafe impl OutFrame for IdentifyOut {}
unsafe impl OutFrame for BeginLoginOut {}
unsafe impl OutFrame for OpenOutboundOut {}
unsafe impl OutFrame for OutboundReadyOut {}
unsafe impl OutFrame for FieldsOut {}

/// The group spans an identity answer reports: `out.identity.groups_len` of the host's
/// `buf.groups`, the count checked against `buf.groups_cap` first. Empty unless the answer is a
/// READY `identified` verdict, the one answer whose groups the validator reads.
fn groups<'a>(
    a: &Answer,
    out: &IdentifyOut,
    buf: &'a IdentityBuf,
    identified: u32,
    field: &'static str,
) -> Result<&'a [Span], Fault> {
    if a.outcome != Outcome::Ready || out.verdict != identified {
        return Ok(&[]);
    }
    // SAFETY: `buf` is the host's own `IdentityBuf` from the op's `in`, its `groups` an array of
    // `groups_cap` live spans the host allocated; `reported` refuses a count above that cap
    // before it builds the slice.
    unsafe {
        reported(
            buf.groups.cast_const(),
            u64::from(out.identity.groups_len),
            u64::from(buf.groups_cap),
            field,
        )
    }
}

impl Kind for Auth {
    const CODE: KindCode = KindCode::Auth;
    type Ops = auth::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn context(st: &Statement) -> Result<Option<Box<Context>>, String> {
        Ok(Some(Box::new(facts(st)?)))
    }

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::VERIFY => "verify",
            slot::BEGIN_LOGIN => "begin_login",
            slot::COMPLETE_LOGIN => "complete_login",
            slot::OPEN_OUTBOUND => "open_outbound",
            slot::OUTBOUND_READY => "outbound_ready",
            slot::FIELDS => "fields",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::VERIFY => {
                let input = a.input::<VerifyIn>()?;
                let buf = &input.out_buf;
                let out = a.out::<IdentifyOut>()?;
                let groups = groups(a, out, buf, VERDICT_IDENTITY, "verify.groups")?;
                // The strip names are read on every READY answer, whatever the verdict.
                let strips: &[StripName] = if a.outcome == Outcome::Ready {
                    // SAFETY: `input.strip` is the host's own array of `strip_cap` live
                    // `StripName`s from the op's `in`; `reported` refuses a count above that cap
                    // before it builds the slice.
                    unsafe {
                        reported(
                            input.strip.cast_const(),
                            u64::from(out.strip_len),
                            u64::from(input.strip_cap),
                            "verify.strip",
                        )?
                    }
                } else {
                    &[]
                };
                check_identify(a.outcome, out, buf, groups, input.strip_cap, strips)
            }
            slot::COMPLETE_LOGIN => {
                let buf = &a.input::<CompleteLoginIn>()?.out_buf;
                let out = a.out::<IdentifyOut>()?;
                let groups = groups(a, out, buf, LOGIN_IDENTITY, "complete_login.groups")?;
                check_complete_login(a.outcome, out, buf, groups)
            }
            slot::FIELDS => {
                let input = a.input::<FieldsIn>()?;
                let out = a.out::<FieldsOut>()?;
                let fields: &[FieldSpan] = if a.outcome == Outcome::Ready {
                    // SAFETY: `input.fields` is the host's own array of `fields_cap` live
                    // `FieldSpan`s from the op's `in`; `reported` refuses a count above that cap
                    // before it builds the slice.
                    unsafe {
                        reported(
                            input.fields.cast_const(),
                            u64::from(out.fields_len),
                            u64::from(input.fields_cap),
                            "fields.fields",
                        )?
                    }
                } else {
                    &[]
                };
                check_fields(
                    a.outcome,
                    out,
                    input.field_buf_cap,
                    input.fields_cap,
                    fields,
                )
            }
            slot::BEGIN_LOGIN => {
                a.input::<BeginLoginIn>()?;
                check_begin_login(a.outcome, a.out::<BeginLoginOut>()?)
            }
            _ => Ok(()),
        }
    }

    fn short(a: &Answer) -> bool {
        if a.outcome != Outcome::Failed {
            return false;
        }
        match a.slot {
            slot::VERIFY | slot::COMPLETE_LOGIN => a
                .out::<IdentifyOut>()
                .is_ok_and(|o| o.needed_bytes != 0 || o.needed_groups != 0 || o.needed_strip != 0),
            slot::FIELDS => a
                .out::<FieldsOut>()
                .is_ok_and(|o| o.needed_bytes != 0 || o.needed_fields != 0),
            _ => false,
        }
    }
}
