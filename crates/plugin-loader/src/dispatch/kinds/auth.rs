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
use busbar_contract::abi::mechanism::check::{reported, Fault};
use busbar_contract::abi::mechanism::door::{Statement, MARK_WORD_CARRIER};
use busbar_contract::abi::mechanism::KindCode;

use crate::dispatch::{lifecycle_name, Answer, Context, InFrame, Kind, OutFrame};

/// The auth kind.
#[derive(Debug, Clone, Copy)]
pub struct Auth;

/// The most carrier word marks an auth Statement may state.
const MAX_CARRIERS: usize = 64;
/// The most outbound styles an auth tail may state.
const MAX_STYLES: usize = 64;
/// The most credential kinds an auth tail may state.
const MAX_CREDENTIAL_KINDS: usize = 64;

/// What an auth instance's Statement states, copied out once at bind and read back through
/// [`crate::dispatch::Plugin::context`]: its capabilities, its facts, the inbound carrier fields
/// `verify` reads (its Statement's carrier word marks, lower-case, in order), and the index of its
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
    /// With `abi::auth::FACT_OPERATOR`: the principal id the operator credential identifies.
    pub operator_principal: Option<String>,
    /// With `abi::auth::FACT_READS_CREDENTIALS`: the credential kinds `verify` reads through
    /// `records.secret`, the only kinds the host serves this instance.
    pub credential_kinds: Vec<String>,
    /// With `abi::auth::CAP_OUTBOUND`: the outbound styles it serves, each judged at load.
    pub styles: Vec<OutboundStyle>,
}

/// ONE OUTBOUND STYLE an auth plugin's tail states (`abi::auth::StyleDecl`), owned by the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundStyle {
    /// The style's name.
    pub name: String,
    /// `abi::auth::STYLE_*`.
    pub flags: u32,
    /// The auth points it needs.
    pub points: u32,
}

/// A `'static` Statement string, copied; `None` when malformed.
fn owned(s: AbiStr) -> Option<String> {
    crate::dispatch::plugin::str_bytes(s).map(|b| String::from_utf8_lossy(b).into_owned())
}

/// The inbound carriers `st` states: its
/// [`MARK_WORD_CARRIER`](busbar_contract::abi::mechanism::door::MARK_WORD_CARRIER) word marks,
/// lower-case, in the Statement's order (the design's One Statement: a carrier is a Statement mark,
/// never a tail fact). At most [`MAX_CARRIERS`].
fn carriers(st: &Statement) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for i in 0..st.mark_words_len {
        // SAFETY: the loader's Statement check refused a NULL `mark_words` with a count; it holds
        // `mark_words_len` `'static` word marks.
        let w = unsafe { st.mark_words.add(i).read_unaligned() };
        if w.class != MARK_WORD_CARRIER {
            continue;
        }
        if out.len() == MAX_CARRIERS {
            return Err(format!(
                "the auth Statement states more than {MAX_CARRIERS} carriers"
            ));
        }
        let word = owned(w.word).ok_or("an auth carrier name is over-long")?;
        out.push(word.to_ascii_lowercase());
    }
    Ok(out)
}

/// Read the auth tail, the carriers and the cache-flush family out of `st`.
fn facts(st: &Statement) -> Result<AuthFacts, String> {
    // SAFETY: `AuthTail` is a `#[repr(C)]` kind tail of integers, pointers and strings (all-zero
    // valid: an appended field the plugin predates reads absent); a non-NULL kind tail is `'static`
    // plugin data of its stated size.
    let t: auth::AuthTail = unsafe {
        crate::dispatch::plugin::kind_tail(st, "an auth plugin", auth::AUTH_TAIL_FROZEN)
    }?;
    let carriers = carriers(st)?;
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
    // The operator fact agrees with its principal, and with the inbound capability: the operator
    // credential is a `verify` that names the principal it identifies. Either without the other
    // refuses the load.
    let principal =
        owned(t.operator_principal).ok_or("the auth operator principal is over-long")?;
    let operator = t.facts & auth::FACT_OPERATOR != 0;
    if operator == principal.is_empty() || (operator && t.caps & auth::CAP_INBOUND == 0) {
        return Err(format!(
            "the auth tail's operator fact disagrees with its principal ({} bytes) or capabilities",
            principal.len()
        ));
    }
    // The credential-read fact agrees with its kinds, and with the inbound capability: a `verify`
    // that reads host-held credentials names exactly the kinds it reads. Either without the other
    // refuses the load.
    if t.credential_kinds_len > MAX_CREDENTIAL_KINDS
        || (t.credential_kinds.is_null() && t.credential_kinds_len != 0)
    {
        return Err(format!(
            "the auth tail states {} credential kinds",
            t.credential_kinds_len
        ));
    }
    let credential_kinds = (0..t.credential_kinds_len)
        // SAFETY: `credential_kinds` holds `credential_kinds_len` `'static` strings (checked above).
        .map(|i| owned(unsafe { t.credential_kinds.add(i).read_unaligned() }))
        .collect::<Option<Vec<_>>>()
        .ok_or("an auth credential kind is over-long")?;
    let reads = t.facts & auth::FACT_READS_CREDENTIALS != 0;
    let blank = credential_kinds.iter().any(String::is_empty);
    if reads == credential_kinds.is_empty() || blank || (reads && t.caps & auth::CAP_INBOUND == 0) {
        return Err(format!(
            "the auth tail's credential-read fact disagrees with its {} credential kinds or \
             capabilities",
            credential_kinds.len()
        ));
    }
    // Every style states known flags and the points it needs; a stray bit refuses the load.
    if t.styles_len > MAX_STYLES || (t.styles.is_null() && t.styles_len != 0) {
        return Err(format!("the auth tail states {} styles", t.styles_len));
    }
    let mut styles = Vec::with_capacity(t.styles_len);
    for i in 0..t.styles_len {
        // SAFETY: `styles` holds `styles_len` `'static` declarations (checked non-NULL above).
        let d = unsafe { t.styles.add(i).read_unaligned() };
        styles.push(OutboundStyle {
            name: owned(d.name).ok_or("an auth style name is over-long")?,
            flags: d.flags,
            points: d.points,
        });
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
        operator_principal: operator.then_some(principal),
        credential_kinds,
        styles,
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

    fn credential_kinds(context: Option<&Context>) -> Vec<String> {
        context
            .and_then(|c| c.downcast_ref::<AuthFacts>())
            .map(|f| f.credential_kinds.clone())
            .unwrap_or_default()
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
