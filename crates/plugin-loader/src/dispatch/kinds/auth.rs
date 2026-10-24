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
//!   no host capacity is involved);
//! * `target` by `check_target`, over the host's buffer from `TargetIn`.
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
    check_inbound_points, check_style_decl, check_target, slot, AuthPoints, BeginLoginIn,
    BeginLoginOut, CompleteLoginIn, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, IdentityBuf,
    OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, StripName, TargetIn,
    TargetOut, VerifyIn, LOGIN_IDENTITY, VERDICT_IDENTITY,
};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::check::{reported, Fault};
use busbar_contract::abi::mechanism::door::{
    Statement, MARK_WORD_CARRIER, MARK_WORD_ISSUED_ID_ALPHABET, MARK_WORD_ISSUED_ID_LENGTH,
    MARK_WORD_ISSUED_ID_PREFIX, MARK_WORD_ISSUED_SECRET_ALPHABET, MARK_WORD_ISSUED_SECRET_LENGTH,
};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::auth_calls::IssuedShape;

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
    /// With `abi::auth::FACT_READS_CREDENTIALS`: the shape of the credential the host issues for
    /// its kinds, from its `MARK_WORD_ISSUED_*` word marks, checked at load ([`issued`]).
    pub issued: Option<IssuedShape>,
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

/// Whether the auth plugin behind `door` is an AUTH-CHAIN MODULE an operator names in `auth.chain`
/// / `admin_auth`: its Statement's auth tail declares an inbound capability (`CAP_INBOUND`: it
/// verifies a caller's credential) and is not a host-held credentials' verifier
/// (`FACT_READS_CREDENTIALS`: its `verify` serves the `keys` entry, opened when the chain names
/// `keys`, and is never named on its own). An outbound-only plugin (style presentation for an
/// upstream credential) states no inbound capability. A door whose Statement does not read as an
/// auth Statement is none: `false`. Reads the door's `'static` Statement only; nothing is opened.
#[must_use]
pub fn declares_chain_module(door: busbar_contract::abi::mechanism::door::DoorFn) -> bool {
    crate::dispatch::load::validate::<Auth>(door)
        .ok()
        .and_then(|v| facts(&v.statement).ok())
        .is_some_and(|f| {
            f.caps & auth::CAP_INBOUND != 0 && f.facts & auth::FACT_READS_CREDENTIALS == 0
        })
}

/// The principal id the auth plugin behind `door` states as THE OPERATOR CREDENTIAL's
/// (`FACT_OPERATOR` and its `operator_principal`); `None` when it states no operator, or its
/// Statement does not read as an auth Statement. Reads the door's `'static` Statement only; nothing
/// is opened.
#[must_use]
pub fn operator_principal(door: busbar_contract::abi::mechanism::door::DoorFn) -> Option<String> {
    crate::dispatch::load::validate::<Auth>(door)
        .ok()
        .and_then(|v| facts(&v.statement).ok())
        .and_then(|f| f.operator_principal)
}

/// EVERYTHING the auth plugin behind `door` states (its Statement's auth tail, carriers and
/// families), as a bind copies it out, read WITHOUT binding it: reading a linked row's static
/// declaration is reading, not loading (Law 7; ARCHITECT ruling 2026-10-20). Reads the door's
/// `'static` Statement only; nothing is bound or opened.
///
/// # Errors
///
/// The door's Statement does not read as an auth Statement, or its tail is one a bind refuses.
pub fn stated_facts(
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> Result<AuthFacts, String> {
    let v = crate::dispatch::load::validate::<Auth>(door).map_err(|e| e.to_string())?;
    facts(&v.statement)
}

/// A Statement string, copied; refused (`over`) above
/// [`MAX_TEXT`](crate::dispatch::plugin::MAX_TEXT) bytes, as a bind refuses a malformed one.
fn fit(s: &str, over: &str) -> Result<String, String> {
    if s.len() > crate::dispatch::plugin::MAX_TEXT {
        return Err(over.to_string());
    }
    Ok(s.to_string())
}

/// The inbound carriers a Statement's word marks state: its
/// [`MARK_WORD_CARRIER`](busbar_contract::abi::mechanism::door::MARK_WORD_CARRIER) word marks,
/// lower-case, in the Statement's order (the design's One Statement: a carrier is a Statement mark,
/// never a tail fact). At most [`MAX_CARRIERS`].
fn carriers(words: &[(u32, String)]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (class, word) in words {
        if *class != MARK_WORD_CARRIER {
            continue;
        }
        if out.len() == MAX_CARRIERS {
            return Err(format!(
                "the auth Statement states more than {MAX_CARRIERS} carriers"
            ));
        }
        let word = fit(word, "an auth carrier name is over-long")?;
        out.push(word.to_ascii_lowercase());
    }
    Ok(out)
}

/// The longest issued id or secret, and the largest alphabet, a Statement may state: a byte of the
/// OS CSPRNG picks one symbol, so an alphabet holds at most 256.
const MAX_ISSUED: usize = 256;

/// The issued credential's shape a Statement's `MARK_WORD_ISSUED_*` word marks state; `None` when
/// it states none. Refused at load: a class stated twice, a shape missing a length or an alphabet, a
/// length that is not a decimal in `1..=256`, an alphabet that is empty, over 256, not ASCII graphic
/// or repeats a character, and a prefix that is not ASCII graphic or leaves no room in the id.
fn issued(words: &[(u32, String)]) -> Result<Option<IssuedShape>, String> {
    let mut slots: [Option<String>; 5] = Default::default();
    let classes = [
        MARK_WORD_ISSUED_ID_PREFIX,
        MARK_WORD_ISSUED_ID_LENGTH,
        MARK_WORD_ISSUED_ID_ALPHABET,
        MARK_WORD_ISSUED_SECRET_LENGTH,
        MARK_WORD_ISSUED_SECRET_ALPHABET,
    ];
    for (class, word) in words {
        let Some(slot) = classes.iter().position(|c| c == class) else {
            continue;
        };
        if slots[slot].is_some() {
            return Err(format!(
                "the auth Statement states issued-credential mark class {class} twice"
            ));
        }
        slots[slot] = Some(fit(word, "an issued-credential mark is over-long")?);
    }
    if slots.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [prefix, id_len, id_alphabet, secret_len, secret_alphabet] = slots;
    let length = |word: Option<String>, what: &str| -> Result<usize, String> {
        let word = word.ok_or_else(|| format!("the issued-credential shape states no {what}"))?;
        match word.parse::<usize>() {
            Ok(n) if (1..=MAX_ISSUED).contains(&n) && word.bytes().all(|b| b.is_ascii_digit()) => {
                Ok(n)
            }
            _ => Err(format!(
                "the issued-credential {what} {word:?} is not a decimal in 1..={MAX_ISSUED}"
            )),
        }
    };
    let alphabet = |word: Option<String>, what: &str| -> Result<String, String> {
        let word = word.ok_or_else(|| format!("the issued-credential shape states no {what}"))?;
        let graphic = !word.is_empty() && word.bytes().all(|b| b.is_ascii_graphic());
        let mut seen = [false; 128];
        let distinct = word
            .bytes()
            .all(|b| !std::mem::replace(&mut seen[usize::from(b & 0x7f)], true));
        if !graphic || !distinct || word.len() > MAX_ISSUED {
            return Err(format!(
                "the issued-credential {what} is not up to {MAX_ISSUED} distinct ASCII graphic \
                 characters"
            ));
        }
        Ok(word)
    };
    let id_len = length(id_len, "id length")?;
    let shape = IssuedShape {
        id_prefix: prefix.unwrap_or_default(),
        id_len,
        id_alphabet: alphabet(id_alphabet, "id alphabet")?,
        secret_len: length(secret_len, "secret length")?,
        secret_alphabet: alphabet(secret_alphabet, "secret alphabet")?,
    };
    if !shape.id_prefix.bytes().all(|b| b.is_ascii_graphic()) || shape.id_prefix.len() >= id_len {
        return Err(format!(
            "the issued-credential id prefix {:?} is not ASCII graphic or leaves no room in a \
             {id_len}-character id",
            shape.id_prefix
        ));
    }
    Ok(Some(shape))
}

/// Read the auth tail, the carriers and the cache-flush family out of `st`, through its canonical
/// rendering: a bind, a linked door's static read and a dropped-in row's signed manifest read the
/// same facts the same way ([`rendered_facts`]).
fn facts(st: &Statement) -> Result<AuthFacts, String> {
    // Read as the auth Statement it is bound as: its tail renders as an auth tail.
    let st = Statement {
        kind: KindCode::Auth as u32,
        ..*st
    };
    // SAFETY: the loader's Statement check ran on `st`: every Statement list is its stated count of
    // `'static` entries, and the rendering bounds each tail list and string before it reads it.
    let rendering = unsafe { busbar_contract::abi::mechanism::rendering::render(&st) }
        .map_err(|e| e.to_string())?;
    rendered_facts(&rendering)
}

/// EVERYTHING an auth Statement states (its auth tail, carriers and families), read from its
/// canonical RENDERING: a dropped-in row's signed manifest rendering is read with no `dlopen`
/// (ARCHITECT ruling 2026-10-20, audit root#7 and loader#9: the rendering carries the whole kind
/// tail, and the admit comparison refuses a door whose Statement is not the manifest's), and a
/// linked door's is its own Statement rendered. A bind refuses exactly what this refuses.
///
/// # Errors
///
/// The rendering does not read back, is not an auth Statement's, or states a tail a bind refuses.
pub fn rendered_facts(rendering: &[u8]) -> Result<AuthFacts, String> {
    let r = busbar_contract::abi::mechanism::rendering::read(rendering).map_err(|e| {
        format!(
            "the auth Statement rendering does not read back: byte {} is not {}",
            e.at, e.what
        )
    })?;
    if r.kind != KindCode::Auth as u32 {
        return Err(format!(
            "the Statement rendering states kind {}, not auth",
            r.kind
        ));
    }
    // THE KIND TAIL GROWTH RULE: a tail smaller than the frozen auth tail refuses the load.
    if r.kind_tail_size == 0 {
        return Err("an auth plugin states no kind tail".to_string());
    }
    if (r.kind_tail_size as usize) < auth::AUTH_TAIL_FROZEN {
        return Err(format!(
            "an auth plugin states a {}-byte tail, smaller than its frozen {}",
            r.kind_tail_size,
            auth::AUTH_TAIL_FROZEN
        ));
    }
    let t =
        busbar_contract::abi::mechanism::rendering::read_auth_tail(&r.kind_tail).map_err(|e| {
            format!(
                "the auth tail's rendering does not read back: byte {} is not {}",
                e.at, e.what
            )
        })?;
    let carriers = carriers(&r.mark_words)?;
    let issued = issued(&r.mark_words)?;
    // The default inbound style IS its carriers: a tail stating it with none refuses the load.
    if t.facts & auth::FACT_DEFAULT_INBOUND_STYLE != 0 && carriers.is_empty() {
        return Err(
            "the auth tail states the default inbound style and its Statement names no carrier"
                .to_string(),
        );
    }
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
    let principal = fit(
        &t.operator_principal,
        "the auth operator principal is over-long",
    )?;
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
    if t.credential_kinds.len() > MAX_CREDENTIAL_KINDS {
        return Err(format!(
            "the auth tail states {} credential kinds",
            t.credential_kinds.len()
        ));
    }
    let credential_kinds = t
        .credential_kinds
        .iter()
        .map(|k| fit(k, "an auth credential kind is over-long"))
        .collect::<Result<Vec<_>, _>>()?;
    let reads = t.facts & auth::FACT_READS_CREDENTIALS != 0;
    let blank = credential_kinds.iter().any(String::is_empty);
    if reads == credential_kinds.is_empty() || blank || (reads && t.caps & auth::CAP_INBOUND == 0) {
        return Err(format!(
            "the auth tail's credential-read fact disagrees with its {} credential kinds or \
             capabilities",
            credential_kinds.len()
        ));
    }
    // An issued credential is one the host holds for the row to read: a shape on a row that reads
    // no host-held credential refuses the load.
    if issued.is_some() && !reads {
        return Err(
            "the auth Statement states an issued-credential shape and reads no host-held credential"
                .to_string(),
        );
    }
    // Every style states known flags and the points it needs; a stray bit refuses the load.
    if t.styles.len() > MAX_STYLES {
        return Err(format!("the auth tail states {} styles", t.styles.len()));
    }
    let mut styles = Vec::with_capacity(t.styles.len());
    for d in &t.styles {
        styles.push(OutboundStyle {
            name: fit(&d.name, "an auth style name is over-long")?,
            flags: d.flags,
            points: d.points,
        });
        check_style_decl(d.flags, d.points).map_err(|f| {
            format!(
                "auth style {} is refused: flags {:#x}, points {:#x}: {f:?}",
                d.name, d.flags, d.points
            )
        })?;
    }
    let mut cache_family = None;
    for (i, f) in r.families.iter().enumerate() {
        if f.name == auth::METRIC_CACHE_FLUSHED {
            cache_family = u32::try_from(i).ok();
        }
    }
    let secret_refs = r
        .secret_refs
        .iter()
        .map(|k| fit(k, "an auth secret-ref key is over-long"))
        .collect::<Result<Vec<_>, _>>()?;
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
        issued,
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
unsafe impl InFrame for TargetIn {}
unsafe impl OutFrame for IdentifyOut {}
unsafe impl OutFrame for BeginLoginOut {}
unsafe impl OutFrame for OpenOutboundOut {}
unsafe impl OutFrame for OutboundReadyOut {}
unsafe impl OutFrame for FieldsOut {}
unsafe impl OutFrame for TargetOut {}

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
            slot::TARGET => "target",
            _ => lifecycle_name(s),
        }
    }

    /// `target` is optional: a style that states none sends its credential to no destination of
    /// its own choosing.
    fn optional_slot(s: u32) -> bool {
        s == slot::TARGET
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
            slot::TARGET => {
                let cap = a.input::<TargetIn>()?.buf_cap;
                check_target(a.outcome, a.out::<TargetOut>()?, cap)
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
