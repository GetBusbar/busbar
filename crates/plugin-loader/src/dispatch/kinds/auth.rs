// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

const MAX_CARRIERS: usize = 64;

const MAX_STYLES: usize = 64;

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
    /// The Statement advertises version 1 pure outbound settings validation.
    pub outbound_settings_check: bool,
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

#[must_use]
pub fn declares_chain_module(door: busbar_contract::abi::mechanism::door::DoorFn) -> bool {
    crate::dispatch::load::validate::<Auth>(crate::dispatch::load::raw(door))
        .ok()
        .and_then(|v| facts(&v.statement).ok())
        .is_some_and(|f| {
            f.caps & auth::CAP_INBOUND != 0 && f.facts & auth::FACT_READS_CREDENTIALS == 0
        })
}

#[must_use]
pub fn operator_principal(door: busbar_contract::abi::mechanism::door::DoorFn) -> Option<String> {
    crate::dispatch::load::validate::<Auth>(crate::dispatch::load::raw(door))
        .ok()
        .and_then(|v| facts(&v.statement).ok())
        .and_then(|f| f.operator_principal)
}

pub fn stated_facts(
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> Result<AuthFacts, String> {
    stated_facts_raw(crate::dispatch::load::raw(door))
}

pub(crate) fn stated_facts_raw(
    door: busbar_contract::abi::sdk::door::RawDoorFn,
) -> Result<AuthFacts, String> {
    let v = crate::dispatch::load::validate::<Auth>(door)
        .map_err(crate::cold::dispatch::kinds::load_refusal)?;
    facts(&v.statement)
}

/// A Statement string the rendering already owns, kept when it fits; `over` is the refusal.
fn fit(s: String, over: &'static str) -> Result<String, String> {
    if s.len() <= crate::dispatch::plugin::MAX_TEXT {
        Ok(s)
    } else {
        Err(crate::cold::dispatch::kinds::refusal(over))
    }
}

/// The carrier words of `words`, moved (lower-cased) into `out`, the bound facts' own list.
fn carriers(words: &mut [(u32, String)], out: &mut Vec<String>) -> Result<(), String> {
    for (class, word) in words.iter_mut() {
        if *class != MARK_WORD_CARRIER {
            continue;
        }
        if out.len() == MAX_CARRIERS {
            return Err(crate::cold::dispatch::kinds::auth_carriers_over(
                MAX_CARRIERS,
            ));
        }
        let mut word = fit(std::mem::take(word), "an auth carrier name is over-long")?;
        word.make_ascii_lowercase();
        out.push(word);
    }
    Ok(())
}

const MAX_ISSUED: usize = 256;

fn issued(words: &mut [(u32, String)]) -> Result<Option<IssuedShape>, String> {
    use crate::cold::dispatch::kinds as cold;
    let mut slots: [Option<String>; 5] = Default::default();
    let classes = [
        MARK_WORD_ISSUED_ID_PREFIX,
        MARK_WORD_ISSUED_ID_LENGTH,
        MARK_WORD_ISSUED_ID_ALPHABET,
        MARK_WORD_ISSUED_SECRET_LENGTH,
        MARK_WORD_ISSUED_SECRET_ALPHABET,
    ];
    for (class, word) in words.iter_mut() {
        let class = *class;
        let Some(slot) = classes.iter().position(|c| *c == class) else {
            continue;
        };
        if slots[slot].is_some() {
            return Err(cold::issued_twice(class));
        }
        slots[slot] = Some(fit(
            std::mem::take(word),
            "an issued-credential mark is over-long",
        )?);
    }
    if slots.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [prefix, id_len, id_alphabet, secret_len, secret_alphabet] = slots;
    let length = |word: Option<String>, what: &str| -> Result<usize, String> {
        let word = word.ok_or_else(|| cold::issued_missing(what))?;
        match word.parse::<usize>() {
            Ok(n) if (1..=MAX_ISSUED).contains(&n) && word.bytes().all(|b| b.is_ascii_digit()) => {
                Ok(n)
            }
            _ => Err(cold::issued_length(what, &word, MAX_ISSUED)),
        }
    };
    let alphabet = |word: Option<String>, what: &str| -> Result<String, String> {
        let word = word.ok_or_else(|| cold::issued_missing(what))?;
        let graphic = !word.is_empty() && word.bytes().all(|b| b.is_ascii_graphic());
        let mut seen = [false; 128];
        let distinct = word
            .bytes()
            .all(|b| !std::mem::replace(&mut seen[usize::from(b & 0x7f)], true));
        if !graphic || !distinct || word.len() > MAX_ISSUED {
            return Err(cold::issued_alphabet(what, MAX_ISSUED));
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
        return Err(cold::issued_prefix(&shape.id_prefix, id_len));
    }
    Ok(Some(shape))
}

fn facts(st: &Statement) -> Result<AuthFacts, String> {
    let st = Statement {
        kind: KindCode::Auth as u32,
        ..*st
    };
    // SAFETY: the loader's Statement check ran on `st`: every Statement list is its stated count of
    // `'static` entries, and the rendering bounds each tail list and string before it reads it.
    let rendering = unsafe { busbar_contract::abi::mechanism::rendering::render(&st) }
        .map_err(crate::cold::dispatch::kinds::load_refusal)?;
    rendered_facts(&rendering)
}

pub fn rendered_facts(rendering: &[u8]) -> Result<AuthFacts, String> {
    use crate::cold::dispatch::kinds as cold;
    let mut r = busbar_contract::abi::mechanism::rendering::read(rendering)
        .map_err(|e| cold::unreadable("the auth Statement", &e))?;
    if r.kind != KindCode::Auth as u32 {
        return Err(cold::rendering_kind(r.kind, "auth"));
    }

    if r.kind_tail_size == 0 {
        return Err(cold::refusal("an auth plugin states no kind tail"));
    }
    if (r.kind_tail_size as usize) < auth::TAIL_FROZEN {
        return Err(cold::auth_tail_size(r.kind_tail_size, auth::TAIL_FROZEN));
    }
    let mut t = busbar_contract::abi::mechanism::rendering::read_auth_tail(&r.kind_tail)
        .map_err(|e| cold::unreadable("the auth tail's", &e))?;
    // The bound facts, filled in place: each list is the instance's own, kept for its life.
    let mut out = AuthFacts::default();
    carriers(&mut r.mark_words, &mut out.carriers)?;
    let issued = issued(&mut r.mark_words)?;

    if t.facts & auth::FACT_DEFAULT_INBOUND_STYLE != 0 && out.carriers.is_empty() {
        return Err(cold::refusal(
            "the auth tail states the default inbound style and its Statement names no carrier",
        ));
    }

    let logs_in = t.caps & auth::CAP_LOGIN != 0;
    let kind_known = matches!(
        t.login_kind,
        auth::LOGIN_KIND_NONE | auth::LOGIN_KIND_REDIRECT | auth::LOGIN_KIND_CREDENTIAL
    );
    if !kind_known || logs_in != (t.login_kind != auth::LOGIN_KIND_NONE) {
        return Err(cold::auth_login_kind(t.login_kind));
    }

    let inbound_points = check_inbound_points(t.caps, t.inbound_points)
        .map_err(|f| cold::auth_inbound_points(t.inbound_points, f))?;

    let principal = fit(
        std::mem::take(&mut t.operator_principal),
        "the auth operator principal is over-long",
    )?;
    let operator = t.facts & auth::FACT_OPERATOR != 0;
    if operator == principal.is_empty() || (operator && t.caps & auth::CAP_INBOUND == 0) {
        return Err(cold::auth_operator(principal.len()));
    }

    if t.credential_kinds.len() > MAX_CREDENTIAL_KINDS {
        return Err(cold::auth_credential_kinds(t.credential_kinds.len()));
    }
    out.credential_kinds.reserve_exact(t.credential_kinds.len());
    for k in std::mem::take(&mut t.credential_kinds) {
        out.credential_kinds
            .push(fit(k, "an auth credential kind is over-long")?);
    }
    let reads = t.facts & auth::FACT_READS_CREDENTIALS != 0;
    let blank = out.credential_kinds.iter().any(String::is_empty);
    if reads == out.credential_kinds.is_empty()
        || blank
        || (reads && t.caps & auth::CAP_INBOUND == 0)
    {
        return Err(cold::auth_credential_read(out.credential_kinds.len()));
    }

    if issued.is_some() && !reads {
        return Err(cold::refusal(
            "the auth Statement states an issued-credential shape and reads no host-held credential",
        ));
    }

    if t.styles.len() > MAX_STYLES {
        return Err(cold::auth_styles(t.styles.len()));
    }
    if (t.caps & auth::CAP_OUTBOUND != 0) != !t.styles.is_empty() {
        return Err(cold::refusal(
            "the auth tail's outbound capability disagrees with its styles",
        ));
    }
    let mut names = foldhash::HashSet::default();
    out.styles.reserve_exact(t.styles.len());
    for d in &t.styles {
        if d.name.is_empty() || !names.insert(d.name.as_str()) {
            return Err(cold::auth_style_duplicated(&d.name));
        }
        if d.name.len() > crate::dispatch::plugin::MAX_TEXT {
            return Err(cold::refusal("an auth style name is over-long"));
        }
        out.styles.push(OutboundStyle {
            name: cold::statement_text(&d.name),
            flags: d.flags,
            points: d.points,
        });
        check_style_decl(d.flags, d.points)
            .map_err(|f| cold::auth_style_refused(&d.name, d.flags, d.points, f))?;
    }
    for (i, f) in r.families.iter().enumerate() {
        if f.name == auth::METRIC_CACHE_FLUSHED {
            out.cache_family = u32::try_from(i).ok();
        }
    }
    out.secret_refs.reserve_exact(r.secret_refs.len());
    for k in std::mem::take(&mut r.secret_refs) {
        out.secret_refs
            .push(fit(k, "an auth secret-ref key is over-long")?);
    }
    out.caps = t.caps;
    out.facts = t.facts;
    out.login_kind = t.login_kind;
    out.inbound_points = inbound_points;
    out.operator_principal = operator.then_some(principal);
    out.outbound_settings_check = busbar_contract::abi::mechanism::extensions::get(
        &r.extensions.bytes,
        auth::EXT_OUTBOUND_SETTINGS_CHECK,
    ) == Some(&[1][..]);
    out.issued = issued;
    Ok(out)
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

impl crate::dispatch::kind_seal::Validated for Auth {}

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
            slot::SERVE => "serve",
            _ => lifecycle_name(s),
        }
    }

    fn optional_slot(s: u32) -> bool {
        s == slot::TARGET
    }

    /// `serve` may be NULL on a plugin that states no `CAP_PROVISION` (auth::Ops::serve): the
    /// kernel never calls it there.
    fn optional_by_statement(s: u32, st: &Statement) -> bool {
        s == slot::SERVE && facts(st).is_ok_and(|f| f.caps & auth::CAP_PROVISION == 0)
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::VERIFY => {
                let input = a.input::<VerifyIn>()?;
                let buf = &input.out_buf;
                let out = a.out::<IdentifyOut>()?;
                let groups = groups(a, out, buf, VERDICT_IDENTITY, "verify.groups")?;

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
