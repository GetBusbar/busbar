// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SAFE ABI SURFACE BESIDE THE OPEN FIELDS (status row 194, expand): every accessor,
//! constructor, setter and builder this tree gains before #1471 makes the pointer and length
//! fields private, each held to the field or path it replaces, so a plugin that moves to it reads
//! and writes exactly what it did.

use std::mem::{size_of, MaybeUninit};
use std::ptr;

use super::{Lent, LentList};
use crate::abi::auth::AuthTail;
use crate::abi::export::Tail as ExportTail;
use crate::abi::hook::Tail as HookTail;
use crate::abi::host::conn::connector::Need;
use crate::abi::mechanism::call::{
    AbiStr, Blob, Field, Span, BLOB_ABSENT, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use crate::abi::mechanism::door::{KindTailHead, MetricFamily, Statement};
use crate::abi::mechanism::lifecycle::{OpenIn, TickOut};
use crate::abi::plane::{OnPieceIn, PlaneTail, TrustKey};
use crate::abi::sdk::generation::Gen;
use crate::abi::sdk::out::Out;
use crate::abi::shared::DeclStr;
use crate::abi::transport::route::RouteMatch;
use crate::abi::transport::{Claim, TransportTail};

/// A `T` whose every byte is set, each to its own value, so two fields never read alike by chance.
/// Every struct a call lends is integers, floats, raw pointers and unions of them: any byte
/// pattern is a value of it, and nothing here reads through a pointer.
fn patterned<T>() -> T {
    let mut v = MaybeUninit::<T>::uninit();
    let at = v.as_mut_ptr().cast::<u8>();
    for i in 0..size_of::<T>() {
        // SAFETY: `i < size_of::<T>()`, inside `v`.
        unsafe { at.add(i).write((i as u8).wrapping_mul(31).wrapping_add(7)) };
    }
    // SAFETY: every byte is written, and every byte pattern is a value of the lent structs
    // (above).
    unsafe { v.assume_init() }
}

/// The bytes of `v`, a value with no padding (each `val` field's type: integers, floats, arrays,
/// spans, tickets, contexts and the signal union).
fn bytes_of<T>(v: &T) -> Vec<u8> {
    // SAFETY: `v` is a live `T` of `size_of::<T>()` initialised bytes (no padding, above).
    unsafe { std::slice::from_raw_parts(ptr::from_ref(v).cast::<u8>(), size_of::<T>()) }.to_vec()
}

fn lend<T>(v: &T) -> Lent<'_, T> {
    // SAFETY: nothing reads through a pointer in `v` (the tests compare addresses and values).
    unsafe { Lent::new(v) }
}

/// EVERY FIELD ACCESSOR, from the one list they are stated from: a `val` copies the field's value,
/// a `str`, `blob` or `sub` lends the field itself (the same address).
macro_rules! parity {
    ($($ty:ty { $($how:ident $name:ident $(: $t:ty)?;)+ })+) => {$({
        let v: $ty = patterned();
        let lent = lend(&v);
        $( parity!(@one $how lent, v, $name, $ty); )+
    })+};
    (@one val $lent:ident, $v:ident, $name:ident, $ty:ty) => {
        assert_eq!(
            bytes_of(&$lent.$name()),
            bytes_of(&$v.$name),
            concat!(stringify!($ty), "::", stringify!($name), "(): the field's value")
        );
    };
    (@one $how:ident $lent:ident, $v:ident, $name:ident, $ty:ty) => {
        assert!(
            ptr::eq($lent.$name().lent, &$v.$name),
            concat!(stringify!($ty), "::", stringify!($name), "(): the field itself, lent")
        );
    };
}

#[test]
fn every_field_accessor_reads_the_field_it_is_named_after() {
    lent_field_list!(parity);
}

#[test]
fn a_named_accessor_reads_what_the_deref_read_did() {
    // The spellings a plugin moves from (`input.unit`, `input.get().from`, `input.field(|i|
    // &i.member)`) and to (`input.unit()`, `input.from()`, `input.member()`).
    let member = b"agent-a";
    let mut v: OnPieceIn = patterned();
    v.member = AbiStr {
        ptr: member.as_ptr(),
        len: member.len(),
    };
    let input = lend(&v);
    assert_eq!(input.unit(), input.unit);
    assert_eq!(input.from(), input.get().from);
    assert_eq!(input.attempt_no(), input.get().attempt_no);
    assert_eq!(input.member().bytes(), input.field(|i| &i.member).bytes());
    assert_eq!(input.member().as_str(), Ok("agent-a"));
    assert_eq!(input.head().ticket(), input.head.ticket);
}

#[test]
fn a_lent_blob_states_its_format_flags_and_absence() {
    let json = br#"{"k":1}"#;
    let present = Blob::json(json).with_flags(BLOB_SECRET);
    let b = lend(&present);
    assert_eq!((b.fmt(), b.flags()), (present.fmt, present.flags));
    assert!(!b.is_absent());
    assert_eq!(b.bytes(), json);
    // Absent by format, and absent by a NULL pointer whatever the format says.
    assert!(lend(&Blob::ABSENT).is_absent());
    let null = Blob {
        fmt: BLOB_JSON,
        ..Blob::ABSENT
    };
    assert!(lend(&null).is_absent());
}

#[test]
fn a_lent_string_states_its_absence_as_its_null_pointer() {
    assert!(lend(&AbiStr::ABSENT).is_absent());
    let empty = AbiStr::of("");
    assert!(!lend(&empty).is_absent(), "present and empty is not absent");
    assert_eq!(lend(&empty).is_absent(), empty.ptr.is_null());
}

#[test]
fn a_scalar_is_copied_and_a_scalar_list_is_a_slice() {
    let span = Span { offset: 3, len: 9 };
    assert_eq!(lend(&span).copied(), span);
    let items = [1_u64, 2, 3];
    // SAFETY: `items` lives for the test.
    let list = unsafe { LentList::new(items.as_ptr(), items.len()) };
    assert_eq!(list.as_slice(), &items);
    // SAFETY: a NULL list is empty.
    let none: LentList<'_, u64> = unsafe { LentList::new(ptr::null(), 4) };
    assert!(none.as_slice().is_empty());
}

#[test]
fn an_abi_str_is_made_and_read_as_its_fields_state() {
    const NAME: AbiStr = AbiStr::of("echo");
    assert_eq!((NAME.ptr(), NAME.len()), (NAME.ptr, NAME.len));
    assert_eq!(NAME.ptr(), "echo".as_ptr());
    assert!(!NAME.is_empty() && !NAME.is_absent());
    // SAFETY: `NAME` names program memory.
    assert_eq!(unsafe { NAME.bytes() }, b"echo");
    // SAFETY: as above.
    assert_eq!(unsafe { NAME.as_str() }, Ok("echo"));
    let bytes: &'static [u8] = b"\xff";
    let raw = AbiStr::of_bytes(bytes);
    assert_eq!(
        (raw.ptr, raw.len),
        (AbiStr::over(bytes).ptr, AbiStr::over(bytes).len)
    );
    // SAFETY: as above.
    assert!(unsafe { raw.as_str() }.is_err());
    assert_eq!(
        (AbiStr::ABSENT.ptr, AbiStr::ABSENT.len),
        (AbiStr::ZERO.ptr, AbiStr::ZERO.len)
    );
    assert!(AbiStr::ABSENT.is_absent() && AbiStr::ABSENT.is_empty());
    // SAFETY: an absent string reads as empty.
    assert_eq!(unsafe { AbiStr::ABSENT.bytes() }, b"");
    // SAFETY: `bytes` lives for the test, past every read.
    let parts = unsafe { AbiStr::from_raw_parts(bytes.as_ptr(), 1) };
    assert_eq!((parts.ptr, parts.len), (bytes.as_ptr(), 1));
}

#[test]
fn a_blob_is_made_and_read_as_its_fields_state() {
    const SCHEMA: Blob = Blob::json(br#"{"type":"object"}"#);
    assert_eq!((SCHEMA.fmt, SCHEMA.flags), (BLOB_JSON, 0));
    assert_eq!((SCHEMA.ptr(), SCHEMA.len()), (SCHEMA.ptr, SCHEMA.len));
    // SAFETY: `SCHEMA` names program memory.
    assert_eq!(unsafe { SCHEMA.bytes() }, br#"{"type":"object"}"#);
    let octets = Blob::of(b"ab");
    assert_eq!((octets.fmt, octets.flags, octets.len), (BLOB_OCTETS, 0, 2));
    let secret = octets.with_fmt(BLOB_JSON).with_flags(BLOB_SECRET);
    assert_eq!((secret.ptr, secret.len), (octets.ptr, octets.len));
    assert_eq!((secret.fmt, secret.flags), (BLOB_JSON, BLOB_SECRET));
    assert!(Blob::ABSENT.is_empty() && !octets.is_empty());
    let bytes = b"xyz";
    // SAFETY: `bytes` lives for the test.
    let raw = unsafe { Blob::from_raw_parts(bytes.as_ptr(), 3, BLOB_ABSENT, BLOB_SECRET) };
    assert_eq!(
        (raw.ptr, raw.len, raw.fmt, raw.flags),
        (bytes.as_ptr(), 3, BLOB_ABSENT, BLOB_SECRET)
    );
}

#[test]
fn a_string_lent_for_the_generation_names_the_same_bytes() {
    let owned = String::from("kept");
    // SAFETY: the test's own borrow: `owned` outlives every read below.
    let gen: Gen<'_> = unsafe { Gen::assume() };
    let s = AbiStr::lent(&owned, &gen);
    assert_eq!((s.ptr, s.len), (owned.as_ptr(), owned.len()));
    let b = Blob::lent(owned.as_bytes(), &gen);
    assert_eq!(
        (b.ptr, b.len, b.fmt, b.flags),
        (owned.as_ptr(), 4, BLOB_OCTETS, 0)
    );

    let mut o: TickOut = crate::abi::sdk::test_support::zeroed();
    let mut out = Out::new(&mut o);
    out.error_lent(&owned, &gen);
    assert_eq!(
        (o.head.error.ptr, o.head.error.len),
        (owned.as_ptr(), owned.len())
    );
}

#[test]
fn an_out_names_a_lent_string_and_blob_where_its_field_reads_them() {
    let owned = String::from("named");
    // SAFETY: as above.
    let gen: Gen<'_> = unsafe { Gen::assume() };
    let mut o: TickOut = crate::abi::sdk::test_support::zeroed();
    Out::new(&mut o).lent_str(|o| &o.head.error, &owned, &gen);
    assert_eq!((o.head.error.ptr, o.head.error.len), (owned.as_ptr(), 5));
    // SAFETY: an all-zero `out` is plain data.
    let mut s: crate::abi::export::StatusOut = unsafe { std::mem::zeroed() };
    Out::new(&mut s).lent_blob(|o| &o.status, owned.as_bytes(), BLOB_JSON, &gen);
    let body = s.status;
    assert_eq!(
        (body.ptr, body.len, body.fmt),
        (owned.as_ptr(), 5, BLOB_JSON)
    );
}

#[test]
fn a_decl_str_is_made_and_read_as_its_fields_state() {
    let new = DeclStr::new("h2");
    let of = DeclStr::of("h2");
    assert_eq!((of.ptr(), of.len()), (new.ptr, new.len));
    assert!(!of.is_empty() && !of.is_absent());
    // SAFETY: `of` names program memory.
    assert_eq!(unsafe { of.bytes() }, b"h2");
    assert!(DeclStr::NONE.is_absent() && DeclStr::NONE.is_empty());
    // SAFETY: the bytes live for the test.
    let raw = unsafe { DeclStr::from_raw_parts(b"x".as_ptr(), 1) };
    assert_eq!(raw.len, 1);
}

/// `v` for the program: one address, as a plugin's `'static` rows have (a `const` promoted at
/// each use need not have one).
fn leak<T>(v: T) -> &'static T {
    Box::leak(Box::new(v))
}

fn keys() -> &'static [AbiStr; 2] {
    leak([AbiStr::of("a"), AbiStr::of("b")])
}

#[test]
fn a_statement_list_set_by_its_setter_is_the_pointer_and_length_it_states() {
    let keys = keys();
    let tail = leak(PlaneTail::EMPTY.with_dialects(keys));
    let s = crate::abi::sdk::door::statement("echo", "1.0.0", 8)
        .with_diag_ids(keys)
        .with_claims(&keys[..1])
        .with_kind_tail(tail);
    assert_eq!((s.diag_ids, s.diag_ids_len), (keys.as_ptr(), 2));
    assert_eq!(
        (s.diag_ids_ptr(), s.diag_ids_len()),
        (s.diag_ids, s.diag_ids_len)
    );
    assert_eq!((s.claims, s.claims_len), (keys.as_ptr(), 1));
    assert_eq!(
        s.kind_tail,
        ptr::from_ref(tail).cast::<KindTailHead>(),
        "the kind tail is the tail's own address"
    );
    assert_eq!((tail.dialects, tail.dialects_len), (keys.as_ptr(), 2));
    assert_eq!(s.kind_tail(), s.kind_tail);
    // What the struct-update spelling a plugin moves from stated: the same fields.
    let by_hand = Statement {
        diag_ids: keys.as_ptr(),
        diag_ids_len: keys.len(),
        ..crate::abi::sdk::door::statement("echo", "1.0.0", 8)
    };
    assert_eq!(
        (by_hand.diag_ids, by_hand.diag_ids_len, by_hand.answers_len),
        (s.diag_ids, s.diag_ids_len, s.answers_len)
    );
    // SAFETY: nothing reads the raw list as items.
    let raw = unsafe { Statement::ZERO.with_raw_needs(ptr::null(), 3) };
    assert_eq!((raw.needs, raw.needs_len), (ptr::null(), 3));
    // SAFETY: as above.
    let none = unsafe { Statement::ZERO.with_raw_kind_tail(ptr::null()) };
    assert!(none.kind_tail.is_null());
}

/// `EMPTY` is `ZERO` with its head sized to the whole tail (a row with no head is `ZERO` itself).
fn empty_is_zero<T>(empty: &T, zero: &T, head: Option<u32>) {
    let (e, z) = (bytes_of(empty), bytes_of(zero));
    match head {
        None => assert_eq!(e, z),
        Some(size) => {
            assert_eq!(
                e[..4],
                size.to_ne_bytes(),
                "the head states the tail's size"
            );
            assert_eq!(e[4..], z[4..], "every other byte zero");
        }
    }
}

#[test]
fn an_empty_row_is_the_zero_row_with_its_head_sized() {
    let sized = |n: usize| Some(u32::try_from(n).unwrap());
    empty_is_zero(
        &AuthTail::EMPTY,
        &AuthTail::ZERO,
        sized(size_of::<AuthTail>()),
    );
    empty_is_zero(
        &ExportTail::EMPTY,
        &ExportTail::ZERO,
        sized(size_of::<ExportTail>()),
    );
    // The plane tail has padding (after `stream_ceiling_secs`): its fields are compared, not its
    // bytes.
    let (plane, zero) = (PlaneTail::EMPTY, PlaneTail::ZERO);
    assert_eq!(plane.head.size as usize, size_of::<PlaneTail>());
    assert!(plane.scope.ptr.is_null() && plane.dialects.is_null() && plane.metric_lanes.is_null());
    assert_eq!(
        (
            plane.flags,
            plane.dialects_len,
            plane.admin_routes_len,
            plane.stream_ceiling_secs
        ),
        (
            zero.flags,
            zero.dialects_len,
            zero.admin_routes_len,
            zero.stream_ceiling_secs
        )
    );
    assert_eq!(plane.admin_openapi.fmt, BLOB_ABSENT);
    empty_is_zero(
        &TransportTail::EMPTY,
        &TransportTail::ZERO,
        sized(size_of::<TransportTail>()),
    );
    assert_eq!(HookTail::EMPTY.head.size as usize, size_of::<HookTail>());
    assert!(HookTail::EMPTY.routes.is_null() && HookTail::EMPTY.requested_signals_len == 0);
    empty_is_zero(&Need::EMPTY, &Need::ZERO, None);
    empty_is_zero(&TrustKey::EMPTY, &TrustKey::ZERO, None);
    empty_is_zero(&Claim::EMPTY, &Claim::ZERO, None);
    assert!(RouteMatch::EMPTY.fields.is_null() && RouteMatch::EMPTY.path.ptr.is_null());
    let family = MetricFamily::new(AbiStr::of("n"), AbiStr::of("h"), AbiStr::ABSENT, 1);
    let by_hand = MetricFamily {
        name: AbiStr::of("n"),
        help: AbiStr::of("h"),
        kind: 1,
        ..MetricFamily::ZERO
    };
    assert_eq!(bytes_of(&family), bytes_of(&by_hand));
}

#[test]
fn every_row_list_setter_states_the_pointer_and_length_together() {
    let keys = keys();
    let facts = leak([AbiStr::of("tls")]);
    let pins: &'static [crate::abi::plane::PinMechanism] = &[];
    let tail = PlaneTail::EMPTY
        .with_scope_kinds(keys)
        .with_metric_lanes(&keys[1..]);
    assert_eq!((tail.scope_kinds, tail.scope_kinds_len), (keys.as_ptr(), 2));
    assert_eq!(
        (tail.metric_lanes, tail.metric_lanes_len),
        (keys[1..].as_ptr(), 1)
    );
    assert_eq!(tail.metric_lanes_ptr(), tail.metric_lanes);
    let key = TrustKey::EMPTY.with_mechanisms(pins);
    assert_eq!((key.mechanisms, key.mechanisms_len), (pins.as_ptr(), 0));
    let claim = Claim::EMPTY.with_facts(facts);
    assert_eq!((claim.facts_ptr(), claim.facts_len()), (facts.as_ptr(), 1));
    let transport = TransportTail::EMPTY.with_composes_over(facts);
    assert_eq!(
        (transport.composes_over, transport.composes_over_len),
        (facts.as_ptr(), 1)
    );
    let need = Need::EMPTY
        .with_keep_response_headers(keys)
        .with_deny_response_headers(facts);
    assert_eq!(need.keep_response_headers_len, 2);
    assert_eq!(need.deny_response_headers, facts.as_ptr());
    let auth = AuthTail::EMPTY.with_credential_kinds(facts);
    assert_eq!(
        (auth.credential_kinds, auth.credential_kinds_len),
        (facts.as_ptr(), 1)
    );
    let hook = HookTail::EMPTY.with_requested_signals(leak([1_u32, 2]));
    assert_eq!(hook.requested_signals_len, 2);
    let family =
        MetricFamily::new(AbiStr::of("n"), AbiStr::ABSENT, AbiStr::ABSENT, 0).with_label_keys(keys);
    assert_eq!(
        (family.label_keys, family.label_keys_len),
        (keys.as_ptr(), 2)
    );
}

#[test]
fn a_test_in_sets_exactly_the_fields_its_builders_name() {
    use crate::abi::sdk::test_support::test_in::TestIn;
    let settings = br#"{"timeout_ms":5}"#.to_vec();
    let secrets = [Blob::of(b"s")];
    let mut err = [0_u8; 8];
    let t = TestIn::<OpenIn>::new()
        .settings(&settings)
        .set(|i| &i.generation, 7_u64)
        .list(|i| &i.secrets, |i| &i.secrets_len, &secrets)
        .buffer(|i| &i.err_buf, |i| &i.err_cap, &mut err);
    let i = &t.input;
    assert_eq!(
        (i.settings.ptr, i.settings.len),
        (settings.as_ptr(), settings.len())
    );
    assert_eq!(i.settings.fmt, BLOB_JSON);
    assert_eq!(i.generation, 7);
    assert_eq!((i.secrets, i.secrets_len), (secrets.as_ptr(), 1));
    assert_eq!(i.err_cap, 8);
    assert!(!i.err_buf.is_null());
    assert!(i.host.is_null(), "a builder never names host tables");

    let scope = b"read".to_vec();
    let login = TestIn::<crate::abi::auth::BeginLoginIn>::new()
        .string(|i| &i.state, b"st")
        .strings(|i| &i.scopes, |i| &i.scopes_len, &[scope.as_slice()]);
    let l = &login.input;
    assert_eq!((l.state.len, l.scopes_len), (2, 1));
    // SAFETY: the list is held by `login`, and its string borrows `scope`, both alive here.
    let first = unsafe { *l.scopes };
    assert_eq!((first.ptr, first.len), (scope.as_ptr(), 4));

    let arrive = TestIn::<crate::abi::plane::ArriveIn>::new()
        .blob(|i| &i.body, b"{}", BLOB_JSON)
        .fields(|i| &i.fields, |i| &i.fields_len, &[(&b"k"[..], &b"v"[..])]);
    let a = &arrive.input;
    assert_eq!((a.body.len, a.body.fmt, a.fields_len), (2, BLOB_JSON, 1));
    // SAFETY: the list is held by `arrive`.
    let f: Field = unsafe { *a.fields };
    assert_eq!((f.name.len, f.value.len), (1, 1));

    let blobs = TestIn::<crate::abi::store::OpBlobsIn>::new().blobs(
        |i| &i.records,
        |i| &i.records_len,
        &[&b"x"[..], &b"yz"[..]],
        BLOB_OCTETS,
    );
    assert_eq!(blobs.input.records_len, 2);
    // SAFETY: the list is held by `blobs`.
    let second = unsafe { *blobs.input.records.add(1) };
    assert_eq!((second.len, second.fmt), (2, BLOB_OCTETS));
}

#[test]
fn a_fake_host_lends_its_own_tables() {
    use crate::abi::sdk::conn::Host;
    use crate::abi::sdk::services::{Services, Wake};
    use crate::abi::sdk::test_support::fake::FakeHost;
    let fake = FakeHost::new();
    let tables = fake.lent();
    assert!(ptr::eq(tables.lent, fake.tables_for_tests()));
    // The spelling a plugin moves to compiles before and after #1469: `of(&tables)`.
    let host = Host::of(&tables);
    // SAFETY: the fake's own tables, alive while `fake` is.
    let raw = unsafe { Host::from_raw(fake.tables_for_tests()) };
    assert_eq!(format!("{host:?}"), format!("{raw:?}"));
    assert_eq!(
        Services::of(&tables).is_some(),
        // SAFETY: as above.
        unsafe { Services::from_raw(fake.tables_for_tests()) }.is_some()
    );
    assert_eq!(
        Wake::of(&tables).is_some(),
        // SAFETY: as above.
        unsafe { Wake::from_raw(fake.tables_for_tests()) }.is_some()
    );
}

#[test]
fn a_kept_handle_is_named_by_its_static_alias() {
    use crate::abi::mechanism::ticket::Ticket;
    use crate::abi::sdk::auth_door::{StaticVerifyOp, VerifyOp};
    use crate::abi::sdk::conn::{Host, StaticHost};
    use crate::abi::sdk::services::{StaticServices, StaticWake};
    use crate::abi::sdk::test_support::fake::FakeHost;
    // The aliases are the types themselves: what a plugin keeps in a struct field reads back as
    // the handle it was handed.
    struct Kept {
        host: StaticHost,
        services: Option<StaticServices>,
        wake: Option<StaticWake>,
    }
    let fake = FakeHost::new();
    let tables = fake.lent();
    let kept = Kept {
        host: Host::of(&tables),
        services: Host::of(&tables).services(),
        wake: crate::abi::sdk::services::Wake::of(&tables),
    };
    assert_eq!(
        format!("{:?}", kept.host),
        format!("{:?}", Host::of(&tables))
    );
    assert_eq!(
        kept.services.is_some(),
        Host::of(&tables).services().is_some()
    );
    assert_eq!(kept.wake.is_some(), fake.tables_for_tests().wake.is_some());
    let op: StaticVerifyOp = VerifyOp::new(kept.services, Ticket::NONE);
    assert_eq!(op.services().is_some(), kept.services.is_some());
}

#[test]
fn pick_reads_the_scalar_get_reads() {
    let mut o: TickOut = crate::abi::sdk::test_support::zeroed();
    let mut out = Out::new(&mut o);
    out.set(|o| &o.next_tick_ns, 42);
    out.wake_at(7);
    assert_eq!(out.pick(|o| &o.next_tick_ns), out.get().next_tick_ns);
    assert_eq!(out.pick(|o| &o.head.wake_at_ns), out.get().head.wake_at_ns);
    assert_eq!(out.pick(|o| &o.next_tick_ns), 42);
}

#[test]
#[should_panic(expected = "Out: the picked reference is not a field of the out")]
fn red_pick_reads_a_field_of_the_out_alone() {
    static ELSEWHERE: u64 = 9;
    let mut o: TickOut = crate::abi::sdk::test_support::zeroed();
    let out = Out::new(&mut o);
    let _ = out.pick(|_| &ELSEWHERE);
}

#[test]
fn a_list_reader_reads_the_items_its_setter_named() {
    let keys = keys();
    let s = crate::abi::sdk::door::statement("echo", "1.0.0", 8)
        .with_diag_ids(keys)
        .with_claims(&keys[..1]);
    // SAFETY: each list was set by its setter, over items that live for the program.
    let (diag_ids, claims, needs) = unsafe { (s.diag_ids(), s.claims(), s.needs()) };
    assert!(ptr::eq(diag_ids, &keys[..]));
    assert_eq!((claims.as_ptr(), claims.len()), (s.claims, s.claims_len));
    assert!(needs.is_empty(), "an unset list reads empty");
    let tail = PlaneTail::EMPTY.with_dialects(keys);
    // SAFETY: as above.
    assert_eq!(unsafe { tail.dialects() }.len(), 2);
    let family =
        MetricFamily::new(AbiStr::ABSENT, AbiStr::ABSENT, AbiStr::ABSENT, 0).with_label_keys(keys);
    // SAFETY: as above.
    assert!(ptr::eq(unsafe { family.label_keys() }, &keys[..]));
}
