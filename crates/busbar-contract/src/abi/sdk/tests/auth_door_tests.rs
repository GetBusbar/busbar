// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `auth_verify_door!` over a safe test plugin, driven through its real table: open, every verdict,
//! the short-buffer answer, refresh's flushed count, the ops it does not serve, close. Each answer is
//! judged by the kind's own validator (`check_identify`).

use std::mem::size_of;
use std::ptr;

use crate::abi::auth::{
    check_identify, slot, IdentifyOut, IdentityBuf, NamedValue, Ops, VerifyIn, FACT_CACHEABLE,
    IDENTITY_HAS_TTL, SPAN_ABSENT, VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use crate::abi::mechanism::call::{
    AbiStr, Blob, Envelope, InHead, Op, OutHead, Outcome, RawOutcome, Span, BLOB_ABSENT, BLOB_JSON,
    BLOB_OCTETS, BLOB_SECRET, METRIC_ADD,
};
use crate::abi::mechanism::door::{Door, MetricFamily, FAMILY_COUNTER};
use crate::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, RefreshIn};
use crate::abi::mechanism::ticket::{HostCtx, Ticket};

use super::*;

mod plugin {
    use super::*;
    use crate::abi::sdk::door::{abi_str, statement};

    /// Identifies `good`, rejects `bad`, passes anything else; the `x-alt` carrier stands in for
    /// the credential. Its settings must be `"ok"`.
    pub struct Judge {
        pub flushes: std::sync::atomic::AtomicU64,
    }

    impl VerifyPlugin for Judge {
        const CACHE_FAMILY: Option<u32> = Some(0);

        fn open(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, &'static str> {
            if settings != b"\"ok\"" || secrets != [b"s3cret".as_slice()] {
                return Err("settings: not this plugin's");
            }
            Ok(Judge {
                flushes: std::sync::atomic::AtomicU64::new(0),
            })
        }

        fn verify(&self, r: &VerifyView<'_>) -> Verdict {
            match r.credential().or_else(|| r.carrier("X-Alt")) {
                Some(b"good") => Verdict::Identity(VerifiedIdentity {
                    subject: "alice".into(),
                    name: Some("Alice".into()),
                    groups: vec!["ops".into(), "dev".into()],
                    ttl_secs: Some(60),
                    ..VerifiedIdentity::default()
                }),
                Some(b"bad") => Verdict::Reject,
                _ => Verdict::Pass,
            }
        }

        fn refresh(&self, _: &[u8], _: &[&[u8]]) -> u64 {
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            3
        }
    }

    const TAIL: &AuthTail = &verify_tail(FACT_CACHEABLE);
    const FAMILIES: &[MetricFamily] = &[MetricFamily {
        name: abi_str(crate::abi::auth::METRIC_CACHE_FLUSHED),
        help: abi_str("inbound cache entries dropped by refresh"),
        unit: AbiStr {
            ptr: ptr::null(),
            len: 0,
        },
        label_keys: ptr::null(),
        label_keys_len: 0,
        kind: FAMILY_COUNTER,
        _reserved: [0; 7],
    }];
    const SECRET_REFS: &[AbiStr] = &[abi_str("token")];

    crate::auth_verify_door!(
        Judge,
        with_tail(
            crate::abi::mechanism::door::Statement {
                families: FAMILIES.as_ptr(),
                families_len: FAMILIES.len(),
                secret_refs: SECRET_REFS.as_ptr(),
                secret_refs_len: SECRET_REFS.len(),
                ..statement("judge", "1.0.0", 8)
            },
            TAIL
        )
    );
}

fn ops() -> &'static Ops {
    // SAFETY: the macro's door and table are `'static` consts.
    let d: &Door = unsafe { &*plugin::door() };
    // SAFETY: as above; the door's ops are an auth table.
    unsafe { &*d.ops.cast::<Ops>() }
}

fn absent() -> Blob {
    Blob {
        ptr: ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    }
}

fn blob(b: &[u8], fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

fn head<T>(op: u32) -> InHead {
    InHead {
        size: size_of::<T>() as u32,
        op,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx {
            ptr: ptr::null_mut(),
        },
        ticket: Ticket::NONE,
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: absent(),
    }
}

fn out_head(size: usize) -> OutHead {
    OutHead {
        size: size as u32,
        outcome: RawOutcome::of(Outcome::Fault),
        _reserved: [0; 3],
        wake_at_ns: 0,
        lease: 0,
        error: AbiStr {
            ptr: ptr::null(),
            len: 0,
        },
        envelope: Envelope {
            metrics: ptr::null(),
            metrics_len: 0,
            diags: ptr::null(),
            diags_len: 0,
        },
        extensions: absent(),
    }
}

fn cross<I, O>(op: Option<Op>, instance: *mut std::ffi::c_void, i: &I, o: &mut O) -> Outcome {
    op.expect("every slot is filled")(instance, ptr::from_ref(i).cast(), ptr::from_mut(o).cast())
        .outcome()
}

fn open(settings: &[u8]) -> (Outcome, OpenOut) {
    let secret = [blob(b"s3cret", BLOB_OCTETS, BLOB_SECRET)];
    let input = OpenIn {
        head: head::<OpenIn>(life::OPEN),
        host: ptr::null(),
        settings: blob(settings, BLOB_JSON, 0),
        secrets: secret.as_ptr(),
        secrets_len: 1,
        generation: 1,
    };
    let mut out = OpenOut {
        head: out_head(size_of::<OpenOut>()),
        instance: ptr::null_mut(),
    };
    let o = cross(ops().head.open, ptr::null_mut(), &input, &mut out);
    (o, out)
}

struct Host {
    buf: Vec<u8>,
    groups: Vec<Span>,
}

impl Host {
    fn new(bytes: usize, groups: usize) -> Self {
        Host {
            buf: vec![0; bytes],
            groups: vec![Span { offset: 0, len: 0 }; groups],
        }
    }

    fn out_buf(&mut self) -> IdentityBuf {
        IdentityBuf {
            buf: self.buf.as_mut_ptr(),
            buf_cap: self.buf.len(),
            groups: self.groups.as_mut_ptr(),
            groups_cap: self.groups.len() as u32,
            _reserved: 0,
        }
    }

    /// The group spans the answer reports, as the host reads them.
    fn reported(&self, out: &IdentifyOut) -> &[Span] {
        let n = if o_ready(out) {
            out.identity.groups_len as usize
        } else {
            0
        };
        &self.groups[..n.min(self.groups.len())]
    }

    fn text(&self, s: Span) -> Option<String> {
        (s.offset != SPAN_ABSENT).then(|| {
            String::from_utf8_lossy(&self.buf[s.offset as usize..(s.offset + s.len) as usize])
                .into()
        })
    }
}

fn o_ready(out: &IdentifyOut) -> bool {
    out.head.outcome.outcome() == Outcome::Ready && out.verdict == VERDICT_IDENTITY
}

fn verify(
    instance: *mut std::ffi::c_void,
    credential: Option<&[u8]>,
    carrier: Option<&[u8]>,
    host: &mut Host,
) -> (Outcome, IdentifyOut, VerifyIn) {
    let named = carrier.map(|v| NamedValue {
        name: crate::abi::sdk::door::abi_str("x-alt"),
        value: blob(v, BLOB_OCTETS, BLOB_SECRET),
    });
    // SAFETY: plain C data; all-zero is valid.
    let mut input: VerifyIn = unsafe { std::mem::zeroed() };
    input.head = head::<VerifyIn>(slot::VERIFY);
    input.credential = credential.map_or_else(absent, |c| blob(c, BLOB_OCTETS, BLOB_SECRET));
    input.carrier = named.as_ref().map_or(ptr::null(), ptr::from_ref);
    input.carrier_len = usize::from(named.is_some());
    input.out_buf = host.out_buf();
    // SAFETY: as above.
    let mut out: IdentifyOut = unsafe { std::mem::zeroed() };
    out.head = out_head(size_of::<IdentifyOut>());
    let o = cross(ops().verify, instance, &input, &mut out);
    (o, out, input)
}

#[test]
fn every_verdict_crosses_the_table_and_passes_the_kinds_check() {
    let (o, opened) = open(b"\"ok\"");
    assert_eq!(o, Outcome::Ready);
    let inst = opened.instance;
    assert!(!inst.is_null());

    let mut host = Host::new(64, 4);
    let (o, out, input) = verify(inst, Some(b"good"), None, &mut host);
    assert_eq!(o, Outcome::Ready);
    assert_eq!(out.verdict, VERDICT_IDENTITY);
    check_identify(o, &out, &input.out_buf, host.reported(&out)).expect("the kind's check passes");
    let id = &out.identity;
    assert_eq!(host.text(id.subject).as_deref(), Some("alice"));
    assert_eq!(host.text(id.name).as_deref(), Some("Alice"));
    assert_eq!(host.text(id.key_id), None);
    assert_eq!(id.groups_len, 2);
    assert_eq!(host.text(host.groups[0]).as_deref(), Some("ops"));
    assert_eq!(host.text(host.groups[1]).as_deref(), Some("dev"));
    assert_eq!((id.flags, id.ttl_secs), (IDENTITY_HAS_TTL, 60));

    let (o, out, input) = verify(inst, None, Some(b"good"), &mut host);
    assert_eq!(
        (o, out.verdict),
        (Outcome::Ready, VERDICT_IDENTITY),
        "the carrier is read"
    );
    check_identify(o, &out, &input.out_buf, host.reported(&out)).expect("check");

    for (cred, verdict) in [
        (Some(&b"bad"[..]), VERDICT_REJECT),
        (Some(b"other"), VERDICT_PASS),
        (None, VERDICT_PASS),
    ] {
        let (o, out, input) = verify(inst, cred, None, &mut host);
        assert_eq!((o, out.verdict), (Outcome::Ready, verdict));
        check_identify(o, &out, &input.out_buf, host.reported(&out)).expect("check");
    }
}

#[test]
fn an_identity_that_does_not_fit_is_the_short_answer_and_writes_nothing() {
    let (_, opened) = open(b"\"ok\"");
    let mut host = Host::new(4, 1);
    let (o, out, input) = verify(opened.instance, Some(b"good"), None, &mut host);
    assert_eq!(o, Outcome::Failed);
    assert_eq!((out.needed_bytes, out.needed_groups), (5 + 5 + 3 + 3, 2));
    check_identify(o, &out, &input.out_buf, host.reported(&out)).expect("a legal short answer");
    assert_eq!(host.buf, vec![0; 4], "a short answer writes nothing");

    // One dimension short, the other fitting: still the short answer, both at full size.
    let mut host = Host::new(64, 1);
    let (o, out, input) = verify(opened.instance, Some(b"good"), None, &mut host);
    assert_eq!(
        (o, out.needed_bytes, out.needed_groups),
        (Outcome::Failed, 16, 2)
    );
    check_identify(o, &out, &input.out_buf, host.reported(&out)).expect("legal");
}

#[test]
fn refresh_reports_the_dropped_count_under_the_cache_family() {
    let (_, opened) = open(b"\"ok\"");
    let input = RefreshIn {
        head: head::<RefreshIn>(life::REFRESH),
        generation: 2,
        settings: blob(b"\"ok\"", BLOB_JSON, 0),
        secrets: ptr::null(),
        secrets_len: 0,
    };
    let mut out = out_head(size_of::<OutHead>());
    assert_eq!(
        cross(ops().head.refresh, opened.instance, &input, &mut out),
        Outcome::Ready
    );
    assert_eq!(out.envelope.metrics_len, 1);
    // SAFETY: the plugin's entry, valid until its next lifecycle op.
    let m = unsafe { &*out.envelope.metrics };
    assert_eq!((m.family_idx, m.kind, m.value), (0, METRIC_ADD, 3.0));
}

#[test]
fn a_bad_setting_fails_open_with_the_plugins_text_and_no_instance() {
    let (o, out) = open(b"\"nope\"");
    assert_eq!(o, Outcome::Failed);
    assert!(out.instance.is_null());
    // SAFETY: the plugin's `'static` text.
    let text = unsafe { std::slice::from_raw_parts(out.head.error.ptr, out.head.error.len) };
    assert_eq!(text, b"settings: not this plugin's");
}

#[test]
fn the_ops_it_does_not_serve_are_refused_and_the_tail_states_inbound_only() {
    let t = ops();
    for op in [
        t.begin_login,
        t.complete_login,
        t.open_outbound,
        t.outbound_ready,
        t.fields,
    ] {
        assert!(op.is_some());
    }
    // SAFETY: the door's `'static` Statement and tail.
    let st = unsafe { &*(*plugin::door()).statement };
    // SAFETY: as above.
    let tail = unsafe { &*st.kind_tail.cast::<AuthTail>() };
    assert_eq!(tail.caps, crate::abi::auth::CAP_INBOUND);
    assert_eq!(tail.facts, FACT_CACHEABLE);
}
