// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plugin/src/hot/pod.rs`.

use super::*;

#[test]
fn handles_reserve_zero_as_none() {
    assert!(AdmissionId::NONE.is_none());
    assert!(EgressId::NONE.is_none());
    assert!(PipeId::NONE.is_none());
    assert!(WorkHandleId::NONE.is_none());
    assert!(VerifyLease::NONE.is_none());
    assert!(Seq::NONE.is_none());
    assert!(!AdmissionId(1).is_none());
}

#[test]
fn every_pod_leads_with_size_version() {
    // The sized-struct discipline: `size` at offset 0, `version` at offset 4, on every struct.
    macro_rules! assert_preamble {
        ($t:ty) => {{
            assert_eq!(
                core::mem::offset_of!($t, size),
                0,
                "size@0 on {}",
                stringify!($t)
            );
            assert_eq!(
                core::mem::offset_of!($t, version),
                4,
                "version@4 on {}",
                stringify!($t)
            );
        }};
    }
    assert_preamble!(Facts);
    assert_preamble!(Usage);
    assert_preamble!(Key);
    assert_preamble!(Signal);
    assert_preamble!(AdmitRefusal);
    assert_preamble!(GovRefusal);
    assert_preamble!(GuardVerdict);
    assert_preamble!(EgressDesc);
    assert_preamble!(EgressHead);
    assert_preamble!(EgressOpen);
    assert_preamble!(EgressFault);
    assert_preamble!(CmdDesc);
    assert_preamble!(FramingDesc);
    assert_preamble!(JournalQuery);
    assert_preamble!(JournalStreamDesc);
    assert_preamble!(ReframeOut);
    assert_preamble!(RestoredHdr);
    assert_preamble!(ChainBreakHdr);
    assert_preamble!(VerifyChainHdr);
    assert_preamble!(OpDesc);
    assert_preamble!(OpResult);
    assert_preamble!(WorkHandleDesc);
    assert_preamble!(VerifyQuery);
    assert_preamble!(ApprovalQuery);
    assert_preamble!(VerifyVerdict);
    assert_preamble!(AuthQuery);
    assert_preamble!(AuthResolved);
    assert_preamble!(IdentityQuery);
    assert_preamble!(IdentityAdmitted);
    assert_preamble!(GateSubjectRef);
    assert_preamble!(GateVerdictOut);
    assert_preamble!(MetricSample);
    assert_preamble!(CounterpartyRef);
    assert_preamble!(CallerRef);
    assert_preamble!(TargetRef);
    assert_preamble!(ContentChunk);
}

// ── The plugin-WRITTEN enum fields cross as raw bytes, never as bare enums ─────────────────────
// A plugin fills `Signal`/`EgressDesc` itself, so every byte in them is attacker-controlled in the
// same way a by-value status return is. Reading a bare `#[repr(u8)]` enum out of such a struct
// materializes an INVALID DISCRIMINANT the moment the host touches it — UB before any `match`. The
// fields carry the `#[repr(transparent)]` raw form and decode through the checked accessors.

/// A `Signal` whose class byte is `7` — a value NO shipped `StatusClass` names. Building it from raw
/// bytes is exactly what an older/newer/hostile plugin does; the host must settle it as `Fault`,
/// never form the invalid enum.
#[test]
fn out_of_range_signal_class_settles_as_fault() {
    let mut bytes = [0u8; core::mem::size_of::<Signal>()];
    bytes[..4].copy_from_slice(&(core::mem::size_of::<Signal>() as u32).to_ne_bytes());
    bytes[4..6].copy_from_slice(&POD_VERSION.to_ne_bytes());
    bytes[core::mem::offset_of!(Signal, class)] = 7;
    bytes[core::mem::offset_of!(Signal, fault_class)] = 200;

    // SAFETY: `Signal` is a `#[repr(C)]` POD of scalars and raw pointers; every field is now a type
    // for which EVERY bit pattern is valid, so any byte image is a valid `Signal`.
    let sig: Signal = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };

    assert_eq!(sig.class.class(), StatusClass::Fault);
    assert_eq!(sig.fault_class.class(), FaultClass::Unspecified);
}

/// The same discipline on the admit side: an unnamed egress kind decodes to `None`, so the host
/// answers `Unsupported` instead of dispatching on a discriminant that does not exist.
#[test]
fn out_of_range_egress_kind_decodes_to_none() {
    assert_eq!(RawEgressKind(0).kind(), Some(EgressKind::Http));
    assert_eq!(RawEgressKind(2).kind(), Some(EgressKind::Subprocess));
    assert_eq!(RawEgressKind(3).kind(), None);
    assert_eq!(RawEgressKind(255).kind(), None);
}

/// Every named class round-trips through its raw carrier unchanged — the encode direction stays
/// lossless while the decode direction stays total.
#[test]
fn raw_fault_class_survives_encode_decode_for_every_named_class() {
    for c in [
        FaultClass::Unspecified,
        FaultClass::RateLimit,
        FaultClass::Overloaded,
        FaultClass::UpstreamError,
        FaultClass::Timeout,
        FaultClass::Network,
        FaultClass::Auth,
        FaultClass::Billing,
        FaultClass::ClientError,
        FaultClass::ContextLength,
    ] {
        assert_eq!(RawFault::of(c).class(), c);
    }
}

/// The metering side of the same class: a plane fills `Usage` itself, so its component byte carries
/// the raw form. Every named component round-trips; every unnamed byte decodes to `None`, which is
/// what makes the host's metering slot REFUSE rather than dispatch on an invalid discriminant.
#[test]
fn raw_usage_component_encodes_decodes_and_refuses_unnamed_bytes() {
    for c in [
        UsageComponent::Tokens,
        UsageComponent::Bytes,
        UsageComponent::Frames,
        UsageComponent::Queries,
    ] {
        assert_eq!(RawUsageComponent::of(c).component(), Some(c));
    }
    assert_eq!(RawUsageComponent(4).component(), None);
    assert_eq!(RawUsageComponent(255).component(), None);
}

/// The journal side: `FramingDesc`/`JournalStreamDesc` are plane-built, so their framing byte carries
/// the raw form too. An unnamed framing decodes to `None` — the host answers `Unsupported` / the
/// reserved invalid sequence instead of reproducing a stream's bytes under a guessed framing.
#[test]
fn raw_framing_encodes_decodes_and_refuses_unnamed_bytes() {
    for f in [Framing::LengthPrefixed, Framing::PipeSeparated] {
        assert_eq!(RawFraming::of(f).framing(), Some(f));
    }
    assert_eq!(RawFraming(2).framing(), None);
    assert_eq!(RawFraming(255).framing(), None);
}

/// The carriers are `#[repr(transparent)]` over `u8`, so swapping the bare enums for them changed no
/// wire byte: the two descriptors and `Usage` keep their exact 1.5.5 layout, and a published plugin's
/// image is read identically. This is the compile-time proof the fix stayed additive.
#[test]
fn the_raw_carriers_are_layout_identical_to_the_bare_enums() {
    assert_eq!(core::mem::size_of::<RawUsageComponent>(), 1);
    assert_eq!(core::mem::align_of::<RawUsageComponent>(), 1);
    assert_eq!(core::mem::size_of::<RawFraming>(), 1);
    assert_eq!(core::mem::align_of::<RawFraming>(), 1);
    assert_eq!(core::mem::offset_of!(Usage, component), 6);
    assert_eq!(core::mem::offset_of!(FramingDesc, framing), 6);
    assert_eq!(core::mem::offset_of!(JournalStreamDesc, framing), 6);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The out-param constructors and the guard-class inverse.
//
// These four PODs were each built by hand at the host's call site, with `size` and `version` spelled
// out every time. Spelling a preamble by hand is the one mistake the sized-struct discipline cannot
// survive -- a `size` that disagrees with the type makes a reader hide fields that ARE written, or
// read fields that are NOT -- so the preamble is now derived from the type and cannot be passed in.
// The behaviour was exercised only through core's call sites before; it is asserted here.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// EVERY out-param constructor stamps the preamble FROM THE TYPE. This is the property that makes
/// the constructors worth having: there is no argument that could make `size` disagree with the
/// layout `abi_layout_matches_golden` pins.
#[test]
fn every_out_param_constructor_stamps_its_own_size_and_version() {
    let gate = GateVerdictOut::new(1, 200, 3, 4);
    assert_eq!(gate.size, core::mem::size_of::<GateVerdictOut>() as u32);
    assert_eq!(gate.version, POD_VERSION);

    let refusal = GovRefusal::new(30, 7);
    assert_eq!(refusal.size, core::mem::size_of::<GovRefusal>() as u32);
    assert_eq!(refusal.version, POD_VERSION);

    let verdict = GuardVerdict::new(true, GuardClass::InternalHost, 9);
    assert_eq!(verdict.size, core::mem::size_of::<GuardVerdict>() as u32);
    assert_eq!(verdict.version, POD_VERSION);

    let auth = AuthResolved::new(42, 1_700_000_000);
    assert_eq!(auth.size, core::mem::size_of::<AuthResolved>() as u32);
    assert_eq!(auth.version, POD_VERSION);
}

/// The constructors carry their arguments through unchanged, and zero the reserved padding — a
/// non-zero reserved byte is what a future minor's field would look like to a newer reader.
#[test]
fn the_out_param_constructors_carry_their_arguments_and_zero_the_padding() {
    let gate = GateVerdictOut::new(0, 403, 11, 5);
    assert_eq!(
        (gate.proceed, gate.status, gate.message_len, gate.hook_len),
        (0, 403, 11, 5)
    );
    assert_eq!(gate._reserved, 0);

    let refusal = GovRefusal::new(30, 7);
    assert_eq!((refusal.retry_after_secs, refusal.reason_len), (30, 7));
    assert_eq!(refusal._reserved, 0);

    let auth = AuthResolved::new(42, 1_700_000_000);
    assert_eq!((auth.resolved_ref, auth.expires_unix), (42, 1_700_000_000));
    assert_eq!((auth._reserved, auth._reserved2), (0, 0));
}

/// A guard verdict keeps the ANSWER and the REASON in separate fields: `verdict` is the refusal,
/// `class` only says why. A reader that could not name the class must still read the refusal.
#[test]
fn a_guard_verdict_separates_the_refusal_from_its_class() {
    let allowed = GuardVerdict::new(false, GuardClass::Allowed, 0);
    assert_eq!(allowed.verdict, 0);
    assert_eq!(allowed.class, GuardClass::Allowed as u8);
    assert_eq!(allowed.reason_len, 0);

    let refused = GuardVerdict::new(true, GuardClass::CloudMetadata, 12);
    assert_eq!(refused.verdict, 1);
    assert_eq!(refused.class, GuardClass::CloudMetadata as u8);
    assert_eq!(refused.reason_len, 12);
    assert_eq!(refused._reserved2, 0);
}

/// `GuardClass::from_u8` is the EXACT inverse of `class as u8` for every declared variant — the
/// round trip a host performs on every guarded URL.
#[test]
fn the_guard_class_byte_round_trips_for_every_variant() {
    for class in [
        GuardClass::Allowed,
        GuardClass::Scheme,
        GuardClass::NoHost,
        GuardClass::CloudMetadata,
        GuardClass::ObfuscatedHost,
        GuardClass::InternalHost,
    ] {
        assert_eq!(GuardClass::from_u8(class as u8), class, "{class:?}");
    }
}

/// An UNKNOWN class byte reads as `Allowed`, never a phantom refusal. A sender at a newer minor may
/// name a class this reader has never heard of; turning "I cannot name this" into a rejection would
/// refuse traffic for no reason. The refusal itself travels in `GuardVerdict::verdict`, which every
/// version agrees on, so an unreadable reason never changes the answer.
#[test]
fn an_unknown_guard_class_byte_is_never_a_phantom_refusal() {
    for byte in [6u8, 7, 99, 255] {
        assert_eq!(
            GuardClass::from_u8(byte),
            GuardClass::Allowed,
            "byte {byte}"
        );
    }
    // ... and the refusal still reads TRUE even when the class byte is unnameable.
    let mut refused = GuardVerdict::new(true, GuardClass::InternalHost, 3);
    refused.class = 200;
    assert_eq!(
        refused.verdict, 1,
        "the answer survives an unreadable reason"
    );
    assert_eq!(GuardClass::from_u8(refused.class), GuardClass::Allowed);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The `EgressDesc` subprocess-tail readers. Both were exercised only through the HOST
// subprocess-open path before they moved here, so these are their first direct cells.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Pack a `u32 len` (LE) + bytes record sequence — the framing `decode_command` reads.
fn pack_records(items: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for it in items {
        out.extend_from_slice(&(it.len() as u32).to_le_bytes());
        out.extend_from_slice(it.as_bytes());
    }
    out
}

#[test]
fn decode_command_splits_program_from_argv() {
    let blob = pack_records(&["/usr/bin/tool", "--flag", "value"]);
    // SAFETY: `blob` is a live, initialized byte range for the call.
    let got = unsafe { decode_command(blob.as_ptr(), blob.len()) };
    assert_eq!(
        got,
        Some((
            "/usr/bin/tool".to_string(),
            vec!["--flag".to_string(), "value".to_string()]
        )),
        "the FIRST record is the program; the rest are argv"
    );
}

#[test]
fn decode_command_takes_a_lone_program_with_empty_argv() {
    let blob = pack_records(&["/bin/echo"]);
    // SAFETY: `blob` is a live, initialized byte range for the call.
    let got = unsafe { decode_command(blob.as_ptr(), blob.len()) };
    assert_eq!(got, Some(("/bin/echo".to_string(), Vec::new())));
}

#[test]
fn decode_command_is_fail_closed_on_unreadable_input() {
    // A null range and a zero-length range are both "no command", never an empty spawn.
    // SAFETY: a null pointer is the documented null case; the len is ignored.
    assert_eq!(unsafe { decode_command(core::ptr::null(), 0) }, None);
    let blob = pack_records(&["/bin/echo"]);
    // SAFETY: `blob` is live; a zero length is the documented empty case.
    assert_eq!(unsafe { decode_command(blob.as_ptr(), 0) }, None);

    // A TRUNCATED record: a length prefix promising more bytes than the block holds. An
    // undecodable command is REFUSED, never guessed into a spawn with the bytes that did parse.
    let mut truncated = pack_records(&["/bin/echo"]);
    truncated.extend_from_slice(&64u32.to_le_bytes());
    truncated.extend_from_slice(b"--partial");
    // SAFETY: `truncated` is a live, initialized byte range for the call.
    assert_eq!(
        unsafe { decode_command(truncated.as_ptr(), truncated.len()) },
        None,
        "a truncated record refuses the whole command"
    );

    // An EMPTY block that is well-formed yields no records at all, so there is no program.
    let empty = pack_records(&[]);
    assert!(empty.is_empty());
}

/// A zeroed `EgressDesc` advertising its full size — the base a cwd cell fills in.
fn blank_egress_desc() -> EgressDesc {
    // SAFETY: `EgressDesc` is a `repr(C)` POD of integers and raw pointers; an all-zero bit
    // pattern is a valid (null-pointer, zero-length) value for every field.
    let mut d: EgressDesc = unsafe { core::mem::zeroed() };
    d.size = core::mem::size_of::<EgressDesc>() as u32;
    d
}

#[test]
fn read_child_cwd_reads_a_written_working_directory() {
    let cwd = "/var/run/child";
    let mut d = blank_egress_desc();
    d.cwd_ptr = cwd.as_ptr();
    d.cwd_len = cwd.len();
    // SAFETY: `cwd` outlives the call, so `(cwd_ptr, cwd_len)` is a live borrowed range.
    assert_eq!(unsafe { read_child_cwd(&d) }, Some(cwd.to_string()));
}

#[test]
fn read_child_cwd_reports_absent_for_an_empty_or_null_field() {
    let mut d = blank_egress_desc();
    // A zeroed tail is a null pointer and a zero length ⇒ inherit the host's cwd.
    // SAFETY: the field is null, which the reader checks before any dereference.
    assert_eq!(unsafe { read_child_cwd(&d) }, None);

    // A non-null pointer with a ZERO length is equally "inherit", not an empty-string cwd — an
    // empty working directory is not a directory a child could be started in.
    let cwd = "/var/run/child";
    d.cwd_ptr = cwd.as_ptr();
    d.cwd_len = 0;
    // SAFETY: the length is zero, so the reader returns before any dereference.
    assert_eq!(unsafe { read_child_cwd(&d) }, None);
}

#[test]
fn read_child_cwd_hides_the_tail_from_a_sender_that_predates_it() {
    // THE SIZED-STRUCT GUARD: a sender whose advertised `size` stops before `cwd_ptr` never wrote
    // the field, so the host must NOT read it — it leaves the host's own cwd untouched instead of
    // reading whatever memory follows a shorter struct.
    let cwd = "/var/run/child";
    let mut d = blank_egress_desc();
    d.cwd_ptr = cwd.as_ptr();
    d.cwd_len = cwd.len();
    d.size = core::mem::offset_of!(EgressDesc, cwd_ptr) as u32;
    // SAFETY: the guard refuses the field on the advertised size, so nothing is dereferenced.
    assert_eq!(
        unsafe { read_child_cwd(&d) },
        None,
        "a pre-minor-8 sender's cwd is hidden, not read past"
    );
}
