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
fn raw_fault_class_round_trips_every_named_class() {
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
