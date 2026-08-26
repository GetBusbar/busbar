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
