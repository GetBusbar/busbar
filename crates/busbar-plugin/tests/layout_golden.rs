// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ABI-LAYOUT GOLDEN GATE.
//!
//! Records every cross-boundary POD struct's field byte-offsets and size into a COMMITTED golden
//! (`tests/golden/abi-layout.golden`). A reorder/resize/insert WITHOUT a major airlock bump changes
//! an offset and fails this test — the machine check behind the "append-only, major-airlock" rule.
//!
//! Offsets are stable across the 64-bit targets busbar ships (pointers/`usize` are 8 bytes on
//! x86_64 and aarch64 alike; every field here is a fixed-width scalar or pointer), so ONE golden
//! covers them. Re-seed intentionally with `BUSBAR_UPDATE_GOLDEN=1 cargo test -p busbar-plugin`.

use busbar_plugin::hot::decl::{BuildCtx, PlaneDecl};
use busbar_plugin::hot::host::PlaneHostVtable;
use busbar_plugin::hot::workitem::{EmitHandle, InboundHandle, WorkItem};
use busbar_plugin::hot::*;
use busbar_plugin::AbiPreamble;
use std::fmt::Write as _;

/// Append `Struct.field=offset` lines for the given fields, then a `Struct.__size=N` line.
macro_rules! record {
    ($out:expr, $t:ty, [$($field:ident),* $(,)?]) => {{
        $(
            writeln!(
                $out,
                "{}.{}={}",
                stringify!($t),
                stringify!($field),
                std::mem::offset_of!($t, $field)
            ).unwrap();
        )*
        writeln!($out, "{}.__size={}", stringify!($t), std::mem::size_of::<$t>()).unwrap();
        writeln!($out, "{}.__align={}", stringify!($t), std::mem::align_of::<$t>()).unwrap();
    }};
}

fn compute_layout() -> String {
    let mut s = String::new();

    record!(s, AbiPreamble, [magic, abi_major, abi_minor]);

    record!(
        s,
        Facts,
        [
            size,
            version,
            _reserved,
            tokens,
            budget_remaining,
            tenant_id,
            priority,
            flags,
            pool_name_ptr,
            pool_name_len,
            identity_id_ptr,
            identity_id_len,
            group_ptr,
            group_len
        ]
    );
    record!(
        s,
        Usage,
        [
            size,
            version,
            component,
            _reserved,
            amount,
            unit_cost_micros,
            admission,
            key_id_ptr,
            key_id_len,
            model_ptr,
            model_len,
            provider_ptr,
            provider_len
        ]
    );
    record!(
        s,
        Key,
        [
            size,
            version,
            _reserved,
            scope,
            _reserved2,
            key_ptr,
            key_len,
            drift_state
        ]
    );
    record!(
        s,
        Signal,
        [
            size,
            version,
            class,
            _reserved,
            latency_nanos,
            bytes,
            fault_class,
            fault_flags,
            _reserved2,
            _reserved3,
            retry_after_secs,
            provider_signal_ptr,
            provider_signal_len
        ]
    );
    record!(
        s,
        AdmitRefusal,
        [size, version, reason, _reserved, retry_after_secs]
    );
    record!(
        s,
        GovRefusal,
        [size, version, _reserved, retry_after_secs, reason_len]
    );
    record!(
        s,
        GuardVerdict,
        [size, version, _reserved, verdict, class, _reserved2, reason_len]
    );
    record!(
        s,
        EgressDesc,
        [
            size,
            version,
            kind,
            _reserved,
            allowlist_scope,
            _reserved2,
            target_ptr,
            target_len,
            client_identity_ref,
            credential_ref,
            verb_ptr,
            verb_len,
            headers_ptr,
            headers_len,
            body_ptr,
            body_len,
            cred_header_ptr,
            cred_header_len,
            cred_scheme_ptr,
            cred_scheme_len,
            env_ptr,
            env_len,
            cwd_ptr,
            cwd_len,
            stderr_inherit,
            _reserved3,
            trust_anchor_ref,
            timeout_ms,
            resolved_addr,
            resolved_addr_kind,
            _reserved4
        ]
    );
    record!(
        s,
        EgressHead,
        [
            size,
            version,
            status_code,
            observed_spki_ptr,
            observed_spki_len,
            resp_headers_ptr,
            resp_headers_len,
            client_identity_offered,
            _reserved4
        ]
    );
    record!(s, EgressOpen, [size, version, _reserved, id, pipe, head]);
    record!(
        s,
        EgressFault,
        [
            size,
            version,
            fail_class,
            _reserved,
            status_code,
            _reserved2,
            cause_len,
            url_len
        ]
    );
    record!(
        s,
        CmdDesc,
        [
            size,
            version,
            argv_count,
            program_ptr,
            program_len,
            argv_ptr,
            argv_len
        ]
    );
    record!(s, FramingDesc, [size, version, framing, digests_scope]);
    record!(
        s,
        JournalQuery,
        [size, version, _reserved, scope, _reserved2, from_seq, limit]
    );
    record!(
        s,
        JournalStreamDesc,
        [
            size,
            version,
            framing,
            digests_scope,
            kind_id,
            _reserved,
            kind_ptr,
            kind_len
        ]
    );
    record!(
        s,
        ReframeOut,
        [
            size,
            version,
            digests_scope,
            _r,
            seq,
            prev_len,
            hash_len,
            suffix_len
        ]
    );
    record!(
        s,
        RestoredHdr,
        [
            size,
            version,
            _reserved,
            scopes,
            records,
            empty_scopes,
            chain_breaks
        ]
    );
    record!(
        s,
        ChainBreakHdr,
        [size, version, broke, _reserved, _reserved2, at_index, seq]
    );
    record!(
        s,
        VerifyChainHdr,
        [size, version, verified, _reserved, _reserved2, at_index, seq]
    );
    record!(
        s,
        OpDesc,
        [
            size,
            version,
            _reserved,
            depth,
            _reserved2,
            correlation_id,
            work_ptr,
            work_len
        ]
    );
    record!(
        s,
        OpResult,
        [size, version, class, _reserved, body_len, seq]
    );
    record!(
        s,
        WorkHandleDesc,
        [size, version, _reserved, scope, ttl_secs, correlation_id]
    );
    record!(
        s,
        VerifyVerdict,
        [size, version, outcome, _reserved, lease, digest_ptr, digest_len]
    );
    record!(
        s,
        AuthQuery,
        [
            size,
            version,
            _reserved,
            credential_ref,
            audience_ptr,
            audience_len
        ]
    );
    record!(
        s,
        AuthResolved,
        [
            size,
            version,
            _reserved,
            _reserved2,
            resolved_ref,
            expires_unix
        ]
    );
    record!(
        s,
        IdentityQuery,
        [
            size,
            version,
            _reserved,
            token_present,
            _reserved2,
            token_ptr,
            token_len,
            audience_ptr,
            audience_len,
            resource_ptr,
            resource_len
        ]
    );
    record!(
        s,
        IdentityAdmitted,
        [size, version, outcome, _reserved, _reserved2, identity]
    );
    record!(
        s,
        GateSubjectRef,
        [
            size,
            version,
            plane_key,
            key_present,
            incremental,
            _reserved,
            request_id,
            container_ptr,
            container_len,
            method_ptr,
            method_len,
            args_ptr,
            args_len,
            key_id_ptr,
            key_id_len,
            key_name_ptr,
            key_name_len,
            session_id_ptr,
            session_id_len
        ]
    );
    record!(
        s,
        GateVerdictOut,
        [
            size,
            version,
            proceed,
            _reserved,
            status,
            message_len,
            hook_len
        ]
    );
    record!(
        s,
        MetricSample,
        [
            size, version, _reserved, _reserved2, value_bits, name_ptr, name_len, labels_ptr,
            labels_len
        ]
    );
    record!(
        s,
        VerifyQuery,
        [
            size,
            version,
            _reserved,
            last_checked_present,
            _reserved2,
            ttl_ms,
            now_ms,
            last_checked_ms
        ]
    );
    record!(
        s,
        ApprovalQuery,
        [size, version, _reserved, scope, _reserved2, expires_at, now, key_ptr, key_len]
    );
    record!(
        s,
        CounterpartyRef,
        [
            size,
            version,
            _reserved,
            scope,
            _reserved2,
            ref_ptr,
            ref_len,
            identity_live,
            grant_outcome,
            registration_state,
            artifact_outcome,
            fact_flags,
            _reserved3,
            _reserved4,
            generation_admitted,
            generation_live
        ]
    );
    record!(
        s,
        CallerRef,
        [size, version, _reserved, scope, _reserved2, ref_ptr, ref_len]
    );
    record!(
        s,
        TargetRef,
        [size, version, _reserved, scope_kind, _reserved2, ref_ptr, ref_len]
    );
    record!(
        s,
        ContentChunk,
        [size, version, is_final, _reserved, session_id, offset, data_ptr, data_len]
    );
    record!(s, OpaqueState, [ptr, free]);

    // The WorkItem keystone + its tagged handles.
    record!(s, InboundHandle, [kind, _reserved, id, ptr, len]);
    record!(s, EmitHandle, [kind, _reserved, id]);
    record!(s, WorkItem, [size, version, _reserved, inbound, emit]);

    // The two vtable headers (preamble + sized header). Slot offsets follow deterministically from
    // `__size`/`__align`; pinning the header offsets + total size catches any reshuffle.
    record!(s, PlaneHostVtable, [abi, size, version]);
    record!(
        s,
        BuildCtx,
        [
            size,
            version,
            _reserved,
            _reserved2,
            host,
            host_ctx,
            config_ptr,
            config_len,
            resolved_refs_ptr,
            resolved_refs_len
        ]
    );
    record!(
        s,
        PlaneDecl,
        [
            abi,
            size,
            version,
            name_ptr,
            name_len,
            section_key_ptr,
            section_key_len,
            scope_ptr,
            scope_len,
            label_ptr,
            label_len,
            provided_carriers,
            _reserved
        ]
    );

    s
}

#[test]
fn abi_layout_matches_golden() {
    let actual = compute_layout();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/abi-layout.golden"
    );

    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let update = std::env::var_os("BUSBAR_UPDATE_GOLDEN").is_some();

    if update || existing.trim().is_empty() {
        std::fs::write(path, &actual).expect("write golden");
        // On a seed run, do not also assert (the file was just written to match).
        return;
    }

    assert_eq!(
        existing, actual,
        "\nABI LAYOUT DRIFT: a POD field offset/size changed.\n\
         If this is an APPEND-ONLY tail addition, bump the airlock MINOR and re-seed with \
         `BUSBAR_UPDATE_GOLDEN=1`.\n\
         If it is a REORDER/RESIZE/INSERT, that is a MAJOR airlock break — do not re-seed \
         without bumping ABI_MAJOR.\n"
    );
}
