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

use busbar_contract::abi::host::conn::{ConnCtx, ConnSlots, WireOpenDesc, WirePiece};
use busbar_contract::abi::hot::decl::{
    BuildCtx, DeclBillableClass, DeclMetricFamily, DeclServedOpClass, DeclStr, PlaneDecl,
};
use busbar_contract::abi::hot::host::PlaneHostVtable;
use busbar_contract::abi::hot::transport::{
    CarrierSlots, DeclByteList, DeclClaim, DeclStrList, FramerSlots, TransportDecl, WireBytesOut,
    WireConnFacts, WireDest, WireEnvPair, WireField, WireFramed, WireFramerOut, WireSettings,
    WireWaker,
};
use busbar_contract::abi::hot::workitem::{EmitHandle, HeadField, InboundHandle, WorkItem};
use busbar_contract::abi::hot::*;
use busbar_contract::abi::AbiPreamble;
// THE ONE MEMORY ABI (M0 ABI-SPEC): aliased, so a name the hot lane also uses cannot collide.
use busbar_contract::abi::mechanism::call::{
    AbiStr as MechStr, Blob as MechBlob, Diag as MechDiag, Envelope as MechEnvelope,
    Field as MechField, InHead as MechInHead, MetricEntry as MechMetricEntry,
    OutHead as MechOutHead, RawOutcome as MechRawOutcome, Span as MechSpan,
};
use busbar_contract::abi::mechanism::door::{
    Door as MechDoor, KindTailHead as MechKindTailHead, MarkWord as MechMarkWord,
    MetricFamily as MechMetricFamily, Rewrite as MechRewrite, Section as MechSection,
    Statement as MechStatement,
};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn as MechCancelIn, CancelOut as MechCancelOut, DriveIn as MechDriveIn,
    GenIn as MechGenIn, OpenIn as MechOpenIn, OpenOut as MechOpenOut, OpsHead as MechOpsHead,
    RefreshIn as MechRefreshIn, ReleaseIn as MechReleaseIn, TickIn as MechTickIn,
    TickOut as MechTickOut, ValidateIn as MechValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{
    CompletionHandle as MechCompletionHandle, HostCtx as MechHostCtx, HostTables as MechHostTables,
    Ticket as MechTicket,
};
use busbar_contract::abi::{
    auth::Ops as AuthOps, plane::Ops as PlaneOps, store::Ops as StoreOps,
    transport::Ops as TransportOps,
};
// M3-SHAPES (abi-v2-perkind.md B.2/B.4/B.5): the secret/hook/export kinds' own ops and shapes.
use busbar_contract::abi::export::{
    CheckIn as ExportCheckIn, CheckInstance as ExportCheckInstance, CheckOut as ExportCheckOut,
    DeliverIn as ExportDeliverIn, Ops as ExportOps, Route as ExportRoute,
    ScrapeFamily as ExportScrapeFamily, ScrapeIn as ExportScrapeIn,
    ScrapeLabel as ExportScrapeLabel, ScrapeOut as ExportScrapeOut,
    ScrapeSample as ExportScrapeSample, ServeIn as ExportServeIn, ServeOut as ExportServeOut,
    StatusOut as ExportStatusOut, Tail as ExportTail,
};
use busbar_contract::abi::hook::{
    BudgetBucketState as HookBudgetBucketState, CandidateDynamic as HookCandidateDynamic,
    CandidateStatic as HookCandidateStatic, ConfigureIn as HookConfigureIn,
    ConfigureOut as HookConfigureOut, DecideIn as HookDecideIn, DecideOut as HookDecideOut,
    DescribeOut as HookDescribeOut, NotifyIn as HookNotifyIn, Ops as HookOps,
    PromptView as HookPromptView, RequestView as HookRequestView, Route as HookRoute,
    ServeIn as HookServeIn, ServeOut as HookServeOut, SignalEntry as HookSignalEntry,
    SignalValue as HookSignalValue, StageView as HookStageView, StatusOut as HookStatusOut,
    Tail as HookTail, TransformOut as HookTransformOut, UserView as HookUserView,
};
use busbar_contract::abi::secret::{
    Ops as SecretOps, ResolveIn as SecretResolveIn, ResolveOut as SecretResolveOut,
};
// THE AUTH KIND (v3, design B.3): aliased, as the mechanism's are.
use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn as AuthBeginLoginIn, BeginLoginOut as AuthBeginLoginOut,
    CompleteLoginIn as AuthCompleteLoginIn, FieldSpan as AuthFieldSpan, FieldsIn as AuthFieldsIn,
    FieldsOut as AuthFieldsOut, IdentifyOut as AuthIdentifyOut, IdentityBuf as AuthIdentityBuf,
    IdentityOut as AuthIdentityOut, LoginField as AuthLoginField, NamedValue as AuthNamedValue,
    OpenOutboundIn as AuthOpenOutboundIn, OpenOutboundOut as AuthOpenOutboundOut,
    OutboundReadyIn as AuthOutboundReadyIn, OutboundReadyOut as AuthOutboundReadyOut,
    RequestFacts as AuthRequestFacts, StyleDecl as AuthStyleDecl, VerifyIn as AuthVerifyIn,
};
// THE PLANE AND TRANSPORT KINDS and THE HOST CONNECTOR: aliased, so the hot lane's names cannot collide.
use busbar_contract::abi::host::conn::connector as hconn;
use busbar_contract::abi::host::service as hsvc;
use busbar_contract::abi::plane as pkind;
use busbar_contract::abi::transport as tkind;
// THE STORE KIND (v3): aliased with a `Store` prefix so a golden line names its kind.
use busbar_contract::abi::store::{
    AddUsageBatchIn as StoreAddUsageBatchIn, AddUsageIn as StoreAddUsageIn,
    AppendBatchIn as StoreAppendBatchIn, AppendPlaneRecordIn as StoreAppendPlaneRecordIn,
    BlobIn as StoreBlobIn, CellGrant as StoreCellGrant, CountOut as StoreCountOut,
    GetPlaneRecordIn as StoreGetPlaneRecordIn, HeadOut as StoreHeadOut, HeadsOut as StoreHeadsOut,
    HostBlobs as StoreHostBlobs, HostBuf as StoreHostBuf, HostBytesOut as StoreHostBytesOut,
    HostListOut as StoreHostListOut, HostRecords as StoreHostRecords,
    HostSessions as StoreHostSessions, IdIn as StoreIdIn, IdReasonIn as StoreIdReasonIn,
    KeyWithCredentialIn as StoreKeyWithCredentialIn, KindBeforeIn as StoreKindBeforeIn,
    KindIdIn as StoreKindIdIn, LeasedBlobOut as StoreLeasedBlobOut,
    LeasedListOut as StoreLeasedListOut, LeasedStrListOut as StoreLeasedStrListOut,
    ListPlaneRecordsIn as StoreListPlaneRecordsIn, OpBlobIn as StoreOpBlobIn,
    OpBlobsIn as StoreOpBlobsIn, OpId as StoreOpId, PlaneRecordRow as StorePlaneRecordRow,
    PutUsageIn as StorePutUsageIn, RecordEntry as StoreRecordEntry,
    RecordGetIn as StoreRecordGetIn, RecordPutIn as StoreRecordPutIn,
    RecordScanIn as StoreRecordScanIn, ReleaseItem as StoreReleaseItem,
    ReserveIn as StoreReserveIn, ReserveOut as StoreReserveOut, SessionPutIn as StoreSessionPutIn,
    SessionRow as StoreSessionRow, SessionsForIn as StoreSessionsForIn,
    SliceReleaseIn as StoreSliceReleaseIn, SliceReleaseOut as StoreSliceReleaseOut,
    StoreTail as StoreStoreTail, StreamHead as StoreStreamHead, TokenIn as StoreTokenIn,
    U64In as StoreU64In, UnitCell as StoreUnitCell,
    UpsertPlaneRecordIn as StoreUpsertPlaneRecordIn, UsageCell as StoreUsageCell,
    VerdictOut as StoreVerdictOut, WindowCap as StoreWindowCap, WindowCapsIn as StoreWindowCapsIn,
    WindowIn as StoreWindowIn,
};
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
            admission,
            key_id_ptr,
            key_id_len,
            model_ptr,
            model_len,
            provider_ptr,
            provider_len,
            units_ptr,
            units_len
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
    record!(
        s,
        WorkItem,
        [
            size,
            version,
            _reserved,
            inbound,
            emit,
            // The dispatch's own host and reply (minor 23).
            host,
            host_ctx,
            reply_ptr,
            reply_cap,
            reply_written,
            // The request head and the answer's head and stream (minor 30).
            head,
            head_read,
            emit_head,
            stream,
            emit_body
        ]
    );
    record!(s, HeadField, [name_ptr, name_len, value_ptr, value_len]);

    // The two vtable headers (preamble + sized header), then the slots themselves. (Slot offsets do
    // NOT "follow deterministically" from the header — every slot is one pointer wide, so the
    // offsets are identical under any permutation and only the recorded NAME→offset pairing
    // distinguishes them.)
    // `__size`/`__align`; pinning the header offsets + total size catches any reshuffle.
    // The host vtable: the two headers AND every fn-pointer slot. Pinning only the headers left the
    // gate blind to the one drift a golden is uniquely able to catch — two slots of the SAME
    // signature swapping places. Sizes and offsets are then identical, every build still compiles,
    // and a published plugin silently calls the wrong host capability through the right-looking
    // slot. Recording each slot's own offset by NAME is what makes that a failure.
    record!(
        s,
        PlaneHostVtable,
        [
            abi,
            size,
            version,
            govern_admit,
            meter_charge,
            breaker_admit,
            breaker_settle,
            verify_lookup,
            verify_store,
            egress_open,
            egress_poll,
            egress_write,
            egress_close,
            journal_append,
            journal_read,
            nested_dispatch,
            workhandle_open,
            workhandle_resume,
            drift_quarantine,
            approval_redeem,
            metrics_emit,
            clock_now,
            auth_resolve,
            trust_evaluate,
            entitlement_check,
            gate_scan,
            breaker_admit_reason,
            verify_decide,
            approval_redeem_q,
            govern_admit_reason,
            pipe_read,
            pipe_write,
            egress_fault,
            journal_register,
            journal_append_scoped,
            journal_read_scoped,
            journal_restore,
            journal_seed,
            journal_forget,
            journal_compact,
            journal_verify_scoped,
            subkey_sign,
            guard_url,
            identity_admit,
            gate_decide,
            counter_add,
            // The host services (minor 30).
            entropy_fill,
            wall_clock,
            tap_fault_latch,
            translate_cap
        ]
    );
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
            resolved_refs_len,
            // The deployment's public URL (minor 23).
            public_url_ptr,
            public_url_len
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
            _reserved,
            // The export slots, for the same reason as the host vtable's: `build`/`hydrate`/`start`
            // share a shape, and swapping two of them is invisible to every other check.
            config_validate,
            build,
            hydrate,
            start,
            admin_routes,
            openapi,
            dispatch,
            // The declaration tail (minor 22).
            fallback,
            _reserved2,
            subject_noun,
            admin_noun,
            audit_kind,
            signing_domain,
            signing_kid_prefix,
            scope_kinds_ptr,
            scope_kinds_len,
            owned_sections_ptr,
            owned_sections_len,
            billable_classes_ptr,
            billable_classes_len,
            fee_units_ptr,
            fee_units_len,
            // The plane's door (minor 23).
            claims,
            admission,
            metric_families_ptr,
            metric_families_len,
            // The served operation classes (minor 28).
            served_op_classes_ptr,
            served_op_classes_len,
            // The plane-record kinds (minor 29).
            record_kinds_ptr,
            record_kinds_len,
            // How its dispatch runs (minor 31).
            dispatch_flags,
            _reserved3,
            // The required config sections (minor 34).
            required_sections_ptr,
            required_sections_len
        ]
    );
    record!(s, DeclStr, [ptr, len]);
    record!(s, DeclBillableClass, [class, family]);
    record!(
        s,
        DeclMetricFamily,
        [name, kind, label_keys_ptr, label_keys_len]
    );
    record!(s, DeclServedOpClass, [op, name]);

    // The TRANSPORT decl, generation 2 (minor 31, TRANSPORT-STACK): the header, the ROW (every
    // constant the transport declares) and exactly one role's slot table. Several fields are
    // same-width neighbours (the `DeclStr`s, the flag bytes, the two table pointers) — a swap is
    // invisible to everything but this.
    record!(
        s,
        TransportDecl,
        [
            abi,
            size,
            version,
            key,
            composes_over,
            selector_forms,
            egress_selector_forms,
            handoff_from,
            handoff_to,
            handoff_binding_fact,
            upgrades_to,
            handshake_frame_kind,
            transport_facts,
            status_namespace,
            framing,
            session,
            session_bound,
            decodes_payload,
            unit0_trigger,
            handshake_max_steps,
            status_at,
            _reserved,
            init,
            carrier,
            framer,
            // The claims (minor 33).
            claims_ptr,
            claims_len
        ]
    );
    // One claim of the entry, lowered field for field from `Claim`.
    record!(
        s,
        DeclClaim,
        [
            key,
            selector_forms,
            transport_facts,
            status_namespace,
            session,
            session_bound,
            unit0_trigger,
            status_at,
            _reserved
        ]
    );
    // One slot per `Carrier` method, named for it: every poll slot is a same-width fn pointer, so a
    // swap of two is invisible to everything but this.
    record!(
        s,
        CarrierSlots,
        [
            size,
            _reserved,
            listen,
            poll_accept,
            dial,
            poll_read,
            poll_write,
            poll_flush,
            poll_close,
            arrival
        ]
    );
    // One slot per `Framer` method, named for it.
    record!(
        s,
        FramerSlots,
        [
            size,
            _reserved,
            locate,
            open,
            ingest,
            emit,
            encode_envelope,
            refusal,
            close,
            detach,
            adopt,
            // The clock seam.
            tick
        ]
    );
    record!(s, DeclStrList, [ptr, len]);
    record!(s, DeclByteList, [ptr, len]);
    record!(
        s,
        WireSettings,
        [
            size,
            version,
            upstream_http1_only,
            upstream_h2_prior_knowledge,
            pool_max_idle_per_host,
            pool_idle_timeout_secs,
            request_body_max_bytes,
            response_body_max_bytes,
            request_timeout_secs
        ]
    );
    // The host's waker handle: the ONE service the host hands a transport.
    record!(s, WireWaker, [size, version, wake]);
    record!(
        s,
        WireDest,
        [size, kind, _reserved, authority, program, args, env, env_len]
    );
    record!(s, WireEnvPair, [name, value]);
    record!(
        s,
        WireConnFacts,
        [
            size,
            version,
            sni,
            alpn,
            cert_subject,
            cert_issuer,
            cert_fingerprint,
            // The resolved claim (minor 33).
            claim
        ]
    );
    record!(
        s,
        WireFramed,
        [
            size,
            end_of_frame,
            status_class,
            flags,
            _reserved,
            stream,
            bytes,
            len,
            status_code,
            _reserved2,
            retry_after_secs
        ]
    );
    record!(
        s,
        WireFramerOut,
        [
            ctx,
            send,
            frame,
            end,
            // The host's clock.
            now_monotonic_nanos,
            now_unix_nanos,
            wake_at
        ]
    );
    record!(s, WireBytesOut, [ctx, put]);
    record!(s, WireField, [name, value]);

    // THE CONNECTION TABLE: one slot per `Conns` operation, the open descriptor and the
    // piece a read writes. Several fields are same-width neighbours — a swap is invisible to all
    // but this.
    record!(s, ConnCtx, [ptr]);
    record!(
        s,
        ConnSlots,
        [size, _reserved, open, write, read, wait, facts, close]
    );
    record!(
        s,
        WireOpenDesc,
        [
            size,
            _reserved,
            target,
            fields,
            fields_len,
            body,
            body_len,
            timeout_ms,
            method,
            head_target
        ]
    );
    record!(
        s,
        WirePiece,
        [
            size,
            kind,
            end,
            status_class,
            flags,
            stream,
            len,
            code,
            _reserved,
            ns,
            retry_after_secs,
            reason
        ]
    );

    // THE ONE MEMORY ABI (`BUSBAR-1.6.0.md` THE DESIGN, §11.5): the shared mechanism and the seven kind
    // tables. This golden is the ONE layout pin (`abi-audit` F2).
    record!(s, MechRawOutcome, []);
    record!(s, MechStr, [ptr, len]);
    record!(s, MechBlob, [ptr, len, fmt, flags]);
    record!(s, MechSpan, [offset, len]);
    record!(s, MechField, [name, value]);
    record!(
        s,
        MechInHead,
        [
            size,
            op,
            flags,
            deadline_class,
            _reserved,
            host,
            ticket,
            deadline_ns,
            trace_id,
            parent_span_id,
            extensions
        ]
    );
    record!(
        s,
        MechMetricEntry,
        [
            family_idx,
            kind,
            _reserved,
            value,
            label_vals,
            label_vals_len
        ]
    );
    record!(s, MechDiag, [id_idx, severity, _reserved, text]);
    record!(s, MechEnvelope, [metrics, metrics_len, diags, diags_len]);
    record!(
        s,
        MechOutHead,
        [size, outcome, _reserved, wake_at_ns, lease, error, envelope, extensions]
    );
    record!(
        s,
        MechDoor,
        [
            magic,
            mechanism_version,
            size,
            kind,
            kind_abi,
            statement,
            ops
        ]
    );
    record!(
        s,
        MechMetricFamily,
        [
            name,
            help,
            unit,
            label_keys,
            label_keys_len,
            kind,
            _reserved
        ]
    );
    record!(
        s,
        MechStatement,
        [
            size,
            kind,
            kind_abi,
            max_inflight,
            name,
            version,
            families,
            families_len,
            diag_ids,
            diag_ids_len,
            kind_tail,
            extensions,
            secret_refs,
            secret_refs_len,
            settings_schema,
            marks,
            mark_words,
            mark_words_len,
            rewrites,
            rewrites_len,
            sections,
            sections_len,
            needs,
            needs_len,
            target_from,
            trust_from,
            answers,
            answers_len,
            claims,
            claims_len
        ]
    );
    record!(s, MechMarkWord, [class, _reserved, word]);
    record!(s, MechRewrite, [class, _reserved, from, to]);
    record!(s, MechSection, [name, flags, _reserved]);
    record!(s, MechKindTailHead, [size, _reserved]);
    record!(s, MechTicket, [slot, generation]);
    record!(s, MechCompletionHandle, [ticket, seq, _reserved]);
    record!(s, MechHostCtx, [ptr]);
    record!(
        s,
        MechHostTables,
        [size, _reserved, ctx, wake, conns, services]
    );
    record!(
        s,
        MechOpsHead,
        [size, slots, validate, open, refresh, retire, tick, drive, cancel, release, close]
    );
    record!(s, MechValidateIn, [head, settings, err_buf, err_cap]);
    record!(
        s,
        MechOpenIn,
        [
            head,
            host,
            settings,
            secrets,
            secrets_len,
            generation,
            err_buf,
            err_cap
        ]
    );
    record!(s, MechOpenOut, [head, instance, err_len]);
    record!(s, MechGenIn, [head, generation]);
    record!(
        s,
        MechRefreshIn,
        [head, generation, settings, secrets, secrets_len]
    );
    record!(s, MechTickIn, [head, now_ns]);
    record!(s, MechTickOut, [head, next_tick_ns]);
    record!(s, MechDriveIn, [head, driver]);
    record!(s, MechCancelIn, [head, ticket]);
    record!(s, MechCancelOut, [head, disposition, _reserved]);
    record!(s, MechReleaseIn, [head, lease]);
    record!(s, StoreHostBuf, [ptr, cap]);
    record!(s, StoreHostBlobs, [items, items_cap, bytes]);
    record!(
        s,
        StoreHostBytesOut,
        [head, found, _reserved, written, needed]
    );
    record!(
        s,
        StoreHostListOut,
        [
            head,
            items_written,
            bytes_written,
            needed_items,
            needed_bytes
        ]
    );
    record!(s, StoreLeasedBlobOut, [head, found, _reserved, record]);
    record!(s, StoreLeasedListOut, [head, items, items_len]);
    record!(s, StoreLeasedStrListOut, [head, items, items_len]);
    record!(s, StoreCountOut, [head, count]);
    record!(s, StoreVerdictOut, [head, verdict, _reserved]);
    record!(
        s,
        StoreStoreTail,
        [head, durable_plane, fork_refusal, _reserved]
    );
    record!(s, StoreOpId, []);
    record!(
        s,
        StoreUnitCell,
        [bucket, pool, dimension, _r, class_key, amount, window_start]
    );
    record!(s, StoreCellGrant, [slice_id, granted, valid_until_ms]);
    record!(
        s,
        StoreReserveIn,
        [head, op_id, epoch, cells, cells_len, grants, grants_cap]
    );
    record!(
        s,
        StoreReserveOut,
        [head, grants_len, reason, failed_cell, needed_grants]
    );
    record!(s, StoreReleaseItem, [slice_id, unspent]);
    record!(
        s,
        StoreSliceReleaseIn,
        [head, op_id, epoch, items, items_len, released, released_cap]
    );
    record!(
        s,
        StoreSliceReleaseOut,
        [head, released_len, needed_released]
    );
    record!(s, StoreUsageCell, [bucket, window_start, delta]);
    record!(s, StoreAddUsageBatchIn, [head, op_id, cells, cells_len]);
    record!(s, StoreOpBlobsIn, [head, op_id, records, records_len]);
    record!(
        s,
        StoreWindowCap,
        [
            bucket,
            pool,
            dimension,
            _r,
            class_key,
            window_start,
            cap,
            config_gen
        ]
    );
    record!(s, StoreWindowCapsIn, [head, op_id, caps, caps_len]);
    record!(s, StoreIdIn, [head, id]);
    record!(s, StoreU64In, [head, value]);
    record!(s, StoreWindowIn, [head, bucket, window_start]);
    record!(s, StorePutUsageIn, [head, bucket, window_start, ledger]);
    record!(s, StoreAddUsageIn, [head, op_id, cell]);
    record!(s, StoreBlobIn, [head, record]);
    record!(s, StoreOpBlobIn, [head, op_id, record]);
    record!(s, StoreKeyWithCredentialIn, [head, key, credential]);
    record!(s, StoreKindIdIn, [head, kind, id]);
    record!(s, StoreIdReasonIn, [head, id, reason]);
    record!(
        s,
        StorePlaneRecordRow,
        [kind, id, parent, seq, ts, disposition, _reserved, body]
    );
    record!(s, StoreUpsertPlaneRecordIn, [head, record]);
    record!(s, StoreAppendPlaneRecordIn, [head, op_id, record]);
    record!(s, StoreGetPlaneRecordIn, [head, kind, id, body]);
    record!(
        s,
        StoreListPlaneRecordsIn,
        [head, kind, selector, _reserved, parent, out]
    );
    record!(s, StoreKindBeforeIn, [head, kind, before]);
    record!(s, StoreTokenIn, [head, kind, token, expires_at, now]);
    record!(
        s,
        StoreAppendBatchIn,
        [head, op_id, stream, records, records_len]
    );
    record!(s, StoreHeadOut, [head, seq, epoch]);
    record!(s, StoreStreamHead, [stream, seq, epoch]);
    record!(s, StoreHeadsOut, [head, items, items_len]);
    record!(s, StoreSessionPutIn, [head, session, node, principal]);
    record!(s, StoreSessionRow, [session, node]);
    record!(s, StoreHostSessions, [items, items_cap, bytes]);
    record!(s, StoreSessionsForIn, [head, principal, out]);
    record!(s, StoreRecordPutIn, [head, schema, key, value]);
    record!(s, StoreRecordGetIn, [head, schema, key, value]);
    record!(s, StoreRecordEntry, [key, value]);
    record!(s, StoreHostRecords, [items, items_cap, bytes]);
    record!(
        s,
        StoreRecordScanIn,
        [head, schema, prefix, limit, _reserved, out]
    );
    record!(
        s,
        StoreOps,
        [
            head,
            put_key,
            get_key,
            list_keys,
            delete_key,
            scrub_key,
            list_keys_since,
            get_usage,
            put_usage,
            add_usage,
            add_metering,
            list_metering,
            purge_windows_before,
            purge_metering_before,
            put_credential,
            put_key_with_credential,
            list_credentials,
            lookup_credential_secret,
            revoke_credential,
            list_credentials_since,
            append_audit,
            list_audit,
            add_denylist,
            list_denylist,
            list_audit_tail,
            upsert_plane_record,
            get_plane_record,
            append_plane_record,
            list_plane_records,
            list_plane_record_parents,
            purge_plane_records_before,
            delete_plane_record,
            redeem_plane_token,
            plane_token_live,
            append_batch,
            reserve,
            slice_release,
            heads,
            session_put,
            session_remove,
            sessions_for,
            record_put,
            record_get,
            record_scan,
            add_usage_batch,
            add_metering_batch,
            append_audit_batch,
            window_caps
        ]
    );
    record!(
        s,
        AuthOps,
        [
            head,
            verify,
            begin_login,
            complete_login,
            open_outbound,
            outbound_ready,
            fields
        ]
    );
    record!(s, AuthStyleDecl, [name, flags, _reserved]);
    record!(
        s,
        AuthTail,
        [head, caps, facts, login_kind, _reserved, styles, styles_len]
    );
    record!(s, AuthNamedValue, [name, value]);
    record!(
        s,
        AuthRequestFacts,
        [
            method,
            authority,
            canonical_path,
            query,
            timestamp,
            body_hash,
            body_hash_present,
            _reserved
        ]
    );
    record!(
        s,
        AuthIdentityBuf,
        [buf, buf_cap, groups, groups_cap, _reserved]
    );
    record!(
        s,
        AuthIdentityOut,
        [
            subject, key_id, key_name, user, provider, name, claims, claims_fmt, flags, ttl_secs,
            groups_len, _reserved
        ]
    );
    record!(
        s,
        AuthVerifyIn,
        [head, credential, carrier, carrier_len, request, out_buf]
    );
    record!(
        s,
        AuthIdentifyOut,
        [head, verdict, needed_groups, needed_bytes, identity]
    );
    record!(
        s,
        AuthBeginLoginIn,
        [
            head,
            redirect_uri,
            state,
            nonce,
            code_challenge,
            scopes,
            scopes_len
        ]
    );
    record!(s, AuthLoginField, [name, label, kind, required]);
    record!(
        s,
        AuthBeginLoginOut,
        [head, shape, _reserved, authorize_url, form, form_len]
    );
    record!(
        s,
        AuthCompleteLoginIn,
        [
            head,
            code,
            state,
            redirect_uri,
            code_verifier,
            submitted,
            submitted_len,
            out_buf
        ]
    );
    record!(s, AuthOpenOutboundIn, [head, style, credential, settings]);
    record!(s, AuthOpenOutboundOut, [head, handle]);
    record!(s, AuthOutboundReadyIn, [head, handle]);
    record!(s, AuthOutboundReadyOut, [head, ready, _reserved]);
    record!(s, AuthFieldSpan, [name, value, flags, _reserved]);
    record!(
        s,
        AuthFieldsIn,
        [
            head,
            handle,
            mode,
            _reserved,
            request,
            caller_credential,
            field_buf,
            field_buf_cap,
            fields,
            fields_cap,
            _reserved2,
            headers,
            headers_len
        ]
    );
    record!(
        s,
        AuthFieldsOut,
        [head, fields_len, needed_fields, needed_bytes]
    );
    record!(s, PlaneOps, [head]);
    record!(s, TransportOps, [head]);

    // THE TRANSPORT KIND (abi/transport/) and THE HOST CONNECTOR (abi/host/conn/connector.rs).
    record!(
        s,
        tkind::Ops,
        [
            head, listen, accept, dial, read, write, flush, shut, arrival, locate, begin, ingest,
            emit, encode, refuse, finish, detach, adopt, timer
        ]
    );
    record!(
        s,
        tkind::Claim,
        [
            selector_forms,
            egress_selector_forms,
            facts,
            facts_len,
            status_namespace,
            session,
            session_bound,
            unit0_trigger,
            status_at,
            _reserved
        ]
    );
    record!(s, tkind::StatusRow, [claim, lo, hi, class]);
    record!(
        s,
        tkind::route::FieldPredicate,
        [op, _reserved, name, value]
    );
    record!(
        s,
        tkind::route::RouteMatch,
        [methods, path_form, path, fields, fields_len, rung, _reserved]
    );
    record!(s, tkind::SettingDecl, [path, kind, _reserved, default]);
    record!(
        s,
        tkind::TransportTail,
        [
            head,
            role,
            framing,
            facts,
            handshake_max_steps,
            composes_over,
            composes_over_len,
            claim_rows,
            claim_rows_len,
            upgrades_to,
            upgrades_to_len,
            handoff_from,
            handoff_to,
            handoff_binding_fact,
            handshake_frame_kind,
            status_rows,
            status_rows_len,
            settings,
            settings_len
        ]
    );
    record!(
        s,
        tkind::Destination,
        [kind, _reserved, authority, program, args, args_len, env, env_len]
    );
    record!(
        s,
        tkind::ConnFacts,
        [
            size,
            _reserved,
            offered_name,
            agreed_protocol,
            peer_subject,
            peer_issuer,
            peer_fingerprint,
            claim
        ]
    );
    record!(
        s,
        tkind::FramePiece,
        [
            stream,
            offset,
            len,
            code,
            status_class,
            _reserved,
            flags,
            retry_after_secs
        ]
    );
    record!(
        s,
        tkind::FramerSink,
        [
            wire,
            wire_cap,
            frame,
            frame_cap,
            pieces,
            pieces_cap,
            now_monotonic_ns,
            now_unix_ns,
            heads,
            heads_cap
        ]
    );
    record!(s, tkind::FrameSpan, [offset, len]);
    record!(
        s,
        tkind::HeadSlots,
        [stream, method, target, authority, reason]
    );
    record!(
        s,
        tkind::FramerYield,
        [
            wire_len,
            frame_len,
            pieces_len,
            flags,
            next_deadline_ns,
            heads_len,
            _reserved
        ]
    );
    record!(s, tkind::ListenIn, [head, bind, addr_buf, addr_cap]);
    record!(s, tkind::ListenOut, [head, listener, addr_written]);
    record!(s, tkind::AcceptIn, [head, listener, peer_buf, peer_cap]);
    record!(s, tkind::AcceptOut, [head, conn, peer_written]);
    record!(s, tkind::DialIn, [head, dest]);
    record!(s, tkind::ConnOut, [head, conn]);
    record!(s, tkind::ReadIn, [head, conn, buf, cap]);
    record!(s, tkind::WriteIn, [head, conn, bytes, len]);
    record!(s, tkind::IoOut, [head, len]);
    record!(s, tkind::ConnIn, [head, conn]);
    record!(s, tkind::ShutIn, [head, conn, reason, _reserved]);
    record!(s, tkind::ArrivalIn, [head, conn, peer_buf, peer_cap]);
    record!(
        s,
        tkind::ArrivalOut,
        [head, peer_written, peer_needed, local_port, _reserved]
    );
    record!(
        s,
        tkind::LocateIn,
        [
            head,
            target,
            authority_buf,
            authority_cap,
            name_buf,
            name_cap,
            alpn_buf,
            alpn_cap
        ]
    );
    record!(
        s,
        tkind::LocateOut,
        [
            head,
            authority_written,
            authority_needed,
            name_written,
            name_needed,
            secure,
            has_name,
            alpn_written,
            alpn_needed
        ]
    );
    record!(s, tkind::FramerOut, [head, yielded, framing]);
    record!(
        s,
        tkind::BeginIn,
        [head, side, _reserved, target, facts, sink]
    );
    record!(
        s,
        tkind::IngestIn,
        [head, framing, bytes, len, end, _reserved, sink]
    );
    record!(
        s,
        tkind::EmitIn,
        [
            head,
            framing,
            stream,
            bytes,
            len,
            end_of_frame,
            _reserved,
            sink,
            deadline_ns
        ]
    );
    record!(
        s,
        tkind::EncodeIn,
        [head, fields, fields_len, body, body_len, sink, method, target]
    );
    record!(
        s,
        tkind::RefuseIn,
        [head, framing, stream, has_stream, _reserved, bytes, len, sink]
    );
    record!(s, tkind::FinishIn, [head, framing, reason, _reserved, sink]);
    record!(s, tkind::FramingIn, [head, framing, sink]);
    record!(
        s,
        tkind::AdoptIn,
        [head, side, _reserved, facts, leftover, leftover_len, sink]
    );
    // THE PLANE KIND (abi/plane/).
    record!(
        s,
        pkind::Ops,
        [head, arrive, on_piece, refusal, serve, hydrate, start, project]
    );
    record!(s, pkind::DialectAuth, [dialect, _reserved, style]);
    record!(s, pkind::OpClass, [op, name]);
    record!(s, pkind::BillableClass, [class, family]);
    record!(s, pkind::RouteCost, [class, _reserved, weight]);
    record!(s, pkind::RecordChain, [kind, framing, flags, _reserved]);
    record!(s, pkind::PinMechanism, [token, flags, _reserved]);
    record!(
        s,
        pkind::TrustKey,
        [key, role, flags, default, mechanisms, mechanisms_len]
    );
    record!(
        s,
        pkind::RefusalStatus,
        [dialect, reason, status, _reserved]
    );
    record!(
        s,
        pkind::PlaneTail,
        [
            head,
            flags,
            ingress,
            dispatch_shape,
            _reserved,
            scope,
            label,
            subject_noun,
            admin_noun,
            audit_kind,
            signing_domain,
            signing_kid_prefix,
            cli_help,
            dialects,
            dialects_len,
            dialect_auth,
            dialect_auth_len,
            scope_kinds,
            scope_kinds_len,
            op_classes,
            op_classes_len,
            billable_classes,
            billable_classes_len,
            route_cost,
            route_cost_len,
            fee_units,
            fee_units_len,
            record_kinds,
            record_kinds_len,
            egress_targets,
            egress_targets_len,
            record_chains,
            record_chains_len,
            trust_keys,
            trust_keys_len,
            refusal_statuses,
            refusal_statuses_len,
            caller_credential_refusal
        ]
    );
    record!(
        s,
        pkind::Claim,
        [verb, target, carrier, flags, refusal_dialect, _pad]
    );
    record!(
        s,
        pkind::AdminRoute,
        [verb, target, flags, _reserved, audit_verb]
    );
    record!(
        s,
        pkind::PlaneSnapshot,
        [
            size,
            _reserved,
            generation,
            claims,
            claims_len,
            admin_routes,
            admin_routes_len,
            openapi,
            audience,
            resource_metadata
        ]
    );
    record!(s, pkind::PlaneOpenIn, [open, public_url]);
    record!(s, pkind::PlaneOpenOut, [open, snapshot]);
    record!(s, pkind::PlaneRefreshOut, [head, snapshot]);
    record!(s, pkind::UnitCount, [class, source, amount]);
    record!(s, pkind::OutField, [name, value]);
    record!(s, pkind::RecordWrite, [kind, op, key, value]);
    record!(
        s,
        pkind::ArriveIn,
        [
            head, unit, claim, _reserved, target, fields, fields_len, body, units_buf, units_cap,
            method
        ]
    );
    record!(
        s,
        pkind::ArriveOut,
        [
            head,
            op_class,
            principal_need,
            dialect,
            units_written,
            units_needed,
            refusal,
            refusal_status,
            _reserved,
            correlation,
            cancels
        ]
    );
    record!(
        s,
        pkind::OnPieceIn,
        [
            head,
            unit,
            from,
            flags,
            stream,
            bytes,
            status_code,
            status_class,
            reply_buf,
            reply_cap,
            units_buf,
            units_cap,
            records_buf,
            records_cap,
            fields_buf,
            fields_cap,
            arena_buf,
            arena_cap,
            member,
            attempt_no,
            _reserved,
            pool,
            caller_ref,
            claim,
            dialect,
            head_fields,
            head_fields_len,
            passthrough,
            _reserved_tail
        ]
    );
    record!(
        s,
        pkind::OnPieceOut,
        [
            head,
            emitted,
            more,
            flags,
            reply_status,
            fields_written,
            fields_needed,
            units_written,
            units_needed,
            records_written,
            records_needed,
            verdict,
            arena_written,
            arena_needed,
            verb,
            target
        ]
    );
    record!(
        s,
        pkind::RefusalIn,
        [
            head,
            cause,
            status,
            dialect,
            reason,
            text,
            reply_buf,
            reply_cap,
            fields_buf,
            fields_cap,
            arena_buf,
            arena_cap,
            unit,
            plane_code,
            retry_after_s,
            target
        ]
    );
    record!(
        s,
        pkind::RefusalOut,
        [
            head,
            reply_written,
            reply_needed,
            arena_written,
            arena_needed,
            marker,
            fields_written,
            fields_needed,
            status
        ]
    );
    record!(
        s,
        pkind::ServeIn,
        [
            head, route, _reserved, target, fields, fields_len, body, reply_buf, reply_cap,
            fields_buf, fields_cap, arena_buf, arena_cap
        ]
    );
    record!(
        s,
        pkind::ServeOut,
        [
            head,
            reply_written,
            reply_needed,
            arena_written,
            arena_needed,
            status,
            fields_written,
            fields_needed,
            audit
        ]
    );
    record!(s, pkind::PlaneDriveIn, [drive, sessions_buf, sessions_cap]);
    record!(
        s,
        pkind::PlaneDriveOut,
        [head, sessions_written, sessions_needed]
    );
    record!(
        s,
        pkind::ProjectIn,
        [
            head,
            claim,
            _reserved,
            target,
            fields,
            fields_len,
            body,
            signals_buf,
            signals_cap,
            arena_buf,
            arena_cap
        ]
    );
    record!(
        s,
        pkind::ProjectOut,
        [
            head,
            view,
            body,
            signals_needed,
            _reserved,
            arena_written,
            arena_needed
        ]
    );
    record!(
        s,
        hconn::Need,
        [
            direction,
            egress_class,
            transport,
            auth,
            target_from,
            trust_from,
            details,
            keep_response_headers,
            keep_response_headers_len,
            timeout_ms
        ]
    );
    record!(
        s,
        hconn::EstablishIn,
        [head, need, _reserved, target, within]
    );
    record!(s, hconn::StreamIn, [head, stream]);
    record!(s, hconn::IoIn, [head, stream, buf, len]);
    record!(s, hconn::UpgradeIn, [head, stream, offered_name, trust]);
    record!(s, hconn::FactsIn, [head, stream, facts]);
    record!(
        s,
        hconn::StreamFacts,
        [size, secure, endpoint, agreed_protocol, peer_cert_hash]
    );
    record!(s, hconn::CheckoutIn, [head, need, _reserved]);
    record!(s, hconn::CheckinIn, [head, stream, disposition, _reserved]);
    record!(s, hconn::RandomIn, [head, buf, len]);
    record!(
        s,
        hconn::ProcessIdentity,
        [size, _reserved, pid, os_user, program]
    );
    record!(s, hconn::IdentityIn, [head, identity]);
    record!(
        s,
        hconn::ConnectorSlots,
        [
            size,
            slots,
            establish,
            reject_endpoint,
            side_stream,
            read,
            write,
            upgrade_secure,
            facts,
            checkout,
            checkin,
            close,
            random,
            identity,
            read_reply,
            write_request
        ]
    );
    record!(s, hconn::ReplyPiece, [kind, code, reason, fields]);
    record!(s, hconn::ReplyIn, [head, stream, buf, len, piece]);
    record!(
        s,
        hconn::RequestPiece,
        [kind, _reserved, method, target, fields, timeout_ms]
    );
    record!(s, hconn::RequestIn, [head, stream, buf, len, piece]);
    // The host services (abi/host/service.rs) and the call shape they share with the connector.
    record!(s, hsvc::ServiceHead, [size, op, handle]);
    record!(
        s,
        hsvc::ServiceOut,
        [
            size,
            outcome,
            _reserved,
            value,
            len,
            items,
            needed_bytes,
            needed_items,
            error
        ]
    );
    record!(s, hsvc::ItemSpan, [key, value]);
    record!(s, hsvc::ServiceBufs, [buf, cap, spans, spans_cap]);
    record!(s, hsvc::ClockReading, [size, _reserved, wall_ns, mono_ns]);
    record!(s, hsvc::ClockNowIn, [head, reading]);
    record!(s, hsvc::RecordsGetIn, [head, kind, key, into]);
    record!(
        s,
        hsvc::RecordsListIn,
        [head, kind, prefix, after, limit, _reserved, into]
    );
    record!(s, hsvc::RecordsClaimIn, [head, kind, key, ttl_ms]);
    record!(
        s,
        hsvc::DestJudgeIn,
        [head, dest, egress_class, flags, into]
    );
    record!(s, hsvc::SignIn, [head, data, into]);
    record!(s, hsvc::UnitNestIn, [head, verb, target, body, into]);
    record!(s, hsvc::WorkOpenIn, [head, kind, record]);
    record!(s, hsvc::WorkFindIn, [head, reference, into]);
    record!(s, hsvc::WorkSettleIn, [head, handle, record]);
    record!(s, hsvc::WorkResumeIn, [head, handle, into]);
    record!(s, hsvc::TrustSightIn, [head, counterparty, catalogue_hash]);
    record!(s, hsvc::TrustDueIn, [head, into]);
    record!(s, hsvc::VerifyLookupIn, [head, key, into]);
    record!(s, hsvc::VerifyStoreIn, [head, key, entry, ttl_ms]);
    record!(s, hsvc::EntitlementCheckIn, [head, target]);
    record!(s, hsvc::ContentScanIn, [head, content, into]);
    record!(s, hsvc::HookCallIn, [head, stage, _reserved, view, into]);
    record!(s, hsvc::RandomFillIn, [head, len, into]);
    record!(
        s,
        hsvc::HostSlots,
        [
            size,
            slots,
            clock_now,
            records_get,
            records_list,
            records_claim,
            dest_judge,
            sign,
            unit_nest,
            work_open,
            work_find,
            work_settle,
            work_resume,
            trust_sight,
            trust_due,
            verify_lookup,
            verify_store,
            entitlement_check,
            content_scan,
            hook_call,
            random_fill,
            need_admit,
            trust_verify
        ]
    );
    record!(s, hsvc::NeedAdmitIn, [head, need, _reserved]);
    record!(
        s,
        hsvc::TrustVerifyIn,
        [head, counterparty, payload, signatures, into]
    );

    // M3-SHAPES (abi-v2-perkind.md B.2): the secret kind's `resolve`.
    record!(s, SecretOps, [head, resolve]);
    record!(s, SecretResolveIn, [head, settings]);
    record!(s, SecretResolveOut, [head, secret, error_kind, _reserved]);
    // M3-SHAPES (abi-v2-perkind.md B.4): the hook kind's decide/transform/notify/configure/
    // status/describe/serve, its views and its Statement tail.
    record!(
        s,
        HookOps,
        [head, decide, transform, notify, configure, status, describe, serve]
    );
    record!(s, HookSignalValue, []);
    record!(s, HookSignalEntry, [id, tag, value]);
    record!(
        s,
        HookRequestView,
        [
            request_id,
            pool,
            ingress_dialect,
            message_count,
            total_chars,
            max_tokens,
            flags,
            signals,
            signals_len
        ]
    );
    record!(
        s,
        HookCandidateStatic,
        [
            idx,
            _reserved,
            model,
            provider,
            weight,
            _reserved3,
            context_max,
            tier,
            cost_per_mtok,
            tags,
            tags_len,
            present,
            _reserved2
        ]
    );
    record!(
        s,
        HookCandidateDynamic,
        [
            latency_ms,
            available_concurrency,
            budget_remaining,
            rate_headroom,
            signals,
            signals_len,
            present,
            _reserved
        ]
    );
    record!(s, HookPromptView, [system, message_count, body]);
    record!(s, HookUserView, [key_id, key_name, user]);
    record!(
        s,
        HookBudgetBucketState,
        [
            bucket_id,
            budget_group,
            pool,
            spend_micros_at_current_rate,
            remaining_micros,
            window_start,
            budget_period,
            present,
            _reserved
        ]
    );
    record!(
        s,
        HookDecideIn,
        [
            head,
            request,
            candidates,
            candidate_dynamics,
            candidates_len,
            prompt,
            user,
            budget_remaining,
            budget,
            budget_len,
            present,
            _reserved,
            order_buf,
            order_cap,
            reject_message_buf,
            reject_message_cap,
            restrict_tags_buf,
            restrict_tags_cap,
            rewrite_buf,
            rewrite_cap
        ]
    );
    record!(
        s,
        HookDecideOut,
        [
            head,
            verbs,
            reject_status,
            _reserved,
            reject_message_written,
            reject_message_needed,
            restrict_tags_written,
            restrict_tags_needed,
            order_written,
            order_needed
        ]
    );
    record!(
        s,
        HookTransformOut,
        [
            head,
            verbs,
            reject_status,
            _reserved,
            reject_message_written,
            reject_message_needed,
            rewrite_written,
            rewrite_needed
        ]
    );
    record!(
        s,
        HookStageView,
        [
            request_id,
            pool,
            ingress_dialect,
            message_count,
            total_chars,
            remaining_candidates,
            model,
            previous_failure,
            outcome,
            max_tokens,
            flags,
            at,
            attempt_number,
            status,
            _reserved,
            stage_present,
            _reserved2
        ]
    );
    record!(s, HookNotifyIn, [head, stage]);
    record!(s, HookConfigureIn, [head, version, settings, name]);
    record!(s, HookConfigureOut, [head, acked_version]);
    record!(s, HookStatusOut, [head, status]);
    record!(s, HookDescribeOut, [head, describe]);
    record!(
        s,
        HookServeIn,
        [head, method, path, query, headers, headers_len, body]
    );
    record!(
        s,
        HookServeOut,
        [
            head,
            status_code,
            _reserved,
            headers_out,
            headers_out_len,
            body
        ]
    );
    record!(s, HookRoute, [path, method, auth, _reserved]);
    record!(
        s,
        HookTail,
        [
            head,
            kind_class,
            prompt_access,
            user_access,
            infallible,
            _reserved,
            requested_signals,
            requested_signals_len,
            routes,
            routes_len
        ]
    );

    // M3-SHAPES (abi-v2-perkind.md B.5): the export kind's deliver/scrape/status/check/serve and
    // its Statement tail.
    record!(s, ExportOps, [head, deliver, scrape, status, check, serve]);
    record!(s, ExportDeliverIn, [head, op_id, stream, _reserved, batch]);
    record!(s, ExportScrapeLabel, [key, value]);
    record!(s, ExportScrapeSample, [name, labels, labels_len, value]);
    record!(
        s,
        ExportScrapeFamily,
        [name, help, unit, kind, _reserved, samples, samples_len]
    );
    record!(s, ExportScrapeIn, [head, families, families_len, buf, cap]);
    record!(s, ExportScrapeOut, [head, written, needed]);
    record!(s, ExportStatusOut, [head, status]);
    record!(s, ExportCheckInstance, [name, settings]);
    record!(
        s,
        ExportCheckIn,
        [head, phase, _reserved, instances, instances_len]
    );
    record!(s, ExportCheckOut, [head, findings]);
    record!(
        s,
        ExportServeIn,
        [head, method, path, query, headers, headers_len, body]
    );
    record!(
        s,
        ExportServeOut,
        [
            head,
            status_code,
            _reserved,
            headers_out,
            headers_out_len,
            body
        ]
    );
    record!(s, ExportRoute, [path, method, auth, _reserved]);
    record!(
        s,
        ExportTail,
        [head, streams, streams_len, routes, routes_len]
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

    if std::env::var_os("BUSBAR_UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &actual).expect("write golden");
        // On a seed run, do not also assert (the file was just written to match).
        return;
    }

    // A missing or empty golden is a FAILURE, not an invitation to self-seed. Seeding on absence
    // means deleting the file is a way to make this gate pass — the check would bless whatever
    // layout it found and report success, which is the opposite of what a golden is for.
    assert!(
        !existing.trim().is_empty(),
        "\nABI LAYOUT GOLDEN MISSING: {path}\n\
         This gate has nothing to compare against. If the golden was lost, restore it from version \
         control; if this layout is genuinely the intended one, seed it DELIBERATELY with \
         `BUSBAR_UPDATE_GOLDEN=1 cargo test -p busbar-plugin`.\n"
    );

    assert!(
        compare(&existing, &actual).is_ok(),
        "{}",
        compare(&existing, &actual).unwrap_err()
    );
    assert_eq!(
        existing, actual,
        "\nABI LAYOUT DRIFT: a POD field offset/size changed.\n\
         If this is an APPEND-ONLY tail addition, bump the airlock MINOR and re-seed with \
         `BUSBAR_UPDATE_GOLDEN=1`.\n\
         If it is a REORDER/RESIZE/INSERT, that is a MAJOR airlock break — do not re-seed \
         without bumping ABI_MAJOR.\n"
    );
}

/// THE COMPARATOR: the golden and the layout agree line for line, or the first line that differs is
/// named.
fn compare(existing: &str, actual: &str) -> Result<(), String> {
    if existing == actual {
        return Ok(());
    }
    let e: Vec<&str> = existing.lines().collect();
    let a: Vec<&str> = actual.lines().collect();
    for i in 0..e.len().max(a.len()) {
        if e.get(i) != a.get(i) {
            return Err(format!(
                "ABI LAYOUT DRIFT at golden line {}: golden {:?}, layout {:?}",
                i + 1,
                e.get(i),
                a.get(i)
            ));
        }
    }
    Err("ABI LAYOUT DRIFT: the golden and the layout differ in line endings".to_string())
}

/// RED ARM: one perturbed golden line (the mechanism door's `kind_abi` offset) fails the comparator.
#[test]
fn a_perturbed_golden_line_fails_the_comparator() {
    let actual = compute_layout();
    assert!(compare(&actual, &actual).is_ok());
    let line = "MechDoor.kind_abi=20";
    assert!(actual.lines().any(|l| l == line), "the golden holds {line}");
    let perturbed = actual.replacen(line, "MechDoor.kind_abi=24", 1);
    let err = compare(&perturbed, &actual).expect_err("a perturbed line must fail");
    assert!(err.contains("MechDoor.kind_abi=24"), "{err}");
}

/// RED ARM (transport kind): one perturbed transport golden line fails the comparator.
#[test]
fn a_perturbed_transport_golden_line_fails_the_comparator() {
    let actual = compute_layout();
    let line = "tkind::Ops.timer=216";
    assert!(actual.lines().any(|l| l == line), "the golden holds {line}");
    let perturbed = actual.replacen(line, "tkind::Ops.timer=208", 1);
    let err = compare(&perturbed, &actual).expect_err("a perturbed line must fail");
    assert!(err.contains("tkind::Ops.timer=208"), "{err}");
}

/// RED ARM (host connector): one perturbed connector golden line fails the comparator.
#[test]
fn a_perturbed_connector_golden_line_fails_the_comparator() {
    let actual = compute_layout();
    let line = "hconn::ConnectorSlots.identity=96";
    assert!(actual.lines().any(|l| l == line), "the golden holds {line}");
    let perturbed = actual.replacen(line, "hconn::ConnectorSlots.identity=88", 1);
    let err = compare(&perturbed, &actual).expect_err("a perturbed line must fail");
    assert!(err.contains("hconn::ConnectorSlots.identity=88"), "{err}");
}

/// RED ARM (plane kind): one perturbed plane golden line fails the comparator.
#[test]
fn a_perturbed_plane_golden_line_fails_the_comparator() {
    let actual = compute_layout();
    let line = "pkind::OnPieceOut.units_written=124";
    assert!(actual.lines().any(|l| l == line), "the golden holds {line}");
    let perturbed = actual.replacen(line, "pkind::OnPieceOut.units_written=112", 1);
    let err = compare(&perturbed, &actual).expect_err("a perturbed line must fail");
    assert!(err.contains("pkind::OnPieceOut.units_written=112"), "{err}");
}

/// RED ARM, THE AUTH KIND: one perturbed auth golden line (`fields`' slot in the auth table) fails
/// the comparator.
#[test]
fn a_perturbed_auth_golden_line_fails_the_comparator() {
    let actual = compute_layout();
    let line = "AuthOps.fields=120";
    assert!(actual.lines().any(|l| l == line), "the golden holds {line}");
    let perturbed = actual.replacen(line, "AuthOps.fields=112", 1);
    let err = compare(&perturbed, &actual).expect_err("a perturbed auth line must fail");
    assert!(err.contains("AuthOps.fields=112"), "{err}");
}

/// RED ARM (M3-SHAPES, secret B.2): a perturbed `ResolveOut.error_kind` offset fails the
/// comparator.
#[test]
fn a_perturbed_secret_golden_line_fails_the_comparator() {
    let actual = compute_layout();
    let line = "SecretResolveOut.error_kind=120";
    assert!(actual.lines().any(|l| l == line), "the golden holds {line}");
    let perturbed = actual.replacen(line, "SecretResolveOut.error_kind=124", 1);
    let err = compare(&perturbed, &actual).expect_err("a perturbed line must fail");
    assert!(err.contains("SecretResolveOut.error_kind=124"), "{err}");
}

/// RED ARM (M3-SHAPES, export B.5): a perturbed `DeliverIn.batch` offset fails the comparator.
#[test]
fn a_perturbed_export_golden_line_fails_the_comparator() {
    let actual = compute_layout();
    let line = "ExportDeliverIn.batch=112";
    assert!(actual.lines().any(|l| l == line), "the golden holds {line}");
    let perturbed = actual.replacen(line, "ExportDeliverIn.batch=120", 1);
    let err = compare(&perturbed, &actual).expect_err("a perturbed line must fail");
    assert!(err.contains("ExportDeliverIn.batch=120"), "{err}");
}

/// RED ARM (M3-SHAPES, hook B.4): a perturbed `DecideOut.order_written` offset fails the
/// comparator.
#[test]
fn a_perturbed_hook_golden_line_fails_the_comparator() {
    let actual = compute_layout();
    let line = "HookDecideOut.order_written=136";
    assert!(actual.lines().any(|l| l == line), "the golden holds {line}");
    let perturbed = actual.replacen(line, "HookDecideOut.order_written=144", 1);
    let err = compare(&perturbed, &actual).expect_err("a perturbed line must fail");
    assert!(err.contains("HookDecideOut.order_written=144"), "{err}");
}

/// RED ARM, store kind: one perturbed store golden line (a `UnitCell`'s `window_start` offset, the
/// money shape of m3-inputs "store v3 money slots" / "window caps") fails the comparator.
#[test]
fn a_perturbed_store_golden_line_fails_the_comparator() {
    let actual = compute_layout();
    let line = "StoreUnitCell.window_start=64";
    assert!(actual.lines().any(|l| l == line), "the golden holds {line}");
    let perturbed = actual.replacen(line, "StoreUnitCell.window_start=56", 1);
    let err = compare(&perturbed, &actual).expect_err("a perturbed store line must fail");
    assert!(err.contains("StoreUnitCell.window_start=56"), "{err}");
}
