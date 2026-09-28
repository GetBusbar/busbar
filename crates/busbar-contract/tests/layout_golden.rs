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
    InHead as MechInHead, MetricEntry as MechMetricEntry, OutHead as MechOutHead,
};
use busbar_contract::abi::mechanism::door::{
    Door as MechDoor, KindTailHead as MechKindTailHead, MetricFamily as MechMetricFamily,
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
    auth::Ops as AuthOps, export::Ops as ExportOps, hook::Ops as HookOps, plane::Ops as PlaneOps,
    secret::Ops as SecretOps, store::Ops as StoreOps, transport::Ops as TransportOps,
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
            unit_cost_micros,
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
            cost_reserve,
            cost_settle,
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
        [size, _reserved, target, fields, fields_len, body, body_len, timeout_ms]
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
            retry_after_secs
        ]
    );

    // THE ONE MEMORY ABI (`BUSBAR-1.6.0.md` THE DESIGN, §11.5): the shared mechanism and the seven kind
    // tables. `tests/mechanism_layout.rs` states the same numbers by hand.
    record!(s, MechStr, [ptr, len]);
    record!(s, MechBlob, [ptr, len, fmt, flags]);
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
            settings_schema
        ]
    );
    record!(s, MechKindTailHead, [size, _reserved]);
    record!(s, MechTicket, [slot, generation]);
    record!(s, MechCompletionHandle, [ticket, seq, _reserved]);
    record!(s, MechHostCtx, [ptr]);
    record!(s, MechHostTables, [size, _reserved, ctx, wake, conns]);
    record!(
        s,
        MechOpsHead,
        [size, slots, validate, open, refresh, retire, tick, drive, cancel, release, close]
    );
    record!(s, MechValidateIn, [head, settings]);
    record!(
        s,
        MechOpenIn,
        [head, host, settings, secrets, secrets_len, generation]
    );
    record!(s, MechOpenOut, [head, instance]);
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
    record!(s, StoreOps, [head]);
    record!(s, SecretOps, [head]);
    record!(s, AuthOps, [head]);
    record!(s, HookOps, [head]);
    record!(s, ExportOps, [head]);
    record!(s, PlaneOps, [head]);
    record!(s, TransportOps, [head]);

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
