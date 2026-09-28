// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE MEMORY ABI'S LAYOUT, PINNED BY HAND (`BUSBAR-1.6.0.md` THE DESIGN, §11.5): the size, the
//! alignment and every field offset of every `#[repr(C)]` type under `abi/mechanism/` and
//! `abi/<kind>/`, written out as numbers. The layout golden (`layout_golden.rs`) catches a DRIFT;
//! this states the INTENDED layout a C author reads off `busbar_plugin.h`, so the two cannot agree
//! on a wrong layout by being re-seeded together. 64-bit targets only (every target busbar ships).

use std::mem::{align_of, offset_of, size_of};

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Diag, Envelope, InHead, MetricEntry, OutHead, RawOutcome,
};
use busbar_contract::abi::mechanism::door::{Door, KindTailHead, MetricFamily, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn, ReleaseIn, TickIn,
    TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables, Ticket};
use busbar_contract::abi::{auth, export, hook, plane, secret, store, transport};

/// `pin!(T, size, align, [field = offset, …])`.
macro_rules! pin {
    ($t:ty, $size:expr, $align:expr, [$($f:ident = $off:expr),* $(,)?]) => {{
        assert_eq!(size_of::<$t>(), $size, "size_of::<{}>", stringify!($t));
        assert_eq!(align_of::<$t>(), $align, "align_of::<{}>", stringify!($t));
        $(
            assert_eq!(
                offset_of!($t, $f),
                $off,
                "offset_of!({}, {})",
                stringify!($t),
                stringify!($f)
            );
        )*
    }};
}

#[test]
fn the_call_shape_types_have_their_stated_layout() {
    pin!(RawOutcome, 1, 1, []);
    pin!(AbiStr, 16, 8, [ptr = 0, len = 8]);
    pin!(Blob, 24, 8, [ptr = 0, len = 8, fmt = 16, flags = 20]);
    pin!(
        InHead,
        88,
        8,
        [
            size = 0,
            op = 4,
            flags = 8,
            deadline_class = 12,
            _reserved = 13,
            host = 16,
            ticket = 24,
            deadline_ns = 32,
            trace_id = 40,
            parent_span_id = 56,
            extensions = 64
        ]
    );
    pin!(
        MetricEntry,
        32,
        8,
        [
            family_idx = 0,
            kind = 4,
            _reserved = 5,
            value = 8,
            label_vals = 16,
            label_vals_len = 24
        ]
    );
    pin!(
        Diag,
        24,
        8,
        [id_idx = 0, severity = 4, _reserved = 5, text = 8]
    );
    pin!(
        Envelope,
        32,
        8,
        [metrics = 0, metrics_len = 8, diags = 16, diags_len = 24]
    );
    pin!(
        OutHead,
        96,
        8,
        [
            size = 0,
            outcome = 4,
            _reserved = 5,
            wake_at_ns = 8,
            lease = 16,
            error = 24,
            envelope = 40,
            extensions = 72
        ]
    );
}

#[test]
fn the_door_and_the_statement_have_their_stated_layout() {
    pin!(
        Door,
        40,
        8,
        [
            magic = 0,
            mechanism_version = 8,
            size = 12,
            kind = 16,
            kind_abi = 20,
            statement = 24,
            ops = 32
        ]
    );
    pin!(
        MetricFamily,
        72,
        8,
        [
            name = 0,
            help = 16,
            unit = 32,
            label_keys = 48,
            label_keys_len = 56,
            kind = 64,
            _reserved = 65
        ]
    );
    pin!(
        Statement,
        152,
        8,
        [
            size = 0,
            kind = 4,
            kind_abi = 8,
            max_inflight = 12,
            name = 16,
            version = 32,
            families = 48,
            families_len = 56,
            diag_ids = 64,
            diag_ids_len = 72,
            kind_tail = 80,
            extensions = 88,
            secret_refs = 112,
            secret_refs_len = 120,
            settings_schema = 128
        ]
    );
}

#[test]
fn tickets_and_host_tables_have_their_stated_layout() {
    pin!(KindTailHead, 8, 4, [size = 0, _reserved = 4]);
    pin!(Ticket, 8, 4, [slot = 0, generation = 4]);
    pin!(
        CompletionHandle,
        16,
        4,
        [ticket = 0, seq = 8, _reserved = 12]
    );
    pin!(HostCtx, 8, 8, [ptr = 0]);
    pin!(
        HostTables,
        32,
        8,
        [size = 0, _reserved = 4, ctx = 8, wake = 16, conns = 24]
    );
}

#[test]
fn the_lifecycle_has_its_stated_layout() {
    pin!(
        OpsHead,
        80,
        8,
        [
            size = 0,
            slots = 4,
            validate = 8,
            open = 16,
            refresh = 24,
            retire = 32,
            tick = 40,
            drive = 48,
            cancel = 56,
            release = 64,
            close = 72
        ]
    );
    pin!(ValidateIn, 112, 8, [head = 0, settings = 88]);
    pin!(
        OpenIn,
        144,
        8,
        [
            head = 0,
            host = 88,
            settings = 96,
            secrets = 120,
            secrets_len = 128,
            generation = 136
        ]
    );
    pin!(OpenOut, 104, 8, [head = 0, instance = 96]);
    pin!(GenIn, 96, 8, [head = 0, generation = 88]);
    pin!(
        RefreshIn,
        136,
        8,
        [
            head = 0,
            generation = 88,
            settings = 96,
            secrets = 120,
            secrets_len = 128
        ]
    );
    pin!(TickIn, 96, 8, [head = 0, now_ns = 88]);
    pin!(TickOut, 104, 8, [head = 0, next_tick_ns = 96]);
    pin!(DriveIn, 96, 8, [head = 0, driver = 88]);
    pin!(CancelIn, 96, 8, [head = 0, ticket = 88]);
    pin!(
        CancelOut,
        104,
        8,
        [head = 0, disposition = 96, _reserved = 100]
    );
    pin!(ReleaseIn, 96, 8, [head = 0, lease = 88]);
}

#[test]
fn every_kind_table_leads_with_the_lifecycle() {
    pin!(store::Ops, 456, 8, [head = 0]);
    // secret, hook and export grew their own slots in M3-SHAPES (abi-v2-perkind.md B.2/B.4/B.5);
    // `.../mechanism/layout.rs` pins every field of each.
    pin!(secret::Ops, 88, 8, [head = 0]);
    pin!(hook::Ops, 136, 8, [head = 0]);
    pin!(export::Ops, 120, 8, [head = 0]);
    pin!(plane::Ops, 80, 8, [head = 0]);
    pin!(transport::Ops, 80, 8, [head = 0]);
}

#[test]
fn the_auth_kind_has_its_stated_layout() {
    use auth::*;
    pin!(
        Ops,
        128,
        8,
        [
            head = 0,
            verify = 80,
            begin_login = 88,
            complete_login = 96,
            open_outbound = 104,
            outbound_ready = 112,
            fields = 120
        ]
    );
    pin!(StyleDecl, 24, 8, [name = 0, flags = 16, _reserved = 20]);
    pin!(
        AuthTail,
        72,
        8,
        [
            head = 0,
            caps = 8,
            facts = 12,
            login_kind = 16,
            _reserved = 20,
            styles = 24,
            styles_len = 32,
            aliases = 40,
            aliases_len = 48,
            carriers = 56,
            carriers_len = 64
        ]
    );
    pin!(Span, 8, 4, [off = 0, len = 4]);
    pin!(NamedValue, 40, 8, [name = 0, value = 16]);
    pin!(
        RequestFacts,
        112,
        8,
        [
            method = 0,
            authority = 16,
            canonical_path = 32,
            query = 48,
            timestamp = 64,
            body_hash = 72,
            body_hash_present = 104,
            _reserved = 108
        ]
    );
    pin!(
        IdentityBuf,
        32,
        8,
        [
            buf = 0,
            buf_cap = 8,
            groups = 16,
            groups_cap = 24,
            _reserved = 28
        ]
    );
    pin!(
        IdentityOut,
        80,
        8,
        [
            subject = 0,
            key_id = 8,
            key_name = 16,
            user = 24,
            provider = 32,
            name = 40,
            claims = 48,
            claims_fmt = 56,
            flags = 60,
            ttl_secs = 64,
            groups_len = 72,
            _reserved = 76
        ]
    );
    pin!(
        VerifyIn,
        272,
        8,
        [
            head = 0,
            credential = 88,
            carrier = 112,
            carrier_len = 120,
            request = 128,
            out_buf = 240
        ]
    );
    pin!(
        IdentifyOut,
        192,
        8,
        [
            head = 0,
            verdict = 96,
            needed_groups = 100,
            needed_bytes = 104,
            identity = 112
        ]
    );
    pin!(
        BeginLoginIn,
        168,
        8,
        [
            head = 0,
            redirect_uri = 88,
            state = 104,
            nonce = 120,
            code_challenge = 136,
            scopes = 152,
            scopes_len = 160
        ]
    );
    pin!(
        LoginField,
        40,
        8,
        [name = 0, label = 16, kind = 32, required = 36]
    );
    pin!(
        BeginLoginOut,
        136,
        8,
        [
            head = 0,
            shape = 96,
            _reserved = 100,
            authorize_url = 104,
            form = 120,
            form_len = 128
        ]
    );
    pin!(
        CompleteLoginIn,
        216,
        8,
        [
            head = 0,
            code = 88,
            state = 112,
            redirect_uri = 128,
            code_verifier = 144,
            submitted = 168,
            submitted_len = 176,
            out_buf = 184
        ]
    );
    pin!(
        OpenOutboundIn,
        152,
        8,
        [head = 0, style = 88, credential = 104, settings = 128]
    );
    pin!(OpenOutboundOut, 104, 8, [head = 0, handle = 96]);
    pin!(OutboundReadyIn, 96, 8, [head = 0, handle = 88]);
    pin!(
        OutboundReadyOut,
        104,
        8,
        [head = 0, ready = 96, _reserved = 100]
    );
    pin!(
        FieldSpan,
        24,
        4,
        [name = 0, value = 8, flags = 16, _reserved = 20]
    );
    pin!(
        FieldsIn,
        288,
        8,
        [
            head = 0,
            handle = 88,
            mode = 96,
            _reserved = 100,
            request = 104,
            caller_credential = 216,
            field_buf = 240,
            field_buf_cap = 248,
            fields = 256,
            fields_cap = 264,
            _reserved2 = 268,
            headers = 272,
            headers_len = 280
        ]
    );
    pin!(
        FieldsOut,
        112,
        8,
        [
            head = 0,
            fields_len = 96,
            needed_fields = 100,
            needed_bytes = 104
        ]
    );
}

/// The auth table's slot numbers are the lifecycle's count plus `k`, contiguous, and the table's
/// size and slot count are what a door must state.
#[test]
fn the_auth_slots_follow_the_lifecycle_contiguously() {
    use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
    let slots = [
        (auth::slot::VERIFY, offset_of!(auth::Ops, verify)),
        (auth::slot::BEGIN_LOGIN, offset_of!(auth::Ops, begin_login)),
        (
            auth::slot::COMPLETE_LOGIN,
            offset_of!(auth::Ops, complete_login),
        ),
        (
            auth::slot::OPEN_OUTBOUND,
            offset_of!(auth::Ops, open_outbound),
        ),
        (
            auth::slot::OUTBOUND_READY,
            offset_of!(auth::Ops, outbound_ready),
        ),
        (auth::slot::FIELDS, offset_of!(auth::Ops, fields)),
    ];
    assert_eq!(slots.len() as u32, auth::KIND_SLOTS);
    for (k, (idx, off)) in slots.into_iter().enumerate() {
        assert_eq!(idx, LIFECYCLE_SLOTS + k as u32);
        assert_eq!(off, 8 + 8 * idx as usize);
    }
    assert_eq!(auth::SLOTS, LIFECYCLE_SLOTS + auth::KIND_SLOTS);
    assert_eq!(size_of::<auth::Ops>(), 8 + 8 * auth::SLOTS as usize);
}

/// The store kind (v3): every `#[repr(C)]` type under `abi/store/` (B.1; m3-inputs "store v3 money
/// slots" and "window caps").
#[test]
fn the_store_kind_has_its_stated_layout() {
    pin!(store::HostBuf, 16, 8, [ptr = 0, cap = 8]);
    pin!(
        store::HostBlobs,
        32,
        8,
        [items = 0, items_cap = 8, bytes = 16]
    );
    pin!(
        store::HostBytesOut,
        120,
        8,
        [
            head = 0,
            found = 96,
            _reserved = 100,
            written = 104,
            needed = 112
        ]
    );
    pin!(
        store::HostListOut,
        128,
        8,
        [
            head = 0,
            items_written = 96,
            bytes_written = 104,
            needed_items = 112,
            needed_bytes = 120
        ]
    );
    pin!(
        store::LeasedBlobOut,
        128,
        8,
        [head = 0, found = 96, _reserved = 100, record = 104]
    );
    pin!(
        store::LeasedListOut,
        112,
        8,
        [head = 0, items = 96, items_len = 104]
    );
    pin!(
        store::LeasedStrListOut,
        112,
        8,
        [head = 0, items = 96, items_len = 104]
    );
    pin!(store::CountOut, 104, 8, [head = 0, count = 96]);
    pin!(
        store::VerdictOut,
        104,
        8,
        [head = 0, verdict = 96, _reserved = 100]
    );
    pin!(
        store::StoreTail,
        16,
        4,
        [
            head = 0,
            ephemeral = 8,
            durable_plane = 9,
            fork_refusal = 10,
            _reserved = 11
        ]
    );
    pin!(store::OpId, 16, 1, []);
    pin!(
        store::UnitCell,
        72,
        8,
        [
            bucket = 0,
            pool = 16,
            dimension = 32,
            _r = 36,
            class_key = 40,
            amount = 56,
            window_start = 64
        ]
    );
    pin!(
        store::CellGrant,
        24,
        8,
        [slice_id = 0, granted = 8, valid_until_ms = 16]
    );
    pin!(
        store::ReserveIn,
        144,
        8,
        [
            head = 0,
            op_id = 88,
            epoch = 104,
            cells = 112,
            cells_len = 120,
            grants = 128,
            grants_cap = 136
        ]
    );
    pin!(
        store::ReserveOut,
        120,
        8,
        [
            head = 0,
            grants_len = 96,
            reason = 104,
            failed_cell = 108,
            needed_grants = 112
        ]
    );
    pin!(store::ReleaseItem, 16, 8, [slice_id = 0, unspent = 8]);
    pin!(
        store::SliceReleaseIn,
        144,
        8,
        [
            head = 0,
            op_id = 88,
            epoch = 104,
            items = 112,
            items_len = 120,
            released = 128,
            released_cap = 136
        ]
    );
    pin!(
        store::SliceReleaseOut,
        112,
        8,
        [head = 0, released_len = 96, needed_released = 104]
    );
    pin!(
        store::UsageCell,
        48,
        8,
        [bucket = 0, window_start = 16, delta = 24]
    );
    pin!(
        store::AddUsageBatchIn,
        120,
        8,
        [head = 0, op_id = 88, cells = 104, cells_len = 112]
    );
    pin!(
        store::OpBlobsIn,
        120,
        8,
        [head = 0, op_id = 88, records = 104, records_len = 112]
    );
    pin!(
        store::WindowCap,
        80,
        8,
        [
            bucket = 0,
            pool = 16,
            dimension = 32,
            _r = 36,
            class_key = 40,
            window_start = 56,
            cap = 64,
            config_gen = 72
        ]
    );
    pin!(
        store::WindowCapsIn,
        120,
        8,
        [head = 0, op_id = 88, caps = 104, caps_len = 112]
    );
    pin!(store::IdIn, 104, 8, [head = 0, id = 88]);
    pin!(store::U64In, 96, 8, [head = 0, value = 88]);
    pin!(
        store::WindowIn,
        112,
        8,
        [head = 0, bucket = 88, window_start = 104]
    );
    pin!(
        store::PutUsageIn,
        136,
        8,
        [head = 0, bucket = 88, window_start = 104, ledger = 112]
    );
    pin!(
        store::AddUsageIn,
        152,
        8,
        [head = 0, op_id = 88, cell = 104]
    );
    pin!(store::BlobIn, 112, 8, [head = 0, record = 88]);
    pin!(
        store::OpBlobIn,
        128,
        8,
        [head = 0, op_id = 88, record = 104]
    );
    pin!(
        store::KeyWithCredentialIn,
        136,
        8,
        [head = 0, key = 88, credential = 112]
    );
    pin!(store::KindIdIn, 120, 8, [head = 0, kind = 88, id = 104]);
    pin!(store::IdReasonIn, 120, 8, [head = 0, id = 88, reason = 104]);
    pin!(
        store::PlaneRecordRow,
        96,
        8,
        [
            kind = 0,
            id = 16,
            parent = 32,
            seq = 48,
            ts = 56,
            disposition = 64,
            _reserved = 68,
            body = 72
        ]
    );
    pin!(store::UpsertPlaneRecordIn, 184, 8, [head = 0, record = 88]);
    pin!(
        store::AppendPlaneRecordIn,
        200,
        8,
        [head = 0, op_id = 88, record = 104]
    );
    pin!(
        store::GetPlaneRecordIn,
        136,
        8,
        [head = 0, kind = 88, id = 104, body = 120]
    );
    pin!(
        store::ListPlaneRecordsIn,
        160,
        8,
        [
            head = 0,
            kind = 88,
            selector = 104,
            _reserved = 108,
            parent = 112,
            out = 128
        ]
    );
    pin!(
        store::KindBeforeIn,
        112,
        8,
        [head = 0, kind = 88, before = 104]
    );
    pin!(
        store::TokenIn,
        136,
        8,
        [
            head = 0,
            kind = 88,
            token = 104,
            expires_at = 120,
            now = 128
        ]
    );
    pin!(
        store::AppendBatchIn,
        136,
        8,
        [
            head = 0,
            op_id = 88,
            stream = 104,
            records = 120,
            records_len = 128
        ]
    );
    pin!(store::HeadOut, 112, 8, [head = 0, seq = 96, epoch = 104]);
    pin!(store::StreamHead, 32, 8, [stream = 0, seq = 16, epoch = 24]);
    pin!(
        store::HeadsOut,
        112,
        8,
        [head = 0, items = 96, items_len = 104]
    );
    pin!(
        store::SessionPutIn,
        128,
        8,
        [head = 0, session = 88, node = 96, principal = 112]
    );
    pin!(store::SessionRow, 24, 8, [session = 0, node = 8]);
    pin!(
        store::HostSessions,
        32,
        8,
        [items = 0, items_cap = 8, bytes = 16]
    );
    pin!(
        store::SessionsForIn,
        136,
        8,
        [head = 0, principal = 88, out = 104]
    );
    pin!(
        store::RecordPutIn,
        152,
        8,
        [head = 0, schema = 88, key = 104, value = 128]
    );
    pin!(
        store::RecordGetIn,
        144,
        8,
        [head = 0, schema = 88, key = 104, value = 128]
    );
    pin!(store::RecordEntry, 48, 8, [key = 0, value = 24]);
    pin!(
        store::HostRecords,
        32,
        8,
        [items = 0, items_cap = 8, bytes = 16]
    );
    pin!(
        store::RecordScanIn,
        168,
        8,
        [
            head = 0,
            schema = 88,
            prefix = 104,
            limit = 128,
            _reserved = 132,
            out = 136
        ]
    );
    pin!(
        store::Ops,
        456,
        8,
        [
            head = 0,
            put_key = 80,
            get_key = 88,
            list_keys = 96,
            delete_key = 104,
            scrub_key = 112,
            list_keys_since = 120,
            get_usage = 128,
            put_usage = 136,
            add_usage = 144,
            add_metering = 152,
            list_metering = 160,
            purge_windows_before = 168,
            purge_metering_before = 176,
            put_credential = 184,
            put_key_with_credential = 192,
            list_credentials = 200,
            lookup_credential_secret = 208,
            revoke_credential = 216,
            list_credentials_since = 224,
            append_audit = 232,
            list_audit = 240,
            add_denylist = 248,
            list_denylist = 256,
            list_audit_tail = 264,
            upsert_plane_record = 272,
            get_plane_record = 280,
            append_plane_record = 288,
            list_plane_records = 296,
            list_plane_record_parents = 304,
            purge_plane_records_before = 312,
            delete_plane_record = 320,
            redeem_plane_token = 328,
            plane_token_live = 336,
            append_batch = 344,
            reserve = 352,
            slice_release = 360,
            heads = 368,
            session_put = 376,
            session_remove = 384,
            sessions_for = 392,
            record_put = 400,
            record_get = 408,
            record_scan = 416,
            add_usage_batch = 424,
            add_metering_batch = 432,
            append_audit_batch = 440,
            window_caps = 448
        ]
    );
}
