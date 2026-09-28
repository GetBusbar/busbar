// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S LAYOUT, PINNED AT COMPILE TIME: the size, alignment and every field offset of
//! every `#[repr(C)]` type under `abi/store/`, as `const` assertions (the same rule as
//! `abi/mechanism/layout.rs`), so a drift fails the build of every target. 64-bit layout.
//! `tests/golden/abi-layout.golden` records the same numbers; `tests/mechanism_layout.rs` states them
//! by hand.

use std::mem::{align_of, offset_of, size_of};

use super::*;

/// `pin!(T, size, align, field = offset, …)`: a compile-time layout assertion.
macro_rules! pin {
    ($t:ty, $size:expr, $align:expr $(, $f:ident = $off:expr)* $(,)?) => {
        const _: () = {
            assert!(size_of::<$t>() == $size);
            assert!(align_of::<$t>() == $align);
            $(assert!(offset_of!($t, $f) == $off);)*
        };
    };
}

pin!(HostBuf, 16, 8, ptr = 0, cap = 8);
pin!(HostBlobs, 32, 8, items = 0, items_cap = 8, bytes = 16);
pin!(
    HostBytesOut,
    112,
    8,
    head = 0,
    found = 96,
    _reserved = 100,
    len = 104
);
pin!(
    HostListOut,
    112,
    8,
    head = 0,
    items_len = 96,
    bytes_len = 104
);
pin!(
    LeasedBlobOut,
    128,
    8,
    head = 0,
    found = 96,
    _reserved = 100,
    record = 104
);
pin!(LeasedListOut, 112, 8, head = 0, items = 96, items_len = 104);
pin!(
    LeasedStrListOut,
    112,
    8,
    head = 0,
    items = 96,
    items_len = 104
);
pin!(CountOut, 104, 8, head = 0, count = 96);
pin!(VerdictOut, 104, 8, head = 0, verdict = 96, _reserved = 100);
pin!(
    StoreTail,
    16,
    4,
    head = 0,
    ephemeral = 8,
    durable_plane = 9,
    fork_refusal = 10,
    _reserved = 11
);
pin!(OpId, 16, 1);
pin!(
    UnitCell,
    64,
    8,
    bucket = 0,
    pool = 16,
    dimension = 32,
    _r = 36,
    class_key = 40,
    amount = 56
);
pin!(
    CellGrant,
    24,
    8,
    slice_id = 0,
    granted = 8,
    valid_until_ms = 16
);
pin!(
    ReserveIn,
    136,
    8,
    head = 0,
    op_id = 88,
    epoch = 104,
    window_start = 112,
    cells = 120,
    cells_len = 128
);
pin!(
    ReserveOut,
    120,
    8,
    head = 0,
    grants = 96,
    grants_len = 104,
    reason = 112,
    _reserved = 116
);
pin!(ReleaseItem, 16, 8, slice_id = 0, unspent = 8);
pin!(
    SliceReleaseIn,
    128,
    8,
    head = 0,
    op_id = 88,
    epoch = 104,
    items = 112,
    items_len = 120
);
pin!(SliceReleaseOut, 104, 8, head = 0, released = 96);
pin!(UsageCell, 48, 8, bucket = 0, window_start = 16, delta = 24);
pin!(
    AddUsageBatchIn,
    120,
    8,
    head = 0,
    op_id = 88,
    cells = 104,
    cells_len = 112
);
pin!(
    OpBlobsIn,
    120,
    8,
    head = 0,
    op_id = 88,
    records = 104,
    records_len = 112
);
pin!(
    WindowCap,
    80,
    8,
    bucket = 0,
    pool = 16,
    dimension = 32,
    _r = 36,
    class_key = 40,
    window_start = 56,
    cap = 64,
    config_gen = 72
);
pin!(
    WindowCapsIn,
    120,
    8,
    head = 0,
    op_id = 88,
    caps = 104,
    caps_len = 112
);
pin!(IdIn, 104, 8, head = 0, id = 88);
pin!(U64In, 96, 8, head = 0, value = 88);
pin!(WindowIn, 112, 8, head = 0, bucket = 88, window_start = 104);
pin!(
    PutUsageIn,
    136,
    8,
    head = 0,
    bucket = 88,
    window_start = 104,
    ledger = 112
);
pin!(AddUsageIn, 152, 8, head = 0, op_id = 88, cell = 104);
pin!(BlobIn, 112, 8, head = 0, record = 88);
pin!(OpBlobIn, 128, 8, head = 0, op_id = 88, record = 104);
pin!(
    KeyWithCredentialIn,
    136,
    8,
    head = 0,
    key = 88,
    credential = 112
);
pin!(KindIdIn, 120, 8, head = 0, kind = 88, id = 104);
pin!(IdReasonIn, 120, 8, head = 0, id = 88, reason = 104);
pin!(
    PlaneRecordRow,
    96,
    8,
    kind = 0,
    id = 16,
    parent = 32,
    seq = 48,
    ts = 56,
    disposition = 64,
    _reserved = 68,
    body = 72
);
pin!(UpsertPlaneRecordIn, 184, 8, head = 0, record = 88);
pin!(
    AppendPlaneRecordIn,
    200,
    8,
    head = 0,
    op_id = 88,
    record = 104
);
pin!(
    GetPlaneRecordIn,
    136,
    8,
    head = 0,
    kind = 88,
    id = 104,
    body = 120
);
pin!(
    ListPlaneRecordsIn,
    160,
    8,
    head = 0,
    kind = 88,
    selector = 104,
    _reserved = 108,
    parent = 112,
    out = 128
);
pin!(KindBeforeIn, 112, 8, head = 0, kind = 88, before = 104);
pin!(
    TokenIn,
    136,
    8,
    head = 0,
    kind = 88,
    token = 104,
    expires_at = 120,
    now = 128
);
pin!(
    AppendBatchIn,
    136,
    8,
    head = 0,
    op_id = 88,
    stream = 104,
    records = 120,
    records_len = 128
);
pin!(HeadOut, 112, 8, head = 0, seq = 96, epoch = 104);
pin!(StreamHead, 32, 8, stream = 0, seq = 16, epoch = 24);
pin!(HeadsOut, 112, 8, head = 0, items = 96, items_len = 104);
pin!(
    SessionPutIn,
    128,
    8,
    head = 0,
    session = 88,
    node = 96,
    principal = 112
);
pin!(SessionRow, 24, 8, session = 0, node = 8);
pin!(HostSessions, 32, 8, items = 0, items_cap = 8, bytes = 16);
pin!(SessionsForIn, 136, 8, head = 0, principal = 88, out = 104);
pin!(
    RecordPutIn,
    152,
    8,
    head = 0,
    schema = 88,
    key = 104,
    value = 128
);
pin!(
    RecordGetIn,
    144,
    8,
    head = 0,
    schema = 88,
    key = 104,
    value = 128
);
pin!(RecordEntry, 48, 8, key = 0, value = 24);
pin!(HostRecords, 32, 8, items = 0, items_cap = 8, bytes = 16);
pin!(
    RecordScanIn,
    168,
    8,
    head = 0,
    schema = 88,
    prefix = 104,
    limit = 128,
    _reserved = 132,
    out = 136
);
pin!(
    Ops,
    456,
    8,
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
);
