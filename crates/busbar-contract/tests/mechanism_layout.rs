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
    pin!(store::Ops, 80, 8, [head = 0]);
    pin!(secret::Ops, 80, 8, [head = 0]);
    pin!(auth::Ops, 80, 8, [head = 0]);
    pin!(hook::Ops, 80, 8, [head = 0]);
    pin!(export::Ops, 80, 8, [head = 0]);
    pin!(plane::Ops, 80, 8, [head = 0]);
    pin!(transport::Ops, 80, 8, [head = 0]);
}
