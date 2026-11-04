// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Frozen v1 textual receipts, before the versioned digest encoding. Product structs' derived
//! Debug is not a persistence format. Names, ordering and punctuation here are the legacy wire
//! format; exhaustive destructuring makes future field changes require an explicit compatibility
//! decision. Debug is used only for primitive quoted strings, never product structs or collections.

use std::collections::BTreeMap;
use std::fmt::{Display, Write as _};

use crate::records::{
    MeteringDelta, ModelTokensDelta, PlaneDisposition, PlaneRecordRef, UsageDelta,
};

fn units<V: Display>(out: &mut String, values: &BTreeMap<String, V>) {
    out.push('{');
    for (index, (name, value)) in values.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{name:?}: {value}");
    }
    out.push('}');
}

fn usage_delta(out: &mut String, delta: &UsageDelta) {
    let UsageDelta {
        requests,
        billable_requests,
        models,
    } = delta;
    let _ = write!(
        out,
        "UsageDelta {{ requests: {requests}, billable_requests: {billable_requests}, models: ["
    );
    for (index, model) in models.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        let ModelTokensDelta { model, usage_units } = model;
        let _ = write!(out, "ModelTokensDelta {{ model: {model:?}, usage_units: ");
        units(out, usage_units);
        out.push_str(" }");
    }
    out.push_str("] }");
}

pub(super) fn usage(out: &mut String, cells: &[(&str, u64, UsageDelta)]) {
    out.push_str("add_usage_batch:[");
    for (index, (bucket, window, delta)) in cells.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "({bucket:?}, {window}, ");
        usage_delta(out, delta);
        out.push(')');
    }
    out.push(']');
}

pub(super) fn metering(out: &mut String, deltas: &[MeteringDelta]) {
    out.push_str("add_metering_batch:[");
    for (index, delta) in deltas.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        let MeteringDelta {
            key_id,
            bucket,
            model,
            provider,
            tokens_input,
            tokens_output,
            tokens_cache_read,
            tokens_cache_write,
            requests,
            billable_requests,
            key_group_at_use,
            pricing_version,
            priced_from_ms,
            usage_units,
        } = delta;
        let _ = write!(out,
            "MeteringDelta {{ key_id: {key_id:?}, bucket: {bucket}, model: {model:?}, provider: {provider:?}, tokens_input: {tokens_input}, tokens_output: {tokens_output}, tokens_cache_read: {tokens_cache_read}, tokens_cache_write: {tokens_cache_write}, requests: {requests}, billable_requests: {billable_requests}, key_group_at_use: {key_group_at_use:?}, pricing_version: {pricing_version:?}, priced_from_ms: {priced_from_ms}, usage_units: "
        );
        units(out, usage_units);
        out.push_str(" }");
    }
    out.push(']');
}

pub(super) fn append(out: &mut String, record: PlaneRecordRef<'_>, owned: bool) {
    let PlaneRecordRef {
        kind,
        id,
        parent,
        seq,
        ts,
        disposition,
        body,
    } = record;
    out.push_str(if owned {
        "append_plane_record:PlaneRecord { "
    } else {
        "append_plane_record:PlaneRecordRef { "
    });
    let _ = write!(out, "kind: {kind:?}, id: {id:?}, parent: ");
    match parent {
        Some(parent) => {
            let _ = write!(out, "Some({parent:?})");
        }
        None => out.push_str("None"),
    }
    let _ = write!(out, ", seq: {seq}, ts: {ts}, disposition: ");
    out.push_str(match disposition {
        PlaneDisposition::Active => "Active",
        PlaneDisposition::Terminal => "Terminal",
    });
    out.push_str(", body: [");
    for (index, byte) in body.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{byte}");
    }
    out.push_str("] }");
}
