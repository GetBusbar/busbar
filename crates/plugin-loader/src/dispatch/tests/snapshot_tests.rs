// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the snapshot layout (`dispatch/snapshot.rs`): the bytes it uses are the bytes it
//! said it needs, and nothing past them is touched. The read-back through the SDK is
//! `host_services_tests::snapshot_read_lays_the_families_out_in_the_callers_buffer`.

use super::*;
use busbar_contract::export_calls::Sample;

#[test]
fn the_layout_uses_exactly_the_bytes_it_needs() {
    assert_eq!(size_of_layout(&[]), 0, "no families: no bytes");
    let families = vec![Family {
        name: "n".into(),
        help: Some("h".into()),
        unit: None,
        kind: 1,
        samples: vec![Sample {
            name: "n".into(),
            labels: vec![("k".into(), "v".into())],
            value: "1".into(),
        }],
    }];
    let needed = size_of_layout(&families);
    let mut words = vec![u64::MAX; needed.div_ceil(8) + 4];
    // SAFETY: the buffer is word-aligned and longer than the layout.
    let used = unsafe { lay_out(&families, words.as_mut_ptr().cast::<u8>()) };
    assert_eq!(used, needed);
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 8) };
    assert!(
        bytes[needed..].iter().all(|b| *b == 0xff),
        "nothing past the layout is written"
    );
}
