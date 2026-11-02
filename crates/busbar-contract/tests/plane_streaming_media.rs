// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::{
    mechanism::{call::AbiStr, door::Statement, rendering, KindCode},
    plane::{check::check_tail, PlaneTail, INGRESS_RESPONSE_STREAM},
};
use std::mem::{offset_of, size_of};

#[test]
fn streaming_media_are_signed_and_old_tail_allocations_render_an_empty_list() {
    let media = [
        AbiStr::of("text/event-stream"),
        AbiStr::of("application/vnd.amazon.eventstream"),
    ];
    // Builders require process-lifetime declarations, as a real plugin's Statement does.
    let media = Box::leak(Box::new(media));
    let mut tail = PlaneTail::EMPTY.with_streaming_content_types(media);
    tail.ingress = INGRESS_RESPONSE_STREAM;
    assert_eq!(check_tail(&tail), Ok(()));
    let mut st = Statement::ZERO;
    st.kind = KindCode::Plane as u32;
    st.kind_tail = &tail.head;
    // SAFETY: the tail and all declared bytes are live through rendering.
    let full = rendering::read(&unsafe { rendering::render(&st) }.unwrap()).unwrap();
    let mut suffix = 2_u32.to_le_bytes().to_vec();
    for mime in ["text/event-stream", "application/vnd.amazon.eventstream"] {
        suffix.extend_from_slice(&(mime.len() as u32).to_le_bytes());
        suffix.extend_from_slice(mime.as_bytes());
    }
    assert!(full.kind_tail.ends_with(&suffix));

    let old_size = offset_of!(PlaneTail, streaming_content_types);
    tail.head.size = old_size as u32;
    let mut old = vec![0_u64; old_size / size_of::<u64>()];
    assert_eq!(old.len() * size_of::<u64>(), old_size);
    // SAFETY: two disjoint allocations each have old_size initialized bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&tail as *const PlaneTail).cast::<u8>(),
            old.as_mut_ptr().cast::<u8>(),
            old_size,
        )
    };
    st.kind_tail = old.as_ptr().cast();
    // SAFETY: old's allocation is exactly its declared size; no appended pointer exists.
    let legacy = rendering::read(&unsafe { rendering::render(&st) }.unwrap()).unwrap();
    let empty = PlaneTail {
        ingress: INGRESS_RESPONSE_STREAM,
        ..PlaneTail::EMPTY
    };
    st.kind_tail = &empty.head;
    // SAFETY: the empty full tail remains live throughout rendering.
    let absent = rendering::read(&unsafe { rendering::render(&st) }.unwrap()).unwrap();
    assert_eq!(legacy.kind_tail, absent.kind_tail);
    assert_ne!(full.kind_tail, absent.kind_tail);
}

#[test]
fn streaming_media_counts_require_a_pointer() {
    let tail = PlaneTail {
        ingress: INGRESS_RESPONSE_STREAM,
        streaming_content_types_len: 1,
        ..PlaneTail::EMPTY
    };
    assert_eq!(
        check_tail(&tail).unwrap_err().field,
        "tail.streaming_content_types"
    );
}
