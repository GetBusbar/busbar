// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::KindCode;
use busbar_plugin_loader::dispatch::kinds::plane::{Plane, PlaneFacts};
use busbar_plugin_loader::dispatch::Kind;
use std::mem::{size_of, zeroed};
use std::ptr::{null, NonNull};

fn z<T>() -> T {
    // SAFETY: called only for Statement, a repr(C) structure of pointers and integers.
    unsafe { zeroed() }
}

fn bounded_tail_context(
    change: impl FnOnce(&mut busbar_contract::abi::plane::PlaneTail),
) -> Result<(), String> {
    use busbar_contract::abi::mechanism::door::{Section, Statement, SECTION_DECLARING};
    use busbar_contract::abi::plane::{PlaneTail, INGRESS_RESPONSE_STREAM};
    let section = [Section {
        name: AbiStr::of("door"),
        flags: SECTION_DECLARING,
        _reserved: 0,
    }];
    let mut tail = PlaneTail::EMPTY;
    tail.ingress = INGRESS_RESPONSE_STREAM;
    change(&mut tail);
    let mut st: Statement = z();
    st.kind_tail = &tail.head;
    st.sections = section.as_ptr();
    st.sections_len = section.len();
    Plane::context(&st).map(|_| ())
}

/// The same declaration supplies loader facts and signed bytes. A physically shorter legacy
/// allocation has no list, even when a newer tail would have held one at that offset.
#[test]
fn streaming_media_are_loaded_and_rendered_and_absent_from_legacy_tails() {
    use busbar_contract::abi::mechanism::{
        door::{KindTailHead, Section, Statement, SECTION_DECLARING},
        rendering,
    };
    use busbar_contract::abi::plane::{PlaneTail, INGRESS_RESPONSE_STREAM};
    let media = [
        AbiStr::of("text/event-stream"),
        AbiStr::of("application/vnd.amazon.eventstream"),
    ];
    let mut tail = PlaneTail::EMPTY;
    tail.ingress = INGRESS_RESPONSE_STREAM;
    tail.streaming_content_types = media.as_ptr();
    tail.streaming_content_types_len = media.len();
    let sections = [Section {
        name: AbiStr::of("door"),
        flags: SECTION_DECLARING,
        _reserved: 0,
    }];
    let mut st: Statement = z();
    st.kind = KindCode::Plane as u32;
    st.kind_tail = &tail.head;
    st.sections = sections.as_ptr();
    st.sections_len = sections.len();
    let facts = |st: &Statement| {
        Plane::context(st)
            .unwrap()
            .unwrap()
            .downcast::<PlaneFacts>()
            .unwrap()
            .served
            .streaming_content_types
    };
    let got = facts(&st);
    assert_eq!(
        got,
        ["text/event-stream", "application/vnd.amazon.eventstream"]
    );
    // SAFETY: all Statement/tail spans above are live throughout rendering.
    let rendered = unsafe { rendering::render(&st) }.unwrap();
    let read = rendering::read(&rendered).unwrap();
    let mut expected = (got.len() as u32).to_le_bytes().to_vec();
    for media in got {
        expected.extend_from_slice(&(media.len() as u32).to_le_bytes());
        expected.extend_from_slice(media.as_bytes());
    }
    assert!(
        read.kind_tail.ends_with(&expected),
        "signed facts carry the loader's complete list"
    );

    let old_size = std::mem::offset_of!(PlaneTail, streaming_content_types);
    tail.head.size = old_size as u32;
    // Allocate only the old layout, aligned like PlaneTail. Reading appended fields directly
    // would access bytes beyond this allocation; both loader and rendering must zero-extend.
    let mut old = vec![0_u64; old_size / size_of::<u64>()];
    assert_eq!(old.len() * size_of::<u64>(), old_size);
    // SAFETY: the source and destination have old_size initialized bytes and do not overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&tail as *const PlaneTail).cast::<u8>(),
            old.as_mut_ptr().cast::<u8>(),
            old_size,
        )
    };
    st.kind_tail = old.as_ptr().cast::<KindTailHead>();
    assert!(facts(&st).is_empty());
    // SAFETY: old has exactly the number of bytes its head states; all its spans remain live.
    let legacy = rendering::read(&unsafe { rendering::render(&st) }.unwrap()).unwrap();
    tail = PlaneTail {
        streaming_content_types: null(),
        streaming_content_types_len: 0,
        ..tail
    };
    tail.head.size = size_of::<PlaneTail>() as u32;
    st.kind_tail = &tail.head;
    // SAFETY: the full tail and its Statement spans remain live.
    let empty = rendering::read(&unsafe { rendering::render(&st) }.unwrap()).unwrap();
    assert_eq!(
        legacy.kind_tail,
        empty.kind_tail[..empty.kind_tail.len() - 4]
    );
}

#[test]
fn streaming_media_null_and_over_cap_lists_are_refused() {
    let err = bounded_tail_context(|tail| tail.streaming_content_types_len = 1)
        .err()
        .unwrap();
    assert!(err.contains("tail.streaming_content_types"), "{err}");
    let err = bounded_tail_context(|tail| {
        tail.streaming_content_types = NonNull::dangling().as_ptr();
        tail.streaming_content_types_len =
            busbar_contract::abi::mechanism::check::STATEMENT_LIST_MAX + 1;
    })
    .err()
    .unwrap();
    assert!(err.contains("longer than its cap"), "{err}");
}
