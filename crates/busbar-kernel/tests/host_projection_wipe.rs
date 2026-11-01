// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe only registered, initialized projection payloads before their allocation is released.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use busbar_kernel::plane_driver::Projection;

thread_local! {
    static WATCH: Cell<Option<(*mut u8, usize)>> = const { Cell::new(None) };
    static WIPED: Cell<Option<bool>> = const { Cell::new(None) };
}

struct InspectBeforeFree;

// SAFETY: allocations are forwarded unchanged to System. Only the initialized payload prefix
// registered by this thread is observed, while its matching allocation still belongs to it.
unsafe impl GlobalAlloc for InspectBeforeFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the allocator caller supplies a valid layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = WATCH.try_with(|watch| {
            if let Some((watched, len)) = watch.get().filter(|(watched, _)| *watched == pointer) {
                watch.set(None);
                let wiped = len <= layout.size()
                    && (0..len).all(|index| {
                        // SAFETY: these bytes were initialized String/Vec contents when
                        // registered. The matching live allocation has not reached dealloc.
                        // No spare capacity, allocation padding, or freed memory is read.
                        unsafe { watched.add(index).read_volatile() == 0 }
                    });
                let _ = WIPED.try_with(|result| result.set(Some(wiped)));
            }
        });
        // SAFETY: pointer and layout match the allocator caller's live allocation.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectBeforeFree = InspectBeforeFree;

fn watch(bytes: &[u8]) {
    assert!(!bytes.is_empty());
    WATCH.with(|watched| watched.set(Some((bytes.as_ptr().cast_mut(), bytes.len()))));
    WIPED.with(|result| result.set(None));
}

fn projection() -> Projection {
    Projection {
        pool: "private-pool".to_string(),
        dialect: "private-dialect".to_string(),
        message_count: 1,
        total_chars: 12,
        max_tokens: Some(7),
        has_tools: true,
        stream: false,
        system: Some("private-system".to_string()),
        turns: vec![("private-author".to_string(), "private-text".to_string())],
        end_user: Some("private-user".to_string()),
        rewritten: Some(b"private-rewrite".to_vec()),
        session: Some(b"private-session".to_vec()),
        projected: Some(b"private-projection".to_vec()),
        rewrite_not_applicable: false,
    }
}

fn field<'a>(view: &'a Projection, name: &str) -> &'a [u8] {
    match name {
        "pool" => view.pool.as_bytes(),
        "dialect" => view.dialect.as_bytes(),
        "system" => view.system.as_ref().unwrap().as_bytes(),
        "author" => view.turns[0].0.as_bytes(),
        "text" => view.turns[0].1.as_bytes(),
        "end-user" => view.end_user.as_ref().unwrap().as_bytes(),
        "rewritten" => view.rewritten.as_deref().unwrap(),
        "session" => view.session.as_deref().unwrap(),
        "projected" => view.projected.as_deref().unwrap(),
        _ => unreachable!(),
    }
}

fn returned(_view: Projection, fail: bool) -> Result<(), ()> {
    if fail {
        Err(())
    } else {
        Ok(())
    }
}

#[test]
fn the_projection_witness_distinguishes_plain_and_wiped_payloads() {
    let plain = b"plain-initialized-control".to_vec();
    watch(&plain);
    drop(plain);
    assert_eq!(WIPED.with(Cell::get), Some(false));

    let wiped = zeroize::Zeroizing::new(b"wiped-initialized-control".to_vec());
    watch(&wiped);
    drop(wiped);
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn host_projection_payloads_wipe_on_return_error_cancel_clone_replacement_and_transfer() {
    for name in [
        "pool",
        "dialect",
        "system",
        "author",
        "text",
        "end-user",
        "rewritten",
        "session",
        "projected",
    ] {
        for exit in [
            "return", "failure", "cancel", "clone", "replace", "transfer",
        ] {
            let mut view = projection();
            if exit == "clone" {
                let clone = view.clone();
                drop(view);
                view = clone;
            }
            watch(field(&view, name));
            match exit {
                "cancel" => {
                    let mut pending = Box::pin(async move {
                        let view = view;
                        std::future::pending::<()>().await;
                        drop(view);
                    });
                    assert_eq!(
                        pending
                            .as_mut()
                            .poll(&mut Context::from_waker(Waker::noop())),
                        Poll::Pending
                    );
                    assert_eq!(WIPED.with(Cell::get), None);
                    drop(pending);
                }
                "replace" => {
                    view = projection();
                    assert_eq!(WIPED.with(Cell::get), Some(true));
                    assert_eq!(
                        view.projected.as_deref(),
                        Some(b"private-projection".as_slice())
                    );
                    drop(view);
                }
                "transfer" => {
                    let final_owner = std::mem::take(&mut view);
                    drop(view);
                    assert_eq!(WIPED.with(Cell::get), None);
                    drop(final_owner);
                }
                _ => {
                    assert_eq!(
                        returned(view, exit == "failure").is_err(),
                        exit == "failure"
                    );
                }
            }
            assert_eq!(WIPED.with(Cell::get), Some(true), "{name} on {exit}");
        }
    }
}
