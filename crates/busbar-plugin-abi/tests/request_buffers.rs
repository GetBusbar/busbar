// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_plugin_abi::records::{Full, Records, Reply, Writer};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn flat_words_are_one_record_with_little_endian_body_and_zero_padding() {
    for values in [vec![], vec![0], vec![u32::MAX, 1], vec![7, 0x0102_0304, 9]] {
        let mut reply = Reply::new();
        reply
            .put_u32s(0x101, |out| {
                values.iter().try_for_each(|&value| out.push(value))
            })
            .unwrap();
        let mut recs = Records::new(reply.as_bytes());
        let body = recs.next().unwrap().unwrap().body;
        let expected: Vec<u8> = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        assert_eq!(body, expected);
        assert!(recs.next().is_none());
        assert!(
            reply.as_bytes()[8 + values.len() * 4..]
                .iter()
                .all(|&byte| byte == 0)
        );
        let mut unaligned = vec![1];
        unaligned.extend_from_slice(reply.as_bytes());
        assert_eq!(
            Records::new(&unaligned[1..]).next().unwrap().unwrap().body,
            expected
        );
    }
}

#[test]
fn nested_writer_contains_one_flat_word_record() {
    let mut reply = Reply::new();
    reply
        .put_nested(0x102, |nested| {
            nested.put_u32s(0x101, |words| {
                words.push(7)?;
                words.push(8)
            })
        })
        .unwrap();
    let outer = Records::new(reply.as_bytes()).next().unwrap().unwrap();
    let mut nested = outer.nested();
    assert_eq!(
        nested.next().unwrap().unwrap().body,
        [7, 0, 0, 0, 8, 0, 0, 0]
    );
    assert!(nested.next().is_none());
}

async fn child(payload: &[u8], expected: &'static [u8]) {
    let mut first = true;
    std::future::poll_fn(|_| {
        assert_eq!(payload, expected);
        if std::mem::take(&mut first) {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    assert_eq!(payload, expected);
}

async fn operation(payload: &'static [u8]) -> Result<Reply, Full> {
    let mut scratch = Reply::new().into_scratch(payload.len())?;
    scratch.put(payload)?;
    child(scratch.as_bytes(), payload).await;
    let mut reply = scratch.finish();
    reply.put(0x101, payload)?;
    Ok(reply)
}

#[test]
fn pending_borrow_survives_cross_thread_resume_and_interleaved_calls() {
    let mut first = Box::pin(operation(b"first body"));
    let mut second = Box::pin(operation(b"second body"));
    assert!(poll(first.as_mut()).is_pending());
    assert!(poll(second.as_mut()).is_pending());
    let resumed = std::thread::spawn(move || {
        let Poll::Ready(reply) = poll(first.as_mut()) else {
            panic!("child resumes")
        };
        reply.unwrap()
    })
    .join()
    .unwrap();
    let Poll::Ready(second) = poll(second.as_mut()) else {
        panic!("second resumes")
    };
    let second = second.unwrap();
    assert_eq!(
        Records::new(resumed.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .body,
        b"first body"
    );
    assert_eq!(
        Records::new(second.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .body,
        b"second body"
    );
}

#[test]
fn canceling_one_pending_borrow_does_not_change_another_call() {
    let mut canceled = Box::pin(operation(b"canceled body"));
    let mut live = Box::pin(operation(b"live body"));
    assert!(poll(canceled.as_mut()).is_pending());
    assert!(poll(live.as_mut()).is_pending());
    drop(canceled);
    let Poll::Ready(reply) = poll(live.as_mut()) else {
        panic!("live resumes")
    };
    let reply = reply.unwrap();
    assert_eq!(
        Records::new(reply.as_bytes()).next().unwrap().unwrap().body,
        b"live body"
    );
}
