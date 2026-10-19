// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The upstream leg's reads: a channel message longer than the reader's buffer.

use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use super::take_ready;

/// RED (THE DESIGN §5: a plugin's slow I/O answers not-ready, "no blocking thread exists"): a
/// channel message longer than the reader's buffer is read in parts, its rest kept first in line.
/// Put back while the queue's lock was still held (the lock taken for the pop lives through the
/// whole `if let`), the read locked the queue a second time on the same thread and never answered,
/// wedging the worker that drove it.
#[test]
fn a_message_longer_than_the_readers_buffer_is_read_in_parts_and_never_wedges_the_reader() {
    let ready = Arc::new(Mutex::new(VecDeque::from([(b"abcd".to_vec(), true)])));
    let (answer, answered) = mpsc::channel();
    let queue = Arc::clone(&ready);
    std::thread::spawn(move || {
        let mut buf = [0_u8; 2];
        let first = take_ready(&queue, &mut buf).map(|(n, end)| (buf[..n].to_vec(), end));
        let second = take_ready(&queue, &mut buf).map(|(n, end)| (buf[..n].to_vec(), end));
        let _ = answer.send((first, second));
    });
    assert_eq!(
        answered.recv_timeout(Duration::from_secs(5)),
        Ok((Some((b"ab".to_vec(), false)), Some((b"cd".to_vec(), true)))),
        "the message is read in two parts, the end on the last"
    );
}
