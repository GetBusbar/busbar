// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO BLOCK OF MEMORY IS GIVEN BACK STILL HOLDING A CALLER'S CREDENTIAL.
//!
//! A caller's request reaches the linked HTTP image as bytes on an accepted connection. The
//! engine's own buffers are wiped in one block when released. The HTTP library inside the image
//! keeps its own copy: the read buffer the request head was parsed from, and the parsed header
//! map's values. Nothing wipes those; they go back to the allocator as they are, so the
//! credential stays readable in freed memory for as long as the allocator leaves it.
//!
//! The proof is the allocator's own view: every block handed back while the test is armed is
//! scanned for the credential before it is released. Zero blocks may hold it.
//!
//! RED at the integration head (the library's read buffer and header values are freed unwiped).
//! GREEN with the fork change stated at the end of this file.
//!

#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use busbar_contract::storage::{StorageAccount, StorageDenied, StorageSource};
use busbar_core_connector::framed_stream::session::TransportConn;
use busbar_plugin_abi::transport as wire;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;
use busbar_ports::transport::ConnIn;

/// The credential the caller sends. Distinct enough that no other block can hold it by chance.
const CREDENTIAL: &[u8] = b"sk-caller-7f3a9c1e5b2d4f60-a8e6c4b2d0f1e3a5";

/// Blocks are scanned only while this is set.
static ARMED: AtomicBool = AtomicBool::new(false);
/// Blocks handed back holding the credential.
static DIRTY: AtomicUsize = AtomicUsize::new(0);
/// The size of the first such block (what kind of buffer it was).
static FIRST_DIRTY_SIZE: AtomicUsize = AtomicUsize::new(0);

struct Scanning;

fn scan(block: &[u8]) {
    if block.len() >= CREDENTIAL.len()
        && block
            .windows(CREDENTIAL.len())
            .any(|window| window == CREDENTIAL)
    {
        if DIRTY.fetch_add(1, Ordering::SeqCst) == 0 {
            FIRST_DIRTY_SIZE.store(block.len(), Ordering::SeqCst);
        }
    }
}

// SAFETY: every call is forwarded verbatim to the system allocator. Before a block is released it
// is read (never written) through the pointer and size the caller is giving back, which are valid
// for reads until the forwarded call returns.
unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded as given.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded as given.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) {
            // SAFETY: `ptr` is valid for reads of `layout.size()` bytes until it is released below.
            scan(unsafe { std::slice::from_raw_parts(ptr, layout.size()) });
        }
        // SAFETY: forwarded as given.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A block that moves leaves its old bytes behind: allocate, copy, scan and release the old
        // one here, so the old block is seen exactly as a plain release would see it.
        // SAFETY: the new layout has the old alignment and a size the caller vouches for.
        let fresh =
            unsafe { System.alloc(Layout::from_size_align_unchecked(new_size, layout.align())) };
        if fresh.is_null() {
            return fresh;
        }
        // SAFETY: both blocks are valid for the smaller of the two sizes and do not overlap.
        unsafe { std::ptr::copy_nonoverlapping(ptr, fresh, layout.size().min(new_size)) };
        // SAFETY: the old block is released exactly once, through the scanning release.
        unsafe { self.dealloc(ptr, layout) };
        fresh
    }
}

#[global_allocator]
static ALLOC: Scanning = Scanning;

/// A storage account that admits everything.
struct Open;

impl StorageAccount for Open {
    fn try_reserve(&self, _bytes: usize) -> Result<(), StorageDenied> {
        Ok(())
    }
    fn release(&self, _bytes: usize) {}
}

fn request() -> Vec<u8> {
    let mut request = b"POST /v1/chat/completions HTTP/1.1\r\nhost: gateway.example\r\n\
        content-type: application/json\r\ncontent-length: 2\r\nauthorization: Bearer "
        .to_vec();
    request.extend_from_slice(CREDENTIAL);
    request.extend_from_slice(b"\r\n\r\n{}");
    request
}

#[test]
fn a_callers_credential_is_in_no_block_the_http_image_gives_back() {
    let harness = Harness::admit_linked(&busbar_transport_http::PLUGIN, FakeNeeds::new())
        .expect("the linked http image admits");
    let port = harness
        .open_transport("busbar-transport-http", b"{}")
        .expect("the linked http image opens");
    // The test's own copy of the request is made and wiped outside the armed window.
    let mut bytes = request();

    ARMED.store(true, Ordering::SeqCst);
    {
        let conn = ConnIn {
            role: wire::ROLE_SERVER,
            flags: 0,
            alpn: "http/1.1",
            sni: "",
            peer: "127.0.0.1:50000",
            local: "127.0.0.1:8080",
            tls_peer_cert: &[],
            leftover: &[],
            head: &[],
            local_fingerprint: "",
            mono_ns: 1,
        };
        let mut session = TransportConn::begin(
            Arc::clone(&port),
            &conn,
            None,
            Instant::now(),
            StorageSource::new(Arc::new(Open) as Arc<dyn StorageAccount>),
        )
        .expect("the session begins");
        // The request arrives in two reads, split inside the credential, so the library's read
        // buffer has to grow and move with part of the credential in it.
        let cut = bytes.len() - CREDENTIAL.len() / 2 - 6;
        session
            .ingest(&bytes[..cut], Instant::now())
            .expect("the first read is taken");
        session
            .ingest(&bytes[cut..], Instant::now())
            .expect("the rest is taken");
        // The caller goes away: the session ends and everything it held is released.
        let _ = session.ingest(&[], Instant::now());
        let _ = session.close(wire::CR_NORMAL, Instant::now());
        drop(session);
    }
    ARMED.store(false, Ordering::SeqCst);
    bytes.fill(0);

    assert_eq!(
        DIRTY.load(Ordering::SeqCst),
        0,
        "{} block(s) were given back still holding the caller's credential (the first was {} \
         bytes): the HTTP library's copy of the request is not wiped",
        DIRTY.load(Ordering::SeqCst),
        FIRST_DIRTY_SIZE.load(Ordering::SeqCst),
    );
}

// THE FORK CHANGE THIS TEST ASKS FOR (our hyper fork; text for a human to write up, the forks
// line owns the change):
//
// 1. `src/proto/h1/io.rs`, `Buffered`: the read buffer (`read_buf: BytesMut`) is wiped over what
//    was filled before it is released or grown: on `Drop`, in `into_inner`, and where
//    `read_buf.reserve` moves the block (reserve into a fresh block, copy, wipe the old one). The
//    slices a parsed head hands out (`Bytes` split off the buffer) share that block, so the wipe
//    is done when the last of them is dropped: a `Bytes` made with `Bytes::from_owner` over a
//    block whose owner wipes on drop gives exactly that.
// 2. `src/proto/h1/role.rs`, `Server::parse`: header values are taken as slices of that same
//    wiping block (they already are slices of the read buffer); no value is copied into a fresh
//    `HeaderValue` allocation. Where a copy is unavoidable (a folded or re-cased line), the copy
//    is made in a wiping block too.
// 3. `h2` fork, `src/hpack/decoder.rs`: decoded literal values (Huffman output and the dynamic
//    table's entries) are held in wiping blocks; an entry evicted from the dynamic table is wiped.
// 4. Nothing else changes: the same bytes are read and parsed in the same order.
