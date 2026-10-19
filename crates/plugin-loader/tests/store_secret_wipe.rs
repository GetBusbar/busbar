// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED (Q128 plugin-loader u72 LOW): the host's copies of a credential's secret are wiped before
//! they are freed. Appendix A's memory classes: the call-scoped bytes of a secret are zeroised; THE
//! DESIGN's outbound section: auth material is zeroised.
//!
//! Its own test binary, because the witness is a `#[global_allocator]` that reads every buffer
//! just before it is freed (or moved by a realloc) while the scan is armed, and counts one still
//! holding the test's secret. The scan is process-wide (a store crossing may run on a dispatcher
//! worker), and this binary runs one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use busbar_contract::abi::store::OpId;
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, RecordStore, SecretForm, VirtualKey,
};
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;

// The build's store, reached BY KIND (`build.rs` writes the fixture from the both-ways row).
include!(concat!(env!("OUT_DIR"), "/store_fixture.rs"));

static SCANNING: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicU64 = AtomicU64::new(0);

/// The secret the test's credential carries; freed memory still holding it was not wiped.
const MARKER: &[u8] = b"MARKER-a1b2c3d4e5f60718293a4b5c6d7e8f90";

fn holds_marker(p: *const u8, len: usize) -> bool {
    if p.is_null() || len < MARKER.len() {
        return false;
    }
    // SAFETY: the allocator reads `p` for its layout's size before the memory is released.
    let bytes = unsafe { std::slice::from_raw_parts(p, len) };
    bytes.windows(MARKER.len()).any(|w| w == MARKER)
}

/// `System`, reading each freed buffer for the secret while the scan is armed.
struct Witness;

// SAFETY: every method forwards to `System` unchanged; the additions only read the buffer being
// released (still live) and bump an atomic.
unsafe impl GlobalAlloc for Witness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded verbatim.
        unsafe { System.alloc(layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let held = SCANNING.load(Ordering::Relaxed) && holds_marker(p, layout.size());
        // SAFETY: forwarded verbatim.
        let moved = unsafe { System.realloc(p, layout, new_size) };
        if held && moved != p {
            UNWIPED.fetch_add(1, Ordering::Relaxed);
        }
        moved
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        if SCANNING.load(Ordering::Relaxed) && holds_marker(p, layout.size()) {
            UNWIPED.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarded verbatim.
        unsafe { System.dealloc(p, layout) }
    }
}

#[global_allocator]
static WITNESS: Witness = Witness;

fn mint() -> OpId {
    static N: AtomicU64 = AtomicU64::new(0);
    OpId::from_parts(0x5ec7, N.fetch_add(1, Ordering::Relaxed) + 1)
}

fn compiled_in() -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(store_fixture::door).expect("the store states its Statement");
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::NoNeeds,
    };
    let p = load_linked::<Store>(&row, bind).expect("door");
    LoadedStore::open(p, d, b"{}", mint).expect("open")
}

fn credential() -> CredentialSecret {
    let mut secret = String::with_capacity(9 + MARKER.len());
    secret.push_str("v1:plain:");
    secret.push_str(std::str::from_utf8(MARKER).expect("ascii"));
    CredentialSecret {
        meta: CredentialMeta {
            id: "c1".into(),
            key_id: "k1".into(),
            kind: "generic".into(),
            slot: 0,
            public_id: "pub".into(),
            secret_form: SecretForm::Recoverable,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 1,
        },
        secret,
    }
}

/// How many buffers still holding the secret `f` freed.
fn scanned<T>(f: impl FnOnce() -> T) -> (T, u64) {
    UNWIPED.store(0, Ordering::SeqCst);
    SCANNING.store(true, Ordering::SeqCst);
    let r = f();
    SCANNING.store(false, Ordering::SeqCst);
    (r, UNWIPED.load(Ordering::SeqCst))
}

#[test]
fn red_the_host_frees_no_copy_of_a_credential_secret_unwiped() {
    let s = compiled_in();
    s.put_key(&VirtualKey {
        id: "k1".into(),
        generation_hash: "h_k1".into(),
        name: "t".into(),
        enabled: true,
        ..Default::default()
    })
    .expect("key");
    let c = credential();
    let ((), put) = scanned(|| s.put_credential(&c).expect("put"));
    assert_eq!(
        put, 0,
        "putting a credential freed {put} unwiped copy(ies) of its secret"
    );

    let (mut got, read) = scanned(|| {
        s.lookup_credential_secret("generic", "pub")
            .expect("lookup")
            .expect("found")
    });
    assert_eq!(got.secret.as_bytes(), c.secret.as_bytes());
    assert_eq!(
        read, 0,
        "reading a credential freed {read} unwiped copy(ies) of its secret"
    );

    let (mut listed, since) = scanned(|| s.list_credentials_since(0).expect("since"));
    assert_eq!(listed.len(), 1);
    assert_eq!(
        since, 0,
        "listing credentials freed {since} unwiped copy(ies) of a secret"
    );

    // The test's own copies are its to wipe.
    zero(&mut got.secret);
    for l in &mut listed {
        zero(&mut l.secret);
    }
}

fn zero(s: &mut String) {
    // SAFETY: zero bytes are valid UTF-8.
    unsafe { s.as_bytes_mut() }.fill(0);
}
