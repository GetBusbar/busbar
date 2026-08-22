// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JOURNAL family of the plane host-vtable, wired over busbar-core's ONE real audit chain
//! ([`crate::audit`]).
//!
//! ## The seam contract (from the Phase-3 chain-cleave spec, §3)
//!
//! The HOST owns the ONE hash chain; a plane keeps only its *record shape + framing* and hands the
//! host its OWN fields as a pre-framed content SUFFIX (bytes). The host frames the PRELUDE
//! (`prev_hash`, then `scope` iff [`FramingDesc::digests_scope`], then `seq`) in the stream's
//! [`Framing`], byte-concatenates the plane's suffix, digests, links, and appends. The digest input is
//!
//! ```text
//! digest_input = frame_prelude(prev_hash, [scope if digests_scope], seq, framing) ⧺ content_suffix
//! hash         = sha256_hex(digest_input)
//! ```
//!
//! and it is produced through the SAME [`crate::audit::Digest`] mechanism the verifier re-runs, so an
//! appended chain [`crate::audit::verify_chain`]-passes byte-identically.
//!
//! ## The PipeSeparated landmine (spec §3b/§3c)
//!
//! For [`Framing::PipeSeparated`] a `|` is emitted BEFORE every field except the first (`started`).
//! The prelude always writes `prev_hash` first (even when empty at genesis), so `started` is true by
//! the time the suffix joins — meaning the plane must pre-frame its suffix WITH its leading `|`
//! (Option A: `content = "|ts|kind|…"`), and the host does a pure byte concat via
//! [`crate::audit::Digest::raw`]. If the suffix were framed in a fresh `Digest` (`started == false`)
//! the join would be short exactly one `|` and every PipeSeparated chain would report `DigestMismatch`
//! at the next boot. For [`Framing::LengthPrefixed`] every field self-delimits, so concatenation is
//! exact with no separator. Both cases are handled uniformly here: the prelude is framed, the suffix is
//! appended RAW.
//!
//! ## Phase 3 note
//!
//! The full generic `audit::Journal` (host-side seq-authority + per-scope position cache + LRU +
//! store-resume, naming no plane type) is PHASE 3. This module wires FAITHFULLY to the existing
//! [`crate::audit::Chain::append`] per scope — same seq authority, same seal/digest — producing
//! byte-identical digests, and holds the positions + rows in a process-local registry. No persisted
//! byte format is changed. The `// Phase 3: cleave to audit::Journal` markers below flag the two
//! places that relocate onto the durable store.

use super::recover;
use crate::audit::{frame_prelude, Chain, ChainLabels, ChainedRecord, Digest, Framing};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{Framing as AbiFraming, FramingDesc, JournalQuery, Seq, StatusClass};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};

/// One appended journal record: the host-assigned prelude (`scope`/`seq`/`prev_hash`/`hash`) plus the
/// plane's opaque pre-framed content suffix and the stream's framing declaration. Implements the real
/// [`ChainedRecord`] so the ONE [`crate::audit`] verifier walks it unchanged.
pub(crate) struct PlaneJournalRecord {
    scope: String,
    seq: u64,
    prev_hash: String,
    hash: String,
    /// The plane's OWN fields, already framed as a suffix (leading `|` for PipeSeparated — Option A).
    content: Vec<u8>,
    /// The stream's prelude framing (carried per-record because the host serves many streams).
    framing: Framing,
    /// Whether the scope participates in the digest (admin-style streams omit it).
    digests_scope: bool,
}

/// The caller payload for one append: everything the plane supplies. Carries NO `seq`/`prev_hash`/
/// `hash` — those are the chain's authority, assigned by [`Chain::append`].
pub(crate) struct PlaneJournalInput {
    content: Vec<u8>,
    framing: Framing,
    digests_scope: bool,
}

impl ChainedRecord for PlaneJournalRecord {
    type Input = PlaneJournalInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the plane journal chain",
        scope: "scope",
    };
    // Unused for framing: `digest_fields` feeds the prelude framed in the RECORD's per-instance
    // `framing` and then the pre-framed suffix RAW, so this const never governs any byte. It only
    // satisfies the trait; the real framing travels on the record (the Phase-3 shape).
    const FRAMING: Framing = Framing::LengthPrefixed;

    fn scope_of(&self) -> &str {
        &self.scope
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn prev_hash(&self) -> &str {
        &self.prev_hash
    }
    fn hash(&self) -> &str {
        &self.hash
    }

    fn link(scope: &str, seq: u64, prev_hash: String, input: PlaneJournalInput) -> Self {
        PlaneJournalRecord {
            scope: scope.to_string(),
            seq,
            prev_hash,
            hash: String::new(),
            content: input.content,
            framing: input.framing,
            digests_scope: input.digests_scope,
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    fn digest_fields(&self, d: &mut Digest) {
        // HOST frames the prelude; the plane's suffix is appended RAW (Option A) — the two Digest::raw
        // calls are a pure byte concat, so `sha256_hex(prelude ⧺ suffix)` matches the legacy single
        // buffer for BOTH framings (the PipeSeparated join `|` lives inside `content`).
        let scope = self.digests_scope.then_some(self.scope.as_str());
        d.raw(&frame_prelude(
            self.framing,
            &self.prev_hash,
            scope,
            self.seq,
        ));
        d.raw(&self.content);
    }
}

/// One scope's live position + its appended rows. The `Chain` is the seq authority (identical to the
/// three shipped streams); `rows` is the store stand-in this Phase-2 bridge holds in-process.
struct ScopeState {
    chain: Chain<PlaneJournalRecord>,
    rows: Vec<PlaneJournalRecord>,
}

/// The process-local per-scope registry. Phase 3: cleave to `audit::Journal` — this map (position
/// cache + rows) becomes the generic scope-keyed Journal over an `Arc<dyn PlaneStore>`.
fn journals() -> &'static Mutex<HashMap<u32, ScopeState>> {
    static J: OnceLock<Mutex<HashMap<u32, ScopeState>>> = OnceLock::new();
    J.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Poison-recovering lock: a panic mid-append must not wedge the registry (same discipline as the
/// dispatch arena).
fn lock() -> std::sync::MutexGuard<'static, HashMap<u32, ScopeState>> {
    journals().lock().unwrap_or_else(|e| e.into_inner())
}

fn map_framing(f: AbiFraming) -> Framing {
    match f {
        AbiFraming::LengthPrefixed => Framing::LengthPrefixed,
        AbiFraming::PipeSeparated => Framing::PipeSeparated,
    }
}

/// WIRED `journal_append` → [`crate::audit::Chain::append`] for the scope. Frames the prelude in the
/// [`FramingDesc`]'s framing, joins the plane's pre-framed content suffix, and appends to the real
/// chain, returning the assigned [`Seq`]. Fail-closed: any panic / null POD → [`Seq::NONE`] (the
/// reserved invalid handle), never a fabricated sequence.
pub(crate) extern "C-unwind" fn journal_append(
    host: HostCtx,
    scope: u32,
    content_ptr: *const u8,
    content_len: usize,
    framing: *const FramingDesc,
) -> Seq {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`). The state is recovered even though this
        // slot draws the chain from the process registry, keeping the boundary discipline uniform.
        let _state = unsafe { recover(host) };
        if framing.is_null() {
            return Seq::NONE;
        }
        // SAFETY: a non-null `framing` is a live, initialized `FramingDesc` for the call (ABI).
        let fd = unsafe { &*framing };
        let content: Vec<u8> = if content_ptr.is_null() || content_len == 0 {
            Vec::new()
        } else {
            // SAFETY: `(content_ptr, content_len)` is a live borrowed range for the call (ABI).
            unsafe { std::slice::from_raw_parts(content_ptr, content_len) }.to_vec()
        };
        let input = PlaneJournalInput {
            content,
            framing: map_framing(fd.framing),
            digests_scope: fd.digests_scope != 0,
        };
        let scope_str = scope.to_string();

        let mut map = lock();
        let st = map.entry(scope).or_insert_with(|| ScopeState {
            chain: Chain::new(),
            rows: Vec::new(),
        });
        // Phase 3: cleave to audit::Journal — advance the RAM position only AFTER a durable write ok.
        // Here (no durable store yet) append == commit; the seq authority is already the real `Chain`.
        let record = st.chain.append(&scope_str, input);
        let seq = record.seq();
        st.rows.push(record);
        Seq(seq)
    }))
    .unwrap_or(Seq::NONE) // fail-closed: a panicked append yields no sequence.
}

/// WIRED `journal_read` → the real audit read path: [`crate::audit::verify_chain`] over the stored
/// rows, then the requested window encoded into the caller buffer. Fail-closed: a panic → `Fault`, a
/// tamper-detected chain → `Fault`, a null query/out → `Refused`, a too-small buffer → `Refused` with
/// the required length reported in `out_written`.
pub(crate) extern "C-unwind" fn journal_read(
    host: HostCtx,
    query: *const JournalQuery,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        if query.is_null() || out_written.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `query` is a live, initialized `JournalQuery` for the call (ABI).
        let q = unsafe { &*query };
        // SAFETY: `out_written` is a live, writable `usize` for the call (ABI). Default to 0.
        unsafe { *out_written = 0 };

        let map = lock();
        let Some(st) = map.get(&q.scope) else {
            // An unknown scope has no rows; that is a legitimate empty read, not a fault.
            return StatusClass::Ok;
        };
        // The real audit read path VERIFIES the stored chain before it is trusted — a tamper is
        // surfaced as a fault rather than silently handed back (mirrors `Chain::from_persisted`).
        if crate::audit::verify_chain(&st.rows).is_err() {
            return StatusClass::Fault;
        }
        // Phase 3: cleave to audit::Journal — this window read becomes a store range scan.
        let encoded = encode_rows(&st.rows, q.from_seq, q.limit);
        if encoded.len() > buf_cap {
            // SAFETY: see above — report the required length so the caller can size a retry.
            unsafe { *out_written = encoded.len() };
            return StatusClass::Refused;
        }
        if !buf.is_null() && !encoded.is_empty() {
            // SAFETY: `encoded.len() <= buf_cap` and `buf` is a live range of `buf_cap` bytes (ABI).
            unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), buf, encoded.len()) };
        }
        // SAFETY: see above.
        unsafe { *out_written = encoded.len() };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

/// Encode the rows whose `seq >= from_seq` (up to `limit`, `0` = all) into a self-describing blob:
/// `count:u32-le`, then per row `seq:u64-le · prev_hash · hash · content`, each variable field as
/// `len:u32-le ⧺ bytes`. A neutral bytes-tier shape (the cold read carries bytes, not typed rows).
fn encode_rows(rows: &[PlaneJournalRecord], from_seq: u64, limit: u64) -> Vec<u8> {
    let take = if limit == 0 {
        usize::MAX
    } else {
        limit as usize
    };
    let selected: Vec<&PlaneJournalRecord> = rows
        .iter()
        .filter(|r| r.seq >= from_seq)
        .take(take)
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&(selected.len() as u32).to_le_bytes());
    let field = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    };
    for r in selected {
        out.extend_from_slice(&r.seq.to_le_bytes());
        field(&mut out, r.prev_hash.as_bytes());
        field(&mut out, r.hash.as_bytes());
        field(&mut out, &r.content);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane_host::{recover, with_dispatch_scope, HostState};
    use busbar_plugin::hot::host::PlaneHostVtable;
    use busbar_plugin::hot::POD_VERSION;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A distinct scope per test run so the process-global registry never collides across parallel
    /// tests (each test owns a fresh chain).
    static NEXT_SCOPE: AtomicU32 = AtomicU32::new(1);
    fn fresh_scope() -> u32 {
        NEXT_SCOPE.fetch_add(1, Ordering::SeqCst)
    }

    fn framing_desc(framing: AbiFraming, digests_scope: u8) -> FramingDesc {
        FramingDesc {
            size: core::mem::size_of::<FramingDesc>() as u32,
            version: POD_VERSION,
            framing,
            digests_scope,
        }
    }

    fn query(scope: u32) -> JournalQuery {
        JournalQuery {
            size: core::mem::size_of::<JournalQuery>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope,
            _reserved2: 0,
            from_seq: 0,
            limit: 0,
        }
    }

    fn with_test_state<R>(f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        let app = crate::test_support::TestApp::new().build();
        with_dispatch_scope(&app, |host, vt| {
            // SAFETY: live HostState minted by `with_dispatch_scope`.
            let _state: &HostState = unsafe { recover(host) };
            f(host, vt)
        })
    }

    /// The task's gate: append two records to a scope via the VTABLE, then the REAL `verify_chain`
    /// passes on the result and the second record's `prev_hash` byte-exactly links the first.
    fn append_two_and_verify(framing: AbiFraming, digests_scope: u8) {
        let scope = fresh_scope();
        let fd = framing_desc(framing, digests_scope);
        with_test_state(|host, vt| {
            let append = vt.journal_append.unwrap();
            let c1 = b"|ts1|first"; // Option A: leading `|` is inert under LengthPrefixed, load-bearing under PipeSeparated
            let c2 = b"|ts2|second";
            let s1 = append(
                host,
                scope,
                c1.as_ptr(),
                c1.len(),
                &fd as *const FramingDesc,
            );
            let s2 = append(
                host,
                scope,
                c2.as_ptr(),
                c2.len(),
                &fd as *const FramingDesc,
            );
            assert_eq!(s1, Seq(1), "genesis record is seq 1");
            assert_eq!(s2, Seq(2), "second record is seq 2");
        });

        // Read the rows back through the real audit chain: verify_chain must pass, and the link must
        // be byte-exact (record 2's prev_hash == record 1's hash, record 1's prev_hash empty).
        let map = lock();
        let st = map.get(&scope).expect("scope has rows");
        assert!(
            crate::audit::verify_chain(&st.rows).is_ok(),
            "the appended chain must verify byte-identically"
        );
        assert_eq!(st.rows.len(), 2);
        assert_eq!(st.rows[0].prev_hash(), "", "genesis prev_hash is empty");
        assert!(!st.rows[0].hash().is_empty());
        assert_eq!(
            st.rows[1].prev_hash(),
            st.rows[0].hash(),
            "record 2 links record 1 byte-exactly"
        );
    }

    #[test]
    fn append_two_verifies_length_prefixed_with_scope() {
        append_two_and_verify(AbiFraming::LengthPrefixed, 1);
    }

    #[test]
    fn append_two_verifies_pipe_separated_with_scope() {
        // The PipeSeparated landmine: the leading `|` in the suffix + the always-first empty/nonempty
        // prev_hash must reproduce the legacy join. verify_chain re-runs the SAME digest, so a missing
        // `|` at the join would surface here as DigestMismatch.
        append_two_and_verify(AbiFraming::PipeSeparated, 1);
    }

    #[test]
    fn append_two_verifies_pipe_separated_no_scope() {
        // admin-style: digests_scope = 0 — scope must NOT enter the digest.
        append_two_and_verify(AbiFraming::PipeSeparated, 0);
    }

    /// The digest is byte-exact against a hand-built `frame_prelude ⧺ content` recompute — this
    /// localizes any failure to the reframe rather than the whole chain walk (spec §4b direct assert).
    #[test]
    fn genesis_digest_matches_hand_built_prelude_join() {
        let scope = fresh_scope();
        let fd = framing_desc(AbiFraming::PipeSeparated, 1);
        with_test_state(|host, vt| {
            let content = b"|ts|kind|state";
            let seq = (vt.journal_append.unwrap())(
                host,
                scope,
                content.as_ptr(),
                content.len(),
                &fd as *const FramingDesc,
            );
            assert_eq!(seq, Seq(1));
        });
        let map = lock();
        let st = map.get(&scope).unwrap();
        let mut expected_input =
            frame_prelude(Framing::PipeSeparated, "", Some(&scope.to_string()), 1);
        expected_input.extend_from_slice(b"|ts|kind|state");
        let expected = busbar_api::sha256_hex(&expected_input);
        assert_eq!(
            st.rows[0].hash(),
            expected,
            "genesis hash == sha256(prelude ⧺ suffix)"
        );
    }

    #[test]
    fn journal_read_returns_ok_and_writes_bytes() {
        let scope = fresh_scope();
        let fd = framing_desc(AbiFraming::LengthPrefixed, 1);
        let q = query(scope);
        with_test_state(|host, vt| {
            let c = b"payload";
            (vt.journal_append.unwrap())(
                host,
                scope,
                c.as_ptr(),
                c.len(),
                &fd as *const FramingDesc,
            );

            let mut out_written: usize = 0;
            let read = vt.journal_read.unwrap();
            // Undersized buffer: Refused, required length reported.
            let mut tiny = [0u8; 1];
            let s = read(
                host,
                &q as *const JournalQuery,
                tiny.as_mut_ptr(),
                tiny.len(),
                &mut out_written as *mut usize,
            );
            assert_eq!(s, StatusClass::Refused);
            assert!(out_written > tiny.len(), "reports the required size");

            let needed = out_written;
            let mut big = vec![0u8; needed];
            let s = read(
                host,
                &q as *const JournalQuery,
                big.as_mut_ptr(),
                big.len(),
                &mut out_written as *mut usize,
            );
            assert_eq!(s, StatusClass::Ok);
            assert_eq!(out_written, needed);
            // First 4 bytes are the row count = 1.
            assert_eq!(u32::from_le_bytes(big[0..4].try_into().unwrap()), 1);
        });
    }

    #[test]
    fn null_pods_fail_closed() {
        let fd = framing_desc(AbiFraming::LengthPrefixed, 1);
        with_test_state(|host, vt| {
            // Null framing → Seq::NONE, not a fabricated sequence.
            let s =
                (vt.journal_append.unwrap())(host, 999_001, std::ptr::null(), 0, std::ptr::null());
            assert_eq!(s, Seq::NONE);
            let _ = fd;
            // Null query → Refused.
            let mut out_written: usize = 0;
            let s = (vt.journal_read.unwrap())(
                host,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                &mut out_written as *mut usize,
            );
            assert_eq!(s, StatusClass::Refused);
        });
    }
}
