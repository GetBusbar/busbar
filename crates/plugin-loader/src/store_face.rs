//! The store kind's COMPLETE face over a loaded ABI-2/4 artifact.
//!
//! [`busbar_contract::kinds::Store`] is the store kind's one face and carries all forty-five verbs.
//! A store artifact this binary can load speaks the 1.5.5 vocabulary
//! ([`busbar_api::Store`], thirty-three verbs at payload schema 2..=4) and nothing else. This module
//! is the translator between the two, and it is the ONLY place in the tree that knows both.
//!
//! # Why a new module rather than another `impl` on `StoreAdapter`
//!
//! [`crate::store_adapter`] binds the same loaded store to the three UNIT-side seams
//! (`SliceStore`, `VerbStore`, `Shipper`) and is proven by the ABI-2 adapter battery under
//! `src/tests/`. The face is a fourth seam with a different shape, so it is written here, beside
//! that file rather than inside it: the battery stays a proof of the wire it was written against,
//! and a change here cannot silently move it. The node-local state the two share is reached through
//! `StoreAdapter`'s own published seams, never copied — see [`StoreFace::reserve`] and
//! [`StoreFace::replay_put`].
//!
//! # The three ways a face verb is answered
//!
//! * **DELEGATE** — the 1.5.5 wire has the same verb under another name. Twenty-four of the
//!   forty-five. The rename is the whole of the translation.
//! * **TRANSLATE** — the 1.5.5 wire has a verb of a different shape. Seven. Each carries the reason
//!   the shapes differ at its own call site.
//! * **SHIM** — the 1.5.5 wire has no such verb at all. Fourteen. PB-93 fixes what a shim may do:
//!   answer node-locally, *never* an error, never a log line, never a boot refusal. A deployment
//!   whose store predates an operation gets the answer a single node can give, which is the answer
//!   it got before this face existed.
//!
//! # THE FIDELITY LIMIT, and it binds the readers too
//!
//! The 1.5.5 wire carries its failures as [`busbar_api::StoreError`] — one string, no class. The
//! face returns [`PluginError`] over a CLOSED ten-class taxonomy. An ABI-2/4 artifact's failures
//! therefore **cannot be classified**: [`legacy_error`] maps every one of them to
//! [`ErrorClass::Internal`] under the single code [`LEGACY_CODE`], with the 1.5.5 string preserved
//! verbatim as the developer message. This is not a gap to be closed later — it is the permanent
//! price of keeping the ABI-2 window open, and it is written here because here is where the
//! information is lost.
//!
//! **A caller must not key behaviour off [`PluginError::class`] for a store failure.** Every class
//! it can observe from a loaded store is `Internal`, so a refusal path that branched on the class
//! would branch on nothing over an ABI-2 artifact and on something over a native one — two
//! different refusal bodies for one condition. Callers read the message, as they did before this
//! face existed, and that is what keeps the money and refusal bytes identical across the window.

use crate::store_adapter::{StoreAdapter, REPLAY_TTL_SECS};
use busbar_api::Store as AbiStore;
use busbar_api::StoreError;
use busbar_contract::error::{ErrorClass, PluginError};
use busbar_contract::ids::{PrincipalId, RecordSchemaId, Registration, SessionId};
use busbar_contract::kinds::{Head, RecordBytes, SliceGrant, Store as StoreFaceTrait};
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};
use busbar_contract::store::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneDisposition,
    PlaneRecord, PlaneSelector, UsageDelta, UsageLedger, VirtualKey,
};
use busbar_unit_verbs::store::Store as VerbStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// The stream a 1.5.5 store's administrative audit rows travel on.
///
/// The face's journal half is stream-addressed; the 1.5.5 wire has exactly one journal — the audit
/// list — so exactly one stream name reaches it. Every other stream is the shim's.
pub const AUDIT_STREAM: &str = "audit";

/// The one code every failure a loaded ABI-2/4 store reports is carried under.
///
/// One code, not a family: the wire gave a string and nothing else, so inventing a second code
/// would be inventing a distinction the artifact never made. The string itself is on the
/// developer message, verbatim.
pub const LEGACY_CODE: &str = "store.legacy";

/// The code an adapter-side translation refusal is carried under.
///
/// Distinct from [`LEGACY_CODE`] on purpose: this one is the ADAPTER saying it cannot express the
/// caller's request in the 1.5.5 vocabulary, which is a different fact from the store having
/// failed, and an operator reading a log must not have to guess which happened.
pub const TRANSLATION_CODE: &str = "store.adapter";

/// Carry a 1.5.5 failure across the face, losing nothing that was there.
///
/// `Internal` because the taxonomy is closed and the wire named no class — see the module preamble.
/// The class is the honest one for "the plugin's own fault, and every failure that predates a
/// taxonomy", which is precisely what an unclassified 1.5.5 string is.
#[must_use]
pub fn legacy_error(e: &StoreError) -> PluginError {
    PluginError::new(ErrorClass::Internal, LEGACY_CODE).with_message(e.0.clone())
}

/// The face's record key as the 1.5.5 record id.
///
/// The face keys a record on BYTES; the 1.5.5 row keys it on a `String`. A key that is not UTF-8
/// has no 1.5.5 spelling at all, and guessing one (a hex rendering, say) would put a row under an
/// id no native store would ever write — so it is refused, loudly, as the adapter's own refusal.
fn record_id(key: &[u8]) -> Result<&str, PluginError> {
    std::str::from_utf8(key).map_err(|_| {
        PluginError::new(ErrorClass::Malformed, TRANSLATION_CODE).with_message(
            "this record key is not UTF-8 and the 1.5.5 store wire keys a record on a string, so \
             the row has no spelling on that wire",
        )
    })
}

/// One stream's head, and the moment this node's shim last advanced it.
///
/// The moment travels WITH the head because [`StoreFace::purge_before`] is the one face verb whose
/// axis the 1.5.5 wire does not share: the face purges by SEQUENCE and the 1.5.5 verb purges by
/// TIME, and the stream's own head is the only place in the process where the two axes are known to
/// meet. Kept as one value so a reader can never pair one stream's sequence with another moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StreamMark {
    head: Head,
    /// Unix seconds at which `head` was reached.
    head_ts: u64,
}

/// The claims one unit made in one namespace, so a failed unit's claims can be forgotten.
type ClaimBook = HashMap<(String, u64), Vec<String>>;

/// The face-local state for the verbs the 1.5.5 wire has no home for at all.
///
/// Deliberately NOT a second copy of [`crate::store_adapter`]'s shim: the two pieces of node-local
/// state that seam already holds — the slice ledger and the sealed replay cache — are reached
/// through its published seams below, so a slice drawn through the face and one drawn through the
/// kernel's `SliceStore` are the same slice. What lives here is only what has no home anywhere
/// else.
///
/// # The lock order, stated once
///
/// Four independent mutexes, and no thread takes more than one: every verb below takes its lock,
/// does its whole answer under it, and drops it before returning. There is no order to get wrong
/// because there is no pair.
#[derive(Default)]
struct FaceShim {
    /// Where each stream has reached, for `heads`, `append_batch` and `purge_before`.
    streams: Mutex<HashMap<String, StreamMark>>,
    /// Which idempotency keys each unit claimed, for `void_claims`.
    claims: Mutex<ClaimBook>,
    /// What each bucket has outstanding, for `reserve`/`release`.
    slices: Mutex<HashMap<String, Vec<u64>>>,
    /// The fleet session directory, which on one node is this node's.
    sessions: Mutex<HashMap<u64, (String, String)>>,
    /// The previous release's own cells, for a migrating deployment.
    cells: Mutex<HashMap<String, Vec<u8>>>,
}

impl FaceShim {
    /// A poisoned shim lock is recovered from, never propagated: a panic somewhere else must not
    /// turn every later face call into an error, which is exactly what a shim may not do.
    fn streams(&self) -> MutexGuard<'_, HashMap<String, StreamMark>> {
        self.streams.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn claims(&self) -> MutexGuard<'_, ClaimBook> {
        self.claims.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn slices(&self) -> MutexGuard<'_, HashMap<String, Vec<u64>>> {
        self.slices.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn sessions(&self) -> MutexGuard<'_, HashMap<u64, (String, String)>> {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn cells(&self) -> MutexGuard<'_, HashMap<String, Vec<u8>>> {
        self.cells.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// A loaded store, presented as the store kind's complete face.
///
/// Cheap to clone — every clone is the same store, the same adapter and the same shim.
#[derive(Clone)]
pub struct StoreFace {
    inner: Arc<FaceInner>,
}

struct FaceInner {
    /// The unit-side seams over the same loaded store. The face reaches the loaded store through
    /// [`StoreAdapter::store`] and reaches the node-local slice and replay state through the seams
    /// this adapter already publishes.
    adapter: StoreAdapter,
    /// The registry key, interned ONCE at construction — see [`StoreFace::over`].
    key: &'static str,
    shim: FaceShim,
    /// What the sealed-replay TTL and the stream marks age against.
    clock: FaceClock,
}

/// The clock the face's stream marks are stamped from, in unix seconds.
pub type FaceClock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The wall clock, for a face whose caller did not name one.
fn system_clock() -> FaceClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// The one epoch a node-local shim has, matching [`crate::store_adapter`]'s. There is no fleet to
/// advance it and nothing that could observe it advancing.
const SHIM_EPOCH: u64 = 0;

impl StoreFace {
    /// Present `adapter`'s loaded store as the complete face, under the registry key `key`.
    ///
    /// # The interning, and why it happens exactly here
    ///
    /// [`Plugin::key`] answers a `&'static str`; a loaded store's registry key is a `String` read
    /// off its manifest at boot. `Registration::key` is the tree's one reviewed leak-once intern
    /// and it is what bridges the two. It is called ONCE, here, at construction — never per call —
    /// so a face that is built is a face whose name is already in the image's vocabulary.
    ///
    /// `None` is a REFUSAL TO ROUTE on that name, not an error to recover from: the vocabulary is
    /// frozen after boot, or the ceiling is reached, and either way this node will not dispatch on
    /// a name it cannot hold. A caller turns that into a boot refusal, exactly as the intern's own
    /// doc frames it.
    #[must_use]
    pub fn over(adapter: StoreAdapter, registration: &mut Registration, key: &str) -> Option<Self> {
        StoreFace::with_clock(adapter, registration, key, system_clock())
    }

    /// [`StoreFace::over`] against a named clock. Anything that must watch the sealed replay cache
    /// or a stream mark age wants one; the composition root has no reason to name one.
    #[must_use]
    pub fn with_clock(
        adapter: StoreAdapter,
        registration: &mut Registration,
        key: &str,
        clock: FaceClock,
    ) -> Option<Self> {
        let key = registration.key(key)?;
        Some(StoreFace {
            inner: Arc::new(FaceInner {
                adapter,
                key,
                shim: FaceShim::default(),
                clock,
            }),
        })
    }

    /// The unit-side seams over the same loaded store.
    #[must_use]
    pub fn adapter(&self) -> &StoreAdapter {
        &self.inner.adapter
    }

    /// The loaded store itself, at its own vocabulary.
    fn store(&self) -> Arc<dyn AbiStore> {
        self.inner.adapter.store()
    }

    fn now(&self) -> u64 {
        (self.inner.clock)()
    }

    /// The sealed-replay key the verbs unit's cache is written in.
    fn replay_key(namespace: &str, key: &[u8]) -> (String, String) {
        (
            namespace.to_string(),
            key.iter().map(|b| format!("{b:02x}")).collect(),
        )
    }

    /// Advance one stream's mark to `seq` and return the head, stamping the moment it was reached.
    fn advance(&self, stream: &str, seq: u64) -> Head {
        let now = self.now();
        let mut streams = self.inner.shim.streams();
        let mark = streams.entry(stream.to_string()).or_default();
        mark.head = Head {
            seq,
            epoch: SHIM_EPOCH,
        };
        mark.head_ts = now;
        mark.head
    }
}

impl Plugin for StoreFace {
    /// The registry key, interned once at construction.
    fn key(&self) -> &'static str {
        self.inner.key
    }

    fn kind(&self) -> Kind {
        Kind::Store
    }

    /// The payload schema the loaded artifact's signed manifest DECLARES — not the face's own.
    ///
    /// This is what makes `speaks_new_ops` a fact rather than an aspiration: a store at
    /// `STORE_ABI_WITH_NEW_OPS` answers the added operations on its own wire and this module
    /// translates nothing for it, while a store below it is answered here. Reporting the face's
    /// generation for a store that does not speak it would say the opposite of what is true.
    ///
    /// The manifest reads the schema as a `u32` and the generation type holds a `u16`. A number
    /// past that range is above every window this binary has, so it saturates HIGH — "newer than
    /// anything here", which is what it is — rather than wrapping into a number that would read as
    /// loadable. No store the registry admits can reach it; the direction is stated so a later
    /// widening of either type is a change to make deliberately.
    fn abi(&self) -> AbiVersion {
        AbiVersion(u16::try_from(self.inner.adapter.abi_version()).unwrap_or(u16::MAX))
    }
}

impl StoreFaceTrait for StoreFace {
    // ── the journal half ──────────────────────────────────────────────────────────────────────

    /// TRANSLATE. The 1.5.5 wire has one journal — the audit list — so the `audit` stream's records
    /// are decoded to their rows and appended there, one call per row, and the returned head is the
    /// LAST ROW'S OWN sequence: the chain is computed engine-side and a store persists it verbatim,
    /// so the head the face reports must be the row's, never a count this node kept.
    ///
    /// Any OTHER stream has no 1.5.5 home. The shim counts the records and advances that stream's
    /// head, and does not retain them — the same posture `Shipper::ship` takes for the same reason:
    /// the deployment's durability is the legacy rows', a refusal here is a durability failure it
    /// does not actually have, and the log's own buffer already holds what was written.
    fn append_batch(&self, stream: &str, records: &[RecordBytes]) -> Result<Head, PluginError> {
        if stream != AUDIT_STREAM {
            let head = self
                .inner
                .shim
                .streams()
                .get(stream)
                .map_or(0, |m| m.head.seq);
            return Ok(self.advance(stream, head.saturating_add(records.len() as u64)));
        }
        let store = self.store();
        let mut last = self
            .inner
            .shim
            .streams()
            .get(stream)
            .map_or(0, |m| m.head.seq);
        for record in records {
            let entry: AuditRecord = serde_json::from_slice(record.as_slice()).map_err(|e| {
                PluginError::new(ErrorClass::Malformed, TRANSLATION_CODE).with_message(format!(
                    "this record is not an audit row and the 1.5.5 store wire's only journal is \
                     the audit list: {e}"
                ))
            })?;
            store.append_audit(&entry).map_err(|e| legacy_error(&e))?;
            last = entry.seq;
        }
        Ok(self.advance(stream, last))
    }

    /// TRANSLATE. `list_audit_tail` is the LIMIT-at-source read the 1.5.5 doc asks for, so the
    /// limit crosses the wire rather than being applied after a full list is materialised. The
    /// `from` bound is applied here because the 1.5.5 verb has no sequence bound of its own.
    ///
    /// Any other stream reads empty: the shim retained nothing to replay, and saying so is not a
    /// failure.
    fn replay_batch(
        &self,
        stream: &str,
        from: u64,
        limit: u32,
    ) -> Result<Vec<RecordBytes>, PluginError> {
        if stream != AUDIT_STREAM {
            return Ok(Vec::new());
        }
        let rows = self
            .store()
            .list_audit_tail(u64::from(limit))
            .map_err(|e| legacy_error(&e))?;
        rows.iter()
            .filter(|row| row.seq >= from)
            .map(|row| {
                let bytes = serde_json::to_vec(row).map_err(|e| {
                    PluginError::new(ErrorClass::Internal, TRANSLATION_CODE)
                        .with_message(format!("this audit row would not re-encode: {e}"))
                })?;
                RecordBytes::new(bytes).map_err(|len| {
                    PluginError::new(ErrorClass::Internal, TRANSLATION_CODE).with_message(format!(
                        "this audit row is {len} bytes, past the face's record ceiling"
                    ))
                })
            })
            .collect()
    }

    /// SHIM, mirroring the `SliceStore` impl beside it at the same epoch.
    ///
    /// A node whose store cannot hold a fleet-wide window has no fleet to share a cap with, so the
    /// bucket's own cap — enforced by the caps unit, not here — is the whole of the limit, and the
    /// draw is bookkeeping the node already did. The requested epoch is STAMPED, not refused:
    /// there is no other node that could have fenced this one out.
    fn reserve(&self, bucket: &str, amount: u64, _epoch: u64) -> Result<SliceGrant, PluginError> {
        self.inner
            .shim
            .slices()
            .entry(bucket.to_string())
            .or_default()
            .push(amount);
        Ok(SliceGrant {
            amount,
            epoch: SHIM_EPOCH,
        })
    }

    /// SHIM. Give an undrawn slice back. A grant the shim never made is accepted and forgotten
    /// rather than refused — a slice drawn before a restore is exactly that case.
    fn release(&self, bucket: &str, grant: SliceGrant) -> Result<(), PluginError> {
        let mut slices = self.inner.shim.slices();
        if let Some(outstanding) = slices.get_mut(bucket) {
            if let Some(at) = outstanding.iter().position(|held| *held == grant.amount) {
                outstanding.remove(at);
            }
            if outstanding.is_empty() {
                slices.remove(bucket);
            }
        }
        Ok(())
    }

    /// SHIM. Where each stream this node has written has reached.
    fn heads(&self) -> Result<Vec<(String, Head)>, PluginError> {
        let mut heads: Vec<(String, Head)> = self
            .inner
            .shim
            .streams()
            .iter()
            .map(|(stream, mark)| (stream.clone(), mark.head))
            .collect();
        // Sorted so two reads of an unchanged shim answer identically; a hash map's order is not a
        // fact about the journal and must not reach a caller as one.
        heads.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(heads)
    }

    /// SHIM. One node is always alive at its own epoch, and there is nothing that could fence it.
    fn heartbeat(&self, _node: &str, _epoch: u64) -> Result<(), PluginError> {
        Ok(())
    }

    /// SHIM. The only node writes every checkpoint. `false` here would mean waiting for a peer that
    /// does not exist, which is a checkpoint that never lands.
    fn elect_checkpoint(&self, _node: &str, _epoch: u64) -> Result<bool, PluginError> {
        Ok(true)
    }

    /// TRANSLATE. `redeem_plane_token` IS a single-use test-and-set, which is what an idempotency
    /// claim needs, so the claim rides it with the namespace as the record kind. The window is the
    /// verbs unit's own idempotency TTL, so a deployment whose store predates the durable claim
    /// table gets the same window it would get from the store rather than a different one.
    ///
    /// The `(namespace, unit)` pair is remembered node-locally so [`StoreFaceTrait::void_claims`]
    /// has something to forget — the 1.5.5 wire has no un-redeem verb.
    fn claim_key(&self, namespace: &str, key: &[u8], unit: u64) -> Result<bool, PluginError> {
        let token = record_id(key)?;
        let now = self.now();
        let claimed = self
            .store()
            .redeem_plane_token(namespace, token, now.saturating_add(REPLAY_TTL_SECS), now)
            .map_err(|e| legacy_error(&e))?;
        if claimed {
            self.inner
                .shim
                .claims()
                .entry((namespace.to_string(), unit))
                .or_default()
                .push(token.to_string());
        }
        Ok(claimed)
    }

    /// SHIM. The 1.5.5 wire cannot un-redeem a token, so what the shim can drop is its own record
    /// of what this unit claimed. The claim itself ages out under the window `claim_key` set — the
    /// same outcome a store with no void support has always given.
    fn void_claims(&self, namespace: &str, unit: u64) -> Result<(), PluginError> {
        self.inner
            .shim
            .claims()
            .remove(&(namespace.to_string(), unit));
        Ok(())
    }

    /// SHIM, over the SAME sealed replay cache the verbs unit's seam uses — not a second copy.
    /// A response committed through either seam replays through both, which is the whole point of
    /// there being one node-local cache rather than one per seam.
    fn replay_put(&self, namespace: &str, key: &[u8], value: &[u8]) -> Result<(), PluginError> {
        let slot = StoreFace::replay_key(namespace, key);
        VerbStore::commit_new_verb_replay(&self.inner.adapter, &slot, value).map_err(|e| {
            PluginError::new(ErrorClass::Internal, TRANSLATION_CODE).with_message(format!("{e:?}"))
        })
    }

    /// SHIM, over the same cache. The probe RESERVES an unseen slot, which is the discipline the
    /// in-process sibling keeps: a concurrent second caller then sees a reservation rather than
    /// another first sighting. A reserved-but-uncommitted slot reads as `None` — the first caller
    /// is still in flight and has not decided what the answer is. Every probe first drops the slots
    /// past [`REPLAY_TTL_SECS`], which is what bounds the cache.
    fn replay_get(&self, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>, PluginError> {
        let slot = StoreFace::replay_key(namespace, key);
        VerbStore::replay_new_verb(&self.inner.adapter, &slot).map_err(|e| {
            PluginError::new(ErrorClass::Internal, TRANSLATION_CODE).with_message(format!("{e:?}"))
        })
    }

    /// SHIM. On one node the fleet directory is this node's own sessions.
    fn session_put(
        &self,
        session: SessionId,
        node: &str,
        principal: &PrincipalId,
    ) -> Result<(), PluginError> {
        self.inner.shim.sessions().insert(
            session.0,
            (node.to_string(), principal.as_str().to_string()),
        );
        Ok(())
    }

    /// SHIM. A session the directory never held is forgotten rather than refused: close and lease
    /// expiry race, and both of them mean the same thing to the directory.
    fn session_remove(&self, session: SessionId) -> Result<(), PluginError> {
        self.inner.shim.sessions().remove(&session.0);
        Ok(())
    }

    /// SHIM. Which sessions a principal holds — across a fleet of one.
    fn sessions_for(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<(SessionId, String)>, PluginError> {
        let mut held: Vec<(SessionId, String)> = self
            .inner
            .shim
            .sessions()
            .iter()
            .filter(|(_, (_, held_by))| held_by == principal.as_str())
            .map(|(session, (node, _))| (SessionId(*session), node.clone()))
            .collect();
        held.sort_by_key(|(session, _)| session.0);
        Ok(held)
    }

    // ── the record half ───────────────────────────────────────────────────────────────────────

    /// TRANSLATE. The face writes `(schema, key) -> bytes`; the 1.5.5 row is a whole
    /// [`PlaneRecord`] with typed sidecar columns. The schema names the kind, the key names the id,
    /// the value is the opaque body, and the disposition is `Active`: the face's record verbs carry
    /// no terminal marker, and a row marked `Terminal` is a row retention may drop, so guessing
    /// `Terminal` here would hand a plane's live record to the next sweep.
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), PluginError> {
        let id = record_id(key)?;
        self.store()
            .upsert_plane_record(&PlaneRecord {
                kind: schema.as_str().to_string(),
                id: id.to_string(),
                parent: None,
                seq: 0,
                ts: self.now(),
                disposition: PlaneDisposition::Active,
                body: value.as_slice().to_vec(),
            })
            .map_err(|e| legacy_error(&e))
    }

    /// TRANSLATE. `get_plane_record` answers the opaque body, which is what the face's record is.
    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, PluginError> {
        let id = record_id(key)?;
        let body = self
            .store()
            .get_plane_record(schema.as_str(), id)
            .map_err(|e| legacy_error(&e))?;
        match body {
            None => Ok(None),
            Some(bytes) => RecordBytes::new(bytes).map(Some).map_err(|len| {
                PluginError::new(ErrorClass::Internal, TRANSLATION_CODE).with_message(format!(
                    "this stored record is {len} bytes, past the face's record ceiling"
                ))
            }),
        }
    }

    /// TRANSLATE, and the one place the 1.5.5 wire gives back LESS than the face asks for.
    ///
    /// An EMPTY prefix is the whole kind (`PlaneSelector::All`); a non-empty one selects a parent's
    /// chain (`PlaneSelector::Parent`), which is the only narrowing the 1.5.5 verb has and the one
    /// the prefix walk was named for.
    ///
    /// **The keys cannot be recovered.** `list_plane_records` answers the opaque bodies and not the
    /// ids they were stored under, so every pair here carries an EMPTY key. That is said out loud
    /// rather than papered over with a fabricated id: a caller that needs the key half needs a
    /// store that speaks the face natively, and a caller that only reads the bodies — which is
    /// every caller the 1.5.5 verb ever had — is unaffected.
    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, PluginError> {
        let selector = if prefix.is_empty() {
            PlaneSelector::All
        } else {
            PlaneSelector::Parent(record_id(prefix)?.to_string())
        };
        let bodies = self
            .store()
            .list_plane_records(schema.as_str(), &selector)
            .map_err(|e| legacy_error(&e))?;
        bodies
            .into_iter()
            .take(limit as usize)
            .map(|body| {
                RecordBytes::new(body)
                    .map(|record| (Vec::new(), record))
                    .map_err(|len| {
                        PluginError::new(ErrorClass::Internal, TRANSLATION_CODE).with_message(
                            format!(
                                "this stored record is {len} bytes, past the face's record ceiling"
                            ),
                        )
                    })
            })
            .collect()
    }

    /// SHIM. The previous release's own cells, node-locally: the 1.5.5 wire has no key-value cell
    /// of its own, and the ledger's migration reads the previous release's ROWS through
    /// [`StoreAdapter`]'s own legacy readers rather than through this verb.
    fn legacy_cells_read(&self, key: &str) -> Result<Option<Vec<u8>>, PluginError> {
        Ok(self.inner.shim.cells().get(key).cloned())
    }

    /// SHIM. See [`StoreFaceTrait::legacy_cells_read`].
    fn legacy_cells_write(&self, key: &str, value: &[u8]) -> Result<(), PluginError> {
        self.inner
            .shim
            .cells()
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    /// DELEGATE, through [`StoreAdapter::legacy_audit_head`] — the reader the migration already
    /// uses, so the face and the boot path answer from the SAME read of the same rows.
    ///
    /// An empty head is a legitimate answer and not a failure: a store that keeps no audit rows, a
    /// store that predates the tail read and a store with an empty log all read the same way. A
    /// store that FAILED to answer said none of those things, and that reader says so out loud on
    /// its own channel; here it reads empty, because a node whose store is briefly unreachable must
    /// still boot.
    fn legacy_audit_head(&self) -> Result<Option<Head>, PluginError> {
        Ok(self
            .inner
            .adapter
            .legacy_audit_head()
            .head
            .seq
            .map(|seq| Head {
                seq,
                epoch: SHIM_EPOCH,
            }))
    }

    /// SHIM. The 1.5.5 wire has no backup notion at all, so what this node can say is how far its
    /// own shipper acknowledged — the one watermark that exists here.
    fn backup_watermark(&self) -> Result<Option<Head>, PluginError> {
        Ok(self
            .inner
            .adapter
            .head()
            .map(|(seq, epoch)| Head { seq, epoch }))
    }

    /// TRANSLATE, and **the one row that is not verb-for-verb** — a reviewer should check this one.
    ///
    /// The face purges by SEQUENCE; `purge_plane_records_before` purges by TIME. The stream's own
    /// head is the only place in this process where the two axes are known to meet, because the
    /// shim stamped the moment it was reached.
    ///
    /// So: a cutoff at or past the head means "everything written so far", and the moment the head
    /// was reached places that in time. A cutoff BELOW the head names an interior sequence this
    /// node cannot place in time, and the adapter purges NOTHING rather than guess — purging the
    /// wrong rows is data loss that no later read can undo, and `0` is exactly what the 1.5.5
    /// default answered before this face existed.
    fn purge_before(&self, stream: &str, seq: u64) -> Result<u64, PluginError> {
        let mark = self.inner.shim.streams().get(stream).copied();
        let Some(mark) = mark else {
            return Ok(0);
        };
        if seq < mark.head.seq {
            return Ok(0);
        }
        self.store()
            .purge_plane_records_before(stream, mark.head_ts.saturating_add(1))
            .map_err(|e| legacy_error(&e))
    }

    // ── the virtual-key directory ─────────────────────────────────────────────────────────────

    /// DELEGATE to `put_key`. The tombstone precondition is the STORE's, and it is the 1.5.5 verb's
    /// too — stated identically on both faces — so nothing is added here that a backend must not be
    /// allowed to do atomically.
    fn key_put(&self, key: &VirtualKey) -> Result<(), PluginError> {
        self.store().put_key(key).map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `get_key`.
    fn key_get(&self, id: &str) -> Result<Option<VirtualKey>, PluginError> {
        self.store().get_key(id).map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `list_keys`, unfiltered on both faces.
    fn key_list(&self) -> Result<Vec<VirtualKey>, PluginError> {
        self.store().list_keys().map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `delete_key`, which is the 1.5.5 name for the same tombstone.
    fn key_revoke(&self, id: &str) -> Result<(), PluginError> {
        self.store().delete_key(id).map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `scrub_key`. A 1.5.5 store with no scrub support answers its own refusal string,
    /// which arrives here as the unclassified legacy failure the module preamble describes.
    fn key_scrub(&self, id: &str) -> Result<(), PluginError> {
        self.store().scrub_key(id).map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `list_keys_since`, tombstones included on both faces — the hydrator's eviction
    /// contract depends on seeing a newly-set deletion.
    fn keys_since(&self, since: u64) -> Result<Vec<VirtualKey>, PluginError> {
        self.store()
            .list_keys_since(since)
            .map_err(|e| legacy_error(&e))
    }

    // ── the token ledger and the metering book ────────────────────────────────────────────────

    /// DELEGATE to `get_usage`. An untouched pair reads as the empty ledger on both faces.
    fn usage_get(&self, bucket: &str, window_start: u64) -> Result<UsageLedger, PluginError> {
        self.store()
            .get_usage(bucket, window_start)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `put_usage` — the absolute set, unchanged.
    fn usage_put(
        &self,
        bucket: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Result<(), PluginError> {
        self.store()
            .put_usage(bucket, window_start, ledger)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `add_usage`.
    ///
    /// The face's contract is an ATOMIC additive accumulate. A 1.5.5 backend that implements the
    /// verb gives exactly that; one that does not falls to the 1.5.5 default, which is a
    /// read-modify-write on the store's own side. That default is the compatibility behaviour this
    /// deployment already had, and it is NOT re-implemented here: doing the read and the write from
    /// this side would move the race from the backend — where a transactional store closes it — up
    /// into the loader, where nothing can.
    fn usage_add(
        &self,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Result<(), PluginError> {
        self.store()
            .add_usage(bucket, window_start, delta)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `add_metering` — raw consumption, best-effort, never consulted for enforcement.
    fn metering_add(&self, delta: &MeteringDelta) -> Result<(), PluginError> {
        self.store()
            .add_metering(delta)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `list_metering`.
    fn metering_list(&self, bucket: u64) -> Result<Vec<MeteringRow>, PluginError> {
        self.store()
            .list_metering(bucket)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `purge_windows_before` — the token ledger's retention sweep.
    fn usage_purge_before(&self, before: u64) -> Result<u64, PluginError> {
        self.store()
            .purge_windows_before(before)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `purge_metering_before`. Billing evidence, opt-in-purge-only: this verb is
    /// reached from an explicit, audit-logged operator action and never from a sweeper, on both
    /// faces alike.
    fn metering_purge_before(&self, bucket: &str) -> Result<u64, PluginError> {
        self.store()
            .purge_metering_before(bucket)
            .map_err(|e| legacy_error(&e))
    }

    // ── row-looked-up credentials ─────────────────────────────────────────────────────────────

    /// DELEGATE to `put_credential`.
    fn credential_put(&self, secret: &CredentialSecret) -> Result<(), PluginError> {
        self.store()
            .put_credential(secret)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `put_key_with_credential`.
    ///
    /// NOT decomposed into the two verbs here even though the 1.5.5 default decomposes it: a
    /// transactional backend that overrides the default wraps both rows in one transaction, and
    /// calling the two verbs from this side would take that atomicity away from every backend that
    /// has it.
    fn key_put_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Result<(), PluginError> {
        self.store()
            .put_key_with_credential(key, secret)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `list_credentials` — metadata only, never the secret, on both faces.
    fn credential_list(&self, key_id: &str) -> Result<Vec<CredentialMeta>, PluginError> {
        self.store()
            .list_credentials(key_id)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `lookup_credential_secret`. An unknown pair is `None` and never an error on
    /// either face: an unrecognised public id is a normal outcome of the admit path.
    fn credential_lookup(
        &self,
        kind: &str,
        public_id: &str,
    ) -> Result<Option<CredentialSecret>, PluginError> {
        self.store()
            .lookup_credential_secret(kind, public_id)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `revoke_credential`.
    fn credential_revoke(&self, id: &str, reason: &str) -> Result<(), PluginError> {
        self.store()
            .revoke_credential(id, reason)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `list_credentials_since`, secret included — the verify-path cache must never
    /// make a synchronous store call. The consumer's eviction contract travels with the face's own
    /// doc and is unchanged by the translation.
    fn credentials_since(&self, since: u64) -> Result<Vec<CredentialSecret>, PluginError> {
        self.store()
            .list_credentials_since(since)
            .map_err(|e| legacy_error(&e))
    }

    // ── the revocation denylist ───────────────────────────────────────────────────────────────

    /// DELEGATE to `add_denylist`.
    fn denylist_add(&self, subject: &str, reason: &str) -> Result<(), PluginError> {
        self.store()
            .add_denylist(subject, reason)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `list_denylist` — the boot hydrate of the in-memory set.
    fn denylist_list(&self) -> Result<Vec<String>, PluginError> {
        self.store().list_denylist().map_err(|e| legacy_error(&e))
    }

    // ── plane-record residue ──────────────────────────────────────────────────────────────────

    /// DELEGATE to `delete_plane_record`; absent is a no-op on both faces.
    fn record_delete(&self, schema: RecordSchemaId, key: &[u8]) -> Result<(), PluginError> {
        let id = record_id(key)?;
        self.store()
            .delete_plane_record(schema.as_str(), id)
            .map_err(|e| legacy_error(&e))
    }

    /// DELEGATE to `plane_token_live` — the multi-use, time-and-state-bounded liveness check that
    /// spends nothing.
    ///
    /// The 1.5.5 default is `false`, which is the FAIL-CLOSED answer the face's own doc requires: a
    /// store that cannot say whether a capability is live must not be read as saying it is. So a
    /// store with no such row and this face agree exactly, and no default is supplied here.
    fn record_live(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        expires_at: u64,
        now: u64,
    ) -> Result<bool, PluginError> {
        let token = record_id(key)?;
        self.store()
            .plane_token_live(schema.as_str(), token, expires_at, now)
            .map_err(|e| legacy_error(&e))
    }
}

impl std::fmt::Debug for StoreFace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreFace")
            .field("key", &self.inner.key)
            .field("abi", &self.inner.adapter.abi_version())
            .field("adapter", &self.inner.adapter)
            .finish()
    }
}

#[cfg(test)]
#[path = "tests/store_face_tests.rs"]
mod tests;
