// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tickets at the `GovState` seam (row 132): minted for a standing key, admitted once, and never a
//! key. Driven over the memory store, whose single-use redemption is a real test-and-set.

use std::sync::Arc;

use super::TicketRefusal;
use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::governance::{GovState, MemoryStore, NewKeySpec};

const PREFIX: &str = "tk_";
const NOW: u64 = 1_000;

fn gov_with(seed: u8) -> Arc<GovState> {
    let store = Arc::new(MemoryStore::new());
    let signer = TokenSigner::from_secret_bytes(&[seed; 32], DEFAULT_KID);
    Arc::new(GovState::new_with_signer(store, None, Some(signer)).expect("gov"))
}

fn gov() -> Arc<GovState> {
    gov_with(9)
}

/// A standing key of `g`, living until `exp`: its id and its token.
fn key(g: &GovState, exp: u64) -> (String, String) {
    let (binding, token) = g
        .mint_signed(
            NewKeySpec {
                name: "caller".into(),
                ..Default::default()
            },
            exp,
            NOW,
        )
        .expect("mint key");
    (binding.id, token.expose(&crate::seal::lend()).to_string())
}

#[test]
fn a_ticket_admits_its_key_once_with_its_record() {
    let g = gov();
    let (id, _) = key(&g, NOW + 86_400);
    let (ticket, exp) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{\"locked\":1}", NOW)
        .expect("mint");
    assert!(
        ticket.starts_with(PREFIX),
        "the plane's prefix leads: {ticket}"
    );
    assert!(!ticket.contains("bbk_"), "a ticket carries no key prefix");
    assert_eq!(exp, NOW + 600);
    let (admitted, record) = g.admit_ticket(PREFIX, &ticket, NOW + 1).expect("admit");
    assert_eq!(admitted.id, id);
    assert_eq!(record, b"{\"locked\":1}");
    // RED: a ticket admits once.
    assert!(
        g.admit_ticket(PREFIX, &ticket, NOW + 2).is_none(),
        "a spent ticket is refused"
    );
}

#[test]
fn a_foreign_or_expired_or_misprefixed_ticket_is_refused() {
    let g = gov();
    let (id, _) = key(&g, NOW + 86_400);
    // RED: minted by another deployment's signer.
    let other = gov_with(7);
    let (other_id, _) = key(&other, NOW + 86_400);
    let (foreign, _) = other
        .mint_ticket(&other_id, PREFIX, 600, None, b"{}", NOW)
        .expect("mint");
    assert!(g.admit_ticket(PREFIX, &foreign, NOW + 1).is_none());
    // RED: past its expiry.
    let (expired, exp) = g
        .mint_ticket(&id, PREFIX, 10, None, b"{}", NOW)
        .expect("mint");
    assert!(g.admit_ticket(PREFIX, &expired, exp).is_none());
    // RED: presented on a route whose plane declares another prefix, or none.
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{}", NOW)
        .expect("mint");
    assert!(g.admit_ticket("other_", &ticket, NOW + 1).is_none());
    assert!(g.admit_ticket("", &ticket, NOW + 1).is_none());
    // A misprefixed presentation spent nothing: the ticket still admits on its own route.
    assert!(g.admit_ticket(PREFIX, &ticket, NOW + 1).is_some());
}

#[test]
fn a_ticket_is_never_a_key_and_a_key_is_never_a_ticket() {
    let g = gov();
    let (id, key_token) = key(&g, NOW + 86_400);
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{}", NOW)
        .expect("mint");
    // RED: the ticket, and its body under the key prefix, on the plain data plane.
    assert!(g.verify_token(&ticket, NOW + 1, None).is_none());
    let body = ticket.strip_prefix(PREFIX).expect("prefixed");
    assert!(g
        .verify_token(&format!("bbk_{body}"), NOW + 1, None)
        .is_none());
    // RED: a key, given the ticket prefix, on a route that takes tickets.
    let key_body = key_token.strip_prefix("bbk_").expect("a key");
    assert!(g
        .admit_ticket(PREFIX, &format!("{PREFIX}{key_body}"), NOW + 1)
        .is_none());
    // The key itself still verifies.
    assert!(g.verify_token(&key_token, NOW + 1, None).is_some());
}

#[test]
fn a_ticket_stands_only_while_its_key_does() {
    let g = gov();
    let (id, _) = key(&g, NOW + 86_400);
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{}", NOW)
        .expect("mint");
    g.revoke(&id, "test").expect("revoke");
    // RED: the key was revoked after the mint.
    assert!(g.admit_ticket(PREFIX, &ticket, NOW + 1).is_none());
    // RED: no ticket for a revoked key, nor an unknown one.
    assert_eq!(
        g.mint_ticket(&id, PREFIX, 600, None, b"{}", NOW),
        Err(TicketRefusal::NoStanding)
    );
    assert_eq!(
        g.mint_ticket("vk_unknown", PREFIX, 600, None, b"{}", NOW),
        Err(TicketRefusal::NoStanding)
    );
}

#[test]
fn a_tickets_lifetime_is_held_under_the_ceiling_and_its_keys_expiry() {
    let g = gov();
    let (id, _) = key(&g, NOW + 86_400);
    // The mint ceiling clamps the lifetime asked.
    let (_, exp) = g
        .mint_ticket(&id, PREFIX, 7_200, Some(120), b"{}", NOW)
        .expect("mint");
    assert_eq!(exp, NOW + 120);
    // The key's own expiry caps it.
    let mut binding = (*g.lookup_by_sub(&id).expect("bound")).clone();
    binding.expires_at = Some(NOW + 300);
    g.store().put_key(&binding).expect("put");
    g.refresh().expect("refresh");
    let (_, exp) = g
        .mint_ticket(&id, PREFIX, 7_200, None, b"{}", NOW)
        .expect("mint");
    assert_eq!(exp, NOW + 300);
}

/// A store serving the RULE-CARRYING purge only: every verb is the memory store's, except the
/// age-only `purge_plane_records_before`, left at the contract's default (it purges nothing). The
/// rule-carrying `purge_plane_records` is the purge the store ABI carries (slot 22 passes the rule
/// with every purge), so a store is complete without the age-only verb.
struct RuleCarryingOnly(Arc<MemoryStore>);

mod rule_carrying_only {
    use super::RuleCarryingOnly;
    use busbar_contract::records::{
        AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
        PlaneSelector, RecordStore, RecordStoreResult, Retention, UsageDelta, UsageLedger,
        VirtualKey,
    };

    impl RecordStore for RuleCarryingOnly {
        fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
            self.0.put_key(key)
        }
        fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
            self.0.get_key(id)
        }
        fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
            self.0.list_keys()
        }
        fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
            self.0.delete_key(id)
        }
        fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
            self.0.list_keys_since(since)
        }
        fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
            self.0.get_usage(bucket_id, window_start)
        }
        fn put_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
            ledger: &UsageLedger,
        ) -> RecordStoreResult<()> {
            self.0.put_usage(bucket_id, window_start, ledger)
        }
        fn add_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
            delta: &UsageDelta,
        ) -> RecordStoreResult<()> {
            self.0.add_usage(bucket_id, window_start, delta)
        }
        fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
            self.0.add_metering(delta)
        }
        fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
            self.0.list_metering(bucket)
        }
        fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
            self.0.put_credential(secret)
        }
        fn put_key_with_credential(
            &self,
            key: &VirtualKey,
            secret: &CredentialSecret,
        ) -> RecordStoreResult<()> {
            self.0.put_key_with_credential(key, secret)
        }
        fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
            self.0.list_credentials(key_id)
        }
        fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
            self.0.revoke_credential(id, reason)
        }
        fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
            self.0.list_credentials_since(since)
        }
        fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
            self.0.append_audit(entry)
        }
        fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
            self.0.list_audit()
        }
        fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
            self.0.add_denylist(sub, reason)
        }
        fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
            self.0.list_denylist()
        }
        fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
            self.0.list_audit_tail(limit)
        }
        fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
            self.0.upsert_plane_record(record)
        }
        fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
            self.0.get_plane_record(kind, id)
        }
        fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
            self.0.append_plane_record(record)
        }
        fn list_plane_records(
            &self,
            kind: &str,
            selector: &PlaneSelector<'_>,
        ) -> RecordStoreResult<Vec<Vec<u8>>> {
            self.0.list_plane_records(kind, selector)
        }
        fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
            self.0.list_plane_record_parents(kind)
        }
        fn purge_plane_records(
            &self,
            kind: &str,
            before: u64,
            retention: Retention,
        ) -> RecordStoreResult<u64> {
            self.0.purge_plane_records(kind, before, retention)
        }
        fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
            self.0.delete_plane_record(kind, id)
        }
        fn redeem_plane_token(
            &self,
            kind: &str,
            token: &str,
            expires_at: u64,
            now: u64,
        ) -> RecordStoreResult<bool> {
            self.0.redeem_plane_token(kind, token, expires_at, now)
        }
        fn plane_token_live(
            &self,
            kind: &str,
            token: &str,
            expires_at: u64,
            now: u64,
        ) -> RecordStoreResult<bool> {
            self.0.plane_token_live(kind, token, expires_at, now)
        }
    }
}

/// How many ticket records `store` holds.
fn ticket_records(store: &MemoryStore) -> usize {
    use busbar_contract::records::{PlaneSelector, RecordStore};
    store
        .list_plane_records(super::TICKET_RECORD_KIND, &PlaneSelector::All)
        .expect("list")
        .len()
}

/// **A LAPSED TICKET'S RECORD GOES AT THE NEXT MINT, THROUGH THE RULE-CARRYING PURGE, BY AGE.** The
/// kernel's ticket kind is purged under `Retention::Age` on the purge that carries the rule, so a
/// store that serves only that purge (the one the store ABI carries) drops a lapsed ticket's record
/// as every other store does. The timing is the one tickets always had: a record whose ticket
/// lapsed before the mint's instant goes; one lapsing at that instant or later stays.
///
/// RED while ticket expiry called the age-only `purge_plane_records_before`: on a store serving
/// only the rule-carrying purge, every lapsed ticket's record was kept, without bound.
#[test]
fn a_lapsed_tickets_record_goes_through_the_rule_carrying_purge_on_the_next_mint() {
    let memory = Arc::new(MemoryStore::new());
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let g = GovState::new_with_signer(
        Arc::new(RuleCarryingOnly(Arc::clone(&memory))),
        None,
        Some(signer),
    )
    .expect("gov");
    let (id, _) = key(&g, NOW + 86_400);
    // They lapse at NOW + 10 and at NOW + 20.
    g.mint_ticket(&id, PREFIX, 10, None, b"{}", NOW)
        .expect("mint");
    g.mint_ticket(&id, PREFIX, 20, None, b"{}", NOW)
        .expect("mint");
    assert_eq!(ticket_records(&memory), 2);
    // At NOW + 20 the first has lapsed and goes; the second lapses at this very instant and stays.
    g.mint_ticket(&id, PREFIX, 600, None, b"{}", NOW + 20)
        .expect("mint");
    assert_eq!(
        ticket_records(&memory),
        2,
        "the record of the ticket lapsed before the mint goes; the one lapsing at it stays"
    );
    // At NOW + 21 the second has lapsed too.
    g.mint_ticket(&id, PREFIX, 600, None, b"{}", NOW + 21)
        .expect("mint");
    assert_eq!(
        ticket_records(&memory),
        2,
        "only the two live tickets' records stay"
    );
}
