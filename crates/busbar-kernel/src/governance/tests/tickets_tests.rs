// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use super::TicketRefusal;
use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::governance::{GovState, NewKeySpec};

const PREFIX: &str = "tk_";

fn at_store_second(second: u64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(35);
    loop {
        let now = crate::store::now();
        if now >= second {
            assert_eq!(now, second, "the backend clock is at the required second");
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the backend deadline arrives within the bounded wait"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn gov_with(seed: u8) -> Arc<GovState> {
    let store = crate::real_store::store();
    let signer = TokenSigner::from_secret_bytes(&[seed; 32], DEFAULT_KID);
    Arc::new(GovState::new_with_signer(store, None, Some(signer)).expect("gov"))
}

fn gov() -> Arc<GovState> {
    gov_with(9)
}

fn key(g: &GovState, exp: u64) -> (String, String) {
    let (binding, token) = g
        .mint_signed(
            NewKeySpec {
                name: "caller".into(),
                ..Default::default()
            },
            exp,
            crate::store::now(),
        )
        .expect("mint key");
    (binding.id, token.expose(&crate::seal::lend()).to_string())
}

#[test]
fn a_ticket_admits_its_key_once_with_its_record() {
    let now = crate::store::now();
    let g = gov();
    let (id, _) = key(&g, now + 86_400);
    let (ticket, exp) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{\"locked\":1}", now)
        .expect("mint");
    assert!(
        ticket.starts_with(PREFIX),
        "the plane's prefix leads: {ticket}"
    );
    assert!(!ticket.contains("bbk_"), "a ticket carries no key prefix");
    assert_eq!(exp, now + 600);
    let (admitted, record) = g.admit_ticket(PREFIX, &ticket, now + 1).expect("admit");
    assert_eq!(admitted.id, id);
    assert_eq!(record, b"{\"locked\":1}");

    assert!(
        g.admit_ticket(PREFIX, &ticket, now + 2).is_none(),
        "a spent ticket is refused"
    );
}

#[test]
fn a_foreign_or_expired_or_misprefixed_ticket_is_refused() {
    let now = crate::store::now();
    let memory = crate::real_store::store();
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let g = GovState::new_with_signer(memory.clone(), None, Some(signer)).unwrap();
    let (id, _) = key(&g, now + 86_400);

    let other = gov_with(7);
    let (other_id, _) = key(&other, now + 86_400);
    let (foreign, _) = other
        .mint_ticket(&other_id, PREFIX, 600, None, b"{}", now)
        .expect("mint");
    assert!(g.admit_ticket(PREFIX, &foreign, now + 1).is_none());

    let (expired, exp) = g
        .mint_ticket(&id, PREFIX, 10, None, b"{}", now - 11)
        .expect("mint");
    assert!(g.admit_ticket(PREFIX, &expired, exp).is_none());

    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{}", now)
        .expect("mint");
    assert!(g.admit_ticket("other_", &ticket, now + 1).is_none());
    assert!(g.admit_ticket("", &ticket, now + 1).is_none());

    assert!(g.admit_ticket(PREFIX, &ticket, now + 1).is_some());
}

#[test]
fn a_ticket_is_never_a_key_and_a_key_is_never_a_ticket() {
    let now = crate::store::now();
    let g = gov();
    let (id, key_token) = key(&g, now + 86_400);
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{}", now)
        .expect("mint");

    assert!(g.verify_token(&ticket, now + 1, None).is_none());
    let body = ticket.strip_prefix(PREFIX).expect("prefixed");
    assert!(g
        .verify_token(&format!("bbk_{body}"), now + 1, None)
        .is_none());

    let key_body = key_token.strip_prefix("bbk_").expect("a key");
    assert!(g
        .admit_ticket(PREFIX, &format!("{PREFIX}{key_body}"), now + 1)
        .is_none());

    assert!(g.verify_token(&key_token, now + 1, None).is_some());
}

#[test]
fn a_ticket_stands_only_while_its_key_does() {
    let now = crate::store::now();
    let g = gov();
    let (id, _) = key(&g, now + 86_400);
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{}", now)
        .expect("mint");
    g.revoke(&id, "test").expect("revoke");

    assert!(g.admit_ticket(PREFIX, &ticket, now + 1).is_none());

    assert_eq!(
        g.mint_ticket(&id, PREFIX, 600, None, b"{}", now),
        Err(TicketRefusal::NoStanding)
    );
    assert_eq!(
        g.mint_ticket("vk_unknown", PREFIX, 600, None, b"{}", now),
        Err(TicketRefusal::NoStanding)
    );
}

#[test]
fn a_tickets_lifetime_is_held_under_the_ceiling_and_its_keys_expiry() {
    let now = crate::store::now();
    let g = gov();
    let (id, _) = key(&g, now + 86_400);

    let (_, exp) = g
        .mint_ticket(&id, PREFIX, 7_200, Some(120), b"{}", now)
        .expect("mint");
    assert_eq!(exp, now + 120);

    let mut binding = (*g.lookup_by_sub(&id).expect("bound")).clone();
    binding.expires_at = Some(now + 300);
    g.store().put_key(&binding).expect("put");
    g.refresh().expect("refresh");
    let (_, exp) = g
        .mint_ticket(&id, PREFIX, 7_200, None, b"{}", now)
        .expect("mint");
    assert_eq!(exp, now + 300);
}

struct RuleCarryingOnly(
    Arc<busbar_plugin_loader::store_v3::LoadedStore>,
    Option<Arc<offload_tests::PausedStore>>,
);

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
            if let Some(pause) = &self.1 {
                pause.wait("get");
            }
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
            if let Some(pause) = &self.1 {
                pause.wait("live");
            }
            self.0.plane_token_live(kind, token, expires_at, now)
        }
    }
}

fn ticket_records(store: &busbar_plugin_loader::store_v3::LoadedStore) -> usize {
    use busbar_contract::records::{PlaneSelector, RecordStore};
    store
        .list_plane_records(super::TICKET_RECORD_KIND, &PlaneSelector::All)
        .expect("list")
        .len()
}

#[test]
fn a_lapsed_tickets_record_goes_through_the_rule_carrying_purge_on_the_next_mint() {
    let now = crate::store::now();
    let memory = crate::real_store::store();
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let g = GovState::new_with_signer(
        Arc::new(RuleCarryingOnly(Arc::clone(&memory), None)),
        None,
        Some(signer),
    )
    .expect("gov");
    let (id, _) = key(&g, now + 86_400);

    g.mint_ticket(&id, PREFIX, 10, None, b"{}", now)
        .expect("mint");
    g.mint_ticket(&id, PREFIX, 20, None, b"{}", now)
        .expect("mint");
    assert_eq!(ticket_records(&memory), 2);

    at_store_second(now + 20);
    g.mint_ticket(&id, PREFIX, 600, None, b"{}", now + 20)
        .expect("mint");
    assert_eq!(
        ticket_records(&memory),
        2,
        "the record of the ticket lapsed before the mint goes; the one lapsing at it stays"
    );

    assert_eq!(
        crate::store::now(),
        now + 20,
        "the purge checked the exact deadline second"
    );
    at_store_second(now + 21);
    g.mint_ticket(&id, PREFIX, 600, None, b"{}", now + 21)
        .expect("mint");
    assert_eq!(
        ticket_records(&memory),
        2,
        "only the two live tickets' records stay"
    );
    assert_eq!(
        crate::store::now(),
        now + 21,
        "the purge checked the second after the deadline"
    );
}

#[test]
fn ticket_deadline_and_record_follow_store_clock_despite_node_skew() {
    const TICKET_TTL_SECS: u64 = 600;
    const NODE_SKEW_SECS: u64 = TICKET_TTL_SECS * 2;
    const KEY_TTL_SECS: u64 = 86_400;
    let store_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let memory = crate::real_store::store();
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let g = GovState::new_with_signer(memory, None, Some(signer)).unwrap();
    let (id, _) = key(&g, store_now + KEY_TTL_SECS);
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, TICKET_TTL_SECS, None, b"original", store_now)
        .unwrap();
    let fast_node = store_now + NODE_SKEW_SECS;
    assert!(
        g.peek_ticket(PREFIX, &ticket, fast_node).is_some(),
        "fast node must not refuse a store-valid ticket"
    );
    g.mint_ticket(&id, PREFIX, TICKET_TTL_SECS, None, b"later", fast_node)
        .unwrap();
    assert!(
        g.peek_ticket(PREFIX, &ticket, fast_node).is_some(),
        "fast mint must not purge its live record"
    );
    assert_eq!(
        g.admit_ticket(PREFIX, &ticket, fast_node).unwrap().1,
        b"original"
    );
    assert!(
        g.admit_ticket(PREFIX, &ticket, store_now).is_none(),
        "preflight never spent, admission spends once"
    );
    let slow_node = store_now - NODE_SKEW_SECS;
    let (expired, _) = g
        .mint_ticket(&id, PREFIX, TICKET_TTL_SECS, None, b"expired", slow_node)
        .unwrap();
    assert!(g.peek_ticket(PREFIX, &expired, slow_node).is_none());
    assert!(
        g.admit_ticket(PREFIX, &expired, slow_node).is_none(),
        "slow caller cannot reopen expired authority"
    );
}

#[test]
fn ticket_preflight_and_first_admission_include_the_store_deadline_second() {
    let now = crate::store::now();
    const TICKET_TTL_SECS: u64 = 10;
    let store = crate::real_store::store();
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let g = GovState::new_with_signer(store.clone(), None, Some(signer)).unwrap();
    let (id, key_token) = key(&g, now + 86_400);
    let (ticket, exp) = g
        .mint_ticket(&id, PREFIX, TICKET_TTL_SECS, None, b"record", now)
        .unwrap();
    at_store_second(exp);
    assert!(g.peek_ticket(PREFIX, &ticket, exp + 1).is_some());
    assert!(g.peek_ticket(PREFIX, &ticket, exp - 1).is_some());
    assert!(g.admit_ticket(PREFIX, &ticket, exp + 1).is_some());
    assert!(g.admit_ticket(PREFIX, &ticket, exp - 1).is_none());
    assert_eq!(
        crate::store::now(),
        exp,
        "the deadline checks finished within the store second"
    );
    assert!(
        g.verify_token(&key_token, now + 86_400, None).is_none(),
        "ordinary bearer expiry is unchanged"
    );
}

#[path = "ticket_offload_tests.rs"]
mod offload_tests;
