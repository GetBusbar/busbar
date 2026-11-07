// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Failure, Mutation, Page,
    PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use super::TicketRefusal;
use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::governance::{GovState, NewKeySpec};

const PREFIX: &str = "tk_";

async fn at_store_second(second: u64) {
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
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
}

async fn gov_with(seed: u8) -> Arc<GovState> {
    let core = crate::real_store::core().await;
    let signer = TokenSigner::from_secret_bytes(&[seed; 32], DEFAULT_KID);
    Arc::new(
        GovState::new_with_core(core, None, Some(signer))
            .await
            .expect("gov"),
    )
}

async fn gov() -> Arc<GovState> {
    gov_with(9).await
}

async fn key(g: &GovState, exp: u64) -> (String, String) {
    let (binding, token) = g
        .mint_signed_async(
            NewKeySpec {
                name: "caller".into(),
                ..Default::default()
            },
            exp,
            crate::store::now(),
        )
        .await
        .expect("mint key");
    (binding.id, token.expose(&crate::seal::lend()).to_string())
}

#[tokio::test]
async fn a_ticket_admits_its_key_once_with_its_record() {
    let now = crate::store::now();
    let g = gov().await;
    let (id, _) = key(&g, now + 86_400).await;
    let (ticket, exp) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{\"locked\":1}", now)
        .await
        .expect("mint");
    assert!(
        ticket.starts_with(PREFIX),
        "the plane's prefix leads: {ticket}"
    );
    assert!(!ticket.contains("bbk_"), "a ticket carries no key prefix");
    assert_eq!(exp, now + 600);
    let (admitted, record) = g
        .admit_ticket_async(PREFIX, &ticket, now + 1)
        .await
        .expect("admit");
    assert_eq!(admitted.id, id);
    assert_eq!(record, b"{\"locked\":1}");

    assert!(
        g.admit_ticket_async(PREFIX, &ticket, now + 2)
            .await
            .is_none(),
        "a spent ticket is refused"
    );
}

#[tokio::test]
async fn a_foreign_or_expired_or_misprefixed_ticket_is_refused() {
    let now = crate::store::now();
    let memory = crate::real_store::core().await;
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let g = Arc::new(
        GovState::new_with_core(memory.clone(), None, Some(signer))
            .await
            .unwrap(),
    );
    let (id, _) = key(&g, now + 86_400).await;

    let other = gov_with(7).await;
    let (other_id, _) = key(&other, now + 86_400).await;
    let (foreign, _) = other
        .mint_ticket(&other_id, PREFIX, 600, None, b"{}", now)
        .await
        .expect("mint");
    assert!(g
        .admit_ticket_async(PREFIX, &foreign, now + 1)
        .await
        .is_none());

    let (expired, exp) = g
        .mint_ticket(&id, PREFIX, 1, None, b"{}", crate::store::now())
        .await
        .expect("mint");
    at_store_second(exp + 1).await;
    assert!(g.admit_ticket_async(PREFIX, &expired, exp).await.is_none());

    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{}", now)
        .await
        .expect("mint");
    assert!(g
        .admit_ticket_async("other_", &ticket, now + 1)
        .await
        .is_none());
    assert!(g.admit_ticket_async("", &ticket, now + 1).await.is_none());

    assert!(g
        .admit_ticket_async(PREFIX, &ticket, now + 1)
        .await
        .is_some());
}

#[tokio::test]
async fn replacing_a_tickets_consumer_prefix_cannot_redelegate_or_spend_it() {
    let now = crate::store::now();
    let g = gov().await;
    let (id, _) = key(&g, now + 86_400).await;
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"original-consumer-record", now)
        .await
        .expect("mint for its declared consumer");
    let body = ticket.strip_prefix(PREFIX).expect("the declared prefix");
    let relabeled = format!("other_{body}");
    assert!(
        g.admit_ticket_async("other_", &relabeled, now + 1)
            .await
            .is_none(),
        "changing an unsigned prefix cannot delegate the credential to another consumer"
    );
    let (admitted, record) = g
        .admit_ticket_async(PREFIX, &ticket, now + 1)
        .await
        .expect("a foreign-consumer attempt cannot spend the original credential");
    assert_eq!(admitted.id, id);
    assert_eq!(record, b"original-consumer-record");
}

#[tokio::test]
async fn a_ticket_is_never_a_key_and_a_key_is_never_a_ticket() {
    let now = crate::store::now();
    let g = gov().await;
    let (id, key_token) = key(&g, now + 86_400).await;
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{}", now)
        .await
        .expect("mint");

    assert!(g.verify_token(&ticket, now + 1, None).is_none());
    let body = ticket.strip_prefix(PREFIX).expect("prefixed");
    assert!(g
        .verify_token(&format!("bbk_{body}"), now + 1, None)
        .is_none());

    let key_body = key_token.strip_prefix("bbk_").expect("a key");
    assert!(g
        .admit_ticket_async(PREFIX, &format!("{PREFIX}{key_body}"), now + 1)
        .await
        .is_none());

    assert!(g.verify_token(&key_token, now + 1, None).is_some());
}

#[tokio::test]
async fn a_ticket_stands_only_while_its_key_does() {
    let now = crate::store::now();
    let g = gov().await;
    let (id, _) = key(&g, now + 86_400).await;
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"{}", now)
        .await
        .expect("mint");
    g.revoke_async(&id, "test").await.expect("revoke");

    assert!(g
        .admit_ticket_async(PREFIX, &ticket, now + 1)
        .await
        .is_none());

    assert_eq!(
        g.mint_ticket(&id, PREFIX, 600, None, b"{}", now).await,
        Err(TicketRefusal::NoStanding)
    );
    assert_eq!(
        g.mint_ticket("vk_unknown", PREFIX, 600, None, b"{}", now)
            .await,
        Err(TicketRefusal::NoStanding)
    );
}

#[tokio::test]
async fn a_tickets_lifetime_is_held_under_the_ceiling_and_its_keys_expiry() {
    let now = crate::store::now();
    let g = gov().await;
    let (id, _) = key(&g, now + 86_400).await;

    let (_, exp) = g
        .mint_ticket(&id, PREFIX, 7_200, Some(120), b"{}", now)
        .await
        .expect("mint");
    assert_eq!(exp, now + 120);

    let mut binding = (*g.lookup_by_sub(&id).expect("bound")).clone();
    binding.expires_at = Some(now + 300);
    g.core_store()
        .unwrap()
        .identity()
        .put_key(&binding)
        .await
        .expect("put");
    g.refresh_async().await.expect("refresh");
    let (_, exp) = g
        .mint_ticket(&id, PREFIX, 7_200, None, b"{}", now)
        .await
        .expect("mint");
    assert_eq!(exp, now + 300);
}

struct TicketBackend {
    inner: Arc<dyn PersistenceBackend>,
    pause: Option<Arc<offload_tests::PausedStore>>,
    fault: Option<&'static str>,
    published: AtomicBool,
}
fn ticket_namespace(schema: &str) -> [u8; 16] {
    crate::persistence::scoped::migration_address(true, super::OWNER, schema, b"")
        .unwrap()
        .namespace
}
impl PersistenceBackend for TicketBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            if request
                .addresses
                .iter()
                .any(|at| at.namespace == ticket_namespace(super::TICKET_RECORD_KIND))
            {
                if let Some(pause) = &self.pause {
                    pause.wait("live").await;
                }
            }
            self.inner.read(request).await
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let writes = |schema: &str| {
                prepared
                    .candidate()
                    .mutations
                    .iter()
                    .any(|mutation| match mutation {
                        Mutation::Put { address, .. } => {
                            address.namespace == ticket_namespace(schema)
                        }
                        _ => false,
                    })
            };
            let spend = writes(super::TICKET_SPENT_KIND);
            let publish = writes(super::TICKET_RECORD_KIND);
            if (self.fault == Some("upsert") && publish) || (self.fault == Some("redeem") && spend)
            {
                return Err(Failure::Refused);
            }
            if spend {
                if let Some(pause) = &self.pause {
                    pause.attempts.lock().unwrap().push(prepared.fingerprint());
                }
            }
            let result = self.inner.commit(prepared).await;
            if publish && matches!(&result, Ok(Decision::Applied(_))) {
                self.published.store(true, Ordering::SeqCst);
            }
            if spend && matches!(&result, Ok(Decision::Applied(_))) {
                if let Some(pause) = &self.pause {
                    pause.wait("get").await;
                }
            }
            result
        })
    }
}
async fn ticket_records(core: &Arc<crate::persistence::facade::CoreStore>) -> usize {
    let rows = super::scope(core.clone()).unwrap();
    let mut after = None;
    let mut count = 0;
    loop {
        let page = rows
            .page(super::TICKET_RECORD_KIND, b"", after.as_ref())
            .await
            .unwrap();
        count += page.rows.len();
        if page.next.is_none() {
            return count;
        }
        after = page.next;
    }
}

#[tokio::test]
async fn a_lapsed_tickets_record_goes_through_the_rule_carrying_purge_on_the_next_mint() {
    let now = crate::store::now();
    let memory = crate::real_store::core().await;
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let g = GovState::new_with_core(memory.clone(), None, Some(signer))
        .await
        .expect("gov");
    let (id, _) = key(&g, now + 86_400).await;

    g.mint_ticket(&id, PREFIX, 10, None, b"{}", now)
        .await
        .expect("mint");
    g.mint_ticket(&id, PREFIX, 20, None, b"{}", now)
        .await
        .expect("mint");
    assert_eq!(ticket_records(&memory).await, 2);

    at_store_second(now + 20).await;
    g.mint_ticket(&id, PREFIX, 600, None, b"{}", now + 20)
        .await
        .expect("mint");
    assert_eq!(
        ticket_records(&memory).await,
        2,
        "the record of the ticket lapsed before the mint goes; the one lapsing at it stays"
    );

    assert_eq!(
        crate::store::now(),
        now + 20,
        "the purge checked the exact deadline second"
    );
    at_store_second(now + 21).await;
    g.mint_ticket(&id, PREFIX, 600, None, b"{}", now + 21)
        .await
        .expect("mint");
    assert_eq!(
        ticket_records(&memory).await,
        2,
        "only the two live tickets' records stay"
    );
    assert_eq!(
        crate::store::now(),
        now + 21,
        "the purge checked the second after the deadline"
    );
}

#[tokio::test]
async fn ticket_deadline_and_record_follow_store_clock_despite_node_skew() {
    const TICKET_TTL_SECS: u64 = 600;
    const NODE_SKEW_SECS: u64 = TICKET_TTL_SECS * 2;
    const KEY_TTL_SECS: u64 = 86_400;
    let store_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let memory = crate::real_store::core().await;
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let g = Arc::new(
        GovState::new_with_core(memory, None, Some(signer))
            .await
            .unwrap(),
    );
    let (id, _) = key(&g, store_now + KEY_TTL_SECS).await;
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, TICKET_TTL_SECS, None, b"original", store_now)
        .await
        .unwrap();
    let fast_node = store_now + NODE_SKEW_SECS;
    assert!(
        g.peek_ticket_async(PREFIX, &ticket, fast_node)
            .await
            .is_some(),
        "fast node must not refuse a store-valid ticket"
    );
    g.mint_ticket(&id, PREFIX, TICKET_TTL_SECS, None, b"later", fast_node)
        .await
        .unwrap();
    assert!(
        g.peek_ticket_async(PREFIX, &ticket, fast_node)
            .await
            .is_some(),
        "fast mint must not purge its live record"
    );
    assert_eq!(
        g.admit_ticket_async(PREFIX, &ticket, fast_node)
            .await
            .unwrap()
            .1,
        b"original"
    );
    assert!(
        g.admit_ticket_async(PREFIX, &ticket, store_now)
            .await
            .is_none(),
        "preflight never spent, admission spends once"
    );
    let slow_node = store_now - NODE_SKEW_SECS;
    assert_eq!(
        g.mint_ticket(&id, PREFIX, TICKET_TTL_SECS, None, b"expired", slow_node)
            .await,
        Err(TicketRefusal::NotKept),
        "store time refuses publication of an already expired authorization"
    );
    let (expired, exp) = g
        .mint_ticket(&id, PREFIX, 1, None, b"expired", crate::store::now())
        .await
        .unwrap();
    at_store_second(exp + 1).await;
    assert!(g
        .peek_ticket_async(PREFIX, &expired, slow_node)
        .await
        .is_none());
    assert!(
        g.admit_ticket_async(PREFIX, &expired, slow_node)
            .await
            .is_none(),
        "slow caller cannot reopen expired authority"
    );
}

#[tokio::test]
async fn ticket_preflight_and_first_admission_include_the_store_deadline_second() {
    let now = crate::store::now();
    const TICKET_TTL_SECS: u64 = 10;
    let store = crate::real_store::core().await;
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let g = Arc::new(
        GovState::new_with_core(store.clone(), None, Some(signer))
            .await
            .unwrap(),
    );
    let (id, key_token) = key(&g, now + 86_400).await;
    let (ticket, exp) = g
        .mint_ticket(&id, PREFIX, TICKET_TTL_SECS, None, b"record", now)
        .await
        .unwrap();
    at_store_second(exp).await;
    assert!(g
        .peek_ticket_async(PREFIX, &ticket, exp + 1)
        .await
        .is_some());
    assert!(g
        .peek_ticket_async(PREFIX, &ticket, exp - 1)
        .await
        .is_some());
    assert!(g
        .admit_ticket_async(PREFIX, &ticket, exp + 1)
        .await
        .is_some());
    assert!(g
        .admit_ticket_async(PREFIX, &ticket, exp - 1)
        .await
        .is_none());
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

#[tokio::test]
async fn host_binding_precedes_publication_and_failed_binding_removes_the_record() {
    let now = crate::store::now();
    let backend = Arc::new(TicketBackend {
        inner: crate::real_store::native_backend().await,
        pause: None,
        fault: None,
        published: AtomicBool::new(false),
    });
    let g = Arc::new(
        GovState::new_with_core(
            crate::real_store::core_over(backend.clone()).await,
            None,
            Some(TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID)),
        )
        .await
        .unwrap(),
    );
    let (id, _) = key(&g, now + 86_400).await;
    let mut bound_id = String::new();
    let result = g
        .mint_ticket_bound(&id, PREFIX, 600, None, b"opaque", now, |identity| {
            assert_eq!(identity.principal().id, id);
            assert_eq!(identity.expires_at(), now + 600);
            assert!(
                backend.published.load(Ordering::SeqCst),
                "native Applied record publication precedes host binding"
            );
            assert!(Arc::ptr_eq(
                identity.store(),
                &g.core_store_handle().unwrap()
            ));
            bound_id = identity.id().to_owned();
            Err(TicketRefusal::NotKept)
        })
        .await;
    assert_eq!(result, Err(TicketRefusal::NotKept));
    assert!(!bound_id.is_empty());
    assert!(super::scope(g.core_store_handle().unwrap())
        .unwrap()
        .get(super::TICKET_RECORD_KIND, bound_id.as_bytes())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn store_failure_never_calls_host_binding_and_failed_spend_returns_no_record() {
    let now = crate::store::now();
    for fault in ["upsert", "redeem"] {
        let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
        let g = Arc::new(
            GovState::new_with_core(
                crate::real_store::core_over(Arc::new(TicketBackend {
                    inner: crate::real_store::native_backend().await,
                    pause: None,
                    fault: Some(fault),
                    published: AtomicBool::new(false),
                }))
                .await,
                None,
                Some(signer),
            )
            .await
            .unwrap(),
        );
        let (id, _) = key(&g, now + 86_400).await;
        let mut bound = false;
        let minted = g
            .mint_ticket_bound(&id, PREFIX, 600, None, b"opaque", now, |_| {
                bound = true;
                Ok(())
            })
            .await;
        if fault == "upsert" {
            assert_eq!(minted, Err(TicketRefusal::NotKept));
            assert!(!bound);
        } else {
            let (ticket, _) = minted.unwrap();
            assert!(bound);
            let identity = g
                .prepare_ticket_redemption_async(PREFIX, &ticket, now)
                .await
                .unwrap();
            assert!(g
                .redeem_verified_ticket_async(identity, now)
                .await
                .is_none());
        }
    }
}

#[tokio::test]
async fn prepared_identity_is_store_bound_revalidated_and_spent_once() {
    let now = crate::store::now();
    let g = gov().await;
    let (id, _) = key(&g, now + 86_400).await;
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"opaque", now)
        .await
        .unwrap();
    let identity = g
        .prepare_ticket_redemption_async(PREFIX, &ticket, now)
        .await
        .unwrap();
    let other = gov().await;
    assert!(other
        .redeem_verified_ticket_async(identity, now)
        .await
        .is_none());
    let identity = g
        .prepare_ticket_redemption_async(PREFIX, &ticket, now)
        .await
        .unwrap();
    let simultaneous = g
        .prepare_ticket_redemption_async(PREFIX, &ticket, now)
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        g.redeem_verified_ticket_async(identity, now),
        g.redeem_verified_ticket_async(simultaneous, now),
    );
    let winners: Vec<_> = [left, right].into_iter().flatten().collect();
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].1, b"opaque");

    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"rotated", now)
        .await
        .unwrap();
    let identity = g
        .prepare_ticket_redemption_async(PREFIX, &ticket, now)
        .await
        .unwrap();
    g.rotate_key_outcome_async(&id, now + 86_400)
        .await
        .unwrap()
        .unwrap();
    assert!(g
        .redeem_verified_ticket_async(identity, now)
        .await
        .is_none());
    assert!(g
        .prepare_ticket_redemption_async(PREFIX, &ticket, now)
        .await
        .is_none());
}

#[tokio::test]
async fn prepared_identity_rejects_expired_or_tampered_credentials_and_redacts_debug() {
    let now = crate::store::now();
    let g = gov().await;
    let (id, _) = key(&g, now + 86_400).await;
    let (expired, exp) = g
        .mint_ticket(&id, PREFIX, 1, None, b"expired", crate::store::now())
        .await
        .unwrap();
    at_store_second(exp + 1).await;
    assert!(g
        .prepare_ticket_redemption_async(PREFIX, &expired, now)
        .await
        .is_none());
    let (ticket, _) = g
        .mint_ticket(&id, PREFIX, 600, None, b"opaque", now)
        .await
        .unwrap();
    let identity = g
        .prepare_ticket_redemption_async(PREFIX, &ticket, now)
        .await
        .unwrap();
    let debug = format!("{identity:?}");
    assert!(!debug.contains(&ticket));
    assert!(!debug.contains(identity.id()));
    assert!(!debug.contains(&identity.principal().generation_hash));
    let mut tampered = ticket;
    tampered.push('x');
    assert!(g
        .prepare_ticket_redemption_async(PREFIX, &tampered, now)
        .await
        .is_none());
}
