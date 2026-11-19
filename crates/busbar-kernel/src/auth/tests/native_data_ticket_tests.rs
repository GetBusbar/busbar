// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A ticket route at its own preparation, end to end: the real sealed store over the real core
//! store, the issuer binding, the route's desk and the route's `prepare` and `complete`. What a
//! ticket admits, where, how often, for how long and as whom; and who may have one minted.

use super::*;
use crate::auth::admission_table::Refusal;
use crate::auth::native_ticket::{IssuerBound, Issuers, Redeem, TicketDesk, TICKET_DOOR};
use crate::auth::route_record::{Money, RouteClass, RouteRecord, Scope, Who};
use crate::host_services::Standing;
use crate::plane_grants::{SealedTickets, TicketMint, Tickets};
use crate::plugin_records::StoreRecords;
use busbar_contract::records::VirtualKey;
use std::collections::HashMap;
use std::sync::Mutex;

const PLANE: &str = "plane-streaming";
const NAME: &str = "realtime";
const INSTANCE: u64 = 7;

fn now() -> u64 {
    crate::store::now()
}

/// A store whose clock stands eleven minutes back: whatever it mints has expired by now, since no
/// ticket lives longer than ten.
fn eleven_minutes_ago() -> u64 {
    crate::store::now() - 660
}

fn plane(name: &str) -> Namespace {
    Namespace {
        plugin: Arc::from(PLANE),
        name: Arc::from(name),
        instance: INSTANCE,
        slot: 0,
    }
}

fn issuer(id: &str) -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: id.into(),
        generation_hash: "g1".into(),
        name: id.into(),
        enabled: true,
        ..Default::default()
    })
}

/// The governance book of the test: a key stands as it was admitted unless the test wrote what it
/// is now.
#[derive(Default)]
struct Book(Mutex<HashMap<String, Arc<VirtualKey>>>);

impl Book {
    fn put(&self, key: VirtualKey) {
        self.0
            .lock()
            .unwrap()
            .insert(key.id.clone(), Arc::new(key));
    }
    fn standing(self: &Arc<Self>) -> Standing {
        let book = Arc::clone(self);
        Arc::new(move |admitted: &Arc<VirtualKey>, _now: u64| {
            Some(
                book.0
                    .lock()
                    .unwrap()
                    .get(&admitted.id)
                    .cloned()
                    .unwrap_or_else(|| Arc::clone(admitted)),
            )
        })
    }
}

struct Rig {
    f: Fixture,
    bound: Arc<IssuerBound<SealedTickets<StoreRecords>>>,
    issuers: Arc<Issuers>,
    book: Arc<Book>,
}

/// The data fixture's route, restated as a ticket route (`who`) that opens a unit, with `desk`.
fn ticket_fixture(who: Who, desk: Option<Arc<TicketDesk>>, open: bool) -> Fixture {
    let mut f = fixture_of(true, false, Vec::new(), open);
    let record = RouteRecord::stated(RouteClass::Data, who, Scope::none(), Money::Unit);
    let old = Arc::clone(&f.route);
    f.route = Arc::new(NativeDataRoute {
        binding: Arc::clone(&old.binding),
        caller: old.caller.clone(),
        owners: DataRouteOwners {
            generation: Arc::clone(&old.owners.generation),
            inventory: None,
            chain: Arc::clone(&old.owners.chain),
            keys: Arc::clone(&old.owners.keys),
            routes: Arc::clone(&old.owners.routes),
        },
        cost: Arc::clone(&old.cost),
        withheld: Arc::clone(&old.withheld),
        audience: None,
        challenge: None,
        admission: crate::auth::admission_table::admission_of(&record),
        record,
        ticket: desk,
    });
    f
}

/// A ticket route of plane instance `door_name`, admitting `who`, over a store whose clock is
/// `clock`. Tickets are minted by the instance [`NAME`].
async fn rig_of(clock: fn() -> u64, door_name: &str, who: Who, open: bool) -> Rig {
    let core = crate::real_store::core().await;
    let sealed = SealedTickets::new(StoreRecords::with_clock(core, clock), &[7u8; 32], clock)
        .expect("a 32-byte key");
    let issuers = Issuers::new();
    let book = Arc::new(Book::default());
    let bound = Arc::new(IssuerBound::new(
        sealed,
        Arc::clone(&issuers),
        book.standing(),
        clock,
    ));
    let desk = TicketDesk::new(
        Arc::clone(&bound) as Arc<dyn Redeem>,
        plane(door_name),
        Arc::clone(&issuers),
    );
    Rig {
        f: ticket_fixture(who, Some(desk), open),
        bound,
        issuers,
        book,
    }
}

async fn rig() -> Rig {
    rig_of(now, NAME, Who::PRINCIPAL.with(Who::TICKET), false).await
}

fn ask<'a>(subject: &'a str, audience: &'a str) -> TicketMint<'a> {
    TicketMint {
        subject,
        scope: "realtime",
        audience,
        ttl_s: 60,
        // The plane asks for a reusable ticket; core mints a single-use one.
        once: false,
        prefix: "ek_",
        record: b"session-config",
    }
}

impl Rig {
    /// A ticket minted for `subject` while its request is served as `key`; that request has
    /// ended by the time the ticket is used.
    async fn mint(&self, subject: &str, key: &Arc<VirtualKey>, audience: &str) -> String {
        let _serving = self.issuers.enter(INSTANCE, subject, key);
        let who = plane(NAME);
        let (ticket, _) = self
            .bound
            .mint(&who.caller(), ask(subject, audience))
            .await
            .expect("a served principal mints");
        ticket.into()
    }

    /// One request on the route, carrying `fields`, as far as its verification.
    async fn arrive(
        &self,
        stream: u64,
        fields: Vec<(String, Vec<u8>)>,
    ) -> (
        Result<PendingData, DataPreparationFailed>,
        CompletingPhysicalRequest,
        StreamOwner,
    ) {
        let (mut request, _, cx, owner) = arrival_with_fields(&self.f, stream, fields);
        let preparation = request.begin_data_preparation().unwrap();
        (self.f.route.prepare(preparation, cx).await, request, owner)
    }

    fn chain_calls(&self) -> usize {
        self.f.calls.calls.load(Ordering::SeqCst)
    }
}

fn bearer(ticket: &str) -> Vec<(String, Vec<u8>)> {
    vec![(
        "authorization".to_owned(),
        format!("Bearer {ticket}").into_bytes(),
    )]
}

/// The one answer to a caller that is not verified: 401 with the route's challenge, written by
/// core. The reason is in the log and nowhere else.
fn the_one_401(arrived: Result<PendingData, DataPreparationFailed>) {
    let Err(failed) = arrived else {
        panic!("the request was verified")
    };
    assert_eq!(failed.reason(), DataRefused::Credential);
    assert!(
        matches!(failed, DataPreparationFailed::Denied(_)),
        "a refused ticket keeps the right to its answer: it is answered, not cancelled"
    );
    assert_eq!(
        failed.reason().refusal(true),
        Some(Refusal::Unverified { presented: true })
    );
    assert!(!failed.reason().after_verification());
}

#[tokio::test]
async fn a_minted_ticket_admits_one_request_on_its_route_as_its_issuer() {
    let rig = rig().await;
    let ticket = rig.mint("alice", &issuer("vk_alice"), TICKET_DOOR).await;

    let (arrived, _request, _owner) = rig.arrive(1, bearer(&ticket)).await;
    let authorization = arrived
        .expect("the ticket admits")
        .complete()
        .await
        .expect("its issuer stands");
    // The unit is the issuer's: its key, as it stands now, and nothing a role binding grants.
    assert_eq!(authorization.key().id, "vk_alice");
    assert_eq!(authorization.identity().subject(), "alice");
    // The plane is handed the record it stored at the mint, and nothing of the issuer binding.
    assert_eq!(
        authorization.ticket_record(),
        Some(&b"session-config"[..])
    );
    assert!(!authorization.is_shared());
    assert_eq!(rig.chain_calls(), 0, "a ticket is core's: no instance ran");
    assert_eq!(
        rig.f.replay.0.load(Ordering::SeqCst),
        0,
        "the ticket's single take is its replay claim"
    );

    // A second time, on the same route: the row is gone.
    let (again, _request, _owner) = rig.arrive(3, bearer(&ticket)).await;
    the_one_401(again);
    assert_eq!(
        rig.chain_calls(),
        0,
        "a refused ticket never falls through to the chain"
    );
}

#[tokio::test]
async fn a_ticket_is_refused_on_another_route() {
    // Another plane instance's door.
    let other = rig_of(now, "another", Who::PRINCIPAL.with(Who::TICKET), false).await;
    let ticket = other.mint("alice", &issuer("vk_alice"), TICKET_DOOR).await;
    let (arrived, _request, _owner) = other.arrive(1, bearer(&ticket)).await;
    the_one_401(arrived);

    // Minted for another door of the same instance.
    let rig = rig().await;
    let ticket = rig.mint("alice", &issuer("vk_alice"), "elsewhere").await;
    let (arrived, _request, _owner) = rig.arrive(1, bearer(&ticket)).await;
    the_one_401(arrived);
    assert_eq!(rig.chain_calls(), 0);
}

#[tokio::test]
async fn a_ticket_is_refused_after_its_expiry() {
    let rig = rig_of(
        eleven_minutes_ago,
        NAME,
        Who::PRINCIPAL.with(Who::TICKET),
        false,
    )
    .await;
    let ticket = rig.mint("alice", &issuer("vk_alice"), TICKET_DOOR).await;
    let (arrived, _request, _owner) = rig.arrive(1, bearer(&ticket)).await;
    the_one_401(arrived);
}

#[tokio::test]
async fn a_ticket_is_refused_once_its_issuer_key_is_disabled() {
    let rig = rig().await;
    let key = issuer("vk_alice");
    let ticket = rig.mint("alice", &key, TICKET_DOOR).await;
    let mut off = (*key).clone();
    off.enabled = false;
    rig.book.put(off);
    let (arrived, _request, _owner) = rig.arrive(1, bearer(&ticket)).await;
    the_one_401(arrived);
}

#[tokio::test]
async fn a_ticket_runs_under_what_its_issuer_holds_now() {
    let rig = rig().await;
    let key = issuer("vk_alice");
    let ticket = rig.mint("alice", &key, TICKET_DOOR).await;
    // The operator narrowed the key after the mint.
    let mut narrowed = (*key).clone();
    narrowed.allowed_scopes = Some(vec![busbar_contract::records::ScopeRef::pool("small")]);
    rig.book.put(narrowed);
    let (arrived, _request, _owner) = rig.arrive(1, bearer(&ticket)).await;
    let authorization = arrived.unwrap().complete().await.unwrap();
    assert_eq!(
        authorization.key().allowed_scopes,
        Some(vec![busbar_contract::records::ScopeRef::pool("small")]),
        "the request runs under the standing key, never the one the ticket remembers"
    );
}

#[tokio::test]
async fn a_ticket_identity_is_never_the_anonymous_principal() {
    // An open relay: every caller that presents nothing is `anonymous`.
    let rig = rig_of(now, NAME, Who::PRINCIPAL.with(Who::TICKET), true).await;
    let ticket = rig.mint("alice", &issuer("vk_alice"), TICKET_DOOR).await;
    let (arrived, _request, _owner) = rig.arrive(1, bearer(&ticket)).await;
    let authorization = arrived.unwrap().complete().await.unwrap();
    assert!(!authorization.is_shared());
    assert_eq!(
        authorization.key().id,
        "vk_alice",
        "the issuer's key, not what `role_bindings.anonymous` grants"
    );
}

#[tokio::test]
async fn a_mint_is_refused_without_a_served_principal() {
    let rig = rig().await;
    let who = plane(NAME);

    // Nobody is being served on the instance.
    assert_eq!(
        rig.bound
            .mint(&who.caller(), ask("alice", TICKET_DOOR))
            .await
            .err(),
        Some(RecordsDenied::Invalid)
    );

    // A principal the route's chain verified, authorized under its governed key: while its
    // request lives, a ticket is minted for its subject.
    let (arrived, _request, _owner) = rig.arrive(1, Vec::new()).await;
    let authorization = arrived
        .expect("the chain verifies a request with no ticket")
        .complete()
        .await
        .expect("its key stands");
    assert_eq!(rig.chain_calls(), 1);
    let subject = authorization.identity().subject().to_owned();
    let (ticket, _) = rig
        .bound
        .mint(&who.caller(), ask(&subject, TICKET_DOOR))
        .await
        .expect("a served principal mints");

    // Its request ended: so did the right to mint for it.
    drop(authorization);
    assert_eq!(
        rig.bound
            .mint(&who.caller(), ask(&subject, TICKET_DOOR))
            .await
            .err(),
        Some(RecordsDenied::Invalid)
    );

    // A request a ticket admitted is not an issuer: a ticket never mints the next one.
    let (arrived, _request, _owner) = rig.arrive(3, bearer(&ticket)).await;
    let _ticketed = arrived.unwrap().complete().await.unwrap();
    assert_eq!(
        rig.bound
            .mint(&who.caller(), ask(&subject, TICKET_DOOR))
            .await
            .err(),
        Some(RecordsDenied::Invalid)
    );
}

#[tokio::test]
async fn a_route_that_admits_a_ticket_alone_never_runs_its_chain() {
    let rig = rig_of(now, NAME, Who::TICKET, false).await;
    // No ticket: nobody verifies the caller.
    let (arrived, _request, _owner) = rig.arrive(1, Vec::new()).await;
    let Err(failed) = arrived else {
        panic!("a caller with no ticket was verified")
    };
    assert_eq!(failed.reason(), DataRefused::Credential);
    assert_eq!(rig.chain_calls(), 0);

    // With one, it is served as its issuer.
    let ticket = rig.mint("alice", &issuer("vk_alice"), TICKET_DOOR).await;
    let (arrived, _request, _owner) = rig.arrive(3, bearer(&ticket)).await;
    let authorization = arrived.unwrap().complete().await.unwrap();
    assert_eq!(authorization.key().id, "vk_alice");
    assert_eq!(rig.chain_calls(), 0);
}

#[tokio::test]
async fn a_ticket_beside_another_credential_is_refused_unspent() {
    let rig = rig().await;
    let ticket = rig.mint("alice", &issuer("vk_alice"), TICKET_DOOR).await;
    let mut both = bearer(&ticket);
    both.push(("authorization".to_owned(), b"Bearer sk-other".to_vec()));
    let (arrived, _request, _owner) = rig.arrive(1, both).await;
    the_one_401(arrived);
    assert_eq!(rig.chain_calls(), 0);

    // It was not spent on the guess: alone, it still admits.
    let (arrived, _request, _owner) = rig.arrive(3, bearer(&ticket)).await;
    assert!(arrived.is_ok());
}

#[tokio::test]
async fn a_ticket_route_with_no_desk_serves_nobody() {
    // No signing key: the plan leaves such a route unmounted. One bound anyway admits nothing,
    // with a ticket or without, and never runs its chain in the ticket's place.
    let f = ticket_fixture(Who::PRINCIPAL.with(Who::TICKET), None, false);
    let (mut request, _, cx, _owner) = arrival(&f, 1);
    let preparation = request.begin_data_preparation().unwrap();
    let Err(failed) = f.route.prepare(preparation, cx).await else {
        panic!("a ticket route with no ticket store admitted a request")
    };
    assert_eq!(failed.reason(), DataRefused::Unsupported);
    assert_eq!(f.calls.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_ticket_request_is_handed_to_its_plane_as_a_ticket() {
    use busbar_plugin_abi::plane::{AUTH_PRINCIPAL, AUTH_TICKET};
    assert_eq!(auth_class(true), AUTH_TICKET);
    assert_eq!(auth_class(false), AUTH_PRINCIPAL);
}
