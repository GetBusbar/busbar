// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The native ticket verifier: what a ticket admits, on which door, how often, for how long and
//! as whom. Every case runs the real sealed store over the real core store; only the issuer's
//! standing (the governance book) is a table the test writes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::records::{ScopeRef, VirtualKey};
use busbar_plugin_abi::fail::refused::R_BAD_CREDENTIAL;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};

use super::*;
use crate::auth::admission_table::{decide, Decision, Refusal, Target};
use crate::auth::reference_plane;
use crate::plane_grants::{SealedTickets, TICKET_MARKER};
use crate::plugin_records::StoreRecords;

const NOW: u64 = 1_800_000_000;
const DOOR: &str = "ticket";
const PLANE: &str = "plane-streaming";
const NAME: &str = "realtime";
const INSTANCE: u64 = 7;

/// The store's clock: every case moves it by hand.
static CLOCK: AtomicU64 = AtomicU64::new(NOW);

fn clock() -> u64 {
    CLOCK.load(Ordering::SeqCst)
}

fn who(name: &str) -> Namespace {
    Namespace {
        plugin: Arc::from(PLANE),
        name: Arc::from(name),
        instance: INSTANCE,
        slot: 0,
    }
}

fn key(id: &str, generation: &str) -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: id.into(),
        generation_hash: generation.into(),
        name: id.into(),
        allowed_scopes: Some(vec![ScopeRef::pool("small")]),
        enabled: true,
        group: Some("team".into()),
        ..Default::default()
    })
}

/// The governance book of the test: the key each id resolves to now.
#[derive(Default)]
struct Book(Mutex<HashMap<String, Arc<VirtualKey>>>);

impl Book {
    fn put(&self, key: &Arc<VirtualKey>) {
        self.0
            .lock()
            .unwrap()
            .insert(key.id.clone(), Arc::clone(key));
    }
    fn remove(&self, id: &str) {
        self.0.lock().unwrap().remove(id);
    }
    fn standing(self: &Arc<Self>) -> Standing {
        let book = Arc::clone(self);
        Arc::new(move |admitted: &Arc<VirtualKey>, _now: u64| {
            book.0.lock().unwrap().get(&admitted.id).cloned()
        })
    }
}

struct Rig {
    bound: Arc<IssuerBound<SealedTickets<StoreRecords>>>,
    issuers: Arc<Issuers>,
    book: Arc<Book>,
    /// The same rows and the same seal with no issuer binding: what a mint around the binding
    /// would have produced.
    plain: SealedTickets<StoreRecords>,
}

async fn rig() -> Rig {
    CLOCK.store(NOW, Ordering::SeqCst);
    let core = crate::real_store::core().await;
    let sealed = |core: Arc<crate::persistence::facade::CoreStore>| {
        SealedTickets::new(StoreRecords::with_clock(core, clock), &[7u8; 32], clock)
            .expect("a 32-byte key")
    };
    let issuers = Issuers::new();
    let book = Arc::new(Book::default());
    Rig {
        bound: Arc::new(IssuerBound::new(
            sealed(Arc::clone(&core)),
            Arc::clone(&issuers),
            book.standing(),
            clock,
        )),
        issuers,
        book,
        plain: sealed(core),
    }
}

impl Rig {
    fn verifier(&self, name: &str, door: &str) -> NativeTicketVerifier {
        NativeTicketVerifier::new(Arc::clone(&self.bound) as Arc<dyn Redeem>, who(name), door)
    }

    /// A mint for `subject` while its request is being served as `issuer`.
    async fn mint(&self, subject: &str, issuer: &Arc<VirtualKey>, ttl_s: u64) -> (String, u64) {
        self.book.put(issuer);
        let _serving = self.issuers.enter(INSTANCE, subject, issuer);
        let plane = who(NAME);
        let (ticket, expires_at) = self
            .bound
            .mint(
                &plane.caller(),
                TicketMint {
                    subject,
                    scope: "realtime",
                    audience: DOOR,
                    ttl_s,
                    // The plane asks for a reusable ticket; core mints a single-use one.
                    once: false,
                    prefix: "ek_",
                    record: b"session-config",
                },
            )
            .await
            .expect("a served principal mints");
        (ticket.into(), expires_at)
    }
}

fn bearer(ticket: &str) -> Vec<(String, Vec<u8>)> {
    vec![(
        "authorization".to_owned(),
        format!("Bearer {ticket}").into_bytes(),
    )]
}

fn head(headers: &[(String, Vec<u8>)]) -> impl Iterator<Item = (&str, &[u8])> + '_ {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
}

fn ticket_route() -> crate::auth::route_record::RouteRecord {
    reference_plane::route_of(Admission::Ticket)
        .expect("the reference plane has a ticket route")
        .record
}

/// The one answer to a request that is not verified, as the table gives it.
fn the_one_401(judged: &TicketJudged) {
    let record = ticket_route();
    let facts = judged.facts(&record, false);
    let Decision::Refuse { refusal, verified } = decide(Target::Route(&record), &facts) else {
        panic!("a refused ticket is refused by the table")
    };
    assert_eq!(refusal, Refusal::Unverified { presented: true });
    assert!(
        !verified,
        "the caller was not verified: core writes the answer"
    );
    let row = refusal.row(false);
    assert_eq!((row.status, row.code), (401, R_BAD_CREDENTIAL));
    assert!(row.challenge);
}

fn refused(judged: &TicketJudged) -> TicketRefused {
    match judged {
        TicketJudged::Refused(refused) => *refused,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_valid_ticket_is_admitted_once_as_its_issuer_with_its_record() {
    let rig = rig().await;
    let issuer = key("key-alice", "g1");
    let (ticket, expires_at) = rig.mint("alice", &issuer, 60).await;
    assert_eq!(expires_at, NOW + 60);
    assert!(ticket.starts_with("ek_") && ticket.contains(TICKET_MARKER));

    let record = ticket_route();
    let judged = rig
        .verifier(NAME, DOOR)
        .verify(&record, head(&bearer(&ticket)), NOW + 1)
        .await;
    let facts = judged.facts(&record, false);
    assert_eq!(facts.verified, Some(Verified::Ticket));
    assert!(facts.ticket_presented);
    assert!(
        !matches!(
            decide(Target::Route(&record), &facts),
            Decision::Refuse { .. }
        ),
        "a verified ticket passes step 2: the table goes on to the body"
    );
    let TicketJudged::Admitted(admitted) = judged else {
        panic!("a live ticket on its own door is admitted")
    };
    assert_eq!(admitted.key().id, "key-alice");
    assert_eq!(admitted.identity().subject(), "alice");
    assert_eq!(
        admitted.ticket_record(),
        b"session-config",
        "the plane is handed its own record, never the issuer binding around it"
    );
    assert_eq!(admitted.instance(), INSTANCE);
}

#[tokio::test]
async fn an_expired_ticket_is_the_one_401() {
    let rig = rig().await;
    let (ticket, expires_at) = rig.mint("alice", &key("key-alice", "g1"), 60).await;
    let judged = rig
        .verifier(NAME, DOOR)
        .verify(&ticket_route(), head(&bearer(&ticket)), expires_at)
        .await;
    assert_eq!(refused(&judged), TicketRefused::Expired);
    the_one_401(&judged);
}

#[tokio::test]
async fn a_ticket_lives_no_longer_than_the_ceiling_or_its_issuers_key() {
    let rig = rig().await;
    let (_, expires_at) = rig.mint("alice", &key("key-alice", "g1"), 86_400).await;
    assert_eq!(
        expires_at,
        NOW + TICKET_LIFE_MAX_S,
        "a mint that asks for a day is given the ceiling"
    );
    let mut short = (*key("key-bob", "g1")).clone();
    short.expires_at = Some(NOW + 30);
    let (ticket, expires_at) = rig.mint("bob", &Arc::new(short), 600).await;
    assert_eq!(
        expires_at,
        NOW + 30,
        "a ticket never outlives its issuer's key"
    );
    let judged = rig
        .verifier(NAME, DOOR)
        .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 30)
        .await;
    assert_eq!(refused(&judged), TicketRefused::Expired);
}

#[tokio::test]
async fn a_ticket_used_on_another_route_is_the_one_401() {
    let rig = rig().await;
    let issuer = key("key-alice", "g1");

    // Another door of the same plane instance.
    let (ticket, _) = rig.mint("alice", &issuer, 60).await;
    let judged = rig
        .verifier(NAME, "sideband")
        .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 1)
        .await;
    assert_eq!(refused(&judged), TicketRefused::Invalid);
    the_one_401(&judged);

    // The same door of another instance of the same plane image.
    let (ticket, _) = rig.mint("alice", &issuer, 60).await;
    let judged = rig
        .verifier("other-realtime", DOOR)
        .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 1)
        .await;
    assert_eq!(refused(&judged), TicketRefused::Invalid);
    the_one_401(&judged);

    // A route whose record admits no ticket: refused unspent, so its own door still admits it.
    let (ticket, _) = rig.mint("alice", &issuer, 60).await;
    let keyed = reference_plane::route_of(Admission::PrincipalOnly)
        .expect("the reference plane has a principal route")
        .record;
    let judged = rig
        .verifier(NAME, DOOR)
        .verify(&keyed, head(&bearer(&ticket)), NOW + 1)
        .await;
    assert_eq!(refused(&judged), TicketRefused::RouteTakesNoTicket);
    assert_eq!(refused(&judged).verified(), Verified::Denied);
    let judged = rig
        .verifier(NAME, DOOR)
        .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 1)
        .await;
    assert!(
        matches!(judged, TicketJudged::Admitted(_)),
        "a ticket refused on a route that takes none was not spent there"
    );
}

#[tokio::test]
async fn a_ticket_used_twice_is_admitted_once() {
    let rig = rig().await;
    let (ticket, _) = rig.mint("alice", &key("key-alice", "g1"), 60).await;
    let verifier = rig.verifier(NAME, DOOR);
    let first = verifier
        .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 1)
        .await;
    assert!(matches!(first, TicketJudged::Admitted(_)));
    let second = verifier
        .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 2)
        .await;
    assert_eq!(
        refused(&second),
        TicketRefused::Replayed,
        "the plane asked for a reusable ticket and core minted a single-use one"
    );
    the_one_401(&second);
}

#[tokio::test]
async fn a_ticket_never_admits_more_than_its_issuer_can_do_now() {
    let rig = rig().await;
    let verifier = rig.verifier(NAME, DOOR);

    // The operator narrows the issuer after the mint: the request runs under the narrow key.
    let issuer = key("key-alice", "g1");
    let (ticket, _) = rig.mint("alice", &issuer, 60).await;
    let mut narrowed = (*issuer).clone();
    narrowed.allowed_scopes = Some(Vec::new());
    narrowed.group = Some("frozen".into());
    rig.book.put(&Arc::new(narrowed));
    let TicketJudged::Admitted(admitted) = verifier
        .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 1)
        .await
    else {
        panic!("a narrowed issuer still stands")
    };
    assert!(admitted
        .key()
        .allowed_scopes
        .as_ref()
        .is_some_and(Vec::is_empty));
    assert_eq!(admitted.key().group.as_deref(), Some("frozen"));

    // The issuer as the mint saw it was unrestricted; today it is restricted. The row remembers
    // the wide key and the request still runs under the one that stands.
    let mut wide = (*key("key-wide", "g1")).clone();
    wide.allowed_scopes = None;
    let (ticket, _) = rig.mint("carol", &Arc::new(wide), 60).await;
    rig.book.put(&key("key-wide", "g1"));
    let TicketJudged::Admitted(admitted) = verifier
        .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 1)
        .await
    else {
        panic!("the restricted issuer still stands")
    };
    assert!(
        admitted.key().allowed_scopes.is_some(),
        "the key the row remembers is never the key the request runs under"
    );

    // Disabled, deleted from the book, rotated, expired: the ticket admits nothing.
    for lapse in ["disabled", "gone", "rotated", "expired"] {
        let issuer = key("key-dave", "g1");
        let (ticket, _) = rig.mint("dave", &issuer, 60).await;
        let mut now = (*issuer).clone();
        match lapse {
            "disabled" => now.enabled = false,
            "rotated" => now.generation_hash = "g2".into(),
            "expired" => now.expires_at = Some(NOW),
            _ => {}
        }
        if lapse == "gone" {
            rig.book.remove("key-dave");
        } else {
            rig.book.put(&Arc::new(now));
        }
        let judged = verifier
            .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 1)
            .await;
        assert_eq!(refused(&judged), TicketRefused::Invalid, "issuer {lapse}");
        the_one_401(&judged);
    }
}

fn ask(subject: &str) -> TicketMint<'_> {
    TicketMint {
        subject,
        scope: "realtime",
        audience: DOOR,
        ttl_s: 60,
        once: true,
        prefix: "ek_",
        record: b"",
    }
}

#[tokio::test]
async fn a_ticket_is_minted_only_for_a_principal_being_served() {
    let rig = rig().await;
    let plane = who(NAME);

    // Nobody of that subject is being served on this instance.
    assert!(rig
        .bound
        .mint(&plane.caller(), ask("mallory"))
        .await
        .is_err());

    // The request ended: its guard is gone, and so is the right to mint for it.
    let alice = key("key-alice", "g1");
    rig.book.put(&alice);
    drop(rig.issuers.enter(INSTANCE, "alice", &alice));
    assert!(rig.bound.mint(&plane.caller(), ask("alice")).await.is_err());

    // Served on another plane instance.
    let _elsewhere = rig.issuers.enter(INSTANCE + 1, "alice", &alice);
    assert!(rig.bound.mint(&plane.caller(), ask("alice")).await.is_err());

    // Two requests state one subject under two keys: which one a mint is for cannot be said.
    let _one = rig
        .issuers
        .enter(INSTANCE, "erin", &key("key-erin-a", "g1"));
    let _two = rig
        .issuers
        .enter(INSTANCE, "erin", &key("key-erin-b", "g1"));
    assert!(rig.bound.mint(&plane.caller(), ask("erin")).await.is_err());

    // An issuer that does not stand mints nothing.
    let mut off = (*key("key-frank", "g1")).clone();
    off.enabled = false;
    let _serving = rig.issuers.enter(INSTANCE, "frank", &Arc::new(off));
    assert!(rig.bound.mint(&plane.caller(), ask("frank")).await.is_err());
}

#[tokio::test]
async fn a_ticket_with_no_issuer_binding_is_refused() {
    let rig = rig().await;
    let plane = who(NAME);
    for record in [&b""[..], &b"session-config"[..]] {
        let (ticket, _) = rig
            .plain
            .mint(
                &plane.caller(),
                TicketMint {
                    subject: "alice",
                    scope: "realtime",
                    audience: DOOR,
                    ttl_s: 60,
                    once: true,
                    prefix: "ek_",
                    record,
                },
            )
            .await
            .expect("the plain store mints");
        let judged = rig
            .verifier(NAME, DOOR)
            .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 1)
            .await;
        assert_eq!(
            refused(&judged),
            TicketRefused::Invalid,
            "a sealed ticket that names no issuer admits nobody"
        );
        the_one_401(&judged);
    }
}

#[tokio::test]
async fn a_ticket_beside_another_credential_is_refused_unspent() {
    let rig = rig().await;
    let (ticket, _) = rig.mint("alice", &key("key-alice", "g1"), 60).await;
    let verifier = rig.verifier(NAME, DOOR);
    let mut decoy = bearer("sk-some-key");
    decoy.extend(bearer(&ticket));
    let judged = verifier
        .verify(&ticket_route(), head(&decoy), NOW + 1)
        .await;
    assert_eq!(refused(&judged), TicketRefused::Ambiguous);
    the_one_401(&judged);
    assert!(
        matches!(
            verifier
                .verify(&ticket_route(), head(&bearer(&ticket)), NOW + 1)
                .await,
            TicketJudged::Admitted(_)
        ),
        "the refused request spent nothing"
    );
}

#[tokio::test]
async fn a_request_with_no_ticket_is_left_to_the_chain_or_not_verified() {
    let rig = rig().await;
    let verifier = rig.verifier(NAME, DOOR);
    let record = ticket_route();
    let judged = verifier
        .verify(&record, head(&bearer("sk-some-key")), NOW)
        .await;
    assert!(matches!(judged, TicketJudged::NoTicket));
    let facts = judged.facts(&record, true);
    assert!(!facts.ticket_presented);
    assert_eq!(
        facts.verified.is_none(),
        record.who.has(Who::PRINCIPAL),
        "a key on a key-or-ticket route is the chain's to judge"
    );
    let mut ticket_only = record.clone();
    ticket_only.who = Who::TICKET;
    assert_eq!(
        judged.facts(&ticket_only, false).verified,
        Some(Verified::Denied)
    );
}

/// A door whose store is down, and one that counts what it was asked.
struct Down(AtomicUsize);

impl Redeem for Down {
    fn is_ticket(&self, credential: &str) -> bool {
        credential.contains(TICKET_MARKER)
    }
    fn redeem<'a>(
        &'a self,
        _plane: &'a Caller<'_>,
        _door: &'a str,
        _credential: &'a str,
        _now_s: u64,
    ) -> BoxFut<'a, Result<Redeemed, TicketDenied>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(TicketDenied::Unavailable) })
    }
}

#[tokio::test]
async fn a_ticket_store_that_cannot_answer_is_503_never_401() {
    let down = Arc::new(Down(AtomicUsize::new(0)));
    let verifier = NativeTicketVerifier::new(Arc::clone(&down) as Arc<dyn Redeem>, who(NAME), DOOR);
    let record = ticket_route();
    let judged = verifier
        .verify(&record, head(&bearer("ek_bbt1.AAAA")), NOW)
        .await;
    assert_eq!(refused(&judged), TicketRefused::Unavailable);
    assert_eq!(down.0.load(Ordering::SeqCst), 1);
    let facts = judged.facts(&record, false);
    assert_eq!(facts.verified, Some(Verified::Unavailable));
    let Decision::Refuse { refusal, .. } = decide(Target::Route(&record), &facts) else {
        panic!("a verifier that cannot answer is refused by the table")
    };
    assert_eq!(refusal, Refusal::VerifierUnavailable);
    assert_eq!(refusal.row(false).status, 503);
}

#[test]
fn a_refusal_says_why_only_to_the_log() {
    let all = [
        TicketRefused::RouteTakesNoTicket,
        TicketRefused::Ambiguous,
        TicketRefused::Invalid,
        TicketRefused::Expired,
        TicketRefused::Replayed,
    ];
    for refused in all {
        assert_eq!(
            refused.verified(),
            Verified::Denied,
            "{}: every denial is the same fact, so the same bytes",
            refused.reason()
        );
        assert!(!refused.reason().is_empty());
    }
    assert_eq!(TicketRefused::Unavailable.verified(), Verified::Unavailable);
    assert_eq!(
        format!("{:?}", Presented::Ticket("ek_bbt1.secret")),
        "Ticket(..)",
        "a presented ticket never prints"
    );
}

#[test]
fn the_table_selects_this_verifier_for_a_ticket_route_only() {
    use crate::auth::admission_table::{plan, VerifyBy};
    use crate::auth::route_record::Money;
    for admission in [
        Admission::Walk,
        Admission::Selected,
        Admission::PrincipalOnly,
        Admission::Catalog,
        Admission::Public,
        Admission::Optional,
        Admission::Ticket,
        Admission::SignedIngress,
        Admission::Upgrade,
        Admission::Operator,
    ] {
        let sequence = plan(admission, Money::None).expect("a listener admission has a sequence");
        assert_eq!(
            selected_by(sequence.verify),
            NativeTicketVerifier::serves(admission),
            "{admission:?}"
        );
    }
    assert!(selected_by(VerifyBy::TicketOrChain));
}
