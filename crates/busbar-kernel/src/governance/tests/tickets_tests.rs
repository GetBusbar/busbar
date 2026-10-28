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
