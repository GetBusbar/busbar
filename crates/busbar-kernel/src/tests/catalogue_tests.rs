// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/catalogue.rs` — THE ONE CATALOGUE WALK.
//!
//! Two jobs, and the second is the one that makes the unification worth doing:
//!
//! 1. **THE RULES THE MECHANISM OWNS.** A catalogue answers "what may this caller SEE", which is a
//!    data-exposure surface. Each rule this module owns — the fail-closed floor, the
//!    entitlement-before-fitness ordering, the inventory order, the render-after-filter rule — is
//!    produced HERE by actually violating it, so a rule that stopped being applied is named by the
//!    failure rather than left to manual review.
//!
//!    The entitlement DECISION itself is not tested here, because it is not this module's: it
//!    belongs to `crate::trust::validate`, which has its own battery. What IS tested here is that
//!    this module reaches it, in the right order, and refuses to enumerate an item that never named
//!    a grant for it to judge.
//!
//! 2. **THE SEAM.** `A THIRD PLANE COSTS AN ITEM TYPE AND NOTHING ELSE` is the acceptance test for
//!    this design, so this file declares a throwaway item type ([`Leaflet`]) for a plane busbar does
//!    not have and shows it is enumerated, filtered by grants and rendered with NO new mechanism: no
//!    catalogue module, no walk, no filter, no error type and no ordering rule written for it.

use super::*;

use std::cell::Cell;
use std::collections::BTreeMap;

use busbar_contract::records::{ScopeRef, VirtualKey};

use crate::trust::validate::{Generations, Grant, Refusal};

/// A throwaway third-plane item: a leaflet in a kiosk, published by a `bureau`, in a `district`,
/// classified up to a `clearance`.
#[derive(Debug)]
struct Leaflet {
    bureau: String,
    district: String,
    id: String,
    /// The minimum clearance a reader needs. The fitness axis — a NUMBER, not a document.
    clearance: u8,
    editions: Vec<String>,
    /// HOW MANY TIMES fitness was asked about this leaflet. A `Cell` so the count survives a `&self`
    /// method: this is what proves entitlement runs BEFORE fitness rather than merely that the
    /// answer comes out the same.
    fitted: Cell<u32>,
}

/// The third plane's own refusal vocabulary. Shares no arm with `DispatchRefusal` or A2A's
/// `Excluded`, which is the point: a plane's refusal words are its own, and it renders the ordered
/// gate's refusal into them rather than adopting them.
#[derive(Debug, PartialEq, Eq)]
enum Unavailable {
    NoTicket,
    ReaderGone,
    AboveClearance { needs: u8, holds: u8 },
    OutOfPrint,
}

struct Reader {
    clearance: u8,
    edition: Option<String>,
}

/// The third plane's wire form, BORROWING from the item.
#[derive(Debug, PartialEq, Eq)]
struct Handout<'a> {
    id: &'a str,
    district: &'a str,
}

impl CatalogueItem for Leaflet {
    type Excluded = Unavailable;
    type Query = Reader;

    type Fit = String;
    type Wire<'a> = Handout<'a>;

    fn required_grants<'g>(&'g self, _reader: &'g Reader, out: &mut Vec<Grant<'g>>) {
        out.push(Grant::Scope {
            kind: "kiosk_bureau",
            name: &self.bureau,
        });
        out.push(Grant::Scope {
            kind: "kiosk_district",
            name: &self.district,
        });
        out.push(Grant::Scope {
            kind: "kiosk_leaflet",
            name: &self.id,
        });
    }

    fn admit(&self, caller: &Caller<'_>, grants: &[Grant<'_>]) -> Result<(), Unavailable> {
        crate::trust::validate::validate_visibility(caller.key, caller.now, grants).map_err(|r| {
            match r {
                Refusal::IdentityNotLive { .. } => Unavailable::ReaderGone,
                _ => Unavailable::NoTicket,
            }
        })
    }

    fn fit(&self, reader: &Reader) -> Result<String, Unavailable> {
        self.fitted.set(self.fitted.get() + 1);
        if reader.clearance < self.clearance {
            return Err(Unavailable::AboveClearance {
                needs: self.clearance,
                holds: reader.clearance,
            });
        }
        match &reader.edition {
            None => self
                .editions
                .first()
                .cloned()
                .ok_or(Unavailable::OutOfPrint),
            Some(want) => self
                .editions
                .iter()
                .find(|e| *e == want)
                .cloned()
                .ok_or(Unavailable::OutOfPrint),
        }
    }

    fn ungranted(&self) -> Unavailable {
        Unavailable::NoTicket
    }

    fn render(&self) -> Handout<'_> {
        Handout {
            id: &self.id,
            district: &self.district,
        }
    }
}

fn leaflet(bureau: &str, district: &str, id: &str, clearance: u8) -> Leaflet {
    Leaflet {
        bureau: bureau.to_string(),
        district: district.to_string(),
        id: id.to_string(),
        clearance,
        editions: vec!["first".to_string(), "revised".to_string()],
        fitted: Cell::new(0),
    }
}

fn key_scoped(scopes: &[(&str, &str)]) -> VirtualKey {
    VirtualKey {
        id: "k1".to_string(),
        generation_hash: String::new(),
        name: "k1".to_string(),
        allowed_scopes: Some(
            scopes
                .iter()
                .map(|(k, v)| ScopeRef {
                    kind: (*k).to_string(),
                    value: (*v).to_string(),
                })
                .collect(),
        ),
        enabled: true,
        created_at: 0,
        group: None,
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

fn caller(key: &VirtualKey) -> Caller<'_> {
    Caller {
        key: Some(key),
        now: 0,
        generation: Generations::at_admission(1),
    }
}

fn ticket(district: &str, id: &str) -> Vec<(&'static str, String)> {
    vec![
        ("kiosk_bureau", "works".to_string()),
        ("kiosk_district", district.to_string()),
        ("kiosk_leaflet", id.to_string()),
    ]
}

fn key_holding(tickets: &[(&'static str, String)]) -> VirtualKey {
    let pairs: Vec<(&str, &str)> = tickets.iter().map(|(k, v)| (*k, v.as_str())).collect();
    key_scoped(&pairs)
}

fn an_inventory() -> Vec<Leaflet> {
    vec![
        leaflet("works", "north", "leaflet-a", 0),
        leaflet("works", "south", "leaflet-b", 0),
        leaflet("works", "north", "leaflet-secret", 5),
    ]
}

fn cleared() -> Reader {
    Reader {
        clearance: 9,
        edition: None,
    }
}

#[test]
fn a_third_plane_costs_an_item_type_and_nothing_else() {
    let inventory = an_inventory();

    let mut all = ticket("north", "leaflet-a");
    all.extend(ticket("south", "leaflet-b"));
    all.extend(ticket("north", "leaflet-secret"));
    let everything = key_holding(&all);
    let seen = entitled(&inventory, &caller(&everything), &cleared());
    assert_eq!(
        seen.iter().map(|e| e.item.id.as_str()).collect::<Vec<_>>(),
        vec!["leaflet-a", "leaflet-b", "leaflet-secret"],
        "every entitled item is enumerated, in the inventory's own order"
    );

    assert!(
        seen.iter().all(|e| e.fit == "first"),
        "the fitness test's chosen edition is carried out of the filter"
    );

    let one = key_holding(&ticket("north", "leaflet-a"));
    assert_eq!(
        visible(&inventory, &caller(&one), &cleared())
            .iter()
            .map(|l| l.id.as_str())
            .collect::<Vec<_>>(),
        vec!["leaflet-a"],
        "a ticket for one leaflet reaches exactly that leaflet"
    );

    assert_eq!(
        rendered(&inventory, &caller(&one), &cleared()),
        vec![Handout {
            id: "leaflet-a",
            district: "north",
        }],
    );

    let uncleared = Reader {
        clearance: 1,
        edition: None,
    };
    assert_eq!(
        visible(&inventory, &caller(&everything), &uncleared)
            .iter()
            .map(|l| l.id.as_str())
            .collect::<Vec<_>>(),
        vec!["leaflet-a", "leaflet-b"],
        "the plane's own fitness rule excludes what its grants admitted"
    );
    assert_eq!(
        judge(&inventory[2], &caller(&everything), &uncleared).unwrap_err(),
        Unavailable::AboveClearance { needs: 5, holds: 1 },
        "and the plane's own refusal words are what comes back"
    );
}

#[test]
fn a_third_plane_inherits_the_identity_step_it_wrote_no_line_for() {
    let inventory = an_inventory();
    let mut all = ticket("north", "leaflet-a");
    all.extend(ticket("south", "leaflet-b"));
    let live = key_holding(&all);

    assert_eq!(visible(&inventory, &caller(&live), &cleared()).len(), 2);

    for (what, mutate) in [
        (
            "deleted",
            (|k: &mut VirtualKey| k.deleted_at = Some(1)) as fn(&mut VirtualKey),
        ),
        ("disabled", |k: &mut VirtualKey| k.enabled = false),
        ("expired", |k: &mut VirtualKey| k.expires_at = Some(1)),
    ] {
        let mut gone = live.clone();
        mutate(&mut gone);
        let asked = Caller {
            key: Some(&gone),
            now: 100,
            generation: Generations::at_admission(1),
        };
        assert!(
            visible(&inventory, &asked, &cleared()).is_empty(),
            "a {what} key must see nothing"
        );
        assert_eq!(
            judge(&inventory[0], &asked, &cleared()).unwrap_err(),
            Unavailable::ReaderGone,
            "{what}: and it is told in this plane's own word, not the gate's"
        );
    }
}

#[test]
fn an_item_that_declares_no_grant_is_invisible_not_public() {
    /// A leaflet whose author forgot to write a requirement. Nothing else about it differs.
    #[derive(Debug)]
    struct Ungated(Leaflet);
    impl CatalogueItem for Ungated {
        type Excluded = Unavailable;
        type Query = Reader;
        type Fit = String;
        type Wire<'a> = Handout<'a>;
        fn required_grants<'g>(&'g self, _reader: &'g Reader, _out: &mut Vec<Grant<'g>>) {}
        fn admit(&self, caller: &Caller<'_>, grants: &[Grant<'_>]) -> Result<(), Unavailable> {
            self.0.admit(caller, grants)
        }
        fn fit(&self, reader: &Reader) -> Result<String, Unavailable> {
            self.0.fit(reader)
        }
        fn ungranted(&self) -> Unavailable {
            Unavailable::NoTicket
        }
        fn render(&self) -> Handout<'_> {
            self.0.render()
        }
    }

    let inventory = vec![Ungated(leaflet("works", "north", "leaflet-a", 0))];

    let mut open = key_scoped(&[]);
    open.allowed_scopes = None;
    assert!(
        visible(&inventory, &caller(&open), &cleared()).is_empty(),
        "an item that requires no grant is invisible; the alternative reading hands it to everyone"
    );
    assert_eq!(
        judge(&inventory[0], &caller(&open), &cleared()).unwrap_err(),
        Unavailable::NoTicket,
        "and it is refused as ungranted, in the plane's own words"
    );
    assert_eq!(
        inventory[0].0.fitted.get(),
        0,
        "an item nobody may see is never fitness-tested, not even to reach the same answer"
    );
}

#[test]
fn every_required_grant_reaches_the_gate_and_a_missing_one_hides_the_item() {
    let inventory = vec![leaflet("works", "north", "leaflet-a", 0)];
    let full = ticket("north", "leaflet-a");

    let holds_all = key_holding(&full);
    assert_eq!(
        visible(&inventory, &caller(&holds_all), &cleared()).len(),
        1,
        "the control must pass, or the rows below prove nothing"
    );

    for dropped in ["kiosk_bureau", "kiosk_district", "kiosk_leaflet"] {
        let partial: Vec<(&'static str, String)> = full
            .iter()
            .filter(|(k, _)| *k != dropped)
            .cloned()
            .collect();
        assert_eq!(partial.len(), 2, "exactly one grant is withheld");
        let holds_two = key_holding(&partial);
        assert!(
            visible(&inventory, &caller(&holds_two), &cleared()).is_empty(),
            "withholding `{dropped}` must hide the item: a declared grant never reached the gate"
        );
    }
}

#[test]
fn an_item_the_caller_may_not_see_is_never_fitness_tested() {
    let inventory = [leaflet("works", "north", "leaflet-secret", 5)];

    let broke = Reader {
        clearance: 0,
        edition: None,
    };
    let nothing = key_scoped(&[]);
    assert_eq!(
        judge(&inventory[0], &caller(&nothing), &broke).unwrap_err(),
        Unavailable::NoTicket,
        "the grant refusal wins, so no clearance level is ever disclosed by the refusal it chose"
    );
    assert_eq!(
        inventory[0].fitted.get(),
        0,
        "fitness was not merely ignored, it was never asked"
    );

    let holds = key_holding(&ticket("north", "leaflet-secret"));
    assert_eq!(
        judge(&inventory[0], &caller(&holds), &broke).unwrap_err(),
        Unavailable::AboveClearance { needs: 5, holds: 0 }
    );
    assert_eq!(inventory[0].fitted.get(), 1);
}

#[test]
fn one_principal_never_sees_another_principals_inventory() {
    let inventory = vec![
        leaflet("works", "north", "leaflet-a", 0),
        leaflet("works", "south", "leaflet-b", 0),
    ];
    let alice = key_holding(&ticket("north", "leaflet-a"));
    let bob = key_holding(&ticket("south", "leaflet-b"));

    let alice_sees: Vec<&str> = visible(&inventory, &caller(&alice), &cleared())
        .iter()
        .map(|l| l.id.as_str())
        .collect();
    let bob_sees: Vec<&str> = visible(&inventory, &caller(&bob), &cleared())
        .iter()
        .map(|l| l.id.as_str())
        .collect();

    assert_eq!(alice_sees, vec!["leaflet-a"]);
    assert_eq!(bob_sees, vec!["leaflet-b"]);

    assert!(
        alice_sees.iter().all(|a| !bob_sees.contains(a)),
        "no item of one principal's catalogue appears in the other's"
    );

    assert!(!alice_sees.is_empty() && !bob_sees.is_empty());
}

#[test]
fn the_entitled_subset_keeps_the_inventorys_own_order() {
    let inventory = vec![
        leaflet("works", "north", "zulu", 0),
        leaflet("works", "north", "alpha", 0),
        leaflet("works", "north", "mike", 0),
    ];
    let mut tickets = ticket("north", "zulu");
    tickets.extend(ticket("north", "alpha"));
    tickets.extend(ticket("north", "mike"));
    let holds = key_holding(&tickets);
    assert_eq!(
        visible(&inventory, &caller(&holds), &cleared())
            .iter()
            .map(|l| l.id.as_str())
            .collect::<Vec<_>>(),
        vec!["zulu", "alpha", "mike"],
    );
}

#[test]
fn nothing_is_rendered_that_was_not_first_entitled() {
    let inventory = an_inventory();
    let holds = key_holding(&ticket("south", "leaflet-b"));
    assert_eq!(
        rendered(&inventory, &caller(&holds), &cleared()),
        vec![Handout {
            id: "leaflet-b",
            district: "south",
        }],
        "only the entitled item is rendered"
    );

    assert_eq!(inventory[0].fitted.get(), 0);
    assert_eq!(inventory[2].fitted.get(), 0);
    assert_eq!(inventory[1].fitted.get(), 1);
}

#[test]
fn the_fitness_answer_is_carried_out_of_the_filter() {
    let inventory = vec![leaflet("works", "north", "leaflet-a", 0)];
    let holds = key_holding(&ticket("north", "leaflet-a"));
    let revised = Reader {
        clearance: 9,
        edition: Some("revised".to_string()),
    };
    let got = entitled(&inventory, &caller(&holds), &revised);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].fit, "revised");

    let gone = Reader {
        clearance: 9,
        edition: Some("withdrawn".to_string()),
    };
    assert_eq!(
        judge(&inventory[0], &caller(&holds), &gone).unwrap_err(),
        Unavailable::OutOfPrint,
    );
    assert!(entitled(&inventory, &caller(&holds), &gone).is_empty());
}
