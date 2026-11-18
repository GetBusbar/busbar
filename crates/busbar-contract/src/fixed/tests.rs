// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use super::{Full, Lent, Reset, Seats, Stock, DEFAULT_NAME_CAP, DEFAULT_SPARE};

fn table(spare: usize) -> Seats<i64> {
    Seats::make([("p", 1_i64), ("q", 2_i64)], spare, 8)
}

#[test]
fn a_planned_name_is_found() {
    let mut seats = table(2);
    assert_eq!(seats.get("p"), Some(&1));
    assert_eq!(seats.get("q"), Some(&2));
    assert_eq!(seats.get("r"), None);
    *seats.claim("p").unwrap() += 10;
    assert_eq!(seats.get("p"), Some(&11));
    assert_eq!(seats.refused(), 0);
}

#[test]
fn an_unplanned_name_claims_a_spare_seat_and_is_found_again() {
    let mut seats = table(2);
    *seats.claim("new").unwrap() = 7;
    assert_eq!(seats.get("new"), Some(&7));
    assert_eq!(seats.claim("new").map(|v| *v), Ok(7));
    assert_eq!(seats.get("p"), Some(&1));
}

#[test]
fn claims_past_the_spare_count_are_refused_and_counted() {
    let mut seats = table(2);
    assert!(seats.claim("a").is_ok());
    assert!(seats.claim("b").is_ok());
    assert_eq!(seats.claim("c").err(), Some(Full::NoneLeft));
    assert_eq!(seats.claim("d").err(), Some(Full::NoneLeft));
    assert_eq!(seats.refused(), 2);
    assert_eq!(seats.get("c"), None);
    // A name that holds a seat is still answered.
    assert!(seats.claim("a").is_ok());
    assert_eq!(seats.refused(), 2);
}

#[test]
fn a_name_one_byte_over_the_buffer_is_refused() {
    let mut seats = table(2);
    assert!(seats.claim("12345678").is_ok());
    assert_eq!(seats.claim("123456789").err(), Some(Full::NameTooLong));
    assert_eq!(seats.refused(), 1);
}

#[test]
fn a_claim_allocates_nothing() {
    let mut seats = table(4);
    let table_room = seats.index.capacity();
    let seats_room = seats.seats.capacity();
    let name_room: Vec<usize> = seats.spare_names.iter().map(String::capacity).collect();
    assert!(name_room.iter().all(|room| *room >= 8));
    for name in ["a", "b", "c", "d"] {
        assert!(seats.claim(name).is_ok());
    }
    assert_eq!(seats.claim("e").err(), Some(Full::NoneLeft));
    assert_eq!(seats.index.capacity(), table_room);
    assert_eq!(seats.seats.capacity(), seats_room);
    for name in ["a", "b", "c", "d"] {
        let (key, _) = seats.index.get_key_value(name).unwrap();
        assert_eq!(key.capacity(), name_room[0]);
    }
}

#[test]
fn plan_after_make_keeps_earlier_values_and_room() {
    let mut seats = table(3);
    assert!(seats.plan("r", 5));
    assert!(!seats.plan("p", 99));
    assert_eq!(seats.get("p"), Some(&1));
    assert_eq!(seats.get("r"), Some(&5));
    let table_room = seats.index.capacity();
    for name in ["a", "b", "c"] {
        assert!(seats.claim(name).is_ok());
    }
    assert_eq!(seats.index.capacity(), table_room);
    assert_eq!(seats.claim("d").err(), Some(Full::NoneLeft));
}

#[test]
fn the_default_table_has_the_stated_spares() {
    let mut seats: Seats<u8> = Seats::default();
    let long = "x".repeat(DEFAULT_NAME_CAP);
    assert!(seats.claim(&long).is_ok());
    for at in 1..DEFAULT_SPARE {
        assert!(seats.claim(&at.to_string()).is_ok());
    }
    assert_eq!(seats.claim("past").err(), Some(Full::NoneLeft));
}

#[derive(Debug, Default)]
struct Set {
    held: Vec<u8>,
}

impl Reset for Set {
    fn reset(&mut self) {
        self.held.clear();
    }
}

fn stock(count: usize) -> Arc<Stock<Set>> {
    Arc::new(Stock::make(count, || Set {
        held: Vec::with_capacity(16),
    }))
}

#[test]
fn a_stock_gives_out_what_it_made_and_no_more() {
    let stock = stock(2);
    assert_eq!(stock.made(), 2);
    let first = stock.take().unwrap();
    let second = stock.take().unwrap();
    assert!(stock.take().is_none());
    stock.give(first);
    assert!(stock.take().is_some());
    drop(second);
}

#[test]
fn giving_back_never_grows_the_list_past_what_was_made() {
    let stock = stock(1);
    stock.give(Set::default());
    stock.give(Set::default());
    assert!(stock.take().is_some());
    assert!(stock.take().is_none());
}

#[test]
fn a_dropped_lent_set_is_reset_and_can_be_taken_again() {
    let stock = stock(1);
    {
        let mut lent = Lent::take(&stock).unwrap();
        lent.held.extend_from_slice(b"secret");
        assert!(Lent::take(&stock).is_none());
    }
    let again = Lent::take(&stock).unwrap();
    assert!(again.held.is_empty());
    assert!(again.held.capacity() >= 16);
}
