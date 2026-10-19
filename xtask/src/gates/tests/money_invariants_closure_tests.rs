//! Q128 section 11: the journalled-record closure is closed. A field type the closure cannot read
//! is a refusal, a type reached through a `pub use` re-export is read where it is defined, and a
//! writer's `crate::` import resolves in the writer's own crate.

use super::*;
use crate::ledger::Status;

fn stored_price_row(ov: Overlay) -> Row {
    let cx = Ctx::workspace().expect("the workspace opens");
    MoneyInvariantsGate
        .run(&cx.with_overlay(ov))
        .rows
        .into_iter()
        .find(|r| r.id == ROW_NO_STORED_PRICE)
        .expect("the gate emits its stored-price row")
}

/// The file at `path` with `from` replaced by `to`, refusing a plant that would plant nothing.
fn planted(path: &str, from: &str, to: &str) -> Overlay {
    let cx = Ctx::workspace().expect("the workspace opens");
    let text = cx.read(path).expect("the planted file reads");
    assert!(
        text.contains(from),
        "{path} no longer spells `{from}`: the plant would plant nothing"
    );
    let mut ov = Overlay::new();
    ov.set(path, text.replacen(from, to, 1));
    ov
}

fn assert_red_naming(row: &Row, needle: &str) {
    assert_eq!(
        row.status,
        Status::Fail,
        "{} must be RED over the plant: {}",
        row.id,
        row.detail
    );
    assert!(
        row.detail.contains(needle),
        "{} must name `{needle}`: {}",
        row.id,
        row.detail
    );
}

/// `AuditRecord.usage: Usage` holds `lines: Vec<UsageLine>`, and `busbar-kernel-audit` only
/// re-exports `UsageLine` from `busbar-contract`. The audit record is journalled whole, so a price
/// on `UsageLine` is a stored price.
#[test]
fn q128_11_a_stored_price_on_the_reexported_usage_line_is_named() {
    let ov = planted(
        "crates/busbar-contract/src/caps/usage.rs",
        "pub struct UsageLine {",
        "pub struct UsageLine {\n    pub price: u64,",
    );
    assert_red_naming(&stored_price_row(ov), "`price` on UsageLine");
}

/// A field type word the closure cannot resolve to one definition is a gap the row refuses on, not
/// a word it steps over.
#[test]
fn q128_11_a_field_type_the_closure_cannot_read_is_a_refusal() {
    let ov = planted(
        "crates/busbar-kernel-audit/src/record.rs",
        "pub struct Usage {",
        "pub struct Usage {\n    pub planted: PlantedUnheardOf,",
    );
    assert_red_naming(&stored_price_row(ov), "PlantedUnheardOf");
}

/// A journal writer outside `crates/busbar` importing its record through `crate::` reads the record
/// in its own crate, not in `crates/busbar/src`.
#[test]
fn q128_11_a_writers_crate_import_resolves_in_its_own_crate() {
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-kernel-audit/src/planted_record.rs",
        "pub struct PlantedRecord {\n    pub price: u64,\n}\n",
    );
    ov.set(
        "crates/busbar-kernel-audit/src/planted_writer.rs",
        "use crate::planted_record::PlantedRecord;\n\n\
         pub fn planted_body(record: &PlantedRecord) -> u64 {\n    \
         let _ = Entry::new(RecordClass::Transaction, record.price);\n    0\n}\n",
    );
    assert_red_naming(&stored_price_row(ov), "`price` on PlantedRecord");
}
