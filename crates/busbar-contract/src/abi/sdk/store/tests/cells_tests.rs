// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The R0 cell codec (MIGRATE-ON-BOOT §A4): byte-identical to the MIN-3 `CellRec` records, and
//! every malformed run refused.

use super::*;

/// One INT cell: the record head (CELL, 0, len 16), the cell head (INT, 0), the i64 LE; no pad.
#[test]
fn one_int_cell_is_the_min3_cell_record_byte_for_byte() {
    let bytes = value(&[Cell::Int(-2)]);
    let mut want = Vec::new();
    want.extend_from_slice(&0x0123u16.to_le_bytes());
    want.extend_from_slice(&0u16.to_le_bytes());
    want.extend_from_slice(&16u32.to_le_bytes());
    want.extend_from_slice(&CELL_INT.to_le_bytes());
    want.extend_from_slice(&0u32.to_le_bytes());
    want.extend_from_slice(&(-2i64).to_le_bytes());
    assert_eq!(bytes, want);
}

/// Text is padded with zeros to the next multiple of 8; NULL has no tail.
#[test]
fn text_is_zero_padded_and_null_has_no_tail() {
    let bytes = value(&[Cell::Text("abc"), Cell::Null]);
    assert_eq!(bytes.len(), 8 + 8 + 3 + 5 + 8 + 8);
    assert_eq!(&bytes[16..19], b"abc");
    assert_eq!(&bytes[19..24], &[0; 5]);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 11);
}

#[test]
fn every_kind_round_trips() {
    let cells = [
        Cell::Null,
        Cell::Int(i64::MIN),
        Cell::Int(i64::MAX),
        Cell::Real((-0.0f64).to_bits()),
        Cell::Text(""),
        Cell::Text("v1:plain:secret"),
        Cell::Blob(&[0, 255, 7]),
        Cell::Blob(&[]),
    ];
    assert_eq!(decode(&value(&cells)).unwrap(), cells);
    assert!(decode(&[]).unwrap().is_empty());
    let k = key(table::USAGE, &[Cell::Text("b1"), Cell::Int(60)]);
    assert_eq!(tag_of(&k), Some(table::USAGE));
    assert_eq!(decode(&k[1..]).unwrap(), [Cell::Text("b1"), Cell::Int(60)]);
}

/// A run that is not well-formed cells is refused, never read in part.
#[test]
fn malformed_runs_are_refused() {
    let good = value(&[Cell::Text("abc")]);
    let mut wrong_tag = good.clone();
    wrong_tag[0] = 0x24;
    let mut reserved = good.clone();
    reserved[2] = 1;
    let mut cell_reserved = good.clone();
    cell_reserved[12] = 1;
    let mut padding = good.clone();
    padding[20] = 1;
    let mut kind = good.clone();
    kind[8] = 9;
    let mut not_utf8 = good.clone();
    not_utf8[16] = 0xff;
    let mut int_short = value(&[Cell::Int(1)]);
    int_short[4] = 12;
    for bad in [
        wrong_tag,
        reserved,
        cell_reserved,
        padding,
        kind,
        not_utf8,
        int_short,
        good[..good.len() - 1].to_vec(),
        [good.as_slice(), &[0]].concat(),
    ] {
        assert_eq!(decode(&bad), Err(Malformed));
    }
}

/// A credential's cells never print.
#[test]
fn cells_never_print_their_text() {
    let text = format!("{:?}", [Cell::Text("v1:plain:secret"), Cell::Blob(b"k")]);
    assert!(!text.contains("secret") && !text.contains('k'), "{text}");
}

/// The SUMMARY row's width, and the import namespace is the reserved one.
#[test]
fn the_summary_width_and_the_import_namespace() {
    assert_eq!(SUMMARY_CELLS, 26);
    assert_eq!(IMPORT_NS.0, *b"busbar.import.r0");
}
