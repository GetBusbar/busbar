// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The contract's method table as data, and the check of one crossing against it.
//!
//! One row per method of every kind: its table slot, how it is called, the bytes of its head, how many
//! texts and how many blobs it carries. The kind faces (`call::kinds`) are written to this table by hand;
//! this module lets the crossing recorder hold every real call to it, so a face that drifts from the
//! table is named at the crossing (kind, method, which part, what was sent, what the table says) and
//! not found later as a plugin's fault on a call it could not read.

use busbar_plugin_abi::types::KindCode;

use super::record::Seen;

/// How a method is called.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// A plain call: no session.
    Plain,
    /// Opens a session: called with none.
    Opens,
    /// Called on a live session.
    OnSession,
    /// Ends a live session.
    Ends,
    /// Starts an async chain: called with none.
    Start,
}

/// One row of the method table.
#[derive(Clone, Copy, Debug)]
pub struct Method {
    pub kind: KindCode,
    pub slot: u8,
    pub name: &'static str,
    pub role: Role,
    /// The bytes of the method's head record.
    pub head: usize,
    pub texts: usize,
    /// The fewest and the most blobs the method carries (equal for every method but `emit`, whose
    /// blobs are one per byte-carrying piece in the call).
    pub blobs: (usize, usize),
}

const fn row(
    kind: KindCode,
    slot: u8,
    name: &'static str,
    role: Role,
    head: usize,
    texts: usize,
    blobs: (usize, usize),
) -> Method {
    Method {
        kind,
        slot,
        name,
        role,
        head,
        texts,
        blobs,
    }
}

use KindCode::{Auth, Export, Hook, Plane, Secret, Store, Transport};
use Role::{Ends, OnSession, Opens, Plain, Start};

/// The 35 methods, in the contract's order.
pub const TABLE: [Method; 35] = [
    row(Store, 0, "read", Start, 0, 0, (1, 1)),
    row(Store, 1, "scan", Start, 0, 0, (1, 1)),
    row(Store, 2, "commit", Start, 0, 0, (1, 1)),
    row(Store, 3, "clock", Start, 0, 0, (1, 1)),
    row(Store, 4, "info", Plain, 0, 0, (0, 0)),
    row(Secret, 0, "resolve", Start, 0, 0, (1, 1)),
    row(Auth, 0, "verify", Plain, 16, 5, (4, 4)),
    row(Auth, 1, "verify_io", Start, 0, 0, (1, 1)),
    row(Auth, 2, "login", Start, 4, 0, (1, 1)),
    row(Auth, 3, "outbound", Start, 0, 0, (1, 1)),
    row(Auth, 4, "refresh", Start, 0, 0, (0, 0)),
    row(Auth, 5, "serve", Start, 0, 0, (1, 1)),
    row(Hook, 0, "on", Plain, 4, 0, (1, 1)),
    row(Hook, 1, "on_io", Start, 4, 0, (1, 1)),
    row(Export, 0, "deliver", Start, 24, 0, (1, 1)),
    row(Export, 1, "render", Plain, 4, 0, (1, 1)),
    row(Export, 2, "confirm", Start, 8, 0, (0, 0)),
    row(Plane, 0, "request", Opens, 32, 4, (4, 4)),
    row(Plane, 1, "upstream", OnSession, 8, 5, (2, 2)),
    row(Plane, 2, "piece", OnSession, 12, 0, (1, 1)),
    row(Plane, 3, "end", Ends, 0, 0, (0, 0)),
    row(Plane, 4, "rewrite", OnSession, 0, 0, (1, 1)),
    row(Plane, 5, "render", Plain, 36, 4, (4, 4)),
    row(Plane, 6, "admin", Start, 4, 0, (1, 1)),
    row(Plane, 7, "probe", Opens, 8, 5, (2, 2)),
    row(Plane, 8, "demux", Plain, 0, 1, (1, 1)),
    row(Plane, 9, "select_resources", Plain, 40, 4, (4, 4)),
    row(Plane, 10, "channel", OnSession, 8, 5, (2, 2)),
    row(Transport, 0, "begin", Opens, 16, 5, (3, 3)),
    row(Transport, 1, "ingest", OnSession, 0, 0, (1, 1)),
    row(Transport, 2, "emit", OnSession, 24, 0, (0, 4)),
    row(Transport, 3, "timer", OnSession, 0, 0, (0, 0)),
    row(Transport, 4, "datagram", OnSession, 8, 0, (1, 1)),
    row(Transport, 5, "event", OnSession, 4, 0, (1, 1)),
    row(Transport, 6, "offer", Plain, 4, 0, (0, 0)),
];

/// The row of `kind`'s table slot `slot`.
pub fn method(kind: KindCode, slot: u8) -> Option<&'static Method> {
    TABLE
        .iter()
        .find(|method| method.kind == kind && method.slot == slot)
}

/// The session bit of a token.
const SESSION: u64 = 1 << 63;

/// Why a crossing is not the call its row states.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Drift {
    pub kind: KindCode,
    pub slot: u8,
    /// The method's name, or `unknown` for a slot with no row.
    pub name: &'static str,
    /// Which part differs and how.
    pub what: String,
}

impl core::fmt::Display for Drift {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {} (slot {}): {}",
            self.kind.word(),
            self.name,
            self.slot,
            self.what
        )
    }
}

/// Hold one crossing to its row: the slot exists, the session is present exactly when the role has
/// one, the head is the stated bytes, the texts and blobs are the stated counts.
pub fn check(kind: KindCode, slot: u8, seen: &Seen<'_>) -> Result<(), Drift> {
    let drift = |name: &'static str, what: String| Drift {
        kind,
        slot,
        name,
        what,
    };
    let Some(row) = method(kind, slot) else {
        return Err(drift(
            "unknown",
            "the engine called a slot the method table does not have".to_string(),
        ));
    };
    let on_session = matches!(row.role, OnSession | Ends);
    if on_session && seen.session & SESSION == 0 {
        return Err(drift(
            row.name,
            "called with no session token; the method runs on a session".to_string(),
        ));
    }
    if !on_session && seen.session != 0 {
        return Err(drift(
            row.name,
            "called with a session token; the method takes none".to_string(),
        ));
    }
    if seen.head.len() != row.head {
        return Err(drift(
            row.name,
            format!(
                "the head is {} bytes; the table says {}",
                seen.head.len(),
                row.head
            ),
        ));
    }
    if seen.texts.len() != row.texts {
        return Err(drift(
            row.name,
            format!("{} texts; the table says {}", seen.texts.len(), row.texts),
        ));
    }
    let (fewest, most) = row.blobs;
    if seen.blobs.len() < fewest || seen.blobs.len() > most {
        return Err(drift(
            row.name,
            if fewest == most {
                format!("{} blobs; the table says {fewest}", seen.blobs.len())
            } else {
                format!(
                    "{} blobs; the table says {fewest} to {most}",
                    seen.blobs.len()
                )
            },
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::frame::{Frame, Mono};
    use crate::call::kinds;

    #[test]
    fn every_kind_has_its_methods_in_slot_order_with_no_gap() {
        for kind in KindCode::ALL {
            let slots: Vec<u8> = TABLE
                .iter()
                .filter(|method| method.kind == kind)
                .map(|method| method.slot)
                .collect();
            let want: Vec<u8> = (0..slots.len() as u8).collect();
            assert_eq!(slots, want, "{}", kind.word());
        }
        let count = |kind| TABLE.iter().filter(|method| method.kind == kind).count();
        assert_eq!(
            [
                count(Store),
                count(Secret),
                count(Auth),
                count(Hook),
                count(Export),
                count(Plane),
                count(Transport)
            ],
            [5, 1, 6, 2, 3, 11, 7]
        );
    }

    #[test]
    fn the_rows_state_the_head_records_the_faces_send() {
        let head = |kind, slot: u8| method(kind, slot).unwrap().head;
        assert_eq!(
            head(Auth, kinds::auth::VERIFY),
            size_of::<kinds::auth::VerifyHead>()
        );
        assert_eq!(
            head(Auth, kinds::auth::LOGIN),
            size_of::<kinds::auth::LoginHead>()
        );
        assert_eq!(
            head(Hook, kinds::hook::ON),
            size_of::<kinds::hook::PointHead>()
        );
        assert_eq!(
            head(Hook, kinds::hook::ON_IO),
            size_of::<kinds::hook::PointHead>()
        );
        assert_eq!(
            head(Export, kinds::export::DELIVER),
            size_of::<kinds::export::DeliverHead>()
        );
        assert_eq!(
            head(Export, kinds::export::RENDER),
            size_of::<kinds::export::ScopeHead>()
        );
        assert_eq!(
            head(Export, kinds::export::CONFIRM),
            size_of::<kinds::export::ConfirmHead>()
        );
        assert_eq!(
            head(Plane, kinds::plane::REQUEST),
            size_of::<kinds::plane::RequestHead>()
        );
        assert_eq!(
            head(Plane, kinds::plane::RENDER),
            kinds::plane::RENDER_HEAD_LEN
        );
        assert_eq!(
            head(Plane, kinds::plane::SELECT_RESOURCES),
            size_of::<kinds::plane::SelectHead>()
        );
        for slot in [
            kinds::plane::UPSTREAM,
            kinds::plane::PROBE,
            kinds::plane::CHANNEL,
        ] {
            assert_eq!(head(Plane, slot), size_of::<kinds::plane::TargetHead>());
        }
        assert_eq!(
            head(Plane, kinds::plane::PIECE),
            size_of::<kinds::plane::PieceHead>()
        );
        assert_eq!(
            head(Plane, kinds::plane::ADMIN),
            size_of::<kinds::plane::AdminHead>()
        );
        assert_eq!(
            head(Transport, kinds::transport::BEGIN),
            size_of::<kinds::transport::BeginHead>()
        );
        assert_eq!(
            head(Transport, kinds::transport::EMIT),
            size_of::<kinds::transport::EmitHead>()
        );
        assert_eq!(
            head(Transport, kinds::transport::DATAGRAM),
            size_of::<kinds::transport::DatagramHead>()
        );
        assert_eq!(
            head(Transport, kinds::transport::EVENT),
            size_of::<kinds::transport::EventHead>()
        );
        assert_eq!(
            head(Transport, kinds::transport::OFFER),
            size_of::<kinds::transport::OfferHead>()
        );
    }

    #[test]
    fn a_call_that_matches_its_row_passes_and_each_drift_is_named() {
        let piece = kinds::plane::PieceHead {
            from: 1,
            exchange: 2,
            flags: 0,
        };
        let frame = Frame::new(piece, [], [b"body".as_slice()]);
        let call = frame.call(Mono::NONE);
        let on_session = Seen::of(SESSION | 7, &call, &[]);
        assert_eq!(check(Plane, kinds::plane::PIECE, &on_session), Ok(()));

        let no_session = Seen::of(0, &call, &[]);
        let drift = check(Plane, kinds::plane::PIECE, &no_session).unwrap_err();
        assert_eq!(
            drift.to_string(),
            "plane piece (slot 2): called with no session token; the method runs on a session"
        );

        let two = Frame::new(piece, [], [b"a".as_slice(), b"b".as_slice()]);
        let call = two.call(Mono::NONE);
        let drift = check(
            Plane,
            kinds::plane::PIECE,
            &Seen::of(SESSION | 7, &call, &[]),
        )
        .unwrap_err();
        assert_eq!(drift.what, "2 blobs; the table says 1");

        let short = Frame::new(piece, [], [b"a".as_slice()]).known(8, 0, 1);
        let call = short.call(Mono::NONE);
        let drift = check(
            Plane,
            kinds::plane::PIECE,
            &Seen::of(SESSION | 7, &call, &[]),
        )
        .unwrap_err();
        assert_eq!(drift.what, "the head is 8 bytes; the table says 12");

        let drift = check(Secret, 3, &Seen::of(0, &call, &[])).unwrap_err();
        assert_eq!(drift.name, "unknown");
    }

    #[test]
    fn emit_carries_one_blob_per_byte_carrying_piece() {
        let head = kinds::transport::EmitHead {
            stream: 1,
            pieces: 0,
            arg: 0,
            credit: 0,
        };
        for n in 0..=4usize {
            let frame = Frame::new(head, [], [b"".as_slice(); 4]).known(24, 0, n);
            let call = frame.call(Mono::NONE);
            assert_eq!(
                check(
                    Transport,
                    kinds::transport::EMIT,
                    &Seen::of(SESSION | 1, &call, &[])
                ),
                Ok(())
            );
        }
    }
}
