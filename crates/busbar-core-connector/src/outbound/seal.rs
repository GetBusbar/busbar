// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALED CREDENTIALS ON THE DIAL: a mark, not a filler.
//!
//! The engine never hands the transport a credential's bytes or any stand-in for them. The head
//! the transport is given says "slot k is a sealed value of N bytes, under this name" (a header
//! value, or the value of a query pair the transport appends to the request target). The
//! transport's output says "bytes `offset..offset + len` of slot k go here" (`WIRE_SEALED`), and
//! the engine writes those bytes itself, from the one buffer that holds them, straight into the
//! run it hands the socket queue. There is nothing for a transport to drop, duplicate, re-encode
//! or split. What a transport can still break is the grammar below, and the engine checks it.
//!
//! Custody: a sealed value exists in exactly one engine-owned buffer (its slot, moved out of the
//! opener's head with no copy). It is kept until every slot is covered or the stream ends, then
//! wiped in one block. It is never written to a connection the engine does not secure unless the
//! operator accepted plaintext for that destination: the app-wide acceptance does not count.
//!
//! The sealing metadata the opener writes (`busbar-sealed-fields`, `busbar-sealed-query`) is the
//! engine's own and never leaves it: [`Slots::take_from`] removes it from the head. Sent upstream
//! as request headers it leaked the credential and left a provider keyed by a query pair with no
//! key in its URL.

use std::io::{self, IoSlice, Write as _};

use busbar_contract::secure::SecureVec;

use super::records::WireSealed;

/// The refusal of a head whose sealed values would cross a connection the engine does not secure
/// and the operator did not accept plaintext for. No value, no length.
pub(crate) const SEALED_IN_CLEAR: &str = "a sealed credential is never written in the clear: this \
     connection is not secured and plaintext was not accepted for this destination";

/// The refusal of sealing metadata the engine cannot read. No value, no length.
pub(crate) const SEAL_UNREADABLE: &str =
    "the sealing metadata of this request is malformed; nothing of the request was sent";

/// Where a sealed value sits in the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    /// A header's value (`H_SEALED_PAIR`).
    Header,
    /// The value of a query pair the transport appends to the request target, in record order,
    /// before any fragment (`H_SEALED_QUERY`). The name is percent-encoded.
    Query,
}

/// What the head declares of one slot: no value bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Declared<'a> {
    /// Header or query.
    pub(crate) place: Place,
    /// The header's name, or the query pair's percent-encoded name.
    pub(crate) name: &'a str,
    /// The value's length in bytes.
    pub(crate) len: u32,
}

/// A rule of the sealed grammar the transport broke (rule L9 and the part's own shape). Every one
/// is FAULT BadRecords: nothing of the answer is written, the session ends, the plugin is charged.
/// None of them says anything about the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SealBreach {
    /// A sealed part for a stream that declared no slots.
    WrongStream,
    /// A slot the head did not declare.
    UnknownSlot,
    /// A part with no bytes.
    Empty,
    /// The part does not start where the last one for its slot ended (a gap, an overlap, a repeat,
    /// or out of order).
    OutOfOrder,
    /// The part runs past the value's end.
    PastEnd,
    /// A payload part or the stream's end mark came before every slot was covered.
    Uncovered,
}

/// A run of a sealed value that a `WIRE_SEALED` named and the grammar admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Covered {
    slot: u32,
    from: u32,
    to: u32,
}

impl Covered {
    /// How many bytes.
    pub(crate) const fn len(&self) -> u32 {
        self.to - self.from
    }
}

struct Slot {
    place: Place,
    name: String,
    value: SecureVec,
    covered: u32,
}

/// THE SEALED VALUES OF ONE REQUEST HEAD. Dropping it wipes every value.
#[derive(Default)]
pub(crate) struct Slots {
    slots: Vec<Slot>,
    /// The request's stream, once the transport opened it.
    stream: Option<u64>,
}

impl std::fmt::Debug for Slots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Slots({} sealed)", self.slots.len())
    }
}

/// Unreserved bytes and percent escapes only (RFC 3986 section 2.3 and 2.1).
fn percent_encoded(bytes: &[u8]) -> bool {
    let mut rest = bytes;
    while let Some((&b, tail)) = rest.split_first() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            rest = tail;
        } else if b == b'%' && tail.len() >= 2 && tail[..2].iter().all(u8::is_ascii_hexdigit) {
            rest = &tail[2..];
        } else {
            return false;
        }
    }
    true
}

impl Slots {
    /// Take the sealed values out of an opener's `fields`, in place.
    ///
    /// * Every `busbar-sealed-fields` field is removed; each header it names is sealed: the field
    ///   leaves `fields` and its value moves (not copied) into a slot, in the fields' own order.
    /// * Every `busbar-sealed-query` field is removed; its `name=value` becomes a query slot, in
    ///   the order written, after the header slots.
    ///
    /// What is left in `fields` is what the transport is handed as ordinary pairs.
    ///
    /// # Errors
    /// [`SEAL_UNREADABLE`] when a query pair has no `=`, is not percent-encoded, or a name is not
    /// text. `fields` is then emptied (every value wiped): nothing of the request is sent.
    pub(crate) fn take_from(fields: &mut Vec<(String, Vec<u8>)>) -> Result<Self, &'static str> {
        let has_metadata = fields.iter().any(|(name, _)| {
            busbar_contract::conn::is_sealed_fields_field(name.as_bytes())
                || busbar_contract::conn::is_sealed_query_field(name.as_bytes())
        });
        if !has_metadata {
            return Ok(Self::default());
        }
        let mut sealed_names: Vec<String> = Vec::new();
        let mut queries: Vec<SecureVec> = Vec::new();
        fields.retain_mut(|(name, value)| {
            if busbar_contract::conn::is_sealed_fields_field(name.as_bytes()) {
                sealed_names.extend(
                    String::from_utf8_lossy(value)
                        .split(',')
                        .map(|one| one.trim().to_ascii_lowercase())
                        .filter(|one| !one.is_empty()),
                );
                false
            } else if busbar_contract::conn::is_sealed_query_field(name.as_bytes()) {
                queries.push(SecureVec::from(std::mem::take(value)));
                false
            } else {
                true
            }
        });
        let mut slots = Vec::with_capacity(sealed_names.len() + queries.len());
        let mut at = 0;
        while at < fields.len() {
            let sealed = sealed_names
                .iter()
                .any(|one| fields[at].0.eq_ignore_ascii_case(one));
            if sealed {
                let (name, value) = fields.remove(at);
                slots.push(Slot {
                    place: Place::Header,
                    name,
                    value: SecureVec::from(value),
                    covered: 0,
                });
            } else {
                at += 1;
            }
        }
        for pair in queries {
            let split = pair.iter().position(|b| *b == b'=');
            let readable = split.is_some_and(|eq| {
                percent_encoded(&pair[..eq]) && percent_encoded(&pair[eq + 1..]) && eq > 0
            });
            let Some(eq) = split.filter(|_| readable) else {
                for (_, value) in fields.drain(..) {
                    drop(SecureVec::from(value));
                }
                return Err(SEAL_UNREADABLE);
            };
            // The name is unreserved bytes and escapes: text by the check above.
            let name = String::from_utf8_lossy(&pair[..eq]).into_owned();
            slots.push(Slot {
                place: Place::Query,
                name,
                value: SecureVec::from(&pair[eq + 1..]),
                covered: 0,
            });
        }
        if slots
            .iter()
            .any(|slot| u32::try_from(slot.value.len()).is_err())
        {
            return Err(SEAL_UNREADABLE);
        }
        Ok(Self {
            slots,
            stream: None,
        })
    }

    /// No value is sealed: the head goes as it always did.
    pub(crate) fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// How many slots the head declares.
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// THE PLAINTEXT RULE, checked before the head is emitted and so before any byte of it exists
    /// outside the engine. `secured` = this connection runs connection security to the target (a
    /// tunnel's own TLS to the proxy does not count). `destination_accepts_plaintext` = the route's
    /// own judged acceptance or an exact per-destination entry; never the app-wide acceptance.
    ///
    /// # Errors
    /// [`SEALED_IN_CLEAR`].
    pub(crate) fn admit(
        &self,
        secured: bool,
        destination_accepts_plaintext: bool,
    ) -> Result<(), &'static str> {
        if self.is_empty() || secured || destination_accepts_plaintext {
            Ok(())
        } else {
            Err(SEALED_IN_CLEAR)
        }
    }

    /// What the head's sealed records state, in slot order (slot k is the k-th item).
    pub(crate) fn declared(&self) -> impl Iterator<Item = Declared<'_>> {
        self.slots.iter().map(|slot| Declared {
            place: slot.place,
            name: slot.name.as_str(),
            // Checked at `take_from`.
            len: slot.value.len() as u32,
        })
    }

    /// The transport opened `stream` for this head: sealed parts must name it.
    pub(crate) fn bind(&mut self, stream: u64) {
        self.stream = Some(stream);
    }

    /// The stream the slots are bound to.
    pub(crate) const fn stream(&self) -> Option<u64> {
        self.stream
    }

    /// The bytes a covered run stands for. The caller puts the slice into the run it is building
    /// and writes the run in one write ([`queue_run`]); it never copies it anywhere else. Empty
    /// for a run that was not made by [`Self::cover`] on these slots.
    pub(crate) fn bytes(&self, covered: Covered) -> &[u8] {
        self.slots
            .get(covered.slot as usize)
            .and_then(|slot| slot.value.get(covered.from as usize..covered.to as usize))
            .unwrap_or_default()
    }

    /// A `WIRE_SEALED`: checked against the grammar, and the slot advanced. The run it names is
    /// read with [`Self::bytes`] when the answer's run is built.
    ///
    /// # Errors
    /// The rule the part breaks; the slot is not advanced.
    pub(crate) fn cover(&mut self, sealed: WireSealed) -> Result<Covered, SealBreach> {
        if self.stream != Some(sealed.stream) || self.slots.is_empty() {
            return Err(SealBreach::WrongStream);
        }
        let slot = self
            .slots
            .get_mut(sealed.slot as usize)
            .ok_or(SealBreach::UnknownSlot)?;
        if sealed.len == 0 {
            return Err(SealBreach::Empty);
        }
        if sealed.offset != slot.covered {
            return Err(SealBreach::OutOfOrder);
        }
        let end = sealed
            .offset
            .checked_add(sealed.len)
            .filter(|end| *end as usize <= slot.value.len())
            .ok_or(SealBreach::PastEnd)?;
        slot.covered = end;
        Ok(Covered {
            slot: sealed.slot,
            from: sealed.offset,
            to: end,
        })
    }

    /// Every slot is covered exactly.
    pub(crate) fn covered(&self) -> bool {
        self.slots
            .iter()
            .all(|slot| slot.covered as usize == slot.value.len())
    }

    /// Rule L9, asked when the stream's first payload part or its end mark arrives.
    ///
    /// # Errors
    /// [`SealBreach::Uncovered`].
    pub(crate) fn before_payload_or_end(&self) -> Result<(), SealBreach> {
        if self.covered() {
            Ok(())
        } else {
            Err(SealBreach::Uncovered)
        }
    }

    /// The transport answered `STREAM_BUSY`, or the request is sent again on a fresh dial: nothing
    /// of the head was kept by the transport, so the same slots are declared again from their
    /// start. The values never left the engine.
    pub(crate) fn rewind(&mut self) {
        self.stream = None;
        for slot in &mut self.slots {
            slot.covered = 0;
        }
    }

    /// Every slot is covered, or the stream ended: the values are wiped now, in one block each,
    /// and their memory given back.
    pub(crate) fn wipe(&mut self) {
        self.slots.clear();
        self.slots.shrink_to_fit();
        self.stream = None;
    }
}

/// QUEUE ONE RUN FOR THE SOCKET: the parts of a run (the transport's bytes and the engine's sealed
/// values between them) handed over in order, in one write.
///
/// In the clear the pieces are appended to `out`. Under TLS they go to the cipher in one vectored
/// write, so the parts are encrypted together and a sealed value never gets a record of its own
/// (a record's size would state the value's length); the records are then drained into `out`.
/// The sealed value is copied once: from its slot into `out`, or into the cipher.
///
/// # Errors
/// The cipher's or the buffer's refusal. On an error the caller fails the connection, which
/// clears `out`.
pub(crate) fn queue_run(
    tls: Option<&mut rustls::ClientConnection>,
    out: &mut SecureVec,
    run: &[&[u8]],
) -> io::Result<()> {
    let Some(tls) = tls else {
        for piece in run {
            out.extend(piece)
                .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "write buffer"))?;
        }
        return Ok(());
    };
    let (mut at, mut skip) = (0_usize, 0_usize);
    loop {
        while at < run.len() && run[at].len() == skip {
            at += 1;
            skip = 0;
        }
        if at == run.len() {
            break;
        }
        let mut slices: smallvec::SmallVec<[IoSlice<'_>; 8]> = smallvec::SmallVec::new();
        slices.push(IoSlice::new(&run[at][skip..]));
        slices.extend(run[at + 1..].iter().map(|piece| IoSlice::new(piece)));
        let mut taken = tls.writer().write_vectored(&slices)?;
        if taken == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "the cipher took no bytes",
            ));
        }
        while taken > 0 {
            let have = run[at].len() - skip;
            if taken >= have {
                taken -= have;
                at += 1;
                skip = 0;
            } else {
                skip += taken;
                taken = 0;
            }
        }
    }
    while tls.wants_write() {
        tls.write_tls(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"sk-live-0123456789abcdef";

    fn sealed(stream: u64, slot: u32, offset: u32, len: u32) -> WireSealed {
        WireSealed {
            stream,
            slot,
            offset,
            len,
            _r: 0,
        }
    }

    fn head() -> Vec<(String, Vec<u8>)> {
        vec![
            ("content-type".to_owned(), b"application/json".to_vec()),
            ("x-api-key".to_owned(), KEY.to_vec()),
            ("busbar-sealed-fields".to_owned(), b"X-Api-Key".to_vec()),
            ("accept".to_owned(), b"*/*".to_vec()),
        ]
    }

    #[test]
    fn a_head_with_no_metadata_seals_nothing_and_is_untouched() {
        let mut fields = vec![("accept".to_owned(), b"*/*".to_vec())];
        let slots = Slots::take_from(&mut fields).unwrap();
        assert!(slots.is_empty());
        assert_eq!(fields.len(), 1);
        assert!(slots.admit(false, false).is_ok());
    }

    #[test]
    fn the_sealed_header_and_the_metadata_leave_the_fields() {
        let mut fields = head();
        let slots = Slots::take_from(&mut fields).unwrap();
        let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["content-type", "accept"]);
        assert!(
            fields
                .iter()
                .all(|(_, value)| !value.windows(KEY.len()).any(|w| w == KEY)),
            "no field the transport is handed holds the credential"
        );
        let declared: Vec<Declared<'_>> = slots.declared().collect();
        assert_eq!(
            declared,
            [Declared {
                place: Place::Header,
                name: "x-api-key",
                len: KEY.len() as u32
            }]
        );
    }

    #[test]
    fn a_query_pair_becomes_a_query_slot_and_never_a_header() {
        let mut fields = vec![
            ("accept".to_owned(), b"*/*".to_vec()),
            (
                "busbar-sealed-query".to_owned(),
                b"key=AIza%2Fsecret".to_vec(),
            ),
        ];
        let slots = Slots::take_from(&mut fields).unwrap();
        assert_eq!(fields.len(), 1, "the metadata is not sent upstream");
        let declared: Vec<Declared<'_>> = slots.declared().collect();
        assert_eq!(
            declared,
            [Declared {
                place: Place::Query,
                name: "key",
                len: 14
            }]
        );
    }

    #[test]
    fn header_slots_come_first_then_query_slots_in_the_order_written() {
        let mut fields = vec![
            ("busbar-sealed-query".to_owned(), b"a=1".to_vec()),
            ("authorization".to_owned(), b"Bearer t".to_vec()),
            ("busbar-sealed-query".to_owned(), b"b=22".to_vec()),
            ("busbar-sealed-fields".to_owned(), b"authorization".to_vec()),
        ];
        let slots = Slots::take_from(&mut fields).unwrap();
        assert!(fields.is_empty());
        let order: Vec<(Place, &str, u32)> = slots
            .declared()
            .map(|one| (one.place, one.name, one.len))
            .collect();
        assert_eq!(
            order,
            [
                (Place::Header, "authorization", 8),
                (Place::Query, "a", 1),
                (Place::Query, "b", 2)
            ]
        );
    }

    #[test]
    fn a_malformed_query_pair_sends_nothing() {
        for bad in [&b"novalue"[..], b"=v", b"na me=v", b"k=v v", b"k=%zz"] {
            let mut fields = vec![
                ("x-api-key".to_owned(), KEY.to_vec()),
                ("busbar-sealed-query".to_owned(), bad.to_vec()),
            ];
            assert_eq!(
                Slots::take_from(&mut fields).err(),
                Some(SEAL_UNREADABLE),
                "{}",
                String::from_utf8_lossy(bad)
            );
            assert!(fields.is_empty(), "every value is wiped with the refusal");
        }
    }

    #[test]
    fn plaintext_needs_the_destinations_own_acceptance() {
        let mut fields = head();
        let slots = Slots::take_from(&mut fields).unwrap();
        assert_eq!(slots.admit(false, false), Err(SEALED_IN_CLEAR));
        assert!(slots.admit(true, false).is_ok());
        assert!(slots.admit(false, true).is_ok());
        assert!(!SEALED_IN_CLEAR.contains("sk-live"));
    }

    #[test]
    fn a_slot_is_covered_in_order_and_exactly() {
        let mut fields = head();
        let mut slots = Slots::take_from(&mut fields).unwrap();
        slots.bind(5);
        assert_eq!(slots.before_payload_or_end(), Err(SealBreach::Uncovered));
        // Split across a frame boundary: two parts.
        let first = slots.cover(sealed(5, 0, 0, 10)).unwrap();
        assert_eq!(slots.bytes(first), &KEY[..10]);
        assert!(!slots.covered());
        let second = slots.cover(sealed(5, 0, 10, 14)).unwrap();
        assert_eq!(slots.bytes(second), &KEY[10..]);
        assert!(slots.covered());
        assert!(slots.before_payload_or_end().is_ok());
    }

    #[test]
    fn each_breach_of_the_grammar_is_refused_and_moves_nothing() {
        let mut fields = head();
        let mut slots = Slots::take_from(&mut fields).unwrap();
        assert_eq!(
            slots.cover(sealed(5, 0, 0, 4)).err(),
            Some(SealBreach::WrongStream),
            "not bound yet"
        );
        slots.bind(5);
        assert_eq!(
            slots.cover(sealed(7, 0, 0, 4)).err(),
            Some(SealBreach::WrongStream)
        );
        assert_eq!(
            slots.cover(sealed(5, 1, 0, 4)).err(),
            Some(SealBreach::UnknownSlot)
        );
        assert_eq!(
            slots.cover(sealed(5, 0, 0, 0)).err(),
            Some(SealBreach::Empty)
        );
        assert_eq!(
            slots.cover(sealed(5, 0, 4, 4)).err(),
            Some(SealBreach::OutOfOrder),
            "a gap"
        );
        assert_eq!(
            slots.cover(sealed(5, 0, 0, 25)).err(),
            Some(SealBreach::PastEnd)
        );
        assert_eq!(
            slots.cover(sealed(5, 0, 0, u32::MAX)).err(),
            Some(SealBreach::PastEnd)
        );
        slots.cover(sealed(5, 0, 0, 24)).unwrap();
        assert_eq!(
            slots.cover(sealed(5, 0, 0, 24)).err(),
            Some(SealBreach::OutOfOrder),
            "a repeat would write the credential twice"
        );
    }

    #[test]
    fn busy_rewinds_the_same_slots_for_another_connection() {
        let mut fields = head();
        let mut slots = Slots::take_from(&mut fields).unwrap();
        slots.bind(5);
        slots.cover(sealed(5, 0, 0, 24)).unwrap();
        slots.rewind();
        assert_eq!(slots.stream(), None);
        slots.bind(9);
        let again = slots.cover(sealed(9, 0, 0, 24)).unwrap();
        assert_eq!(slots.bytes(again), KEY);
    }

    #[test]
    fn wipe_leaves_no_slot() {
        let mut fields = head();
        let mut slots = Slots::take_from(&mut fields).unwrap();
        slots.bind(5);
        slots.wipe();
        assert!(slots.is_empty());
        assert_eq!(
            slots.cover(sealed(5, 0, 0, 1)).err(),
            Some(SealBreach::WrongStream)
        );
    }

    #[test]
    fn a_run_in_the_clear_is_the_parts_and_the_value_in_order_once() {
        let mut fields = head();
        let mut slots = Slots::take_from(&mut fields).unwrap();
        slots.bind(1);
        let mut out = SecureVec::new();
        let covered = slots.cover(sealed(1, 0, 0, 24)).unwrap();
        let value = slots.bytes(covered);
        queue_run(None, &mut out, &[b"x-api-key: ", value, b"\r\n\r\n"]).unwrap();
        let mut wire = b"x-api-key: ".to_vec();
        wire.extend_from_slice(KEY);
        wire.extend_from_slice(b"\r\n\r\n");
        assert_eq!(out.as_slice(), wire.as_slice());
    }

    #[test]
    fn the_debug_form_states_a_count_and_nothing_else() {
        let mut fields = head();
        let slots = Slots::take_from(&mut fields).unwrap();
        assert_eq!(format!("{slots:?}"), "Slots(1 sealed)");
    }
}
