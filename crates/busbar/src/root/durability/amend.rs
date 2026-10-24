// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE AMENDMENT JOURNAL, BOUND TO THE ONE CHAIN.
//!
//! The node keeps one amendment journal (`busbar_kernel_audit::NodeAmendments`, the instance its
//! governance owns and every `App` generation carries): every hook or export handed content leaves
//! an access on it, and every root correction of a unit's counts an adjustment. Held in memory
//! only, a restart dropped every one — a corrected count read as recorded again, and money with it.
//!
//! So each amendment goes on the node's journal as it is sealed — an access as an `Access` record,
//! an adjustment as a `Transaction` record (the classes the journal unit names for them) — carrying
//! every field its digest covers, and a boot rebuilds the node journal from the chain before
//! anything can seal onto it, whenever the chain has a durable source: a data directory, or the
//! configured store the chain was resumed from. A node with neither journals and rebuilds nothing.
//!
//! A private child module of `durability`, as `replay` is; the parent re-exports the two items that
//! are part of its public surface.

use super::*;
use busbar_kernel_audit::amend::{
    self as amend, Access, Adjust, AmendBody, AmendClass, AmendSink, Amendment, ClassCounts,
    NodeAmendments, Reader,
};
use busbar_kernel_audit::record::OpClassId;
use std::sync::{Arc, Mutex, Weak};

/// THE NODE'S HELD AMENDMENT RUN (`journal`, the one its `App` carries), verified as it stands
/// now — what `GET /admin/verify` reports. The boot restore verifies what it reads back; this sees
/// an edit made after boot.
///
/// # Errors
///
/// The held run does not verify; the break, rendered.
#[cfg(feature = "root-admin")]
pub(crate) fn verify_held(journal: &NodeAmendments) -> Result<(), String> {
    journal.verify().map_err(|broken| broken.to_string())
}

/// The first field of every amendment record: names the shape, so no other record on the chain is
/// read as one.
const AMENDMENT: &str = "amend.v1";

/// The journal record one amendment is written as.
fn entry(amendment: &Amendment) -> Entry {
    let (class, wall) = match &amendment.body {
        AmendBody::Access(a) => (RecordClass::Access, a.wall),
        AmendBody::Adjust(a) => (RecordClass::Transaction, a.wall),
    };
    Entry::new(class, body(amendment)).at(wall, 0)
}

/// Every field the amendment's digest covers, plus the digest itself, in digest order.
fn body(amendment: &Amendment) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.text(AMENDMENT)
        .num(amendment.seq)
        .text(&amendment.prev_hash)
        .text(&amendment.hash)
        .text(amendment.class().as_str());
    let subject = |body: &mut BodyWriter, s| {
        let (tag, value) = amend::subject_fields(s);
        body.text(tag).text(&value);
    };
    match &amendment.body {
        AmendBody::Access(a) => {
            body.text(a.reader.as_str()).text(&a.name);
            subject(&mut body, &a.subject);
            body.text(a.op_class.as_str()).num(a.fields.len() as u64);
            for field in &a.fields {
                body.text(field);
            }
            body.num(a.wall);
        }
        AmendBody::Adjust(a) => {
            body.text(&a.amends_hash);
            subject(&mut body, &a.subject);
            body.text(&a.lane).num(a.card_epoch_ms);
            for side in [&a.was, &a.now] {
                body.num(side.len() as u64);
                for (class, count) in side {
                    body.text(class).text(&count.to_decimal_string());
                }
            }
            body.text(&a.authorised_by).text(&a.reason).num(a.wall);
            // Q64/Q67: the pool, LAST and only when named — an unscoped adjustment's record is
            // byte-for-byte the one written before the field existed.
            if let Some(pool) = &a.pool {
                body.text(pool);
            }
        }
    }
    body.finish()
}

/// The amendment a record written by [`entry`] carries, or `None` for any other record.
fn from_record(record: &JournalRecord) -> Option<Amendment> {
    let mut body = BodyReader::new(&record.body);
    if body.text()? != AMENDMENT {
        return None;
    }
    let (seq, prev_hash, hash) = (body.num()?, body.text()?, body.text()?);
    let subject = |body: &mut BodyReader<'_>| {
        let (tag, value) = (body.text()?, body.text()?);
        amend::subject_from_fields(tag, value)
    };
    let amendment = match AmendClass::parse(body.text()?)? {
        AmendClass::Access => {
            let (reader, name) = (Reader::parse(body.text()?)?, body.text()?.to_string());
            let subject = subject(&mut body)?;
            let op_class = OpClassId::new(body.text()?);
            let fields = (0..body.num()?)
                .map(|_| body.text().map(str::to_string))
                .collect::<Option<Vec<_>>>()?;
            AmendBody::Access(Access {
                reader,
                name,
                subject,
                op_class,
                fields,
                wall: body.num()?,
            })
        }
        AmendClass::Adjust => {
            let amends_hash = body.text()?.to_string();
            let subject = subject(&mut body)?;
            let (lane, card_epoch_ms) = (body.text()?.to_string(), body.num()?);
            let mut side = || -> Option<ClassCounts> {
                (0..body.num()?)
                    .map(|_| {
                        let class = body.text()?.to_string();
                        Some((
                            class,
                            busbar_contract::count::Count::parse(body.text()?).ok()?,
                        ))
                    })
                    .collect()
            };
            let (was, now) = (side()?, side()?);
            AmendBody::Adjust(Adjust {
                amends_hash,
                subject,
                lane,
                card_epoch_ms,
                was,
                now,
                authorised_by: body.text()?.to_string(),
                reason: body.text()?.to_string(),
                wall: body.num()?,
                // Absent on a record written before Q64/Q67: that adjustment reads UNSCOPED.
                pool: body.text().map(str::to_string),
            })
        }
    };
    let expected = match &amendment {
        AmendBody::Access(_) => RecordClass::Access,
        AmendBody::Adjust(_) => RecordClass::Transaction,
    };
    (record.class == expected).then(|| Amendment {
        seq,
        body: amendment,
        prev_hash: prev_hash.to_string(),
        hash: hash.to_string(),
    })
}

/// THE CHAIN THE RECORDS HOLD, walked from the genesis: each amendment is kept only where it links
/// to the one kept before it, at the next position, and its fields reproduce its digest. Answers the
/// run and how many amendment records were set aside — a record a crash tore, or one a predecessor
/// sealed on a chain it could not rebuild, is not silently spliced into the history.
fn linked_run(records: &[JournalRecord]) -> (Vec<Amendment>, usize) {
    let (mut run, mut set_aside) = (Vec::<Amendment>::new(), 0);
    for amendment in records.iter().filter_map(from_record) {
        let (prev, next) = run.last().map_or((String::new(), 1), |a| {
            (a.hash.clone(), a.seq.saturating_add(1))
        });
        let digest = amend::AmendChain::digest_of(&amendment);
        if amendment.prev_hash == prev && amendment.seq == next && digest == amendment.hash {
            run.push(amendment);
        } else {
            set_aside += 1;
        }
    }
    (run, set_aside)
}

impl Durability {
    /// **THE BOOT'S REBUILD OF THE NODE AMENDMENT JOURNAL** `journal` (the node's one, which its
    /// `App` carries), before anything can seal onto it: it becomes exactly the run this book's
    /// chain holds, so a count a root correction amended reads as corrected after a restart, and so
    /// does its money. It runs whenever the chain has a durable source
    /// ([`Durability::keeps_chain`]): a disk, or the configured store the chain was resumed from. A
    /// book with neither rebuilds nothing.
    ///
    /// An amendment record the walk cannot link is REPORTED on
    /// [`Durability::restart_findings`], never spliced in. Once rebuilt, the book is the one
    /// [`bind_amendments`] binds.
    ///
    /// # Errors
    ///
    /// The chain could not be read back. The boot refuses then, as it refuses a store that would
    /// not read the chain back the first time: taken for an empty chain, the failed read rebuilt no
    /// amendment, so every signed count correction reverted for the life of the process and none
    /// sealed afterwards was journalled (audit R1#3).
    pub fn restore_amendments(
        &mut self,
        journal: &NodeAmendments,
        token: &Grant<DurableWrite>,
    ) -> Result<(), String> {
        if !self.keeps_chain() {
            return Ok(());
        }
        let (run, set_aside) = match self.chain() {
            Ok(Ok(records)) => linked_run(&records),
            // A chain that does not verify: the book's own rebuild verified the same chain and
            // already reported the break as a restart finding.
            Ok(Err(_)) => return Ok(()),
            Err(e) => return Err(self.unreadable(&e)),
        };
        if set_aside > 0 {
            let finding = JournalDisagreement::Unreadable(format!(
                "{set_aside} amendment record(s) do not link onto the amendment chain and were set \
                 aside"
            ));
            tracing::error!(finding = %finding, "the amendment journal was rebuilt without them");
            self.restart_findings.push(finding);
        }
        match journal.restore(run, token) {
            Ok(through) => self.amendments_through = Some(through),
            Err(broken) => self
                .restart_findings
                .push(JournalDisagreement::Unreadable(format!(
                    "the amendment chain does not verify: {broken:?}"
                ))),
        }
        Ok(())
    }
}

/// Journals each amendment the node's journal seals onto the book it was rebuilt from.
struct BookAmendments {
    book: Weak<Mutex<Durability>>,
    token: Grant<DurableWrite>,
}

impl AmendSink for BookAmendments {
    fn sealed(&self, amendment: &Amendment) {
        let Some(book) = self.book.upgrade() else {
            return;
        };
        let mut durability = book.lock().unwrap_or_else(|p| p.into_inner());
        // A durability loss is retained and re-offered by the log like any other append; it is
        // never a refusal of the read or the correction the amendment records.
        if let Err(lost) =
            durability
                .journal
                .append(&self.token, StepName::Audit, &[entry(amendment)])
        {
            tracing::error!(
                step = lost.step().as_str(),
                seq = amendment.seq,
                "the journal lost an amendment: a restart will not reproduce it"
            );
        }
    }
}

/// **BIND THE BOOK THE NODE AMENDMENT JOURNAL `journal` WAS REBUILT FROM**: every amendment sealed
/// on it from here on — and any sealed since the rebuild — goes on the book's journal as it is
/// sealed. A no-op for a book that rebuilt nothing ([`Durability::restore_amendments`] never ran,
/// or the chain has no durable source), which leaves the node journal memory-only.
pub fn bind_amendments(book: &Arc<Mutex<Durability>>, journal: &NodeAmendments) {
    let Some(through) = book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .amendments_through
    else {
        return;
    };
    // ONE durable-write grant, minted once: the sink journals under it, and the binding is made
    // under it.
    let sink = Arc::new(BookAmendments {
        book: Arc::downgrade(book),
        token: busbar_kernel::teller::Kernel::new().durability_token(),
    });
    journal.bind(
        Some(Arc::clone(&sink) as Arc<dyn AmendSink>),
        through,
        &sink.token,
    );
}

#[cfg(test)]
#[path = "../tests/durability_amend.rs"]
mod tests;
