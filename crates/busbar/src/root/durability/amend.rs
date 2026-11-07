// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel_audit::amend::{
    self as amend, Access, Adjust, AmendBody, AmendClass, AmendSink, Amendment, ClassCounts,
    NodeAmendments, Reader,
};
use busbar_kernel_audit::record::OpClassId;
use std::sync::{Arc, Mutex};

#[cfg(feature = "root-admin")]
pub(crate) fn verify_held(journal: &NodeAmendments) -> Result<(), String> {
    journal.verify().map_err(|broken| broken.to_string())
}

const AMENDMENT: &str = "amend.v1";

fn entry(amendment: &Amendment) -> Entry {
    let (class, wall) = match &amendment.body {
        AmendBody::Access(a) => (RecordClass::Access, a.wall),
        AmendBody::Adjust(a) => (RecordClass::Transaction, a.wall),
    };
    Entry::new(class, body(amendment)).at(wall, 0)
}

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

            if let Some(pool) = &a.pool {
                body.text(pool);
            }
        }
    }
    body.finish()
}

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

fn linked_run(records: &[JournalRecord]) -> (Vec<Amendment>, usize) {
    let (mut run, mut set_aside) = (Vec::<Amendment>::new(), 0);
    for record in records {
        let Some(amendment) = from_record(record) else {
            if BodyReader::new(&record.body).text() == Some(AMENDMENT) {
                set_aside += 1;
            }
            continue;
        };
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
    pub async fn restore_amendments(
        &mut self,
        journal: &NodeAmendments,
        token: &Grant<DurableWrite>,
    ) -> Result<(), String> {
        if !self.keeps_chain() {
            return Ok(());
        }
        let (run, set_aside) = match self.chain().await {
            Ok(Ok(records)) => linked_run(&records),

            Ok(Err(broken)) => return Err(format!("the journal does not verify: {broken}")),
            Err(e) => return Err(self.unreadable(&e)),
        };
        if set_aside > 0 {
            let finding = format!(
                "{set_aside} amendment record(s) do not link onto the amendment chain and were set \
                 aside"
            );
            tracing::error!(finding = %finding, "the amendment journal was rebuilt without them");
            self.restart_findings.push(finding);
        }
        match journal.restore(run, token) {
            Ok(through) => self.amendments_through = Some(through),
            Err(broken) => self
                .restart_findings
                .push(format!("the amendment chain does not verify: {broken:?}")),
        }
        Ok(())
    }
}

type PendingAmendments = std::collections::BTreeMap<
    u64,
    (
        String,
        Arc<busbar_kernel::persistence::journal::runtime::StagedRun>,
    ),
>;

struct BookAmendments {
    journal: Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>,
    pending: Arc<Mutex<PendingAmendments>>,
    token: Grant<DurableWrite>,
}

impl AmendSink for BookAmendments {
    fn sealed(
        &self,
        amendment: &Amendment,
    ) -> Result<
        busbar_kernel_audit::amend::AmendCommit,
        busbar_kernel_audit::amend::AmendPersistError,
    > {
        use busbar_kernel_audit::amend::AmendPersistError;
        let staged = (|| {
            let mut pending = self.pending.lock().map_err(|_| AmendPersistError)?;
            pending.retain(|_, (_, run)| !matches!(self.journal.is_confirmed(run), Ok(true)));
            if let Some((hash, run)) = pending.get(&amendment.seq) {
                if hash != &amendment.hash {
                    return Err(AmendPersistError);
                }
                return Ok(run.clone());
            }
            let run = self
                .journal
                .stage_run(&[entry(amendment)])
                .map_err(|_| AmendPersistError)?;
            pending.insert(amendment.seq, (amendment.hash.clone(), run.clone()));
            Ok(run)
        })()?;
        let journal = self.journal.clone();
        let pending = self.pending.clone();
        let seq = amendment.seq;
        Ok(Box::pin(async move {
            let run = staged;
            journal.confirm(&run).await.map_err(|_| AmendPersistError)?;
            pending.lock().map_err(|_| AmendPersistError)?.remove(&seq);
            Ok(())
        }))
    }
}

pub async fn bind_amendments(
    book: &Arc<Mutex<Durability>>,
    journal: &NodeAmendments,
) -> Result<(), String> {
    let (through, runtime) = {
        let book = book.lock().unwrap_or_else(|poison| poison.into_inner());
        (
            book.amendments_through
                .ok_or("amendment restoration has not completed")?,
            book.journal.clone(),
        )
    };
    let sink = Arc::new(BookAmendments {
        journal: runtime,
        pending: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        token: busbar_kernel::teller::Kernel::new().durability_token(),
    });
    journal
        .bind(
            Some(sink.clone() as Arc<dyn AmendSink>),
            through,
            &sink.token,
        )
        .await
        .map_err(|_| "amendment binding remains unconfirmed in the native journal".into())
}

#[cfg(test)]
#[path = "../tests/durability_amend.rs"]
mod tests;
