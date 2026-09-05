// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two amendment classes: an access, and an adjustment.
//!
//! ## Access — every time somebody outside the node reads content
//!
//! Content never enters the chain, but it does leave the node: a hook sees it, an export plugin
//! receives it. Each of those is a disclosure, and a disclosure that leaves no record is a
//! disclosure nobody can answer questions about later. So every hook or export content access is an
//! entry of its own, naming who read what and why, and — deliberately — not what they read.
//!
//! The record is small on purpose. It is written at request rate, so anything expensive in it would
//! be a reason to turn it off, and an audit that gets turned off under load is an audit that is not
//! there when it matters.
//!
//! ## Adjust — every time a figure that was already recorded changes
//!
//! A journal is append-only, so a figure is never corrected in place; a correction is a NEW entry
//! that names the old one and says what it is now. That is what makes an adjustment visible: there
//! is no state in which the original amount has quietly become something else. The amendment carries
//! what it was, what it is, who authorised it, and — because a correction that nobody can question is
//! a correction nobody should trust — the reason.
//!
//! ## Why these are amendments rather than fields on the audit record
//!
//! Both happen at a different time from the unit they concern, and often more than once. Folding
//! them into the unit's own record would mean either rewriting that record — which the whole design
//! exists to prevent — or waiting to write it until nothing further could happen, which is never.

use crate::record::{OpClassId, Subject};

/// Which class of amendment this is.
///
/// The two names are the two the journal knows. Keeping them as a closed pair rather than an open
/// string is what stops a third meaning being invented at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmendClass {
    /// Somebody outside the node read content.
    Access,
    /// A figure that was already recorded changed.
    Adjust,
}

impl AmendClass {
    /// The word this class is written as.
    pub fn as_str(self) -> &'static str {
        match self {
            AmendClass::Access => "access",
            AmendClass::Adjust => "adjust",
        }
    }
}

impl std::fmt::Display for AmendClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of thing reached for the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader {
    /// A hook, running inside the unit.
    Hook,
    /// An export plugin, receiving facts on its way off the node.
    Export,
}

impl Reader {
    /// The word this reader is written as.
    pub fn as_str(self) -> &'static str {
        match self {
            Reader::Hook => "hook",
            Reader::Export => "export",
        }
    }
}

/// One content access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// What kind of thing read it.
    pub reader: Reader,
    /// Which one, by name.
    pub name: String,
    /// Whose content it was.
    pub subject: Subject,
    /// What kind of operation the content belonged to.
    pub op_class: OpClassId,
    /// Which fields were reached for. Field NAMES, never their values.
    pub fields: Vec<String>,
    /// When, in unix seconds.
    pub wall: u64,
}

/// One correction to a figure that was already recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjust {
    /// Which entry is being corrected, by its digest.
    pub amends_hash: String,
    /// Whose figure it is.
    pub subject: Subject,
    /// What it was, in nano-units.
    pub was: i128,
    /// What it is now.
    pub now: i128,
    /// Who authorised the correction.
    pub authorised_by: String,
    /// Why. A correction nobody can question is a correction nobody should trust, so this is not
    /// optional.
    pub reason: String,
    /// When, in unix seconds.
    pub wall: u64,
}

impl Adjust {
    /// How much the figure moved by.
    pub fn delta(&self) -> i128 {
        self.now - self.was
    }
}

/// What the amendment is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmendBody {
    /// A content access.
    Access(Access),
    /// A correction.
    Adjust(Adjust),
}

impl AmendBody {
    /// Which class this body belongs to.
    pub fn class(&self) -> AmendClass {
        match self {
            AmendBody::Access(_) => AmendClass::Access,
            AmendBody::Adjust(_) => AmendClass::Adjust,
        }
    }
}

/// One amendment, on its own chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amendment {
    /// Its position.
    pub seq: u64,
    /// What it is about.
    pub body: AmendBody,
    /// The preceding amendment's digest.
    pub prev_hash: String,
    /// Its own digest.
    pub hash: String,
}

impl Amendment {
    /// Which class this amendment belongs to.
    pub fn class(&self) -> AmendClass {
        self.body.class()
    }
}

/// The chain of amendments.
///
/// One chain for both classes, because an access and a correction are both "something happened after
/// the fact" and interleaving them preserves the order in which they did. Splitting them would make
/// the question "what happened to this posting, in order" need two reads and a merge.
#[derive(Debug, Default)]
pub struct AmendChain {
    tail_hash: String,
    next_seq: u64,
}

impl AmendChain {
    /// A chain with nothing in it.
    pub fn new() -> Self {
        AmendChain {
            tail_hash: String::new(),
            next_seq: 1,
        }
    }

    /// Continue from a persisted tail.
    pub fn resume(tail_hash: String, next_seq: u64) -> Self {
        AmendChain {
            tail_hash,
            next_seq,
        }
    }

    /// The position the next amendment will take.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The digest of the most recent amendment.
    pub fn head(&self) -> &str {
        &self.tail_hash
    }

    /// Append one amendment, linking and sealing it.
    ///
    /// The token is the audit unit's, for the same reason sealing an audit record needs one: an
    /// amendment is evidence, and evidence anybody could add is evidence nobody can rely on.
    pub fn append(
        &mut self,
        body: AmendBody,
        _token: &busbar_caps::UnitToken<busbar_caps::Audit>,
    ) -> Amendment {
        let mut amendment = Amendment {
            seq: self.next_seq,
            body,
            prev_hash: self.tail_hash.clone(),
            hash: String::new(),
        };
        amendment.hash = AmendChain::digest_of(&amendment);
        self.tail_hash = amendment.hash.clone();
        self.next_seq = self.next_seq.saturating_add(1);
        amendment
    }

    /// Recompute one amendment's digest from its own fields.
    ///
    /// Length-prefixed, like the fixed audit record and unlike the previous release's chain: nothing
    /// here is already on anybody's disk, so the framing is chosen for the property rather than
    /// inherited for compatibility.
    pub fn digest_of(amendment: &Amendment) -> String {
        let mut d = crate::legacy::Digest::new(crate::legacy::Framing::LengthPrefixed);
        d.text(&amendment.prev_hash);
        d.num(amendment.seq);
        d.text(amendment.class().as_str());
        match &amendment.body {
            AmendBody::Access(a) => {
                d.text(a.reader.as_str());
                d.text(&a.name);
                d.text(&format!("{:?}", a.subject));
                d.text(a.op_class.as_str());
                d.num(a.fields.len() as u64);
                for field in &a.fields {
                    d.text(field);
                }
                d.num(a.wall);
            }
            AmendBody::Adjust(a) => {
                d.text(&a.amends_hash);
                d.text(&format!("{:?}", a.subject));
                d.text(&a.was.to_string());
                d.text(&a.now.to_string());
                d.text(&a.authorised_by);
                d.text(&a.reason);
                d.num(a.wall);
            }
        }
        d.finish()
    }

    /// Whether a run of amendments links and digests correctly, oldest first.
    pub fn verify(amendments: &[Amendment]) -> Result<(), crate::record::AuditBreak> {
        let mut expected_prev = amendments
            .first()
            .map(|a| a.prev_hash.clone())
            .unwrap_or_default();
        let mut expected_seq = amendments.first().map(|a| a.seq).unwrap_or(1);
        for (i, amendment) in amendments.iter().enumerate() {
            if amendment.prev_hash != expected_prev || amendment.seq != expected_seq {
                return Err(crate::record::AuditBreak {
                    at_index: i + 1,
                    kind: crate::record::AuditBreakKind::LinkMismatch,
                });
            }
            if AmendChain::digest_of(amendment) != amendment.hash {
                return Err(crate::record::AuditBreak {
                    at_index: i + 1,
                    kind: crate::record::AuditBreakKind::DigestMismatch,
                });
            }
            expected_prev = amendment.hash.clone();
            expected_seq = expected_seq.saturating_add(1);
        }
        Ok(())
    }
}

/// A convenience for the commonest access: one named hook or export read one unit's content.
pub fn content_access(
    reader: Reader,
    name: impl Into<String>,
    subject: Subject,
    op_class: OpClassId,
    fields: Vec<String>,
    wall: u64,
) -> AmendBody {
    AmendBody::Access(Access {
        reader,
        name: name.into(),
        subject,
        op_class,
        fields,
        wall,
    })
}

/// Named so that the type checker, rather than a reviewer, notices an amendment written against no
/// prior entry: an adjustment must name what it amends.
pub fn correction(
    amends: &str,
    subject: Subject,
    was: i128,
    now: i128,
    authorised_by: impl Into<String>,
    reason: impl Into<String>,
    wall: u64,
) -> AmendBody {
    AmendBody::Adjust(Adjust {
        amends_hash: amends.to_string(),
        subject,
        was,
        now,
        authorised_by: authorised_by.into(),
        reason: reason.into(),
        wall,
    })
}

/// The digest of an audit record, so an amendment can name the entry it amends without the caller
/// reaching into the chain's internals.
pub fn amends(record: &crate::record::AuditRecord) -> String {
    record.hash.clone()
}
