// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission of owner-interpreted facts against the independently captured original bytes.
//! Coverage is complete and bounded; an invalid stream cannot be retried in the same verifier.
use crate::{archive_source::ArchiveRows, Error};
use busbar_contract::persistence::{
    archive,
    lifecycle::{source::SourceChunk, SourceReader},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

struct ActiveGroup {
    digest: [u8; 32],
    next: u64,
    evidence: u64,
    facts: u64,
}
/// Complete original-byte coverage of a declared logical source stream.
/// This capability never grants native fencing, target writes or activation.
pub struct SourceCoverage {
    reader: SourceReader,
    rows: u64,
    seen: Vec<u8>,
    covered: u64,
    active: Option<ActiveGroup>,
    completed: BTreeSet<[u8; 32]>,
    charged: usize,
    index_bytes: usize,
    failed: bool,
}
impl std::fmt::Debug for SourceCoverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCoverage")
            .field("rows", &self.rows)
            .field("covered", &self.covered)
            .field("groups", &self.completed.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
impl SourceCoverage {
    pub fn new(reader: SourceReader, rows: u64, index_bytes: usize) -> Result<Self, Error> {
        let bytes = usize::try_from(rows.checked_add(7).ok_or(Error::Bounds)? / 8)
            .map_err(|_| Error::Bounds)?;
        if bytes > index_bytes || index_bytes == 0 {
            return Err(Error::Bounds);
        }
        let mut seen = Vec::new();
        seen.try_reserve_exact(bytes).map_err(|_| Error::Bounds)?;
        seen.resize(bytes, 0);
        Ok(Self {
            reader,
            rows,
            seen,
            covered: 0,
            active: None,
            completed: BTreeSet::new(),
            charged: bytes,
            index_bytes,
            failed: false,
        })
    }
    /// Validate one chunk before its facts enter the protected logical spool.
    pub fn admit(
        &mut self,
        source: &mut dyn ArchiveRows,
        chunk: &SourceChunk,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::InvalidState);
        }
        let result = self.admit_inner(source, chunk);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn admit_inner(
        &mut self,
        source: &mut dyn ArchiveRows,
        chunk: &SourceChunk,
    ) -> Result<(), Error> {
        let seal = crate::seal::lend();
        if chunk.reader != self.reader
            || source.row_count() != self.rows
            || chunk.group.expose(&seal).is_empty()
            || (chunk.evidence.is_empty() && chunk.facts.is_empty())
            || chunk.facts.iter().any(|fact| fact.family() != chunk.family)
        {
            return Err(Error::IdentityMismatch);
        }
        let mut hash = Sha256::new();
        hash.update(b"busbar.interpreted.source-group/1\0");
        hash.update([match chunk.family {
            busbar_contract::persistence::lifecycle::source::HistoricalFamily::Identity => 0,
            busbar_contract::persistence::lifecycle::source::HistoricalFamily::Accounting => 1,
            busbar_contract::persistence::lifecycle::source::HistoricalFamily::Archival => 2,
            busbar_contract::persistence::lifecycle::source::HistoricalFamily::Audit => 3,
            busbar_contract::persistence::lifecycle::source::HistoricalFamily::Evidence => 4,
        }]);
        hash.update(chunk.group.expose(&seal));
        let digest: [u8; 32] = hash.finalize().into();
        if let Some(active) = &self.active {
            if active.digest != digest || active.next != chunk.sequence {
                return Err(Error::Verification);
            }
        } else {
            if chunk.sequence != 0 || self.completed.contains(&digest) {
                return Err(Error::Verification);
            }
            // Charge a conservative tree-node allocation before inserting a public commitment.
            self.charged = self.charged.checked_add(128).ok_or(Error::Bounds)?;
            if self.charged > self.index_bytes {
                return Err(Error::Bounds);
            }
            self.active = Some(ActiveGroup {
                digest,
                next: 0,
                evidence: 0,
                facts: 0,
            });
        }
        for evidence in &chunk.evidence {
            let ordinal = source
                .find_native(evidence.table, evidence.native_key.expose(&seal))?
                .ok_or(Error::Verification)?;
            if ordinal >= self.rows {
                return Err(Error::Corrupt);
            }
            let byte = usize::try_from(ordinal / 8).map_err(|_| Error::Bounds)?;
            let bit = 1u8 << (ordinal % 8);
            if self.seen[byte] & bit != 0 {
                return Err(Error::Verification);
            }
            let original = source.read_row(ordinal)?;
            if original.table != evidence.table
                || original.native_key != evidence.native_key
                || archive::digest(original.value.expose(&seal)) != evidence.value_digest
            {
                return Err(Error::Verification);
            }
            self.seen[byte] |= bit;
            self.covered = self.covered.checked_add(1).ok_or(Error::Bounds)?;
        }
        let active = self.active.as_mut().ok_or(Error::InvalidState)?;
        active.evidence = active
            .evidence
            .checked_add(chunk.evidence.len().try_into().map_err(|_| Error::Bounds)?)
            .ok_or(Error::Bounds)?;
        active.facts = active
            .facts
            .checked_add(chunk.facts.len().try_into().map_err(|_| Error::Bounds)?)
            .ok_or(Error::Bounds)?;
        if chunk.complete {
            if active.evidence == 0 || active.facts == 0 {
                return Err(Error::Verification);
            }
            self.active = None;
            if !self.completed.insert(digest) {
                return Err(Error::Verification);
            }
        } else {
            self.active.as_mut().ok_or(Error::InvalidState)?.next =
                chunk.sequence.checked_add(1).ok_or(Error::Bounds)?;
        }
        Ok(())
    }
    /// Seal only a complete stream whose groups consumed every original row exactly once.
    pub fn finish(self) -> Result<(), Error> {
        if self.failed || self.active.is_some() || self.covered != self.rows {
            Err(Error::Verification)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::{
        persistence::{
            archive::{ArchiveRow, Header},
            lifecycle::{
                source::{HistoricalFact, HistoricalFamily, SourceEvidence},
                DocumentSemantics, SourceCodec,
            },
        },
        Secret,
    };
    struct Rows {
        header: Header,
    }
    impl Rows {
        fn new() -> Self {
            Self {
                header: Header {
                    owner: [1; 16],
                    physical: 1,
                    catalogue_digest: [2; 32],
                    native_anchor_digest: [3; 32],
                    capture: None,
                    tables: vec![],
                },
            }
        }
    }
    impl ArchiveRows for Rows {
        fn header(&self) -> &Header {
            &self.header
        }
        fn row_count(&self) -> u64 {
            2
        }
        fn read_row(&mut self, ordinal: u64) -> Result<ArchiveRow, Error> {
            if ordinal >= 2 {
                return Err(Error::Corrupt);
            }
            Ok(ArchiveRow {
                table: 0,
                native_key: Secret::new(vec![ordinal as u8]),
                value: Secret::new(vec![10 + ordinal as u8]),
            })
        }
        fn find_native(&self, table: u32, key: &[u8]) -> Result<Option<u64>, Error> {
            Ok((table == 0 && key.len() == 1 && key[0] < 2).then(|| u64::from(key[0])))
        }
    }
    fn reader() -> SourceReader {
        SourceReader::new(
            SourceCodec::HistoricalV1,
            DocumentSemantics::Historical,
            [4; 32],
        )
        .unwrap()
    }
    fn chunk(ordinal: u8, sequence: u64, complete: bool) -> SourceChunk {
        SourceChunk {
            reader: reader(),
            family: HistoricalFamily::Identity,
            group: Secret::new(b"group".to_vec()),
            sequence,
            complete,
            evidence: vec![SourceEvidence {
                table: 0,
                native_key: Secret::new(vec![ordinal]),
                value_digest: archive::digest(&[10 + ordinal]),
            }],
            facts: vec![HistoricalFact::Revision(1)],
        }
    }
    #[test]
    fn interpreted_source_requires_exact_complete_original_byte_coverage() {
        let mut rows = Rows::new();
        let mut valid = SourceCoverage::new(reader(), 2, 1024).unwrap();
        valid.admit(&mut rows, &chunk(0, 0, false)).unwrap();
        valid.admit(&mut rows, &chunk(1, 1, true)).unwrap();
        valid.finish().unwrap();
        let mut missing = SourceCoverage::new(reader(), 2, 1024).unwrap();
        missing.admit(&mut rows, &chunk(0, 0, true)).unwrap();
        assert!(matches!(missing.finish(), Err(Error::Verification)));
        let mut unfinished = SourceCoverage::new(reader(), 2, 1024).unwrap();
        unfinished.admit(&mut rows, &chunk(0, 0, false)).unwrap();
        unfinished.admit(&mut rows, &chunk(1, 1, false)).unwrap();
        assert!(matches!(unfinished.finish(), Err(Error::Verification)));
    }
    #[test]
    fn invalid_interpretation_poisoning_prevents_retrying_away_bad_evidence() {
        let mut rows = Rows::new();
        for mode in 0..4 {
            let mut coverage = SourceCoverage::new(reader(), 2, 1024).unwrap();
            coverage.admit(&mut rows, &chunk(0, 0, false)).unwrap();
            let mut bad = chunk(1, 1, true);
            match mode {
                0 => bad.evidence[0].value_digest = [99; 32],
                1 => bad.evidence[0].native_key = Secret::new(vec![0]),
                2 => bad.sequence = 2,
                _ => {
                    bad.reader = SourceReader::new(
                        SourceCodec::HistoricalV1,
                        DocumentSemantics::Historical,
                        [9; 32],
                    )
                    .unwrap()
                }
            }
            assert!(coverage.admit(&mut rows, &bad).is_err());
            assert!(matches!(
                coverage.admit(&mut rows, &chunk(1, 1, true)),
                Err(Error::InvalidState)
            ));
            assert!(coverage.finish().is_err());
        }
        assert!(SourceCoverage::new(reader(), 1_000_000, 128).is_err());
        let mut limited = SourceCoverage::new(reader(), 2, 128).unwrap();
        assert!(matches!(
            limited.admit(&mut rows, &chunk(0, 0, true)),
            Err(Error::Bounds)
        ));
    }
}
