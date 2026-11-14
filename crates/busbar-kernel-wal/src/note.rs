// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The quarantine note a written journal can carry: a `ChainBreak` body naming a hole in the
//! chain. Journals already written hold these, so the reader stays.

/// Where a quarantine leaves a hole in the journal's chain, and the only place a chain may skip
/// numbers or a link and still verify. See [`crate::journal::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bridge {
    /// The last record kept before the hole.
    pub before: (u64, u64),
    /// The first record kept after it, or `None` when the chain resumes with whatever is written
    /// next.
    pub after: Option<(u64, u64)>,
}

/// What a quarantine's `ChainBreak` body says about where the set-aside bytes were: the segment, the
/// first byte, and the hole they leave in the chain. Read back so that a chain carrying the break
/// verifies across the hole it names, and so that a hole re-found at a later boot is not recorded a
/// second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantineNote {
    /// Which segment.
    pub segment: u64,
    /// The first byte set aside.
    pub offset: u64,
    /// The hole it names in the chain, on a body that names one.
    pub bridge: Option<Bridge>,
}

impl QuarantineNote {
    /// Read a quarantine `ChainBreak` body back. `None` for any other body.
    #[must_use]
    pub fn read(body: &[u8]) -> Option<Self> {
        let mut r = crate::journal::BodyReader::new(body);
        if r.text()? != QUARANTINE_BODY_TAG {
            return None;
        }
        let _segment_file = r.text()?;
        let segment = r.num()?;
        let offset = r.num()?;
        let _damage_at = r.num()?;
        let _bytes = r.num()?;
        let _kept = r.text()?;
        let _at = r.num()?;
        let _count = r.num()?;

        let bridge = read_bridge(&mut r);
        Some(QuarantineNote {
            segment,
            offset,
            bridge,
        })
    }
}

/// The hole a quarantine body names, read after its fixed fields: whether a record was kept before
fn read_bridge(r: &mut crate::journal::BodyReader<'_>) -> Option<Bridge> {
    let has_before = r.num()?;
    let before = (r.num()?, r.num()?);
    let has_after = r.num()?;
    let after = (r.num()?, r.num()?);
    (has_before == 1).then_some(Bridge {
        before,
        after: (has_after == 1).then_some(after),
    })
}

/// The first field of a quarantine's `ChainBreak` body, which tells it apart from the break an
pub const QUARANTINE_BODY_TAG: &str = "journal-quarantine";
