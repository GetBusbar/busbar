// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reading a segment back after a crash, and cutting away whatever the crash left behind.
//!
//! ## The rule, in one sentence
//!
//! The log ends at the last record every one of whose frames verifies; everything after that point
//! is removed.
//!
//! ## Why it is stated over RECORDS and not over frames
//!
//! A record whose body needs three frames is one fact, not three. If a crash landed two of its
//! frames and lost the third, keeping the two would hand the reader a truncated body — a fact that
//! was never written, invented by the recovery path. So the scan tracks the record being assembled
//! and only advances the durable end once a record is complete. Two frames of an incomplete record
//! are cut away with the damage, and the writer that meant to write it will write it again.
//!
//! ## Why every byte offset is a test and not a comment
//!
//! There is no interesting subset of the offsets a crash can stop at. So the battery truncates the
//! segment at every byte offset from zero to the end, recovers, and asserts the result is the
//! longest prefix of the records that were written. Any special-cased offset would show up as the
//! one the loop fails on.
//!
//! ## Two ways a scan stops on damage, and only one of them may be cut
//!
//! A crash in the middle of a group commit leaves a TORN tail: the commit's bytes are partly on the
//! medium and nothing after them was ever written. Cutting that tail loses nothing that was
//! acknowledged — the sync never returned — so it is cut silently, exactly as it always was. A
//! record that was acknowledged and then damaged is something else, and is never cut silently
//! wherever it sits, the tail included: a silent cut would drop a settlement the node had already
//! made, and let recovery settle the unit again at its checkpoint. So it is CORRUPT. Telling the two
//! apart is a question about what was ACKNOWLEDGED, and the medium answers it two ways.
//!
//! **A subsequent commit verifying past the damage.** The first frame of every group commit says so, and
//! a commit is only ever written after the one before it synced. So a verifying frame that opens a
//! commit, past the damage, proves the damaged commit's sync returned: it was acknowledged, and the
//! damage is the medium, or something outside this process, changing bytes that were already
//! durable. Corrupt, whatever the damage looks like. A verifying frame of the SAME commit proves
//! nothing — writeback puts a commit's pages down in any order, so a crash mid-commit leaves good
//! frames past missing ones as a matter of course — and is cut with the torn commit it belongs to.
//!
//! **The shape of the damage, in the commit nothing acknowledges.** The last commit has no subsequent one
//! to vouch for it; its sync may or may not have returned. A crash leaves only one shape behind:
//! frames that never landed (the zeros the segment claimed ahead of the writes) and frames whose
//! write stopped part way (their leading bytes, then zeros). Every frame ends with an end mark that
//! is never zero, so a frame whose write stopped anywhere inside it — header, digest or payload —
//! has a zero last byte, and one whose last byte is there was written to its end. If every frame of
//! the damaged tail is one a write could have left unfinished, the tail is TORN. If any is a WHOLE
//! frame that fails a check — its end mark is there, so the write that made it completed — it was
//! written in full and changed afterwards: CORRUPT, and the record's bytes as they now read are
//! handed to the caller (`Quarantine::damaged`), which is the one place that knows what they named.
//!
//! What this cannot see, nothing can: bytes changed in the last commit into exactly the shape of an
//! unfinished write — zeros to the end of a frame — read as a torn tail. That is the power to cut
//! the file short, which a torn tail has always been indistinguishable from.
//!
//! A corrupt segment is never cut on its own say-so: the damaged remainder is first copied, byte for
//! byte, into a quarantine the factory makes durable, and only then is the segment cut back to the
//! verified prefix. A crash between the two steps leaves the copy AND the uncut segment, so it loses
//! nothing. A frame written under a layout version this build does not read is never one a write of
//! this layout left unfinished, so it is treated the same way — its bytes are whole and another
//! build can read them, so they are never simply cut.
//!
//! ## Acknowledged damage is never cut, and nothing behind it is lost with it
//!
//! Frames sit at a fixed stride, so the scan does not stop for good at acknowledged damage: it reads
//! on to the next frame that opens a record, and every record from there on whose frames all verify
//! is kept, exactly as if the damage were not there. The damaged record alone is the HOLE: copied
//! into a quarantine, reported, and LEFT IN PLACE, because cutting it would cut every good record
//! behind it, and because only a true torn tail is ever truncated (THE DESIGN, MONEY-CHAIN,
//! BUSBAR-1.6.0.md l.1056-1058). A corrupt remainder with no record behind it is copied too, and the
//! segment is closed to writes rather than cut, so the next append rolls past it. Either way the
//! damage is still on the medium at the next boot, which finds it, reports it and keeps the units it
//! names from settling at 0 all over again. Each hole names the kept records on either side of it
//! ([`Quarantine::before`], [`Quarantine::after`]), which is what lets the journal's chain verify
//! across it and nowhere else. A torn tail is still cut whole: what a crash left of a commit nothing
//! acknowledged is not read past.
//!
//! The verdict is returned rather than acted on further here. Raising the alarm — the log line, the
//! counter, the durable record naming what was set aside — is the caller's, which is the one place
//! that knows what the lost records meant.

use std::io;
use std::path::PathBuf;

use crate::backend::SegmentFactory;
use crate::record::{
    checked_header, decode_frame, unchecked_whole, unfinished_write, FrameError, Record,
    FRAME_BYTES,
};
use crate::segment::Segment;

/// How a scan of a segment ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailVerdict {
    /// The writes end where the verified records end. Anything past them is space claimed ahead of
    /// the writes, which is zeros.
    Clean,
    /// The scan stopped in the last group commit, on damage a crash mid-commit leaves: frames that
    /// never landed and frames whose write stopped part way. Nothing acknowledged is in it: cut
    /// silently, with any frame of the same commit that did land.
    Torn,
    /// The scan stopped on damage a crash does not leave: a commit a subsequent one acknowledges, a whole
    /// frame that fails a check, or a frame written under a layout this build does not read.
    /// Acknowledged records are in it. Copied into a quarantine and never cut.
    Corrupt {
        /// The byte offset, inside the segment, of the frame the scan stopped on.
        at: u64,
    },
}

impl TailVerdict {
    /// Whether this verdict is one the caller answers by cutting the segment with no copy kept.
    ///
    /// The question lives on the verdict rather than in each caller, because "anything that is not
    /// clean is a torn tail" is exactly the habit that turned a corrupted record into the silent
    /// loss of every good record behind it.
    #[must_use]
    pub fn truncates(self) -> bool {
        !matches!(self, TailVerdict::Corrupt { .. })
    }
}

/// Where a quarantined remainder was kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineKept {
    /// In a file beside the segment, written and synced before the segment was cut.
    File(PathBuf),
    /// In the memory factory's own quarantine list. A memory-backed log has no disk to put it on,
    /// and the process holding it is the only thing that could ever have read it.
    Memory,
    /// The copy could not be made durable, so the damaged bytes are only where they were, in the
    /// segment — which recovery never cuts, and which is closed to writes besides, so the next
    /// append rolls to a fresh segment and nothing is ever written near them. The text is why the
    /// copy failed.
    InPlace(String),
}

/// What a corrupt segment gave up: which bytes, from where, and where they were kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantine {
    /// Which segment.
    pub segment: u64,
    /// The segment's file, on a log that has one.
    pub segment_file: Option<PathBuf>,
    /// The first byte set aside — the end of the record kept before it.
    pub offset: u64,
    /// The frame the scan stopped on. At or after `offset`: frames of a record that never completed
    /// verify on their own and still go with the damage.
    pub damage_at: u64,
    /// How many bytes were set aside, from `offset` to the next record kept — or, past the last
    /// one, to the end of what was ever written. Space claimed ahead of the writes is zeros and is
    /// not copied.
    pub bytes: u64,
    /// Why the scan stopped, when a frame said so.
    pub why: Option<FrameError>,
    /// Every `(node, node_seq)` a verifying frame in the set-aside bytes carries. Those records were
    /// acknowledged and may already be in a store, so the log must never hand the same identities
    /// out again: it marks them taken.
    pub identities: Vec<(u64, u64)>,
    /// The identities in [`Quarantine::identities`] that only a WHOLE frame whose header does not
    /// check carries: read as the bytes now stand, so the damaged byte may be the number itself. The
    /// log takes each of them only as far as the set-aside bytes could have numbered: an unverified
    /// number never moves a node's numbering further than one per set-aside record.
    pub unverified: Vec<(u64, u64)>,
    /// Every record the set-aside bytes hold whose frames' HEADERS check, assembled as the bytes now
    /// read: a whole altered record (header checks, digest does not), and the head of a record the
    /// damage cut into. They are off the book, and the caller reads what they named — a
    /// settlement the node made must not be settled again as if it never happened. A whole frame
    /// whose header does not check — of this layout or another — contributes its record as its
    /// bytes now read (unverified, so a caller that cannot decode it holds back what it cannot rule
    /// out); a frame a write left unfinished contributes nothing.
    pub damaged: Vec<Record>,
    /// When recovery set them aside, in milliseconds since the Unix epoch. The quarantine file's
    /// name carries the same number.
    pub at_unix_ms: u64,
    /// Where the bytes went.
    pub kept: QuarantineKept,
    /// The last record the log KEPT before the set-aside bytes, in the log's order across every
    /// segment: the record the journal's chain re-anchors on. `None` when nothing precedes them.
    pub before: Option<(u64, u64)>,
    /// The first record the log kept AFTER the set-aside bytes, when one does: its link points at a
    /// record that is no longer readable. `None` for a remainder nothing was kept behind, where the
    /// next record written is the one that resumes the chain.
    pub after: Option<(u64, u64)>,
}

/// Where a quarantine leaves a hole in the journal's chain, and the only place a chain may skip
/// numbers or a link and still verify. See [`crate::journal::verify_bridged`].
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
        // A body sealed before the hole was named carries no bridge.
        let bridge = read_bridge(&mut r);
        Some(QuarantineNote {
            segment,
            offset,
            bridge,
        })
    }
}

/// The hole a quarantine body names, read after its fixed fields: whether a record was kept before
/// it and which, then whether one was kept after it and which.
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

impl Quarantine {
    /// The hole this quarantine leaves in the chain, when a record was kept before it.
    #[must_use]
    pub fn bridge(&self) -> Option<Bridge> {
        self.before.map(|before| Bridge {
            before,
            after: self.after,
        })
    }

    /// The body of the `ChainBreak` journal record that says, durably, what was set aside: a tag,
    /// the segment file, the segment index, the first byte set aside, the frame the damage was
    /// found at, the byte count, where the bytes went, the moment, how many record identities
    /// they held, and the hole they leave in the chain (whether a record was kept before it and
    /// which, whether one was kept after it and which) — in that order, through the journal's own
    /// body writer.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let segment_file = self
            .segment_file
            .as_ref()
            .map_or_else(String::new, |p| p.display().to_string());
        let kept = match &self.kept {
            QuarantineKept::File(path) => path.display().to_string(),
            QuarantineKept::Memory => "in-process".to_string(),
            QuarantineKept::InPlace(e) => format!("in-place: {e}"),
        };
        let mut body = crate::journal::BodyWriter::new();
        body.text(QUARANTINE_BODY_TAG)
            .text(&segment_file)
            .num(self.segment)
            .num(self.offset)
            .num(self.damage_at)
            .num(self.bytes)
            .text(&kept)
            .num(self.at_unix_ms)
            .num(self.identities.len() as u64);
        let (has_before, before) = self.before.map_or((0, (0, 0)), |id| (1, id));
        let (has_after, after) = self.after.map_or((0, (0, 0)), |id| (1, id));
        body.num(has_before)
            .num(before.0)
            .num(before.1)
            .num(has_after)
            .num(after.0)
            .num(after.1);
        body.finish()
    }
}

/// The first field of a quarantine's `ChainBreak` body, which tells it apart from the break an
/// overflow seals.
pub const QUARANTINE_BODY_TAG: &str = "journal-quarantine";

impl std::fmt::Display for Quarantine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let segment = self.segment_file.as_ref().map_or_else(
            || format!("segment {}", self.segment),
            |p| p.display().to_string(),
        );
        write!(
            f,
            "journal corruption in {segment} at byte {}: {} byte(s) from byte {} holding {} \
             record identity(ies) are no longer on the book",
            self.damage_at,
            self.bytes,
            self.offset,
            self.identities.len()
        )?;
        if let Some(why) = self.why {
            write!(f, " ({why})")?;
        }
        match &self.kept {
            QuarantineKept::File(path) => write!(f, "; quarantined to {}", path.display()),
            QuarantineKept::Memory => f.write_str("; quarantined in memory"),
            QuarantineKept::InPlace(e) => write!(
                f,
                "; the quarantine copy failed ({e}), so the bytes were left in the segment and it \
                 is closed to writes"
            ),
        }
    }
}

/// What a scan of a segment found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// Every record whose frames all verify, in the order they were written — those behind a hole
    /// included.
    pub records: Vec<Record>,
    /// The offset the last complete record ends at. This is where appending resumes.
    pub durable_end: u64,
    /// How many bytes past `durable_end` the backing held. Non-zero means a tail was cut.
    pub discarded_bytes: u64,
    /// Why the scan stopped at the end, when it stopped on damage rather than on the end of the
    /// writes.
    pub stopped_because: Option<FrameError>,
    /// How the segment read, as a whole: [`TailVerdict::Corrupt`] at the first acknowledged damage
    /// anywhere in it (a hole or the tail), otherwise how the tail ended.
    pub verdict: TailVerdict,
    /// How the bytes past the last kept record ended: what is cut silently, what is clean, and what
    /// is a corrupt remainder copied aside and never cut.
    pub tail: TailVerdict,
    /// The damaged records the scan read past, in order: every one of them has a kept record behind
    /// it in this segment.
    pub holes: Vec<Hole>,
    /// Where the bytes every hole and a corrupt tail gave up went, in the order they sit in the
    /// segment. Set only by [`recover_and_truncate`] and [`quarantine_in_place`]; a bare [`scan`]
    /// modifies nothing and so has set nothing aside.
    pub quarantined: Vec<Quarantine>,
    /// The end of what was ever written past the verified prefix: the last byte that is not
    /// claimed-ahead zeros. Equal to `durable_end` when nothing was written past it.
    pub written_end: u64,
    /// Every identity a verifying frame past the stop carries. See [`Quarantine::identities`].
    pub identities_beyond: Vec<(u64, u64)>,
    /// The identities past the stop no verified header carries. See [`Quarantine::unverified`].
    pub unverified_beyond: Vec<(u64, u64)>,
    /// The records the corrupt tail holds, as they now read. See [`Quarantine::damaged`].
    pub damaged: Vec<Record>,
}

/// One damaged stretch the scan read past: acknowledged damage with a kept record behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hole {
    /// The first byte of the damaged record: the end of the record kept before it.
    pub offset: u64,
    /// The frame the scan stopped on.
    pub damage_at: u64,
    /// Where the next kept record starts.
    pub end: u64,
    /// Why the scan stopped, when a frame said so.
    pub why: Option<FrameError>,
    /// See [`Quarantine::identities`].
    pub identities: Vec<(u64, u64)>,
    /// See [`Quarantine::unverified`].
    pub unverified: Vec<(u64, u64)>,
    /// See [`Quarantine::damaged`].
    pub damaged: Vec<Record>,
    /// The record kept before it in this segment, if any.
    pub before: Option<(u64, u64)>,
    /// The record kept after it.
    pub after: (u64, u64),
}

impl Recovered {
    /// Whether the scan stopped on a genuine torn tail — an incomplete final record a crash left
    /// behind, with nothing verifying past it. That, and only that, is damage cut away silently.
    pub fn was_torn(&self) -> bool {
        self.verdict == TailVerdict::Torn
    }

    /// Whether the scan met acknowledged damage anywhere in the segment.
    pub fn was_corrupt(&self) -> bool {
        matches!(self.verdict, TailVerdict::Corrupt { .. })
    }
}

/// Scan `segment` from its beginning and report every complete, verifying record, reading past
/// acknowledged damage to the records behind it.
///
/// This does not modify anything. [`recover_and_truncate`] is the one that cuts.
pub fn scan(segment: &Segment) -> io::Result<Recovered> {
    let len = segment.len()?;
    let mut records: Vec<Record> = Vec::new();
    let mut holes: Vec<Hole> = Vec::new();
    let mut from = 0u64;
    loop {
        let Walk {
            records: run,
            durable_end,
            stopped_because,
            stop_at,
        } = walk(segment, from, usize::MAX)?;
        records.extend(run);

        let beyond = look_past(segment, durable_end, stop_at, len)?;
        // Corrupt when anything is past the verified prefix and either a subsequent commit
        // acknowledges the damaged one or the damage is not a shape a crash leaves. See the module
        // preamble.
        let corrupt =
            beyond.written_end > durable_end && (beyond.acknowledged || !beyond.unfinished_only);
        if corrupt {
            // Acknowledged damage with a record behind it: read past it, and keep reading.
            if let Some((resume, after)) =
                resync(segment, durable_end, stop_at, beyond.written_end)?
            {
                let in_hole = look_past(segment, durable_end, stop_at, resume)?;
                let SetAside {
                    identities,
                    unverified,
                    damaged,
                } = set_aside(segment, durable_end, resume, in_hole)?;
                holes.push(Hole {
                    offset: durable_end,
                    damage_at: stop_at,
                    end: resume,
                    why: stopped_because,
                    identities,
                    unverified,
                    damaged,
                    before: records.last().map(Record::identity),
                    after,
                });
                from = resume;
                continue;
            }
        }

        let written_end = beyond.written_end;
        let SetAside {
            identities: identities_beyond,
            unverified: unverified_beyond,
            damaged,
        } = if corrupt {
            set_aside(segment, durable_end, len, beyond)?
        } else {
            SetAside {
                identities: beyond.identities,
                unverified: Vec::new(),
                damaged: Vec::new(),
            }
        };
        let tail = if corrupt {
            TailVerdict::Corrupt { at: stop_at }
        } else if written_end > durable_end {
            TailVerdict::Torn
        } else {
            TailVerdict::Clean
        };
        let verdict = holes
            .first()
            .map_or(tail, |h| TailVerdict::Corrupt { at: h.damage_at });
        return Ok(Recovered {
            records,
            durable_end,
            discarded_bytes: len.saturating_sub(durable_end),
            stopped_because,
            verdict,
            tail,
            holes,
            quarantined: Vec::new(),
            written_end,
            identities_beyond,
            unverified_beyond,
            damaged,
        });
    }
}

/// The identities and records a set-aside stretch `[from, until)` holds: every identity a frame in
/// it carries (the altered record's first, it is the one the caller asks about), the ones no
/// verified header vouches for, and its records as they now read.
fn set_aside(segment: &Segment, from: u64, until: u64, mut beyond: Beyond) -> io::Result<SetAside> {
    let set_aside = read_set_aside(segment, from, until)?;
    // Every set-aside identity is named, the altered record's first: it was acknowledged, and it
    // is the one the caller asks about.
    for id in set_aside.iter().rev().map(|(r, _)| r.identity()) {
        if let Some(i) = beyond.identities.iter().position(|x| *x == id) {
            beyond.identities.remove(i);
        }
        beyond.identities.insert(0, id);
    }
    // An identity no verified header vouches for is named, never trusted to number by.
    let mut unverified = Vec::new();
    let vouched = |id: &(u64, u64)| {
        beyond.verified.contains(id)
            || set_aside
                .iter()
                .any(|(r, checked)| *checked && r.identity() == *id)
    };
    for id in set_aside.iter().map(|(r, _)| r.identity()) {
        if !vouched(&id) && !unverified.contains(&id) {
            unverified.push(id);
        }
    }
    let damaged = set_aside.into_iter().map(|(r, _)| r).collect();
    Ok(SetAside {
        identities: beyond.identities,
        unverified,
        damaged,
    })
}

/// What a set-aside stretch holds. See [`Quarantine`] for each field.
struct SetAside {
    identities: Vec<(u64, u64)>,
    unverified: Vec<(u64, u64)>,
    damaged: Vec<Record>,
}

/// The first record behind damage: the offset of the first frame at or past `stop_at` (and past
/// the record the damage is in) that verifies, opens a record, and starts one whose every frame
/// verifies — and that record's identity. `None` when no complete record lies before `until`.
///
/// Read in blocks, because the stretch may be long and is mostly frames that do not verify.
fn resync(
    segment: &Segment,
    durable_end: u64,
    stop_at: u64,
    until: u64,
) -> io::Result<Option<(u64, (u64, u64))>> {
    const BLOCK_FRAMES: usize = 128;
    let mut at = u64::max(stop_at, durable_end + FRAME_BYTES as u64);
    let mut block = vec![0u8; BLOCK_FRAMES * FRAME_BYTES];
    while at < until {
        let want = usize::try_from(u64::min(until - at, block.len() as u64)).unwrap_or(block.len());
        let mut filled = 0usize;
        while filled < want {
            let n = segment.read_at(at + filled as u64, &mut block[filled..want])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled < FRAME_BYTES {
            return Ok(None);
        }
        for (i, chunk) in block[..filled].chunks(FRAME_BYTES).enumerate() {
            let chunk_at = at + (i * FRAME_BYTES) as u64;
            let Ok(whole) = <&[u8; FRAME_BYTES]>::try_from(chunk) else {
                continue;
            };
            let Ok((header, _)) = decode_frame(whole) else {
                continue;
            };
            if header.part_index != 0 {
                continue;
            }
            let walked = walk(segment, chunk_at, 1)?;
            if let Some(first) = walked.records.first() {
                return Ok(Some((chunk_at, first.identity())));
            }
        }
        at += (filled - filled % FRAME_BYTES) as u64;
    }
    Ok(None)
}

/// The complete, verifying records of `segment` from `from` (a record boundary) on, at most `limit`
/// of them, and where the walk stopped: the frame it could not take, or the leftover short of one.
struct Walk {
    records: Vec<Record>,
    /// The offset the last complete record returned ends at.
    durable_end: u64,
    stopped_because: Option<FrameError>,
    stop_at: u64,
}

/// Walk `segment` from `from`, assembling records across continuation frames, until the writes end,
/// a frame does not verify, or `limit` records are complete. The one reader of a segment's records:
/// a restart's scan walks from the start with no limit, and the store's catch-up reads a run of
/// them from where it left off.
fn walk(segment: &Segment, from: u64, limit: usize) -> io::Result<Walk> {
    let mut records = Vec::new();
    let mut offset: u64 = from;
    let mut durable_end: u64 = from;
    let mut stopped_because = None;
    // The record currently being assembled across continuation frames.
    let mut partial: Option<Partial> = None;
    let mut frame = [0u8; FRAME_BYTES];
    // Where the scan stopped: the frame it could not take, or the leftover short of one.
    let mut stop_at: u64;

    loop {
        stop_at = offset;
        let read = read_full(segment, offset, &mut frame)?;
        if !read {
            // Fewer bytes left than one frame. The writes end here; there is nothing to report as
            // damage beyond the leftover bytes, which the discard count already names.
            break;
        }
        let (header, payload) = match decode_frame(&frame) {
            Ok(decoded) => decoded,
            Err(FrameError::NotAFrame) if frame.iter().all(|&b| b == 0) => {
                // Zeros: preallocated space that was never written to. The ordinary end.
                break;
            }
            Err(e) => {
                stopped_because = Some(e);
                break;
            }
        };
        let mismatch = FrameError::BadParts {
            index: header.part_index,
            count: header.part_count,
        };
        match partial.as_mut() {
            None => {
                if header.part_index != 0 {
                    // A continuation with no head in front of it. The head was lost, so this is not
                    // a record — it is the tail of one that never completed.
                    stopped_because = Some(mismatch);
                    break;
                }
                partial = Some(Partial {
                    node: header.node,
                    node_seq: header.node_seq,
                    part_count: header.part_count,
                    next_part: 1,
                    body: payload.to_vec(),
                });
            }
            Some(open) => {
                if header.node != open.node
                    || header.node_seq != open.node_seq
                    || header.part_count != open.part_count
                    || header.part_index != open.next_part
                {
                    stopped_because = Some(mismatch);
                    break;
                }
                open.next_part += 1;
                open.body.extend_from_slice(payload);
            }
        }
        offset += FRAME_BYTES as u64;
        if !header.more_parts {
            if let Some(open) = partial.take() {
                records.push(Record {
                    node: open.node,
                    node_seq: open.node_seq,
                    body: open.body,
                });
                durable_end = offset;
                if records.len() >= limit {
                    stop_at = offset;
                    break;
                }
            }
        }
    }
    Ok(Walk {
        records,
        durable_end,
        stopped_because,
        stop_at,
    })
}

/// The complete, verifying records of `segment` from byte `from` — the start of a record — at most
/// `limit` of them, and the offset the last one ends at (`from` when there are none). What the log
/// re-reads from its own medium to hand a store the records it is still owed.
///
/// A hole recovery set aside is read past, as [`scan`] reads past it: the records behind it are
/// owed like any other, and stopping at it would leave them unshipped while the reader moved on to
/// the next segment.
pub(crate) fn records_from(
    segment: &Segment,
    from: u64,
    limit: usize,
) -> io::Result<(Vec<Record>, u64)> {
    let mut at = from;
    loop {
        let walked = walk(segment, at, limit)?;
        if !walked.records.is_empty() {
            return Ok((walked.records, walked.durable_end));
        }
        let len = segment.len()?;
        match resync(segment, at, walked.stop_at, len)? {
            Some((next, _)) => at = next,
            None => return Ok((Vec::new(), at)),
        }
    }
}

/// Every record in `[from, len)`, read frame by frame through each frame's full verification or its
/// HEADER CHECK, payloads joined as they now read, each with whether every one of its frames' headers
/// checked.
/// A WHOLE frame whose header does not check is read as its bytes stand ([`unchecked_whole`]): it
/// was acknowledged, so its identity is named and its record is handed over rather than dropped —
/// a caller that cannot decode it holds back what it cannot rule out, which is the safe side. Its
/// identity is unverified (`false`). A frame that is none of these is skipped, and so is a record
/// whose parts do not run in order.
fn read_set_aside(segment: &Segment, from: u64, len: u64) -> io::Result<Vec<(Record, bool)>> {
    let mut frame = [0u8; FRAME_BYTES];
    let mut at = from;
    let mut records = Vec::new();
    let mut open: Option<(u64, u64, u32, Vec<u8>, bool)> = None;
    while at < len && read_full(segment, at, &mut frame)? {
        at += FRAME_BYTES as u64;
        let read = match decode_frame(&frame) {
            Ok((header, payload)) => Some((header, payload.to_vec(), true)),
            Err(_) => checked_header(&frame)
                .map(|(header, payload)| (header, payload.to_vec(), true))
                .or_else(|| {
                    unchecked_whole(&frame)
                        .map(|(header, payload)| (header, payload.to_vec(), false))
                }),
        };
        let Some((header, payload, checked)) = read else {
            open = None;
            continue;
        };
        match open.as_mut() {
            Some((node, node_seq, next, body, all_checked))
                if header.node == *node
                    && header.node_seq == *node_seq
                    && header.part_index == *next =>
            {
                *next += 1;
                body.extend_from_slice(&payload);
                *all_checked &= checked;
            }
            _ if header.part_index == 0 => {
                open = Some((header.node, header.node_seq, 1, payload, checked));
            }
            _ => {
                open = None;
                continue;
            }
        }
        if !header.more_parts {
            if let Some((node, node_seq, _, body, all_checked)) = open.take() {
                records.push((Record::new(node, node_seq, body), all_checked));
            }
        }
    }
    Ok(records)
}

/// What lies past the verified prefix.
struct Beyond {
    /// The end of the last frame-sized chunk that holds a non-zero byte.
    written_end: u64,
    /// Whether a verifying frame that OPENS a commit lies past the frame the scan stopped on: a
    /// commit written after the damaged one, which therefore synced.
    acknowledged: bool,
    /// Whether every frame past the prefix is one a crash can leave: verifying (a frame of the torn
    /// commit that landed), or a write of this layout that never reached the frame's end. A short
    /// remainder at the end of the backing counts too: the backing simply stops there.
    unfinished_only: bool,
    /// The identities every verifying frame past the prefix carries, deduplicated, in the order
    /// they were met.
    identities: Vec<(u64, u64)>,
    /// The same identities, as the set a fully verified frame vouches for. `identities` is the list
    /// the quarantine names, which gains the set-aside records' own; this one never does.
    verified: Vec<(u64, u64)>,
}

/// Walk `[from, len)` a frame at a time: note where the written bytes end, whether a subsequent commit
/// verifies past `stop_at`, and whether every frame is one a crash can leave. Read in blocks,
/// because on an ordinary boot this walks the zeros claimed ahead of the writes and a read per
/// frame would be a read per 512 bytes.
fn look_past(segment: &Segment, from: u64, stop_at: u64, len: u64) -> io::Result<Beyond> {
    const BLOCK_FRAMES: usize = 128;
    let mut beyond = Beyond {
        written_end: from,
        acknowledged: false,
        unfinished_only: true,
        identities: Vec::new(),
        verified: Vec::new(),
    };
    let mut block = vec![0u8; BLOCK_FRAMES * FRAME_BYTES];
    let mut at = from;
    while at < len {
        let want = usize::try_from(u64::min(len - at, block.len() as u64)).unwrap_or(block.len());
        let mut filled = 0usize;
        while filled < want {
            let n = segment.read_at(at + filled as u64, &mut block[filled..want])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        for (i, chunk) in block[..filled].chunks(FRAME_BYTES).enumerate() {
            let chunk_at = at + (i * FRAME_BYTES) as u64;
            if chunk.iter().any(|&b| b != 0) {
                beyond.written_end = chunk_at + chunk.len() as u64;
            }
            let Ok(whole) = <&[u8; FRAME_BYTES]>::try_from(chunk) else {
                continue;
            };
            match decode_frame(whole) {
                Ok((header, _)) => {
                    // A verifying frame AT the stop is one the scan refused for where it sits (a
                    // part out of order), which no crash writes.
                    if chunk_at == stop_at {
                        beyond.unfinished_only = false;
                    }
                    // Frames before the stop are the head of a record that never completed: they
                    // verify on their own, belong to the damaged commit, and still carry an
                    // identity the set-aside bytes hold.
                    if chunk_at > stop_at && header.opens_commit {
                        beyond.acknowledged = true;
                    }
                    let id = (header.node, header.node_seq);
                    if !beyond.identities.contains(&id) {
                        beyond.identities.push(id);
                        beyond.verified.push(id);
                    }
                }
                Err(_) if unfinished_write(whole) => {}
                Err(_) => beyond.unfinished_only = false,
            }
        }
        at += filled as u64;
    }
    Ok(beyond)
}

/// Scan, then make the backing agree with the scan — branching on WHY it stopped.
///
/// - Every hole is copied, byte for byte, into a quarantine `factory` makes durable, and LEFT IN
///   PLACE: the records behind it are kept, and the next scan reads past it again.
/// - A torn tail (the last commit, torn by a crash), or a clean end with space claimed ahead of
///   it, is cut silently back to the last kept record.
/// - A corrupt tail is copied the same way and NEVER cut: the segment is closed to writes instead,
///   so the next append rolls past it and the damaged bytes stay exactly where they are.
/// - A copy that cannot be made closes the segment to writes as well, whatever the tail: the bytes
///   it could not copy are the only ones there are, and nothing is written into their segment.
///
/// After this returns the backing holds the records reported, the damage set aside in place, and —
/// past the last kept record — nothing an append could land on but space the cut freed.
///
/// `clock` is the composition root's wall clock in unix milliseconds. It is read once, and only
/// when something is set aside, to stamp when; this crate never reads a clock itself.
pub fn recover_and_truncate(
    segment: &mut Segment,
    factory: &mut dyn SegmentFactory,
    clock: crate::wal::Clock,
) -> io::Result<Recovered> {
    let mut recovered = scan(segment)?;
    set_aside_in_place(segment, &mut recovered, factory, clock)?;
    match recovered.tail {
        // A crash mid-commit, or space claimed ahead of the writes. Nothing past the last kept
        // record was acknowledged.
        TailVerdict::Torn | TailVerdict::Clean => segment.truncate_to(recovered.durable_end)?,
        TailVerdict::Corrupt { .. } => segment.close_to_writes(),
    }
    if recovered
        .quarantined
        .iter()
        .any(|q| matches!(q.kept, QuarantineKept::InPlace(_)))
    {
        segment.close_to_writes();
    }
    Ok(recovered)
}

/// Scan a segment the log no longer writes to — one below the tail — and set aside whatever
/// acknowledged damage it holds, cutting nothing. Its holes and a corrupt tail are copied into a
/// quarantine exactly as [`recover_and_truncate`] copies them; the segment itself is left as it is.
///
/// A torn remainder at the end of a closed segment is not set aside: a segment is closed past its
/// last commit only by a roll, which is either a full segment or a lost sync, and the batch a lost
/// sync tore is written again, whole, in the next segment.
pub fn quarantine_in_place(
    segment: &Segment,
    factory: &mut dyn SegmentFactory,
    clock: crate::wal::Clock,
) -> io::Result<Recovered> {
    let mut recovered = scan(segment)?;
    set_aside_in_place(segment, &mut recovered, factory, clock)?;
    Ok(recovered)
}

/// Copy every hole, and a corrupt tail, into a quarantine, and note each in
/// [`Recovered::quarantined`]. Nothing in `segment` is changed.
fn set_aside_in_place(
    segment: &Segment,
    recovered: &mut Recovered,
    factory: &mut dyn SegmentFactory,
    clock: crate::wal::Clock,
) -> io::Result<()> {
    let tail = match recovered.tail {
        TailVerdict::Corrupt { at } => Some(at),
        _ => None,
    };
    if recovered.holes.is_empty() && tail.is_none() {
        return Ok(());
    }
    let at_unix_ms = clock();
    let segment_file = factory.segment_file(segment.index());
    let mut quarantined = Vec::new();
    for hole in &recovered.holes {
        let (bytes, kept) = copy_aside(segment, factory, hole.offset, hole.end, at_unix_ms)?;
        quarantined.push(Quarantine {
            segment: segment.index(),
            segment_file: segment_file.clone(),
            offset: hole.offset,
            damage_at: hole.damage_at,
            bytes,
            why: hole.why,
            identities: hole.identities.clone(),
            unverified: hole.unverified.clone(),
            damaged: hole.damaged.clone(),
            at_unix_ms,
            kept,
            before: hole.before,
            after: Some(hole.after),
        });
    }
    if let Some(at) = tail {
        let offset = recovered.durable_end;
        let (bytes, kept) =
            copy_aside(segment, factory, offset, recovered.written_end, at_unix_ms)?;
        quarantined.push(Quarantine {
            segment: segment.index(),
            segment_file,
            offset,
            damage_at: at,
            bytes,
            why: recovered.stopped_because,
            identities: recovered.identities_beyond.clone(),
            unverified: recovered.unverified_beyond.clone(),
            damaged: recovered.damaged.clone(),
            at_unix_ms,
            kept,
            before: recovered.records.last().map(Record::identity),
            after: None,
        });
    }
    recovered.quarantined = quarantined;
    Ok(())
}

/// Copy `[from, until)` of `segment` into a quarantine `factory` makes durable, and say where it
/// went and how many bytes it holds. A copy that cannot be made is answered, not raised: the bytes
/// are still in the segment, which nothing cuts.
fn copy_aside(
    segment: &Segment,
    factory: &mut dyn SegmentFactory,
    from: u64,
    until: u64,
    at_unix_ms: u64,
) -> io::Result<(u64, QuarantineKept)> {
    let mut copy = vec![0u8; usize::try_from(until.saturating_sub(from)).unwrap_or(usize::MAX)];
    let mut filled = 0usize;
    while filled < copy.len() {
        let n = segment.read_at(from + filled as u64, &mut copy[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    copy.truncate(filled);
    let kept = match factory.quarantine(segment.index(), from, at_unix_ms, &copy) {
        Ok(Some(path)) => QuarantineKept::File(path),
        Ok(None) => QuarantineKept::Memory,
        Err(e) => QuarantineKept::InPlace(e.to_string()),
    };
    Ok((copy.len() as u64, kept))
}

/// Read exactly one frame, or report that there is not a whole one left.
fn read_full(segment: &Segment, offset: u64, frame: &mut [u8; FRAME_BYTES]) -> io::Result<bool> {
    let mut filled = 0usize;
    while filled < FRAME_BYTES {
        let n = segment.read_at(offset + filled as u64, &mut frame[filled..])?;
        if n == 0 {
            return Ok(false);
        }
        filled += n;
    }
    Ok(true)
}

/// The record being assembled across continuation frames.
struct Partial {
    node: u64,
    node_seq: u64,
    part_count: u32,
    /// The part index the next frame of this record must carry.
    next_part: u32,
    body: Vec<u8>,
}
