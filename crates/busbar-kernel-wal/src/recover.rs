// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reading a segment back after a crash, and cutting away whatever the crash left behind.

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
    pub fn was_torn(&self) -> bool {
        self.verdict == TailVerdict::Torn
    }

    /// Whether the scan met acknowledged damage anywhere in the segment.
    pub fn was_corrupt(&self) -> bool {
        matches!(self.verdict, TailVerdict::Corrupt { .. })
    }
}

/// Scan `segment` from its beginning and report every complete, verifying record, reading past
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

        let corrupt =
            beyond.written_end > durable_end && (beyond.acknowledged || !beyond.unfinished_only);
        if corrupt {
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
fn set_aside(segment: &Segment, from: u64, until: u64, mut beyond: Beyond) -> io::Result<SetAside> {
    let set_aside = read_set_aside(segment, from, until)?;

    for id in set_aside.iter().rev().map(|(r, _)| r.identity()) {
        if let Some(i) = beyond.identities.iter().position(|x| *x == id) {
            beyond.identities.remove(i);
        }
        beyond.identities.insert(0, id);
    }

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
struct Walk {
    records: Vec<Record>,
    /// The offset the last complete record returned ends at.
    durable_end: u64,
    stopped_because: Option<FrameError>,
    stop_at: u64,
}

/// Walk `segment` from `from`, assembling records across continuation frames, until the writes end,
fn walk(segment: &Segment, from: u64, limit: usize) -> io::Result<Walk> {
    let mut records = Vec::new();
    let mut offset: u64 = from;
    let mut durable_end: u64 = from;
    let mut stopped_because = None;

    let mut partial: Option<Partial> = None;
    let mut frame = [0u8; FRAME_BYTES];

    let mut stop_at: u64;

    loop {
        stop_at = offset;
        let read = read_full(segment, offset, &mut frame)?;
        if !read {
            break;
        }
        let (header, payload) = match decode_frame(&frame) {
            Ok(decoded) => decoded,
            Err(FrameError::NotAFrame) if frame.iter().all(|&b| b == 0) => {
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
    acknowledged: bool,
    /// Whether every frame past the prefix is one a crash can leave: verifying (a frame of the torn
    unfinished_only: bool,
    /// The identities every verifying frame past the prefix carries, deduplicated, in the order
    identities: Vec<(u64, u64)>,
    /// The same identities, as the set a fully verified frame vouches for. `identities` is the list
    verified: Vec<(u64, u64)>,
}

/// Walk `[from, len)` a frame at a time: note where the written bytes end, whether a subsequent commit
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
                    if chunk_at == stop_at {
                        beyond.unfinished_only = false;
                    }

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
pub fn recover_and_truncate(
    segment: &mut Segment,
    factory: &mut dyn SegmentFactory,
    clock: crate::wal::Clock,
) -> io::Result<Recovered> {
    let mut recovered = scan(segment)?;
    set_aside_in_place(segment, &mut recovered, factory, clock)?;
    match recovered.tail {
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
