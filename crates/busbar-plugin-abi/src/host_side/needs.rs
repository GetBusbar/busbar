// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Decoded Need values, the Need result writer and the `Needs` trait core implements (IF §10.3; W1-H1). The
//! NeedRec decode table that produces these values is the driver's (`driver.rs`, IF §10.3 "owner H1, driver.rs").

use zerocopy::{FromZeros, IntoBytes};

use crate::host_side::caller::Caller;
use crate::host_side::pool::PooledOut;
use crate::need::{NeedResRec, need_status};
use crate::records::{Full, PairRec, RawWrite, RecHead, Records, tag};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConnId(pub u64);

#[derive(Clone, Copy, Debug)]
pub enum TlsMode<'a> {
    None,
    Required {
        sni: &'a str,
        alpn: &'a str,
        trust: u32,
    },
    Mutual {
        sni: &'a str,
        alpn: &'a str,
        trust: u32,
        cert: u32,
    },
    /// OPEN(TLS_INBAND): plaintext connect; the pool lookup uses the post-STARTTLS PoolKey (§6.1).
    Inband {
        sni: &'a str,
        alpn: &'a str,
        trust: u32,
        cert: Option<u32>,
    },
    // Round 29 (AGREED 133): round 28's `Unverified` arm is deleted; every TlsMode is verified.
}

/// `egress` (round 28; promised since r7) = the class the plugin STATED, NeedRec.flags bits 16..=19, 0..=4
/// (`egress::*`). The connector never uses it as the verdict: it computes `guard::judged_class(egress, configured)`.
#[derive(Clone, Copy, Debug)]
pub struct OpenNeed<'a> {
    pub dest: &'a str,
    pub tls: TlsMode<'a>,
    pub egress: u32,
}

// W0-ABI: the IF derives `Debug` on FetchNeed, RecordNeed and DirNeed, but `Records<'a>` (§3.1) derives only
// `Clone, Copy`; `Debug` is left off these three until records.rs gives `Records` a `Debug` impl.
#[derive(Clone, Copy)]
pub struct FetchNeed<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: Records<'a>,
    pub body: &'a [u8],
    pub max_body: u64,
    pub trust: u32,
    pub cert: Option<u32>,
    pub egress: u32,
}

#[derive(Clone, Copy)]
pub enum RecordNeed<'a> {
    Get(&'a [u8]),
    Put(&'a [u8], &'a [u8], u64),
    Claim(&'a [u8], &'a [u8], u64),
    Del(&'a [u8]),
    List(&'a [u8], u32),
    /// The nested REC_PRED*/REC_PUT*/REC_DEL* records, validated by the driver (≤ commit::MAX_OPS).
    Commit(Records<'a>),
}

/// Round 29: a decoded DIRECTORY Need (§6.1), validated by the driver (op, kind and flag ranges, the op's arg set,
/// caps; anything else INVALID before the handler). `kind` = `dir::SUBJECT | GROUP | MEMBER`. Index and member lists
/// stay borrowed nested records (PAIR*, DM_*) the handler walks; nothing is copied.
#[derive(Clone, Copy)]
pub enum DirNeed<'a> {
    Get {
        kind: u32,
        id: &'a str,
    },
    Lookup {
        kind: u32,
        index: &'a str,
        value: &'a [u8],
    },
    Scan {
        kind: u32,
        scope: &'a str,
        after: &'a str,
        limit: u32,
    },
    Count {
        kind: u32,
        scope: &'a str,
    },
    Create {
        kind: u32,
        state: u32,
        pull: bool,
        document: &'a [u8],
        indexes: Records<'a>,
    },
    Apply {
        kind: u32,
        id: &'a str,
        expected_version: u64,
        apply: u32,
        state: u32,
        document: &'a [u8],
        indexes: Records<'a>,
        members: Records<'a>,
    },
    Delete {
        kind: u32,
        id: &'a str,
        expected_version: u64,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NeedErr {
    Denied,
    Unavailable,
    Timeout,
    Absent,
    Taken,
    Limit,
    Tls,
    Closed,
    Invalid,
}

/// Where a handler writes its result: straight into the chain's `ChainBufs::results`, so no intermediate Vec
/// exists and everything is zeroed on release (I11). The driver frames it as one NEED_RES record.
///
/// W1-H1: the driver opens the record (head and a zero `NeedResRec`) before the handler runs and closes it
/// after (`finish`): the head's length, the result's status, `a`/`b` and the two data lengths, zero padding to
/// 8. A non-OK result keeps no data (the plugin reads nothing but the status, §6.1). `cap` bounds data0 plus
/// data1 plus the record's padding, so the record always closes inside the room the driver reserved for it.
pub struct NeedOut<'r> {
    out: &'r mut PooledOut,
    /// Where the record starts in `out`.
    start: usize,
    /// Data bytes (both parts, padding included) this op may write.
    cap: usize,
    op: u32,
    a: u64,
    b: u64,
    lens: [u32; 2],
    /// Writing data1 (switching is one-way).
    second: bool,
}

/// The NEED_RES head plus its fixed Pod: where data0 begins, relative to the record start.
pub(crate) const RES_FIXED: usize = size_of::<RecHead>() + size_of::<NeedResRec>();

/// The `need_status` code of a handler error.
pub(crate) fn status_of(err: NeedErr) -> u32 {
    match err {
        NeedErr::Denied => need_status::DENIED,
        NeedErr::Unavailable => need_status::UNAVAILABLE,
        NeedErr::Timeout => need_status::TIMEOUT,
        NeedErr::Absent => need_status::ABSENT,
        NeedErr::Taken => need_status::TAKEN,
        NeedErr::Limit => need_status::LIMIT,
        NeedErr::Tls => need_status::TLS,
        NeedErr::Closed => need_status::CLOSED,
        NeedErr::Invalid => need_status::INVALID,
    }
}

impl<'r> NeedOut<'r> {
    /// Opens one NEED_RES record for `op` at the end of `out`, with `cap` data bytes allowed. Full: not even the
    /// fixed part fits (the driver reserves it, so this is a host bug it answers as a FAULT-free LIMIT).
    pub(crate) fn begin(out: &'r mut PooledOut, op: u32, cap: usize) -> Result<NeedOut<'r>, Full> {
        let start = out.written();
        out.room(RES_FIXED)?;
        let head = RecHead {
            tag: tag::NEED_RES,
            _r: 0,
            len: 0,
        };
        out.append(head.as_bytes());
        out.append(NeedResRec::new_zeroed().as_bytes());
        Ok(NeedOut {
            out,
            start,
            cap: cap & !7,
            op,
            a: 0,
            b: 0,
            lens: [0; 2],
            second: false,
        })
    }

    /// Data bytes written so far, both parts.
    fn data(&self) -> usize {
        self.out.written() - self.start - RES_FIXED
    }

    /// Room for `n` more data bytes within the op's cap (padding counted) and the buffer.
    fn reserve(&mut self, n: usize) -> Result<(), NeedErr> {
        let total = self.data().checked_add(n).ok_or(NeedErr::Limit)?;
        let padded = total.next_multiple_of(8);
        if padded > self.cap {
            return Err(NeedErr::Limit);
        }
        self.out
            .room(padded - self.data())
            .map_err(|_| NeedErr::Limit)
    }

    fn grow_len(&mut self, part: usize, n: usize) -> Result<(), NeedErr> {
        let n = u32::try_from(n).map_err(|_| NeedErr::Limit)?;
        let len = self.lens.get_mut(part).ok_or(NeedErr::Invalid)?;
        *len = len.checked_add(n).ok_or(NeedErr::Limit)?;
        Ok(())
    }

    /// Appends `parts` back to back to data0 (`part` 0) or data1 (1).
    fn put(&mut self, part: usize, parts: &[&[u8]]) -> Result<(), NeedErr> {
        if part == 0 && self.second {
            return Err(NeedErr::Invalid);
        }
        let n = parts
            .iter()
            .try_fold(0usize, |n, p| n.checked_add(p.len()))
            .ok_or(NeedErr::Limit)?;
        self.reserve(n)?;
        for p in parts {
            self.out.append(p);
        }
        if part == 1 {
            self.second = true;
        }
        self.grow_len(part, n)
    }

    /// One nested PAIR record (head, PairRec, name, value, zero padding) in data0 or data1.
    fn pair(&mut self, part: usize, name: &[u8], value: &[u8]) -> Result<(), NeedErr> {
        let body = size_of::<PairRec>()
            .checked_add(name.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(NeedErr::Limit)?;
        let head = RecHead {
            tag: tag::PAIR,
            _r: 0,
            len: u32::try_from(body).map_err(|_| NeedErr::Limit)?,
        };
        let pair = PairRec {
            name_len: u32::try_from(name.len()).map_err(|_| NeedErr::Limit)?,
            _r: 0,
        };
        let pad = body.next_multiple_of(8) - body;
        self.put(
            part,
            &[
                head.as_bytes(),
                pair.as_bytes(),
                name,
                value,
                &[0u8; 8][..pad],
            ],
        )
    }

    /// Closes the record: OK keeps its data and values; any other status drops them (zeroed) and keeps only the
    /// status. Pads the body to 8 and writes the head's length and the `NeedResRec`.
    pub(crate) fn finish(mut self, status: u32) {
        if status != need_status::OK {
            self.out.truncate(self.start + RES_FIXED);
            self.a = 0;
            self.b = 0;
            self.lens = [0; 2];
        }
        let body = self.out.written() - self.start - size_of::<RecHead>();
        let pad = body.next_multiple_of(8) - body;
        if pad > 0 && self.out.room(pad).is_ok() {
            self.out.append(&[0u8; 8][..pad]);
        }
        let len = u32::try_from(body).unwrap_or(u32::MAX);
        self.out.patch(
            self.start + core::mem::offset_of!(RecHead, len),
            len.as_bytes(),
        );
        let res = NeedResRec {
            op: self.op,
            status,
            a: self.a,
            b: self.b,
            lens: self.lens,
            _r: 0,
        };
        self.out
            .patch(self.start + size_of::<RecHead>(), res.as_bytes());
    }
}

impl NeedOut<'_> {
    /// The NeedResRec a/b values (default 0/0).
    pub fn set(&mut self, a: u64, b: u64) {
        self.a = a;
        self.b = b;
    }
    /// Append to data0. Then data1 (switching is one-way). Over the op's cap => Err(NeedErr::Limit).
    pub fn put0(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        self.put(0, &[bytes])
    }
    pub fn put1(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        self.put(1, &[bytes])
    }
    /// A nested PAIR record in data0 (RECORD LIST) or data1 (FETCH headers).
    pub fn pair0(&mut self, name: &[u8], value: &[u8]) -> Result<(), NeedErr> {
        self.pair(0, name, value)
    }
    pub fn pair1(&mut self, name: &str, value: &[u8]) -> Result<(), NeedErr> {
        self.pair(1, name.as_bytes(), value)
    }
    /// Zero-copy read target: up to `max` writable bytes at the end of data0; then `commit0(n)`.
    ///
    /// W1-H1: empty once data1 has started, and clipped to the op's cap; every byte handed out is zeroed on
    /// release whether or not it is committed.
    pub fn spare0(&mut self, max: usize) -> &mut [u8] {
        if self.second {
            return &mut [];
        }
        let left = self.cap.saturating_sub(self.data().next_multiple_of(8));
        let n = max.min(left).min(u32::MAX as usize - self.lens[0] as usize);
        self.out.spare(n).unwrap_or(&mut [])
    }
    /// Counts `n` bytes of the last `spare0` as data0 (never more than it handed out).
    pub fn commit0(&mut self, n: usize) {
        if self.second {
            return;
        }
        let before = self.out.written();
        self.out.commit(n);
        let added = self.out.written() - before;
        let _ = self.grow_len(0, added);
    }
}

/// Core's I/O, custody and records, as seen by the step driver. Every method enforces cx.deadline itself.
/// No method retries (§12.3). Not dyn: `Driver`/`Registry` are generic over `N: Needs` (the binary picks
/// HostNeeds, the test crate FakeNeeds), so no Need step is boxed (I5).
pub trait Needs: Send + Sync + 'static {
    /// Host-only final instance retirement after its leased root work drains. No wire ABI entry.
    fn retire(&self, _instance: u64) {}
    /// a = conn id, b = open_flag bits, data0 = negotiated ALPN, data1 = the pooled-conn id
    /// (round 19: `res.put1(&id.to_le_bytes())`, exactly `open_flag::POOLED_ID_LEN` bytes, §6.1).
    fn open(
        &self,
        cx: &Caller<'_>,
        n: OpenNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send;
    /// b = open_flag bits, data0 = negotiated ALPN.
    fn starttls(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        tls: TlsMode<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send;
    /// a = bytes written.
    fn write(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        bytes: &[u8],
        res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send;
    /// data0 = at least 1 byte, a = bytes read; or EOF: a = 0, b = 1.
    fn read(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        max: u32,
        res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send;
    fn close(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        reusable: bool,
    ) -> impl core::future::Future<Output = ()> + Send;
    /// a = HTTP status, data0 = body, data1 = PAIR* headers.
    fn fetch(
        &self,
        cx: &Caller<'_>,
        n: FetchNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send;
    /// handle = the NeedRec.secret value, resolved in cx.instance's binding table only. data0 = value.
    fn secret(
        &self,
        cx: &Caller<'_>,
        handle: u32,
        res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send;
    /// a = 1 if found / won. data0 = value (GET) or PAIR* (LIST). COMMIT: a = outcome, b = failed index.
    fn record(
        &self,
        cx: &Caller<'_>,
        n: RecordNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send;
    /// Round 29: a = `code | index << 32`, b = version or count, data0 per `dir`, data1 = `DirFacts` (16 bytes).
    /// The kernel directory of (cx.plugin, cx.name) only (§12.29). Denied: no `provisioning:` block.
    fn directory(
        &self,
        cx: &Caller<'_>,
        n: DirNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send;
    /// The chain ended (OK, REFUSED, FAILED, FAULT, Steps, Deadline) or was cancelled: close (non-reusable) every
    /// conn it still holds and drop its rows. Sync, never fails. Round 16: the `ChainGuard` calls it exactly once
    /// per chain that made at least one NEED, whatever ended it, and never for a chain that made none (§10.5).
    fn release(&self, cx: &Caller<'_>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_side::pool::Pool;
    use crate::need::op;
    use zerocopy::FromBytes;

    /// The one NEED_RES record in `buf`: its Pod and its data (data0 then data1).
    fn record(buf: &PooledOut) -> (NeedResRec, Vec<u8>) {
        let mut recs = Records::new(buf.bytes());
        let rec = recs.next().expect("one record").expect("framed");
        assert!(recs.next().is_none(), "exactly one record");
        assert_eq!(rec.tag, tag::NEED_RES);
        let (res, data) = NeedResRec::read_from_prefix(rec.body).expect("NeedResRec");
        (res, data.to_vec())
    }

    #[test]
    fn an_ok_result_keeps_its_values_and_both_parts_in_order() {
        let mut buf = Pool::global().acquire(1 << 20);
        let mut out = NeedOut::begin(&mut buf, op::OPEN, 4096).expect("room");
        out.set(7, 1);
        out.put0(b"h2").expect("alpn");
        out.put1(&9u64.to_le_bytes()).expect("pooled id");
        assert_eq!(
            out.put0(b"late"),
            Err(NeedErr::Invalid),
            "switching is one-way"
        );
        out.finish(need_status::OK);
        let (res, data) = record(&buf);
        assert_eq!((res.op, res.status, res.a, res.b), (op::OPEN, 0, 7, 1));
        assert_eq!(res.lens, [2, 8]);
        assert_eq!(&data[..2], b"h2");
        assert_eq!(&data[2..10], &9u64.to_le_bytes());
        assert_eq!(buf.bytes().len() % 8, 0, "padded to 8");
    }

    #[test]
    fn a_failed_result_keeps_only_its_status_and_zeroes_the_data() {
        let mut buf = Pool::global().acquire(1 << 20);
        let mut out = NeedOut::begin(&mut buf, op::SECRET, 4096).expect("room");
        out.set(1, 2);
        out.put0(b"a half-written secret").expect("data");
        out.finish(need_status::DENIED);
        let (res, data) = record(&buf);
        assert_eq!(
            (res.status, res.a, res.b, res.lens),
            (need_status::DENIED, 0, 0, [0, 0])
        );
        assert!(data.is_empty());
        let len = buf.bytes().len();
        assert!(
            buf.whole()[len..].iter().all(|&b| b == 0),
            "the dropped data is zero"
        );
    }

    #[test]
    fn the_op_cap_counts_padding_and_answers_limit() {
        let mut buf = Pool::global().acquire(1 << 20);
        let mut out = NeedOut::begin(&mut buf, op::READ, 16).expect("room");
        out.put0(&[1u8; 9]).expect("9 bytes pad to 16");
        assert_eq!(out.put0(&[1u8; 8]), Err(NeedErr::Limit));
        out.put0(&[1u8; 7]).expect("16 exactly");
        assert_eq!(out.put0(&[1u8]), Err(NeedErr::Limit));
        out.finish(need_status::OK);
        assert_eq!(record(&buf).0.lens, [16, 0]);
    }

    #[test]
    fn pairs_are_nested_records_and_spare_reads_land_in_place() {
        let mut buf = Pool::global().acquire(1 << 20);
        let mut out = NeedOut::begin(&mut buf, op::FETCH, 1 << 16).expect("room");
        let spare = out.spare0(5);
        assert_eq!(spare.len(), 5);
        spare.copy_from_slice(b"body!");
        out.commit0(4);
        out.pair1("content-type", b"text/plain").expect("header");
        out.pair1("x-a", b"").expect("header");
        assert!(out.spare0(3).is_empty(), "no data0 once data1 started");
        out.finish(need_status::OK);
        let (res, data) = record(&buf);
        assert_eq!(res.lens[0], 4);
        assert_eq!(&data[..4], b"body");
        let headers: Vec<(String, Vec<u8>)> = Records::new(&data[4..4 + res.lens[1] as usize])
            .map(|rec| {
                let rec = rec.expect("framed");
                assert_eq!(rec.tag, tag::PAIR);
                let (name, value) = rec.pair().expect("pair");
                (name.to_owned(), value.to_vec())
            })
            .collect();
        assert_eq!(
            headers,
            [
                ("content-type".to_owned(), b"text/plain".to_vec()),
                ("x-a".to_owned(), Vec::new())
            ]
        );
    }

    #[test]
    fn every_handler_error_has_its_status() {
        let all = [
            (NeedErr::Denied, need_status::DENIED),
            (NeedErr::Unavailable, need_status::UNAVAILABLE),
            (NeedErr::Timeout, need_status::TIMEOUT),
            (NeedErr::Absent, need_status::ABSENT),
            (NeedErr::Taken, need_status::TAKEN),
            (NeedErr::Limit, need_status::LIMIT),
            (NeedErr::Tls, need_status::TLS),
            (NeedErr::Closed, need_status::CLOSED),
            (NeedErr::Invalid, need_status::INVALID),
        ];
        for (err, status) in all {
            assert_eq!(status_of(err), status);
        }
    }
}
