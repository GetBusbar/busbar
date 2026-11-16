// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Decoded Need values, the Need result writer and the `Needs` trait core implements (IF §10.3). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H1 fills it.

use core::marker::PhantomData;

use crate::host_side::caller::Caller;
use crate::host_side::pool::PooledOut;
use crate::records::Records;

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
pub struct NeedOut<'r> {
    // W0-ABI: private fields (&'r mut PooledOut, record start, cap for this op) land with W1-H1.
    _stub: PhantomData<&'r mut PooledOut>,
}
impl NeedOut<'_> {
    /// The NeedResRec a/b values (default 0/0).
    pub fn set(&mut self, a: u64, b: u64) {
        let _ = (a, b);
        todo!()
    }
    /// Append to data0. Then data1 (switching is one-way). Over the op's cap => Err(NeedErr::Limit).
    pub fn put0(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        let _ = bytes;
        todo!()
    }
    pub fn put1(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        let _ = bytes;
        todo!()
    }
    /// A nested PAIR record in data0 (RECORD LIST) or data1 (FETCH headers).
    pub fn pair0(&mut self, name: &[u8], value: &[u8]) -> Result<(), NeedErr> {
        let _ = (name, value);
        todo!()
    }
    pub fn pair1(&mut self, name: &str, value: &[u8]) -> Result<(), NeedErr> {
        let _ = (name, value);
        todo!()
    }
    /// Zero-copy read target: up to `max` writable bytes at the end of data0; then `commit0(n)`.
    pub fn spare0(&mut self, max: usize) -> &mut [u8] {
        let _ = max;
        todo!()
    }
    pub fn commit0(&mut self, n: usize) {
        let _ = n;
        todo!()
    }
}

/// Core's I/O, custody and records, as seen by the step driver. Every method enforces cx.deadline itself.
/// No method retries (§12.3). Not dyn: `Driver`/`Registry` are generic over `N: Needs` (the binary picks
/// HostNeeds, the test crate FakeNeeds), so no Need step is boxed (I5).
pub trait Needs: Send + Sync + 'static {
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
