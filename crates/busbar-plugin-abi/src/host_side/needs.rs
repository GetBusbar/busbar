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
