// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Export request encoders and answer decoders (IF §8.8, round 33 §49).
//!
//! Wire notes the IF leaves to this file:
//! - A `deliver` request is one generic `TEXT` record per line, in line order, the body exactly the line (no
//!   newline), so a line's record index is the `i` of the stable per-line key `(delivery, i)`.
//! - A `render` snapshot is one `M_FAMILY` record per family: `FamilyRec` then nested `M_NAME`, `M_HELP` and
//!   `M_SAMPLE*`; each `M_SAMPLE` is `SampleRec` then nested `M_LABEL*` (pair shape).
//! - Every grammar violation in an answer or a describe is a `RecErr` the adapter turns into FAULT `BadRecords`:
//!   `Size` for a record that does not belong where it stands (or a value out of range), `Truncated` for a missing
//!   required record, `Unknown` for a tag this position does not know. Generic `METRIC` records ride any answer
//!   and are skipped here (`decode_metrics` reads them).

use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::kinds::export::export::FamilyRec;
use busbar_plugin_abi::kinds::export::export::{
    tag, Ack, AppendRec, CustodyRec, DeliveryRec, CUSTODY_ACCEPTED, CUSTODY_INDEXED, M_CONFIRM,
    SAMPLE_BUCKET, SAMPLE_QUANTILE, STREAM_CONTENT,
};
use busbar_plugin_abi::records::{tag as generic, Full, RecErr, Records, Writer};

use crate::export::FamilyIn;

/// A record head and body into `out`, padded to the 8-byte record grid (the layout `Records` reads).
fn put_rec(out: &mut Vec<u8>, tag: u16, parts: &[&[u8]]) -> Result<(), Full> {
    let len = parts.iter().map(|p| p.len()).sum::<usize>();
    let len32 = u32::try_from(len).map_err(|_| Full)?;
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&len32.to_le_bytes());
    for part in parts {
        out.extend_from_slice(part);
    }
    out.resize(out.len() + (8 - len % 8) % 8, 0);
    Ok(())
}

/// A `deliver` request: one `TEXT` record per line.
pub fn encode_batch(w: &mut impl Writer, lines: &[&[u8]]) -> Result<(), Full> {
    for line in lines {
        w.put(generic::TEXT, line)?;
    }
    Ok(())
}

/// A `render` request: the metric snapshot, one `M_FAMILY` per family.
pub fn encode_snapshot(w: &mut impl Writer, families: &[FamilyIn<'_>]) -> Result<(), Full> {
    for family in families {
        let mut tail = Vec::new();
        put_rec(&mut tail, tag::M_NAME, &[family.name.as_bytes()])?;
        put_rec(&mut tail, tag::M_HELP, &[family.help.as_bytes()])?;
        for sample in family.samples {
            let mut labels = Vec::new();
            for (name, value) in sample.labels {
                let name_len = u32::try_from(name.len()).map_err(|_| Full)?;
                put_rec(
                    &mut labels,
                    tag::M_LABEL,
                    &[
                        &name_len.to_le_bytes(),
                        &[0; 4],
                        name.as_bytes(),
                        value.as_bytes(),
                    ],
                )?;
            }
            // `bound` is the bucket `le` or the quantile `q`; NaN for every other role.
            let bound = if sample.role == SAMPLE_BUCKET || sample.role == SAMPLE_QUANTILE {
                sample.bound
            } else {
                f64::NAN
            };
            put_rec(
                &mut tail,
                tag::M_SAMPLE,
                &[
                    &sample.value.to_le_bytes(),
                    &bound.to_le_bytes(),
                    &sample.ts_ms.to_le_bytes(),
                    &sample.role.to_le_bytes(),
                    &[0; 4],
                    &labels,
                ],
            )?;
        }
        w.put_pod_tail(
            tag::M_FAMILY,
            &FamilyRec {
                kind: family.kind,
                _r: 0,
            },
            &tail,
        )?;
    }
    Ok(())
}

/// A CUSTODY record read as a `CustodyRec`, its level checked to be ACCEPTED..=INDEXED.
fn custody(rec: busbar_plugin_abi::records::Rec<'_>) -> Result<CustodyRec, RecErr> {
    let rec = rec.pod::<CustodyRec>()?;
    if rec.level < CUSTODY_ACCEPTED || rec.level > CUSTODY_INDEXED {
        return Err(RecErr::Size);
    }
    Ok(rec)
}

type Delivered<'o> = (u64, Option<(u32, &'o [u8])>, Option<CustodyRec>);

fn delivered<'o>(mut recs: Records<'o>, confirm: bool) -> Result<Delivered<'o>, RecErr> {
    let mut append = None;
    let mut accepted = None;
    let mut seen = None;
    while let Some(next) = recs.next_rec() {
        let rec = next?;
        match rec.tag {
            tag::APPEND => {
                if append.is_some() || accepted.is_some() {
                    return Err(RecErr::Size);
                }
                let (head, tail) = rec.pod_tail::<AppendRec>()?;
                if head._r != 0 {
                    return Err(RecErr::Reserved);
                }
                append = Some((head.dest, tail));
            }
            tag::ACK => {
                if accepted.is_some() {
                    return Err(RecErr::Size);
                }
                accepted = Some(rec.pod::<Ack>()?.accepted);
            }
            tag::CUSTODY => {
                // After ACK only, never after APPEND, once.
                if accepted.is_none() || append.is_some() || seen.is_some() {
                    return Err(RecErr::Size);
                }
                let found = custody(rec)?;
                if found.recheck_s > 0 && !confirm {
                    return Err(RecErr::Size);
                }
                seen = Some(found);
            }
            generic::METRIC => {}
            other => return Err(RecErr::Unknown(other)),
        }
    }
    let accepted = accepted.ok_or(RecErr::Truncated)?;
    Ok((accepted, append, seen))
}

/// Round 7: ACK, or APPEND then ACK (§8.5). Borrowed tail; the adapter copies only a non-empty tail.
/// Round 33: plus the optional CUSTODY after ACK. CUSTODY after APPEND, CUSTODY_NONE or a level above INDEXED,
/// a second CUSTODY, or `recheck_s > 0` when `confirm` (the image declared M_CONFIRM) is false: RecErr.
pub fn decode_delivered<'o>(a: &Answer<'o>, confirm: bool) -> Result<Delivered<'o>, RecErr> {
    delivered(a.records(), confirm)
}

fn confirmed(recs: Records<'_>) -> Result<CustodyRec, RecErr> {
    let mut found = None;
    for next in recs {
        let rec = next?;
        match rec.tag {
            tag::CUSTODY if found.is_none() => {
                let value = rec.pod::<CustodyRec>()?;
                if value.level > CUSTODY_INDEXED {
                    return Err(RecErr::Size);
                }
                found = Some(value);
            }
            generic::METRIC => {}
            tag::CUSTODY => return Err(RecErr::Size),
            other => return Err(RecErr::Unknown(other)),
        }
    }
    found.ok_or(RecErr::Truncated)
}

/// IF §8.5: a bytes-free confirm answers exactly one CUSTODY, including NONE.
pub fn decode_confirmed(a: &Answer<'_>) -> Result<CustodyRec, RecErr> {
    confirmed(a.records())
}

/// The most deliveries an export instance may hold pending custody (DES-EXPORT-1.6 r3 #236). Bookkeeping only:
/// bytes are bounded by the content budget. A describe above it refuses the instance at admit; core never clamps.
pub const PENDING_CAPACITY_MAX: u64 = 4096;

/// Round 33: D_DELIVERY's `pending_capacity` (None when absent), with §8.5's describe rules checked in the
/// same pass as D_STREAMS and FB_SPAN_RECORDS: M_CONFIRM ⇔ D_DELIVERY, STREAM_CONTENT declared, no D_DEST_PATH,
/// `1..=PENDING_CAPACITY_MAX` (refused above it, never clamped: #236), at most one. In 1.6.0 L7 calls it for the
/// validation only; the value is kept from 1.6.x.
pub fn decode_delivery(describe: Records<'_>, methods: u64) -> Result<Option<u64>, RecErr> {
    let mut capacity = None;
    let mut content = false;
    let mut dest = false;
    let mut streams = false;
    for next in describe {
        let rec = next?;
        match rec.tag {
            tag::D_STREAMS => {
                if streams {
                    return Err(RecErr::Size);
                }
                streams = true;
                content = rec.body.iter().any(|&id| u32::from(id) == STREAM_CONTENT);
            }
            tag::D_DELIVERY => {
                if capacity.is_some() {
                    return Err(RecErr::Size);
                }
                let pending = rec.pod::<DeliveryRec>()?.pending_capacity;
                if pending == 0 || pending > PENDING_CAPACITY_MAX {
                    return Err(RecErr::Size);
                }
                capacity = Some(pending);
            }
            generic::D_DEST_PATH => dest = true,
            _ => {}
        }
    }
    let confirm = methods & M_CONFIRM != 0;
    if confirm != capacity.is_some() || (confirm && (!content || dest)) {
        return Err(RecErr::Size);
    }
    Ok(capacity)
}

fn ceiling(mut recs: Records<'_>) -> Result<Option<u32>, RecErr> {
    let mut level = None;
    while let Some(next) = recs.next_rec() {
        let rec = next?;
        // The ceiling is the answer's last record: anything after it, a second CUSTODY included, is out of place.
        if level.is_some() {
            return Err(RecErr::Size);
        }
        if rec.tag == tag::CUSTODY {
            let found = custody(rec)?;
            if found.recheck_s != 0 {
                return Err(RecErr::Size);
            }
            level = Some(found.level);
        }
    }
    Ok(level)
}

/// Round 33: an export `open` answer's last CUSTODY (the ceiling): level 1..=3, `recheck_s` 0, at most one.
pub fn decode_ceiling(a: &Answer<'_>) -> Result<Option<u32>, RecErr> {
    ceiling(a.records())
}

#[cfg(test)]
mod tests {
    use busbar_plugin_abi::kinds::export::export::{SampleRec, CUSTODY_DURABLE, CUSTODY_NONE};
    use busbar_plugin_abi::records::Reply;

    use super::*;
    use crate::export::SampleIn;

    fn ack(w: &mut Reply, accepted: u64) {
        w.put_pod(tag::ACK, &Ack { accepted }).unwrap();
    }
    fn cust(w: &mut Reply, level: u32, recheck_s: u32) {
        w.put_pod(tag::CUSTODY, &CustodyRec { level, recheck_s })
            .unwrap();
    }
    fn run(w: &Reply, confirm: bool) -> Result<Delivered<'_>, RecErr> {
        delivered(Records::new(w.as_bytes()), confirm)
    }

    #[test]
    fn confirm_accepts_none_and_each_positive_custody_level() {
        for level in CUSTODY_NONE..=CUSTODY_INDEXED {
            let mut w = Reply::new();
            cust(&mut w, level, 7);
            let found = confirmed(Records::new(w.as_bytes())).unwrap();
            assert_eq!((found.level, found.recheck_s), (level, 7));
        }
    }

    #[test]
    fn confirm_refuses_missing_duplicate_or_out_of_range_custody() {
        assert!(confirmed(Records::new(&[])).is_err());
        let mut w = Reply::new();
        cust(&mut w, CUSTODY_INDEXED + 1, 0);
        assert!(confirmed(Records::new(w.as_bytes())).is_err());
        let mut w = Reply::new();
        cust(&mut w, CUSTODY_ACCEPTED, 0);
        cust(&mut w, CUSTODY_INDEXED, 0);
        assert!(confirmed(Records::new(w.as_bytes())).is_err());
    }

    #[test]
    fn confirm_does_not_accept_a_delivery_ack_or_body() {
        let mut w = Reply::new();
        ack(&mut w, 1);
        cust(&mut w, CUSTODY_INDEXED, 0);
        assert!(confirmed(Records::new(w.as_bytes())).is_err());
        let mut w = Reply::new();
        cust(&mut w, CUSTODY_INDEXED, 0);
        w.put(tag::BODY, b"must not be returned on confirm")
            .unwrap();
        assert!(confirmed(Records::new(w.as_bytes())).is_err());
    }

    #[test]
    fn an_ack_alone_and_with_custody() {
        let mut w = Reply::new();
        ack(&mut w, 5);
        let (accepted, append, found) = run(&w, false).unwrap();
        assert_eq!((accepted, append), (5, None));
        assert!(found.is_none());
        cust(&mut w, CUSTODY_DURABLE, 0);
        let (accepted, append, found) = run(&w, false).unwrap();
        assert_eq!((accepted, append), (5, None));
        let found = found.unwrap();
        assert_eq!((found.level, found.recheck_s), (CUSTODY_DURABLE, 0));
    }

    #[test]
    fn append_then_ack_carries_the_tail() {
        let mut w = Reply::new();
        w.put_pod_tail(tag::APPEND, &AppendRec { dest: 2, _r: 0 }, b"x\n")
            .unwrap();
        ack(&mut w, 1);
        let (accepted, append, found) = run(&w, false).unwrap();
        assert_eq!((accepted, append), (1, Some((2, &b"x\n"[..]))));
        assert!(found.is_none());
    }

    #[test]
    fn custody_grammar_faults() {
        // After APPEND.
        let mut w = Reply::new();
        w.put_pod_tail(tag::APPEND, &AppendRec { dest: 1, _r: 0 }, b"")
            .unwrap();
        ack(&mut w, 1);
        cust(&mut w, 1, 0);
        assert!(run(&w, true).is_err());
        // NONE, and a level above INDEXED.
        for level in [CUSTODY_NONE, 4] {
            let mut w = Reply::new();
            ack(&mut w, 1);
            cust(&mut w, level, 0);
            assert!(run(&w, true).is_err());
        }
        // Twice.
        let mut w = Reply::new();
        ack(&mut w, 1);
        cust(&mut w, 1, 0);
        cust(&mut w, 1, 0);
        assert!(run(&w, true).is_err());
        // recheck_s without M_CONFIRM, and with it.
        let mut w = Reply::new();
        ack(&mut w, 1);
        cust(&mut w, 1, 30);
        assert!(run(&w, false).is_err());
        assert_eq!(run(&w, true).unwrap().2.unwrap().recheck_s, 30);
        // Before ACK, and no ACK at all.
        let mut w = Reply::new();
        cust(&mut w, 1, 0);
        ack(&mut w, 1);
        assert!(run(&w, true).is_err());
        let mut w = Reply::new();
        cust(&mut w, 1, 0);
        assert!(run(&w, true).is_err());
    }

    #[test]
    fn the_ceiling_is_one_last_custody() {
        let open = |build: &dyn Fn(&mut Reply)| {
            let mut w = Reply::new();
            w.put_pod(
                generic::INSTANCE,
                &busbar_plugin_abi::records::InstanceRec { inst: 1 },
            )
            .unwrap();
            build(&mut w);
            ceiling(Records::new(w.as_bytes()))
        };
        assert_eq!(open(&|_| {}).unwrap(), None);
        assert_eq!(open(&|w| cust(w, 2, 0)).unwrap(), Some(2));
        assert!(open(&|w| cust(w, 0, 0)).is_err());
        assert!(open(&|w| cust(w, 4, 0)).is_err());
        assert!(open(&|w| cust(w, 1, 5)).is_err());
        assert!(open(&|w| {
            cust(w, 1, 0);
            cust(w, 1, 0);
        })
        .is_err());
        assert!(open(&|w| {
            cust(w, 1, 0);
            w.put_text(generic::TEXT, "late").unwrap();
        })
        .is_err());
    }

    #[test]
    fn a_batch_is_one_text_record_per_line() {
        let mut w = Reply::new();
        encode_batch(&mut w, &[b"{\"a\":1}", b"", b"{\"b\":2}"]).unwrap();
        let bodies = Records::new(w.as_bytes())
            .map(|r| {
                let r = r.unwrap();
                assert_eq!(r.tag, generic::TEXT);
                r.body.to_vec()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            bodies,
            [b"{\"a\":1}".to_vec(), Vec::new(), b"{\"b\":2}".to_vec()]
        );
    }

    #[test]
    fn a_snapshot_round_trips_its_families() {
        let samples = [
            SampleIn {
                value: 3.0,
                bound: 0.5,
                ts_ms: 7,
                role: SAMPLE_BUCKET,
                labels: &[("le", "0.5"), ("route", "a")],
            },
            SampleIn {
                value: 4.0,
                bound: 9.0,
                ts_ms: 8,
                role: 0,
                labels: &[],
            },
        ];
        let families = [FamilyIn {
            kind: 3,
            name: "latency",
            help: "how long",
            samples: &samples,
        }];
        let mut w = Reply::new();
        encode_snapshot(&mut w, &families).unwrap();
        let mut top = Records::new(w.as_bytes());
        let family = top.next().unwrap().unwrap();
        assert!(top.next().is_none());
        assert_eq!(family.tag, tag::M_FAMILY);
        let (head, tail) = family.pod_tail::<FamilyRec>().unwrap();
        assert_eq!((head.kind, head._r), (3, 0));
        let mut nested = Records::new(tail);
        assert_eq!(nested.next().unwrap().unwrap().text().unwrap(), "latency");
        assert_eq!(nested.next().unwrap().unwrap().text().unwrap(), "how long");
        let first = nested.next().unwrap().unwrap();
        let (rec, labels) = first.pod_tail::<SampleRec>().unwrap();
        assert_eq!(
            (rec.value, rec.bound, rec.ts_ms, rec.role),
            (3.0, 0.5, 7, SAMPLE_BUCKET)
        );
        let pairs = Records::new(labels)
            .map(|l| {
                let (k, v) = l.unwrap().pair().unwrap();
                (k.to_string(), v.to_vec())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            pairs,
            [
                ("le".to_string(), b"0.5".to_vec()),
                ("route".to_string(), b"a".to_vec())
            ]
        );
        let second = nested.next().unwrap().unwrap();
        let (rec, labels) = second.pod_tail::<SampleRec>().unwrap();
        assert!(rec.bound.is_nan());
        assert!(labels.is_empty());
        assert!(nested.next().is_none());
    }
}
