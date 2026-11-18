// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::auth;
use crate::host::HostFns;
use crate::need::NeedResRec;
use crate::plugin::__rt::host::{OpenAnswer, OutLease, Resumed};
use crate::plugin::__rt::image::Admitted;
use crate::plugin::__rt::kind as marker;
use crate::records::{FailRec, Records};

static HOST: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: None,
        crypto: None,
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        migrate_admit: None,
    },
);

struct Fx;
impl crate::Auth for Fx {}
impl Open for Fx {
    async fn open(_: &'static Host, _: ChainBytes) -> Result<Self, Fail> {
        let port_bytes = *b"5432";
        let port = std::str::from_utf8(&port_bytes).unwrap();
        let parts = ["db.test", ":", port];
        let _ = crate::need::need::open_parts(&parts, crate::need::need::Tls::None, 2).await?;
        Ok(Fx)
    }
    fn check(_: &Host, config: &[u8], ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        let text = std::str::from_utf8(&config[2..]).unwrap();
        let (first, rest) = text.split_at(text.len() / 2);
        for _ in 0..config[1] {
            if config[0] == 0 {
                ends.open(text, need_flag::TLS_NONE, 2);
            } else {
                ends.open_parts(&[first, "", rest], need_flag::TLS_NONE, 2);
            }
        }
        Ok(())
    }
    fn describe(d: &mut Describe<'_>) {
        d.item_parts(
            auth::tag::D_STYLE_FLAGS,
            &[&auth::STYLE_PER_REQUEST.to_le_bytes(), b"sigv4"],
        );
        let prefix = auth::IssuedShapeRec {
            id_len: 20,
            secret_len: 40,
        };
        d.item_pod_nested(auth::tag::D_ISSUED_SHAPE, &prefix, |nested| {
            for text in ["AKIA", "ABC", "XYZ"] {
                nested.put_text(tag::TEXT, text)?;
            }
            Ok(())
        });
    }
}
crate::plugin!(@kind [crate::auth] Fx);

fn image() -> Admitted {
    Admitted::linked(&PLUGIN).unwrap()
}
fn answer(mode: u8, count: u8, text: &str) -> (Status, Vec<u8>) {
    let mut config = vec![mode, count];
    config.extend_from_slice(text.as_bytes());
    let mut out = OutLease::new(vec![0; 8192], 8192).unwrap();
    let OpenAnswer::Done(status, _) =
        image().open::<marker::Auth>(&HOST, config, OPEN_DRY_RUN, &mut out)
    else {
        panic!("check is synchronous")
    };
    (status, out.with_answer(<[u8]>::to_vec))
}

#[test]
fn endpoint_parts_preserve_check_limits_and_wire_bytes() {
    for text in [
        "",
        "db.test:5432",
        "127.0.0.1:0",
        "[::1]:65535",
        &"a".repeat(2048),
    ] {
        assert_eq!(answer(0, 1, text), answer(1, 1, text));
    }
    for (count, len, status) in [
        (1, 2048, Status::OK),
        (1, 2049, Status::REFUSED),
        (16, 4, Status::OK),
        (17, 4, Status::REFUSED),
    ] {
        let text = "a".repeat(len);
        let old = answer(0, count, &text);
        assert_eq!(old, answer(1, count, &text));
        assert_eq!(old.0, status);
    }
}

#[test]
fn describe_parts_and_pod_nested_preserve_whole_answer_limit_failure() {
    let mut out = OutLease::new(vec![0; 4096], 4096).unwrap();
    assert_eq!(image().describe(&HOST, &mut out), Status::OK);
    out.with_answer(|bytes| {
        let records = Records::new(bytes).map(Result::unwrap).collect::<Vec<_>>();
        assert_eq!(
            records[0].body,
            [auth::STYLE_PER_REQUEST.to_le_bytes().as_slice(), b"sigv4"].concat()
        );
        let (shape, tail) = records[1].pod_tail::<auth::IssuedShapeRec>().unwrap();
        assert_eq!((shape.id_len, shape.secret_len), (20, 40));
        assert_eq!(
            Records::new(tail)
                .map(|r| r.unwrap().text().unwrap())
                .collect::<Vec<_>>(),
            ["AKIA", "ABC", "XYZ"]
        );
    });
    drop(out);
    let mut small = OutLease::new(vec![0; 64], 64).unwrap();
    assert_eq!(image().describe(&HOST, &mut small), Status::FAILED);
    small.with_answer(|bytes| {
        let records = Records::new(bytes).map(Result::unwrap).collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tag, tag::FAIL);
        assert_eq!(
            records[0].pod_tail::<FailRec>().unwrap().0.code,
            failed::F_LIMIT
        );
    });
}

#[test]
fn local_open_parts_survive_pending_resume_and_cancellation() {
    let image = image();
    for complete in [false, true] {
        // One lease per open, as the host leases one per entry: a reused lease still holds the earlier
        // open's NEED and TOKEN, and the chain would take that (cancelled) token as its own.
        let mut out = OutLease::new(vec![0; 4096], 4096).unwrap();
        let OpenAnswer::Chain(mut chain) =
            image.open::<marker::Auth>(&HOST, Vec::new(), 0, &mut out)
        else {
            panic!("OPEN should suspend")
        };
        out.with_answer(|bytes| {
            let record = Records::new(bytes)
                .map(Result::unwrap)
                .find(|r| r.tag == tag::NEED)
                .unwrap();
            let (head, tail) = record.pod_tail::<crate::need::NeedRec>().unwrap();
            assert_eq!(&tail[..head.lens[0] as usize], b"db.test:5432");
        });
        if complete {
            let mut result = Reply::new();
            result
                .put_pod_tail(
                    tag::NEED_RES,
                    &NeedResRec {
                        op: op::OPEN,
                        status: 0,
                        a: 1,
                        b: 0,
                        lens: [0, 8],
                        _r: 0,
                    },
                    &0u64.to_le_bytes(),
                )
                .unwrap();
            assert!(matches!(
                chain.resume(result.as_bytes().to_vec(), &mut out),
                Resumed::Done(Status::OK, Some(_))
            ));
        }
        drop(chain);
    }
}
