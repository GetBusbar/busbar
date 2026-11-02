// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::program::Expected;
use busbar_contract::conn::{
    PROGRAM_EXPECT_GENERATION_FIELD as GENERATION, PROGRAM_EXPECT_INSTANCE_FIELD as INSTANCE,
};

fn guarded_connector() -> Connector {
    let io = Arc::new(crate::hostio::HostIo::new());
    let mut connector = connector_over(TestDoor::identity("bytes").with_host_io(Arc::clone(&io)));
    connector.io = io;
    connector
}

#[test]
fn program_guard_counts_are_local_while_other_connectors_and_guards_run_in_parallel() {
    worker().block_on(async {
        let unrelated = connector();
        declare(&unrelated, &[("unrelated", sh(ECHO_PID, &[]))]).unwrap();
        let held = open(&unrelated, "unrelated", b"").unwrap();
        let _pair = observed_pair(&unrelated, held).await;
        let results = std::thread::scope(|scope| {
            let cold = scope
                .spawn(a_guarded_open_never_spawns_and_only_the_exact_live_pair_receives_its_body);
            let replaced = scope.spawn(
                a_changed_member_and_an_ended_generation_cannot_be_restarted_by_a_stale_guard,
            );
            (cold.join(), replaced.join())
        });
        unrelated.close(OWNER, held).unwrap();
        unrelated.forget(OWNER);
        assert!(results.0.is_ok(), "cold/live pair guard fixture failed");
        assert!(
            results.1.is_ok(),
            "replacement/ended pair guard fixture failed"
        );
    });
}

async fn observed_pair(c: &Connector, id: ConnId) -> Expected {
    let mut bytes = [0; 512];
    let piece = read(c, id, &mut bytes).await.unwrap();
    assert_eq!(piece.kind, PieceKind::Fields);
    let fields: std::collections::BTreeMap<_, _> = std::str::from_utf8(&bytes[..piece.len])
        .unwrap()
        .lines()
        .map(|line| line.split_once(": ").unwrap())
        .collect();
    Expected {
        instance: fields["program-instance"].parse().unwrap(),
        generation: fields["generation"].parse().unwrap(),
    }
}

fn guarded(c: &Connector, expected: Expected, body: &[u8]) -> Result<ConnId, ConnError> {
    let instance = expected.instance.to_string();
    let generation = expected.generation.to_string();
    c.open(
        OWNER,
        NEED,
        &OpenDesc {
            target: "m",
            fields: &[
                (INSTANCE, instance.as_bytes()),
                (GENERATION, generation.as_bytes()),
            ],
            body: busbar_contract::conn::Bytes::copy_from_slice(body),
            ..OpenDesc::default()
        },
    )
}

#[test]
fn program_constraints_require_one_complete_canonical_pair() {
    assert_eq!(Expected::of(&[]), Ok(None));
    assert_eq!(
        Expected::of(&[(INSTANCE, b"42"), (GENERATION, b"3")]),
        Ok(Some(Expected {
            instance: 42,
            generation: 3
        }))
    );
    let invalid: Vec<Vec<(&str, &[u8])>> = vec![
        vec![(INSTANCE, b"1")],
        vec![(GENERATION, b"1")],
        vec![
            (INSTANCE, b"1"),
            (GENERATION, b"1"),
            ("PROGRAM-EXPECT-INSTANCE", b"1"),
        ],
        vec![(INSTANCE, b"1"), (GENERATION, b"1"), (GENERATION, b"1")],
        vec![(INSTANCE, b"0"), (GENERATION, b"1")],
        vec![(INSTANCE, b"01"), (GENERATION, b"1")],
        vec![(INSTANCE, b"+1"), (GENERATION, b"1")],
        vec![(INSTANCE, b"1 "), (GENERATION, b"1")],
        vec![(INSTANCE, b"18446744073709551616"), (GENERATION, b"1")],
        vec![(INSTANCE, b"1"), (GENERATION, b"")],
        vec![(INSTANCE, b"1"), (GENERATION, b"-1")],
        vec![(" program-expect-instance", b"1"), (GENERATION, b"1")],
        vec![
            (INSTANCE, b"1"),
            (GENERATION, b"1"),
            ("unrecognized", b"value"),
        ],
    ];
    for fields in invalid {
        assert_eq!(Expected::of(&fields), Err(ConnError::Refused), "{fields:?}");
    }
}

#[test]
fn a_guarded_open_never_spawns_and_only_the_exact_live_pair_receives_its_body() {
    worker().block_on(async {
        let c = guarded_connector();
        declare(&c, &[("m", sh(ECHO_PID, &[]))]).unwrap();
        let member = Arc::clone(
            c.over
                .lock()
                .unwrap()
                .get(&(OWNER, NEED))
                .unwrap()
                .members
                .as_ref()
                .unwrap()
                .get("m")
                .unwrap(),
        );
        let cold = Expected {
            instance: member.supervision_key,
            generation: 1,
        };
        assert_eq!(
            guarded(&c, cold, b"MUST-NOT-SPAWN\n"),
            Err(ConnError::Refused)
        );
        assert_eq!(c.io.held(), 0);
        assert_eq!(member.lock().generation, 0);
        let monitor = open(&c, "m", b"").unwrap();
        let pair = observed_pair(&c, monitor).await;
        let accepted = guarded(&c, pair, b"accepted\n").unwrap();
        assert_eq!(observed_pair(&c, accepted).await, pair);
        let mut heard = Vec::new();
        assert!(line(&c, monitor, &mut heard)
            .await
            .unwrap()
            .ends_with(" accepted"));
        for stale in [
            Expected {
                instance: pair.instance + 1,
                ..pair
            },
            Expected {
                generation: pair.generation + 1,
                ..pair
            },
        ] {
            assert_eq!(
                guarded(&c, stale, b"MUST-NOT-SEND\n"),
                Err(ConnError::Refused)
            );
        }
        let after = guarded(&c, pair, b"after\n").unwrap();
        assert_eq!(observed_pair(&c, after).await, pair);
        assert!(
            line(&c, monitor, &mut heard)
                .await
                .unwrap()
                .ends_with(" after"),
            "a refused body's output reached the already-open monitor"
        );
        for id in [monitor, accepted, after] {
            c.close(OWNER, id).unwrap();
        }
        c.forget(OWNER);
    });
}

#[test]
fn a_changed_member_and_an_ended_generation_cannot_be_restarted_by_a_stale_guard() {
    worker().block_on(async {
        let c = guarded_connector();
        let script = "while read l; do if [ \"$l\" = end ]; then exit 0; fi; echo \"$$ $l\"; done";
        declare(&c, &[("m", sh(script, &[]))]).unwrap();
        let old = open(&c, "m", b"").unwrap();
        let before = observed_pair(&c, old).await;
        declare(
            &c,
            &[("m", sh(script, &[("VERSION", "changed-private-recipe")]))],
        )
        .unwrap();
        assert_eq!(
            guarded(&c, before, b"MUST-NOT-SPAWN\n"),
            Err(ConnError::Refused)
        );
        assert_eq!(
            c.io.held(),
            1,
            "only the old member's still-leased child remains"
        );
        let new = open(&c, "m", b"").unwrap();
        let current = observed_pair(&c, new).await;
        assert!(current.instance > before.instance);
        assert_eq!(current.generation, 1);
        c.close(OWNER, old).unwrap();
        assert_eq!(c.write(OWNER, new, b"end\n", false, false), Ok(4));
        assert_eq!(line(&c, new, &mut Vec::new()).await, None);
        assert_eq!(
            guarded(&c, current, b"MUST-NOT-RESPAWN\n"),
            Err(ConnError::Refused)
        );
        assert_eq!(c.io.held(), 0);
        let fresh = open(&c, "m", b"").unwrap();
        let next = observed_pair(&c, fresh).await;
        assert_eq!(next.instance, current.instance);
        assert_eq!(next.generation, 2);
        assert_eq!(
            guarded(&c, current, b"MUST-NOT-SEND\n"),
            Err(ConnError::Refused)
        );
        for id in [new, fresh] {
            c.close(OWNER, id).unwrap();
        }
        c.forget(OWNER);
    });
}

#[test]
fn program_constraint_fields_never_reach_a_network_open() {
    worker().block_on(async {
        let door = TestDoor::identity("bytes");
        let c = Connector::serving(
            Transports::new(vec![Entry {
                door: Arc::new(door),
                alpn: Vec::new(),
            }])
            .unwrap(),
            crate::tests::loopback_literals(),
            None,
            Arc::new(|_, _| {}),
        );
        c.declare_need(OWNER, NEED, "bytes", crate::DEFAULT_CLASS)
            .unwrap();
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = server.local_addr().unwrap().to_string();
        let positive = c
            .open(
                OWNER,
                NEED,
                &OpenDesc {
                    target: &at,
                    ..OpenDesc::default()
                },
            )
            .unwrap();
        let (peer, _) = tokio::time::timeout(Duration::from_secs(5), server.accept())
            .await
            .unwrap()
            .unwrap();
        c.close(OWNER, positive).unwrap();
        drop(peer);
        for name in [
            INSTANCE,
            GENERATION,
            "PROGRAM-EXPECT-INSTANCE",
            " program-expect-generation ",
        ] {
            assert_eq!(
                c.open(
                    OWNER,
                    NEED,
                    &OpenDesc {
                        target: &at,
                        fields: &[(name, b"1")],
                        body: busbar_contract::conn::Bytes::copy_from_slice(b"MUST-NOT-SEND"),
                        ..OpenDesc::default()
                    }
                ),
                Err(ConnError::Refused)
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(25), server.accept())
                .await
                .is_err(),
            "a host-only constraint opened a network connection"
        );
    });
}
