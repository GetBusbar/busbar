// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn pending(n: u32) -> Pending {
    let mut id = [0; 16];
    id[..4].copy_from_slice(&n.to_be_bytes());
    Pending {
        snapshot: UnitCheckpoint {
            id,
            revision: 0,
            unit: u64::from(n),
            principal: "p".into(),
            group: "g".into(),
            arrived: 0,
            lane: "l".into(),
            provider: None,
            era_at: 0,
            era_entry: None,
            units: BTreeMap::new(),
            targets: vec![UnitTarget {
                bucket: "b".into(),
                window: 1,
                group: None,
            }],
            metered: false,
            ended: false,
            terminal: None,
            audit: None,
            measurement: None,
        },
        persisted: None,
        recovered: false,
    }
}

/// C3: the admission check walks no pending checkpoint while none is recovered.
#[test]
fn admission_visits_flat() {
    let visits = |n: u32| {
        let book = UnitCheckpointBook::default();
        {
            let mut book = book.pending.lock().unwrap();
            for i in 0..n {
                let p = pending(i);
                book.insert(p.snapshot.id, p);
            }
        }
        let before = book.pending.lock().unwrap().visits();
        assert!(!book.unresolved("b", 1));
        book.pending.lock().unwrap().visits() - before
    };
    assert_eq!(visits(10), visits(100_000));
}
