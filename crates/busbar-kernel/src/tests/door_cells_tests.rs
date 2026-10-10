// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/metrics/door_cells.rs`: a door plane's breaker cells read
//! under the labels the plane stated, and on the scrape.

use super::*;

const NOW: u64 = 1_800_000_000;

fn d(id: u64) -> DestinationId {
    DestinationId::new(id)
}

/// A breaker whose pool `pool` holds members 7 (`a`) and 9 (`b`), member 9's cell tripped and
/// member 7's touched and closed, plus a cell under a pool with no stated label.
fn tripped(pool: &str, stated: &str) -> DoorBreaker {
    let unit = Arc::new(BreakerUnit::new());
    let _ = unit.cell(pool, d(7));
    unit.cell(pool, d(9)).hard_down(NOW, 600);
    let _ = unit.cell("not-stated", d(7));
    DoorBreaker {
        unit,
        pools: HashMap::from([(pool.to_string(), stated.to_string())]),
        lanes: HashMap::from([(d(7), "a".to_string()), (d(9), "b".to_string())]),
        models: HashMap::new(),
    }
}

#[test]
fn a_cell_reads_under_its_stated_labels() {
    let cells = DoorCells::new();
    cells.publish_breaker("plane-a", tripped("key-a", "sec/pool-a"));
    let mut readings = cells.cell_readings(NOW);
    readings.sort_by(|x, y| x.1.cmp(&y.1));
    assert_eq!(
        readings,
        vec![
            ("sec/pool-a".into(), "a".into(), BreakerState::Closed, 0),
            (
                "sec/pool-a".into(),
                "b".into(),
                BreakerState::Open { until: NOW + 600 },
                600
            ),
        ],
        "each cell reads alone, under the labels stated for it; a cell with none is not read"
    );
}

#[test]
fn a_spent_destination_reads_open_for_good() {
    let cells = DoorCells::new();
    let unit = Arc::new(BreakerUnit::new());
    unit.set_budget(d(3), 0);
    let _ = unit.cell("solo", d(3));
    cells.publish_breaker(
        "plane-b",
        DoorBreaker {
            unit,
            pools: HashMap::from([("solo".to_string(), "sec/solo".to_string())]),
            lanes: HashMap::from([(d(3), "solo".to_string())]),
            models: HashMap::new(),
        },
    );
    assert_eq!(
        cells.cell_readings(NOW),
        vec![(
            "sec/solo".into(),
            "solo".into(),
            BreakerState::Open { until: u64::MAX },
            0
        )]
    );
}

#[test]
fn a_newer_generation_replaces_the_older() {
    let cells = DoorCells::new();
    cells.publish_breaker("plane-c", tripped("key-c", "sec/c"));
    let fresh = Arc::new(BreakerUnit::new());
    let _ = fresh.cell("key-c", d(7));
    cells.publish_breaker(
        "plane-c",
        DoorBreaker {
            unit: fresh,
            pools: HashMap::from([("key-c".to_string(), "sec/c".to_string())]),
            lanes: HashMap::from([(d(7), "a".to_string())]),
            models: HashMap::new(),
        },
    );
    assert_eq!(
        cells.cell_readings(NOW),
        vec![("sec/c".into(), "a".into(), BreakerState::Closed, 0)],
        "the retired generation's tripped cell is not read"
    );
}

/// THE SCRAPE: a published door plane's tripped cell is a `busbar_lane_state` sample of 2 under
/// its stated labels, a healthy one 0, and no label value carries a control byte. RED with the
/// door-cells loop removed from `refresh_scrape_gauges`.
#[test]
fn a_door_planes_tripped_cell_is_on_the_scrape() {
    crate::metrics::init();
    let app = crate::test_support::TestApp::new().build();
    let now = busbar_kernel::store::now();
    let unit = Arc::new(BreakerUnit::new());
    let _ = unit.cell("k\u{1f}scrape", d(7));
    unit.cell("k\u{1f}scrape", d(9)).hard_down(now, 600);
    app.door_cells.publish_breaker(
        "plane-d",
        DoorBreaker {
            unit,
            pools: HashMap::from([("k\u{1f}scrape".to_string(), "sec-d/scrape".to_string())]),
            lanes: HashMap::from([(d(7), "ok-m".to_string()), (d(9), "down-m".to_string())]),
            models: HashMap::new(),
        },
    );
    crate::metrics::refresh_scrape_gauges(&app);
    let out = crate::metrics::render();
    let sample = |lane: &str| {
        out.lines()
            .find(|l| {
                l.starts_with("busbar_lane_state{")
                    && l.contains("pool=\"sec-d/scrape\"")
                    && l.contains(&format!("lane=\"{lane}\""))
            })
            .and_then(|l| l.rsplit(' ').next())
            .map(str::to_string)
    };
    assert_eq!(
        sample("down-m").as_deref(),
        Some("2"),
        "the tripped member:\n{out}"
    );
    assert_eq!(
        sample("ok-m").as_deref(),
        Some("0"),
        "the healthy member:\n{out}"
    );
    assert!(
        !out.contains('\u{1f}'),
        "no label value carries a control byte:\n{out}"
    );
}
