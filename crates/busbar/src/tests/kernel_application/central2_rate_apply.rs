// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use busbar_contract::billing::RawTierRates;
use busbar_kernel::rate_apply::{rates_applied, RawRates};
use std::time::{Duration, Instant};
#[test]
fn the_actual_rate_holder_preserves_every_tier_unit_fee_and_present_empty_card() {
    const CHILD: &str = "BUSBAR_CENTRAL2_RATES_CHILD";
    const WITNESS: &str = "actual root rate view fidelity completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    assert!(
        busbar_kernel::preflight::root_rows().rate_apply.is_some(),
        "the actual root installs its real rate holder"
    );
    assert!(
        crate::root::kernel::ROOT_CARD.history().is_none(),
        "the isolated actual holder starts without a card"
    );
    let fast = RawTierRates {
        input: Some(1_000),
        output: Some(2_000),
        cache_read: Some(3_000),
        cache_write: Some(4_000),
    };
    let slow = RawTierRates {
        input: Some(5_000),
        output: Some(6_000),
        cache_read: Some(7_000),
        cache_write: Some(8_000),
    };
    let lanes = [("fast".to_string(), fast), ("slow".to_string(), slow)];
    let units = [("slow".to_string(), "search_units".to_string(), 5_000)];
    rates_applied(&RawRates {
        lanes: &lanes,
        units: &units,
        flat_minor: 11,
        present: true,
        plane_fees: &Default::default(),
    });
    let history = crate::root::kernel::ROOT_CARD
        .history()
        .expect("the actual apply publishes its card");
    assert_eq!(
        history.len(),
        1,
        "exactly one installed apply reaches the actual holder"
    );
    let card = history.entries()[0].card();
    assert_eq!(card.fee(), 11, "the resolved fee is carried verbatim");
    assert!(
        card.pricing_enabled(),
        "the resolved present flag is carried verbatim"
    );
    for (name, original) in &lanes {
        let rates = card
            .lane_rates(name)
            .expect("every supplied lane is present");
        for (class, expected) in [
            ("input", original.input),
            ("output", original.output),
            ("cache_read", original.cache_read),
            ("cache_write", original.cache_write),
        ] {
            assert!(
                rates.class_priced(class),
                "{name}.{class} remains explicitly priced"
            );
            assert_eq!(
                rates.nanos_per_unit(class),
                expected.unwrap(),
                "every supplied tier rate is delivered verbatim"
            );
        }
    }
    let slow_rates = card.lane_rates("slow").unwrap();
    assert!(slow_rates.class_priced("search_units"));
    assert_eq!(
        slow_rates.nanos_per_unit("search_units"),
        units[0].2,
        "the named unit rate is delivered verbatim"
    );
    assert!(
        !card
            .lane_rates("fast")
            .unwrap()
            .class_priced("search_units"),
        "a unit is not invented on another lane"
    );
    rates_applied(&RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 11,
        present: true,
        plane_fees: &Default::default(),
    });
    let history = crate::root::kernel::ROOT_CARD
        .history()
        .expect("the empty apply is carried");
    assert_eq!(history.len(), 2, "both actual applies are delivered once");
    let card = history.entries()[1].card();
    assert_eq!(card.fee(), 11);
    assert!(
        card.pricing_enabled(),
        "an empty lane list under a PRESENT card is not folded into absent"
    );
    assert!(
        card.lane_unpriced("fast") && card.lane_unpriced("slow"),
        "the empty apply retains no old lanes"
    );
    println!("{WITNESS}");
}
