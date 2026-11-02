use super::*;
use std::sync::Mutex;

struct Recorder(Mutex<Vec<Seen>>);

type Seen = (
    Vec<(String, RawTierRates)>,
    Vec<(String, String, u64)>,
    i64,
    bool,
);

impl RateApply for Recorder {
    fn prepare(
        &self,
        _: &CardFields,
        _: &RawRates<'_>,
        _: &str,
    ) -> Result<Box<dyn PreparedRates>, String> {
        Ok(Box::new(NoRates))
    }

    fn rates_applied(&self, rates: &RawRates<'_>) {
        self.0.lock().unwrap().push((
            rates.lanes.to_vec(),
            rates.units.to_vec(),
            rates.flat_minor,
            rates.present,
        ));
    }
}

#[test]
fn the_seam_is_silent_until_a_holder_installs_and_then_delivers_the_view_verbatim() {
    assert!(
        crate::test_support::rate_holders::apply().is_none()
            && crate::preflight::root_rows().rate_apply.is_none(),
        "this is the only test that installs a holder, so the seam must still be empty here"
    );
    rates_applied(&RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 7,
        present: false,
        plane_fees: &Default::default(),
    });

    let recorder: &'static Recorder = Box::leak(Box::new(Recorder(Mutex::new(Vec::new()))));
    crate::test_support::rate_holders::install_rate_apply(recorder);

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

    let seen = recorder.0.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![(lanes.to_vec(), units.to_vec(), 11, true)],
        "exactly the one apply raised after the install, with the lanes in the deployment's own \
         order, every tier rate, the fee and the present flag as they were resolved — the apply \
         raised BEFORE it reached nobody, which is what an uninstalled seam owes"
    );

    rates_applied(&RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 11,
        present: true,
        plane_fees: &Default::default(),
    });
    let seen = recorder.0.lock().unwrap().clone();
    assert_eq!(
        seen.last(),
        Some(&(Vec::new(), Vec::new(), 11, true)),
        "an empty lane list under a PRESENT card is carried as present, not folded into absent"
    );
}
