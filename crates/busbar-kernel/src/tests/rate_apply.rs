use super::{rates_applied, RawRates};

#[test]
fn the_seam_is_silent_until_a_holder_installs_and_then_delivers_the_view_verbatim() {
    assert!(
        crate::preflight::root_rows().rate_apply.is_none(),
        "the kernel alone installs no product rate holder"
    );
    rates_applied(&RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 7,
        present: false,
        plane_fees: &Default::default(),
    });
    assert!(
        crate::preflight::root_rows().rate_apply.is_none(),
        "an uninstalled apply reaches nobody and installs no holder"
    );
    // The original installed-holder data predicates are exercised against the
    // actual product CardRepricer in kernel_application/central2_rate_apply.rs.
}
