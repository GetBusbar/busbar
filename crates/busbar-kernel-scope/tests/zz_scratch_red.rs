//! SCRATCH (CI-LOGGING red arm): fails on purpose; the PR carrying it is closed unmerged.
#[test]
fn scratch_red_arm_deliberate_failure() {
    assert_eq!(2 + 2, 5, "CI-LOGGING red arm: this failure is deliberate");
}
