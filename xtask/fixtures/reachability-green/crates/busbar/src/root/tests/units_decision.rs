use super::DecisionUnit;

#[test]
fn the_unit_drives() {
    let unit = DecisionUnit::new(1);
    assert_eq!(unit.n, 1);
}
