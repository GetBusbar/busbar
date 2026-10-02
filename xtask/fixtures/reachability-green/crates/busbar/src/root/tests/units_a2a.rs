use super::A2aUnits;

#[test]
fn the_unit_drives() {
    let unit = A2aUnits::new(1);
    assert_eq!(unit.n, 1);
}
