use super::LlmUnit;

#[test]
fn the_unit_drives() {
    let unit = LlmUnit::new(1);
    assert_eq!(unit.n, 1);
}
