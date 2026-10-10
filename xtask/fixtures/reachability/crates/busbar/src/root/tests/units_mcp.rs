use super::McpUnit;

#[test]
fn the_unit_drives() {
    let unit = McpUnit::new(1);
    assert_eq!(unit.n, 1);
}
