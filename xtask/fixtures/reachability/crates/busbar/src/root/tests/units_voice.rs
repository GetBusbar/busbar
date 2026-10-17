use super::VoiceUnit;

#[test]
fn the_unit_drives() {
    let unit = VoiceUnit::new(1);
    assert_eq!(unit.n, 1);
}
