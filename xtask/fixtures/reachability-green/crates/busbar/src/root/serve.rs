// The door planes' one composition, in miniature: exactly one function reached from `fn main()`
// builds a `PlaneDriver`, and a reached line in this module drives a unit through it (the served data
// route). A plane whose crate is linked on the `plane-door` axis is served here.
pub struct ServedPlane {
    driver: PlaneDriver,
}

pub fn compose_planes() -> Vec<ServedPlane> {
    let driver = PlaneDriver::new(1);
    vec![ServedPlane { driver }]
}

pub fn serve(planes: &[ServedPlane]) -> u64 {
    planes.iter().map(|p| p.driver.unit(1)).sum()
}
