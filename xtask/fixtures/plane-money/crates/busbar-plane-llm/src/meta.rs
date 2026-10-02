// FIXTURE for plane-pricing-blindness. A CONTRACT PLANE doing exactly what #71 asks of it:
// declaring its meter classes as data, and nothing else. Nothing here may flag.
const METER_CLASSES: &[MeterClassDecl] = &[MeterClassDecl {
    key: MeterClassId::new("tokens_out"),
    family: "token",
    direction: ClassDirection::Response,
    default_divisor: 4,
}];
