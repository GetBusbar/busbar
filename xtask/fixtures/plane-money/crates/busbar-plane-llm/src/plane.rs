// The legitimate half, continued: emit a raw count under a declared class, and render the
// kernel's own money refusals onto this plane's wire. Neither is valuing.
pub fn meter(r: &Response) -> UsageLocators {
    let mut l = UsageLocators::default();
    let _ = l.lines.push(UsageLocator {
        class: CLASS_TOKENS_OUT,
        location: None,
        quantity: Some(r.ir.body().len() as u64),
        lane: None,
    });
    l
}

pub fn refusal_shape(reason: RefusalReason) -> (u16, &'static str) {
    match reason {
        RefusalReason::OverBudget | RefusalReason::OverdraftCeiling => (429, KIND_RATE_LIMIT),
        RefusalReason::Unpriced | RefusalReason::NoRate => (400, KIND_INVALID_REQUEST),
        _ => (500, KIND_INTERNAL),
    }
}
