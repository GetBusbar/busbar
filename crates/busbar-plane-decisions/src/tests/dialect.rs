use super::*;

/// The two dialects, their claims and their billing units (THE DESIGN section 2).
#[test]
fn jev_and_nanojev_are_the_rows() {
    assert_eq!(row(JEV).name, "jev");
    assert_eq!(row(JEV).path, "/v1/systemone");
    assert_eq!(row(JEV).units, "/usage/units");
    assert_eq!(row(NANOJEV).name, "nanojev");
    assert_eq!(row(NANOJEV).path, "/api/evaluate");
    assert_eq!(row(NANOJEV).units, "/execution/states");
    assert_eq!(row(NANOJEV).input_tokens, None);
    assert!(!row(NANOJEV).names_model);
    assert_eq!(index_of("nanojev"), Some(NANOJEV));
    assert_eq!(index_of("anthropic"), None);
    assert_eq!(of_path("/api/evaluate"), Some(NANOJEV));
    assert_eq!(of_path("/v1/models"), None);
}

/// Each dialect's error shape: jev's code and message, NanoJev's bare text (its server's own
/// `{"error": <text>}`).
#[test]
fn each_dialect_writes_its_own_error() {
    assert_eq!(
        error_body(JEV, "invalid_request", "no"),
        br#"{"error":{"code":"invalid_request","message":"no"}}"#
    );
    assert_eq!(
        error_body(NANOJEV, "invalid_request", "no \"x\""),
        br#"{"error":"no \"x\""}"#
    );
}
