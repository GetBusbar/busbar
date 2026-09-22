use super::*;

const SUCCESS: &[u8] =
    br#"{"request_id":"req_1","usage":{"units":42},"answers":{"decision":"approve"}}"#;

const FAILURE: &[u8] =
    br#"{"error":{"code":"invalid_state","message":"bad"},"state":{"secret":"caller-state"},"answers":{"x":1}}"#;

#[test]
fn reads_the_declared_pointers_off_a_success_body() {
    assert!(!has(SUCCESS, PTR_ERROR));
    assert_eq!(read_str(SUCCESS, PTR_REQUEST_ID), Some("req_1"));
    assert_eq!(read_u64(SUCCESS, PTR_USAGE_UNITS), Some(42));
}

#[test]
fn reads_the_declared_pointers_off_a_failure_body() {
    assert!(has(FAILURE, PTR_ERROR));
    // No request_id/id in this fixture, and no usage under an error — both read back as absent.
    assert_eq!(read_str(FAILURE, PTR_REQUEST_ID), None);
    assert_eq!(read_str(FAILURE, PTR_ID), None);
    assert_eq!(read_u64(FAILURE, PTR_USAGE_UNITS), None);
}

#[test]
fn request_ptrs_is_empty() {
    assert!(REQUEST_PTRS.is_empty());
}

#[test]
fn response_ptrs_never_names_state_or_answers() {
    for p in RESPONSE_PTRS {
        assert!(!p.contains("state"));
        assert!(!p.contains("answers"));
    }
}

#[test]
fn read_raw_never_resolves_a_pointer_this_module_does_not_declare() {
    // `/state` and `/answers` are real pointers in this fixture — `read_raw` CAN resolve them if
    // asked, because it is a general primitive. What matters is that nothing in `RESPONSE_PTRS` or
    // `REQUEST_PTRS` ever asks: the guarantee lives in the declared list, not in the primitive
    // refusing. This test documents that split rather than asserting a false safety property of
    // `read_raw` itself.
    assert!(read_raw(FAILURE, "/state").is_some());
    assert!(read_raw(FAILURE, "/answers").is_some());
    assert!(!RESPONSE_PTRS.contains(&"/state"));
    assert!(!RESPONSE_PTRS.contains(&"/answers"));
}
