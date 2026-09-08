//! Tests for `envelope.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches what it
//! always did.

use super::*;

/// The ten rows of the frozen taxonomy, spelled out.
///
/// A literal table rather than a walk over the variants, and deliberately: the claim is that these
/// exact strings and these exact numbers are what shipped, so a test that derived them from the
/// implementation would agree with any implementation. A row changing here is a breaking change to
/// v1 and is meant to be as loud as editing a wire format.
#[test]
fn every_code_and_status_is_the_one_that_shipped() {
    let rows: [(AdminError, &str, u16); 10] = [
        (AdminError::not_found("key"), "not_found", 404),
        (AdminError::Unauthorized, "unauthorized", 401),
        (AdminError::MethodNotAllowed, "method_not_allowed", 405),
        (AdminError::Forbidden { needed: "full" }, "forbidden", 403),
        (AdminError::Validation("bad".into()), "invalid_request", 400),
        (
            AdminError::VersionConflict("stale".into()),
            "version_conflict",
            409,
        ),
        (AdminError::Conflict("busy".into()), "conflict", 409),
        (AdminError::RateLimited, "rate_limited", 429),
        (AdminError::Internal, "internal", 500),
        (AdminError::Unavailable("slow".into()), "unavailable", 503),
    ];
    for (error, code, status) in rows {
        assert_eq!(error.code(), code, "the code for {error:?}");
        assert_eq!(error.http_status(), status, "the status for {error:?}");
        assert!(
            !error.message().is_empty(),
            "{error:?} renders an empty message"
        );
    }
}

/// The messages that are PHRASES rather than pass-throughs.
///
/// Six of the ten build their message rather than carrying one, so six are what a client actually
/// reads and are pinned. The other four hand back the string they were given, which the envelope
/// test below covers.
#[test]
fn the_built_messages_are_the_ones_that_shipped() {
    assert_eq!(AdminError::not_found("key").message(), "key not found");
    assert_eq!(
        AdminError::not_found_because("key", "governance disabled").message(),
        "key not found (governance disabled)"
    );
    assert_eq!(
        AdminError::Unauthorized.message(),
        "missing or invalid admin credential (Bearer or x-admin-token)"
    );
    assert_eq!(
        AdminError::MethodNotAllowed.message(),
        "method not allowed for this resource"
    );
    assert_eq!(
        AdminError::Forbidden { needed: "full" }.message(),
        "insufficient scope: this endpoint requires `full`"
    );
    assert_eq!(
        AdminError::RateLimited.message(),
        "admin mutation rate limit exceeded; retry next minute"
    );
    assert_eq!(AdminError::Internal.message(), "internal error");
}

/// The taxonomy renders through the one envelope, including for a message a caller wrote.
///
/// The `what` of a `not_found` is a name the caller asked for and a `Validation` message quotes what
/// it complained about, so this is the taxonomy's half of the claim the envelope's own escaping test
/// makes: whatever a caller put in the request, what comes back is one document carrying this
/// error's frozen code and this error's message.
#[test]
fn the_envelope_carries_this_errors_own_code_and_message() {
    for error in [
        AdminError::not_found(r#"key "prod""#),
        AdminError::Validation("field `a\\b` is not one of: x, y".into()),
        AdminError::Conflict("a change\nis in flight".into()),
        AdminError::Unauthorized,
    ] {
        let rendered = error.envelope();
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("one document per error");
        let body = parsed
            .get("error")
            .and_then(serde_json::Value::as_object)
            .expect("the envelope's one key");
        assert_eq!(
            body.len(),
            2,
            "the envelope is code and message and nothing else"
        );
        assert_eq!(body["code"], error.code());
        assert_eq!(body["message"].as_str(), Some(error.message().as_str()));
    }
}
