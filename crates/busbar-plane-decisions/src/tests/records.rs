use super::*;

#[test]
fn no_record_schemas_are_declared() {
    assert!(
        RECORD_SCHEMAS.is_empty(),
        "jev is stateless passthrough (see the module note); a schema here would need a route.rs \
         leg and a documented reason"
    );
}
