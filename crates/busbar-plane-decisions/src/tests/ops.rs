use super::*;

#[test]
fn row_for_matches_systemone() {
    let row = row_for("POST", PATH_SYSTEMONE).expect("systemone is declared");
    assert_eq!(row.op, OP_SYSTEMONE);
    assert!(row.has_request_body);
}

#[test]
fn row_for_matches_models() {
    let row = row_for("GET", PATH_MODELS).expect("models is declared");
    assert_eq!(row.op, OP_MODELS);
    assert!(!row.has_request_body);
}

#[test]
fn row_for_is_verb_case_insensitive() {
    assert!(row_for("post", PATH_SYSTEMONE).is_some());
    assert!(row_for("get", PATH_MODELS).is_some());
}

#[test]
fn row_for_refuses_wrong_verb() {
    assert!(row_for("GET", PATH_SYSTEMONE).is_none());
    assert!(row_for("POST", PATH_MODELS).is_none());
}

#[test]
fn row_for_refuses_unknown_path() {
    assert!(row_for("GET", "/v1/unknown").is_none());
}

#[test]
fn op_classes_matches_the_method_table() {
    assert_eq!(OP_CLASSES.len(), METHODS.len());
    for row in METHODS {
        assert!(OP_CLASSES.contains(&row.op));
    }
}
