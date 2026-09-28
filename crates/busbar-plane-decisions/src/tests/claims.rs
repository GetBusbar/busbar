use super::*;
use busbar_contract::grammar::Selector;

#[test]
fn both_claims_are_exact_paths_on_http() {
    assert_eq!(CLAIMS.len(), 2);
    for claim in CLAIMS {
        assert_eq!(claim.transport, TRANSPORT);
        assert!(matches!(claim.selector, Selector::ExactPath(_)));
        assert_eq!(claim.scheme, Some(SCHEME));
        assert_eq!(claim.scheme_alternatives, &[ALT_TOKEN]);
    }
}

#[test]
fn claims_cover_both_declared_ops_paths() {
    let paths: Vec<&str> = CLAIMS
        .iter()
        .map(|c| match c.selector {
            Selector::ExactPath(p) => p,
            _ => panic!("every claim here is an exact path"),
        })
        .collect();
    assert!(paths.contains(&crate::ops::PATH_SYSTEMONE));
    assert!(paths.contains(&crate::ops::PATH_MODELS));
}
