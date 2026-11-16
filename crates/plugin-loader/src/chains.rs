// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The registry's chains (IF §11.2): the describe decode `add` runs, the generic `open` and DRY_RUN chains every
//! `open_<kind>` and `check_endpoints` share, the boot order `boot_plan` computes and the config merge
//! `reconfigure` applies. W1-L2. The kind-specific part of an open (its port) stays in `instance.rs`.

use busbar_plugin_abi::records::Records;
use busbar_plugin_abi::types::KindCode;

use crate::instance::{BootPhase, Described, OpenError};
use crate::refusal::Refusal;

/// §8 / §11.2 `add`: the describe answer's items as `Described`, checked against the kind the stamp names. The
/// generic items (D_METHODS, D_FACTS, D_SCHEMA, D_METRIC) are decoded; every item is also kept in `items`, in
/// answer order, for the kind decoders and the path lists. A missing or oversized method mask, a method bit the
/// kind does not have (CapUnknown) and a missing REQUIRED method are refused here; D_ERRORS and D_CEILING are
/// judged by `admit_described`.
pub(crate) fn decode_described(
    kind: KindCode,
    describe: Records<'_>,
) -> Result<Described, Refusal> {
    let _ = (kind, describe);
    todo!("W1-L2: decode the describe frame")
}

/// RFC 7386 merge of `patch` (a JSON object) into `base` (the stored config of an instance): absent fields keep
/// their values, a `null` removes one, objects merge recursively. A patch that is not an object is refused.
pub(crate) fn merge_patch(base: &[u8], patch: &[u8]) -> Result<Vec<u8>, String> {
    let _ = (base, patch);
    todo!("W1-L2: merge the pushed patch into the stored config")
}

/// The r6 §3 step 2 order over configured kinds. `deps(i)` = the secret instances instance `i`'s bag references
/// (indices into `kinds`). 2a = the store's secret instances and, transitively, theirs (depth at most 4, a cycle
/// is refused), dependencies first; 2b = the store; 2c = every remaining instance kind by kind (secret, auth,
/// hook, export, plane, transport), config order within a kind.
pub(crate) fn plan_order(
    kinds: &[KindCode],
    deps: &mut dyn FnMut(usize) -> Result<Vec<usize>, OpenError>,
) -> Result<Vec<(u32, BootPhase)>, OpenError> {
    let _ = (kinds, deps);
    todo!("W1-L2: the boot order")
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::fail::refused::R_CONFIG;
    use busbar_plugin_abi::kinds::store::store as st;
    use busbar_plugin_abi::records::{tag, MaskRec, MetricDecl, Reply, Writer};

    use crate::refusal::RefusalCode;

    fn mask(r: &mut Reply, t: u16, mask: u64) {
        r.put_pod(t, &MaskRec { mask }).unwrap();
    }

    fn describe(methods: u64) -> Reply {
        let mut r = Reply::new();
        mask(&mut r, tag::D_METHODS, methods);
        mask(&mut r, tag::D_FACTS, 0b101);
        r.put_text(tag::D_SCHEMA, r#"{"type":"object"}"#).unwrap();
        let mut tail = Reply::new();
        tail.put_text(tag::TEXT, "reads").unwrap();
        tail.put_text(tag::TEXT, "Reads served").unwrap();
        tail.put_text(tag::TEXT, "op").unwrap();
        r.put_pod_tail(
            tag::D_METRIC,
            &MetricDecl { id: 7, kind: 1 },
            tail.as_bytes(),
        )
        .unwrap();
        r
    }

    #[test]
    fn a_describe_frame_decodes_into_its_facts() {
        let r = describe(st::REQUIRED | 1 << 5);
        let d = decode_described(KindCode::Store, Records::new(r.as_bytes())).unwrap();
        assert_eq!(d.kind, KindCode::Store);
        assert_eq!(d.methods, st::REQUIRED | 1 << 5);
        assert_eq!(d.facts, 0b101);
        assert_eq!(d.schema.as_deref(), Some(r#"{"type":"object"}"#));
        assert_eq!(d.items.len(), 4);
        let [m] = &d.metrics[..] else {
            panic!("one metric")
        };
        assert_eq!(
            (m.id, m.kind, &*m.name, &*m.help),
            (7, 1, "reads", "Reads served")
        );
        assert_eq!(
            m.label_keys.iter().map(|k| &**k).collect::<Vec<_>>(),
            ["op"]
        );
    }

    #[test]
    fn a_method_the_kind_lacks_is_cap_unknown_and_a_missing_required_one_is_invalid() {
        let r = describe(st::REQUIRED | st::ALL + 1);
        let e = decode_described(KindCode::Store, Records::new(r.as_bytes()))
            .err()
            .unwrap();
        assert_eq!(e.code, RefusalCode::CapUnknown);
        let r = describe(st::REQUIRED & !1);
        let e = decode_described(KindCode::Store, Records::new(r.as_bytes()))
            .err()
            .unwrap();
        assert_eq!(e.code, RefusalCode::DescribeInvalid);
        let e = decode_described(KindCode::Store, Records::new(&[]))
            .err()
            .unwrap();
        assert_eq!(
            (e.code, e.field),
            (RefusalCode::DescribeInvalid, "describe.methods")
        );
    }

    fn json(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap()
    }

    #[test]
    fn a_patch_keeps_absent_fields_merges_objects_and_null_removes() {
        let out = merge_patch(
            br#"{"a":1,"b":{"c":2,"e":5},"f":[1]}"#,
            br#"{"a":null,"b":{"c":3,"d":4},"f":[2]}"#,
        )
        .unwrap();
        assert_eq!(json(&out), json(br#"{"b":{"c":3,"d":4,"e":5},"f":[2]}"#));
        assert!(merge_patch(b"{}", b"[1]").is_err());
        assert!(merge_patch(b"{}", b"nope").is_err());
        assert!(merge_patch(b"nope", b"{}").is_err());
    }

    use BootPhase::{Rest, Store, StoreSecrets};
    use KindCode as K;

    #[test]
    fn the_plan_runs_store_secrets_then_the_store_then_every_other_kind_in_order() {
        // 0 plane, 1 store, 2 secret, 3 secret (the store's), 4 auth, 5 hook, 6 secret
        let kinds = [
            K::Plane,
            K::Store,
            K::Secret,
            K::Secret,
            K::Auth,
            K::Hook,
            K::Secret,
        ];
        let mut deps = |i: usize| {
            Ok(match i {
                1 => vec![3],
                3 => vec![2],
                _ => vec![],
            })
        };
        let plan = plan_order(&kinds, &mut deps).unwrap();
        assert_eq!(
            plan,
            [
                (2, StoreSecrets),
                (3, StoreSecrets),
                (1, Store),
                (6, Rest),
                (4, Rest),
                (5, Rest),
                (0, Rest)
            ]
        );
    }

    #[test]
    fn a_secret_cycle_and_a_chain_deeper_than_four_are_refused_naming_the_instances() {
        let kinds = [K::Store, K::Secret, K::Secret];
        let mut cycle = |i: usize| {
            Ok(match i {
                0 => vec![1],
                1 => vec![2],
                2 => vec![1],
                _ => vec![],
            })
        };
        let Err(OpenError::Config { code, text, .. }) = plan_order(&kinds, &mut cycle) else {
            panic!("a cycle is refused")
        };
        assert_eq!(code, R_CONFIG);
        assert!(text.contains('1') && text.contains('2'), "{text}");
        let kinds = [
            K::Store,
            K::Secret,
            K::Secret,
            K::Secret,
            K::Secret,
            K::Secret,
            K::Secret,
        ];
        let mut deep = |i: usize| Ok(if i < 6 { vec![i + 1] } else { vec![] });
        assert!(matches!(
            plan_order(&kinds, &mut deep),
            Err(OpenError::Config { .. })
        ));
        let mut shallow = |i: usize| Ok(if i < 4 { vec![i + 1] } else { vec![] });
        assert!(plan_order(&kinds[..5], &mut shallow).is_ok());
    }

    #[test]
    fn no_store_means_no_store_phase() {
        let kinds = [K::Auth, K::Secret];
        let plan = plan_order(&kinds, &mut |_| Ok(vec![])).unwrap();
        assert_eq!(plan, [(1, Rest), (0, Rest)]);
    }
}
