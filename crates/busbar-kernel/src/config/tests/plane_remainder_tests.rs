// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::*;
use std::collections::HashMap;

fn strip_from_document(
    text: &str,
    observed: &mut Vec<serde_yaml::Value>,
) -> Result<DeployCfg, serde_yaml::Error> {
    struct Section<'a>(&'a mut Lifted);
    impl<'de> DeserializeSeed<'de> for Section<'_> {
        type Value = serde_yaml::Value;
        fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
            plane_remainder_in("tools", "card-plane", "card thing", de, self.0)
        }
    }
    struct Document<'a>(&'a mut Vec<serde_yaml::Value>);
    impl<'de> Visitor<'de> for Document<'_> {
        type Value = DeployCfg;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("the plane card test document")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut lifted = Lifted::default();
            let mut deploy = crate::config::tests::base_deploy();
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "tools" => {
                        let section = map.next_value_seed(Section(&mut lifted))?;
                        self.0.push(section);
                    }
                    "per_request_fee" => deploy.per_request_fee = map.next_value()?,
                    _ => {
                        let _: serde::de::IgnoredAny = map.next_value()?;
                    }
                }
            }
            lifted.install(&mut deploy);
            Ok(deploy)
        }
    }
    serde::Deserializer::deserialize_map(
        serde_yaml::Deserializer::from_str(text),
        Document(observed),
    )
}

#[test]
fn a_plane_sections_rate_card_is_lifted_off_before_the_plane_sees_it() {
    let mut observed = Vec::new();
    observed.clear();
    let deploy = strip_from_document(
        "providers: {}\nmodels: {}\ntools:\n  srv: { url: \"https://x.example/srv\" }\n  \
         rate_card:\n    srv_read: { units: { tool_calls: 3 } }\n",
        &mut observed,
    )
    .expect("a plane section with a card parses");

    let saw = observed.clone();
    assert_eq!(saw.len(), 1, "the plane parsed its section once: {saw:?}");
    let blob = serde_yaml::to_string(&saw[0]).unwrap();
    assert!(
        !blob.contains("rate_card") && !blob.contains("tool_calls") && blob.contains("srv"),
        "the plane got its own settings and not a byte of its card: {blob}"
    );
    let card = &deploy.plane_rate_cards["card-plane"];
    assert_eq!(
        card["srv_read"].units["tool_calls"].nanos_per_unit(),
        3_000,
        "the card is filed under the plane's registry key, exact"
    );

    let root = resolve(&deploy, &HashMap::new()).expect("resolves");
    let composed = root.rate_card.expect("a plane card present");
    let lane = format!(
        "card-plane{}srv_read",
        busbar_kernel_ledger::cost::PLANE_LANE_SEP
    );
    assert!(composed.contains_key(&lane), "{composed:?}");
    assert!(
        !busbar_kernel_ledger::cost::flat_card_present(
            composed
                .keys()
                .map(|k| busbar_kernel_ledger::cost::split_plane_lane(k).0)
        ),
        "no top-level `rate_card:`: the flat plane stays billing OFF beside another plane's card"
    );
}

#[test]
fn a_plane_sections_fees_are_lifted_off_before_the_plane_sees_them() {
    let mut observed = Vec::new();
    use busbar_kernel_ledger::cost::PlaneFees;
    observed.clear();
    let deploy = strip_from_document(
        "providers: {}\nmodels: {}\nper_request_fee: 5\ntools:\n  srv: { url: \"https://x.example/srv\" }\n  \
         fees: { per_request: 3, per_session: 40 }\n",
     &mut observed)
    .expect("a plane section with fees parses");
    let saw = observed.clone();
    let blob = serde_yaml::to_string(&saw[0]).unwrap();
    assert!(
        !blob.contains("fees") && !blob.contains("per_request") && blob.contains("srv"),
        "the plane got its own settings and not a byte of its fees: {blob}"
    );
    let fees = PlaneFees {
        per_request: 3,
        per_session: 40,
    };
    assert_eq!(deploy.plane_fees.get("card-plane"), Some(&fees));
    let root = resolve(&deploy, &HashMap::new()).expect("resolves");
    assert_eq!(root.plane_fees.get("card-plane"), Some(&fees));
    assert_eq!(
        root.per_request_fee, 5,
        "the pools plane's fee is untouched"
    );
    assert_eq!(root.rate_card, None, "fees alone switch no card on");

    for bad in ["{ per_call: 1 }", "{ per_request: -1 }", "3"] {
        observed.clear();
        let err = strip_from_document(
            &format!("providers: {{}}\nmodels: {{}}\ntools:\n  fees: {bad}\n"),
            &mut observed,
        )
        .expect_err("a malformed `fees` is refused");
        assert!(err.to_string().contains("tools.fees"), "{bad}: {err}");
        assert!(
            observed.is_empty(),
            "the refused section never reached the plane"
        );
    }
}

#[test]
fn a_plane_entry_named_after_a_reserved_key_is_refused_at_its_position() {
    let mut observed = Vec::new();
    use busbar_contract::section::reserved_name_refusal;
    let head = "providers: {}\nmodels: {}\ntools:\n  srv: { url: \"https://x.example/srv\" }\n";
    for key in [
        "breaker",
        "on_exhausted",
        "gates",
        "affinity",
        "tier",
        "repeatable",
        "work",
        "pools",
        "hooks",
        "upstream_credentials",
        "fees",
        "rate_card",
    ] {
        observed.clear();
        let err = strip_from_document(
            &format!("{head}  {key}:\n    url: \"https://y.example/\"\n"),
            &mut observed,
        )
        .expect_err(key);
        assert_eq!(
            err.to_string(),
            format!(
                "tools.{key}: {} at line 6 column 5",
                reserved_name_refusal("tools", "card thing", key)
            )
        );
        assert!(
            observed.is_empty(),
            "the refused section never reached the plane"
        );
    }
    observed.clear();
    strip_from_document(
        &format!(
            "{head}  hooks: [h]\n  upstream_credentials: own\n  tier: big\n  gates: [g]\n  \
         repeatable: [read]\n  breaker: {{ base_cooldown_secs: 3 }}\n  on_exhausted: reject\n  \
         affinity: {{ header_name: x-s }}\n  work: {{ max_live: 2, retain_s: 3 }}\n  \
         fees: {{ per_request: 1 }}\n  pools:\n    p1: {{ members: [srv] }}\n"
        ),
        &mut observed,
    )
    .expect("every reserved knob, well-shaped, loads");
    let saw = serde_yaml::to_string(&observed[0]).unwrap();
    assert!(saw.contains("srv") && !saw.contains("fees"), "{saw}");
}
