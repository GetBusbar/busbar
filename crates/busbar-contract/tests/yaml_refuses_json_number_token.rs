// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The YAML writer never sees a JSON number or raw-value token.
//!
//! A JSON library that keeps number lexemes (sonic-rs, serde_json `arbitrary_precision`) hands a
//! foreign serializer a one-field token struct instead of a number. Written as YAML that is a
//! marker map, which corrupts the value silently. `busbar_contract::yaml` refuses the token by
//! its struct name, and says to convert with `json::to_yaml`. A local `Serialize` stands in for
//! each library, so the test holds whichever JSON library the workspace uses.

use busbar_contract::yaml;
use serde::ser::{Serialize, SerializeStruct, Serializer};

struct Token(&'static str);

impl Serialize for Token {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut token = serializer.serialize_struct(self.0, 1)?;
        token.serialize_field(self.0, "123")?;
        token.end()
    }
}

const TOKENS: [&str; 3] = [
    "$sonic_rs::private::JsonNumber",
    "$serde_json::private::Number",
    "$sonic_rs::LazyValue",
];

#[test]
fn yaml_writer_refuses_json_number_token() {
    for name in TOKENS {
        let error = yaml::to_string(&Token(name)).expect_err(name).to_string();
        assert!(error.contains("json::to_yaml"), "{name}: {error}");
        assert!(yaml::to_value(Token(name)).is_err(), "{name}");
        let mut out = Vec::new();
        assert!(yaml::to_writer(&mut out, &Token(name)).is_err(), "{name}");
    }
}

#[test]
fn yaml_writer_refuses_the_token_at_any_depth() {
    for name in TOKENS {
        let nested = vec![vec![Token(name)]];
        assert!(yaml::to_string(&nested).is_err(), "{name}");
    }
}

#[test]
fn yaml_writer_still_writes_an_ordinary_struct() {
    struct Plain;
    impl Serialize for Plain {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut plain = serializer.serialize_struct("Plain", 1)?;
            plain.serialize_field("n", &30_u64)?;
            plain.end()
        }
    }
    assert_eq!(yaml::to_string(&Plain).unwrap().trim(), "n: 30");
}
