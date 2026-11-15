// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JSON values handed to the YAML tree.
//!
//! A JSON library that keeps number lexemes hands a foreign serializer a token struct in place of
//! a number, and the YAML writer refuses it (`yaml::TagWriter`). [`to_yaml`] is the conversion:
//! every number becomes a real YAML scalar, or is refused when it cannot be written exactly.

use crate::yaml::Value;

/// Convert plugin JSON into real YAML scalars. serde_json arbitrary_precision exposes a
/// private map marker through generic serializers, which would corrupt numeric settings.
/// Refuse integers outside YAML's exact range instead of silently rounding their value.
pub fn to_yaml(value: &serde_json::Value) -> Result<Value, String> {
    use serde_json::Value as Json;
    Ok(match value {
        Json::Null => Value::Null,
        Json::Bool(value) => Value::Bool(*value),
        Json::String(value) => Value::Text(value.clone()),
        Json::Number(value) => {
            if let Some(value) = value.as_u64() {
                Value::from(value)
            } else if let Some(value) = value.as_i64() {
                Value::from(value)
            } else {
                let text = value.to_string();
                if !text.contains(['.', 'e', 'E']) {
                    return Err("plugin migration integer exceeds the exact YAML range".into());
                }
                let value = value
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .ok_or("plugin migration number is not a finite YAML scalar")?;
                let replay = serde_json::Number::from_f64(value)
                    .ok_or("plugin migration number is not finite")?
                    .to_string();
                if decimal_value(&text) != decimal_value(&replay) {
                    return Err(
                        "plugin migration decimal cannot be represented exactly in YAML".into(),
                    );
                }
                Value::Float(value)
            }
        }
        Json::Array(values) => Value::Array(values.iter().map(to_yaml).collect::<Result<_, _>>()?),
        Json::Object(values) => Value::Map(
            values
                .iter()
                .map(|(key, value)| Ok((Value::Text(key.clone()), to_yaml(value)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

fn decimal_value(text: &str) -> Option<(bool, String, i64)> {
    let (negative, text) = text
        .strip_prefix('-')
        .map_or((false, text), |text| (true, text));
    let (coefficient, exponent) =
        text.split_once(['e', 'E'])
            .map_or(Some((text, 0_i64)), |(coefficient, exponent)| {
                exponent
                    .parse()
                    .ok()
                    .map(|exponent| (coefficient, exponent))
            })?;
    let decimals = coefficient
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let mut digits = coefficient.replace('.', "");
    digits = digits.trim_start_matches('0').to_owned();
    if digits.is_empty() {
        return Some((false, "0".into(), 0));
    }
    let trailing = digits.len() - digits.trim_end_matches('0').len();
    digits.truncate(digits.len() - trailing);
    let exponent = exponent
        .checked_sub(i64::try_from(decimals).ok()?)?
        .checked_add(i64::try_from(trailing).ok()?)?;
    Some((negative, digits, exponent))
}
