// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared JSON facade and the contract-owned YAML conversion.

pub use busbar_json::*;

/// Convert plugin JSON into real YAML scalars. A tree that keeps number lexemes hands a generic
/// serializer a token struct in place of a number, which would corrupt numeric settings; this
/// writes each number as a YAML scalar. Integers outside YAML's exact range are refused instead of
/// silently rounded.
pub fn to_yaml(value: &Value) -> Result<crate::yaml::Value, String> {
    use crate::yaml::Value as Yaml;
    Ok(match value.get_type() {
        JsonType::Null => Yaml::Null,
        JsonType::Boolean => Yaml::Bool(value.as_bool().unwrap_or_default()),
        JsonType::String => Yaml::Text(value.as_str().unwrap_or_default().to_owned()),
        JsonType::Number => {
            if let Some(unsigned) = value.as_u64() {
                Yaml::from(unsigned)
            } else if let Some(signed) = value.as_i64() {
                Yaml::from(signed)
            } else {
                let text = number_text(value).unwrap_or_default();
                if !text.contains(['.', 'e', 'E']) {
                    return Err("plugin migration integer exceeds the exact YAML range".into());
                }
                let float = value
                    .as_f64()
                    .filter(|float| float.is_finite())
                    .ok_or("plugin migration number is not a finite YAML scalar")?;
                let replay = Number::from_f64(float)
                    .ok_or("plugin migration number is not finite")?
                    .to_string();
                if decimal_value(&text) != decimal_value(&replay) {
                    return Err(
                        "plugin migration decimal cannot be represented exactly in YAML".into(),
                    );
                }
                Yaml::Float(float)
            }
        }
        JsonType::Array => Yaml::Array(
            value
                .as_array()
                .map(|items| items.iter().map(to_yaml).collect::<Result<_, _>>())
                .transpose()?
                .unwrap_or_default(),
        ),
        JsonType::Object => Yaml::Map(
            value
                .as_object()
                .map(|members| {
                    members
                        .iter()
                        .map(|(key, member)| Ok((Yaml::Text(key.to_owned()), to_yaml(member)?)))
                        .collect::<Result<_, String>>()
                })
                .transpose()?
                .unwrap_or_default(),
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
