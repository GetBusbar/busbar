//! The 1.5.5 admin error envelope: `{"error":{"code":"<code>","message":"<message>"}}`.

/// The 1.5.5 admin error envelope around one code and one message.
#[must_use]
pub fn envelope_of(code: &str, message: &str) -> String {
    format!(
        r#"{{"error":{{"code":{},"message":{}}}}}"#,
        json_string(code),
        json_string(message)
    )
}

/// `value` as one JSON string literal, quotes included.
fn json_string(value: &str) -> String {
    serde_json::Value::from(value).to_string()
}

#[cfg(test)]
#[path = "tests/refusal.rs"]
mod tests;
