// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[derive(Debug)]
pub(super) struct Fields(&'static [&'static str]);
impl std::fmt::Display for Fields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the grammar's fields")
    }
}
impl std::error::Error for Fields {}
impl serde::de::Error for Fields {
    fn custom<M: std::fmt::Display>(_: M) -> Self {
        Fields(&[])
    }
}
pub(super) struct Probe;
impl<'de> serde::Deserializer<'de> for Probe {
    type Error = Fields;
    fn deserialize_any<V: serde::de::Visitor<'de>>(self, _: V) -> Result<V::Value, Fields> {
        Err(Fields(&[]))
    }
    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Fields> {
        Err(Fields(fields))
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map enum identifier
        ignored_any
    }
}

pub(super) fn struct_keys<T>(
    read: impl FnOnce(Probe) -> Result<T, Fields>,
) -> &'static [&'static str] {
    match read(Probe) {
        Err(Fields(fields)) => fields,
        Ok(_) => &[],
    }
}
