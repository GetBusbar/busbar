//! The resolved tag of a node, as bytes (a `%TAG` prefix or URI escapes may produce any octets).

use std::fmt::{self, Debug, Write as _};
use std::ops::Deref;

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Tag(pub(in crate::libyaml) Box<[u8]>);

impl Tag {
    pub const NULL: &'static str = "tag:yaml.org,2002:null";
    pub const BOOL: &'static str = "tag:yaml.org,2002:bool";
    pub const INT: &'static str = "tag:yaml.org,2002:int";
    pub const FLOAT: &'static str = "tag:yaml.org,2002:float";
}

impl Tag {
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.0.starts_with(prefix.as_bytes())
    }
}

impl PartialEq<str> for Tag {
    fn eq(&self, other: &str) -> bool {
        *self.0 == *other.as_bytes()
    }
}

impl Deref for Tag {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Tag {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        debug_lossy(&self.0, formatter)
    }
}

/// serde_yaml_ng's `cstr::debug_lossy`: a quoted, escaped rendering that shows invalid UTF-8 as
/// `\xNN` octets.
pub(crate) fn debug_lossy(mut bytes: &[u8], formatter: &mut fmt::Formatter) -> fmt::Result {
    formatter.write_char('"')?;
    while !bytes.is_empty() {
        let (valid, broken) = match std::str::from_utf8(bytes) {
            Ok(valid) => (valid, None),
            Err(utf8_error) => {
                let valid_up_to = utf8_error.valid_up_to();
                let valid = std::str::from_utf8(&bytes[..valid_up_to]).unwrap_or_default();
                let end_of_broken = match utf8_error.error_len() {
                    Some(error_len) => valid_up_to + error_len,
                    None => bytes.len(),
                };
                (valid, Some(end_of_broken))
            }
        };
        let mut written = 0;
        for (i, ch) in valid.char_indices() {
            let esc = ch.escape_debug();
            if esc.len() != 1 && ch != '\'' {
                formatter.write_str(&valid[written..i])?;
                for ch in esc {
                    formatter.write_char(ch)?;
                }
                written = i + ch.len_utf8();
            }
        }
        formatter.write_str(&valid[written..])?;
        match broken {
            None => break,
            Some(end_of_broken) => {
                for b in &bytes[valid.len()..end_of_broken] {
                    write!(formatter, "\\x{:02x}", b)?;
                }
                bytes = &bytes[end_of_broken..];
            }
        }
    }
    formatter.write_char('"')
}
