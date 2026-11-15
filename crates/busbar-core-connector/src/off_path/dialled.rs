// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dialled upstream leg's off-path body (`crate::dialled`): the exchange body a datagram
//! association's open composes once, as the association is bound and dialled, never per datagram.

use busbar_contract::conn::ConnError;

/// THE EXCHANGE BODY OF A COMPOSED OPEN: the open's own `body` (when it has one) joined to the
/// association's session `description` as the final part of the open's `multipart/form-data`
/// content type, or just the description when the open carries no body.
pub(crate) fn composed_body(
    fields: &[(&str, &[u8])],
    body: &[u8],
    description: &[u8],
) -> Result<Vec<u8>, ConnError> {
    if body.is_empty() {
        return Ok(description.to_vec());
    }
    let boundary = fields
        .iter()
        .filter(|(name, _)| !busbar_contract::conn::is_sealed_fields_field(name.as_bytes()))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, value)| std::str::from_utf8(value).ok())
        .and_then(form_boundary)
        .ok_or(ConnError::Refused)?;
    // The delimiter is `CRLF--boundary`; the description is searched for it in place.
    const LEAD: &[u8] = b"\r\n--";
    let boundary = boundary.as_bytes();
    if description
        .windows(LEAD.len() + boundary.len())
        .any(|w| w.starts_with(LEAD) && w[LEAD.len()..] == *boundary)
    {
        return Err(ConnError::Refused);
    }
    Ok([body, description, LEAD, boundary, b"--\r\n"].concat())
}

/// The `boundary` of a `multipart/form-data` content type (RFC 7578, RFC 2046 section 5.1.1),
/// parsed by `mime` (quoted parameter values included, so another parameter's quoted text cannot
/// pose as the boundary), then held to the RFC 2046 `bchars` set and the 1..=70 length. The answer
/// borrows the same bytes from `content_type`: no copy.
fn form_boundary(content_type: &str) -> Option<&str> {
    let parsed: mime::Mime = content_type.trim().parse().ok()?;
    if parsed.essence_str() != "multipart/form-data" {
        return None;
    }
    let boundary = parsed.get_param(mime::BOUNDARY)?.as_str();

    let fits = (1..=70).contains(&boundary.len())
        && boundary
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b));
    if !fits {
        return None;
    }
    let at = content_type.find(boundary)?;
    content_type.get(at..at + boundary.len())
}
