//! RUNG 2 OF THE MODEL LADDER: the `model` form field of a multipart arrival, read as a document.
//!
//! Moved byte-identical from the legacy engine's ingress (its `native_ingress` module), which
//! now calls it here: the arrival reading is the plane's, and there is one of it.

/// The first occurrence of `needle` in `hay`.
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// THE BOUNDARY, off the `Content-Type` — the one thing that says where a part begins.
///
/// A multipart body has no structure without it: every delimiter in the document is spelled from
/// this value, so a reader that does not have it is not reading parts, it is reading bytes that
/// resemble them. `None` where the header carries no `boundary` parameter, which is a body no
/// conforming parser can read either — including the provider's.
///
/// The parameter is matched as a WHOLE key rather than by substring, so a `boundary` that appears
/// inside some other parameter's quoted value is not mistaken for the real one; the value may be
/// quoted and is unquoted here, per RFC 2045.
fn multipart_boundary(content_type: &str) -> Option<String> {
    for param in split_params(content_type).skip(1) {
        let (key, value) = param.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("boundary") {
            let v = value.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|r| r.strip_suffix('"'))
                .unwrap_or(v);
            return (!v.is_empty()).then(|| v.to_string());
        }
    }
    None
}

/// Split a header value on `;`, IGNORING separators inside a quoted string.
///
/// A naive `split(';')` cuts a quoted `filename="a;b"` in half and turns the tail into a parameter
/// that was never written. The first item is the value's own token (`multipart/form-data`), which is
/// why the boundary search above skips it.
fn split_params(value: &str) -> impl Iterator<Item = &str> {
    let mut out = Vec::new();
    let (mut start, mut quoted) = (0usize, false);
    for (i, c) in value.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                out.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&value[start..]);
    out.into_iter()
}

/// Whether a part's header block declares the form field `model`.
///
/// The `name` parameter of `Content-Disposition`, matched as a whole key against a whole value —
/// never as a substring of the header block. `filename="model"` is a different parameter and does not
/// answer this; a `name` written inside some other part's body is not a header at all and never
/// reaches here, because the caller only hands over bytes the boundary said were headers.
fn part_is_model(headers: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(headers) else {
        // A header block is ASCII by construction. One that is not is not a header block this
        // reader will guess at.
        return false;
    };
    // Header field lines are unfolded here only as far as the split: a folded `Content-Disposition`
    // is not something any client emits for a form part, and a continuation line that failed to
    // match simply makes this part not-the-model, which is the safe direction.
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("content-disposition") {
            continue;
        }
        for param in split_params(value).skip(1) {
            let Some((key, v)) = param.split_once('=') else {
                continue;
            };
            if !key.trim().eq_ignore_ascii_case("name") {
                continue;
            }
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|r| r.strip_suffix('"'))
                .unwrap_or(v);
            return v == "model";
        }
    }
    false
}

/// RUNG 2 OF THE MODEL LADDER — the `model` form field of a multipart arrival, read as a DOCUMENT.
///
/// The model this returns decides the lane the unit is verified against, the pool it is admitted to
/// and the card that prices it. The provider decides which model actually answers, by parsing the
/// same bytes with a conforming multipart parser. Those two readings have to agree, or the caller
/// picks what busbar charges for independently of what it receives — so this walks the parts the
/// boundary delimits and reads the `model` part's headers, rather than scanning for a string that
/// occurs just as readily inside somebody's prompt.
///
/// TWO `model` PARTS RESOLVE TO NOTHING. Repetition is legal and no rule says which one a provider
/// takes, so a body carrying two is a body whose model busbar cannot know. It falls to the ladder's
/// floor and gets the same missing-model refusal an absent field gets — before the door, so it costs
/// the caller nothing and cannot be made to charge for the wrong lane.
///
/// The 64 KiB bound is kept: it is far larger than any plausible run of text form fields preceding
/// the audio blob, and it is what stops this from walking a megabyte of binary looking for a
/// delimiter. A `model` part beyond it is not found, which is the same answer the scan gave and the
/// same safe direction — a refusal, never a different model.
///
/// Public so every reader of the arrival calls this rung of the model ladder instead of carrying a
/// second copy of it. A copy would be a second reading of the same wire, and two readings of one
/// wire are two answers waiting to disagree.
pub fn multipart_model(content_type: &str, body: &[u8]) -> Option<String> {
    const HEAD: usize = 64 * 1024;
    let boundary = multipart_boundary(content_type)?;
    let head = &body[..body.len().min(HEAD)];

    // Every part after the first is opened by CRLF + `--boundary`; the first is opened by
    // `--boundary` at the very start of the body (an optional preamble may precede it, and then it
    // too is CRLF-prefixed). Both forms are the same delimiter with one optional CRLF in front, so
    // the walk searches for the dashed form and accepts it only where the document says a delimiter
    // may be: at offset zero, or immediately after a CRLF.
    let dashed = format!("--{boundary}");
    let closing = format!("\r\n--{boundary}");
    let mut found: Option<String> = None;
    let mut at = 0usize;

    while at < head.len() {
        let Some(rel) = find_sub(&head[at..], dashed.as_bytes()) else {
            break;
        };
        let abs = at + rel;
        // A `--boundary` that is not at a line start is text that happens to look like a delimiter.
        if abs != 0 && !head[..abs].ends_with(b"\r\n") {
            at = abs + dashed.len();
            continue;
        }
        let after = abs + dashed.len();
        let rest = &head[after..];
        if rest.starts_with(b"--") {
            // The closing delimiter. Everything past it is the epilogue.
            break;
        }
        // A delimiter line may carry linear whitespace before its CRLF; anything else is not a
        // delimiter line, and a document this reader cannot follow is a document it does not guess
        // at.
        let Some(line_end) = find_sub(rest, b"\r\n") else {
            break;
        };
        if rest[..line_end].iter().any(|b| !matches!(b, b' ' | b'\t')) {
            at = after;
            continue;
        }
        let hdr_at = after + line_end + 2;
        // The part's header block ends at the blank line. A part whose block does not close inside
        // the head is a part this read does not reach.
        let Some(hdr_len) = find_sub(&head[hdr_at..], b"\r\n\r\n") else {
            break;
        };
        let body_at = hdr_at + hdr_len + 4;
        let Some(body_len) = find_sub(&head[body_at..], closing.as_bytes()) else {
            break;
        };
        if part_is_model(&head[hdr_at..hdr_at + hdr_len]) {
            if found.is_some() {
                // Two `model` parts: no model, rather than a guess at which one is billed.
                return None;
            }
            found = Some(
                String::from_utf8_lossy(&head[body_at..body_at + body_len])
                    .trim()
                    .to_string(),
            );
        }
        at = body_at + body_len + 2;
    }
    found.filter(|m| !m.is_empty())
}
