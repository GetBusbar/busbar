// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `multipart_model` (relocated with the body-model ingress into `native_ingress`).

use super::multipart_model;

#[test]
fn extracts_model_from_head_ignoring_large_binary_tail() {
    // A well-formed transcription: the `model` text part precedes a large binary audio part.
    // multipart_model must find the model in the head without touching the (here 1 MiB) tail.
    let mut body = Vec::new();
    body.extend_from_slice(
        b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n",
    );
    body.extend_from_slice(
        b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\n",
    );
    body.extend(std::iter::repeat_n(0u8, 1 << 20)); // 1 MiB of binary, not valid UTF-8
    body.extend_from_slice(b"\r\n--BOUNDARY--\r\n");
    assert_eq!(multipart_model(&body).as_deref(), Some("whisper-1"));
}

#[test]
fn absent_model_is_none() {
    let body = b"--B\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nx\r\n--B--\r\n";
    assert_eq!(multipart_model(body), None);
}

/// A `name="model"` SPELLED INSIDE ANOTHER PART'S VALUE IS NOT A PART HEADER.
///
/// This is the whole of the multipart read's security argument. The model decides which lane the
/// unit is verified against, which pool it is admitted to and which rate card it is billed on; the
/// provider decides which model actually answers, by parsing the same body with a real multipart
/// parser. If those two readers can be made to disagree, the caller picks what busbar charges for
/// independently of what it receives.
///
/// A raw scan for the first `name="model"` in the body can be made to disagree trivially. The
/// request below is well-formed: a `prompt` text part, then a real `model` part naming an expensive
/// model. Every conforming parser reads the model as `expensive-model`, because the only `model`
/// PART is the second one — the earlier occurrence is characters inside the prompt's value, which is
/// user text and is not structure. A scanner that never looks at the boundary reads the decoy,
/// because the decoy comes first.
///
/// The assertion is the identity, not the string: whatever busbar bills is what the provider
/// serves.
#[test]
fn a_decoy_model_inside_another_parts_value_does_not_win() {
    let mut body = Vec::new();
    body.extend_from_slice(b"--zz\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\n");
    // The caller's own prompt text. It is a VALUE: a multipart parser copies these bytes out
    // verbatim and never reads a header out of them.
    body.extend_from_slice(
        b"transcribe this\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ncheap-model",
    );
    body.extend_from_slice(b"\r\n--zz\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n");
    body.extend_from_slice(b"expensive-model\r\n");
    body.extend_from_slice(b"--zz\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n");
    body.extend_from_slice(&[0u8, 1, 2]);
    body.extend_from_slice(b"\r\n--zz--\r\n");

    assert_eq!(
        multipart_model(&body).as_deref(),
        Some("expensive-model"),
        "busbar must verify, admit and bill the model the provider will actually serve"
    );
}

/// TWO `model` PARTS IS NOT A REQUEST WITH A MODEL.
///
/// A conforming multipart body may repeat a field name, and there is no rule that says which
/// repetition a provider takes — some take the first, some the last. So a body carrying two is a
/// body whose model busbar cannot know, and guessing at one is guessing at what will be billed.
/// It resolves to no model at all, which the ladder's floor turns into the same missing-model
/// refusal an absent field gets: a refusal before the door costs the caller nothing and cannot be
/// made to charge for the wrong lane.
#[test]
fn two_model_parts_resolve_to_no_model() {
    let body = concat!(
        "--zz\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nfirst\r\n",
        "--zz\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nsecond\r\n",
        "--zz--\r\n"
    );
    assert_eq!(multipart_model(body.as_bytes()), None);
}
