// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The composed open's exchange body: the description alone, or framed into the opener's form.

use super::composed_body;
use busbar_contract::conn::ConnError;

const FORM: &[u8] = b"multipart/form-data; boundary=b0und";

#[test]
fn an_open_with_no_body_sends_the_description_alone() {
    assert_eq!(composed_body(&[], b"", b"v=0\r\n"), Ok(b"v=0\r\n".to_vec()));
}

#[test]
fn an_open_with_a_form_gets_the_description_as_its_last_part() {
    let lead = b"--b0und\r\nContent-Disposition: form-data; name=\"one\"\r\n\r\n{}\r\n\
--b0und\r\nContent-Disposition: form-data; name=\"two\"\r\n\r\n";
    let got = composed_body(&[("Content-Type", FORM)], lead, b"v=0\r\n").expect("composed");
    let mut want = lead.to_vec();
    want.extend_from_slice(b"v=0\r\n\r\n--b0und--\r\n");
    assert_eq!(got, want);
    // A quoted boundary, a lower-case field name and a parameter before the boundary.
    let quoted: &[u8] = b"multipart/form-data; charset=utf-8; boundary=\"b0und\"";
    assert_eq!(
        composed_body(&[("content-type", quoted)], lead, b"v=0\r\n"),
        Ok(want)
    );
}

#[test]
fn a_body_the_connector_cannot_frame_is_refused() {
    let lead = b"--b0und\r\n\r\n";
    // RED: no content type, another content type, a form with no boundary, an unusable boundary.
    for fields in [
        &[][..],
        &[("content-type", &b"application/json"[..])][..],
        &[("content-type", &b"multipart/form-data"[..])][..],
        &[("content-type", &b"multipart/form-data; boundary="[..])][..],
    ] {
        assert_eq!(
            composed_body(fields, lead, b"v=0"),
            Err(ConnError::Refused),
            "{fields:?}"
        );
    }
    // RED: a description holding the form's delimiter would end the form early.
    assert_eq!(
        composed_body(&[("content-type", FORM)], lead, b"v=0\r\n--b0und--\r\n"),
        Err(ConnError::Refused)
    );
}
