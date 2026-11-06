// SPDX-License-Identifier: Apache-2.0
//! The actual connector guard distinguishes host completion from caller/authentication input.
use super::*;
use busbar_contract::conn::CompletedHead;

const OWNER: InstanceId = InstanceId(17);
const NEED: NeedId = NeedId(2);
const TARGET: &str = "https://sink.example/logs";

fn complete(carried: &[(&str, &[u8])], body_len: usize) -> CompletedHead {
    HeadDefaults {
        lines: vec![(b"host".to_vec(), b"sink.example".to_vec())],
        states_length: true,
    }
    .completed_for(
        OWNER,
        NEED,
        TARGET,
        |name| {
            carried
                .iter()
                .any(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
        },
        body_len,
    )
    .unwrap()
}

fn refused(fields: &[(&str, &[u8])], body: &'static [u8], completed: &CompletedHead) -> bool {
    request_head_is_refused(
        OWNER,
        NEED,
        &OpenDesc {
            target: TARGET,
            fields,
            body: Bytes::from_static(body),
            completed_head: Some(completed),
            ..OpenDesc::default()
        },
        true,
    )
}

#[test]
fn generated_signed_suffix_is_accepted_without_changing_the_wire_head() {
    let completed = complete(&[], 3);
    let fields: &[(&str, &[u8])] = &[
        ("authorization", b"signature"),
        ("host", b"sink.example"),
        ("content-length", b"3"),
    ];
    assert!(!refused(fields, b"abc", &completed));
    assert!(head_is_refused(
        &OpenDesc {
            fields,
            ..OpenDesc::default()
        },
        true
    ));
    assert_eq!(
        fields[1..],
        [
            ("host", b"sink.example".as_slice()),
            ("content-length", b"3".as_slice())
        ]
    );
}

#[test]
fn caller_and_authentication_framing_and_authority_remain_refused() {
    for (name, value) in [
        ("content-length", b"3".as_slice()),
        ("transfer-encoding", b"chunked".as_slice()),
        ("host", b"other.example".as_slice()),
    ] {
        // Caller-owned fields suppress the corresponding default; they remain untrusted.
        let caller = [(name, value)];
        let completed = complete(&caller, 3);
        let mut fields = caller.to_vec();
        fields.extend(
            completed
                .fields()
                .iter()
                .map(|(n, v)| (std::str::from_utf8(n).unwrap(), v.as_slice())),
        );
        assert!(refused(&fields, b"abc", &completed), "caller {name}");

        // An authentication result cannot replace, or duplicate, a generated default.
        let completed = complete(&[], 3);
        let mut fields = vec![
            (name, value),
            ("host", b"sink.example".as_slice()),
            ("content-length", b"3".as_slice()),
        ];
        assert!(refused(&fields, b"abc", &completed), "auth {name}");
        fields.retain(|(n, _)| *n != name);
        fields.insert(0, (name, value));
        assert!(
            refused(&fields, b"abc", &completed),
            "auth replacement {name}"
        );
    }
}

#[test]
fn completion_rejects_altered_missing_reordered_and_duplicated_fields() {
    let completed = complete(&[], 3);
    for fields in [
        vec![
            ("host", b"other.example".as_slice()),
            ("content-length", b"3".as_slice()),
        ],
        vec![("host", b"sink.example".as_slice())],
        vec![
            ("content-length", b"3".as_slice()),
            ("host", b"sink.example".as_slice()),
        ],
        vec![
            ("HOST", b"sink.example".as_slice()),
            ("host", b"sink.example".as_slice()),
            ("content-length", b"3".as_slice()),
        ],
        vec![
            ("x-auth", b"ok\r\ncontent-length: 3".as_slice()),
            ("host", b"sink.example".as_slice()),
            ("content-length", b"3".as_slice()),
        ],
    ] {
        assert!(refused(&fields, b"abc", &completed), "{fields:?}");
    }
    let fields = [
        ("host", b"sink.example".as_slice()),
        ("content-length", b"3".as_slice()),
    ];
    assert!(refused(&fields, b"abcd", &completed));
    let disguised = [
        ("Host ", b"other.example".as_slice()),
        ("host", b"sink.example".as_slice()),
        ("content-length", b"3".as_slice()),
    ];
    assert!(
        request_head_is_refused(
            OWNER,
            NEED,
            &OpenDesc {
                target: TARGET,
                fields: &disguised,
                body: Bytes::from_static(b"abc"),
                completed_head: Some(&completed),
                ..OpenDesc::default()
            },
            false
        ),
        "a generated authority cannot be duplicated through whitespace"
    );

    let desc = OpenDesc {
        target: TARGET,
        fields: &fields,
        body: Bytes::from_static(b"abc"),
        completed_head: Some(&completed),
        ..OpenDesc::default()
    };
    assert!(request_head_is_refused(InstanceId(18), NEED, &desc, true));
    assert!(request_head_is_refused(OWNER, NeedId(3), &desc, true));
    assert!(request_head_is_refused(
        OWNER,
        NEED,
        &OpenDesc {
            target: "https://other.example/logs",
            ..desc
        },
        true
    ));
}

#[test]
fn protocol_completion_rejects_noncanonical_length_transfer_encoding_and_injection() {
    for lines in [
        vec![(b"content-length".to_vec(), b"03".to_vec())],
        vec![(b"content-length".to_vec(), b"4".to_vec())],
        vec![(b"transfer-encoding".to_vec(), b"chunked".to_vec())],
        vec![
            (b"host".to_vec(), b"sink.example".to_vec()),
            (b"Host".to_vec(), b"other.example".to_vec()),
        ],
        vec![(b"host".to_vec(), b"sink.example\r\nx: y".to_vec())],
        vec![(b" content-length ".to_vec(), b"3".to_vec())],
    ] {
        assert!(HeadDefaults {
            lines,
            states_length: true
        }
        .completed_for(OWNER, NEED, TARGET, |_| false, 3)
        .is_err());
    }
    assert!(HeadDefaults {
        lines: vec![(b"content-length".to_vec(), b"3".to_vec())],
        states_length: false
    }
    .completed_for(OWNER, NEED, TARGET, |_| false, 3)
    .is_err());
}

#[test]
fn empty_body_completion_omits_length_and_does_not_admit_caller_zero_length() {
    let completed = complete(&[], 0);
    assert_eq!(completed.fields().len(), 1);
    assert!(!refused(&[("host", b"sink.example")], b"", &completed));
    assert!(refused(
        &[("content-length", b"0"), ("host", b"sink.example")],
        b"",
        &completed
    ));
}
