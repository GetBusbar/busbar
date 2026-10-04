// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A declared egress scheme is read as data: the credential-family table decides first, the lane's
//! credential mode decides the rest, and a signing scheme's region is the declared function of the
//! host.

use super::*;
use busbar_contract::protocol::CredentialFamily;

const KEY_HEADER: CredentialHeader = CredentialHeader::Raw {
    header: "x-key",
    trim_start: true,
};

/// Two credential families and a mode-keyed fallback: a static key family in its own header, an
/// access-token family as a bearer.
const TWO_FAMILIES: EgressScheme = EgressScheme::Static {
    families: &[
        CredentialFamily {
            prefix: "key-",
            presented_as: KEY_HEADER,
        },
        CredentialFamily {
            prefix: "tok-",
            presented_as: CredentialHeader::Bearer,
        },
    ],
    own: CredentialHeader::Raw {
        header: "x-key",
        trim_start: false,
    },
    passthrough: CredentialHeader::Bearer,
};

fn region_of(host: &str) -> Option<&str> {
    host.split('.')
        .nth(1)
        .filter(|label| label.starts_with("region-"))
}

const SIGNING: EgressScheme = EgressScheme::SigV4 {
    service: "svc",
    region_of_host: region_of,
    default_region: "region-0",
    content_type: "application/json",
};

/// The table decides on the trimmed credential, whatever the mode; a credential in no family is
/// presented by the mode; a signing scheme has no static presentation.
#[test]
fn the_family_table_decides_first_and_the_mode_decides_the_rest() {
    use UpstreamCreds::{Own, Passthrough};
    assert_eq!(
        presentation(&TWO_FAMILIES, "  key-1", Passthrough),
        Some(KEY_HEADER)
    );
    assert_eq!(
        presentation(&TWO_FAMILIES, "tok-1", Own),
        Some(CredentialHeader::Bearer)
    );
    assert_eq!(
        presentation(&TWO_FAMILIES, "opaque", Own),
        Some(CredentialHeader::Raw {
            header: "x-key",
            trim_start: false
        })
    );
    assert_eq!(
        presentation(&TWO_FAMILIES, "opaque", Passthrough),
        Some(CredentialHeader::Bearer)
    );
    assert_eq!(presentation(&SIGNING, "a:b", Own), None);
}
