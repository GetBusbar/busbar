// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_kernel::auth::chain_run::IdentityPolicy;

    fn request() -> AuthIn<'static> {
        AuthIn {
            method: "POST",
            path: "/provision/directory/Groups",
            query: "",
            authority: "node",
            headers: &[],
            peer: "127.0.0.1",
            tls_peer_cert: &[],
            body: &[],
            now_s: 1,
        }
    }

    #[test]
    fn client_policy_is_exact_and_bound_to_the_admitted_instance() {
        let policy = ClientPolicy {
            instance: 41,
            epoch: 7,
            clients: vec!["IdP".into()],
        };
        assert!(policy
            .authorize(41, &Identity::from_ticket("IdP", ""), &request())
            .is_ok());
        assert!(policy
            .authorize(41, &Identity::from_ticket("idp", ""), &request())
            .is_err());
        assert!(policy
            .authorize(42, &Identity::from_ticket("IdP", ""), &request())
            .is_err());
        assert_eq!(policy.epoch(), 7);
    }

    #[test]
    fn provisioning_path_is_relative_to_exact_instance_mount() {
        assert_eq!(
            relative_path("directory", "/provision/directory/Groups"),
            Some("/Groups")
        );
        assert_eq!(
            relative_path("directory", "/provision/directory2/Groups"),
            None
        );
        assert_eq!(relative_path("directory", "/Groups"), None);
    }
}
