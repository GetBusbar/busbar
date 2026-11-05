// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Raw user input, owned beside OauthAsCfg. Native validation remains authoritative for URLs,
//! scope/issuer identity, PEM/secret resolution and public-key cryptography.
use serde_json::{json, Value};

fn nullable(schema: Value) -> Value {
    json!({"anyOf":[schema,{"type":"null"}],"default":null})
}
fn strings() -> Value {
    json!({"type":"array","items":{"type":"string"},"default":[]})
}
fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}
fn ttl(max: u64, default: u64) -> Value {
    let mut value = nullable(
        json!({"type":"integer","minimum":1,"maximum":max,"x-busbar-integer-token":"unsigned"}),
    );
    value["x-busbar-effective-default"] = json!(default);
    value
}

pub(super) fn schema() -> Value {
    let mut secret = busbar_contract::secret_ref::oneof_schema();
    secret["writeOnly"] = json!(true);
    let mut jwk = object(
        json!({"kty":{"enum":["EC","RSA"]},"crv":nullable(json!({"type":"string"})),"x":nullable(json!({"type":"string"})),"y":nullable(json!({"type":"string"})),"n":nullable(json!({"type":"string"})),"e":nullable(json!({"type":"string"})),"kid":nullable(json!({"type":"string"})),"alg":nullable(json!({"type":"string"})),"d":{"type":"null","description":"Private key material is refused by the owner. Only absent/null is valid user input."}}),
        &["kty"],
    );
    jwk["additionalProperties"] = json!(true);
    jwk["x-busbar-runtime-validation"]=json!(["only EC P-256/ES256 or RSA/PS256 public keys; correct coordinate/modulus/exponent encoding","all keys of one client share one algorithm; no private d value"]);
    let client = object(
        json!({"client_id":{"type":"string"},"redirect_uris":strings(),"device_authorization":{"type":"boolean","default":false},"jwks":object(json!({"keys":{"type":"array","items":jwk,"minItems":1}}),&["keys"])}),
        &["client_id", "jwks"],
    );
    let mut schema = object(
        json!({
            "issuer":{"type":"string","description":"Canonical absolute HTTP(S) issuer; owner trims surrounding whitespace and refuses query, fragment or trailing slash."},
            "signing_key":nullable(secret),"key_id":nullable(json!({"type":"string"})),
            "default_grant":strings(),"access_token_ttl_secs":ttl(super::MAX_ACCESS_TOKEN_TTL_SECS,super::DEFAULT_ACCESS_TOKEN_TTL.as_secs()),
            "refresh_token_ttl_secs":ttl(super::MAX_REFRESH_TOKEN_TTL_SECS,super::DEFAULT_REFRESH_TOKEN_TTL.as_secs()),
            "fapi2":{"type":"boolean","default":false},"clients":{"type":"array","items":client,"default":[]}
        }),
        &["issuer"],
    );
    schema["x-busbar-settings-profile"] = json!("integer-token-v1");
    schema["x-busbar-input-owner"] = json!("busbar-core-oauth2::config::OauthAsCfg/AsIdentity");
    schema["x-busbar-runtime-validation"] = json!([
        "issuer URL identity and legal RFC6749 scope tokens",
        "unique nonempty client IDs, redirect URI semantics and device-grant exception",
        "public key encoding, algorithm and minimum RSA strength",
        "SecretRef resolution and ES256 signing-key decoding",
        "canonical configuration validation/current semantic security policy"
    ]);
    schema["x-busbar-edit"] = json!({"operation":"PUT /api/v1/admin/config/settings document_patch","root":"/oauth_as","source_fence":"configuration.source_revision and config ETag","private_values":"signing_key is explicit keep/set/remove/reset; sanitized configured readback is never a full replacement","activation":"follow actual mutation restart/activation receipt; configured presence alone is not live AS proof"});
    schema["description"]=json!("Actual raw OAuthAS host input. Absent/null disables the server. Omitted signing_key deliberately generates an ephemeral boot key, invalidating issued tokens after restart. This is independent of identity-provider module settings and is not an admin credential issuer promise.");
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oauth_authoring_schema_matches_owned_structs_and_identity_constraints() {
        let schema = schema();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for value in [
            json!({"issuer":"https://gateway.example"}),
            json!({"issuer":"https://gateway.example","signing_key":{"env":"KEY"},"default_grant":["read"],"fapi2":true}),
            json!({"issuer":"https://gateway.example","access_token_ttl_secs":null,"refresh_token_ttl_secs":1}),
            json!({"issuer":"https://gateway.example","access_token_ttl_secs":0}),
            json!({"issuer":"https://gateway.example","refresh_token_ttl_secs":31536001_u64}),
            json!({"issuer":"https://gateway.example","clients":null}),
            json!({"issuer":"https://gateway.example","signing_key":"literal"}),
            json!({"issuer":"https://gateway.example","unknown":true}),
            json!({}),
        ] {
            let accepted = serde_json::from_value::<super::super::OauthAsCfg>(value.clone())
                .is_ok_and(|cfg| super::super::AsIdentity::from_cfg(&cfg).is_ok());
            assert_eq!(validator.is_valid(&value), accepted, "{value}");
        }
        let parsed: super::super::OauthAsCfg =
            serde_json::from_value(json!({"issuer":"https://gateway.example"})).unwrap();
        let identity = super::super::AsIdentity::from_cfg(&parsed).unwrap();
        assert_eq!(
            schema["properties"]["access_token_ttl_secs"]["x-busbar-effective-default"],
            identity.access_token_ttl.as_secs()
        );
        assert_eq!(
            schema["properties"]["refresh_token_ttl_secs"]["x-busbar-effective-default"],
            identity.refresh_token_ttl.as_secs()
        );
    }
}
