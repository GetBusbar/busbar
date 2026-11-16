// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR'S TEST KIT: a private test CA, the adoption observer and the datagram reservation
//! bound, for this crate's tests and plugin repos' dev-dependencies.

#![cfg(any(test, feature = "test-support"))]

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

#[path = "test_support_adoption.rs"]
mod adoption;
pub use adoption::observe_adoption;

/// A private test CA and a `localhost` leaf it signed: the CA's certificate as PEM (what a suite's
/// test trust anchors are), the leaf's certificate and its private key, DER (what a test far
/// end serves).
#[derive(Debug, Clone)]
pub struct TestCa {
    /// The CA certificate, PEM.
    pub ca_pem: String,
    /// The `localhost` leaf certificate, DER.
    pub leaf_der: Vec<u8>,
    /// The leaf's private key, PKCS#8 DER.
    pub key_der: Vec<u8>,
}

/// A fresh [`TestCa`].
#[must_use]
pub fn private_ca() -> TestCa {
    use busbar_contract::crypto::testing::rcgen::{
        BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair,
    };
    let ca_kp = KeyPair::generate().expect("a CA key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_kp).expect("the CA certificate");
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let kp = KeyPair::generate().expect("a leaf key");
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .expect("leaf params")
        .signed_by(&kp, &issuer)
        .expect("the leaf certificate");
    TestCa {
        ca_pem: ca.pem(),
        leaf_der: leaf.der().to_vec(),
        key_der: kp.serialize_der(),
    }
}

/// Every certificate in a PEM bundle, DER.
#[must_use]
pub fn certs_from_pem(pem: &str) -> Vec<Vec<u8>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|c| c.expect("certificate PEM").to_vec())
        .collect()
}
