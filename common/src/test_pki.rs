//! Ephemeral runtime PKI generator for unit and integration tests.
//!
//! Generates self-contained CAs, server/client certificates (with SANs and custom
//! RBAC OID extensions), no-SAN certificates, and Certificate Revocation Lists (CRLs)
//! inside a [`tempfile::TempDir`] using `rcgen` — removing any dependency on
//! checked-in or gitignored `server_certs/` / `client_certs/` files or the `openssl` CLI.

use std::path::PathBuf;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CustomExtension, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
    KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use tempfile::TempDir;

/// Ephemeral test PKI directory containing public and relay CAs, leaf certs, and CRLs.
pub struct TestPki {
    _dir: TempDir,
    /// Path to the public Root CA PEM (`public_ca.pem`).
    pub public_ca_pem: PathBuf,
    /// Path to the public server leaf cert PEM (`praeco_public.pem`).
    pub praeco_public_pem: PathBuf,
    /// Path to the public server leaf private key PEM (`praeco_public.key`).
    pub praeco_public_key: PathBuf,
    /// Path to the relay control-plane CA PEM (`relay_ca.pem`, no DNS SANs).
    pub relay_ca_pem: PathBuf,
    /// Path to the relay server leaf cert PEM (`relay_server.pem`).
    pub relay_server_pem: PathBuf,
    /// Path to the relay server leaf private key PEM (`relay_server.key`).
    pub relay_server_key: PathBuf,
    /// Path to the Praeco client leaf cert PEM (`praeco_client.pem`, with SANs & OID `.1`).
    pub praeco_client_pem: PathBuf,
    /// Path to the Praeco client leaf private key PEM (`praeco_client.key`).
    pub praeco_client_key: PathBuf,
    /// Path to a valid non-revoking CRL PEM (`relay_ca.crl.pem`, revokes serial `9999`).
    pub relay_crl_pem: PathBuf,
    /// Path to a CRL PEM that explicitly revokes `praeco_client.pem` (`relay_ca_revoked_client.crl.pem`).
    pub relay_crl_revoking_client_pem: PathBuf,
    /// Path to a client leaf cert signed by `relay_ca` WITHOUT any DNS SAN (`nosan_client.pem`).
    pub nosan_client_pem: PathBuf,
    /// Path to `nosan_client`'s private key PEM (`nosan_client.key`).
    pub nosan_client_key: PathBuf,
}

impl TestPki {
    /// Generates a complete ephemeral PKI in a fresh temporary directory.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation or writing to the temporary directory fails.
    pub fn new() -> Self {
        let dir = TempDir::new().expect("create temp PKI directory");
        let root = dir.path();

        // ── 1. Public CA + Praeco public server cert ─────────────────────────
        let (public_ca_cert, public_ca_key) = make_ca("Praeco Test Public CA");
        let public_ca_pem = root.join("public_ca.pem");
        std::fs::write(&public_ca_pem, public_ca_cert.pem()).expect("write public_ca.pem");

        let mut pub_srv_params = CertificateParams::new(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "wurzelwerk.api.aweirich.eu".to_string(),
            "wurzelwerk.onboarding.aweirich.eu".to_string(),
            "wurzelwerk.admin.aweirich.eu".to_string(),
            "wurzelwerk.idp.aweirich.eu".to_string(),
        ])
        .expect("public server SANs");
        pub_srv_params.distinguished_name = cn_dn("wurzelwerk.api.aweirich.eu");
        pub_srv_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        pub_srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let pub_srv_key = KeyPair::generate().expect("generate public server key");
        let pub_srv_cert = pub_srv_params
            .signed_by(&pub_srv_key, &public_ca_cert, &public_ca_key)
            .expect("sign public server cert");

        let praeco_public_pem = root.join("praeco_public.pem");
        let praeco_public_key = root.join("praeco_public.key");
        std::fs::write(&praeco_public_pem, pub_srv_cert.pem()).expect("write praeco_public.pem");
        std::fs::write(&praeco_public_key, pub_srv_key.serialize_pem())
            .expect("write praeco_public.key");

        // ── 2. Relay CA (strictly NO DNS SANs) + Relay Server + Praeco Client ─
        let (relay_ca_cert, relay_ca_key) = make_ca("Praeco Test Relay CA");
        let relay_ca_pem = root.join("relay_ca.pem");
        std::fs::write(&relay_ca_pem, relay_ca_cert.pem()).expect("write relay_ca.pem");

        let mut relay_srv_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("relay server SANs");
        relay_srv_params.distinguished_name = cn_dn("relay.test.local");
        relay_srv_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        relay_srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let relay_srv_key = KeyPair::generate().expect("generate relay server key");
        let relay_srv_cert = relay_srv_params
            .signed_by(&relay_srv_key, &relay_ca_cert, &relay_ca_key)
            .expect("sign relay server cert");

        let relay_server_pem = root.join("relay_server.pem");
        let relay_server_key = root.join("relay_server.key");
        std::fs::write(&relay_server_pem, relay_srv_cert.pem()).expect("write relay_server.pem");
        std::fs::write(&relay_server_key, relay_srv_key.serialize_pem())
            .expect("write relay_server.key");

        let client_serial: u64 = 1001;
        let mut client_params = CertificateParams::new(vec![
            "wurzelwerk.api.aweirich.eu".to_string(),
            "wurzelwerk.onboarding.aweirich.eu".to_string(),
            "wurzelwerk.admin.aweirich.eu".to_string(),
            "wurzelwerk.idp.aweirich.eu".to_string(),
        ])
        .expect("client SANs");
        client_params.serial_number = Some(SerialNumber::from(client_serial));
        client_params.distinguished_name = cn_dn("praeco-gateway-client");
        client_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let mut oid_ext = CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 65111, 1],
            b"Proxy-RBAC-Role".to_vec(),
        );
        oid_ext.set_criticality(false);
        client_params.custom_extensions.push(oid_ext);

        let client_key = KeyPair::generate().expect("generate client key");
        let client_cert = client_params
            .signed_by(&client_key, &relay_ca_cert, &relay_ca_key)
            .expect("sign client cert");

        let praeco_client_pem = root.join("praeco_client.pem");
        let praeco_client_key = root.join("praeco_client.key");
        std::fs::write(&praeco_client_pem, client_cert.pem()).expect("write praeco_client.pem");
        std::fs::write(&praeco_client_key, client_key.serialize_pem())
            .expect("write praeco_client.key");

        // ── 3. No-SAN client cert signed by Relay CA ─────────────────────────
        let mut nosan_params = CertificateParams::default();
        nosan_params.serial_number = Some(SerialNumber::from(1003u64));
        nosan_params.distinguished_name = cn_dn("NoSanClient");
        nosan_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        nosan_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let nosan_key = KeyPair::generate().expect("generate no-SAN key");
        let nosan_cert = nosan_params
            .signed_by(&nosan_key, &relay_ca_cert, &relay_ca_key)
            .expect("sign no-SAN cert");

        let nosan_client_pem = root.join("nosan_client.pem");
        let nosan_client_key = root.join("nosan_client.key");
        std::fs::write(&nosan_client_pem, nosan_cert.pem()).expect("write nosan_client.pem");
        std::fs::write(&nosan_client_key, nosan_key.serialize_pem())
            .expect("write nosan_client.key");

        // ── 4. CRLs signed by Relay CA ───────────────────────────────────────
        let now = time::OffsetDateTime::now_utc();
        let this_update = now - time::Duration::hours(1);
        let next_update = now + time::Duration::days(3650);

        let non_revoking_crl = CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(9999u64),
                revocation_time: this_update,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&relay_ca_cert, &relay_ca_key)
        .expect("sign non-revoking CRL");
        let relay_crl_pem = root.join("relay_ca.crl.pem");
        std::fs::write(
            &relay_crl_pem,
            non_revoking_crl.pem().expect("encode CRL PEM"),
        )
        .expect("write relay_ca.crl.pem");

        let revoking_crl = CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: SerialNumber::from(2u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(client_serial),
                revocation_time: this_update,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&relay_ca_cert, &relay_ca_key)
        .expect("sign revoking CRL");
        let relay_crl_revoking_client_pem = root.join("relay_ca_revoked_client.crl.pem");
        std::fs::write(
            &relay_crl_revoking_client_pem,
            revoking_crl.pem().expect("encode revoking CRL PEM"),
        )
        .expect("write relay_ca_revoked_client.crl.pem");

        Self {
            _dir: dir,
            public_ca_pem,
            praeco_public_pem,
            praeco_public_key,
            relay_ca_pem,
            relay_server_pem,
            relay_server_key,
            praeco_client_pem,
            praeco_client_key,
            relay_crl_pem,
            relay_crl_revoking_client_pem,
            nosan_client_pem,
            nosan_client_key,
        }
    }

    /// Convenience helper returning a `&str` for a path.
    pub fn s(path: &std::path::Path) -> &str {
        path.to_str().expect("temp path must be valid UTF-8")
    }
}

impl Default for TestPki {
    fn default() -> Self {
        Self::new()
    }
}

fn cn_dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

fn make_ca(cn: &str) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.distinguished_name = cn_dn(cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate().expect("generate CA key");
    let cert = params.self_signed(&key).expect("self-sign CA");
    (cert, key)
}
