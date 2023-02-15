//! Shared key authentication

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Generate a key string suitable for use in a "Shared Key" identity in the Ditto SDK.
///
/// This is a P-256 ECDSA private key encoded as base64 PKCS#8 document, however you should treat it
/// as an opaque string.
pub fn generate_key() -> Result<String, SharedKeyError> {
    let rand = SystemRandom::new();
    let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rand)
        .map_err(|_| SharedKeyError::Generate)?;
    let b64 = base64::encode(key.as_ref());
    Ok(b64)
}

#[derive(Error, Debug)]
pub enum SharedKeyError {
    #[error("failed to generate new shared key")]
    Generate,
}

const DITTO_IDENTITY_TAG: &str = "DITTO IDENTITY";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct X509Auth {
    certificates: Vec<Vec<u8>>,
    private_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum JwtAuth {
    AuthUrl { url: String },
    AuthProvider { name: String },
    Token { token: String },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ManualIdentity {
    version: u16,
    private_key: Vec<u8>,
    expiry: chrono::DateTime<chrono::Utc>,
    identity_data: Vec<u8>,
    inband_ca_pubkey_keys: Vec<Vec<u8>>,
    // inband_certificate: InbandCertificate,
    // inband_metadata: Option<??>,
    x509_auth: Option<X509Auth>,
    jwt: Option<JwtAuth>,
}

impl ManualIdentity {
    pub fn new() -> Self {
        Self {
            version: 1,
            private_key: vec![],
            expiry: chrono::Utc::now(),
            identity_data: vec![],
            inband_ca_pubkey_keys: vec![],
            x509_auth: None,
            jwt: None,
        }
    }

    pub fn to_string(&self) -> String {
        let cbor = serde_cbor::to_vec(&self).unwrap();
        let pem = pem::Pem {
            tag: DITTO_IDENTITY_TAG.to_string(),
            contents: cbor,
        };
        let pem_string = pem::encode(&pem);
        pem_string
    }

    pub fn from_string(input: &str) -> Result<Self, anyhow::Error> {
        let p = pem::parse(input)?;

        if p.tag != DITTO_IDENTITY_TAG {
            return Err(anyhow::anyhow!("Wrong tag"));
        }
        let ret: ManualIdentity = serde_cbor::from_slice(&p.contents)?;
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encoding_decoding() {
        let identity = ManualIdentity::new();

        let pem_string = identity.to_string();
        let lines = pem_string.lines().collect::<Vec<_>>();

        assert_eq!(lines[0], "-----BEGIN DITTO IDENTITY-----");
        assert_eq!(lines.last().unwrap(), &"-----END DITTO IDENTITY-----");

        let parsed_identity = ManualIdentity::from_string(&pem_string).unwrap();

        assert_eq!(parsed_identity, identity);
    }

    #[test]
    fn key_round_trip() {
        let key = generate_key().unwrap();
        let pkcs = base64::decode(&key).unwrap();

        // Test round trip in ring
        let parsed = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs);
        assert!(parsed.is_ok());

        // Also that it can be read by rcgen for certificate signing
        let rc_key = rcgen::KeyPair::from_der(&pkcs);
        assert!(rc_key.is_ok());
    }
}
