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

pub const IN_BAND_CERTIFICATE_VERSION: u32 = 1;

/// Information which is verified by the signature inside the `InBandCertificate`.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Payload {
    /// Application for which this certificate is granted
    #[serde(rename = "a")]
    pub app_id: String,

    /// Seconds since unix epoch that this certificate became valid, i.e. now() >= not_before
    #[serde(rename = "n")]
    pub not_before: i64,

    /// Seconds since unix epoch until which this certificate remains valid, i.e. now() < expiry
    #[serde(rename = "e")]
    pub expiry: i64,

    /// Hash of the serialised `IdentityData`, as it was issued for this peer upon authentication.
    /// This is also a serialised Ditto TLV.
    #[serde(rename = "h", with = "serde_bytes")]
    pub identity_data_hash: Vec<u8>,
}

/// An assertion that a certain `IdentityData` is valid. The `IdentityData` contains a mapping from
/// information about the peer to their Peer Key.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct InBandCertificate {
    /// Version of certificate format. See [IN_BAND_CERTIFICATE_VERSION].
    #[serde(rename = "v")]
    pub version: u32,

    /// Signed content: a TLV-serialised form of [Payload].
    ///
    /// Stored as opaque binary to ensure the signature can be verified without decoding ambiguity.
    #[serde(rename = "p", with = "serde_bytes")]
    pub payload: Vec<u8>,

    /// Public key of the signer. Should be 33 bytes.
    #[serde(rename = "k", with = "serde_bytes")]
    pub ecdsa_verifying_key: Vec<u8>,

    /// ECDSA signature. Should be 64 bytes.
    #[serde(rename = "s", with = "serde_bytes")]
    pub ecdsa_signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InBandAuthV1 {
    /// This peer's InBandCertificate
    inband_certificate: InBandCertificate,
    /// CA public keys to verify the in band certificate
    inband_ca_pubkey_keys: Vec<Vec<u8>>,
    // inband_metadata: Option<??>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct X509AuthV1 {
    /// This peer's private key
    private_key: Vec<u8>,
    /// This peer's certificate
    my_certificate: Vec<u8>,
    /// CA certificates to verify my own certificate
    ca_certificates: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum JwtAuthV1 {
    OnlineAuth {
        url: String,
        provider: String,
        token_credential: String,
    },
    Static {
        jwt: String,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ManualIdentity {
    V1(ManualIdentityV1),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManualIdentityV1 {
    version: u16,
    /// The application id
    app_id: String,
    /// This peer private key
    private_key: Vec<u8>,
    /// Exipry date time
    expiry: chrono::DateTime<chrono::Utc>,
    /// Identity data issued by auth server
    identity_data: Vec<u8>,

    inband_auth: Option<InBandAuthV1>,
    x509_auth: Option<X509AuthV1>,
    jwt_auth: Option<JwtAuthV1>,
}

impl ManualIdentityV1 {
    pub fn new() -> Self {
        Self {
            version: 1,
            app_id: "test_app_id".to_string(),
            private_key: vec![],
            expiry: chrono::Utc::now(),
            identity_data: vec![],
            inband_auth: None,
            x509_auth: None,
            jwt_auth: None,
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
        let ret: ManualIdentityV1 = serde_cbor::from_slice(&p.contents)?;
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encoding_decoding() {
        let identity = ManualIdentityV1::new();

        let pem_string = identity.to_string();
        let lines = pem_string.lines().collect::<Vec<_>>();

        assert_eq!(lines[0], "-----BEGIN DITTO IDENTITY-----");
        assert_eq!(lines.last().unwrap(), &"-----END DITTO IDENTITY-----");

        let parsed_identity = ManualIdentityV1::from_string(&pem_string).unwrap();

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
